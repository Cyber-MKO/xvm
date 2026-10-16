//! Saving run-time changes across engine restarts.
//!
//! Each host has a snapshot of its run-time layer and an append-only change
//! log. Every applied write is appended to the log at once; a flusher thread
//! fsyncs logs and new blobs in batches (every 200 ms by default), so a power
//! loss can drop at most the last batch. After a set number of changes the
//! host gets a fresh snapshot and its log starts again.
//!
//! On start the engine loads each snapshot and replays the log through the
//! same `apply` the server uses. A torn last line or a change that no longer
//! applies ends the replay there, keeping a clean prefix of the history. Then
//! the host is compacted: a new snapshot, an empty log.
//!
//! A snapshot records a digest of the host's compiled profile and base. If
//! they changed since, the saved changes were made against a different host,
//! so the host's state is moved aside (never deleted) and it starts fresh.
//!
//! | Path | Holds |
//! | --- | --- |
//! | `hosts/NAME/snapshot.json` | `{schema, host, digest, runtime}` |
//! | `hosts/NAME/log.jsonl` | One `{op, params}` per change since the snapshot |
//! | `blobs/SHA256` | File bytes written at run time, stored once |
//! | `discarded/NAME-TIME/` | State moved aside after a profile change |

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Map, Value, json};

use crate::apply::apply;
use crate::files::{Blobs, sha256_hex};
use crate::runtime::Runtime;
use crate::store::{Host, Store, StoreError};

pub const SNAPSHOT_SCHEMA: u64 = 1;
/// Changes logged before a host is snapshotted again.
pub const DEFAULT_SNAPSHOT_EVERY: usize = 1000;
pub const DEFAULT_FLUSH: Duration = Duration::from_millis(200);

/// The state folder's blob store, for run-time file bytes.
pub struct StateBlobs {
    dir: PathBuf,
    /// Written but not yet fsynced.
    pending: Mutex<Vec<PathBuf>>,
}

impl StateBlobs {
    fn put(&self, data: &[u8]) -> io::Result<String> {
        let sha = sha256_hex(data);
        let path = self.dir.join(&sha);
        if !path.exists() {
            let tmp = self.dir.join(format!(".{sha}.tmp"));
            fs::write(&tmp, data)?;
            fs::rename(&tmp, &path)?;
            self.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(path);
        }
        Ok(sha)
    }
}

impl Blobs for StateBlobs {
    fn get(&self, sha256: &str) -> Result<Arc<[u8]>, String> {
        let ok = sha256.len() == 64
            && sha256
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
        if !ok {
            return Err(format!("bad blob name {sha256:?}"));
        }
        let path = self.dir.join(sha256);
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if sha256_hex(&bytes) != sha256 {
            return Err(format!(
                "{}: content does not match its name",
                path.display()
            ));
        }
        Ok(Arc::from(bytes))
    }
}

struct HostLog {
    file: BufWriter<File>,
    dirty: bool,
    since_snapshot: usize,
}

pub struct Persist {
    dir: PathBuf,
    blobs: StateBlobs,
    logs: Mutex<HashMap<String, HostLog>>,
    snapshot_every: usize,
}

/// What loading the state found, for the daemon to report.
#[derive(Debug, Default)]
pub struct LoadReport {
    pub restored: Vec<String>,
    pub fresh: Vec<String>,
    pub replayed: usize,
    pub warnings: Vec<String>,
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
}

/// Write a file so it is either fully there or not at all.
fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

fn open_log(path: &Path, truncate: bool) -> io::Result<BufWriter<File>> {
    let file = OpenOptions::new()
        .create(true)
        .append(!truncate)
        .write(true)
        .truncate(truncate)
        .open(path)?;
    Ok(BufWriter::new(file))
}

impl Persist {
    /// Open (or create) the state folder and restore every host in `store`.
    pub fn open(
        dir: &Path,
        store: &Store,
        snapshot_every: usize,
    ) -> Result<(Self, LoadReport), StoreError> {
        let err = |e: io::Error, what: &Path| StoreError(format!("{}: {e}", what.display()));
        for sub in ["hosts", "blobs", "discarded"] {
            fs::create_dir_all(dir.join(sub)).map_err(|e| err(e, &dir.join(sub)))?;
        }
        let persist = Persist {
            dir: dir.to_path_buf(),
            blobs: StateBlobs {
                dir: dir.join("blobs"),
                pending: Mutex::new(Vec::new()),
            },
            logs: Mutex::new(HashMap::new()),
            snapshot_every: snapshot_every.max(1),
        };
        let mut report = LoadReport::default();
        for host in store.hosts.values() {
            if !safe_name(&host.name) {
                return Err(StoreError(format!(
                    "host name {:?} cannot name a state folder",
                    host.name
                )));
            }
            persist.restore(host, &mut report)?;
        }
        if let Ok(entries) = fs::read_dir(dir.join("hosts")) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if !store.hosts.contains_key(&name) {
                    report
                        .warnings
                        .push(format!("state for {name} kept, but no such host is loaded"));
                }
            }
        }
        persist.flush().map_err(|e| err(e, dir))?;
        Ok((persist, report))
    }

    fn host_dir(&self, name: &str) -> PathBuf {
        self.dir.join("hosts").join(name)
    }

    /// Load one host: snapshot, then log replay, then compaction.
    fn restore(&self, host: &Host, report: &mut LoadReport) -> Result<(), StoreError> {
        let dir = self.host_dir(&host.name);
        let err = |e: io::Error| StoreError(format!("{}: {e}", dir.display()));
        let snap_path = dir.join("snapshot.json");
        let mut restored = false;
        if snap_path.exists() {
            match self.load_snapshot(host, &snap_path) {
                Ok(rt) => {
                    *host.write() = rt;
                    restored = true;
                }
                Err(why) => {
                    let moved = self.discard(&host.name).map_err(err)?;
                    report.warnings.push(format!(
                        "{}: saved state discarded ({why}); moved to {}",
                        host.name,
                        moved.display()
                    ));
                }
            }
        }
        fs::create_dir_all(&dir).map_err(err)?;
        if restored {
            let (n, warning) = self.replay(host, &dir.join("log.jsonl"));
            report.replayed += n;
            if let Some(w) = warning {
                report.warnings.push(format!("{}: {w}", host.name));
            }
            report.restored.push(host.name.clone());
        } else {
            report.fresh.push(host.name.clone());
        }
        // Compact: one snapshot of the state as loaded, and an empty log.
        let rt = host.read();
        self.write_snapshot(host, &rt).map_err(err)?;
        let log = open_log(&dir.join("log.jsonl"), true).map_err(err)?;
        self.logs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            host.name.clone(),
            HostLog {
                file: log,
                dirty: false,
                since_snapshot: 0,
            },
        );
        Ok(())
    }

    fn load_snapshot(&self, host: &Host, path: &Path) -> Result<Runtime, String> {
        let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let v: Value =
            serde_json::from_str(&text).map_err(|e| format!("unreadable snapshot: {e}"))?;
        if v["schema"].as_u64() != Some(SNAPSHOT_SCHEMA) {
            return Err(format!(
                "snapshot schema {} is not {SNAPSHOT_SCHEMA}",
                v["schema"]
            ));
        }
        if v["host"].as_str() != Some(host.name.as_str()) {
            return Err("snapshot names another host".into());
        }
        if v["digest"].as_str() != Some(host.digest.as_str()) {
            return Err("the host's profile or base image changed".into());
        }
        Runtime::from_snapshot(&v["runtime"], &self.blobs)
    }

    /// Replay a log. Returns the changes applied and why it stopped early, if it did.
    fn replay(&self, host: &Host, path: &Path) -> (usize, Option<String>) {
        let Ok(file) = File::open(path) else {
            return (0, None);
        };
        let mut rt = host.write();
        let mut applied = 0;
        for (i, line) in BufReader::new(file).lines().enumerate() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    return (
                        applied,
                        Some(format!("log line {}: {e}; replay stopped", i + 1)),
                    );
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let Ok(entry) = serde_json::from_str::<Value>(&line) else {
                return (
                    applied,
                    Some(format!(
                        "log line {} is incomplete; replay stopped there",
                        i + 1
                    )),
                );
            };
            let (Some(op), Some(params)) = (entry["op"].as_str(), entry["params"].as_object())
            else {
                return (
                    applied,
                    Some(format!("log line {} is malformed; replay stopped", i + 1)),
                );
            };
            if let Err(f) = apply(host, &mut rt, op, params, Some(&self.blobs)) {
                return (
                    applied,
                    Some(format!(
                        "log line {} ({op}) no longer applies: {}; replay stopped",
                        i + 1,
                        f.1
                    )),
                );
            }
            applied += 1;
        }
        (applied, None)
    }

    fn write_snapshot(&self, host: &Host, rt: &Runtime) -> io::Result<()> {
        let runtime = rt.to_snapshot(&mut |b| self.blobs.put(b))?;
        // Blobs must be durable before the snapshot that names them.
        self.sync_blobs()?;
        let snap = json!({
            "schema": SNAPSHOT_SCHEMA,
            "host": host.name,
            "digest": host.digest,
            "runtime": runtime,
        });
        let path = self.host_dir(&host.name).join("snapshot.json");
        write_atomic(&path, &serde_json::to_vec(&snap).map_err(io::Error::other)?)
    }

    /// Move a host's state aside. Returns where it went.
    fn discard(&self, name: &str) -> io::Result<PathBuf> {
        let stamp = crate::runtime::now().replace([':', '.'], "-");
        let target = self.dir.join("discarded").join(format!("{name}-{stamp}"));
        fs::rename(self.host_dir(name), &target)?;
        Ok(target)
    }

    /// Log one applied change. Called with the host's write lock held, so the
    /// log order is the order changes were applied.
    pub fn record(
        &self,
        host: &Host,
        rt: &Runtime,
        op: &str,
        params: &Map<String, Value>,
    ) -> io::Result<()> {
        let mut params = params.clone();
        if op == "file.write"
            && let Some(data) = params.remove("data")
        {
            let bytes = B64
                .decode(data.as_str().unwrap_or_default())
                .map_err(io::Error::other)?;
            params.insert("blob".into(), self.blobs.put(&bytes)?.into());
        }
        let line = serde_json::to_string(&json!({"op": op, "params": params}))
            .map_err(io::Error::other)?;
        let snapshot_due = {
            let mut logs = self.logs.lock().unwrap_or_else(|e| e.into_inner());
            let log = logs
                .get_mut(&host.name)
                .ok_or_else(|| io::Error::other(format!("no state log for {}", host.name)))?;
            writeln!(log.file, "{line}")?;
            log.dirty = true;
            log.since_snapshot += 1;
            log.since_snapshot >= self.snapshot_every
        };
        if snapshot_due {
            self.snapshot(host, rt)?;
        }
        Ok(())
    }

    /// Snapshot a host now and start its log again.
    pub fn snapshot(&self, host: &Host, rt: &Runtime) -> io::Result<()> {
        // Every logged line describes a change already in `rt`, so the log can go.
        self.write_snapshot(host, rt)?;
        // Under the lock, so the flusher cannot write old lines into the emptied log.
        let mut logs = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(log) = logs.get_mut(&host.name) {
            // Drop buffered lines without writing them: dropping a BufWriter would flush them.
            let placeholder =
                BufWriter::new(File::open(self.host_dir(&host.name).join("snapshot.json"))?);
            let (file, _unwritten) = std::mem::replace(&mut log.file, placeholder).into_parts();
            file.set_len(0)?;
            file.sync_data()?;
            log.file = BufWriter::new(file);
            log.dirty = false;
            log.since_snapshot = 0;
        }
        Ok(())
    }

    fn sync_blobs(&self) -> io::Result<()> {
        let pending: Vec<PathBuf> =
            std::mem::take(&mut *self.blobs.pending.lock().unwrap_or_else(|e| e.into_inner()));
        for p in &pending {
            File::open(p)?.sync_all()?;
        }
        if !pending.is_empty() {
            File::open(&self.blobs.dir)?.sync_all()?;
        }
        Ok(())
    }

    /// Make everything logged so far durable: blobs first, then the logs that name them.
    pub fn flush(&self) -> io::Result<()> {
        self.sync_blobs()?;
        let mut logs = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        for log in logs.values_mut().filter(|l| l.dirty) {
            log.file.flush()?;
            log.file.get_ref().sync_data()?;
            log.dirty = false;
        }
        Ok(())
    }

    /// Flush every `every` until the process ends. Errors are reported and retried.
    pub fn spawn_flusher(self: &Arc<Self>, every: Duration) {
        let p = self.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(every);
                if let Err(e) = p.flush() {
                    eprintln!("xvm-engined: could not save run-time changes: {e}");
                }
            }
        });
    }
}
