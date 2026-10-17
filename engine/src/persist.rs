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
//! | `hosts/NAME/events/CHANNEL-HASH.NNNNNN.jsonl` | Event log segments, one event per line |
//! | `discarded/NAME-TIME/` | State moved aside after a profile change |
//!
//! Event logs are kept out of the change log and snapshots, since a busy
//! Security log can see many events per second. Each channel appends to
//! segment files of about a quarter of its size limit; a segment is deleted
//! once every event in it has been dropped by retention. `reset` deletes them.

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
    /// Open event segments, by (host, normalised channel).
    events: Mutex<HashMap<(String, String), ChannelFiles>>,
    snapshot_every: usize,
}

/// One channel's segment files.
struct ChannelFiles {
    prefix: String,
    /// (index, last record ID) of each segment, oldest first.
    segments: std::collections::VecDeque<(u64, u64)>,
    current: Option<BufWriter<File>>,
    current_bytes: u64,
    cap: u64,
    dirty: bool,
}

/// Smallest segment, so tiny channels do not make thousands of files.
const MIN_SEGMENT: u64 = 64 * 1024;

/// A file name for a channel: readable, and unique even when names differ only by case or `/`.
fn channel_prefix(name: &str) -> String {
    let readable: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let hash = sha256_hex(crate::merge::norm(name).as_bytes());
    format!("{readable}-{}", &hash[..8])
}

/// What loading the state found, for the daemon to report.
#[derive(Debug, Default)]
pub struct LoadReport {
    pub restored: Vec<String>,
    pub fresh: Vec<String>,
    pub replayed: usize,
    /// Events read back from segment files.
    pub events: usize,
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
            events: Mutex::new(HashMap::new()),
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
        drop(rt);
        // Events last: a `reset` in the replayed log has already emptied them.
        self.load_events(host, report).map_err(err)?;
        Ok(())
    }

    fn events_dir(&self, host: &str) -> PathBuf {
        self.host_dir(host).join("events")
    }

    /// Read every event segment of a host back into its event logs.
    fn load_events(&self, host: &Host, report: &mut LoadReport) -> io::Result<()> {
        let dir = self.events_dir(&host.name);
        fs::create_dir_all(&dir)?;
        // (prefix, index) to path, so segments load oldest first.
        let mut segs: Vec<(String, u64, PathBuf)> = Vec::new();
        for e in fs::read_dir(&dir)?.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(stem) = name.strip_suffix(".jsonl") else {
                continue;
            };
            let Some((prefix, idx)) = stem.rsplit_once('.') else {
                continue;
            };
            if let Ok(i) = idx.parse::<u64>() {
                segs.push((prefix.to_string(), i, e.path()));
            }
        }
        segs.sort();
        let rt = host.read();
        let reg = host.registry(&rt);
        let mut logs = host.events_write();
        let mut files = self.events.lock().unwrap_or_else(|e| e.into_inner());
        let mut loaded = 0usize;
        for (prefix, idx, path) in segs {
            let text = fs::read_to_string(&path)?;
            let mut last_id = 0;
            let mut channel_key = None;
            for (n, line) in text.lines().enumerate() {
                let Ok(v) = serde_json::from_str::<Value>(line) else {
                    report.warnings.push(format!(
                        "{}: {} line {} is incomplete; the rest of that segment is skipped",
                        host.name,
                        path.display(),
                        n + 1
                    ));
                    break;
                };
                let (Some(name), Some(id)) = (v["channel"].as_str(), v["record_id"].as_u64())
                else {
                    continue;
                };
                let ch = match logs.channel_mut(name, &reg) {
                    Ok(c) => c,
                    Err(_) => {
                        report.warnings.push(format!(
                            "{}: saved events for undeclared channel {name} skipped",
                            host.name
                        ));
                        break;
                    }
                };
                let mut doc = v.as_object().cloned().unwrap_or_default();
                let computer = doc
                    .remove("computer")
                    .and_then(|c| c.as_str().map(str::to_string))
                    .unwrap_or_default();
                doc.remove("record_id");
                doc.remove("channel");
                let e = crate::eventlog::Event {
                    record_id: id,
                    channel: ch.name.clone(),
                    computer,
                    doc,
                    size: line.len() + 1,
                };
                ch.push(Arc::new(e));
                channel_key = Some(crate::merge::norm(name));
                last_id = id;
                loaded += 1;
            }
            let Some(key) = channel_key else { continue };
            let cap = logs
                .channels
                .get(&key)
                .map_or(MIN_SEGMENT, |c| (c.max_bytes / 4).max(MIN_SEGMENT));
            let entry = files
                .entry((host.name.clone(), key))
                .or_insert_with(|| ChannelFiles {
                    prefix: prefix.clone(),
                    segments: Default::default(),
                    current: None,
                    current_bytes: 0,
                    cap,
                    dirty: false,
                });
            entry.segments.push_back((idx, last_id));
            entry.current_bytes = fs::metadata(&path)?.len();
            entry.current = Some(BufWriter::new(OpenOptions::new().append(true).open(&path)?));
        }
        if loaded > 0 {
            report.events += loaded;
        }
        Ok(())
    }

    /// Append one event to its channel's current segment. Called with the
    /// host's event lock held, so lines are in record order. Segments whose
    /// events retention has dropped (all below `oldest`) are deleted.
    pub fn append_event(
        &self,
        host: &Host,
        ch: &crate::eventlog::Channel,
        line: &str,
        oldest: u64,
    ) -> io::Result<()> {
        let key = (host.name.clone(), crate::merge::norm(&ch.name));
        let dir = self.events_dir(&host.name);
        let mut files = self.events.lock().unwrap_or_else(|e| e.into_inner());
        let f = files.entry(key).or_insert_with(|| ChannelFiles {
            prefix: channel_prefix(&ch.name),
            segments: Default::default(),
            current: None,
            current_bytes: 0,
            cap: (ch.max_bytes / 4).max(MIN_SEGMENT),
            dirty: false,
        });
        let record_id = ch.next_record_id - 1;
        if f.current.is_none() || f.current_bytes >= f.cap {
            if let Some(mut old) = f.current.take() {
                old.flush()?;
                old.get_ref().sync_data()?;
            }
            let idx = f.segments.back().map_or(1, |(i, _)| i + 1);
            let path = dir.join(format!("{}.{idx:06}.jsonl", f.prefix));
            fs::create_dir_all(&dir)?;
            f.current = Some(open_log(&path, true)?);
            f.current_bytes = 0;
            f.segments.push_back((idx, record_id));
        }
        let w = f.current.as_mut().expect("opened above");
        writeln!(w, "{line}")?;
        f.current_bytes += line.len() as u64 + 1;
        f.dirty = true;
        if let Some(last) = f.segments.back_mut() {
            last.1 = record_id;
        }
        // Never delete the segment being written.
        while f.segments.len() > 1 && f.segments.front().is_some_and(|(_, last)| *last < oldest) {
            let (idx, _) = f.segments.pop_front().expect("checked");
            let _ = fs::remove_file(dir.join(format!("{}.{idx:06}.jsonl", f.prefix)));
        }
        Ok(())
    }

    /// Delete a host's event segments (`reset`).
    fn clear_events(&self, host: &str) -> io::Result<()> {
        let mut files = self.events.lock().unwrap_or_else(|e| e.into_inner());
        files.retain(|(h, _), _| h != host);
        let dir = self.events_dir(host);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(&dir)
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
        if op == "reset" {
            self.clear_events(&host.name)?;
        }
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
        drop(logs);
        let mut files = self.events.lock().unwrap_or_else(|e| e.into_inner());
        for f in files.values_mut().filter(|f| f.dirty) {
            if let Some(w) = f.current.as_mut() {
                w.flush()?;
                w.get_ref().sync_data()?;
            }
            f.dirty = false;
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
