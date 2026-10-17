//! Run-time changes survive an engine restart: snapshot, log replay, drift.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use xvm_engine::persist::{LoadReport, Persist};
use xvm_engine::protocol::{Request, code};
use xvm_engine::server::Server;
use xvm_engine::store::{Base, Host, Store};

const T1: &str = "2026-10-16T10:00:00Z";
static COUNTER: AtomicU32 = AtomicU32::new(0);

fn read(p: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap()
}

fn vector(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name)
}

fn temp_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("xvm-persist-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// A fresh store holding the edge host, as the engine would load it after a restart.
fn store_with(host_doc: Value) -> Arc<Store> {
    let base = Arc::new(Base::from_value(read(&vector("edge/base.json"))).unwrap());
    let host = Arc::new(Host::from_value(host_doc, base.clone()).unwrap());
    let mut store = Store::default();
    store.bases.insert(base.name.clone(), base);
    store.hosts.insert(host.name.clone(), host);
    Arc::new(store)
}

fn store() -> Arc<Store> {
    store_with(read(&vector("edge/host.json")))
}

struct Engine {
    server: Server,
    persist: Arc<Persist>,
    store: Arc<Store>,
    report: LoadReport,
    bound: Option<Arc<Host>>,
    next: u64,
}

impl Engine {
    /// Start an engine on `state`, as `xvm-engined --state` does.
    fn start(state: &Path, store: Arc<Store>, snapshot_every: usize) -> Self {
        let (p, report) = Persist::open(state, &store, snapshot_every).unwrap();
        let persist = Arc::new(p);
        let gaps: Box<dyn std::io::Write + Send> = Box::new(std::io::sink());
        let server = Server::new(store.clone(), Arc::new(Mutex::new(gaps)))
            .with_persistence(persist.clone());
        let mut e = Engine {
            server,
            persist,
            store,
            report,
            bound: None,
            next: 1,
        };
        e.ok("hello", json!({"host": "edge-host"}));
        e
    }

    fn call(&mut self, op: &str, params: Value) -> Result<Value, String> {
        let req = Request {
            id: self.next,
            op: op.into(),
            params: params.as_object().cloned().unwrap_or_default(),
        };
        self.next += 1;
        let resp = self.server.handle(&req, &mut self.bound);
        match (resp.ok, resp.result, resp.error) {
            (true, r, _) => Ok(r.unwrap_or(Value::Null)),
            (false, _, Some(e)) => Err(e.code),
            _ => panic!("malformed response"),
        }
    }

    fn ok(&mut self, op: &str, params: Value) -> Value {
        self.call(op, params)
            .unwrap_or_else(|e| panic!("{op}: {e}"))
    }

    fn host(&self) -> Arc<Host> {
        self.store.hosts["edge-host"].clone()
    }

    /// Everything a client can observe about the host.
    fn observe(&mut self) -> Value {
        json!({
            "resolved": self.host().resolved(),
            "procs": self.ok("proc.list", json!({})),
            "changes": self.ok("changes", json!({})),
            "log": self.text(r"C:\ProgramData\Vendor\agent.log"),
        })
    }

    fn text(&mut self, path: &str) -> Value {
        match self.call("file.read", json!({"path": path})) {
            Ok(r) => {
                json!(String::from_utf8(B64.decode(r["data"].as_str().unwrap()).unwrap()).unwrap())
            }
            Err(code) => json!({"error": code}),
        }
    }
}

const APP: &str = r"HKLM\SOFTWARE\Vendor\App";

/// One of every kind of write.
fn workload(e: &mut Engine) {
    e.ok(
        "reg.set_value",
        json!({"key": APP, "name": "Version", "type": "REG_SZ", "data": "7.0", "time": T1}),
    );
    e.ok(
        "reg.delete_key",
        json!({"key": format!(r"{APP}\Plugins"), "recursive": true}),
    );
    e.ok(
        "reg.create_key",
        json!({"key": r"HKLM\SOFTWARE\Vendor\Fresh"}),
    );
    e.ok("reg.delete_value", json!({"key": APP, "name": "Path"}));
    e.ok(
        "list.upsert",
        json!({"name": "services", "item": {"name": "Alpha", "state": "stopped"}}),
    );
    e.ok("list.remove", json!({"name": "users", "item": "Operator"}));
    e.ok(
        "section.update",
        json!({"name": "hardware", "patch": {"memory_mb": 4096}}),
    );
    e.ok("file.mkdir", json!({"path": r"C:\ProgramData\Vendor\logs"}));
    e.ok(
        "file.write",
        json!({"path": r"C:\ProgramData\Vendor\agent.log", "data": B64.encode("start\n")}),
    );
    e.ok("file.write", json!({"path": r"C:\ProgramData\Vendor\agent.log", "data": B64.encode("more\n"), "append": true}));
    e.ok("file.rename", json!({"from": r"C:\ProgramData\Vendor\config.ini", "to": r"C:\ProgramData\Vendor\old.ini"}));
    e.ok(
        "file.set",
        json!({"path": r"C:\ProgramData\Vendor\old.ini", "patch": {"attributes": ["hidden"]}}),
    );
    e.ok(
        "file.delete",
        json!({"path": r"C:\Users\svc-backup\notes.txt"}),
    );
    let pid = e.ok(
        "proc.start",
        json!({"image": "wazuh-agent.exe", "native_pid": 4242, "pid": 1000}),
    )["pid"]
        .clone();
    e.ok("proc.start", json!({"image": "cmd.exe", "parent_pid": pid}));
    e.ok("proc.exit", json!({"pid": pid, "exit_code": 0}));
}

fn log_lines(state: &Path) -> usize {
    fs::read_to_string(state.join("hosts/edge-host/log.jsonl"))
        .unwrap()
        .lines()
        .count()
}

#[test]
fn changes_survive_a_restart_through_the_log() {
    let state = temp_dir();
    let mut e = Engine::start(&state, store(), 1_000_000);
    assert_eq!(e.report.fresh, ["edge-host"]);
    workload(&mut e);
    let before = e.observe();
    e.persist.flush().unwrap();
    assert_eq!(log_lines(&state), 16);
    drop(e);

    let mut again = Engine::start(&state, store(), 1_000_000);
    assert_eq!(again.report.restored, ["edge-host"]);
    assert_eq!(again.report.replayed, 16);
    assert!(
        again.report.warnings.is_empty(),
        "{:?}",
        again.report.warnings
    );
    assert_eq!(again.observe(), before);
    // Loading compacts: the replayed log is folded into the snapshot.
    assert_eq!(log_lines(&state), 0);
    // The PID generator was restored too: the next PID is the one the old engine would give.
    let mut fresh = Engine::start(&temp_dir(), store(), 1_000_000);
    workload(&mut fresh);
    let want = fresh.ok("proc.start", json!({"image": "x.exe"}))["pid"].clone();
    assert_eq!(
        again.ok("proc.start", json!({"image": "x.exe"}))["pid"],
        want
    );
}

#[test]
fn snapshots_cut_the_log() {
    let state = temp_dir();
    let mut e = Engine::start(&state, store(), 5);
    workload(&mut e);
    let before = e.observe();
    e.persist.flush().unwrap();
    assert_eq!(log_lines(&state), 1); // 16 changes: snapshots after 5, 10, 15
    drop(e);
    let mut again = Engine::start(&state, store(), 5);
    assert_eq!(again.report.replayed, 1);
    assert_eq!(again.observe(), before);
}

#[test]
fn run_time_bytes_are_stored_once_in_the_state_blobs() {
    let state = temp_dir();
    let mut e = Engine::start(&state, store(), 1_000_000);
    for f in ["a.txt", "b.txt"] {
        e.ok("file.write", json!({"path": format!(r"C:\ProgramData\Vendor\{f}"), "data": B64.encode("same bytes")}));
    }
    e.persist.flush().unwrap();
    let sha = xvm_engine::files::sha256_hex(b"same bytes");
    assert_eq!(
        fs::read(state.join("blobs").join(&sha)).unwrap(),
        b"same bytes"
    );
    let log = fs::read_to_string(state.join("hosts/edge-host/log.jsonl")).unwrap();
    assert!(
        log.contains(&sha) && !log.contains(&B64.encode("same bytes")),
        "the log names the blob, not the bytes"
    );
    // A client may not point a write at a blob in the state folder.
    assert_eq!(
        e.call(
            "file.write",
            json!({"path": r"C:\ProgramData\Vendor\c.txt", "blob": sha})
        )
        .unwrap_err(),
        code::BAD_REQUEST
    );
}

#[test]
fn rejected_writes_are_not_logged() {
    let state = temp_dir();
    let mut e = Engine::start(&state, store(), 1_000_000);
    assert!(
        e.call(
            "reg.set_value",
            json!({"key": APP, "name": "X", "type": "REG_DWORD", "data": -1})
        )
        .is_err()
    );
    assert!(
        e.call("file.write", json!({"path": r"C:\Nope\x", "data": ""}))
            .is_err()
    );
    assert!(e.call("proc.exit", json!({"pid": 99999})).is_err());
    e.persist.flush().unwrap();
    assert_eq!(log_lines(&state), 0);
}

#[test]
fn a_torn_last_line_ends_the_replay_there() {
    let state = temp_dir();
    let mut e = Engine::start(&state, store(), 1_000_000);
    e.ok(
        "reg.set_value",
        json!({"key": APP, "name": "Version", "type": "REG_SZ", "data": "kept"}),
    );
    e.persist.flush().unwrap();
    drop(e);
    let mut log = fs::OpenOptions::new()
        .append(true)
        .open(state.join("hosts/edge-host/log.jsonl"))
        .unwrap();
    write!(log, r#"{{"op": "reg.set_value", "params": {{"key": "#).unwrap();
    drop(log);
    let mut again = Engine::start(&state, store(), 1_000_000);
    assert_eq!(again.report.replayed, 1);
    assert!(
        again.report.warnings[0].contains("line 2 is incomplete"),
        "{:?}",
        again.report.warnings
    );
    assert_eq!(
        again.ok("reg.query_value", json!({"key": APP, "name": "Version"}))["data"],
        "kept"
    );
}

#[test]
fn a_missing_blob_ends_the_replay_at_its_change() {
    let state = temp_dir();
    let mut e = Engine::start(&state, store(), 1_000_000);
    e.ok(
        "reg.set_value",
        json!({"key": APP, "name": "Version", "type": "REG_SZ", "data": "kept"}),
    );
    e.ok(
        "file.write",
        json!({"path": r"C:\ProgramData\Vendor\lost.txt", "data": B64.encode("lost")}),
    );
    e.ok(
        "reg.set_value",
        json!({"key": APP, "name": "Version", "type": "REG_SZ", "data": "after"}),
    );
    e.persist.flush().unwrap();
    drop(e);
    fs::remove_file(
        state
            .join("blobs")
            .join(xvm_engine::files::sha256_hex(b"lost")),
    )
    .unwrap();
    let mut again = Engine::start(&state, store(), 1_000_000);
    assert_eq!(again.report.replayed, 1);
    assert!(
        again.report.warnings[0].contains("line 2 (file.write) no longer applies"),
        "{:?}",
        again.report.warnings
    );
    assert_eq!(
        again.ok("reg.query_value", json!({"key": APP, "name": "Version"}))["data"],
        "kept"
    );
    assert_eq!(
        again.text(r"C:\ProgramData\Vendor\lost.txt"),
        json!({"error": "not_found"})
    );
}

#[test]
fn a_changed_profile_discards_the_state() {
    let state = temp_dir();
    let mut e = Engine::start(&state, store(), 1_000_000);
    e.ok(
        "reg.set_value",
        json!({"key": APP, "name": "Version", "type": "REG_SZ", "data": "old profile"}),
    );
    e.persist.flush().unwrap();
    drop(e);

    let mut changed = read(&vector("edge/host.json"));
    changed["hardware"]["cpu"]["cores"] = json!(16);
    let mut again = Engine::start(&state, store_with(changed), 1_000_000);
    assert_eq!(again.report.fresh, ["edge-host"]);
    assert!(
        again.report.warnings[0].contains("profile or base image changed"),
        "{:?}",
        again.report.warnings
    );
    assert_eq!(
        again.ok("reg.query_value", json!({"key": APP, "name": "Version"}))["data"],
        "2.0"
    );
    // The old state was moved aside, not deleted.
    let discarded: Vec<_> = fs::read_dir(state.join("discarded"))
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(discarded.len(), 1);
    assert!(discarded[0].path().join("snapshot.json").is_file());
    assert!(
        discarded[0]
            .file_name()
            .to_string_lossy()
            .starts_with("edge-host-")
    );
}

#[test]
fn state_for_an_unloaded_host_is_kept_and_reported() {
    let state = temp_dir();
    fs::create_dir_all(state.join("hosts/retired-host")).unwrap();
    let e = Engine::start(&state, store(), 1_000_000);
    assert!(
        e.report.warnings.iter().any(|w| w.contains("retired-host")),
        "{:?}",
        e.report.warnings
    );
    assert!(state.join("hosts/retired-host").is_dir());
}

#[test]
fn reset_is_saved_too() {
    let state = temp_dir();
    let mut e = Engine::start(&state, store(), 1_000_000);
    workload(&mut e);
    e.ok("reset", json!({}));
    let before = e.observe();
    e.persist.flush().unwrap();
    drop(e);
    let mut again = Engine::start(&state, store(), 1_000_000);
    assert_eq!(again.observe(), before);
    assert_eq!(again.host().resolved(), read(&vector("edge/resolved.json")));
}
