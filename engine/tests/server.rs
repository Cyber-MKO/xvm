//! End to end: compiled profiles on disk, the daemon on a Unix socket, the client.

use std::fs;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::json;
use xvm_engine::client::{Client, ClientError};
use xvm_engine::server::Server;
use xvm_engine::store::Store;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("xvm-engine-test-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// Lay out the vectors the way `xvm-profile compile` writes them.
fn compiled(dir: &Path) {
    let v = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    fs::create_dir_all(dir.join("bases")).unwrap();
    fs::create_dir_all(dir.join("hosts")).unwrap();
    fs::copy(v.join("edge/base.json"), dir.join("bases/edge-base.json")).unwrap();
    fs::copy(v.join("edge/host.json"), dir.join("hosts/edge-host.json")).unwrap();
    fs::copy(
        v.join("example/base.json"),
        dir.join("bases/windows-example.json"),
    )
    .unwrap();
    fs::copy(
        v.join("example/host.json"),
        dir.join("hosts/win-web-01.json"),
    )
    .unwrap();
    fs::write(
        dir.join("compiled.json"),
        r#"{"schema": 1, "bases": ["edge-base", "windows-example"], "hosts": ["edge-host", "win-web-01"]}"#,
    )
    .unwrap();
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn start() -> (PathBuf, Captured) {
    let dir = temp_dir();
    compiled(&dir.join("compiled"));
    let store = Store::load(&dir.join("compiled")).unwrap();
    assert_eq!(store.bases.len(), 2);
    assert_eq!(store.hosts.len(), 2);
    let socket = dir.join("engine.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let gaps = Captured::default();
    let server = Arc::new(Server::new(
        Arc::new(store),
        Arc::new(Mutex::new(Box::new(gaps.clone()))),
    ));
    thread::spawn(move || server.run(listener));
    (socket, gaps)
}

fn engine_code(e: ClientError) -> String {
    match e {
        ClientError::Engine(b) => b.code,
        other => panic!("expected an engine error, got {other}"),
    }
}

#[test]
fn queries_over_the_socket() {
    let (socket, _) = start();
    let mut c = Client::connect(&socket, "edge-host").unwrap();
    assert_eq!(
        c.section("identity").unwrap(),
        json!({"hostname": "EDGE-01"})
    );
    assert_eq!(
        c.reg_query_value(r"hklm\software\vendor\app", "version")
            .unwrap(),
        json!({"name": "Version", "type": "REG_SZ", "data": "2.0"})
    );
    assert_eq!(
        c.reg_enum_subkeys(r"HKLM\SOFTWARE").unwrap(),
        json!(["Other", "Vendor"])
    );
    assert_eq!(
        c.list("services").unwrap()[1],
        json!({"name": "Beta", "state": "stopped", "start_mode": "manual"})
    );
    assert_eq!(
        c.call(
            "reg.key_exists",
            json!({"key": r"HKLM\SOFTWARE\Vendor\Legacy"})
        )
        .unwrap(),
        json!(false)
    );
    let want: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/edge/resolved.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(c.call("resolved", json!({})).unwrap(), want);

    // Writes go through the same connection and show up in the journal.
    c.reg_set_value(
        r"HKLM\SOFTWARE\Vendor\App",
        "Version",
        &json!({"type": "REG_SZ", "data": "4.0"}),
    )
    .unwrap();
    assert_eq!(
        c.reg_query_value(r"HKLM\SOFTWARE\Vendor\App", "Version")
            .unwrap()["data"],
        "4.0"
    );
    assert_eq!(c.changes(0).unwrap()["last_seq"], 1);

    // A second connection serves a different host on the same engine.
    let mut w = Client::connect(&socket, "win-web-01").unwrap();
    assert_eq!(w.section("identity").unwrap()["hostname"], "WIN-WEB-01");
}

#[test]
fn errors() {
    let (socket, _) = start();
    assert_eq!(
        engine_code(Client::connect(&socket, "nobody").err().unwrap()),
        "unknown_host"
    );
    let mut c = Client::connect(&socket, "edge-host").unwrap();
    assert_eq!(
        engine_code(c.reg_query_value(r"HKLM\SOFTWARE\Nope", "x").unwrap_err()),
        "not_found"
    );
    assert_eq!(
        engine_code(c.section("secrets").unwrap_err()),
        "bad_request"
    );
    assert_eq!(
        engine_code(c.call("reg.query_value", json!({"key": 5})).unwrap_err()),
        "bad_request"
    );
}

#[test]
fn hello_is_required() {
    let (socket, _) = start();
    let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    xvm_engine::protocol::write_message(
        &mut stream,
        &json!({"id": 7, "op": "section", "name": "identity"}),
    )
    .unwrap();
    let body = xvm_engine::protocol::read_message(&mut stream)
        .unwrap()
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp["id"], 7);
    assert_eq!(resp["error"]["code"], "no_host");
}

#[test]
fn unsupported_ops_are_logged_as_gaps() {
    let (socket, gaps) = start();
    let mut c = Client::connect(&socket, "edge-host").unwrap();
    assert_eq!(
        engine_code(
            c.call("wmi.query", json!({"query": "SELECT * FROM Win32_Process"}))
                .unwrap_err()
        ),
        "unsupported"
    );
    let log = String::from_utf8(gaps.0.lock().unwrap().clone()).unwrap();
    let record: serde_json::Value = serde_json::from_str(log.trim()).unwrap();
    assert_eq!(
        record,
        json!({"gap": "engine-op", "op": "wmi.query", "host": "edge-host",
               "agent": {"product": "wazuh", "version": "4.14.2"}})
    );
}
