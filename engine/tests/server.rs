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
        json!(["Microsoft", "Other", "Vendor"])
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
    // The loader's settings: the agent's launch fields and the windows section.
    let agent = w.section("agent").unwrap();
    assert_eq!(agent["pid"], 4812);
    assert_eq!(agent["service"], "WazuhSvc");
    assert_eq!(agent["environment"]["COMPUTERNAME"], "WIN-WEB-01");
    let win = w.section("windows").unwrap();
    assert_eq!(win["system_module_directory"], r"C:\Windows\SysWOW64");
    assert_eq!(
        win["cert_stores"]["ROOT"][0]["name"],
        "DigiCert Assured ID Root CA"
    );
    assert_eq!(
        w.reg_query_value(r"HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage", "ACP")
            .unwrap()["data"],
        "1252"
    );
    // A host without the section gets null.
    assert!(c.section("windows").unwrap().is_null());
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

fn security_event() -> serde_json::Value {
    json!({"provider": "Microsoft-Windows-Security-Auditing", "event_id": 4625})
}

/// Start an `evt.wait` on its own connection and thread.
fn wait_in_thread(
    socket: &Path,
    channel: &'static str,
    after: u64,
    timeout_ms: u64,
) -> thread::JoinHandle<(serde_json::Value, std::time::Duration)> {
    let socket = socket.to_path_buf();
    thread::spawn(move || {
        let mut c = Client::connect(&socket, "edge-host").unwrap();
        let t0 = std::time::Instant::now();
        let r = c.evt_wait(channel, after, timeout_ms).unwrap();
        (r, t0.elapsed())
    })
}

#[test]
fn evt_wait_wakes_on_a_write_without_blocking_others() {
    let (socket, _) = start();
    let a = wait_in_thread(&socket, "Security", 0, 20_000);
    let b = wait_in_thread(&socket, "security", 0, 20_000);
    let other = wait_in_thread(&socket, "System", 0, 300);
    thread::sleep(std::time::Duration::from_millis(150));
    // Other connections carry on while the waits block.
    let mut c = Client::connect(&socket, "edge-host").unwrap();
    assert_eq!(c.section("identity").unwrap()["hostname"], "EDGE-01");
    assert_eq!(c.evt_write("Security", &security_event()).unwrap(), 1);
    for h in [a, b] {
        let (r, took) = h.join().unwrap();
        assert_eq!(
            r,
            json!({"newest_record_id": 1, "reset": false, "timed_out": false})
        );
        assert!(took < std::time::Duration::from_secs(10), "{took:?}");
    }
    // A write to Security does not answer a wait on System.
    let (r, took) = other.join().unwrap();
    assert_eq!(
        r,
        json!({"newest_record_id": 0, "reset": false, "timed_out": true})
    );
    assert!(took >= std::time::Duration::from_millis(300), "{took:?}");
    // A record already after `after` answers at once; timeout 0 is a plain check.
    assert_eq!(c.evt_wait("Security", 0, 0).unwrap()["newest_record_id"], 1);
    assert_eq!(c.evt_wait("Security", 1, 0).unwrap()["timed_out"], true);
}

#[test]
fn evt_wait_reports_resets() {
    let (socket, _) = start();
    let mut c = Client::connect(&socket, "edge-host").unwrap();
    c.evt_write("Security", &security_event()).unwrap();
    c.evt_write("Security", &security_event()).unwrap();
    // Caught up at record 2, waiting for more; then the logs are reset.
    let caught_up = wait_in_thread(&socket, "Security", 2, 20_000);
    // Nothing written yet on System; a reset still wakes the wait.
    let empty = wait_in_thread(&socket, "System", 0, 20_000);
    thread::sleep(std::time::Duration::from_millis(150));
    c.call("reset", json!({})).unwrap();
    for (h, newest) in [(caught_up, 0), (empty, 0)] {
        let (r, took) = h.join().unwrap();
        assert_eq!(
            r,
            json!({"newest_record_id": newest, "reset": true, "timed_out": false})
        );
        assert!(took < std::time::Duration::from_secs(10));
    }
    // A reader whose position is beyond the log learns of the reset at once.
    assert_eq!(c.evt_wait("Security", 7, 5_000).unwrap()["reset"], true);
}

#[test]
fn evt_wait_errors() {
    let (socket, _) = start();
    let mut c = Client::connect(&socket, "edge-host").unwrap();
    assert_eq!(
        engine_code(c.evt_wait("Security", 0, 60_001).unwrap_err()),
        "bad_request"
    );
    assert_eq!(
        engine_code(c.evt_wait("Nope", 0, 10).unwrap_err()),
        "not_found"
    );
}

#[test]
fn uninstall_keys_come_from_the_software_list() {
    let (socket, _) = start();
    let mut w = Client::connect(&socket, "win-web-01").unwrap();
    let root = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    let wow = r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
    // The example host's software entry, as Windows lists it.
    assert_eq!(
        w.reg_enum_subkeys(root).unwrap(),
        json!(["Example Web Server"])
    );
    let key = format!(r"{root}\Example Web Server");
    assert_eq!(
        w.reg_query_value(&key, "DisplayVersion").unwrap(),
        json!({"name": "DisplayVersion", "type": "REG_SZ", "data": "2.4.1"})
    );
    assert_eq!(
        w.reg_query_value(&key, "Publisher").unwrap()["data"],
        "Example Corp"
    );
    // A package installed at run time appears at once; 32-bit ones under WOW6432Node.
    w.call(
        "list.upsert",
        json!({"name": "software", "item": {"name": "Old Tool", "version": "1.0",
            "architecture": "x86", "uninstall_key": "{1234}", "install_date": "2026-03-04"}}),
    )
    .unwrap();
    let old = format!(r"{wow}\{{1234}}");
    assert_eq!(
        w.reg_query_value(&old, "DisplayName").unwrap()["data"],
        "Old Tool"
    );
    assert_eq!(
        w.reg_query_value(&old, "InstallDate").unwrap()["data"],
        "20260304"
    );
    assert!(w.call("reg.key_exists", json!({"key": wow})).unwrap() == json!(true));
    // Removing the package removes its key.
    w.call(
        "list.remove",
        json!({"name": "software", "item": "Old Tool"}),
    )
    .unwrap();
    assert_eq!(
        engine_code(w.reg_query_value(&old, "DisplayName").unwrap_err()),
        "not_found"
    );
    // The resolved host stays the profile: derived keys are not listed there.
    let resolved = w.call("resolved", json!({})).unwrap();
    assert!(
        !resolved["registry"]["keys"]
            .as_object()
            .unwrap()
            .keys()
            .any(|k| k.contains("Uninstall\\Example"))
    );
    // A key the host writes at the same path replaces the derived one. Agents
    // only read these keys; a write starts a run-time key of its own.
    w.reg_set_value(
        &key,
        "DisplayVersion",
        &json!({"type": "REG_SZ", "data": "9.9"}),
    )
    .unwrap();
    assert_eq!(
        w.reg_query_value(&key, "DisplayVersion").unwrap()["data"],
        "9.9"
    );
    assert_eq!(
        engine_code(w.reg_query_value(&key, "Publisher").unwrap_err()),
        "not_found"
    );
}
