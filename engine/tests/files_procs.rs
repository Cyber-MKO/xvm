//! File and process state: profile layers, run-time changes, the blob store.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use xvm_engine::files::sha256_hex;
use xvm_engine::protocol::{Request, code};
use xvm_engine::server::Server;
use xvm_engine::store::{Base, Host, Store};

const T1: &str = "2026-10-16T10:00:00Z";

fn read(p: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap()
}

fn vector(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name)
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

struct Conn {
    server: Server,
    host: Option<Arc<Host>>,
    gaps: Captured,
    next: u64,
}

impl Conn {
    fn with(base: Value, host: Value) -> Self {
        let base = Arc::new(Base::from_value(base).unwrap());
        let host = Arc::new(Host::from_value(host, base.clone()).unwrap());
        let name = host.name.clone();
        let mut store = Store::default();
        store.bases.insert(base.name.clone(), base);
        store.hosts.insert(name.clone(), host);
        let gaps = Captured::default();
        let server = Server::new(
            Arc::new(store),
            Arc::new(Mutex::new(Box::new(gaps.clone()))),
        );
        let mut c = Conn {
            server,
            host: None,
            gaps,
            next: 1,
        };
        c.ok("hello", json!({"host": name}));
        c
    }

    fn edge() -> Self {
        Self::with(
            read(&vector("edge/base.json")),
            read(&vector("edge/host.json")),
        )
    }

    fn call(&mut self, op: &str, params: Value) -> Result<Value, String> {
        let req = Request {
            id: self.next,
            op: op.into(),
            params: params.as_object().cloned().unwrap_or_default(),
        };
        self.next += 1;
        let resp = self.server.handle(&req, &mut self.host);
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

    fn err(&mut self, op: &str, params: Value) -> String {
        self.call(op, params).expect_err(op)
    }

    fn text(&mut self, path: &str) -> String {
        let r = self.ok("file.read", json!({"path": path}));
        String::from_utf8(B64.decode(r["data"].as_str().unwrap()).unwrap()).unwrap()
    }

    fn write(&mut self, path: &str, text: &str, extra: Value) -> Result<Value, String> {
        let mut p = json!({"path": path, "data": B64.encode(text), "time": T1});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        self.call("file.write", p)
    }

    fn names(&mut self, dir: &str) -> Vec<String> {
        self.ok("file.list", json!({"path": dir}))
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["path"].as_str().unwrap().to_string())
            .collect()
    }
}

const HOSTS: &str = r"C:\Windows\System32\drivers\etc\hosts";

#[test]
fn profile_files() {
    let mut c = Conn::edge();
    // The profile replaced the base's hosts file; any case and slash direction finds it.
    assert_eq!(
        c.text("c:/windows/SYSTEM32/drivers/ETC/HOSTS"),
        "# edge hosts\r\n192.0.2.1 gateway\r\n"
    );
    let st = c.ok("file.stat", json!({"path": HOSTS}));
    assert_eq!(st["path"], HOSTS);
    assert_eq!(st["size"], 33);
    assert_eq!(
        st["sha256"],
        sha256_hex(b"# edge hosts\r\n192.0.2.1 gateway\r\n")
    );
    assert_eq!(st["modified"], "2026-01-01T00:00:00Z");
    assert_eq!(st["has_content"], true);
    // A vendor file: metadata from the capture, no bytes.
    let k32 = c.ok(
        "file.stat",
        json!({"path": r"C:\Windows\System32\kernel32.dll"}),
    );
    assert_eq!(k32["size"], 787456);
    assert_eq!(k32["has_content"], false);
    assert_eq!(
        k32["sha256"],
        "0000000000000000000000000000000000000000000000000000000000000001"
    );
    // The profile removed C:\Windows\Temp and everything below it.
    assert_eq!(
        c.err("file.stat", json!({"path": r"C:\Windows\Temp\old.log"})),
        code::NOT_FOUND
    );
    assert_eq!(
        c.err("file.stat", json!({"path": r"C:\Windows\Temp"})),
        code::NOT_FOUND
    );
}

#[test]
fn listings_and_implied_directories() {
    let mut c = Conn::edge();
    assert_eq!(
        c.names(r"C:\"),
        [r"C:\ProgramData", r"C:\Users", r"C:\Windows"]
    );
    assert_eq!(c.names(r"C:\Windows"), [r"C:\Windows\System32"]);
    assert_eq!(
        c.names(r"c:\windows\system32"),
        [
            r"C:\Windows\System32\drivers",
            r"C:\Windows\System32\kernel32.dll"
        ]
    );
    let root = c.ok("file.stat", json!({"path": "C:"}));
    assert_eq!(
        root,
        json!({"path": r"C:\", "type": "dir", "implied": true})
    );
    let windows = c.ok("file.stat", json!({"path": r"C:\Windows"}));
    assert_eq!(windows["attributes"], json!(["system"]));
    assert_eq!(windows.get("implied"), None);
    assert_eq!(
        c.err("file.list", json!({"path": HOSTS})),
        code::NOT_A_DIRECTORY
    );
    assert_eq!(c.err("file.list", json!({"path": r"D:\"})), code::NOT_FOUND);
    assert_eq!(
        c.err("file.read", json!({"path": r"C:\Windows"})),
        code::IS_DIRECTORY
    );
    assert_eq!(
        c.err("file.stat", json!({"path": r"Windows\x"})),
        code::BAD_REQUEST
    );
    assert_eq!(
        c.err("file.stat", json!({"path": r"C:\bad|name"})),
        code::BAD_REQUEST
    );
}

#[test]
fn reading_vendor_bytes_is_a_logged_gap() {
    let mut c = Conn::edge();
    assert_eq!(
        c.err(
            "file.read",
            json!({"path": r"C:\Windows\System32\kernel32.dll"})
        ),
        code::NO_CONTENT
    );
    let log = String::from_utf8(c.gaps.0.lock().unwrap().clone()).unwrap();
    let rec: Value = serde_json::from_str(log.trim()).unwrap();
    assert_eq!(rec["gap"], "file-content");
    assert_eq!(rec["path"], r"C:\Windows\System32\kernel32.dll");
    assert_eq!(rec["host"], "edge-host");
    assert_eq!(rec["agent"]["product"], "wazuh");
}

#[test]
fn partial_reads() {
    let mut c = Conn::edge();
    let r = c.ok(
        "file.read",
        json!({"path": HOSTS, "offset": 2, "length": 4}),
    );
    assert_eq!(B64.decode(r["data"].as_str().unwrap()).unwrap(), b"edge");
    assert_eq!(r["eof"], false);
    let r = c.ok("file.read", json!({"path": HOSTS, "offset": 1000}));
    assert_eq!(r, json!({"data": "", "eof": true}));
}

#[test]
fn writes() {
    let mut c = Conn::edge();
    let dir = r"C:\ProgramData\Vendor";
    // New file: spelled after its parent, Windows archive attribute, times set.
    let r = c
        .write(r"c:\programdata\vendor\New.log", "line1\n", json!({}))
        .unwrap();
    assert_eq!(r["path"], r"C:\ProgramData\Vendor\New.log");
    assert_eq!(r["size"], 6);
    c.write(
        r"C:\ProgramData\Vendor\New.log",
        "line2\n",
        json!({"append": true}),
    )
    .unwrap();
    assert_eq!(c.text(r"C:\ProgramData\Vendor\new.log"), "line1\nline2\n");
    c.write(
        r"C:\ProgramData\Vendor\New.log",
        "LINE",
        json!({"offset": 6}),
    )
    .unwrap();
    assert_eq!(c.text(r"C:\ProgramData\Vendor\New.log"), "line1\nLINE2\n");
    c.write(r"C:\ProgramData\Vendor\New.log", "!", json!({"offset": 14}))
        .unwrap();
    assert_eq!(
        c.text(r"C:\ProgramData\Vendor\New.log"),
        "line1\nLINE2\n\0\0!"
    );
    let st = c.ok(
        "file.stat",
        json!({"path": r"C:\ProgramData\Vendor\New.log"}),
    );
    assert_eq!(st["created"], T1);
    assert_eq!(st["attributes"], json!(["archive"]));
    assert_eq!(st["sha256"], sha256_hex(b"line1\nLINE2\n\0\0!"));
    assert_eq!(
        c.names(dir),
        [
            r"C:\ProgramData\Vendor\config.ini",
            r"C:\ProgramData\Vendor\New.log"
        ]
    );

    // Changing a profile file copies it; the profile view and other hosts are untouched.
    c.write(
        r"C:\ProgramData\Vendor\config.ini",
        "[main]\nlevel=2\n",
        json!({}),
    )
    .unwrap();
    assert_eq!(
        c.text(r"C:\ProgramData\Vendor\config.ini"),
        "[main]\nlevel=2\n"
    );
    let h = c.host.clone().unwrap();
    let nk = h.rules().norm(r"C:\ProgramData\Vendor\config.ini");
    assert_eq!(
        h.profile_files().get(&nk).unwrap().content.bytes().unwrap(),
        b"[main]\nlevel=1\n"
    );

    // Errors.
    assert_eq!(
        c.write(r"C:\Nope\x.txt", "x", json!({})).unwrap_err(),
        code::NOT_FOUND
    );
    assert_eq!(
        c.write(r"C:\Windows", "x", json!({})).unwrap_err(),
        code::IS_DIRECTORY
    );
    assert_eq!(
        c.write(r"C:\Windows\System32", "x", json!({})).unwrap_err(),
        code::IS_DIRECTORY
    );
    assert_eq!(
        c.write(&format!(r"{HOSTS}\child"), "x", json!({}))
            .unwrap_err(),
        code::NOT_A_DIRECTORY
    );
    assert_eq!(
        c.write(r"C:\", "x", json!({})).unwrap_err(),
        code::IS_DIRECTORY
    );
    assert_eq!(
        c.write(HOSTS, "x", json!({"append": true, "offset": 1}))
            .unwrap_err(),
        code::BAD_REQUEST
    );
    assert_eq!(
        c.err("file.write", json!({"path": HOSTS, "data": "%%%"})),
        code::BAD_REQUEST
    );
    // A vendor file can be replaced, but not appended to: its old bytes are unknown.
    let k32 = r"C:\Windows\System32\kernel32.dll";
    assert_eq!(
        c.write(k32, "x", json!({"append": true})).unwrap_err(),
        code::NO_CONTENT
    );
    c.write(k32, "patched", json!({})).unwrap();
    assert_eq!(c.text(k32), "patched");
}

#[test]
fn read_only_files_refuse_writes() {
    let mut c = Conn::edge();
    c.ok(
        "file.set",
        json!({"path": HOSTS, "patch": {"attributes": ["readonly", "archive"]}}),
    );
    assert_eq!(
        c.write(HOSTS, "x", json!({})).unwrap_err(),
        code::ACCESS_DENIED
    );
    assert_eq!(
        c.err(
            "file.set",
            json!({"path": HOSTS, "patch": {"attributes": ["shiny"]}})
        ),
        code::BAD_REQUEST
    );
    assert_eq!(
        c.err("file.set", json!({"path": HOSTS, "patch": {"size": 1}})),
        code::BAD_REQUEST
    );
    assert_eq!(
        c.err(
            "file.set",
            json!({"path": HOSTS, "patch": {"modified": "today"}})
        ),
        code::BAD_REQUEST
    );
    c.ok(
        "file.set",
        json!({"path": HOSTS, "patch": {"attributes": [], "modified": T1}}),
    );
    c.write(HOSTS, "ok", json!({})).unwrap();
}

#[test]
fn directories_delete_and_rename() {
    let mut c = Conn::edge();
    c.ok("file.mkdir", json!({"path": r"C:\ProgramData\Vendor\logs"}));
    assert_eq!(
        c.err("file.mkdir", json!({"path": r"C:\ProgramData\Vendor\LOGS"})),
        code::EXISTS
    );
    assert_eq!(
        c.err("file.mkdir", json!({"path": r"C:\Windows\System32"})),
        code::EXISTS
    );
    assert_eq!(
        c.err("file.mkdir", json!({"path": r"C:\a\b"})),
        code::NOT_FOUND
    );
    c.write(r"C:\ProgramData\Vendor\logs\a.log", "a", json!({}))
        .unwrap();

    assert_eq!(
        c.err("file.delete", json!({"path": r"C:\ProgramData\Vendor"})),
        code::NOT_EMPTY
    );
    // Rename a directory: its children move with it and keep their own spelling.
    let r = c.ok(
        "file.rename",
        json!({"from": r"c:\programdata\vendor", "to": r"C:\ProgramData\Moved"}),
    );
    assert_eq!(r["from"], r"C:\ProgramData\Vendor");
    assert_eq!(r["to"], r"C:\ProgramData\Moved");
    assert_eq!(r["moved"], 3); // config.ini, logs, logs\a.log; Vendor itself is implied
    assert_eq!(
        c.names(r"C:\ProgramData\Moved"),
        [
            r"C:\ProgramData\Moved\config.ini",
            r"C:\ProgramData\Moved\logs"
        ]
    );
    assert_eq!(c.text(r"C:\ProgramData\Moved\logs\a.log"), "a");
    assert_eq!(
        c.err("file.stat", json!({"path": r"C:\ProgramData\Vendor"})),
        code::NOT_FOUND
    );
    assert_eq!(
        c.err(
            "file.rename",
            json!({"from": r"C:\ProgramData\Moved", "to": r"C:\ProgramData\Moved\x"})
        ),
        code::BAD_REQUEST
    );
    assert_eq!(
        c.err(
            "file.rename",
            json!({"from": r"C:\ProgramData\Moved", "to": r"C:\Windows"})
        ),
        code::EXISTS
    );
    assert_eq!(
        c.err(
            "file.rename",
            json!({"from": r"C:\Gone", "to": r"C:\Other"})
        ),
        code::NOT_FOUND
    );

    // Renaming an implied directory (System32 is not listed itself) moves what is below it.
    c.ok(
        "file.rename",
        json!({"from": r"C:\Windows\System32\drivers", "to": r"C:\Windows\drv"}),
    );
    assert_eq!(
        c.text(r"C:\Windows\drv\etc\hosts"),
        "# edge hosts\r\n192.0.2.1 gateway\r\n"
    );

    let r = c.ok(
        "file.delete",
        json!({"path": r"C:\ProgramData\Moved", "recursive": true}),
    );
    assert_eq!(r["deleted"], 3);
    assert_eq!(c.names(r"C:\ProgramData"), Vec::<String>::new());
    c.ok(
        "file.delete",
        json!({"path": r"C:\Users\svc-backup\notes.txt"}),
    );
    // Directories implied only by that file stay, as on a real file system.
    assert_eq!(c.names(r"C:\Users\svc-backup"), Vec::<String>::new());
    assert_eq!(c.names(r"C:\Users"), [r"C:\Users\svc-backup"]);
    assert_eq!(
        c.err("file.delete", json!({"path": r"C:\"})),
        code::BAD_REQUEST
    );
    assert_eq!(
        c.err("file.delete", json!({"path": r"C:\Nope"})),
        code::NOT_FOUND
    );
}

#[test]
fn file_changes_are_journaled_and_reset() {
    let mut c = Conn::edge();
    c.write(r"C:\ProgramData\Vendor\x.txt", "x", json!({}))
        .unwrap();
    c.ok(
        "file.delete",
        json!({"path": r"C:\ProgramData\Vendor\config.ini", "time": T1}),
    );
    let j = c.ok("changes", json!({}));
    assert_eq!(
        j["changes"][0],
        json!({"path": r"C:\ProgramData\Vendor\x.txt", "size": 1, "mode": "replace",
        "op": "file.write", "seq": 1, "time": T1})
    );
    assert_eq!(j["changes"][1]["op"], "file.delete");
    assert_eq!(j["changes"][1]["deleted"], 1);
    // resolved shows run-time bytes as base64.
    let h = c.host.clone().unwrap();
    let files = h.resolved()["files"].clone();
    let x = files
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == r"C:\ProgramData\Vendor\x.txt")
        .unwrap()
        .clone();
    assert_eq!(x["content"], json!({"base64": "eA=="}));
    c.ok("reset", json!({}));
    assert_eq!(h.resolved(), read(&vector("edge/resolved.json")));
    assert_eq!(
        c.text(r"C:\ProgramData\Vendor\config.ini"),
        "[main]\nlevel=1\n"
    );
}

#[test]
fn rejected_file_ops_change_nothing() {
    let mut c = Conn::edge();
    let before = c.host.clone().unwrap().resolved();
    let _ = c.write(r"C:\Nope\x", "x", json!({}));
    let _ = c.call(
        "file.delete",
        json!({"path": r"C:\ProgramData", "recursive": "yes"}),
    );
    let _ = c.call(
        "file.rename",
        json!({"from": r"C:\ProgramData", "to": r"C:\Windows"}),
    );
    assert_eq!(c.ok("changes", json!({}))["last_seq"], 0);
    assert_eq!(c.host.clone().unwrap().resolved(), before);
}

#[test]
fn boot_processes() {
    let mut c = Conn::edge();
    let list = c.ok("proc.list", json!({}));
    let by_id = |id: &str| {
        list.as_array()
            .unwrap()
            .iter()
            .find(|p| p["profile_id"] == id)
            .unwrap()
            .clone()
    };
    let system = by_id("system");
    assert_eq!(system["pid"], 4);
    assert_eq!(system["ppid"], 0);
    assert_eq!(system["start_time"], "2026-10-16T08:00:00.000Z");
    let smss = by_id("smss");
    assert_eq!(smss["ppid"], 4);
    assert_eq!(smss["start_time"], "2026-10-16T08:00:01.000Z");
    let backup = by_id("backup");
    assert_eq!(backup["ppid"], by_id("svchost-1")["pid"]);
    assert_eq!(backup["user"], r"EDGE-01\svc-backup");
    assert_eq!(
        by_id("svchost-2")["command_line"],
        "svchost.exe -k netsvcs -p"
    );
    assert_eq!(list.as_array().unwrap().len(), 5); // spooler removed by the profile
    for p in list.as_array().unwrap() {
        assert_eq!(p["pid"].as_u64().unwrap() % 4, 0, "{p}");
    }
    // Deterministic: the same host gets the same PIDs every time.
    let again = Conn::edge().ok("proc.list", json!({}));
    assert_eq!(list, again);
}

#[test]
fn start_and_exit() {
    let mut c = Conn::edge();
    let parent = c.ok("proc.list", json!({}))[1]["pid"].as_u64().unwrap();
    let p = c.ok("proc.start", json!({"image": "wazuh-agent.exe", "path": r"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe",
        "parent_pid": parent, "user": r"NT AUTHORITY\SYSTEM", "native_pid": 31337, "time": T1}));
    let pid = p["pid"].as_u64().unwrap();
    assert_eq!(pid % 4, 0);
    assert_eq!(p["ppid"], parent);
    assert_eq!(p["start_time"], T1);
    assert_eq!(p["native_pid"], 31337);
    assert_eq!(
        c.ok("proc.get", json!({"pid": pid}))["image"],
        "wazuh-agent.exe"
    );
    assert_eq!(c.ok("proc.list", json!({})).as_array().unwrap().len(), 6);
    let child = c.ok("proc.start", json!({"image": "cmd.exe", "parent_pid": pid}))["pid"]
        .as_u64()
        .unwrap();
    // A parent's exit leaves its children running with their old parent PID, as on Windows.
    c.ok("proc.exit", json!({"pid": pid, "exit_code": 1, "time": T1}));
    assert_eq!(c.err("proc.get", json!({"pid": pid})), code::NOT_FOUND);
    assert_eq!(c.ok("proc.get", json!({"pid": child}))["ppid"], pid);
    let j = c.ok("changes", json!({}));
    assert_eq!(
        j["changes"][2],
        json!({"op": "proc.exit", "pid": pid, "ppid": parent, "image": "wazuh-agent.exe",
        "exit_code": 1, "seq": 3, "time": T1})
    );

    assert_eq!(
        c.err("proc.start", json!({"image": "x.exe", "parent_pid": pid})),
        code::NOT_FOUND
    );
    assert_eq!(c.err("proc.start", json!({"path": "x"})), code::BAD_REQUEST);
    assert_eq!(
        c.err("proc.start", json!({"image": "x.exe", "colour": "blue"})),
        code::BAD_REQUEST
    );
    assert_eq!(
        c.err("proc.start", json!({"image": "x.exe", "session": "one"})),
        code::BAD_REQUEST
    );
    assert_eq!(c.err("proc.exit", json!({"pid": pid})), code::NOT_FOUND);
    assert_eq!(c.err("proc.exit", json!({"pid": "4"})), code::BAD_REQUEST);

    // reset restores the boot table, with the same PIDs.
    let boot = Conn::edge().ok("proc.list", json!({}));
    c.ok("reset", json!({}));
    assert_eq!(c.ok("proc.list", json!({})), boot);
}

#[test]
fn start_with_a_requested_pid() {
    let mut c = Conn::edge();
    let boot = c.ok("proc.list", json!({}))[1]["pid"].as_u64().unwrap();
    // The loader registers the agent under the PID its profile gives.
    let p = c.ok(
        "proc.start",
        json!({"image": "wazuh-agent.exe", "pid": 1200, "native_pid": 777}),
    );
    assert_eq!(p["pid"], 1200);
    assert_eq!(c.ok("proc.get", json!({"pid": 1200}))["native_pid"], 777);
    let j = c.ok("changes", json!({}));
    assert_eq!(j["changes"][0]["pid"], 1200);
    // In use, by a boot process or a run-time one.
    for pid in [boot, 1200] {
        assert_eq!(
            c.err("proc.start", json!({"image": "x.exe", "pid": pid})),
            code::EXISTS
        );
    }
    // Windows PIDs are non-zero multiples of 4 below 65536.
    for pid in [
        json!(0),
        json!(1202),
        json!(65536),
        json!("1204"),
        json!(-4),
    ] {
        assert_eq!(
            c.err("proc.start", json!({"image": "x.exe", "pid": pid})),
            code::BAD_REQUEST,
            "{pid}"
        );
    }
    // A rejected request changes nothing.
    assert_eq!(c.ok("changes", json!({}))["last_seq"], 1);
    // The generator never hands out a requested PID, even after it exits.
    c.ok("proc.exit", json!({"pid": 1200}));
    for _ in 0..3000 {
        let pid = c.ok("proc.start", json!({"image": "w.exe"}))["pid"]
            .as_u64()
            .unwrap();
        assert_ne!(pid, 1200);
    }
}

#[test]
fn many_processes_never_share_a_pid() {
    let mut c = Conn::edge();
    let mut seen = std::collections::BTreeSet::new();
    for p in c.ok("proc.list", json!({})).as_array().unwrap() {
        seen.insert(p["pid"].as_u64().unwrap());
    }
    for _ in 0..3000 {
        let pid = c.ok("proc.start", json!({"image": "w.exe"}))["pid"]
            .as_u64()
            .unwrap();
        assert!(seen.insert(pid), "pid {pid} handed out twice");
    }
}

fn linux_base() -> Value {
    json!({"schema": 1, "kind": "base-image", "name": "lin", "os": "linux",
        "os_info": {"last_boot": "2026-10-16T00:00:00Z"},
        "files": [
            {"path": "/etc", "type": "dir", "mode": "0755"},
            {"path": "/etc/hostname", "content": {"text": "lin\n"}},
            {"path": "/etc/Hostname", "content": {"text": "other\n"}}
        ],
        "processes": [{"id": "init", "image": "systemd", "pid": 1}, {"id": "sshd", "image": "sshd", "parent": "init"}]})
}

#[test]
fn linux_is_case_sensitive_with_sequential_pids() {
    let host = json!({"schema": 1, "kind": "host-profile", "name": "lin-01", "base": "lin", "os": "linux",
        "identity": {"hostname": "lin-01"}});
    let mut c = Conn::with(linux_base(), host);
    assert_eq!(c.text("/etc/hostname"), "lin\n");
    assert_eq!(c.text("/etc/Hostname"), "other\n");
    assert_eq!(c.names("/"), ["/etc"]);
    assert_eq!(c.names("/etc"), ["/etc/Hostname", "/etc/hostname"]);
    let pids: Vec<u64> = c
        .ok("proc.list", json!({}))
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["pid"].as_u64().unwrap())
        .collect();
    assert_eq!(pids, [1, 2]);
    assert_eq!(c.ok("proc.start", json!({"image": "bash"}))["pid"], 3);
    assert_eq!(
        c.ok("proc.start", json!({"image": "agent", "pid": 4001}))["pid"],
        4001
    );
    assert_eq!(
        c.err("proc.start", json!({"image": "x", "pid": 1})),
        code::EXISTS
    );
    assert_eq!(
        c.err("proc.start", json!({"image": "x", "pid": 0})),
        code::BAD_REQUEST
    );
    assert_eq!(
        c.err(
            "file.set",
            json!({"path": "/etc/hostname", "patch": {"attributes": ["hidden"]}})
        ),
        code::BAD_REQUEST
    );
    c.ok(
        "file.set",
        json!({"path": "/etc/hostname", "patch": {"mode": "0600", "owner": "root"}}),
    );
    assert_eq!(
        c.ok("file.stat", json!({"path": "/etc/hostname"}))["mode"],
        "0600"
    );
    // No Windows archive attribute on Linux.
    c.write("/etc/new", "n", json!({})).unwrap();
    assert_eq!(
        c.ok("file.stat", json!({"path": "/etc/new"}))
            .get("attributes"),
        None
    );
    assert_eq!(
        c.err("file.stat", json!({"path": r"C:\x"})),
        code::BAD_REQUEST
    );
}

#[test]
fn blobs_are_shared_and_checked() {
    let dir = std::env::temp_dir().join(format!("xvm-blobs-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    for sub in ["bases", "hosts", "blobs"] {
        fs::create_dir_all(dir.join(sub)).unwrap();
    }
    let data = b"shared bytes";
    let sha = sha256_hex(data);
    fs::write(dir.join("blobs").join(&sha), data).unwrap();
    let mut base = linux_base();
    base["files"][1] = json!({"path": "/etc/hostname", "content": {"blob": sha}, "size": data.len(), "sha256": sha});
    fs::write(dir.join("bases/lin.json"), base.to_string()).unwrap();
    for h in ["a", "b"] {
        let host = json!({"schema": 1, "kind": "host-profile", "name": h, "base": "lin", "os": "linux", "identity": {"hostname": h}});
        fs::write(dir.join(format!("hosts/{h}.json")), host.to_string()).unwrap();
    }
    fs::write(
        dir.join("compiled.json"),
        r#"{"schema": 1, "bases": ["lin"], "hosts": ["a", "b"]}"#,
    )
    .unwrap();
    let store = Store::load(&dir).unwrap();
    let a = &store.hosts["a"];
    let b = &store.hosts["b"];
    let nk = a.rules().norm("/etc/hostname");
    let ba = a
        .profile_files()
        .get(&nk)
        .unwrap()
        .content
        .bytes()
        .unwrap()
        .as_ptr();
    let bb = b
        .profile_files()
        .get(&nk)
        .unwrap()
        .content
        .bytes()
        .unwrap()
        .as_ptr();
    assert_eq!(ba, bb, "both hosts read the one copy in the base");
    // A tampered blob is refused at load.
    fs::write(dir.join("blobs").join(&sha), b"tampered").unwrap();
    let err = Store::load(&dir).unwrap_err();
    assert!(err.0.contains("does not match its name"), "{}", err.0);
    let _ = fs::remove_dir_all(&dir);
}
