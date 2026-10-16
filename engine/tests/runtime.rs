//! Run-time changes: registry writes, list and section changes, the journal, reset.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::thread;

use serde_json::{Value, json};
use xvm_engine::protocol::{Request, code};
use xvm_engine::server::Server;
use xvm_engine::store::{Base, Host, Store};

const T1: &str = "2026-10-16T10:00:00Z";
const T2: &str = "2026-10-16T10:00:05.250Z";

fn read(p: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap()
}

fn vector(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name)
}

/// A server holding the edge host, and a connection bound to it.
struct Conn {
    server: Server,
    host: Option<Arc<Host>>,
    next: u64,
}

impl Conn {
    fn new() -> Self {
        let base = Arc::new(Base::from_value(read(&vector("edge/base.json"))).unwrap());
        let host =
            Arc::new(Host::from_value(read(&vector("edge/host.json")), base.clone()).unwrap());
        let mut store = Store::default();
        store.bases.insert(base.name.clone(), base);
        store.hosts.insert(host.name.clone(), host);
        let gaps: Box<dyn std::io::Write + Send> = Box::new(std::io::sink());
        let server = Server::new(Arc::new(store), Arc::new(std::sync::Mutex::new(gaps)));
        let mut c = Conn {
            server,
            host: None,
            next: 1,
        };
        c.ok("hello", json!({"host": "edge-host"}));
        c
    }

    fn call(&mut self, op: &str, params: Value) -> Result<Value, (String, String)> {
        let req = Request {
            id: self.next,
            op: op.into(),
            params: params.as_object().cloned().unwrap_or_default(),
        };
        self.next += 1;
        let resp = self.server.handle(&req, &mut self.host);
        assert_eq!(resp.id, req.id);
        match (resp.ok, resp.result, resp.error) {
            (true, r, _) => Ok(r.unwrap_or(Value::Null)),
            (false, _, Some(e)) => Err((e.code, e.message)),
            _ => panic!("malformed response"),
        }
    }

    fn ok(&mut self, op: &str, params: Value) -> Value {
        self.call(op, params)
            .unwrap_or_else(|e| panic!("{op}: {e:?}"))
    }

    fn err(&mut self, op: &str, params: Value) -> String {
        self.call(op, params).expect_err(op).0
    }

    fn value(&mut self, key: &str, name: &str) -> Option<Value> {
        self.call("reg.query_value", json!({"key": key, "name": name}))
            .ok()
    }
}

const APP: &str = r"HKLM\SOFTWARE\Vendor\App";

#[test]
fn set_value_updates_in_place_and_keeps_spelling() {
    let mut c = Conn::new();
    let r = c.ok(
        "reg.set_value",
        json!({"key": r"hklm\software\vendor\app", "name": "PATH",
        "type": "REG_SZ", "data": r"C:\New", "time": T1}),
    );
    assert_eq!(r["seq"], 1);
    assert_eq!(
        c.value(APP, "path").unwrap(),
        json!({"name": "Path", "type": "REG_SZ", "data": r"C:\New"})
    );
    // Place kept: Version, Path, NewValue (from the profile), nothing appended.
    let names: Vec<Value> = c
        .ok("reg.enum_values", json!({"key": APP}))
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["name"].clone())
        .collect();
    assert_eq!(names, [json!("Version"), json!("Path"), json!("NewValue")]);
    // The profile view is untouched.
    let h = c.host.clone().unwrap();
    assert_eq!(
        h.profile_registry().value(APP, "Path").unwrap().1["data"],
        r"%ProgramFiles%\App"
    );
}

#[test]
fn set_value_creates_key_with_existing_spelling() {
    let mut c = Conn::new();
    c.ok(
        "reg.set_value",
        json!({"key": r"hklm\software\VENDOR\NewApp\Sub", "name": "X",
        "type": "REG_DWORD", "data": 7, "time": T1}),
    );
    assert_eq!(
        c.ok(
            "reg.key_path",
            json!({"key": r"HKLM\SOFTWARE\Vendor\NewApp\Sub"})
        ),
        json!(r"HKLM\SOFTWARE\Vendor\NewApp\Sub")
    );
    assert_eq!(
        c.ok("reg.enum_subkeys", json!({"key": r"HKLM\SOFTWARE\Vendor"})),
        json!(["App", "NewApp"])
    );
    // The implied parent exists without values.
    assert_eq!(
        c.ok(
            "reg.enum_values",
            json!({"key": r"HKLM\SOFTWARE\Vendor\NewApp"})
        ),
        json!([])
    );
    // Last write times: the key itself, and its parent, which gained a subkey.
    let info = c.ok(
        "reg.key_info",
        json!({"key": r"HKLM\SOFTWARE\Vendor\NewApp\Sub"}),
    );
    assert_eq!(
        info,
        json!({"path": r"HKLM\SOFTWARE\Vendor\NewApp\Sub", "subkeys": 0, "values": 1, "last_write": T1})
    );
    assert_eq!(
        c.ok(
            "reg.key_info",
            json!({"key": r"HKLM\SOFTWARE\Vendor\NewApp"})
        )["last_write"],
        T1
    );
    assert_eq!(
        c.ok("reg.key_info", json!({"key": APP}))["last_write"],
        Value::Null
    );
}

#[test]
fn create_and_delete_keys() {
    let mut c = Conn::new();
    assert_eq!(
        c.ok("reg.create_key", json!({"key": APP}))["created"],
        false
    );
    let r = c.ok(
        "reg.create_key",
        json!({"key": r"HKLM\SOFTWARE\Vendor\Fresh", "time": T1}),
    );
    assert_eq!(r["created"], true);
    assert_eq!(
        c.ok(
            "reg.key_exists",
            json!({"key": r"hklm\software\vendor\fresh"})
        ),
        json!(true)
    );

    // RegDeleteKey refuses a key with subkeys; RegDeleteTree removes everything.
    assert_eq!(
        c.err(
            "reg.delete_key",
            json!({"key": r"HKLM\SOFTWARE\Vendor\App\Plugins"})
        ),
        code::HAS_SUBKEYS
    );
    let r = c.ok(
        "reg.delete_key",
        json!({"key": r"HKLM\SOFTWARE\Vendor\App\Plugins", "recursive": true, "time": T2}),
    );
    assert_eq!(r["deleted_keys"], 4); // Plugins (implied), One, Two, Three
    assert_eq!(
        c.ok(
            "reg.key_exists",
            json!({"key": r"HKLM\SOFTWARE\Vendor\App\Plugins\One"})
        ),
        json!(false)
    );
    assert_eq!(
        c.ok(
            "reg.key_exists",
            json!({"key": r"HKLM\SOFTWARE\Vendor\App\Plugins"})
        ),
        json!(false)
    );
    assert_eq!(c.ok("reg.enum_subkeys", json!({"key": APP})), json!([]));
    assert_eq!(c.ok("reg.key_info", json!({"key": APP}))["last_write"], T2);

    // A deleted key can come back, empty but for the new value.
    c.ok(
        "reg.set_value",
        json!({"key": r"HKLM\SOFTWARE\Vendor\App\Plugins\One", "name": "Back",
        "type": "REG_SZ", "data": "yes"}),
    );
    let vals = c.ok(
        "reg.enum_values",
        json!({"key": r"HKLM\SOFTWARE\Vendor\App\Plugins\One"}),
    );
    assert_eq!(
        vals,
        json!([{"name": "Back", "type": "REG_SZ", "data": "yes"}])
    );

    assert_eq!(
        c.err("reg.delete_key", json!({"key": r"HKLM\SOFTWARE\Nope"})),
        code::NOT_FOUND
    );
    assert_eq!(
        c.err("reg.delete_key", json!({"key": "HKLM"})),
        code::BAD_REQUEST
    );
    assert_eq!(
        c.err("reg.delete_key", json!({"key": APP, "recursive": "yes"})),
        code::BAD_REQUEST
    );
}

#[test]
fn delete_value() {
    let mut c = Conn::new();
    c.ok("reg.delete_value", json!({"key": APP, "name": "version"}));
    assert_eq!(c.value(APP, "Version"), None);
    assert_eq!(
        c.err("reg.delete_value", json!({"key": APP, "name": "Version"})),
        code::NOT_FOUND
    );
    assert_eq!(
        c.err(
            "reg.delete_value",
            json!({"key": r"HKLM\Nope", "name": "x"})
        ),
        code::NOT_FOUND
    );
}

#[test]
fn bad_writes_are_rejected_and_change_nothing() {
    let mut c = Conn::new();
    for (params, why) in [
        (
            json!({"key": APP, "name": "X", "type": "REG_DWORD", "data": -1}),
            "negative dword",
        ),
        (
            json!({"key": APP, "name": "X", "type": "REG_WEIRD", "data": 1}),
            "unknown type",
        ),
        (
            json!({"key": APP, "name": "X", "type": "REG_SZ"}),
            "no data",
        ),
        (
            json!({"key": r"HKEY_LOCAL_MACHINE\X", "name": "X", "type": "REG_SZ", "data": "x"}),
            "long hive",
        ),
        (
            json!({"key": r"HKLM\A\\B", "name": "X", "type": "REG_SZ", "data": "x"}),
            "empty name",
        ),
        (
            json!({"key": "HKLM", "name": "X", "type": "REG_SZ", "data": "x"}),
            "hive root",
        ),
        (
            json!({"key": APP, "name": "X", "type": "REG_SZ", "data": "x", "time": "yesterday"}),
            "bad time",
        ),
    ] {
        assert_eq!(c.err("reg.set_value", params), code::BAD_REQUEST, "{why}");
    }
    assert_eq!(c.ok("changes", json!({}))["last_seq"], 0);
    let h = c.host.clone().unwrap();
    let want = read(&vector("edge/resolved.json"));
    assert_eq!(h.resolved(), want);
}

#[test]
fn lists_and_sections() {
    let mut c = Conn::new();
    // A scenario stops a service and installs a package.
    let r = c.ok(
        "list.upsert",
        json!({"name": "services", "item": {"name": "alpha", "state": "stopped"}, "time": T1}),
    );
    assert_eq!(r["added"], false);
    let r = c.ok(
        "list.upsert",
        json!({"name": "software", "item": {"name": "New Pkg", "version": "1.0"}}),
    );
    assert_eq!(r["added"], true);
    let services = c.ok("list", json!({"name": "services"}));
    assert_eq!(
        services[0],
        json!({"name": "Alpha", "state": "stopped", "start_mode": "auto"})
    );
    let software = c.ok("list", json!({"name": "software"}));
    let names: Vec<&Value> = software
        .as_array()
        .unwrap()
        .iter()
        .map(|s| &s["name"])
        .collect();
    assert_eq!(names, [&json!("Added Tool"), &json!("New Pkg")]);
    c.ok(
        "list.remove",
        json!({"name": "users", "item": "SVC-BACKUP"}),
    );
    assert_eq!(
        c.ok("list", json!({"name": "users"}))
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        c.err("list.remove", json!({"name": "users", "item": "nobody"})),
        code::NOT_FOUND
    );
    assert_eq!(
        c.err(
            "list.upsert",
            json!({"name": "users", "item": {"enabled": true}})
        ),
        code::BAD_REQUEST
    );
    assert_eq!(
        c.err(
            "list.upsert",
            json!({"name": "users", "item": {"name": "x", "remove": true}})
        ),
        code::BAD_REQUEST
    );
    assert_eq!(
        c.err(
            "list.upsert",
            json!({"name": "secrets", "item": {"name": "x"}})
        ),
        code::BAD_REQUEST
    );

    // Interfaces are a list inside network.
    c.ok(
        "list.upsert",
        json!({"name": "interfaces", "item": {"name": "ethernet2", "ipv4": ["192.0.2.9/24"]}}),
    );
    let net = c.ok("section", json!({"name": "network"}));
    assert_eq!(
        net["interfaces"][1],
        json!({"name": "Ethernet2", "description": "NIC two", "ipv4": ["192.0.2.9/24"]})
    );
    assert_eq!(net["dns_suffix"], "base.example.invalid");
    assert_eq!(
        c.err(
            "section.update",
            json!({"name": "network", "patch": {"interfaces": []}})
        ),
        code::BAD_REQUEST
    );
    c.ok(
        "section.update",
        json!({"name": "network", "patch": {"dns_suffix": "new.example.invalid"}}),
    );
    let net = c.ok("section", json!({"name": "network"}));
    assert_eq!(net["dns_suffix"], "new.example.invalid");
    assert_eq!(net["interfaces"][1]["ipv4"], json!(["192.0.2.9/24"]));

    // Sections deep-merge; nulls and host renames are refused.
    c.ok(
        "section.update",
        json!({"name": "hardware", "patch": {"cpu": {"mhz": 3000}}}),
    );
    assert_eq!(
        c.ok("section", json!({"name": "hardware"}))["cpu"],
        json!({"name": "Base CPU", "cores": 8, "logical_processors": 4, "mhz": 3000})
    );
    assert_eq!(
        c.err(
            "section.update",
            json!({"name": "hardware", "patch": {"cpu": null}})
        ),
        code::BAD_REQUEST
    );
    assert_eq!(
        c.err(
            "section.update",
            json!({"name": "identity", "patch": {"hostname": "X"}})
        ),
        code::BAD_REQUEST
    );

    // resolved shows the live host.
    let h = c.host.clone().unwrap();
    let r = h.resolved();
    assert_eq!(r["hardware"]["cpu"]["mhz"], 3000);
    assert_eq!(r["services"][0]["state"], "stopped");
    assert_eq!(r["network"]["dns_suffix"], "new.example.invalid");
}

#[test]
fn journal_orders_every_change() {
    let mut c = Conn::new();
    c.ok(
        "reg.set_value",
        json!({"key": APP, "name": "Version", "type": "REG_SZ", "data": "3.0", "time": T1}),
    );
    c.ok(
        "list.upsert",
        json!({"name": "services", "item": {"name": "Beta", "state": "running"}, "time": T2}),
    );
    c.ok(
        "reg.delete_key",
        json!({"key": r"HKLM\SOFTWARE\Vendor\App\Plugins\One", "time": T2}),
    );
    let all = c.ok("changes", json!({}));
    assert_eq!(all["last_seq"], 3);
    assert_eq!(all["lost"], false);
    let ops: Vec<Value> = all["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["op"].clone())
        .collect();
    assert_eq!(
        ops,
        [
            json!("reg.set_value"),
            json!("list.upsert"),
            json!("reg.delete_key")
        ]
    );
    assert_eq!(
        all["changes"][0],
        json!({"op": "reg.set_value", "key": APP, "name": "Version",
        "value": {"type": "REG_SZ", "data": "3.0"}, "seq": 1, "time": T1})
    );
    let tail = c.ok("changes", json!({"since": 2}));
    assert_eq!(tail["changes"].as_array().unwrap().len(), 1);
    assert_eq!(tail["changes"][0]["seq"], 3);
    let page = c.ok("changes", json!({"since": 0, "limit": 2}));
    assert_eq!(page["changes"].as_array().unwrap().len(), 2);
    assert_eq!(c.ok("changes", json!({"since": 3}))["changes"], json!([]));
    assert_eq!(c.err("changes", json!({"since": -1})), code::BAD_REQUEST);
    assert_eq!(c.err("changes", json!({"limit": 0})), code::BAD_REQUEST);
}

#[test]
fn journal_reports_lost_entries() {
    let mut c = Conn::new();
    let n = xvm_engine::runtime::JOURNAL_LIMIT + 5;
    for i in 0..n {
        c.ok(
            "reg.set_value",
            json!({"key": APP, "name": "Counter", "type": "REG_DWORD", "data": i}),
        );
    }
    let r = c.ok("changes", json!({"since": 0, "limit": 1}));
    assert_eq!(r["lost"], true);
    assert_eq!(r["changes"][0]["seq"], 6);
    let r = c.ok("changes", json!({"since": 5, "limit": 1}));
    assert_eq!(r["lost"], false);
    assert_eq!(c.ok("changes", json!({"since": n}))["lost"], false);
}

#[test]
fn reset_returns_to_the_profile() {
    let mut c = Conn::new();
    c.ok(
        "reg.delete_key",
        json!({"key": r"HKLM\SOFTWARE\Vendor", "recursive": true}),
    );
    c.ok("list.remove", json!({"name": "services", "item": "Alpha"}));
    c.ok(
        "section.update",
        json!({"name": "agent", "patch": {"group": "moved"}}),
    );
    let r = c.ok("reset", json!({"time": T2}));
    assert_eq!(r["seq"], 4);
    let h = c.host.clone().unwrap();
    assert_eq!(h.resolved(), read(&vector("edge/resolved.json")));
    let last = c.ok("changes", json!({"since": 3}));
    assert_eq!(
        last["changes"][0],
        json!({"op": "reset", "seq": 4, "time": T2})
    );
}

#[test]
fn hosts_on_one_base_do_not_share_changes() {
    let base = Arc::new(Base::from_value(read(&vector("edge/base.json"))).unwrap());
    let a = Host::from_value(read(&vector("edge/host.json")), base.clone()).unwrap();
    let b = Host::from_value(read(&vector("edge/host.json")), base).unwrap();
    {
        let mut rt = a.write();
        a.registry_writer(&mut rt)
            .set_value(APP, "Version", &json!({"type": "REG_SZ", "data": "9"}), T1)
            .unwrap();
    }
    assert_eq!(
        a.registry(&a.read()).value(APP, "Version").unwrap().1["data"],
        "9"
    );
    assert_eq!(
        b.registry(&b.read()).value(APP, "Version").unwrap().1["data"],
        "2.0"
    );
}

#[test]
fn concurrent_writers_lose_nothing() {
    let base = Arc::new(Base::from_value(read(&vector("edge/base.json"))).unwrap());
    let host = Arc::new(Host::from_value(read(&vector("edge/host.json")), base).unwrap());
    let workers: Vec<_> = (0..8)
        .map(|t| {
            let h = host.clone();
            thread::spawn(move || {
                for i in 0..100 {
                    let mut rt = h.write();
                    h.registry_writer(&mut rt)
                        .set_value(
                            &format!(r"{APP}\T{t}"),
                            &format!("V{i}"),
                            &json!({"type": "REG_DWORD", "data": i}),
                            T1,
                        )
                        .unwrap();
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    let rt = host.read();
    let reg = host.registry(&rt);
    for t in 0..8 {
        assert_eq!(reg.values(&format!(r"{APP}\T{t}")).unwrap().len(), 100);
    }
    let changes = rt.changes(0, usize::MAX);
    assert_eq!(changes["last_seq"], 800);
    let seqs: Vec<u64> = changes["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, (1..=800).collect::<Vec<_>>());
}
