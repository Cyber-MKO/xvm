//! Event logs: channels from the registry, writes, queries, rendering,
//! messages, retention, gaps, and persistence.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use xvm_engine::persist::Persist;
use xvm_engine::protocol::{Request, code};
use xvm_engine::server::Server;
use xvm_engine::store::{Base, Host, Store};

const T1: &str = "2026-10-16T10:00:00Z";
const SEC: &str = "Microsoft-Windows-Security-Auditing";
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
    let d = std::env::temp_dir().join(format!("xvm-evt-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
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

fn store() -> Arc<Store> {
    let base = Arc::new(Base::from_value(read(&vector("edge/base.json"))).unwrap());
    let host = Arc::new(Host::from_value(read(&vector("edge/host.json")), base.clone()).unwrap());
    let mut s = Store::default();
    s.bases.insert(base.name.clone(), base);
    s.hosts.insert(host.name.clone(), host);
    Arc::new(s)
}

struct Conn {
    server: Server,
    persist: Option<Arc<Persist>>,
    host: Option<Arc<Host>>,
    gaps: Captured,
    next: u64,
}

impl Conn {
    fn start(state: Option<&Path>) -> Self {
        let store = store();
        let gaps = Captured::default();
        let mut server = Server::new(store.clone(), Arc::new(Mutex::new(Box::new(gaps.clone()))));
        let mut persist = None;
        if let Some(dir) = state {
            let (p, _) = Persist::open(dir, &store, 1_000_000).unwrap();
            let p = Arc::new(p);
            server = server.with_persistence(p.clone());
            persist = Some(p);
        }
        let mut c = Conn {
            server,
            persist,
            host: None,
            gaps,
            next: 1,
        };
        c.ok("hello", json!({"host": "edge-host"}));
        c
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

    fn logon(&mut self, channel: &str, user: &str, logon_type: &str) -> u64 {
        self.ok("evt.write", json!({"channel": channel, "time": T1, "event": {
            "provider": SEC, "event_id": 4624, "version": 2, "task": 12544,
            "keywords": "0x8020000000000000",
            "data": [{"name": "TargetUserName", "value": user}, {"name": "LogonType", "value": logon_type}]
        }}))["record_id"]
            .as_u64()
            .unwrap()
    }

    fn ids(&mut self, params: Value) -> Vec<u64> {
        self.ok("evt.query", params)["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["record_id"].as_u64().unwrap())
            .collect()
    }

    fn gap_log(&self) -> Vec<Value> {
        String::from_utf8(self.gaps.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

#[test]
fn channels_come_from_the_registry() {
    let mut c = Conn::start(None);
    let chans = c.ok("evt.channels", json!({}));
    let by: std::collections::BTreeMap<String, Value> = chans
        .as_array()
        .unwrap()
        .iter()
        .map(|ch| (ch["name"].as_str().unwrap().to_string(), ch.clone()))
        .collect();
    assert_eq!(
        by.keys().collect::<Vec<_>>(),
        [
            "Application",
            "Microsoft-Windows-Sysmon/Operational",
            "Security",
            "System"
        ]
    );
    assert_eq!(by["Security"]["max_size"], 4096);
    assert_eq!(by["Security"]["max_size_from_registry"], true);
    // Application's key has no MaxSize: the documented Windows default, flagged.
    assert_eq!(by["Application"]["max_size"], 20 * 1024 * 1024);
    assert_eq!(by["Application"]["max_size_from_registry"], false);
    assert_eq!(by["System"]["events"], 0);
    assert_eq!(
        c.call(
            "evt.write",
            json!({"channel": "Setup", "event": {"provider": "p", "event_id": 1}})
        )
        .unwrap_err(),
        code::NOT_FOUND
    );
    assert_eq!(
        c.call("evt.query", json!({"channel": "Setup"}))
            .unwrap_err(),
        code::NOT_FOUND
    );
}

#[test]
fn write_and_render() {
    let mut c = Conn::start(None);
    assert_eq!(c.logon("security", "bob", "3"), 1);
    assert_eq!(c.logon("Security", "alice", "2"), 2);
    let r = c.ok("evt.query", json!({"channel": "Security"}));
    assert_eq!(r["last_record_id"], 2);
    assert_eq!(r["more"], false);
    let xml = r["events"][0]["xml"].as_str().unwrap();
    // The computer comes from the host profile (rule 5).
    assert!(xml.contains("<Computer>EDGE-01</Computer>"), "{xml}");
    assert!(xml.contains("<Channel>Security</Channel>"));
    assert!(xml.contains("<EventRecordID>1</EventRecordID>"));
    assert!(xml.contains("<TimeCreated SystemTime='2026-10-16T10:00:00.0000000Z'/>"));
    assert!(xml.contains("<Data Name='TargetUserName'>bob</Data>"));
    let j = c.ok(
        "evt.query",
        json!({"channel": "Security", "format": "json", "after": 1}),
    );
    assert_eq!(j["events"][0]["data"][0]["value"], "alice");
    let one = c.ok("evt.get", json!({"channel": "Security", "record_id": 2}));
    assert_eq!(one["computer"], "EDGE-01");
    assert!(one["xml"].as_str().unwrap().contains("alice"));
    assert_eq!(
        c.call("evt.get", json!({"channel": "Security", "record_id": 9}))
            .unwrap_err(),
        code::NOT_FOUND
    );
    // Channels are separate, each with its own record IDs.
    let sys = c.ok(
        "evt.write",
        json!({"channel": "System", "event": {
        "provider": "Service Control Manager", "event_id": 7036, "qualifiers": 16384,
        "data": {"param1": "Windows Time", "param2": "stopped"}}}),
    );
    assert_eq!(sys["record_id"], 1);
    assert_eq!(
        c.call(
            "evt.write",
            json!({"channel": "Security", "event": {"provider": "p"}})
        )
        .unwrap_err(),
        code::BAD_REQUEST
    );
}

#[test]
fn queries_and_paging() {
    let mut c = Conn::start(None);
    for i in 0..10 {
        c.logon(
            "Security",
            &format!("user{i}"),
            if i % 2 == 0 { "3" } else { "2" },
        );
    }
    c.ok("evt.write", json!({"channel": "Security", "event": {"provider": SEC, "event_id": 4625,
        "data": [{"name": "TargetUserName", "value": "mallory"}, {"name": "LogonType", "value": "3"}]}}));
    assert_eq!(
        c.ids(json!({"channel": "Security", "query": "Event/System[EventID=4625]"})),
        [11]
    );
    // Wazuh's default Security query shape.
    let wazuh = "Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and EventID != 4656 and EventID != 4658]";
    assert_eq!(
        c.ids(json!({"channel": "Security", "query": wazuh})).len(),
        11
    );
    assert_eq!(
        c.ids(json!({"channel": "Security", "query": "*[EventData[Data[@Name='LogonType']='2']]"})),
        [2, 4, 6, 8, 10]
    );
    let q = r#"<QueryList><Query Id="0"><Select Path="Security">*[System[EventID=4625]]</Select></Query></QueryList>"#;
    assert_eq!(c.ids(json!({"channel": "Security", "query": q})), [11]);
    assert_eq!(
        c.ids(json!({"channel": "System", "query": q})),
        Vec::<u64>::new()
    );
    // Paging: after and limit, with `more` until the end.
    let p1 = c.ok("evt.query", json!({"channel": "Security", "limit": 4}));
    assert_eq!(p1["more"], true);
    assert_eq!(p1["last_record_id"], 4);
    let p3 = c.ok(
        "evt.query",
        json!({"channel": "Security", "after": 8, "limit": 4}),
    );
    assert_eq!(p3["more"], false);
    assert_eq!(p3["last_record_id"], 11);
    // A query the engine cannot run is an error and a logged gap, never ignored.
    assert_eq!(
        c.call(
            "evt.query",
            json!({"channel": "Security", "query": "*[System[not(EventID=1)]]"})
        )
        .unwrap_err(),
        code::BAD_QUERY
    );
    let gap = c.gap_log().pop().unwrap();
    assert_eq!(gap["gap"], "event-query");
    assert_eq!(gap["host"], "edge-host");
}

#[test]
fn messages_from_templates_and_events() {
    let mut c = Conn::start(None);
    c.logon("Security", "bob", "3");
    // 4624 version 2 uses the versioned template.
    let m = c.ok(
        "evt.format_message",
        json!({"channel": "Security", "record_id": 1}),
    );
    assert_eq!(
        m["message"],
        "An account was successfully logged on.\r\n\tAccount Name:\tbob\r\n\tLogon Type:\t3"
    );
    assert_eq!(m["source"], "template");
    // The host profile overrides the base's 4625 template.
    c.ok("evt.write", json!({"channel": "Security", "event": {"provider": SEC, "event_id": 4625,
        "data": [{"name": "TargetUserName", "value": "mallory"}, {"name": "LogonType", "value": "3"}]}}));
    assert_eq!(
        c.ok(
            "evt.format_message",
            json!({"channel": "Security", "record_id": 2})
        )["message"],
        "Logon failure for mallory (type 3)."
    );
    // An event that carries its own message (golden corpus replay) keeps it.
    c.ok(
        "evt.write",
        json!({"channel": "Security", "event": {"provider": SEC, "event_id": 4624,
        "message": "Captured text, exactly as Windows rendered it."}}),
    );
    let m = c.ok(
        "evt.format_message",
        json!({"channel": "Security", "record_id": 3}),
    );
    assert_eq!(
        m,
        json!({"message": "Captured text, exactly as Windows rendered it.", "source": "event"})
    );
    // No template: an error and a gap naming the event.
    c.ok(
        "evt.write",
        json!({"channel": "Security", "event": {"provider": SEC, "event_id": 4720}}),
    );
    assert_eq!(
        c.call(
            "evt.format_message",
            json!({"channel": "Security", "record_id": 4})
        )
        .unwrap_err(),
        code::NO_MESSAGE
    );
    let gap = c.gap_log().pop().unwrap();
    assert_eq!(
        (gap["gap"].as_str(), gap["event_id"].as_u64()),
        (Some("event-message"), Some(4720))
    );
    // A template asking for more values than the event has.
    c.ok(
        "evt.write",
        json!({"channel": "Security", "event": {"provider": SEC, "event_id": 4625,
        "data": [{"name": "TargetUserName", "value": "short"}]}}),
    );
    assert_eq!(
        c.call(
            "evt.format_message",
            json!({"channel": "Security", "record_id": 5})
        )
        .unwrap_err(),
        code::NO_MESSAGE
    );
}

#[test]
fn full_channels_drop_the_oldest() {
    let mut c = Conn::start(None);
    // Security's MaxSize in the edge profile is 4096 bytes.
    for i in 0..60 {
        c.logon("Security", &format!("u{i}"), "3");
    }
    let info = c.ok("evt.channels", json!({}));
    let sec = info
        .as_array()
        .unwrap()
        .iter()
        .find(|ch| ch["name"] == "Security")
        .unwrap()
        .clone();
    assert!(sec["bytes"].as_u64().unwrap() <= 4096, "{sec}");
    assert_eq!(sec["newest_record_id"], 60);
    let oldest = sec["oldest_record_id"].as_u64().unwrap();
    assert!(oldest > 1, "{sec}");
    let ids = c.ids(json!({"channel": "Security", "limit": 1000}));
    assert_eq!(ids, (oldest..=60).collect::<Vec<_>>());
    // A reader whose bookmark fell out of the log picks up at the oldest kept event.
    assert_eq!(
        c.ids(json!({"channel": "Security", "after": 1, "limit": 1}))[0],
        oldest
    );
}

#[test]
fn events_survive_a_restart_and_reset_clears_them() {
    let state = temp_dir();
    let mut c = Conn::start(Some(&state));
    for i in 0..60 {
        c.logon("Security", &format!("u{i}"), "3");
    }
    c.ok("evt.write", json!({"channel": "Microsoft-Windows-Sysmon/Operational", "event": {"provider": "Microsoft-Windows-Sysmon", "event_id": 1}}));
    let before_sec = c.ok("evt.query", json!({"channel": "Security", "limit": 1000}));
    let before_sys = c.ok(
        "evt.query",
        json!({"channel": "microsoft-windows-sysmon/operational"}),
    );
    c.persist.as_ref().unwrap().flush().unwrap();
    // Retention deleted old segments: Security is capped at 4096 bytes, segments at 64 KiB.
    let files: Vec<String> = fs::read_dir(state.join("hosts/edge-host/events"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        files
            .iter()
            .any(|f| f.starts_with("Microsoft-Windows-Sysmon_Operational-")),
        "{files:?}"
    );
    drop(c);

    let mut again = Conn::start(Some(&state));
    assert_eq!(
        again.ok("evt.query", json!({"channel": "Security", "limit": 1000})),
        before_sec
    );
    assert_eq!(
        again.ok(
            "evt.query",
            json!({"channel": "Microsoft-Windows-Sysmon/Operational"})
        ),
        before_sys
    );
    // Record IDs continue.
    assert_eq!(again.logon("Security", "after-restart", "3"), 61);

    // reset empties the logs, and the emptiness is saved too.
    again.ok("reset", json!({}));
    assert_eq!(
        again.ok("evt.query", json!({"channel": "Security"}))["events"],
        json!([])
    );
    assert_eq!(again.logon("Security", "fresh", "3"), 1);
    again.persist.as_ref().unwrap().flush().unwrap();
    drop(again);
    let mut third = Conn::start(Some(&state));
    assert_eq!(third.ids(json!({"channel": "Security"})), [1]);
    assert_eq!(
        third.ok("evt.get", json!({"channel": "Security", "record_id": 1}))["data"][0]["value"],
        "fresh"
    );
}

#[test]
fn a_torn_event_line_is_skipped_with_a_warning() {
    let state = temp_dir();
    let mut c = Conn::start(Some(&state));
    c.logon("System", "x", "3");
    c.persist.as_ref().unwrap().flush().unwrap();
    drop(c);
    let seg = fs::read_dir(state.join("hosts/edge-host/events"))
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    fs::OpenOptions::new()
        .append(true)
        .open(&seg)
        .unwrap()
        .write_all(b"{\"record_id\": 2, \"chan")
        .unwrap();
    let store = store();
    let (_, report) = Persist::open(&state, &store, 1_000_000).unwrap();
    assert_eq!(report.events, 1);
    assert!(
        report.warnings.iter().any(|w| w.contains("incomplete")),
        "{:?}",
        report.warnings
    );
}

#[test]
fn old_segments_are_deleted_as_retention_drops_their_events() {
    let state = temp_dir();
    let mut c = Conn::start(Some(&state));
    // About 300 bytes per event: 600 events fill several 64 KiB segments, while
    // Security keeps only its last 4096 bytes.
    for i in 0..600 {
        c.logon("Security", &format!("user-{i:05}"), "3");
    }
    c.persist.as_ref().unwrap().flush().unwrap();
    let mut segs: Vec<String> = fs::read_dir(state.join("hosts/edge-host/events"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("Security-"))
        .collect();
    segs.sort();
    assert!(segs.len() <= 2, "{segs:?}");
    assert!(
        !segs[0].ends_with(".000001.jsonl"),
        "the first segment should be gone: {segs:?}"
    );
    let kept = c.ids(json!({"channel": "Security", "limit": 1000}));
    drop(c);
    let mut again = Conn::start(Some(&state));
    assert_eq!(
        again.ids(json!({"channel": "Security", "limit": 1000})),
        kept
    );
    assert_eq!(*kept.last().unwrap(), 600);
}
