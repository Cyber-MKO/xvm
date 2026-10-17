//! The engine's layered view must equal `xvm-profile resolve` on every vector.
//! The vectors are written by tests/control/test_vectors.py.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};
use xvm_engine::store::{Base, Host};

fn vectors() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let mut cases: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("resolved.json").is_file())
        .collect();
    cases.sort();
    assert!(cases.len() >= 2, "expected the example and edge vectors");
    cases
}

fn read(p: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap()
}

fn host(case: &Path) -> Host {
    let base = Arc::new(Base::from_value(read(&case.join("base.json"))).unwrap());
    Host::from_value(read(&case.join("host.json")), base).unwrap()
}

fn keys(v: &Value) -> Vec<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

#[test]
fn resolved_matches_python() {
    for case in vectors() {
        let want = read(&case.join("resolved.json"));
        let got = host(&case).resolved();
        assert_eq!(got, want, "vector {}", case.display());
    }
}

#[test]
fn value_order_matches_python() {
    for case in vectors() {
        let want = read(&case.join("resolved.json"));
        let h = host(&case);
        let Some(reg) = want.get("registry") else {
            continue;
        };
        for (path, values) in reg["keys"].as_object().unwrap() {
            let got: Vec<String> = h
                .profile_registry()
                .values(path)
                .unwrap()
                .into_iter()
                .map(|(n, _)| n)
                .collect();
            assert_eq!(got, keys(values), "{} {path}", case.display());
        }
        for field in ["users", "groups", "software", "services"] {
            if let Some(list) = want.get(field) {
                assert_eq!(&Value::Array(h.list(field).unwrap()), list, "{field}");
            }
        }
    }
}

fn edge() -> Host {
    host(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/edge"))
}

#[test]
fn registry_lookups() {
    let h = edge();
    // The live view with no run-time changes must equal the profile view.
    let rt = h.read();
    let r = h.registry(&rt);
    // Case-insensitive, base spelling kept.
    assert_eq!(
        r.value(r"hklm\SOFTWARE\vendor\APP", "VERSION"),
        Some(("Version".into(), json!({"type": "REG_SZ", "data": "2.0"})))
    );
    assert_eq!(
        r.key_path(r"hklm\software\vendor\app\"),
        Some(r"HKLM\SOFTWARE\Vendor\App".into())
    );
    // Deleted by the host, inherited, added.
    assert_eq!(r.value(r"HKLM\SOFTWARE\Vendor\App", "Flags"), None);
    assert!(r.value(r"HKLM\SOFTWARE\Vendor\App", "Path").is_some());
    assert_eq!(
        r.value(r"HKLM\SOFTWARE\Vendor\App", "NewValue").unwrap().1["data"],
        5
    );
    // A deleted subtree is gone, a deleted then re-added key has only new values.
    assert!(!r.key_exists(r"HKLM\SOFTWARE\Vendor\Legacy"));
    assert!(!r.key_exists(r"HKLM\SOFTWARE\Vendor\Legacy\Child"));
    assert_eq!(r.value(r"HKLM\SOFTWARE\Other", "Keep"), None);
    assert_eq!(r.values(r"HKLM\SOFTWARE\Other").unwrap().len(), 1);
    // Implied parents exist and list their children, sorted, base spelling.
    assert!(r.key_exists("HKLM"));
    assert!(r.key_exists(r"HKLM\Software"));
    assert_eq!(r.key_path(r"hklm\software"), Some(r"HKLM\SOFTWARE".into()));
    assert_eq!(
        r.subkeys(r"HKLM\SOFTWARE").unwrap(),
        // WOW6432Node holds the 32-bit Uninstall key the engine always serves.
        vec!["Microsoft", "Other", "Vendor", "WOW6432Node"]
    );
    assert_eq!(r.subkeys(r"HKLM\SOFTWARE\Vendor").unwrap(), vec!["App"]);
    assert_eq!(
        r.subkeys(r"HKLM\SOFTWARE\Vendor\App\Plugins").unwrap(),
        vec!["One", "Three", "Two"]
    );
    assert_eq!(
        r.subkeys(r"HKLM\SOFTWARE\Vendor\App\Plugins\One").unwrap(),
        Vec::<String>::new()
    );
    // Missing keys.
    assert!(!r.key_exists(r"HKLM\SOFTWARE\Nope"));
    assert_eq!(r.values(r"HKLM\SOFTWARE\Nope"), None);
    assert_eq!(r.subkeys(r"HKLM\SOFTWARE\Nope"), None);
    assert!(!r.key_exists(r"HKLM\SOFTWAREX"));
}

#[test]
fn sections_and_lists() {
    let h = edge();
    assert_eq!(
        h.section("hardware").unwrap()["cpu"],
        json!({"name": "Base CPU", "cores": 8, "logical_processors": 4})
    );
    assert_eq!(
        h.section("identity").unwrap(),
        json!({"hostname": "EDGE-01"})
    );
    let nics = h.list("interfaces").unwrap();
    assert_eq!(
        nics.iter()
            .map(|n| n["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["Ethernet0", "Ethernet2"]
    );
    assert_eq!(
        h.list("software").unwrap(),
        vec![json!({"name": "Added Tool", "version": "3.0"})]
    );
    assert_eq!(h.list("nonsense"), None);
}

#[test]
fn hosts_share_their_base() {
    let case = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/edge");
    let base = Arc::new(Base::from_value(read(&case.join("base.json"))).unwrap());
    let a = Host::from_value(read(&case.join("host.json")), base.clone()).unwrap();
    let b = Host::from_value(read(&case.join("host.json")), base.clone()).unwrap();
    assert!(Arc::ptr_eq(&a.base, &b.base));
    assert_eq!(Arc::strong_count(&base), 3);
}

#[test]
fn bad_profiles_are_rejected() {
    let case = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/edge");
    let base = Arc::new(Base::from_value(read(&case.join("base.json"))).unwrap());
    let mut doc = read(&case.join("host.json"));
    doc["registry"]["delete_keys"] = json!([r"HKLM\SOFTWARE\Missing"]);
    let err = Host::from_value(doc, base.clone()).unwrap_err();
    assert!(err.0.contains("not in the base"), "{}", err.0);
    let mut doc = read(&case.join("host.json"));
    doc["base"] = json!("other");
    assert!(Host::from_value(doc, base.clone()).is_err());
    let mut doc = read(&case.join("host.json"));
    doc["os"] = json!("linux");
    assert!(Host::from_value(doc, base).is_err());
    assert!(Base::from_value(json!({"schema": 2, "kind": "base-image", "name": "x"})).is_err());
}
