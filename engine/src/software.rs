//! Uninstall registry keys built from the host's `software` list.
//!
//! Windows lists installed programs under
//! `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\KEY`, and 32-bit
//! programs on 64-bit Windows under the same path below `WOW6432Node`
//! ("Uninstall Registry Key" on Microsoft Learn). Inventory agents read them
//! there. The profile keeps one list, `software`; the engine shows each entry
//! as a key, so the list and the registry cannot disagree.
//!
//! | Entry field | Value |
//! | --- | --- |
//! | `uninstall_key`, else `name` | The key's name |
//! | `name` | `DisplayName` |
//! | `version` | `DisplayVersion` |
//! | `vendor` | `Publisher` |
//! | `location` | `InstallLocation` |
//! | `install_date` (`YYYY-MM-DD`) | `InstallDate` (`YYYYMMDD`) |
//!
//! All values are `REG_SZ`. The keys are a read-only view: a key the profile
//! or a run-time write lists at the same path wins.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::merge::norm;

pub const UNINSTALL: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
pub const UNINSTALL_WOW64: &str =
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

/// Keys by normalised path: their spelling and values in order.
pub type Synth = BTreeMap<String, (String, Vec<(String, Value)>)>;

/// The Uninstall keys for a Windows host. `os_arch` is `os_info.architecture`;
/// only a 64-bit Windows has the `WOW6432Node` view.
pub fn uninstall_keys(software: &[Value], os_arch: Option<&str>) -> Synth {
    let wow64 = !matches!(os_arch, Some("x86"));
    let mut out = Synth::new();
    for item in software {
        let Some(name) = item.get("name").and_then(Value::as_str) else {
            continue;
        };
        let key = item
            .get("uninstall_key")
            .and_then(Value::as_str)
            .unwrap_or(name);
        if key.is_empty() || key.contains('\\') {
            continue;
        }
        let root = if wow64 && item.get("architecture").and_then(Value::as_str) == Some("x86") {
            UNINSTALL_WOW64
        } else {
            UNINSTALL
        };
        let mut values = vec![("DisplayName".to_string(), sz(name))];
        for (field, value) in [
            ("version", "DisplayVersion"),
            ("vendor", "Publisher"),
            ("location", "InstallLocation"),
        ] {
            if let Some(v) = item.get(field).and_then(Value::as_str) {
                values.push((value.to_string(), sz(v)));
            }
        }
        if let Some(d) = item.get("install_date").and_then(Value::as_str) {
            let digits: String = d.chars().filter(char::is_ascii_digit).collect();
            if digits.len() == 8 {
                values.push(("InstallDate".to_string(), sz(&digits)));
            }
        }
        let path = format!(r"{root}\{key}");
        // Two entries with the same key: the first wins, as only one key can exist.
        out.entry(norm(&path)).or_insert((path, values));
    }
    out
}

fn sz(s: &str) -> Value {
    json!({"type": "REG_SZ", "data": s})
}
