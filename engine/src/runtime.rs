//! Run-time state: changes made after a host starts.
//!
//! The scenario engine (logons, service starts, package installs) and the
//! agent itself change a host while it runs. Those changes live in a third
//! layer above the base image and the host profile, so the profile stays
//! untouched and `reset` returns to it.
//!
//! | Layer | Holds | Shared |
//! | --- | --- | --- |
//! | Base image | Facts common to many hosts | By every host on the base |
//! | Host profile | What differs for one host | No |
//! | Run time | Changes since the host started | No |
//!
//! The run-time layer copies a registry key, list or section the first time it
//! changes and edits the copy. Deleted keys become tombstones. Every change is
//! appended to the host's change journal with a sequence number, so a
//! personality can poll for changes (registry notifications, FIM) and every
//! component sees one consistent order (brief section 6).
//!
//! Nothing here touches the real machine (CLAUDE.md rule 7).

use std::collections::{BTreeMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use crate::merge::{merge_dict, norm};
use crate::registry::View;

/// Journal entries kept per host. Older entries are dropped; `changes` reports the loss.
pub const JOURNAL_LIMIT: usize = 10_000;
/// Longest key or value name Windows allows, in characters.
const MAX_NAME: usize = 255;
const HIVES: [&str; 3] = ["HKLM", "HKU", "HKCR"];

/// A rejected change: an error code from `protocol::code` and a message.
#[derive(Debug, PartialEq)]
pub struct Rejected(pub &'static str, pub String);

fn bad(msg: impl Into<String>) -> Rejected {
    Rejected(crate::protocol::code::BAD_REQUEST, msg.into())
}

fn not_found(msg: impl Into<String>) -> Rejected {
    Rejected(crate::protocol::code::NOT_FOUND, msg.into())
}

/// One copied registry key in the run-time layer.
#[derive(Debug, Clone)]
pub struct RtKey {
    pub path: String,
    pub values: Vec<(String, Value)>,
}

#[derive(Debug, Default)]
pub struct Runtime {
    /// Normalised key path to its state. `None` is a tombstone: deleted at run time.
    pub(crate) reg: BTreeMap<String, Option<RtKey>>,
    /// Last write time of keys changed at run time.
    pub(crate) last_write: BTreeMap<String, String>,
    /// Keyed lists changed at run time, in full.
    pub(crate) lists: BTreeMap<String, Vec<Value>>,
    /// Sections changed at run time, in full.
    pub(crate) sections: Map<String, Value>,
    journal: VecDeque<Value>,
    next_seq: u64,
}

// ---------------------------------------------------------------- time

/// Days since 1970-01-01 to a civil date (proleptic Gregorian).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// The engine's clock as RFC 3339 UTC with milliseconds.
pub fn now() -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = t.as_secs() as i64;
    let (y, mo, d) = civil(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        s / 3600,
        s % 3600 / 60,
        s % 60,
        t.subsec_millis()
    )
}

/// Accept `YYYY-MM-DDTHH:MM:SS[.fraction]Z`. Scenarios pass their own clock
/// so each host can run on a jittered clock (brief section 8).
pub fn check_time(t: &str) -> Result<(), Rejected> {
    let b = t.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| r.clone().all(|i| b.get(i).is_some_and(u8::is_ascii_digit));
    let ok = b.len() >= 20
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19)
        && b[b.len() - 1] == b'Z'
        && (b.len() == 20 || (b[19] == b'.' && b.len() > 21 && digits(20..b.len() - 1)));
    if ok {
        Ok(())
    } else {
        Err(bad(format!(
            "time must look like 2026-10-16T10:00:00Z, got {t:?}"
        )))
    }
}

// ---------------------------------------------------------------- validation

/// Check a registry value as the host profile schema does.
pub fn check_value(v: &Value) -> Result<(), Rejected> {
    let Some(m) = v.as_object() else {
        return Err(bad("a registry value is an object with type and data"));
    };
    if m.keys().any(|k| k != "type" && k != "data") {
        return Err(bad("a registry value has only type and data"));
    }
    let ty = m.get("type").and_then(Value::as_str).unwrap_or("");
    let data = m.get("data").unwrap_or(&Value::Null);
    let ok = match ty {
        "REG_SZ" | "REG_EXPAND_SZ" => data.is_string(),
        "REG_MULTI_SZ" => data
            .as_array()
            .is_some_and(|a| a.iter().all(Value::is_string)),
        "REG_DWORD" => data.as_u64().is_some_and(|n| n <= u64::from(u32::MAX)),
        "REG_QWORD" => data.as_u64().is_some(),
        "REG_BINARY" => data.as_str().is_some_and(|s| {
            s.len() % 2 == 0
                && s.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        }),
        _ => return Err(bad(format!("unknown registry type {ty:?}"))),
    };
    if ok {
        Ok(())
    } else {
        Err(bad(format!("data does not fit type {ty}")))
    }
}

/// Check a key path: a hive, then non-empty names of at most 255 characters.
pub fn check_key(path: &str) -> Result<(), Rejected> {
    let mut parts = path.trim_end_matches('\\').split('\\');
    let hive = parts.next().unwrap_or("");
    if !HIVES.iter().any(|h| h.eq_ignore_ascii_case(hive)) {
        return Err(bad(format!(
            "key must start with HKLM, HKU or HKCR: {path}"
        )));
    }
    for p in parts {
        if p.is_empty() || p.chars().count() > MAX_NAME {
            return Err(bad(format!("bad key name in {path}")));
        }
    }
    Ok(())
}

fn parent(nk: &str) -> Option<&str> {
    nk.rsplit_once('\\').map(|(p, _)| p)
}

// ---------------------------------------------------------------- registry view

/// A host's registry with the run-time layer on top.
pub struct Live<'a> {
    pub lower: View<'a>,
    pub rt: &'a Runtime,
}

impl Live<'_> {
    /// The key's spelling if it is listed (not merely implied) in any layer.
    fn listed(&self, nk: &str) -> Option<String> {
        match self.rt.reg.get(nk) {
            Some(Some(k)) => Some(k.path.clone()),
            Some(None) => None,
            None => self.lower.listed(nk),
        }
    }

    /// Listed keys strictly below `nk` that are alive, as (normalised, spelling).
    fn below(&self, nk: &str) -> BTreeMap<String, String> {
        let mut out: BTreeMap<String, String> = self
            .lower
            .listed_below(nk)
            .into_iter()
            .filter(|(k, _)| !matches!(self.rt.reg.get(k), Some(None)))
            .collect();
        let start = format!("{nk}\\");
        for (k, v) in self.rt.reg.range(start.clone()..) {
            if !k.starts_with(&start) {
                break;
            }
            if let Some(key) = v {
                out.insert(k.clone(), key.path.clone());
            }
        }
        out
    }

    pub fn key_exists(&self, path: &str) -> bool {
        let nk = norm(path);
        self.listed(&nk).is_some() || !self.below(&nk).is_empty()
    }

    pub fn key_path(&self, path: &str) -> Option<String> {
        let nk = norm(path);
        if let Some(p) = self.listed(&nk) {
            return Some(p);
        }
        let below = self.below(&nk);
        let (_, first) = below.iter().next()?;
        let depth = nk.split('\\').count();
        Some(first.split('\\').take(depth).collect::<Vec<_>>().join("\\"))
    }

    pub fn values(&self, path: &str) -> Option<Vec<(String, Value)>> {
        let nk = norm(path);
        match self.rt.reg.get(&nk) {
            Some(Some(k)) => Some(k.values.clone()),
            Some(None) => self.key_exists(path).then(Vec::new),
            None => {
                if !self.key_exists(path) {
                    return None;
                }
                Some(self.lower.values(path).unwrap_or_default())
            }
        }
    }

    pub fn value(&self, path: &str, name: &str) -> Option<(String, Value)> {
        let nn = norm(name);
        self.values(path)?.into_iter().find(|(n, _)| norm(n) == nn)
    }

    pub fn subkeys(&self, path: &str) -> Option<Vec<String>> {
        if !self.key_exists(path) {
            return None;
        }
        let nk = norm(path);
        let depth = nk.split('\\').count();
        let mut found: BTreeMap<String, String> = BTreeMap::new();
        for p in self.below(&nk).values() {
            if let Some(child) = p.split('\\').nth(depth) {
                found
                    .entry(child.to_lowercase())
                    .or_insert_with(|| child.to_string());
            }
        }
        Some(found.into_values().collect())
    }

    /// Counts and the run-time last write time (null if the key never changed).
    pub fn key_info(&self, path: &str) -> Option<Value> {
        let values = self.values(path)?;
        let subkeys = self.subkeys(path)?;
        Some(json!({
            "path": self.key_path(path),
            "subkeys": subkeys.len(),
            "values": values.len(),
            "last_write": self.rt.last_write.get(&norm(path)),
        }))
    }

    pub fn materialize(&self) -> Value {
        let mut listed: BTreeMap<String, String> = self.lower.listed_below("");
        listed.retain(|k, _| !matches!(self.rt.reg.get(k), Some(None)));
        for (k, v) in &self.rt.reg {
            if let Some(key) = v {
                listed.insert(k.clone(), key.path.clone());
            }
        }
        let mut keys = Map::new();
        for path in listed.into_values() {
            let values: Map<String, Value> =
                self.values(&path).unwrap_or_default().into_iter().collect();
            keys.insert(path, Value::Object(values));
        }
        json!({ "keys": keys })
    }

    /// How a new key should be spelled: existing ancestors keep their spelling.
    fn spell(&self, path: &str) -> String {
        let trimmed = path.trim_end_matches('\\');
        let parts: Vec<&str> = trimmed.split('\\').collect();
        let mut spelled = parts[0].to_uppercase();
        for i in 1..parts.len() {
            let prefix = parts[..=i].join("\\");
            match self.key_path(&prefix) {
                Some(p) => spelled = p,
                None => {
                    spelled.push('\\');
                    spelled.push_str(parts[i]);
                }
            }
        }
        spelled
    }
}

// ---------------------------------------------------------------- changes

impl Runtime {
    fn record(&mut self, time: &str, mut change: Map<String, Value>) -> u64 {
        self.next_seq += 1;
        change.insert("seq".into(), self.next_seq.into());
        change.insert("time".into(), time.into());
        self.journal.push_back(Value::Object(change));
        if self.journal.len() > JOURNAL_LIMIT {
            self.journal.pop_front();
        }
        self.next_seq
    }

    /// Journal entries after `since`, at most `limit`.
    ///
    /// `lost` is true when entries after `since` were already dropped; the
    /// reader should then re-read the state it cares about.
    pub fn changes(&self, since: u64, limit: usize) -> Value {
        let first = self
            .journal
            .front()
            .and_then(|c| c["seq"].as_u64())
            .unwrap_or(self.next_seq + 1);
        let list: Vec<Value> = self
            .journal
            .iter()
            .filter(|c| c["seq"].as_u64().is_some_and(|s| s > since))
            .take(limit)
            .cloned()
            .collect();
        json!({
            "changes": list,
            "last_seq": self.next_seq,
            "lost": since + 1 < first && since < self.next_seq,
        })
    }

    /// Copy a key into the run-time layer, creating it if needed.
    fn copy_key(
        &mut self,
        live_values: Option<Vec<(String, Value)>>,
        nk: &str,
        spelled: String,
    ) -> &mut RtKey {
        let entry = self.reg.entry(nk.to_string()).or_insert(None);
        if entry.is_none() {
            *entry = Some(RtKey {
                path: spelled,
                values: live_values.unwrap_or_default(),
            });
        }
        entry.as_mut().expect("just filled")
    }

    fn touch(&mut self, nk: &str, time: &str) {
        self.last_write.insert(nk.to_string(), time.to_string());
    }
}

/// Apply registry changes. Each takes the lower view, since the run-time layer
/// copies from it the first time a key changes.
pub struct Writer<'a> {
    pub lower: View<'a>,
    pub rt: &'a mut Runtime,
}

impl Writer<'_> {
    fn live(&self) -> Live<'_> {
        Live {
            lower: View {
                base: self.lower.base,
                delta: self.lower.delta,
            },
            rt: self.rt,
        }
    }

    /// RegCreateKeyEx: creates the key and its missing parents. Returns whether it was new.
    pub fn create_key(&mut self, path: &str, time: &str) -> Result<Value, Rejected> {
        check_key(path)?;
        let nk = norm(path);
        if nk.split('\\').count() < 2 {
            return Err(bad("cannot create a hive root"));
        }
        let (exists, values, spelled) = {
            let live = self.live();
            (live.key_exists(path), live.values(path), live.spell(path))
        };
        if exists {
            return Ok(json!({"created": false, "path": spelled}));
        }
        self.rt.copy_key(values, &nk, spelled.clone());
        self.rt.touch(&nk, time);
        if let Some(p) = parent(&nk) {
            self.rt.touch(p, time);
        }
        let mut c = Map::new();
        c.insert("op".into(), "reg.create_key".into());
        c.insert("key".into(), spelled.clone().into());
        let seq = self.rt.record(time, c);
        Ok(json!({"created": true, "path": spelled, "seq": seq}))
    }

    /// RegSetValueEx, creating the key if needed. Keeps an existing value's spelling and place.
    pub fn set_value(
        &mut self,
        path: &str,
        name: &str,
        value: &Value,
        time: &str,
    ) -> Result<Value, Rejected> {
        check_key(path)?;
        check_value(value)?;
        if name.chars().count() > MAX_NAME {
            return Err(bad("value name longer than 255 characters"));
        }
        let nk = norm(path);
        if nk.split('\\').count() < 2 {
            return Err(bad("cannot set a value on a hive root"));
        }
        let (existed, values, spelled) = {
            let live = self.live();
            (live.key_exists(path), live.values(path), live.spell(path))
        };
        let key = self.rt.copy_key(values, &nk, spelled.clone());
        let nn = norm(name);
        let stored_name = match key.values.iter_mut().find(|(n, _)| norm(n) == nn) {
            Some((n, v)) => {
                *v = value.clone();
                n.clone()
            }
            None => {
                key.values.push((name.to_string(), value.clone()));
                name.to_string()
            }
        };
        self.rt.touch(&nk, time);
        if !existed && let Some(p) = parent(&nk) {
            self.rt.touch(p, time);
        }
        let mut c = Map::new();
        c.insert("op".into(), "reg.set_value".into());
        c.insert("key".into(), spelled.into());
        c.insert("name".into(), stored_name.into());
        c.insert("value".into(), value.clone());
        let seq = self.rt.record(time, c);
        Ok(json!({"seq": seq}))
    }

    /// RegDeleteValue.
    pub fn delete_value(&mut self, path: &str, name: &str, time: &str) -> Result<Value, Rejected> {
        let nk = norm(path);
        let nn = norm(name);
        let (values, spelled) = {
            let live = self.live();
            (live.values(path), live.key_path(path))
        };
        let Some(values) = values else {
            return Err(not_found(format!("no key {path}")));
        };
        let Some((stored, _)) = values.iter().find(|(n, _)| norm(n) == nn).cloned() else {
            return Err(not_found(format!("no value {name} in {path}")));
        };
        let spelled = spelled.unwrap_or_else(|| path.to_string());
        let key = self.rt.copy_key(Some(values), &nk, spelled.clone());
        key.values.retain(|(n, _)| norm(n) != nn);
        self.rt.touch(&nk, time);
        let mut c = Map::new();
        c.insert("op".into(), "reg.delete_value".into());
        c.insert("key".into(), spelled.into());
        c.insert("name".into(), stored.into());
        let seq = self.rt.record(time, c);
        Ok(json!({"seq": seq}))
    }

    /// RegDeleteKey (no subkeys allowed) or, with `recursive`, RegDeleteTree.
    pub fn delete_key(
        &mut self,
        path: &str,
        recursive: bool,
        time: &str,
    ) -> Result<Value, Rejected> {
        let nk = norm(path);
        if nk.split('\\').count() < 2 {
            return Err(bad("cannot delete a hive root"));
        }
        let (exists, below, spelled) = {
            let live = self.live();
            (live.key_exists(path), live.below(&nk), live.key_path(path))
        };
        if !exists {
            return Err(not_found(format!("no key {path}")));
        }
        if !recursive && !below.is_empty() {
            return Err(Rejected(
                crate::protocol::code::HAS_SUBKEYS,
                format!("{path} has subkeys; pass recursive to delete the tree"),
            ));
        }
        for k in below.keys().chain(std::iter::once(&nk)) {
            self.rt.reg.insert(k.clone(), None);
            self.rt.last_write.remove(k);
        }
        if let Some(p) = parent(&nk) {
            self.rt.touch(p, time);
        }
        let mut c = Map::new();
        c.insert("op".into(), "reg.delete_key".into());
        c.insert(
            "key".into(),
            spelled.unwrap_or_else(|| path.to_string()).into(),
        );
        c.insert("recursive".into(), recursive.into());
        c.insert("deleted_keys".into(), (below.len() + 1).into());
        let seq = self.rt.record(time, c);
        Ok(json!({"seq": seq, "deleted_keys": below.len() + 1}))
    }
}

/// Changes to keyed lists and sections. `lower` is the merged base and profile state.
impl Runtime {
    /// Add an entry or merge into the one with the same name (base spelling kept).
    pub fn list_upsert(
        &mut self,
        list: &str,
        lower: Vec<Value>,
        item: &Value,
        time: &str,
    ) -> Result<Value, Rejected> {
        let Some(obj) = item.as_object() else {
            return Err(bad("item must be an object"));
        };
        let Some(name) = obj.get("name").and_then(Value::as_str) else {
            return Err(bad("item needs a text name"));
        };
        if obj.contains_key("remove") {
            return Err(bad("use list.remove to delete an entry"));
        }
        let entries = self.lists.entry(list.to_string()).or_insert(lower);
        let key = norm(name);
        let mut added = false;
        let stored = match entries
            .iter_mut()
            .find(|e| e["name"].as_str().map(norm).as_deref() == Some(key.as_str()))
        {
            Some(e) => {
                let spelled = e["name"].clone();
                let merged = merge_dict(e.as_object().expect("list entries are objects"), obj);
                *e = Value::Object(merged);
                e["name"] = spelled;
                e.clone()
            }
            None => {
                entries.push(item.clone());
                added = true;
                item.clone()
            }
        };
        let mut c = Map::new();
        c.insert("op".into(), "list.upsert".into());
        c.insert("list".into(), list.into());
        c.insert("item".into(), stored);
        c.insert("added".into(), added.into());
        let seq = self.record(time, c);
        Ok(json!({"seq": seq, "added": added}))
    }

    pub fn list_remove(
        &mut self,
        list: &str,
        lower: Vec<Value>,
        name: &str,
        time: &str,
    ) -> Result<Value, Rejected> {
        let entries = self.lists.entry(list.to_string()).or_insert(lower);
        let key = norm(name);
        let Some(pos) = entries
            .iter()
            .position(|e| e["name"].as_str().map(norm).as_deref() == Some(key.as_str()))
        else {
            return Err(not_found(format!("no {name} in {list}")));
        };
        let removed = entries.remove(pos);
        let mut c = Map::new();
        c.insert("op".into(), "list.remove".into());
        c.insert("list".into(), list.into());
        c.insert("name".into(), removed["name"].clone());
        let seq = self.record(time, c);
        Ok(json!({"seq": seq}))
    }

    /// Deep-merge a patch into a section. Nulls are refused: a section field is
    /// changed, never left undefined.
    pub fn section_update(
        &mut self,
        section: &str,
        lower: Option<Value>,
        patch: &Value,
        time: &str,
    ) -> Result<Value, Rejected> {
        let Some(p) = patch.as_object() else {
            return Err(bad("patch must be an object"));
        };
        fn has_null(v: &Value) -> bool {
            match v {
                Value::Null => true,
                Value::Object(m) => m.values().any(has_null),
                _ => false,
            }
        }
        if has_null(patch) {
            return Err(bad("patch may not contain null"));
        }
        if section == "network" && p.contains_key("interfaces") {
            return Err(bad("change interfaces with list.upsert and list.remove"));
        }
        let current = self
            .sections
            .get(section)
            .cloned()
            .or(lower)
            .unwrap_or_else(|| Value::Object(Map::new()));
        let Value::Object(cur) = current else {
            return Err(bad(format!("{section} is not an object")));
        };
        let merged = Value::Object(merge_dict(&cur, p));
        self.sections.insert(section.to_string(), merged);
        let mut c = Map::new();
        c.insert("op".into(), "section.update".into());
        c.insert("section".into(), section.into());
        c.insert("patch".into(), patch.clone());
        let seq = self.record(time, c);
        Ok(json!({"seq": seq}))
    }

    /// Drop every run-time change. The journal keeps counting and records the reset.
    pub fn reset(&mut self, time: &str) -> Value {
        self.reg.clear();
        self.last_write.clear();
        self.lists.clear();
        self.sections.clear();
        let mut c = Map::new();
        c.insert("op".into(), "reset".into());
        let seq = self.record(time, c);
        json!({"seq": seq})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(19_723), (2024, 1, 1));
        assert_eq!(civil(20_742), (2026, 10, 16));
        assert_eq!(civil(-1), (1969, 12, 31));
        assert_eq!(civil(11_016), (2000, 2, 29));
    }

    #[test]
    fn now_is_valid() {
        check_time(&now()).unwrap();
    }

    #[test]
    fn time_format() {
        for ok in ["2026-10-16T10:00:00Z", "2026-10-16T10:00:00.123Z"] {
            check_time(ok).unwrap();
        }
        for bad in [
            "2026-10-16 10:00:00Z",
            "2026-10-16T10:00:00",
            "2026-10-16T10:00:00.Z",
            "x",
        ] {
            assert!(check_time(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn values() {
        for ok in [
            json!({"type": "REG_SZ", "data": "x"}),
            json!({"type": "REG_MULTI_SZ", "data": ["a"]}),
            json!({"type": "REG_DWORD", "data": 4294967295u64}),
            json!({"type": "REG_QWORD", "data": 18446744073709551615u64}),
            json!({"type": "REG_BINARY", "data": "00ff"}),
        ] {
            check_value(&ok).unwrap();
        }
        for bad in [
            json!({"type": "REG_DWORD", "data": 4294967296u64}),
            json!({"type": "REG_DWORD", "data": -1}),
            json!({"type": "REG_BINARY", "data": "0F"}),
            json!({"type": "REG_BINARY", "data": "f"}),
            json!({"type": "REG_SZ", "data": 1}),
            json!({"type": "REG_NONE", "data": ""}),
            json!({"type": "REG_SZ", "data": "x", "extra": 1}),
        ] {
            assert!(check_value(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn keys() {
        check_key(r"HKLM\SOFTWARE\X").unwrap();
        check_key(r"hku\.DEFAULT").unwrap();
        assert!(check_key(r"HKEY_LOCAL_MACHINE\X").is_err());
        assert!(check_key(r"HKLM\\X").is_err());
        assert!(check_key(&format!(r"HKLM\{}", "a".repeat(256))).is_err());
    }
}
