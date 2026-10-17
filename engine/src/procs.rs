//! Process table: processes from the profile at boot, plus starts and exits at run time.
//!
//! PIDs are assigned by the engine. They are deterministic per host (seeded by
//! the host name), so a host gets the same PIDs every time it starts, and
//! different hosts get different PIDs, like a real fleet. Windows PIDs are
//! multiples of 4; Linux and macOS PIDs count up. A profile may pin a PID, for
//! example System at 4, and `proc.start` may ask for one, for example the
//! agent's PID from the loader profile.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::protocol::code;
use crate::runtime::Rejected;

/// Fields a caller may give when starting a process.
const START_FIELDS: [&str; 9] = [
    "image",
    "pid",
    "path",
    "command_line",
    "user",
    "session",
    "parent_pid",
    "native_pid",
    "time",
];
const WINDOWS_PID_MAX: u64 = 65_536;
const UNIX_PID_MAX: u64 = 4_194_304;

#[derive(Debug, Clone, PartialEq)]
pub struct Process {
    pub pid: u64,
    pub ppid: u64,
    pub image: String,
    pub fields: Map<String, Value>,
    pub start_time: String,
    /// The profile id, for processes defined by the profile.
    pub profile_id: Option<String>,
}

impl Process {
    pub fn to_value(&self) -> Value {
        let mut out = Map::new();
        out.insert("pid".into(), self.pid.into());
        out.insert("ppid".into(), self.ppid.into());
        out.insert("image".into(), self.image.clone().into());
        for (k, v) in &self.fields {
            out.insert(k.clone(), v.clone());
        }
        out.insert("start_time".into(), self.start_time.clone().into());
        if let Some(id) = &self.profile_id {
            out.insert("profile_id".into(), id.clone().into());
        }
        Value::Object(out)
    }
}

/// Deterministic PID source for one host.
#[derive(Debug, Clone, Default)]
pub struct PidGen {
    windows: bool,
    state: u64,
    next_seq: u64,
    /// Every PID handed out, so none repeats while others are free.
    used: BTreeSet<u64>,
}

fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

impl PidGen {
    pub fn new(host: &str, windows: bool) -> Self {
        PidGen {
            windows,
            state: fnv1a(host),
            next_seq: 1,
            used: BTreeSet::new(),
        }
    }

    fn splitmix(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn reserve(&mut self, pid: u64) {
        self.used.insert(pid);
    }

    /// A PID not in `live`, preferring one never used before.
    pub fn next(&mut self, live: &BTreeMap<u64, Process>) -> Option<u64> {
        if self.windows {
            // 8..65532 in steps of 4; 0 and 4 belong to Idle and System.
            let slots = WINDOWS_PID_MAX / 4 - 2;
            for _ in 0..4096 {
                let pid = (self.splitmix() % slots + 2) * 4;
                if !self.used.contains(&pid) && !live.contains_key(&pid) {
                    self.used.insert(pid);
                    return Some(pid);
                }
            }
            let pid = (2..WINDOWS_PID_MAX / 4)
                .map(|n| n * 4)
                .find(|p| !live.contains_key(p))?;
            self.used.insert(pid);
            return Some(pid);
        }
        for _ in 0..UNIX_PID_MAX {
            let pid = self.next_seq;
            self.next_seq = if self.next_seq + 1 >= UNIX_PID_MAX {
                2
            } else {
                self.next_seq + 1
            };
            if !live.contains_key(&pid) && !self.used.contains(&pid) {
                self.used.insert(pid);
                return Some(pid);
            }
        }
        // Every PID was used once: allow reuse of exited ones.
        let pid = (2..UNIX_PID_MAX).find(|p| !live.contains_key(p))?;
        Some(pid)
    }
}

/// Add seconds to an RFC 3339 UTC time (`...Z`).
fn add_seconds(base: &str, secs: f64) -> String {
    let Some(t0) = crate::runtime::parse_ms(base) else {
        return base.to_string();
    };
    crate::runtime::format_ms(t0 + (secs * 1000.0).round() as i64)
}

/// The process table as the profile defines it at boot.
pub fn boot_table(
    defs: &[Value],
    host: &str,
    windows: bool,
    boot: &str,
) -> Result<(BTreeMap<u64, Process>, PidGen), String> {
    let mut pidgen = PidGen::new(host, windows);
    let mut pids: BTreeMap<String, u64> = BTreeMap::new();
    for d in defs {
        if let Some(pid) = d.get("pid").and_then(Value::as_u64) {
            pidgen.reserve(pid);
        }
    }
    let mut table = BTreeMap::new();
    for d in defs {
        let id = d
            .get("id")
            .and_then(Value::as_str)
            .ok_or("a process needs an id")?;
        let pid = match d.get("pid").and_then(Value::as_u64) {
            Some(p) => p,
            None => pidgen.next(&table).ok_or("no free PID")?,
        };
        if pids.insert(id.to_string(), pid).is_some() {
            return Err(format!("duplicate process id {id}"));
        }
        table.insert(
            pid,
            Process {
                pid,
                ppid: 0,
                image: String::new(),
                fields: Map::new(),
                start_time: String::new(),
                profile_id: None,
            },
        );
    }
    for d in defs {
        let id = d["id"].as_str().unwrap_or_default();
        let pid = pids[id];
        let image = d
            .get("image")
            .and_then(Value::as_str)
            .ok_or(format!("process {id} has no image"))?;
        let ppid = match d.get("parent").and_then(Value::as_str) {
            Some(p) => *pids
                .get(p)
                .ok_or(format!("process {id} names unknown parent {p}"))?,
            None => 0,
        };
        let offset = d
            .get("start_offset_s")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let mut fields = Map::new();
        for k in ["path", "command_line", "user", "session"] {
            if let Some(v) = d.get(k) {
                fields.insert(k.into(), v.clone());
            }
        }
        table.insert(
            pid,
            Process {
                pid,
                ppid,
                image: image.to_string(),
                fields,
                start_time: add_seconds(boot, offset),
                profile_id: Some(id.to_string()),
            },
        );
    }
    Ok((table, pidgen))
}

/// Live processes of one host.
#[derive(Debug, Clone, Default)]
pub struct ProcTable {
    pub live: BTreeMap<u64, Process>,
    pub pids: PidGen,
}

impl ProcTable {
    pub fn list(&self) -> Vec<Value> {
        self.live.values().map(Process::to_value).collect()
    }

    pub fn get(&self, pid: u64) -> Option<Value> {
        self.live.get(&pid).map(Process::to_value)
    }

    /// Start a process. `params` holds the caller's fields; `time` is already checked.
    pub fn start(&mut self, params: &Map<String, Value>, time: &str) -> Result<Process, Rejected> {
        let bad = |m: String| Rejected(code::BAD_REQUEST, m);
        if let Some(k) = params.keys().find(|k| !START_FIELDS.contains(&k.as_str())) {
            return Err(bad(format!("proc.start does not take {k}")));
        }
        let image = params
            .get("image")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| bad("proc.start needs an image".into()))?;
        for k in ["path", "command_line", "user"] {
            if params.get(k).is_some_and(|v| !v.is_string()) {
                return Err(bad(format!("{k} must be text")));
            }
        }
        for k in ["session", "native_pid"] {
            if params.get(k).is_some_and(|v| v.as_u64().is_none()) {
                return Err(bad(format!("{k} must be a whole number")));
            }
        }
        let ppid = match params.get("parent_pid") {
            None => 0,
            Some(v) => {
                let p = v
                    .as_u64()
                    .ok_or_else(|| bad("parent_pid must be a whole number".into()))?;
                if !self.live.contains_key(&p) {
                    return Err(Rejected(code::NOT_FOUND, format!("no running process {p}")));
                }
                p
            }
        };
        let pid = match params.get("pid") {
            Some(v) => {
                let pid = v
                    .as_u64()
                    .ok_or_else(|| bad("pid must be a whole number".into()))?;
                self.requested_pid(pid)?
            }
            None => self
                .pids
                .next(&self.live)
                .ok_or_else(|| Rejected(code::BAD_REQUEST, "no free PID".into()))?,
        };
        let mut fields = Map::new();
        for k in ["path", "command_line", "user", "session", "native_pid"] {
            if let Some(v) = params.get(k) {
                fields.insert(k.into(), v.clone());
            }
        }
        let p = Process {
            pid,
            ppid,
            image: image.to_string(),
            fields,
            start_time: time.to_string(),
            profile_id: None,
        };
        self.live.insert(pid, p.clone());
        Ok(p)
    }

    /// Check a PID the caller asked for and claim it.
    fn requested_pid(&mut self, pid: u64) -> Result<u64, Rejected> {
        let valid = if self.pids.windows {
            pid != 0 && pid.is_multiple_of(4) && pid < WINDOWS_PID_MAX
        } else {
            pid != 0 && pid < UNIX_PID_MAX
        };
        if !valid {
            let rule = if self.pids.windows {
                "a non-zero multiple of 4 below 65536"
            } else {
                "between 1 and 4194303"
            };
            return Err(Rejected(
                code::BAD_REQUEST,
                format!("pid {pid} is not valid: it must be {rule}"),
            ));
        }
        if self.live.contains_key(&pid) {
            return Err(Rejected(code::EXISTS, format!("pid {pid} is in use")));
        }
        self.pids.reserve(pid);
        Ok(pid)
    }

    /// End a process. Its children keep running and keep their parent PID, as on Windows.
    pub fn exit(&mut self, pid: u64) -> Result<Process, Rejected> {
        self.live
            .remove(&pid)
            .ok_or_else(|| Rejected(code::NOT_FOUND, format!("no running process {pid}")))
    }
}

impl ProcTable {
    pub fn to_snapshot(&self) -> Value {
        let live: Vec<Value> = self
            .live
            .values()
            .map(|p| {
                serde_json::json!({
                    "pid": p.pid, "ppid": p.ppid, "image": p.image, "fields": p.fields,
                    "start_time": p.start_time, "profile_id": p.profile_id,
                })
            })
            .collect();
        serde_json::json!({
            "live": live,
            "pids": {
                "windows": self.pids.windows,
                "state": self.pids.state.to_string(),
                "next_seq": self.pids.next_seq,
                "used": self.pids.used.iter().collect::<Vec<_>>(),
            },
        })
    }

    pub fn from_snapshot(v: &Value) -> Result<Self, String> {
        let bad = || "malformed process table in snapshot".to_string();
        let mut live = BTreeMap::new();
        for p in v["live"].as_array().ok_or_else(bad)? {
            let pid = p["pid"].as_u64().ok_or_else(bad)?;
            live.insert(
                pid,
                Process {
                    pid,
                    ppid: p["ppid"].as_u64().ok_or_else(bad)?,
                    image: p["image"].as_str().ok_or_else(bad)?.to_string(),
                    fields: p["fields"].as_object().cloned().unwrap_or_default(),
                    start_time: p["start_time"].as_str().unwrap_or_default().to_string(),
                    profile_id: p["profile_id"].as_str().map(str::to_string),
                },
            );
        }
        let g = &v["pids"];
        let pids = PidGen {
            windows: g["windows"].as_bool().ok_or_else(bad)?,
            // A string: JSON numbers lose precision past 2^53.
            state: g["state"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .ok_or_else(bad)?,
            next_seq: g["next_seq"].as_u64().ok_or_else(bad)?,
            used: g["used"]
                .as_array()
                .ok_or_else(bad)?
                .iter()
                .filter_map(Value::as_u64)
                .collect(),
        };
        Ok(ProcTable { live, pids })
    }
}

/// Make a process-table change into a journal entry.
pub fn journal_entry(op: &str, p: &Process, exit_code: Option<i64>) -> Map<String, Value> {
    let mut c = Map::new();
    c.insert("op".into(), op.into());
    c.insert("pid".into(), p.pid.into());
    c.insert("ppid".into(), p.ppid.into());
    c.insert("image".into(), p.image.clone().into());
    if let Some(code) = exit_code {
        c.insert("exit_code".into(), code.into());
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_seconds_crosses_days() {
        assert_eq!(
            add_seconds("2026-10-16T23:59:59Z", 2.5),
            "2026-10-17T00:00:01.500Z"
        );
        assert_eq!(
            add_seconds("2024-02-28T00:00:00Z", 86_400.0),
            "2024-02-29T00:00:00.000Z"
        );
        assert_eq!(
            add_seconds("2026-01-01T00:00:00.25Z", 0.5),
            "2026-01-01T00:00:00.750Z"
        );
        assert_eq!(
            add_seconds("1969-12-31T23:59:59Z", 1.0),
            "1970-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn windows_pids_are_multiples_of_four_and_deterministic() {
        let live = BTreeMap::new();
        let mut a = PidGen::new("host-a", true);
        let mut b = PidGen::new("host-a", true);
        let mut c = PidGen::new("host-b", true);
        let pa: Vec<u64> = (0..50).map(|_| a.next(&live).unwrap()).collect();
        let pb: Vec<u64> = (0..50).map(|_| b.next(&live).unwrap()).collect();
        let pc: Vec<u64> = (0..50).map(|_| c.next(&live).unwrap()).collect();
        assert_eq!(pa, pb);
        assert_ne!(pa, pc);
        assert!(
            pa.iter()
                .all(|p| p % 4 == 0 && *p >= 8 && *p < WINDOWS_PID_MAX)
        );
        let unique: BTreeSet<_> = pa.iter().collect();
        assert_eq!(unique.len(), 50);
    }

    #[test]
    fn unix_pids_count_up_and_skip_reserved() {
        let live = BTreeMap::new();
        let mut g = PidGen::new("h", false);
        g.reserve(2);
        let got: Vec<u64> = (0..3).map(|_| g.next(&live).unwrap()).collect();
        assert_eq!(got, [1, 3, 4]);
    }
}
