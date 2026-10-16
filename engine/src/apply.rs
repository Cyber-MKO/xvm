//! Every run-time write, in one place.
//!
//! The server applies a request through `apply`, and so does log replay after a
//! restart, so a replayed change takes exactly the path the original did. The
//! parameters must already carry the change's `time`; the server fills it in
//! before applying and logging.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Map, Value, json};

use crate::files::{Blobs, WriteMode};
use crate::procs;
use crate::protocol::code;
use crate::runtime::{Rejected, Runtime, check_time};
use crate::store::{Host, SECTIONS};

/// Ops that change a host. Only these are logged for persistence.
pub const WRITE_OPS: [&str; 15] = [
    "reg.create_key",
    "reg.set_value",
    "reg.delete_value",
    "reg.delete_key",
    "list.upsert",
    "list.remove",
    "section.update",
    "file.write",
    "file.mkdir",
    "file.delete",
    "file.rename",
    "file.set",
    "proc.start",
    "proc.exit",
    "reset",
];

pub fn is_write(op: &str) -> bool {
    WRITE_OPS.contains(&op)
}

/// A failed request: an error code and a message.
#[derive(Debug)]
pub struct Fail(pub &'static str, pub String);

impl From<Rejected> for Fail {
    fn from(r: Rejected) -> Self {
        Fail(r.0, r.1)
    }
}

fn bad(msg: impl Into<String>) -> Fail {
    Fail(code::BAD_REQUEST, msg.into())
}

pub fn text<'a>(op: &str, p: &'a Map<String, Value>, name: &str) -> Result<&'a str, Fail> {
    p.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| bad(format!("{op} needs text parameter {name}")))
}

pub fn whole(op: &str, p: &Map<String, Value>, name: &str) -> Result<u64, Fail> {
    p.get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| bad(format!("{op} needs whole-number parameter {name}")))
}

fn flag(p: &Map<String, Value>, name: &str) -> Result<bool, Fail> {
    match p.get(name) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(bad(format!("{name} must be true or false"))),
    }
}

pub fn section_name<'a>(op: &str, p: &'a Map<String, Value>) -> Result<&'a str, Fail> {
    let n = text(op, p, "name")?;
    if SECTIONS.contains(&n) {
        Ok(n)
    } else {
        Err(bad(format!("unknown section {n}")))
    }
}

/// The bytes of a `file.write`: inline base64 from a client, or a blob
/// reference written by the persistence layer.
fn write_data(p: &Map<String, Value>, blobs: Option<&dyn Blobs>) -> Result<Vec<u8>, Fail> {
    if let Some(sha) = p.get("blob").and_then(Value::as_str) {
        let store = blobs.ok_or_else(|| bad("blob data is only accepted from the state log"))?;
        return store
            .get(sha)
            .map(|b| b.to_vec())
            .map_err(|e| Fail(code::NOT_FOUND, e));
    }
    B64.decode(text("file.write", p, "data")?)
        .map_err(|e| bad(format!("data is not base64: {e}")))
}

/// Apply one write. `blobs` resolves `file.write` blob references during replay.
pub fn apply(
    h: &Host,
    rt: &mut Runtime,
    op: &str,
    p: &Map<String, Value>,
    blobs: Option<&dyn Blobs>,
) -> Result<Value, Fail> {
    let time = text(op, p, "time")?.to_string();
    check_time(&time)?;
    match op {
        "reg.create_key" | "reg.set_value" | "reg.delete_value" | "reg.delete_key" => {
            let k = text(op, p, "key")?;
            let mut w = h.registry_writer(rt);
            let done = match op {
                "reg.create_key" => w.create_key(k, &time),
                "reg.set_value" => {
                    let value = json!({
                        "type": p.get("type").cloned().unwrap_or(Value::Null),
                        "data": p.get("data").cloned().unwrap_or(Value::Null),
                    });
                    w.set_value(k, text(op, p, "name")?, &value, &time)
                }
                "reg.delete_value" => w.delete_value(k, text(op, p, "name")?, &time),
                _ => w.delete_key(k, flag(p, "recursive")?, &time),
            };
            Ok(done?)
        }
        "list.upsert" | "list.remove" => {
            let n = text(op, p, "name")?;
            let lower = h
                .list_with(rt, n)
                .ok_or_else(|| bad(format!("unknown list {n}")))?;
            let done = if op == "list.upsert" {
                let item = p.get("item").ok_or_else(|| bad("list.upsert needs item"))?;
                rt.list_upsert(n, lower, item, &time)
            } else {
                rt.list_remove(n, lower, text(op, p, "item")?, &time)
            };
            Ok(done?)
        }
        "section.update" => {
            let n = section_name(op, p)?;
            let patch = p
                .get("patch")
                .ok_or_else(|| bad("section.update needs patch"))?;
            if n == "identity" && patch.get("hostname").is_some() {
                // Renaming a host would break every component that knows it by name.
                return Err(bad("identity.hostname cannot change at run time"));
            }
            let lower = h.section_with(rt, n);
            Ok(rt.section_update(n, lower, patch, &time)?)
        }
        "file.write" | "file.mkdir" | "file.delete" | "file.rename" | "file.set" => {
            file_write(h, rt, op, p, &time, blobs)
        }
        "proc.start" => {
            let mut fields = p.clone();
            fields.remove("time");
            let started = rt.procs.start(&fields, &time)?;
            let seq = rt.record(&time, procs::journal_entry("proc.start", &started, None));
            let mut out = started.to_value();
            out["seq"] = seq.into();
            Ok(out)
        }
        "proc.exit" => {
            let pid = whole(op, p, "pid")?;
            let exit_code = match p.get("exit_code") {
                None => 0,
                Some(v) => v
                    .as_i64()
                    .ok_or_else(|| bad("exit_code must be a whole number"))?,
            };
            let ended = rt.procs.exit(pid)?;
            let seq = rt.record(
                &time,
                procs::journal_entry("proc.exit", &ended, Some(exit_code)),
            );
            Ok(json!({"seq": seq}))
        }
        "reset" => Ok(h.reset(rt, &time)),
        other => Err(Fail(code::UNSUPPORTED, format!("{other} is not a write"))),
    }
}

fn file_write(
    h: &Host,
    rt: &mut Runtime,
    op: &str,
    p: &Map<String, Value>,
    time: &str,
    blobs: Option<&dyn Blobs>,
) -> Result<Value, Fail> {
    let mut w = h.files_writer(rt);
    let mut change = Map::new();
    let out = match op {
        "file.write" => {
            let path = text(op, p, "path")?;
            let data = write_data(p, blobs)?;
            let append = flag(p, "append")?;
            let mode = match (p.get("offset"), append) {
                (Some(_), true) => return Err(bad("give offset or append, not both")),
                (Some(v), false) => WriteMode::At(
                    v.as_u64()
                        .and_then(|n| usize::try_from(n).ok())
                        .ok_or_else(|| bad("offset must be a whole number"))?,
                ),
                (None, true) => WriteMode::Append,
                (None, false) => WriteMode::Replace,
            };
            let out = w.write(path, &data, mode, time)?;
            change.insert("path".into(), out["path"].clone());
            change.insert("size".into(), out["size"].clone());
            let mode_name = match mode {
                WriteMode::Replace => "replace",
                WriteMode::Append => "append",
                WriteMode::At(_) => "offset",
            };
            change.insert("mode".into(), mode_name.into());
            out
        }
        "file.mkdir" => {
            let out = w.mkdir(text(op, p, "path")?, time)?;
            change.insert("path".into(), out["path"].clone());
            out
        }
        "file.delete" => {
            let out = w.delete(text(op, p, "path")?, flag(p, "recursive")?)?;
            change.insert("path".into(), out["path"].clone());
            change.insert("deleted".into(), out["deleted"].clone());
            out
        }
        "file.rename" => {
            let out = w.rename(text(op, p, "from")?, text(op, p, "to")?, time)?;
            change.insert("from".into(), out["from"].clone());
            change.insert("to".into(), out["to"].clone());
            out
        }
        _ => {
            let patch = p
                .get("patch")
                .and_then(Value::as_object)
                .ok_or_else(|| bad("file.set needs an object patch"))?;
            let out = w.set(text(op, p, "path")?, patch)?;
            change.insert("path".into(), out["path"].clone());
            change.insert("patch".into(), Value::Object(patch.clone()));
            out
        }
    };
    change.insert("op".into(), op.into());
    let seq = rt.record(time, change);
    let mut out = out;
    out["seq"] = seq.into();
    Ok(out)
}
