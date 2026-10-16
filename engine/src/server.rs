//! The engine daemon: one thread per connection, one host per connection.

use std::io::{self, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{Map, Value, json};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use crate::apply::{self, Fail, apply, is_write};
use crate::files::ReadError;
use crate::persist::Persist;
use crate::protocol::{Request, Response, code, read_message, write_message};
use crate::runtime;
use crate::store::{Host, Store};

/// Where gap records go: one JSON object per line (CLAUDE.md rule 4).
pub type GapLog = Arc<Mutex<Box<dyn Write + Send>>>;

pub struct Server {
    store: Arc<Store>,
    gaps: GapLog,
    persist: Option<Arc<Persist>>,
}

/// Largest read answered in one message; the base64 text must fit `MAX_MESSAGE`.
const MAX_READ: usize = 4 * 1024 * 1024;

fn param<'a>(req: &'a Request, name: &str) -> Result<&'a str, Fail> {
    apply::text(&req.op, &req.params, name)
}

/// The scenario's clock for this change, or the engine's.
fn time_param(req: &Request) -> Result<String, Fail> {
    match req.params.get("time") {
        None => Ok(runtime::now()),
        Some(Value::String(t)) => {
            runtime::check_time(t)?;
            Ok(t.clone())
        }
        Some(_) => Err(Fail(code::BAD_REQUEST, "time must be text".into())),
    }
}

fn reg_value(name: String, v: &Value) -> Value {
    let mut out = Map::new();
    out.insert("name".into(), name.into());
    if let Value::Object(m) = v {
        for (k, x) in m {
            out.insert(k.clone(), x.clone());
        }
    }
    Value::Object(out)
}

impl Server {
    pub fn new(store: Arc<Store>, gaps: GapLog) -> Self {
        Server {
            store,
            gaps,
            persist: None,
        }
    }

    /// Log every applied change to `persist`, so it survives a restart.
    pub fn with_persistence(mut self, persist: Arc<Persist>) -> Self {
        self.persist = Some(persist);
        self
    }

    /// Apply a write and log it, under the host's write lock so the log order
    /// is the order of the changes. A rejected write is not logged.
    fn write(&self, req: &Request, h: &Host) -> Result<Value, Fail> {
        let mut params = req.params.clone();
        if params.contains_key("blob") {
            return Err(Fail(
                code::BAD_REQUEST,
                "blob is not a request parameter".into(),
            ));
        }
        params.insert("time".into(), time_param(req)?.into());
        let mut rt = h.write();
        let out = apply(h, &mut rt, &req.op, &params, None)?;
        if let Some(p) = &self.persist
            && let Err(e) = p.record(h, &rt, &req.op, &params)
        {
            // The change is applied; saving it failed. Say so rather than pretend.
            eprintln!("xvm-engined: {}: could not log {}: {e}", h.name, req.op);
            return Err(Fail(
                code::NOT_SAVED,
                format!("applied, but not saved: {e}"),
            ));
        }
        Ok(out)
    }

    fn log_gap(&self, host: Option<&Host>, op: &str) {
        self.log(host, json!({"gap": "engine-op", "op": op}));
    }

    /// Write one gap record, adding the host and its agent (CLAUDE.md rule 4).
    fn log(&self, host: Option<&Host>, mut record: Value) {
        record["host"] = host.map(|h| h.name.clone()).into();
        record["agent"] = host.and_then(|h| h.section("agent")).unwrap_or(Value::Null);
        if let Ok(mut w) = self.gaps.lock() {
            let _ = writeln!(w, "{record}");
            let _ = w.flush();
        }
    }

    fn file_read(&self, req: &Request, h: &Host) -> Result<Value, Fail> {
        let path = param(req, "path")?;
        h.rules().check(path)?;
        let rt = h.read();
        let files = h.files(&rt);
        let missing = || Fail(code::NOT_FOUND, format!("{path} does not exist"));
        match req.op.as_str() {
            "file.stat" => files.stat(path).ok_or_else(missing),
            "file.list" => match files.list(path) {
                Some(entries) => Ok(Value::Array(entries)),
                None if files.exists(path) => {
                    Err(Fail(code::NOT_A_DIRECTORY, format!("{path} is a file")))
                }
                None => Err(missing()),
            },
            _ => {
                let offset = match req.params.get("offset") {
                    None => 0,
                    Some(v) => v
                        .as_u64()
                        .and_then(|n| usize::try_from(n).ok())
                        .ok_or_else(|| {
                            Fail(code::BAD_REQUEST, "offset must be a whole number".into())
                        })?,
                };
                let length = match req.params.get("length") {
                    None => MAX_READ,
                    Some(v) => v
                        .as_u64()
                        .and_then(|n| usize::try_from(n).ok())
                        .ok_or_else(|| {
                            Fail(code::BAD_REQUEST, "length must be a whole number".into())
                        })?
                        .min(MAX_READ),
                };
                match files.read(path, offset, Some(length)) {
                    Ok((bytes, eof)) => Ok(json!({"data": B64.encode(bytes), "eof": eof})),
                    Err(ReadError::NotFound) => Err(missing()),
                    Err(ReadError::IsDirectory) => {
                        Err(Fail(code::IS_DIRECTORY, format!("{path} is a directory")))
                    }
                    Err(ReadError::NoContent) => {
                        drop(rt);
                        self.log(Some(h), json!({"gap": "file-content", "path": path}));
                        Err(Fail(
                            code::NO_CONTENT,
                            format!("{path} has metadata only; its bytes were not captured"),
                        ))
                    }
                }
            }
        }
    }

    /// Answer one request. `host` is the host bound by an earlier `hello`.
    pub fn handle(&self, req: &Request, host: &mut Option<Arc<Host>>) -> Response {
        match self.dispatch(req, host) {
            Ok(v) => Response::ok(req.id, v),
            Err(Fail(c, message)) => Response::err(req.id, c, message),
        }
    }

    fn dispatch(&self, req: &Request, host: &mut Option<Arc<Host>>) -> Result<Value, Fail> {
        if req.op == "hello" {
            let name = param(req, "host")?;
            let h = self
                .store
                .hosts
                .get(name)
                .ok_or_else(|| Fail(code::UNKNOWN_HOST, format!("no host named {name}")))?;
            *host = Some(h.clone());
            return Ok(json!({"name": h.name, "os": h.os(), "base": h.base.name}));
        }
        let h = host
            .as_deref()
            .ok_or_else(|| Fail(code::NO_HOST, "send hello first".into()))?;
        if is_write(&req.op) {
            return self.write(req, h);
        }
        let no_key = |k: &str| Fail(code::NOT_FOUND, format!("no key {k}"));
        let op = req.op.as_str();
        match op {
            "section" => {
                let n = apply::section_name(&req.op, &req.params)?;
                Ok(h.section(n).unwrap_or(Value::Null))
            }
            "list" => {
                let n = param(req, "name")?;
                h.list(n)
                    .map(Value::Array)
                    .ok_or_else(|| Fail(code::BAD_REQUEST, format!("unknown list {n}")))
            }
            "reg.key_exists" | "reg.key_path" | "reg.query_value" | "reg.enum_values"
            | "reg.enum_subkeys" | "reg.key_info" => {
                let k = param(req, "key")?;
                let rt = h.read();
                let reg = h.registry(&rt);
                match op {
                    "reg.key_exists" => Ok(Value::Bool(reg.key_exists(k))),
                    "reg.key_path" => reg.key_path(k).map(Value::String).ok_or_else(|| no_key(k)),
                    "reg.query_value" => {
                        let n = param(req, "name")?;
                        reg.value(k, n)
                            .map(|(name, v)| reg_value(name, &v))
                            .ok_or_else(|| Fail(code::NOT_FOUND, format!("no value {n} in {k}")))
                    }
                    "reg.enum_values" => {
                        let values = reg.values(k).ok_or_else(|| no_key(k))?;
                        Ok(Value::Array(
                            values.into_iter().map(|(n, v)| reg_value(n, &v)).collect(),
                        ))
                    }
                    "reg.enum_subkeys" => {
                        let names = reg.subkeys(k).ok_or_else(|| no_key(k))?;
                        Ok(Value::Array(names.into_iter().map(Value::String).collect()))
                    }
                    _ => reg.key_info(k).ok_or_else(|| no_key(k)),
                }
            }
            "changes" => {
                let since = match req.params.get("since") {
                    None => 0,
                    Some(v) => v.as_u64().ok_or_else(|| {
                        Fail(code::BAD_REQUEST, "since must be a whole number".into())
                    })?,
                };
                let limit = match req.params.get("limit") {
                    None => 1000,
                    Some(v) => v.as_u64().filter(|&n| n > 0).ok_or_else(|| {
                        Fail(code::BAD_REQUEST, "limit must be a positive number".into())
                    })? as usize,
                };
                Ok(h.read().changes(since, limit))
            }
            "file.stat" | "file.list" | "file.read" => self.file_read(req, h),
            "proc.list" => Ok(Value::Array(h.read().procs.list())),
            "proc.get" => {
                let pid = apply::whole(&req.op, &req.params, "pid")?;
                h.read()
                    .procs
                    .get(pid)
                    .ok_or_else(|| Fail(code::NOT_FOUND, format!("no running process {pid}")))
            }
            "resolved" => Ok(h.resolved()),
            other => {
                self.log_gap(Some(h), other);
                Err(Fail(
                    code::UNSUPPORTED,
                    format!("op {other} is not implemented"),
                ))
            }
        }
    }

    /// Serve one connection until the peer closes it.
    pub fn serve_connection(&self, mut stream: UnixStream) -> io::Result<()> {
        let mut host: Option<Arc<Host>> = None;
        while let Some(body) = read_message(&mut stream)? {
            let resp = match serde_json::from_slice::<Request>(&body) {
                Ok(req) => self.handle(&req, &mut host),
                Err(e) => Response::err(0, code::BAD_REQUEST, format!("bad request: {e}")),
            };
            write_message(&mut stream, &resp)?;
        }
        Ok(())
    }

    /// Accept connections forever, one thread each.
    pub fn run(self: Arc<Self>, listener: UnixListener) -> io::Result<()> {
        for stream in listener.incoming() {
            let stream = stream?;
            let server = self.clone();
            thread::spawn(move || {
                if let Err(e) = server.serve_connection(stream) {
                    eprintln!("xvm-engine: connection error: {e}");
                }
            });
        }
        Ok(())
    }
}
