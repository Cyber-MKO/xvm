//! The engine daemon: one thread per connection, one host per connection.

use std::io::{self, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{Map, Value, json};

use crate::protocol::{Request, Response, code, read_message, write_message};
use crate::store::{Host, SECTIONS, Store};

/// Where gap records go: one JSON object per line (CLAUDE.md rule 4).
pub type GapLog = Arc<Mutex<Box<dyn Write + Send>>>;

pub struct Server {
    store: Arc<Store>,
    gaps: GapLog,
}

/// A failed request: an error code and a message. Kept small; becomes a Response at the end.
struct Fail(&'static str, String);

fn param<'a>(req: &'a Request, name: &str) -> Result<&'a str, Fail> {
    req.params.get(name).and_then(Value::as_str).ok_or_else(|| {
        Fail(
            code::BAD_REQUEST,
            format!("{} needs text parameter {name}", req.op),
        )
    })
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
        Server { store, gaps }
    }

    fn log_gap(&self, host: Option<&Host>, op: &str) {
        let agent = host.and_then(|h| h.section("agent"));
        let record = json!({
            "gap": "engine-op",
            "op": op,
            "host": host.map(|h| h.name.clone()),
            "agent": agent,
        });
        if let Ok(mut w) = self.gaps.lock() {
            let _ = writeln!(w, "{record}");
            let _ = w.flush();
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
        let reg = h.registry();
        let no_key = |k: &str| Fail(code::NOT_FOUND, format!("no key {k}"));
        match req.op.as_str() {
            "section" => {
                let n = param(req, "name")?;
                if !SECTIONS.contains(&n) {
                    return Err(Fail(code::BAD_REQUEST, format!("unknown section {n}")));
                }
                Ok(h.section(n).unwrap_or(Value::Null))
            }
            "list" => {
                let n = param(req, "name")?;
                h.list(n)
                    .map(Value::Array)
                    .ok_or_else(|| Fail(code::BAD_REQUEST, format!("unknown list {n}")))
            }
            "reg.key_exists" => Ok(Value::Bool(reg.key_exists(param(req, "key")?))),
            "reg.key_path" => {
                let k = param(req, "key")?;
                reg.key_path(k).map(Value::String).ok_or_else(|| no_key(k))
            }
            "reg.query_value" => {
                let k = param(req, "key")?;
                let n = param(req, "name")?;
                reg.value(k, n)
                    .map(|(name, v)| reg_value(name, &v))
                    .ok_or_else(|| Fail(code::NOT_FOUND, format!("no value {n} in {k}")))
            }
            "reg.enum_values" => {
                let k = param(req, "key")?;
                let values = reg.values(k).ok_or_else(|| no_key(k))?;
                Ok(Value::Array(
                    values.into_iter().map(|(n, v)| reg_value(n, &v)).collect(),
                ))
            }
            "reg.enum_subkeys" => {
                let k = param(req, "key")?;
                let names = reg.subkeys(k).ok_or_else(|| no_key(k))?;
                Ok(Value::Array(names.into_iter().map(Value::String).collect()))
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
