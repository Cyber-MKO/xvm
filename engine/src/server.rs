//! The engine daemon: one thread per connection, one host per connection.

use std::io::{self, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use crate::apply::{self, Fail, apply, is_write};
use crate::eventlog::{self, Event, check_event, declared_channels, find_template, format_message};
use crate::evtquery;
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

/// Longest `evt.wait`, in milliseconds.
const MAX_WAIT_MS: u64 = 60_000;

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

    fn evt_channels(&self, h: &Host) -> Value {
        let rt = h.read();
        let declared = declared_channels(&h.registry(&rt));
        let logs = h.events_read();
        let list: Vec<Value> = declared
            .iter()
            .map(
                |(key, (name, max, from_reg))| match logs.channels.get(key) {
                    Some(ch) => ch.info(),
                    None => eventlog::Channel::new(name.clone(), *max, *from_reg).info(),
                },
            )
            .collect();
        Value::Array(list)
    }

    fn evt_write(&self, req: &Request, h: &Host) -> Result<Value, Fail> {
        let channel = param(req, "channel")?;
        let time = time_param(req)?;
        let raw = req
            .params
            .get("event")
            .ok_or_else(|| Fail(code::BAD_REQUEST, "evt.write needs event".into()))?;
        let doc = check_event(raw, &time)?;
        let rt = h.read();
        let computer = h.computer(&rt);
        let reg = h.registry(&rt);
        let mut logs = h.events_write();
        let ch = logs.channel_mut(channel, &reg)?;
        let mut e = Event {
            record_id: ch.next_record_id,
            channel: ch.name.clone(),
            computer,
            doc,
            size: 0,
        };
        let line = serde_json::to_string(&e.to_value()).unwrap_or_default();
        e.size = line.len() + 1;
        let record_id = e.record_id;
        let oldest = ch.push(Arc::new(e));
        // Waiters wake now and read once this write releases the log lock.
        h.signal_events(false);
        if let Some(p) = &self.persist
            && let Err(err) = p.append_event(h, ch, &line, oldest)
        {
            eprintln!(
                "xvm-engined: {}: could not save event {record_id}: {err}",
                h.name
            );
            return Err(Fail(
                code::NOT_SAVED,
                format!("event {record_id} kept, but not saved: {err}"),
            ));
        }
        Ok(json!({"record_id": record_id, "channel": ch.name}))
    }

    /// Block until `channel` has a record after `after`, the logs are reset, or
    /// `timeout_ms` passes. Only this connection waits; others carry on.
    fn evt_wait(&self, req: &Request, h: &Host) -> Result<Value, Fail> {
        let channel = param(req, "channel")?;
        let after = match req.params.get("after") {
            None => 0,
            Some(_) => apply::whole(&req.op, &req.params, "after")?,
        };
        let timeout = match req.params.get("timeout_ms") {
            None => 0,
            Some(_) => apply::whole(&req.op, &req.params, "timeout_ms")?,
        };
        if timeout > MAX_WAIT_MS {
            return Err(Fail(
                code::BAD_REQUEST,
                format!("timeout_ms must be at most {MAX_WAIT_MS}"),
            ));
        }
        {
            let rt = h.read();
            if !declared_channels(&h.registry(&rt)).contains_key(&crate::merge::norm(channel)) {
                return Err(Fail(code::NOT_FOUND, format!("no event channel {channel}")));
            }
        }
        let deadline = Instant::now() + Duration::from_millis(timeout);
        let start = h.event_signal();
        let mut seen = start;
        loop {
            // The newest record ever written: retention may have dropped it, but
            // a reader still needs to know the log moved past `after`.
            let newest = h
                .events_read()
                .channel(channel)
                .map_or(0, |c| c.next_record_id - 1);
            let answer = |reset: bool, timed_out: bool| json!({"newest_record_id": newest, "reset": reset, "timed_out": timed_out});
            // `after` beyond anything written means the log was reset since the reader read it.
            if after > newest || seen.resets != start.resets {
                return Ok(answer(true, false));
            }
            if newest > after {
                return Ok(answer(false, false));
            }
            if Instant::now() >= deadline {
                return Ok(answer(false, true));
            }
            seen = h.wait_events(seen, deadline);
        }
    }

    fn evt_query(&self, req: &Request, h: &Host) -> Result<Value, Fail> {
        let channel = param(req, "channel")?;
        let after = match req.params.get("after") {
            None => 0,
            Some(_) => apply::whole(&req.op, &req.params, "after")?,
        };
        let limit = match req.params.get("limit") {
            None => 100,
            Some(_) => apply::whole(&req.op, &req.params, "limit")?.clamp(1, 1000) as usize,
        };
        let as_json = match req.params.get("format").and_then(Value::as_str) {
            None | Some("xml") => false,
            Some("json") => true,
            Some(other) => return Err(Fail(code::BAD_REQUEST, format!("unknown format {other}"))),
        };
        let text = req
            .params
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or("*");
        let expr = match evtquery::parse(text, channel) {
            Ok(Some(e)) => e,
            Ok(None) => return Ok(json!({"events": [], "more": false, "last_record_id": after})),
            Err(why) => {
                self.log(
                    Some(h),
                    json!({"gap": "event-query", "query": text, "why": why}),
                );
                return Err(Fail(code::BAD_QUERY, why));
            }
        };
        {
            let rt = h.read();
            let declared = declared_channels(&h.registry(&rt));
            if !declared.contains_key(&crate::merge::norm(channel)) {
                return Err(Fail(code::NOT_FOUND, format!("no event channel {channel}")));
            }
        }
        let logs = h.events_read();
        let (events, more) = logs.read(channel, after, &expr, limit, &runtime::now());
        let last = events.last().map_or(after, |e| e.record_id);
        let list: Vec<Value> = events
            .iter()
            .map(|e| {
                if as_json {
                    e.to_value()
                } else {
                    json!({"record_id": e.record_id, "xml": e.xml()})
                }
            })
            .collect();
        Ok(json!({"events": list, "more": more, "last_record_id": last}))
    }

    fn evt_record(&self, req: &Request, h: &Host) -> Result<Arc<Event>, Fail> {
        let channel = param(req, "channel")?;
        let id = apply::whole(&req.op, &req.params, "record_id")?;
        let logs = h.events_read();
        let ch = logs
            .channel(channel)
            .ok_or_else(|| Fail(code::NOT_FOUND, format!("no events in {channel}")))?;
        let i = ch
            .events
            .binary_search_by_key(&id, |e| e.record_id)
            .map_err(|_| Fail(code::NOT_FOUND, format!("no record {id} in {channel}")))?;
        Ok(ch.events[i].clone())
    }

    /// EvtFormatMessage for the event's message: its own text, or the host's template.
    fn evt_message(&self, req: &Request, h: &Host) -> Result<Value, Fail> {
        let e = self.evt_record(req, h)?;
        if let Some(m) = e.doc.get("message").and_then(Value::as_str) {
            return Ok(json!({"message": m, "source": "event"}));
        }
        let gap = |why: &str| {
            json!({"gap": "event-message", "provider": e.doc["provider"], "event_id": e.doc["event_id"],
                   "version": e.doc.get("version"), "why": why})
        };
        let Some(template) = find_template(&h.event_messages, &e) else {
            self.log(Some(h), gap("no template"));
            return Err(Fail(
                code::NO_MESSAGE,
                "no message template for this event".into(),
            ));
        };
        match format_message(template, &e.data()) {
            Ok(m) => Ok(json!({"message": m, "source": "template"})),
            Err(why) => {
                self.log(Some(h), gap(&why));
                Err(Fail(code::NO_MESSAGE, why))
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
            "evt.channels" => Ok(self.evt_channels(h)),
            "evt.write" => self.evt_write(req, h),
            "evt.query" => self.evt_query(req, h),
            "evt.wait" => self.evt_wait(req, h),
            "evt.get" => {
                let e = self.evt_record(req, h)?;
                let mut v = e.to_value();
                v["xml"] = e.xml().into();
                Ok(v)
            }
            "evt.format_message" => self.evt_message(req, h),
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
