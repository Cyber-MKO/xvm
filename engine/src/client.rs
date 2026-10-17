//! Blocking client for personality runtimes. Builds for i686 and x86_64.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

use serde_json::{Map, Value, json};

use crate::protocol::{ErrorBody, Request, Response, read_message, write_message};

#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    /// The engine answered with an error.
    Engine(ErrorBody),
    Protocol(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "engine connection: {e}"),
            ClientError::Engine(e) => write!(f, "engine: {}: {}", e.code, e.message),
            ClientError::Protocol(m) => write!(f, "engine protocol: {m}"),
        }
    }
}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// A connection bound to one host.
pub struct Client {
    stream: UnixStream,
    next_id: u64,
}

impl Client {
    /// Connect and bind the connection to `host`.
    pub fn connect(socket: &Path, host: &str) -> Result<Self, ClientError> {
        let mut c = Client {
            stream: UnixStream::connect(socket)?,
            next_id: 1,
        };
        c.call("hello", json!({"host": host}))?;
        Ok(c)
    }

    /// Send one request and wait for its answer.
    pub fn call(&mut self, op: &str, params: Value) -> Result<Value, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        let params = match params {
            Value::Object(m) => m,
            Value::Null => Map::new(),
            _ => return Err(ClientError::Protocol("params must be an object".into())),
        };
        write_message(
            &mut self.stream,
            &Request {
                id,
                op: op.into(),
                params,
            },
        )?;
        let body = read_message(&mut self.stream)?
            .ok_or_else(|| ClientError::Protocol("engine closed the connection".into()))?;
        let resp: Response =
            serde_json::from_slice(&body).map_err(|e| ClientError::Protocol(e.to_string()))?;
        if resp.id != id {
            return Err(ClientError::Protocol(format!(
                "answer {} for request {id}",
                resp.id
            )));
        }
        match (resp.ok, resp.result, resp.error) {
            (true, result, _) => Ok(result.unwrap_or(Value::Null)),
            (false, _, Some(e)) => Err(ClientError::Engine(e)),
            (false, _, None) => Err(ClientError::Protocol("error without a body".into())),
        }
    }

    pub fn section(&mut self, name: &str) -> Result<Value, ClientError> {
        self.call("section", json!({"name": name}))
    }

    pub fn list(&mut self, name: &str) -> Result<Value, ClientError> {
        self.call("list", json!({"name": name}))
    }

    pub fn reg_query_value(&mut self, key: &str, name: &str) -> Result<Value, ClientError> {
        self.call("reg.query_value", json!({"key": key, "name": name}))
    }

    pub fn reg_enum_subkeys(&mut self, key: &str) -> Result<Value, ClientError> {
        self.call("reg.enum_subkeys", json!({"key": key}))
    }

    /// RegSetValueEx. `value` is `{"type": ..., "data": ...}`.
    pub fn reg_set_value(
        &mut self,
        key: &str,
        name: &str,
        value: &Value,
    ) -> Result<Value, ClientError> {
        let mut params = json!({"key": key, "name": name});
        params["type"] = value["type"].clone();
        params["data"] = value["data"].clone();
        self.call("reg.set_value", params)
    }

    /// Add an event to a channel. Returns its record ID.
    pub fn evt_write(&mut self, channel: &str, event: &Value) -> Result<u64, ClientError> {
        let r = self.call("evt.write", json!({"channel": channel, "event": event}))?;
        r["record_id"]
            .as_u64()
            .ok_or_else(|| ClientError::Protocol("evt.write answered without a record_id".into()))
    }

    /// Events in `channel` after record `after` that match `query`, as XML.
    pub fn evt_query(
        &mut self,
        channel: &str,
        query: &str,
        after: u64,
        limit: u64,
    ) -> Result<Value, ClientError> {
        self.call(
            "evt.query",
            json!({"channel": channel, "query": query, "after": after, "limit": limit}),
        )
    }

    /// Journal entries after `since`. See `Runtime::changes`.
    /// Block until `channel` has a record after `after`, the logs are reset, or
    /// `timeout_ms` passes. Returns `{newest_record_id, reset, timed_out}`.
    pub fn evt_wait(
        &mut self,
        channel: &str,
        after: u64,
        timeout_ms: u64,
    ) -> Result<Value, ClientError> {
        self.call(
            "evt.wait",
            json!({"channel": channel, "after": after, "timeout_ms": timeout_ms}),
        )
    }

    pub fn changes(&mut self, since: u64) -> Result<Value, ClientError> {
        self.call("changes", json!({"since": since}))
    }
}
