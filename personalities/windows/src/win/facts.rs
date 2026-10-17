//! Host facts from the host-state engine (CLAUDE.md rule 5).
//!
//! The runner connects each process to the engine for one host
//! (`xvm-windows-run --engine SOCKET --host NAME`). Emulated functions
//! read facts through these helpers, outside the process lock. Without a
//! connection, or when the engine fails, the call is a logged gap and the
//! caller fails the way the function fails for a missing value.

use serde_json::Value;
use xvm_engine::protocol::code;

use crate::gap::GapKind;
use crate::runtime::with_current;
use xvm_engine::client::{Client, ClientError};

/// The function asking, for gap records: (DLL, function).
pub(crate) type Caller = (&'static str, &'static str);

fn gap(caller: Caller, what: String) {
    let symbol = format!("{}: {what}", caller.1);
    with_current(|p| p.record_runtime_gap(GapKind::Feature, caller.0, &symbol));
}

fn ask<T>(
    caller: Caller,
    what: &str,
    f: impl FnOnce(&mut Client) -> Result<T, ClientError>,
) -> Result<T, ClientError> {
    let Some(engine) = with_current(|p| p.engine.clone()) else {
        gap(caller, format!("{what} needs the host-state engine"));
        return Err(ClientError::Protocol("no engine connection".into()));
    };
    let mut client = engine.lock().unwrap();
    f(&mut client)
}

/// A profile section, such as `os_info`. None (logged) if the engine has
/// none or cannot answer.
pub(crate) fn section(caller: Caller, name: &str) -> Option<Value> {
    match ask(caller, &format!("section {name}"), |c| c.section(name)) {
        Ok(Value::Null) => {
            gap(caller, format!("the host has no {name} section"));
            None
        }
        Ok(v) => Some(v),
        Err(ClientError::Protocol(m)) if m == "no engine connection" => None,
        Err(e) => {
            gap(caller, format!("section {name}: {e}"));
            None
        }
    }
}

/// A registry value as `{name, type, data}`. Ok(None) if the key or value
/// does not exist; Err (logged) if the engine cannot answer.
pub(crate) fn reg_value(caller: Caller, key: &str, name: &str) -> Result<Option<Value>, ()> {
    match ask(caller, &format!("registry {key}"), |c| {
        c.reg_query_value(key, name)
    }) {
        Ok(v) => Ok(Some(v)),
        Err(ClientError::Engine(e)) if e.code == code::NOT_FOUND => Ok(None),
        Err(ClientError::Protocol(m)) if m == "no engine connection" => Err(()),
        Err(e) => {
            gap(caller, format!("registry {key}\\{name}: {e}"));
            Err(())
        }
    }
}

/// Why an engine call gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The engine says the thing does not exist.
    NotFound,
    /// No engine, or it could not answer: already logged as a gap.
    Unavailable,
}

/// Any engine operation, for callers that need more than sections and
/// registry values.
pub(crate) fn call(caller: Caller, op: &str, params: Value) -> Result<Value, Failure> {
    match ask(caller, op, |c| c.call(op, params)) {
        Ok(v) => Ok(v),
        Err(ClientError::Engine(e)) if e.code == code::NOT_FOUND => Err(Failure::NotFound),
        Err(ClientError::Protocol(m)) if m == "no engine connection" => Err(Failure::Unavailable),
        Err(e) => {
            gap(caller, format!("{op}: {e}"));
            Err(Failure::Unavailable)
        }
    }
}

/// Whether the host runs 64-bit Windows (`os_info.architecture`).
pub(crate) fn is_64bit(caller: Caller) -> Option<bool> {
    let os_info = section(caller, "os_info")?;
    let arch = os_info.get("architecture")?.as_str()?.to_ascii_lowercase();
    Some(matches!(arch.as_str(), "x86_64" | "amd64" | "arm64"))
}

/// An engine serving one host built from `base` and `host` (compiled
/// JSON), connected for that host.
#[cfg(test)]
pub(crate) fn test_engine(base: Value, host: Value) -> std::sync::Arc<std::sync::Mutex<Client>> {
    let (socket, name) = crate::testing::serve(base, host);
    std::sync::Arc::new(std::sync::Mutex::new(
        Client::connect(&socket, &name).unwrap(),
    ))
}
