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

/// An engine serving one host built from `base` and `host` (compiled
/// JSON), on a socket in the temporary folder.
#[cfg(test)]
pub(crate) fn test_engine(base: Value, host: Value) -> std::sync::Arc<std::sync::Mutex<Client>> {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use xvm_engine::server::Server;
    use xvm_engine::store::{Base, Host, Store};

    static NEXT: AtomicU32 = AtomicU32::new(0);
    let base = Arc::new(Base::from_value(base).unwrap());
    let host = Arc::new(Host::from_value(host, base.clone()).unwrap());
    let name = host.name.clone();
    let mut store = Store::default();
    store.bases.insert(base.name.clone(), base);
    store.hosts.insert(host.name.clone(), host);
    let gaps: Box<dyn std::io::Write + Send> = Box::new(std::io::sink());
    let server = Arc::new(Server::new(Arc::new(store), Arc::new(Mutex::new(gaps))));
    let socket = std::env::temp_dir().join(format!(
        "xvm-facts-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_file(&socket);
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::thread::spawn(move || server.run(listener));
    Arc::new(Mutex::new(Client::connect(&socket, &name).unwrap()))
}
