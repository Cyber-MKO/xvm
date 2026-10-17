//! An in-process host-state engine for tests: serves one host built from
//! compiled base and host JSON on a socket in the temporary folder.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use xvm_engine::server::Server;
use xvm_engine::store::{Base, Host, Store};

/// Start serving and return the socket path and the host's name.
pub fn serve(base: Value, host: Value) -> (PathBuf, String) {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let base = Arc::new(Base::from_value(base).expect("base image"));
    let host = Arc::new(Host::from_value(host, base.clone()).expect("host profile"));
    let name = host.name.clone();
    let mut store = Store::default();
    store.bases.insert(base.name.clone(), base);
    store.hosts.insert(host.name.clone(), host);
    let gaps: Box<dyn std::io::Write + Send> = Box::new(std::io::sink());
    let server = Arc::new(Server::new(Arc::new(store), Arc::new(Mutex::new(gaps))));
    let socket = std::env::temp_dir().join(format!(
        "xvm-test-engine-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_file(&socket);
    let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
    std::thread::spawn(move || server.run(listener));
    (socket, name)
}
