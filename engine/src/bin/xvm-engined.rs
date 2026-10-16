//! xvm-engined --compiled DIR --socket PATH [--gap-log FILE]

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use xvm_engine::server::{GapLog, Server};
use xvm_engine::store::Store;

const USAGE: &str = "usage: xvm-engined --compiled DIR --socket PATH [--gap-log FILE]";

fn main() -> ExitCode {
    let mut compiled = None;
    let mut socket = None;
    let mut gap_log = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--compiled" => compiled = args.next().map(PathBuf::from),
            "--socket" => socket = args.next().map(PathBuf::from),
            "--gap-log" => gap_log = args.next().map(PathBuf::from),
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(compiled), Some(socket)) = (compiled, socket) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let store = match Store::load(&compiled) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("xvm-engined: {e}");
            return ExitCode::from(1);
        }
    };
    let gaps: Box<dyn Write + Send> = match gap_log {
        Some(path) => match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("xvm-engined: {}: {e}", path.display());
                return ExitCode::from(1);
            }
        },
        None => Box::new(io::stderr()),
    };
    // A socket file left by an earlier run would make bind fail.
    if socket.exists() {
        let _ = fs::remove_file(&socket);
    }
    let listener = match UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("xvm-engined: {}: {e}", socket.display());
            return ExitCode::from(1);
        }
    };
    eprintln!(
        "xvm-engined: {} base images, {} hosts, listening on {}",
        store.bases.len(),
        store.hosts.len(),
        socket.display()
    );
    let gaps: GapLog = Arc::new(Mutex::new(gaps));
    let server = Arc::new(Server::new(Arc::new(store), gaps));
    match server.run(listener) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xvm-engined: {e}");
            ExitCode::from(1)
        }
    }
}
