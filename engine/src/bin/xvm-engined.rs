//! xvm-engined --compiled DIR --socket PATH [--gap-log FILE] [--state DIR] [--flush-ms N] [--snapshot-every N]

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use std::time::Duration;

use xvm_engine::persist::{self, Persist};
use xvm_engine::server::{GapLog, Server};
use xvm_engine::store::Store;

const USAGE: &str = "usage: xvm-engined --compiled DIR --socket PATH [--gap-log FILE] [--state DIR] [--flush-ms N] [--snapshot-every N]";

fn main() -> ExitCode {
    let mut compiled = None;
    let mut socket = None;
    let mut gap_log = None;
    let mut state = None;
    let mut flush = persist::DEFAULT_FLUSH;
    let mut snapshot_every = persist::DEFAULT_SNAPSHOT_EVERY;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--compiled" => compiled = args.next().map(PathBuf::from),
            "--socket" => socket = args.next().map(PathBuf::from),
            "--gap-log" => gap_log = args.next().map(PathBuf::from),
            "--state" => state = args.next().map(PathBuf::from),
            "--flush-ms" => match args.next().and_then(|n| n.parse::<u64>().ok()) {
                Some(ms) if ms > 0 => flush = Duration::from_millis(ms),
                _ => {
                    eprintln!("{USAGE}");
                    return ExitCode::from(2);
                }
            },
            "--snapshot-every" => match args.next().and_then(|n| n.parse::<usize>().ok()) {
                Some(n) if n > 0 => snapshot_every = n,
                _ => {
                    eprintln!("{USAGE}");
                    return ExitCode::from(2);
                }
            },
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
    let store = Arc::new(store);
    let gaps: GapLog = Arc::new(Mutex::new(gaps));
    let mut server = Server::new(store.clone(), gaps);
    if let Some(dir) = state {
        let (p, report) = match Persist::open(&dir, &store, snapshot_every) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("xvm-engined: {e}");
                return ExitCode::from(1);
            }
        };
        for w in &report.warnings {
            eprintln!("xvm-engined: warning: {w}");
        }
        eprintln!(
            "xvm-engined: state {}: {} hosts restored ({} changes replayed), {} fresh",
            dir.display(),
            report.restored.len(),
            report.replayed,
            report.fresh.len()
        );
        let p = Arc::new(p);
        p.spawn_flusher(flush);
        server = server.with_persistence(p);
    }
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
    let server = Arc::new(server);
    match server.run(listener) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xvm-engined: {e}");
            ExitCode::from(1)
        }
    }
}
