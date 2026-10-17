//! The agent process in the engine's process list (decision: the loader
//! asks the engine for the profile's PID).
//!
//! `start` registers the process with `proc.start`, giving the profile's
//! PID and the real process ID; a service's parent is the host's
//! `services.exe`. `exit` ends it with `proc.exit`, once, from whichever
//! exit path comes first.

use serde_json::{Value, json};

use crate::process::Process;

/// Register the process. Does nothing without an engine connection.
pub fn start(p: &mut Process) -> Result<(), String> {
    let Some(engine) = p.engine.clone() else {
        return Ok(());
    };
    // The program the command line names, as the runner loads it.
    let program = crate::cmdline::split(&p.params.command_line)
        .into_iter()
        .next()
        .ok_or("empty command line")?;
    let path = crate::paths::DriveMap::full_path(&program, &p.params.current_directory)
        .map_err(|e| format!("{program}: {e}"))?;
    let image = path.rsplit('\\').next().unwrap_or(&path).to_string();
    let mut request = json!({
        "image": image,
        "path": path,
        "command_line": p.params.command_line,
        "pid": p.params.pid,
        "native_pid": std::process::id(),
    });
    let mut client = engine.lock().unwrap();
    if p.params.service.is_some() {
        let list = client
            .call("proc.list", Value::Null)
            .map_err(|e| e.to_string())?;
        let parent = list.as_array().into_iter().flatten().find(|proc| {
            proc.get("image")
                .and_then(Value::as_str)
                .is_some_and(|i| i.eq_ignore_ascii_case("services.exe"))
        });
        if let Some(pid) = parent.and_then(|proc| proc.get("pid")) {
            request["parent_pid"] = pid.clone();
        }
    }
    client
        .call("proc.start", request)
        .map_err(|e| format!("registering the process: {e}"))?;
    drop(client);
    p.registered = true;
    Ok(())
}

/// End the registered process with `exit_code`. Later calls do nothing.
pub fn exit(p: &mut Process, exit_code: u32) {
    if !std::mem::take(&mut p.registered) {
        return;
    }
    if let Some(engine) = &p.engine {
        let request = json!({"pid": p.params.pid, "exit_code": exit_code});
        if let Err(e) = engine.lock().unwrap().call("proc.exit", request) {
            eprintln!("engine: ending process {}: {e}", p.params.pid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn registers_the_profile_pid_once() {
        let base = json!({
            "schema": 1, "kind": "base-image", "name": "b", "os": "windows",
            "source": {"golden_capture": "synthetic"},
            "processes": [{"id": "services", "image": "services.exe",
                           "path": "C:\\Windows\\System32\\services.exe", "start_offset_s": 1}],
        });
        let host = json!({"schema": 1, "kind": "host-profile", "name": "h", "base": "b",
                          "os": "windows", "identity": {"hostname": "H"}});
        let engine = crate::win::facts::test_engine(base, host);
        let mut p = Process::new(Vec::new());
        p.engine = Some(engine.clone());
        p.params.command_line = r#""C:\Program Files\agent.exe" -f"#.into();
        p.params.current_directory = r"C:\".into();
        p.params.pid = 1200;
        p.params.service = Some("Svc".into());
        start(&mut p).unwrap();
        let get = |e: &Arc<Mutex<xvm_engine::client::Client>>| {
            e.lock().unwrap().call("proc.get", json!({"pid": 1200}))
        };
        let proc = get(&engine).unwrap();
        assert_eq!(proc["image"], "agent.exe");
        assert_eq!(proc["path"], r"C:\Program Files\agent.exe");
        assert_eq!(proc["native_pid"], std::process::id());
        let services = engine
            .lock()
            .unwrap()
            .call("proc.list", Value::Null)
            .unwrap();
        let services_pid = services
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["image"] == "services.exe")
            .unwrap()["pid"]
            .clone();
        assert_eq!(proc["ppid"], services_pid);
        assert!(start(&mut p).is_err(), "the PID is taken");
        exit(&mut p, 0);
        assert!(get(&engine).is_err(), "ended");
        exit(&mut p, 0);
    }
}
