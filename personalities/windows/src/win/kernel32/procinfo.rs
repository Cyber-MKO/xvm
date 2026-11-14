//! Other processes: `OpenProcess`, `GetProcessTimes`,
//! `ProcessIdToSessionId`.
//!
//! Processes are the engine's process list (`proc.get`). A process handle
//! names a PID; the current-process pseudo-handle names ours. Following
//! the OpenProcess page on Microsoft Learn: PID 0, the System Idle
//! Process, fails with ERROR_INVALID_PARAMETER; the System process and
//! CSRSS processes fail with ERROR_ACCESS_DENIED; a PID the host does not
//! run fails with ERROR_INVALID_PARAMETER.
//!
//! `GetProcessTimes` gives the creation time from the engine's
//! `start_time` and no exit time (the process runs). Kernel and user CPU
//! time are not modelled: 0, a logged gap.

use serde_json::{Value, json};

use super::error::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, set_last_error};
use super::process::CURRENT_PROCESS;
use crate::gap::GapKind;
use crate::handles::Object;
use crate::runtime::with_current;
use crate::win::facts::{self, Caller};

const ERROR_ACCESS_DENIED: u32 = 5;
/// Milliseconds from 1601-01-01, where FILETIMEs start, to 1970-01-01.
const EPOCH_DIFFERENCE_MS: i64 = 11_644_473_600_000;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("OpenProcess", OpenProcess as *const () as u32),
        ("GetProcessTimes", GetProcessTimes as *const () as u32),
        (
            "ProcessIdToSessionId",
            ProcessIdToSessionId as *const () as u32,
        ),
    ]
}

/// The engine's record of `pid`, or None.
pub(crate) fn record(caller: Caller, pid: u32) -> Option<Value> {
    facts::call(caller, "proc.get", json!({ "pid": pid })).ok()
}

/// The PID a process handle names: the pseudo-handle is ours.
pub(crate) fn pid_of(handle: u32) -> Option<u32> {
    with_current(|p| {
        if handle == CURRENT_PROCESS {
            return Some(p.params.pid);
        }
        match p.handles.get(handle) {
            Some(Object::Process(pid)) => Some(*pid),
            _ => None,
        }
    })
}

#[allow(non_snake_case)]
extern "stdcall" fn OpenProcess(_access: u32, _inherit: i32, pid: u32) -> u32 {
    const CALLER: Caller = ("kernel32.dll", "OpenProcess");
    if pid == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let Some(found) = record(CALLER, pid) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let image = found
        .get("image")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if image.eq_ignore_ascii_case("System") || image.eq_ignore_ascii_case("csrss.exe") {
        set_last_error(ERROR_ACCESS_DENIED);
        return 0;
    }
    with_current(|p| p.handles.insert(Object::Process(pid)))
}

#[allow(non_snake_case)]
extern "stdcall" fn GetProcessTimes(
    handle: u32,
    creation: *mut u64,
    exit: *mut u64,
    kernel: *mut u64,
    user: *mut u64,
) -> i32 {
    const CALLER: Caller = ("kernel32.dll", "GetProcessTimes");
    let Some(pid) = pid_of(handle) else {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };
    let start = record(CALLER, pid)
        .and_then(|r| {
            r.get("start_time")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .and_then(|t| super::time::parse_utc(&t));
    let Some(start) = start else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    with_current(|p| {
        p.record_runtime_gap(
            GapKind::Feature,
            CALLER.0,
            "GetProcessTimes: CPU times are not modelled",
        )
    });
    if creation.is_null() || exit.is_null() || kernel.is_null() || user.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: four writable FILETIMEs (the API's contract).
    unsafe {
        creation.write_unaligned(((start + EPOCH_DIFFERENCE_MS) * 10_000) as u64);
        exit.write_unaligned(0);
        kernel.write_unaligned(0);
        user.write_unaligned(0);
    }
    1
}

/// The Remote Desktop session `pid` runs in, from the engine.
#[allow(non_snake_case)]
extern "stdcall" fn ProcessIdToSessionId(pid: u32, session: *mut u32) -> i32 {
    const CALLER: Caller = ("kernel32.dll", "ProcessIdToSessionId");
    let found = record(CALLER, pid).and_then(|r| r.get("session").and_then(Value::as_u64));
    match (found, session.is_null()) {
        (Some(s), false) => {
            // SAFETY: writable (the API's contract).
            unsafe { *session = s as u32 };
            1
        }
        _ => {
            set_last_error(ERROR_INVALID_PARAMETER);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use crate::win::kernel32::error::GetLastError;

    #[test]
    fn processes_from_the_engine() {
        let base = json!({
            "schema": 1, "kind": "base-image", "name": "b", "os": "windows",
            "source": {"golden_capture": "synthetic"},
            "os_info": {"last_boot": "2026-11-01T08:00:00Z"},
            "processes": [
                {"id": "system", "image": "System", "pid": 4, "user": "NT AUTHORITY\\SYSTEM"},
                {"id": "smss", "image": "smss.exe", "parent": "system", "pid": 400,
                 "path": "C:\\Windows\\System32\\smss.exe", "user": "NT AUTHORITY\\SYSTEM",
                 "session": 0, "start_offset_s": 2},
                {"id": "csrss", "image": "csrss.exe", "parent": "smss", "pid": 500,
                 "path": "C:\\Windows\\System32\\csrss.exe", "user": "NT AUTHORITY\\SYSTEM",
                 "session": 1, "start_offset_s": 3},
            ],
        });
        let host = json!({"schema": 1, "kind": "host-profile", "name": "h", "base": "b",
                          "os": "windows", "identity": {"hostname": "H"}});
        let mut process = Process::new(Vec::new());
        process.engine = Some(facts::test_engine(base, host));
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();

        assert_eq!(OpenProcess(0x400, 0, 0), 0);
        assert_eq!(GetLastError(), ERROR_INVALID_PARAMETER);
        assert_eq!(OpenProcess(0x400, 0, 4), 0);
        assert_eq!(GetLastError(), ERROR_ACCESS_DENIED);
        assert_eq!(OpenProcess(0x400, 0, 500), 0, "CSRSS");
        assert_eq!(OpenProcess(0x400, 0, 9999), 0);
        assert_eq!(GetLastError(), ERROR_INVALID_PARAMETER);

        let smss = OpenProcess(0x400, 0, 400);
        assert_ne!(smss, 0);
        let (mut c, mut e, mut k, mut u) = (0u64, 1u64, 1u64, 1u64);
        assert_eq!(GetProcessTimes(smss, &mut c, &mut e, &mut k, &mut u), 1);
        let boot = facts::call(("t", "t"), "proc.get", json!({"pid": 4})).unwrap();
        let boot = super::super::time::parse_utc(boot["start_time"].as_str().unwrap()).unwrap();
        assert_eq!(
            c,
            ((boot + 2000 + EPOCH_DIFFERENCE_MS) * 10_000) as u64,
            "boot plus 2 s"
        );
        assert_eq!((e, k, u), (0, 0, 0));
        assert_eq!(GetProcessTimes(0x1234, &mut c, &mut e, &mut k, &mut u), 0);

        let mut session = 9;
        assert_eq!(ProcessIdToSessionId(500, &mut session), 1);
        assert_eq!(session, 1);
        assert_eq!(ProcessIdToSessionId(9999, &mut session), 0);
        assert_eq!(super::super::file::CloseHandle(smss), 1);
        assert_eq!(runtime.lock().gaps().len(), 1, "CPU times");
    }
}
