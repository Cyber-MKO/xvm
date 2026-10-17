//! Tool Help process snapshots: `CreateToolhelp32Snapshot`,
//! `Process32First`, `Process32Next`.
//!
//! A snapshot holds the engine's process list (`proc.list`) as it was
//! when it was taken. Following the functions' pages on Microsoft Learn,
//! `PROCESSENTRY32` (ANSI, 296 bytes) gets:
//!
//! | Field | Value |
//! | --- | --- |
//! | `th32ProcessID`, `th32ParentProcessID` | `pid`, `ppid` |
//! | `szExeFile` | `image`, in the profile's ANSI code page |
//! | `cntUsage`, `th32DefaultHeapID`, `th32ModuleID`, `dwFlags` | 0, as documented: no longer used |
//! | `cntThreads`, `pcPriClassBase` | Not in the process list: 0, a logged gap |
//!
//! Only `TH32CS_SNAPPROCESS` is implemented. Other snapshot kinds (heaps,
//! modules, threads) are logged gaps.

use std::sync::Arc;

use serde_json::Value;

use super::error::set_last_error;
use crate::codepage;
use crate::gap::GapKind;
use crate::handles::{Object, ProcessSnapshot, SnapshotEntry};
use crate::runtime::with_current;
use crate::win::facts::{self, Caller};

const TH32CS_SNAPPROCESS: u32 = 0x2;
const TH32CS_INHERIT: u32 = 0x8000_0000;
const INVALID_HANDLE_VALUE: u32 = u32::MAX;
const ENTRY_SIZE: usize = 296;
const MAX_PATH: usize = 260;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_NO_MORE_FILES: u32 = 18;
const ERROR_BAD_LENGTH: u32 = 24;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NOT_SUPPORTED: u32 = 50;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        (
            "CreateToolhelp32Snapshot",
            CreateToolhelp32Snapshot as *const () as u32,
        ),
        ("Process32First", Process32First as *const () as u32),
        ("Process32Next", Process32Next as *const () as u32),
    ]
}

fn gap(function: &str, what: &str) {
    with_current(|p| {
        p.record_runtime_gap(
            GapKind::Feature,
            "kernel32.dll",
            &format!("{function}: {what}"),
        )
    });
}

/// A snapshot of the processes. Other kinds are a logged gap.
#[allow(non_snake_case)]
extern "stdcall" fn CreateToolhelp32Snapshot(flags: u32, _pid: u32) -> u32 {
    const CALLER: Caller = ("kernel32.dll", "CreateToolhelp32Snapshot");
    if flags & !(TH32CS_SNAPPROCESS | TH32CS_INHERIT) != 0 || flags & TH32CS_SNAPPROCESS == 0 {
        gap(CALLER.1, &format!("snapshot kinds 0x{flags:x}"));
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    let Ok(list) = facts::call(CALLER, "proc.list", Value::Null) else {
        set_last_error(ERROR_NOT_SUPPORTED);
        return INVALID_HANDLE_VALUE;
    };
    let number = |p: &Value, k: &str| {
        p.get(k)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
    };
    let processes = list
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| {
            Some(SnapshotEntry {
                pid: number(p, "pid")?,
                ppid: number(p, "ppid").unwrap_or(0),
                image: p.get("image")?.as_str()?.to_string(),
            })
        })
        .collect();
    let snapshot = ProcessSnapshot {
        processes,
        next: Default::default(),
    };
    with_current(|p| p.handles.insert(Object::Snapshot(Arc::new(snapshot))))
}

/// Fills `entry` with the process after the snapshot's position.
fn fill(handle: u32, entry: *mut u8, first: bool) -> i32 {
    let snapshot = with_current(|p| match p.handles.get(handle) {
        Some(Object::Snapshot(s)) => Some(s.clone()),
        _ => None,
    });
    let Some(snapshot) = snapshot else {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };
    // SAFETY: entry starts with dwSize (the API's contract).
    if entry.is_null() || (unsafe { entry.cast::<u32>().read_unaligned() } as usize) < ENTRY_SIZE {
        set_last_error(ERROR_BAD_LENGTH);
        return 0;
    }
    let process = {
        let mut next = snapshot.next.lock().unwrap();
        if first {
            *next = 0;
        }
        let process = snapshot.processes.get(*next).cloned();
        if process.is_some() {
            *next += 1;
        }
        process
    };
    let Some(process) = process else {
        set_last_error(ERROR_NO_MORE_FILES);
        return 0;
    };
    gap(
        "PROCESSENTRY32",
        "thread counts and base priorities are not in the process list",
    );
    let pages = with_current(|p| p.params.code_pages);
    let units: Vec<u16> = process.image.encode_utf16().collect();
    let mut name = match codepage::single_byte(pages.ansi) {
        Some(table) => table.encode(&units, true, table.default_byte).0,
        None => process.image.bytes().collect(),
    };
    name.truncate(MAX_PATH - 1);
    let mut buf = [0u8; ENTRY_SIZE];
    buf[0..4].copy_from_slice(&(ENTRY_SIZE as u32).to_le_bytes());
    buf[8..12].copy_from_slice(&process.pid.to_le_bytes());
    buf[24..28].copy_from_slice(&process.ppid.to_le_bytes());
    buf[36..36 + name.len()].copy_from_slice(&name);
    // SAFETY: entry holds a PROCESSENTRY32 (checked above).
    unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), entry, ENTRY_SIZE) };
    1
}

#[allow(non_snake_case)]
extern "stdcall" fn Process32First(snapshot: u32, entry: *mut u8) -> i32 {
    fill(snapshot, entry, true)
}

#[allow(non_snake_case)]
extern "stdcall" fn Process32Next(snapshot: u32, entry: *mut u8) -> i32 {
    fill(snapshot, entry, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use crate::win::kernel32::error::GetLastError;
    use serde_json::json;

    #[test]
    fn processes_from_the_engine() {
        let base = json!({
            "schema": 1, "kind": "base-image", "name": "b", "os": "windows",
            "source": {"golden_capture": "synthetic"},
            "processes": [
                {"id": "system", "image": "System", "pid": 4, "user": "NT AUTHORITY\\SYSTEM"},
                {"id": "smss", "image": "smss.exe", "parent": "system",
                 "path": "C:\\Windows\\System32\\smss.exe", "user": "NT AUTHORITY\\SYSTEM",
                 "session": 0, "start_offset_s": 1},
            ],
        });
        let host = json!({"schema": 1, "kind": "host-profile", "name": "h", "base": "b",
                          "os": "windows", "identity": {"hostname": "H"}});
        let mut process = Process::new(Vec::new());
        process.engine = Some(facts::test_engine(base, host));
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        assert_ne!(snapshot, INVALID_HANDLE_VALUE);
        let mut entry = [0u8; ENTRY_SIZE];
        assert_eq!(Process32First(snapshot, entry.as_mut_ptr()), 0, "no dwSize");
        assert_eq!(GetLastError(), ERROR_BAD_LENGTH);
        entry[0..4].copy_from_slice(&(ENTRY_SIZE as u32).to_le_bytes());
        let mut seen = Vec::new();
        let mut ok = Process32First(snapshot, entry.as_mut_ptr());
        while ok == 1 {
            let field = |o: usize| u32::from_le_bytes(entry[o..o + 4].try_into().unwrap());
            let end = entry[36..].iter().position(|&b| b == 0).unwrap();
            let name = String::from_utf8(entry[36..36 + end].to_vec()).unwrap();
            seen.push((field(8), field(24), name));
            ok = Process32Next(snapshot, entry.as_mut_ptr());
        }
        assert_eq!(GetLastError(), ERROR_NO_MORE_FILES);
        let smss = seen.iter().find(|p| p.2 == "smss.exe").unwrap();
        assert_eq!(smss.1, 4, "parent System");
        assert!(seen.contains(&(4, 0, "System".to_string())), "{seen:?}");
        // First starts over.
        assert_eq!(Process32First(snapshot, entry.as_mut_ptr()), 1);
        assert_eq!(super::super::file::CloseHandle(snapshot), 1);
        assert_eq!(Process32Next(snapshot, entry.as_mut_ptr()), 0);
        assert_eq!(CreateToolhelp32Snapshot(0x8, 0), INVALID_HANDLE_VALUE);
        let gaps = runtime.lock().gaps().len();
        assert_eq!(gaps, 2, "threads and priorities; module snapshots");
    }
}
