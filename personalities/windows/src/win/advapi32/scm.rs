//! The Service Control Manager, queried: `OpenSCManagerW`,
//! `EnumServicesStatusExW`, `OpenServiceW`, `QueryServiceConfigW`,
//! `QueryServiceConfig2W`, `CloseServiceHandle`.
//!
//! Services come from the engine's `services` list (Kasim, 2026-11-14).
//! Following each function's Microsoft Learn page:
//!
//! | Field | Source |
//! | --- | --- |
//! | Type | `type`: own process 0x10, share process 0x20, kernel driver 0x1, file system driver 0x2 |
//! | State | `state`: running 4, stopped 1 |
//! | Start type | `start_mode`: boot 0, system 1, auto 2, manual 3, disabled 4 |
//! | Error control | `error_control`: ignore 0, normal 1, severe 2, critical 3 |
//! | Path, account, display name, description | `path`, `account`, `display_name`, `description` |
//! | PID of a running service | The process whose command line has `-s NAME`, else the only one whose command line is the service's path |
//!
//! A fact the profile lacks is a logged gap: type and error control 0,
//! description empty, PID 0. Accepted controls, exit codes, load order
//! groups, tags and dependencies are not modelled and report nothing.
//! Only the local SCM answers. Results that do not fit fail with
//! ERROR_MORE_DATA or ERROR_INSUFFICIENT_BUFFER and the size needed;
//! enumeration returns every match at once.

use serde_json::{Value, json};

use crate::gap::GapKind;
use crate::handles::Object;
use crate::runtime::with_current;
use crate::win::facts::{self, Caller};
use crate::win::kernel32::error::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, set_last_error,
};
use crate::win::text::wide;

const ERROR_MORE_DATA: u32 = 234;
const ERROR_INVALID_LEVEL: u32 = 124;
const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
const SERVICE_ACTIVE: u32 = 1;
const SERVICE_INACTIVE: u32 = 2;
const SERVICE_RUNNING: u32 = 4;
const SERVICE_STOPPED: u32 = 1;
const SC_ENUM_PROCESS_INFO: u32 = 0;
const SERVICE_CONFIG_DESCRIPTION: u32 = 1;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("OpenSCManagerW", OpenSCManagerW as *const () as u32),
        (
            "EnumServicesStatusExW",
            EnumServicesStatusExW as *const () as u32,
        ),
        ("OpenServiceW", OpenServiceW as *const () as u32),
        (
            "QueryServiceConfigW",
            QueryServiceConfigW as *const () as u32,
        ),
        (
            "QueryServiceConfig2W",
            QueryServiceConfig2W as *const () as u32,
        ),
        ("CloseServiceHandle", CloseServiceHandle as *const () as u32),
    ]
}

fn gap(what: &str) {
    with_current(|p| p.record_runtime_gap(GapKind::Feature, "advapi32.dll", what));
}

fn fail(code: u32) -> i32 {
    set_last_error(code);
    0
}

fn text(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn services(caller: Caller) -> Option<Vec<Value>> {
    match facts::call(caller, "list", json!({"name": "services"})) {
        Ok(Value::Array(items)) => Some(items),
        Ok(_) => Some(Vec::new()),
        Err(_) => None,
    }
}

fn service_type(s: &Value) -> u32 {
    match s.get("type").and_then(Value::as_str) {
        Some("own_process") => 0x10,
        Some("share_process") => 0x20,
        Some("kernel_driver") => 0x1,
        Some("file_system_driver") => 0x2,
        _ => {
            gap("service type is not in the host profile");
            0
        }
    }
}

fn running(s: &Value) -> bool {
    s.get("state").and_then(Value::as_str) == Some("running")
}

/// The PID of a running service, from the engine's process list.
fn pid_of(name: &str, path: &str, processes: &[Value]) -> u32 {
    let line = |p: &Value| text(p, "command_line");
    let pid = |p: &Value| p.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
    let split = processes.iter().find(|p| {
        let words: Vec<String> = line(p).split_whitespace().map(str::to_lowercase).collect();
        words
            .windows(2)
            .any(|w| w[0] == "-s" && w[1] == name.to_lowercase())
    });
    if let Some(p) = split {
        return pid(p);
    }
    let same: Vec<&Value> = processes
        .iter()
        .filter(|p| !path.is_empty() && line(p).eq_ignore_ascii_case(path))
        .collect();
    if let [only] = same[..] {
        return pid(only);
    }
    gap("the process of a running service is not in the process list");
    0
}

/// UTF-16 with a NUL, as bytes.
fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// A fixed record and its string fields: (offset of the pointer, bytes).
type Record = (Vec<u8>, Vec<(usize, Vec<u8>)>);

/// Lays out `count` fixed records of `size` bytes, then strings. Each
/// record is (fixed bytes, [(offset of a pointer field, string)]).
/// Returns the bytes, with pointers relative to `base`.
fn layout(records: &[Record], size: usize, base: u32) -> Vec<u8> {
    let mut out = vec![0u8; records.len() * size];
    for (i, (fixed, strings)) in records.iter().enumerate() {
        out[i * size..i * size + fixed.len()].copy_from_slice(fixed);
        for (field, bytes) in strings {
            let at = out.len() as u32;
            out.extend_from_slice(bytes);
            out[i * size + field..i * size + field + 4].copy_from_slice(&(base + at).to_le_bytes());
        }
    }
    out
}

/// Copies `bytes` into a caller buffer of `room` bytes, or reports the
/// size needed in `needed` and fails with `too_small`.
fn deliver(bytes: &[u8], out: *mut u8, room: u32, needed: *mut u32, too_small: u32) -> bool {
    if !needed.is_null() {
        // SAFETY: writable (the API's contract).
        unsafe {
            *needed = if (room as usize) < bytes.len() {
                bytes.len() as u32
            } else {
                0
            }
        };
    }
    if out.is_null() || (room as usize) < bytes.len() {
        set_last_error(too_small);
        return false;
    }
    // SAFETY: `room` writable bytes.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    true
}

#[allow(non_snake_case)]
extern "stdcall" fn OpenSCManagerW(
    machine: *const u16,
    _database: *const u16,
    _access: u32,
) -> u32 {
    // SAFETY: NULL or a NUL-terminated string (the API's contract).
    if let Some(m) = unsafe { wide(machine) }.filter(|m| !m.is_empty()) {
        gap(&format!("OpenSCManagerW on {m}"));
        set_last_error(ERROR_NOT_SUPPORTED);
        return 0;
    }
    with_current(|p| p.handles.insert(Object::ScManager))
}

fn is_manager(h: u32) -> bool {
    with_current(|p| matches!(p.handles.get(h), Some(Object::ScManager)))
}

/// `ENUM_SERVICE_STATUS_PROCESSW` records (44 bytes each) for the
/// services matching the type and state filters.
#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn EnumServicesStatusExW(
    manager: u32,
    level: u32,
    types: u32,
    states: u32,
    out: *mut u8,
    room: u32,
    needed: *mut u32,
    returned: *mut u32,
    resume: *mut u32,
    group: *const u16,
) -> i32 {
    const CALLER: Caller = ("advapi32.dll", "EnumServicesStatusExW");
    if !is_manager(manager) {
        return fail(ERROR_INVALID_HANDLE);
    }
    if level != SC_ENUM_PROCESS_INFO {
        gap(&format!("EnumServicesStatusExW level {level}"));
        return fail(ERROR_INVALID_LEVEL);
    }
    if !(1..=3).contains(&states) || needed.is_null() || returned.is_null() {
        return fail(ERROR_INVALID_PARAMETER);
    }
    // SAFETY: NULL or a NUL-terminated string (the API's contract).
    if unsafe { wide(group) }.is_some_and(|g| !g.is_empty()) {
        gap("EnumServicesStatusExW by load order group");
    }
    let (Some(list), Ok(procs)) = (
        services(CALLER),
        facts::call(CALLER, "proc.list", Value::Null),
    ) else {
        return fail(ERROR_NOT_SUPPORTED);
    };
    let procs = procs.as_array().cloned().unwrap_or_default();
    let records: Vec<_> = list
        .iter()
        .filter(|s| {
            let kind = service_type(s);
            let state_ok = if running(s) {
                states & SERVICE_ACTIVE != 0
            } else {
                states & SERVICE_INACTIVE != 0
            };
            (kind == 0 || kind & types != 0) && state_ok
        })
        .map(|s| {
            let name = text(s, "name");
            let mut fixed = vec![0u8; 44];
            fixed[8..12].copy_from_slice(&service_type(s).to_le_bytes());
            let (state, pid) = if running(s) {
                (SERVICE_RUNNING, pid_of(&name, &text(s, "path"), &procs))
            } else {
                (SERVICE_STOPPED, 0)
            };
            fixed[12..16].copy_from_slice(&state.to_le_bytes());
            fixed[36..40].copy_from_slice(&pid.to_le_bytes());
            let display = text(s, "display_name");
            (fixed, vec![(0, utf16(&name)), (4, utf16(&display))])
        })
        .collect();
    let bytes = layout(&records, 44, out as u32);
    // SAFETY: writable (checked above); resume is NULL or writable.
    unsafe {
        *returned = 0;
        if let Some(r) = resume.as_mut() {
            *r = 0;
        }
    }
    if !deliver(&bytes, out, room, needed, ERROR_MORE_DATA) {
        return 0;
    }
    // SAFETY: as above.
    unsafe { *returned = records.len() as u32 };
    1
}

#[allow(non_snake_case)]
extern "stdcall" fn OpenServiceW(manager: u32, name: *const u16, _access: u32) -> u32 {
    const CALLER: Caller = ("advapi32.dll", "OpenServiceW");
    if !is_manager(manager) {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    // SAFETY: a NUL-terminated string (the API's contract).
    let Some(name) = (unsafe { wide(name) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let found = services(CALLER)
        .unwrap_or_default()
        .into_iter()
        .find(|s| text(s, "name").eq_ignore_ascii_case(&name));
    match found {
        Some(s) => with_current(|p| p.handles.insert(Object::Service(text(&s, "name")))),
        None => {
            set_last_error(ERROR_SERVICE_DOES_NOT_EXIST);
            0
        }
    }
}

/// The engine's record of the service a handle names.
fn service_of(caller: Caller, h: u32) -> Option<Value> {
    let name = with_current(|p| match p.handles.get(h) {
        Some(Object::Service(n)) => Some(n.clone()),
        _ => None,
    })?;
    services(caller)?
        .into_iter()
        .find(|s| text(s, "name").eq_ignore_ascii_case(&name))
}

/// `QUERY_SERVICE_CONFIGW` (36 bytes, then strings).
#[allow(non_snake_case)]
extern "stdcall" fn QueryServiceConfigW(
    service: u32,
    out: *mut u8,
    room: u32,
    needed: *mut u32,
) -> i32 {
    const CALLER: Caller = ("advapi32.dll", "QueryServiceConfigW");
    let Some(s) = service_of(CALLER, service) else {
        return fail(ERROR_INVALID_HANDLE);
    };
    let start = match s.get("start_mode").and_then(Value::as_str) {
        Some("boot") => 0,
        Some("system") => 1,
        Some("auto") => 2,
        Some("manual") => 3,
        Some("disabled") => 4,
        _ => {
            gap("service start mode is not in the host profile");
            0
        }
    };
    let error_control = match s.get("error_control").and_then(Value::as_str) {
        Some("ignore") => 0,
        Some("normal") => 1,
        Some("severe") => 2,
        Some("critical") => 3,
        _ => {
            gap("service error control is not in the host profile");
            0
        }
    };
    let mut fixed = vec![0u8; 36];
    fixed[0..4].copy_from_slice(&service_type(&s).to_le_bytes());
    fixed[4..8].copy_from_slice(&(start as u32).to_le_bytes());
    fixed[8..12].copy_from_slice(&(error_control as u32).to_le_bytes());
    let strings = vec![
        (12, utf16(&text(&s, "path"))),
        (16, utf16("")),
        // An empty list of dependencies ends with two NULs.
        (24, vec![0, 0, 0, 0]),
        (28, utf16(&text(&s, "account"))),
        (32, utf16(&text(&s, "display_name"))),
    ];
    let bytes = layout(&[(fixed, strings)], 36, out as u32);
    i32::from(deliver(
        &bytes,
        out,
        room,
        needed,
        ERROR_INSUFFICIENT_BUFFER,
    ))
}

/// Level 1, `SERVICE_DESCRIPTIONW`, only.
#[allow(non_snake_case)]
extern "stdcall" fn QueryServiceConfig2W(
    service: u32,
    level: u32,
    out: *mut u8,
    room: u32,
    needed: *mut u32,
) -> i32 {
    const CALLER: Caller = ("advapi32.dll", "QueryServiceConfig2W");
    let Some(s) = service_of(CALLER, service) else {
        return fail(ERROR_INVALID_HANDLE);
    };
    if level != SERVICE_CONFIG_DESCRIPTION {
        gap(&format!("QueryServiceConfig2W level {level}"));
        return fail(ERROR_INVALID_LEVEL);
    }
    if s.get("description").is_none() {
        gap("service description is not in the host profile");
    }
    let bytes = layout(
        &[(vec![0u8; 4], vec![(0, utf16(&text(&s, "description")))])],
        4,
        out as u32,
    );
    i32::from(deliver(
        &bytes,
        out,
        room,
        needed,
        ERROR_INSUFFICIENT_BUFFER,
    ))
}

#[allow(non_snake_case)]
extern "stdcall" fn CloseServiceHandle(h: u32) -> i32 {
    let closed = with_current(|p| match p.handles.get(h) {
        Some(Object::ScManager | Object::Service(_)) => p.handles.remove(h).is_some(),
        _ => false,
    });
    if closed {
        1
    } else {
        fail(ERROR_INVALID_HANDLE)
    }
}

#[cfg(test)]
mod tests;
