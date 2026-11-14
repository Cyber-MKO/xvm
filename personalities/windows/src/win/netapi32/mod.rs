//! `netapi32.dll`: local users and groups. `NetLocalGroupEnum`,
//! `NetUserEnum`, `NetUserGetInfo`, `NetUserGetLocalGroups`,
//! `NetApiBufferFree`.
//!
//! Users and groups come from the engine's `users` and `groups` lists.
//! Following each function's Microsoft Learn page, results go in one
//! block that `NetApiBufferFree` releases, strings inside it. Every entry
//! comes back at once with NERR_Success; the preferred length is advisory.
//!
//! | Function | Levels |
//! | --- | --- |
//! | `NetLocalGroupEnum` | 0 (name), 1 (name, comment: not in the profile, empty and a logged gap) |
//! | `NetUserEnum` | 0 (name) |
//! | `NetUserGetLocalGroups` | 0 (group names, from the user's `groups`) |
//! | `NetUserGetInfo` | None yet |
//!
//! Other levels, and remote servers, are logged gaps: ERROR_INVALID_LEVEL
//! or ERROR_NOT_SUPPORTED.

use serde_json::{Value, json};

use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::win::facts::{self, Caller};
use crate::win::text::wide;

const NERR_SUCCESS: u32 = 0;
const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_LEVEL: u32 = 124;
const NERR_USER_NOT_FOUND: u32 = 2221;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("NetLocalGroupEnum", NetLocalGroupEnum as *const () as u32),
        ("NetUserEnum", NetUserEnum as *const () as u32),
        ("NetUserGetInfo", NetUserGetInfo as *const () as u32),
        (
            "NetUserGetLocalGroups",
            NetUserGetLocalGroups as *const () as u32,
        ),
        ("NetApiBufferFree", NetApiBufferFree as *const () as u32),
    ]
}

fn gap(what: &str) {
    with_current(|p| p.record_runtime_gap(GapKind::Feature, "netapi32.dll", what));
}

/// The engine list `name`, or an error code.
fn list(caller: Caller, name: &str) -> Result<Vec<Value>, u32> {
    match facts::call(caller, "list", json!({ "name": name })) {
        Ok(Value::Array(items)) => Ok(items),
        Ok(_) => Ok(Vec::new()),
        Err(_) => Err(ERROR_NOT_SUPPORTED),
    }
}

/// Whether `server` names this host: NULL or empty. Others are a gap.
fn local(function: &str, server: *const u16) -> bool {
    // SAFETY: NULL or a NUL-terminated string (the API's contract).
    let name = unsafe { wide(server) }.unwrap_or_default();
    if name.is_empty() {
        return true;
    }
    gap(&format!("{function} on server {name}"));
    false
}

/// Builds one block of `fields` pointers per entry, followed by the
/// UTF-16 strings they point at. Returns its address.
fn block(entries: &[Vec<String>], fields: usize) -> u32 {
    let head = entries.len() * fields * 4;
    let strings: usize = entries
        .iter()
        .flatten()
        .map(|s| (s.encode_utf16().count() + 1) * 2)
        .sum();
    // SAFETY: a plain allocation; freed by NetApiBufferFree.
    let base = unsafe { libc::calloc(1, (head + strings).max(4)) }.cast::<u8>();
    if base.is_null() {
        return 0;
    }
    let mut at = head;
    for (i, entry) in entries.iter().enumerate() {
        for (j, text) in entry.iter().enumerate() {
            let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
            // SAFETY: inside the block sized above.
            unsafe {
                let target = base.add(at);
                std::ptr::copy_nonoverlapping(units.as_ptr().cast::<u8>(), target, units.len() * 2);
                base.add((i * fields + j) * 4)
                    .cast::<u32>()
                    .write_unaligned(target as u32);
            }
            at += units.len() * 2;
        }
    }
    base as u32
}

/// Stores a result block and its counts.
fn deliver(
    entries: &[Vec<String>],
    fields: usize,
    buf: *mut u32,
    read: *mut u32,
    total: *mut u32,
) -> u32 {
    if buf.is_null() || read.is_null() || total.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let b = block(entries, fields);
    if b == 0 {
        return 8; // ERROR_NOT_ENOUGH_MEMORY
    }
    // SAFETY: writable (the API's contract).
    unsafe {
        *buf = b;
        *read = entries.len() as u32;
        *total = entries.len() as u32;
    }
    NERR_SUCCESS
}

fn name_of(v: &Value) -> String {
    v.get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn NetLocalGroupEnum(
    server: *const u16,
    level: u32,
    buf: *mut u32,
    _max: u32,
    read: *mut u32,
    total: *mut u32,
    resume: *mut u32,
) -> u32 {
    const CALLER: Caller = ("netapi32.dll", "NetLocalGroupEnum");
    if !local(CALLER.1, server) {
        return ERROR_NOT_SUPPORTED;
    }
    let groups = match list(CALLER, "groups") {
        Ok(g) => g,
        Err(e) => return e,
    };
    let entries: Vec<Vec<String>> = match level {
        0 => groups.iter().map(|g| vec![name_of(g)]).collect(),
        1 => {
            gap("NetLocalGroupEnum: group comments are not in the host profile");
            groups
                .iter()
                .map(|g| vec![name_of(g), String::new()])
                .collect()
        }
        _ => {
            gap(&format!("NetLocalGroupEnum level {level}"));
            return ERROR_INVALID_LEVEL;
        }
    };
    if !resume.is_null() {
        // SAFETY: writable (the API's contract).
        unsafe { *resume = 0 };
    }
    deliver(&entries, level as usize + 1, buf, read, total)
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn NetUserEnum(
    server: *const u16,
    level: u32,
    _filter: u32,
    buf: *mut u32,
    _max: u32,
    read: *mut u32,
    total: *mut u32,
    resume: *mut u32,
) -> u32 {
    const CALLER: Caller = ("netapi32.dll", "NetUserEnum");
    if !local(CALLER.1, server) {
        return ERROR_NOT_SUPPORTED;
    }
    if level != 0 {
        gap(&format!("NetUserEnum level {level}"));
        return ERROR_INVALID_LEVEL;
    }
    let users = match list(CALLER, "users") {
        Ok(u) => u,
        Err(e) => return e,
    };
    let entries: Vec<Vec<String>> = users.iter().map(|u| vec![name_of(u)]).collect();
    if !resume.is_null() {
        // SAFETY: writable (the API's contract).
        unsafe { *resume = 0 };
    }
    deliver(&entries, 1, buf, read, total)
}

#[allow(non_snake_case)]
extern "stdcall" fn NetUserGetInfo(
    server: *const u16,
    _user: *const u16,
    level: u32,
    _buf: *mut u32,
) -> u32 {
    if !local("NetUserGetInfo", server) {
        return ERROR_NOT_SUPPORTED;
    }
    gap(&format!("NetUserGetInfo level {level}"));
    ERROR_INVALID_LEVEL
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn NetUserGetLocalGroups(
    server: *const u16,
    user: *const u16,
    level: u32,
    _flags: u32,
    buf: *mut u32,
    _max: u32,
    read: *mut u32,
    total: *mut u32,
) -> u32 {
    const CALLER: Caller = ("netapi32.dll", "NetUserGetLocalGroups");
    if !local(CALLER.1, server) {
        return ERROR_NOT_SUPPORTED;
    }
    if level != 0 {
        gap(&format!("NetUserGetLocalGroups level {level}"));
        return ERROR_INVALID_LEVEL;
    }
    // SAFETY: a NUL-terminated string (the API's contract).
    let Some(user) = (unsafe { wide(user) }) else {
        return ERROR_INVALID_PARAMETER;
    };
    // A DOMAIN\name form names the local account by its last part.
    let user = user.rsplit('\\').next().unwrap_or_default().to_string();
    let users = match list(CALLER, "users") {
        Ok(u) => u,
        Err(e) => return e,
    };
    let Some(found) = users
        .iter()
        .find(|u| name_of(u).eq_ignore_ascii_case(&user))
    else {
        return NERR_USER_NOT_FOUND;
    };
    let entries: Vec<Vec<String>> = found
        .get("groups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|g| vec![g.to_string()])
        .collect();
    deliver(&entries, 1, buf, read, total)
}

#[allow(non_snake_case)]
extern "stdcall" fn NetApiBufferFree(buf: u32) -> u32 {
    // SAFETY: NULL or a block from one of the functions above.
    unsafe { libc::free(buf as usize as *mut libc::c_void) };
    NERR_SUCCESS
}

#[cfg(test)]
mod tests;
