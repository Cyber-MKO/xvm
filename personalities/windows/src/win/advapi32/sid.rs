//! SIDs and accounts: `IsValidSid`, `GetLengthSid`, `EqualSid`,
//! `GetSidSubAuthority`, `GetSidSubAuthorityCount`,
//! `ConvertSidToStringSidA/W`, `ConvertStringSidToSidA`,
//! `LookupAccountNameA/W`, `LookupAccountSidA/W`.
//!
//! Following each function's Microsoft Learn page. Strings and SIDs the
//! conversions return are `LocalAlloc` blocks the caller frees with
//! `LocalFree`.
//!
//! Accounts come from the engine's `users` and `groups` lists:
//!
//! | Account | Domain | Type |
//! | --- | --- | --- |
//! | A user | The computer's name | SidTypeUser (1) |
//! | A group with a `S-1-5-32-` SID | `BUILTIN` | SidTypeAlias (4) |
//! | Another group | The computer's name | SidTypeAlias (4) |
//!
//! The computer's name is its NetBIOS form: `identity.hostname` in upper
//! case, at most 15 characters. A name or SID in neither list fails with
//! ERROR_NONE_MAPPED and is a logged gap. Remote systems are logged gaps.

use std::ffi::c_char;

use serde_json::{Value, json};

use crate::codepage;
use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::sid;
use crate::win::facts::{self, Caller};
use crate::win::kernel32::error::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, set_last_error,
};
use crate::win::kernel32::message::LocalAlloc;
use crate::win::text::{ansi, wide};

const ERROR_NONE_MAPPED: u32 = 1332;
const ERROR_INVALID_SID: u32 = 1337;
const ERROR_NOT_SUPPORTED: u32 = 50;
const SID_TYPE_USER: u32 = 1;
const SID_TYPE_ALIAS: u32 = 4;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("IsValidSid", IsValidSid as *const () as u32),
        ("GetLengthSid", GetLengthSid as *const () as u32),
        ("EqualSid", EqualSid as *const () as u32),
        ("GetSidSubAuthority", GetSidSubAuthority as *const () as u32),
        (
            "GetSidSubAuthorityCount",
            GetSidSubAuthorityCount as *const () as u32,
        ),
        (
            "ConvertSidToStringSidA",
            ConvertSidToStringSidA as *const () as u32,
        ),
        (
            "ConvertSidToStringSidW",
            ConvertSidToStringSidW as *const () as u32,
        ),
        (
            "ConvertStringSidToSidA",
            ConvertStringSidToSidA as *const () as u32,
        ),
        ("LookupAccountNameA", LookupAccountNameA as *const () as u32),
        ("LookupAccountNameW", LookupAccountNameW as *const () as u32),
        ("LookupAccountSidA", LookupAccountSidA as *const () as u32),
        ("LookupAccountSidW", LookupAccountSidW as *const () as u32),
    ]
}

fn gap(what: &str) {
    with_current(|p| p.record_runtime_gap(GapKind::Feature, "advapi32.dll", what));
}

#[allow(non_snake_case)]
extern "stdcall" fn IsValidSid(p: *const u8) -> i32 {
    // SAFETY: NULL or a SID (the API's contract).
    i32::from(unsafe { sid::read(p) }.is_some())
}

#[allow(non_snake_case)]
extern "stdcall" fn GetLengthSid(p: *const u8) -> u32 {
    // SAFETY: as above.
    unsafe { sid::read(p) }.map_or(0, |s| s.len() as u32)
}

#[allow(non_snake_case)]
extern "stdcall" fn EqualSid(a: *const u8, b: *const u8) -> i32 {
    // SAFETY: as above.
    let (a, b) = unsafe { (sid::read(a), sid::read(b)) };
    set_last_error(0);
    i32::from(a.is_some() && a == b)
}

/// The address of sub-authority `n`. Not checked, as documented.
#[allow(non_snake_case)]
extern "stdcall" fn GetSidSubAuthority(p: *mut u8, n: u32) -> *mut u32 {
    // SAFETY: the caller asks for a sub-authority the SID has.
    unsafe { p.add(8 + 4 * n as usize).cast() }
}

/// The address of the sub-authority count. Not checked, as documented.
#[allow(non_snake_case)]
extern "stdcall" fn GetSidSubAuthorityCount(p: *mut u8) -> *mut u8 {
    // SAFETY: the caller passes a SID.
    unsafe { p.add(1) }
}

/// Copies `bytes` and a NUL of `unit` bytes into a `LocalAlloc` block.
fn local_copy(bytes: &[u8], unit: usize) -> *mut u8 {
    let block = LocalAlloc(0x40, (bytes.len() + unit) as u32);
    if !block.is_null() {
        // SAFETY: the block holds bytes and the zeroed NUL.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), block, bytes.len()) };
    }
    block
}

fn sid_text(p: *const u8) -> Option<String> {
    // SAFETY: NULL or a SID (the API's contract).
    unsafe { sid::read(p) }.and_then(|s| sid::to_text(&s))
}

#[allow(non_snake_case)]
extern "stdcall" fn ConvertSidToStringSidA(p: *const u8, out: *mut *mut u8) -> i32 {
    let (Some(text), false) = (sid_text(p), out.is_null()) else {
        set_last_error(ERROR_INVALID_SID);
        return 0;
    };
    // SAFETY: writable (the API's contract).
    unsafe { *out = local_copy(text.as_bytes(), 1) };
    1
}

#[allow(non_snake_case)]
extern "stdcall" fn ConvertSidToStringSidW(p: *const u8, out: *mut *mut u8) -> i32 {
    let (Some(text), false) = (sid_text(p), out.is_null()) else {
        set_last_error(ERROR_INVALID_SID);
        return 0;
    };
    let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    // SAFETY: writable (the API's contract).
    unsafe { *out = local_copy(&bytes, 2) };
    1
}

#[allow(non_snake_case)]
extern "stdcall" fn ConvertStringSidToSidA(text: *const c_char, out: *mut *mut u8) -> i32 {
    // SAFETY: a NUL-terminated string (the API's contract).
    let parsed = unsafe { ansi(text) }.and_then(|t| sid::to_bytes(&t));
    let (Some(bytes), false) = (parsed, out.is_null()) else {
        set_last_error(ERROR_INVALID_SID);
        return 0;
    };
    // SAFETY: writable (the API's contract).
    unsafe { *out = local_copy(&bytes, 0) };
    1
}

/// An account: name, SID, domain and SID type.
struct Account {
    name: String,
    sid: String,
    domain: String,
    kind: u32,
}

/// Every account in the profile, or an error code.
fn accounts(caller: Caller) -> Result<Vec<Account>, u32> {
    let list = |name: &str| match facts::call(caller, "list", json!({ "name": name })) {
        Ok(Value::Array(items)) => Ok(items),
        Ok(_) => Ok(Vec::new()),
        Err(_) => Err(ERROR_NOT_SUPPORTED),
    };
    let computer: String = facts::section(caller, "identity")
        .and_then(|i| {
            i.get("hostname")
                .and_then(Value::as_str)
                .map(str::to_uppercase)
        })
        .unwrap_or_default()
        .chars()
        .take(15)
        .collect();
    let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let mut out = Vec::new();
    for u in list("users")? {
        if let (Some(name), Some(sid)) = (text(&u, "name"), text(&u, "sid")) {
            let domain = computer.clone();
            out.push(Account {
                name,
                sid,
                domain,
                kind: SID_TYPE_USER,
            });
        }
    }
    for g in list("groups")? {
        if let (Some(name), Some(sid)) = (text(&g, "name"), text(&g, "sid")) {
            let domain = if sid.starts_with("S-1-5-32-") {
                "BUILTIN".to_string()
            } else {
                computer.clone()
            };
            out.push(Account {
                name,
                sid,
                domain,
                kind: SID_TYPE_ALIAS,
            });
        }
    }
    Ok(out)
}

fn remote(function: &str, system: Option<String>) -> bool {
    match system.filter(|s| !s.is_empty()) {
        Some(s) => {
            gap(&format!("{function} on system {s}"));
            true
        }
        None => false,
    }
}

/// Text in the profile's ANSI code page.
fn to_ansi(text: &str) -> Vec<u8> {
    let pages = with_current(|p| p.params.code_pages);
    let units: Vec<u16> = text.encode_utf16().collect();
    match codepage::single_byte(pages.ansi) {
        Some(table) => table.encode(&units, true, table.default_byte).0,
        None => text.bytes().collect(),
    }
}

/// A text output: stores `units` and a NUL in a buffer of `*len`
/// characters. Returns whether it fit; `*len` gets the size with the NUL
/// when it did not, and the length without it when it did.
///
/// # Safety
///
/// `len` must be readable and writable; `buf` must hold `*len` units.
unsafe fn put<T: Copy + Default>(units: &[T], buf: *mut T, len: *mut u32, fits: bool) {
    // SAFETY: the caller's contract.
    unsafe {
        if fits {
            std::ptr::copy_nonoverlapping(units.as_ptr(), buf, units.len());
            *buf.add(units.len()) = T::default();
            *len = units.len() as u32;
        } else {
            *len = units.len() as u32 + 1;
        }
    }
}

/// The work of `LookupAccountName`, with strings in units of `T`.
#[allow(clippy::too_many_arguments)]
fn lookup_name<T: Copy + Default>(
    function: &str,
    name: Option<String>,
    sid_out: *mut u8,
    sid_len: *mut u32,
    domain_out: *mut T,
    domain_len: *mut u32,
    kind: *mut u32,
    encode: impl Fn(&str) -> Vec<T>,
) -> i32 {
    let caller: Caller = ("advapi32.dll", "LookupAccountName");
    let (Some(name), false, false) = (name, sid_len.is_null(), domain_len.is_null()) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let all = match accounts(caller) {
        Ok(a) => a,
        Err(e) => {
            set_last_error(e);
            return 0;
        }
    };
    let (domain, bare) = match name.rsplit_once('\\') {
        Some((d, n)) => (Some(d.to_string()), n.to_string()),
        None => (None, name.clone()),
    };
    let found = all.iter().find(|a| {
        a.name.eq_ignore_ascii_case(&bare)
            && domain
                .as_deref()
                .is_none_or(|d| d.eq_ignore_ascii_case(&a.domain))
    });
    let Some(account) = found else {
        gap(&format!("{function}: {name} is not in the host profile"));
        set_last_error(ERROR_NONE_MAPPED);
        return 0;
    };
    let sid_bytes = sid::to_bytes(&account.sid).unwrap_or_default();
    let domain_units = encode(&account.domain);
    // SAFETY: readable (checked above).
    let (sid_room, domain_room) = unsafe { (*sid_len as usize, *domain_len as usize) };
    let fits = sid_room >= sid_bytes.len()
        && domain_room > domain_units.len()
        && !sid_out.is_null()
        && !domain_out.is_null();
    // SAFETY: the buffers hold the sizes the caller gave.
    unsafe {
        *sid_len = sid_bytes.len() as u32;
        put(&domain_units, domain_out, domain_len, fits);
        if !fits {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        std::ptr::copy_nonoverlapping(sid_bytes.as_ptr(), sid_out, sid_bytes.len());
        if !kind.is_null() {
            *kind = account.kind;
        }
    }
    1
}

/// The work of `LookupAccountSid`, with strings in units of `T`.
#[allow(clippy::too_many_arguments)]
fn lookup_sid<T: Copy + Default>(
    function: &str,
    sid_in: *const u8,
    name_out: *mut T,
    name_len: *mut u32,
    domain_out: *mut T,
    domain_len: *mut u32,
    kind: *mut u32,
    encode: impl Fn(&str) -> Vec<T>,
) -> i32 {
    let caller: Caller = ("advapi32.dll", "LookupAccountSid");
    let (Some(text), false, false) = (sid_text(sid_in), name_len.is_null(), domain_len.is_null())
    else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let all = match accounts(caller) {
        Ok(a) => a,
        Err(e) => {
            set_last_error(e);
            return 0;
        }
    };
    let Some(account) = all.iter().find(|a| a.sid.eq_ignore_ascii_case(&text)) else {
        gap(&format!("{function}: {text} is not in the host profile"));
        set_last_error(ERROR_NONE_MAPPED);
        return 0;
    };
    let (name, domain) = (encode(&account.name), encode(&account.domain));
    // SAFETY: readable (checked above).
    let (name_room, domain_room) = unsafe { (*name_len as usize, *domain_len as usize) };
    let fits = name_room > name.len()
        && domain_room > domain.len()
        && !name_out.is_null()
        && !domain_out.is_null();
    // SAFETY: the buffers hold the sizes the caller gave.
    unsafe {
        put(&name, name_out, name_len, fits);
        put(&domain, domain_out, domain_len, fits);
        if !fits {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        if !kind.is_null() {
            *kind = account.kind;
        }
    }
    1
}

fn utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn LookupAccountNameW(
    system: *const u16,
    name: *const u16,
    sid_out: *mut u8,
    sid_len: *mut u32,
    domain: *mut u16,
    domain_len: *mut u32,
    kind: *mut u32,
) -> i32 {
    // SAFETY: NULL or NUL-terminated strings (the API's contract).
    let (system, name) = unsafe { (wide(system), wide(name)) };
    if remote("LookupAccountNameW", system) {
        set_last_error(ERROR_NOT_SUPPORTED);
        return 0;
    }
    lookup_name(
        "LookupAccountNameW",
        name,
        sid_out,
        sid_len,
        domain,
        domain_len,
        kind,
        utf16,
    )
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn LookupAccountNameA(
    system: *const c_char,
    name: *const c_char,
    sid_out: *mut u8,
    sid_len: *mut u32,
    domain: *mut u8,
    domain_len: *mut u32,
    kind: *mut u32,
) -> i32 {
    // SAFETY: NULL or NUL-terminated strings (the API's contract).
    let (system, name) = unsafe { (ansi(system), ansi(name)) };
    if remote("LookupAccountNameA", system) {
        set_last_error(ERROR_NOT_SUPPORTED);
        return 0;
    }
    lookup_name(
        "LookupAccountNameA",
        name,
        sid_out,
        sid_len,
        domain,
        domain_len,
        kind,
        to_ansi,
    )
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn LookupAccountSidW(
    system: *const u16,
    sid_in: *const u8,
    name: *mut u16,
    name_len: *mut u32,
    domain: *mut u16,
    domain_len: *mut u32,
    kind: *mut u32,
) -> i32 {
    // SAFETY: NULL or a NUL-terminated string (the API's contract).
    if remote("LookupAccountSidW", unsafe { wide(system) }) {
        set_last_error(ERROR_NOT_SUPPORTED);
        return 0;
    }
    lookup_sid(
        "LookupAccountSidW",
        sid_in,
        name,
        name_len,
        domain,
        domain_len,
        kind,
        utf16,
    )
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn LookupAccountSidA(
    system: *const c_char,
    sid_in: *const u8,
    name: *mut u8,
    name_len: *mut u32,
    domain: *mut u8,
    domain_len: *mut u32,
    kind: *mut u32,
) -> i32 {
    // SAFETY: NULL or a NUL-terminated string (the API's contract).
    if remote("LookupAccountSidA", unsafe { ansi(system) }) {
        set_last_error(ERROR_NOT_SUPPORTED);
        return 0;
    }
    lookup_sid(
        "LookupAccountSidA",
        sid_in,
        name,
        name_len,
        domain,
        domain_len,
        kind,
        to_ansi,
    )
}

#[cfg(test)]
mod tests;
