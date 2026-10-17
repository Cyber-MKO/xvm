//! Enumerating keys: `RegEnumKeyExA`, `RegEnumValueA`, `RegQueryInfoKeyA`.
//!
//! Subkeys and values come from the engine (`reg.enum_subkeys`,
//! `reg.enum_values`, `reg.key_info`), in the engine's order. Following
//! the functions' pages on Microsoft Learn:
//!
//! | Case | Behaviour |
//! | --- | --- |
//! | Index past the end | ERROR_NO_MORE_ITEMS |
//! | Name buffer too small | ERROR_MORE_DATA |
//! | Data buffer too small (`RegEnumValueA`) | ERROR_MORE_DATA and the size needed |
//! | Lengths (`RegQueryInfoKeyA`) | Characters without the NUL for names; bytes for data, as `RegQueryValueExA` returns it |
//! | Class names | Empty: profiles hold none |
//! | Last write time | The engine's, for keys changed at run time. A profile key has none: 0, a logged gap |
//! | Security descriptor length | Not modelled: 0, a logged gap when asked for |
//! | A predefined root with nothing under it in the profile | Empty: the roots always exist |

use std::ffi::c_char;

use serde_json::{Value, json};

use super::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA,
    ERROR_SUCCESS, gap, key_path, value_bytes,
};
use crate::codepage;
use crate::runtime::with_current;
use crate::win::facts::{self, Caller, Failure};

const ERROR_NO_MORE_ITEMS: i32 = 259;
/// Milliseconds from 1601-01-01, where FILETIMEs start, to 1970-01-01.
const EPOCH_DIFFERENCE_MS: i64 = 11_644_473_600_000;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("RegEnumKeyExA", RegEnumKeyExA as *const () as u32),
        ("RegEnumValueA", RegEnumValueA as *const () as u32),
        ("RegQueryInfoKeyA", RegQueryInfoKeyA as *const () as u32),
    ]
}

/// An engine answer about the key at `path`. A predefined root always
/// exists on Windows, so one the profile has nothing under is empty.
fn ask(caller: Caller, op: &str, path: &str) -> Result<Value, i32> {
    match facts::call(caller, op, json!({ "key": path })) {
        Ok(v) => Ok(v),
        Err(Failure::NotFound) if !path.contains('\\') => Ok(match op {
            "reg.key_info" => {
                json!({"path": path, "subkeys": 0, "values": 0, "last_write": null})
            }
            _ => json!([]),
        }),
        Err(Failure::NotFound) => Err(ERROR_FILE_NOT_FOUND),
        Err(Failure::Unavailable) => Err(ERROR_ACCESS_DENIED),
    }
}

/// A name in the profile's ANSI code page, without a NUL.
fn ansi_name(name: &str) -> Vec<u8> {
    let pages = with_current(|p| p.params.code_pages);
    let units: Vec<u16> = name.encode_utf16().collect();
    match codepage::single_byte(pages.ansi) {
        Some(table) => table.encode(&units, true, table.default_byte).0,
        None => name
            .bytes()
            .map(|b| if b.is_ascii() { b } else { b'?' })
            .collect(),
    }
}

/// Stores `name` and a NUL in a buffer of `*len` characters, and its
/// length in `*len`. ERROR_MORE_DATA when it does not fit.
fn store_name(name: &[u8], buf: *mut c_char, len: *mut u32) -> i32 {
    if buf.is_null() || len.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: readable and writable (the API's contract).
    let room = unsafe { *len } as usize;
    if name.len() + 1 > room {
        return ERROR_MORE_DATA;
    }
    // SAFETY: buf holds `room` bytes; name and NUL fit.
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), buf.cast::<u8>(), name.len());
        *buf.add(name.len()) = 0;
        *len = name.len() as u32;
    }
    ERROR_SUCCESS
}

/// The key's last write time as a FILETIME: the engine's, or 0 with a
/// logged gap for a key that has not changed since the profile.
fn last_write(caller: Caller, info: &Value) -> u64 {
    match info
        .get("last_write")
        .and_then(Value::as_str)
        .and_then(crate::win::kernel32::time::parse_utc)
    {
        Some(ms) => ((ms + EPOCH_DIFFERENCE_MS) * 10_000) as u64,
        None => {
            gap(caller, "the last write time of a profile key");
            0
        }
    }
}

/// Clears an optional class buffer: profiles hold no class names.
fn no_class(class: *mut c_char, class_len: *mut u32) {
    // SAFETY: NULL or writable (the API's contract).
    unsafe {
        if !class.is_null() && !class_len.is_null() && *class_len > 0 {
            *class = 0;
        }
        if let Some(l) = class_len.as_mut() {
            *l = 0;
        }
    }
}

/// The subkey at `index`, with its class and last write time.
#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn RegEnumKeyExA(
    hkey: u32,
    index: u32,
    name: *mut c_char,
    name_len: *mut u32,
    reserved: *mut u32,
    class: *mut c_char,
    class_len: *mut u32,
    written: *mut u64,
) -> i32 {
    const CALLER: Caller = ("advapi32.dll", "RegEnumKeyExA");
    if !reserved.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let path = match key_path(CALLER, hkey) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let subkeys = match ask(CALLER, "reg.enum_subkeys", &path) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let Some(subkey) = subkeys.get(index as usize).and_then(Value::as_str) else {
        return ERROR_NO_MORE_ITEMS;
    };
    let rc = store_name(&ansi_name(subkey), name, name_len);
    if rc != ERROR_SUCCESS {
        return rc;
    }
    no_class(class, class_len);
    if !written.is_null() {
        let time = match ask(CALLER, "reg.key_info", &format!("{path}\\{subkey}")) {
            Ok(info) => last_write(CALLER, &info),
            Err(code) => return code,
        };
        // SAFETY: writable (the API's contract).
        unsafe { written.write_unaligned(time) };
    }
    ERROR_SUCCESS
}

/// The value at `index`: its name, type and data.
#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn RegEnumValueA(
    hkey: u32,
    index: u32,
    name: *mut c_char,
    name_len: *mut u32,
    reserved: *mut u32,
    kind: *mut u32,
    data: *mut u8,
    size: *mut u32,
) -> i32 {
    const CALLER: Caller = ("advapi32.dll", "RegEnumValueA");
    if !reserved.is_null() || (!data.is_null() && size.is_null()) {
        return ERROR_INVALID_PARAMETER;
    }
    let path = match key_path(CALLER, hkey) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let values = match ask(CALLER, "reg.enum_values", &path) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let Some(value) = values.get(index as usize) else {
        return ERROR_NO_MORE_ITEMS;
    };
    let value_name = value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let rc = store_name(&ansi_name(value_name), name, name_len);
    if rc != ERROR_SUCCESS {
        return rc;
    }
    let Some((code, bytes)) = value_bytes(CALLER, value) else {
        return ERROR_FILE_NOT_FOUND;
    };
    // SAFETY: NULL or writable (the API's contract).
    unsafe {
        if let Some(k) = kind.as_mut() {
            *k = code;
        }
        let Some(size) = size.as_mut() else {
            return ERROR_SUCCESS;
        };
        let room = *size as usize;
        *size = bytes.len() as u32;
        if data.is_null() {
            return ERROR_SUCCESS;
        }
        if room < bytes.len() {
            return ERROR_MORE_DATA;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), data, bytes.len());
    }
    ERROR_SUCCESS
}

/// Counts and longest lengths of a key's subkeys and values.
#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn RegQueryInfoKeyA(
    hkey: u32,
    class: *mut c_char,
    class_len: *mut u32,
    reserved: *mut u32,
    subkey_count: *mut u32,
    max_subkey_len: *mut u32,
    max_class_len: *mut u32,
    value_count: *mut u32,
    max_value_name_len: *mut u32,
    max_value_len: *mut u32,
    security_len: *mut u32,
    written: *mut u64,
) -> i32 {
    const CALLER: Caller = ("advapi32.dll", "RegQueryInfoKeyA");
    if !reserved.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let path = match key_path(CALLER, hkey) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let (info, subkeys, values) = match (
        ask(CALLER, "reg.key_info", &path),
        ask(CALLER, "reg.enum_subkeys", &path),
        ask(CALLER, "reg.enum_values", &path),
    ) {
        (Ok(i), Ok(s), Ok(v)) => (i, s, v),
        (Err(code), ..) | (_, Err(code), _) | (.., Err(code)) => return code,
    };
    let subkeys: Vec<&str> = subkeys
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let values: &[Value] = values.as_array().map_or(&[], Vec::as_slice);
    let longest = |names: &mut dyn Iterator<Item = &str>| {
        names.map(|n| ansi_name(n).len()).max().unwrap_or(0) as u32
    };
    let max_subkey = longest(&mut subkeys.iter().copied());
    let max_value_name = longest(&mut values.iter().filter_map(|v| v.get("name")?.as_str()));
    let max_value = values
        .iter()
        .filter_map(|v| value_bytes(CALLER, v))
        .map(|(_, b)| b.len())
        .max()
        .unwrap_or(0) as u32;
    no_class(class, class_len);
    if !security_len.is_null() {
        gap(CALLER, "security descriptors are not modelled");
    }
    let time = if written.is_null() {
        0
    } else {
        last_write(CALLER, &info)
    };
    // SAFETY: NULL or writable (the API's contract).
    unsafe {
        for (out, v) in [
            (subkey_count, subkeys.len() as u32),
            (max_subkey_len, max_subkey),
            (max_class_len, 0),
            (value_count, values.len() as u32),
            (max_value_name_len, max_value_name),
            (max_value_len, max_value),
            (security_len, 0),
        ] {
            if let Some(o) = out.as_mut() {
                *o = v;
            }
        }
        if !written.is_null() {
            written.write_unaligned(time);
        }
    }
    ERROR_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::super::tests::host;
    use super::super::{HKEY_LOCAL_MACHINE, RegOpenKeyExA};
    use super::*;

    fn open(path: &std::ffi::CStr) -> u32 {
        let mut h = 0;
        assert_eq!(
            RegOpenKeyExA(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, 0x100, &mut h),
            0
        );
        h
    }

    #[test]
    fn subkeys_and_values_in_profile_order() {
        let runtime = host();
        let _thread = runtime.attach().unwrap();
        let software = open(c"SOFTWARE");
        let mut names = Vec::new();
        for i in 0.. {
            let mut buf = [0 as c_char; 32];
            let mut len = 32;
            let mut time = 1u64;
            match RegEnumKeyExA(
                software,
                i,
                buf.as_mut_ptr(),
                &mut len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut time,
            ) {
                ERROR_SUCCESS => {
                    let bytes: Vec<u8> = buf[..len as usize].iter().map(|&c| c as u8).collect();
                    assert_eq!(buf[len as usize], 0);
                    assert_eq!(time, 0, "a profile key");
                    names.push(String::from_utf8(bytes).unwrap());
                }
                ERROR_NO_MORE_ITEMS => break,
                other => panic!("{other}"),
            }
        }
        assert_eq!(
            names,
            ["Microsoft", "Wazuh", "WOW6432Node"],
            "sorted without case"
        );
        let mut short = [0 as c_char; 4];
        let mut len = 4;
        let none = std::ptr::null_mut();
        assert_eq!(
            RegEnumKeyExA(
                software,
                0,
                short.as_mut_ptr(),
                &mut len,
                none,
                none.cast(),
                none,
                std::ptr::null_mut()
            ),
            ERROR_MORE_DATA
        );

        let cv = open(c"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
        let (mut subkeys, mut max_value_name, mut values, mut max_value) = (9, 0, 0, 0);
        assert_eq!(
            RegQueryInfoKeyA(
                cv,
                none.cast(),
                none,
                none,
                &mut subkeys,
                none,
                none,
                &mut values,
                &mut max_value_name,
                &mut max_value,
                none,
                std::ptr::null_mut(),
            ),
            0
        );
        assert_eq!((subkeys, values), (0, 4));
        assert_eq!(max_value_name, "CurrentMajorVersionNumber".len() as u32);
        assert_eq!(
            max_value,
            "Windows Server 2022 Caf\u{e9}".chars().count() as u32 + 1
        );

        let mut name = [0 as c_char; 32];
        let (mut len, mut kind, mut size) = (32, 0, 0);
        assert_eq!(
            RegEnumValueA(
                cv,
                2,
                name.as_mut_ptr(),
                &mut len,
                none,
                &mut kind,
                std::ptr::null_mut(),
                &mut size
            ),
            0
        );
        assert_eq!((len, kind, size), (4, 7, 6), "Tags, REG_MULTI_SZ a, bc");
        let mut data = [0u8; 6];
        let mut small = 3;
        len = 32;
        assert_eq!(
            RegEnumValueA(
                cv,
                2,
                name.as_mut_ptr(),
                &mut len,
                none,
                &mut kind,
                data.as_mut_ptr(),
                &mut small
            ),
            ERROR_MORE_DATA
        );
        assert_eq!(small, 6);
        len = 32;
        assert_eq!(
            RegEnumValueA(
                cv,
                2,
                name.as_mut_ptr(),
                &mut len,
                none,
                &mut kind,
                data.as_mut_ptr(),
                &mut size
            ),
            0
        );
        assert_eq!(&data, b"a\0bc\0\0");
        assert_eq!(
            RegEnumValueA(
                cv,
                4,
                name.as_mut_ptr(),
                &mut len,
                none,
                &mut kind,
                data.as_mut_ptr(),
                &mut size
            ),
            ERROR_NO_MORE_ITEMS
        );
        // HKEY_USERS has nothing under it in this profile: empty, not missing.
        let mut buf = [0 as c_char; 8];
        let mut len = 8;
        assert_eq!(
            RegEnumKeyExA(
                super::super::HKEY_USERS,
                0,
                buf.as_mut_ptr(),
                &mut len,
                none,
                none.cast(),
                none,
                std::ptr::null_mut()
            ),
            ERROR_NO_MORE_ITEMS
        );
        let gaps: Vec<String> = runtime
            .lock()
            .gaps()
            .iter()
            .map(|g| g.symbol.clone())
            .collect();
        assert!(
            gaps.contains(&"RegEnumKeyExA: the last write time of a profile key".to_string()),
            "{gaps:?}"
        );
    }
}
