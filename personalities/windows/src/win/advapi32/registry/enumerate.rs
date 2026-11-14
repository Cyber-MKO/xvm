//! Enumerating keys: `RegEnumKeyExA/W`, `RegEnumKeyW`, `RegEnumValueA/W`,
//! `RegQueryInfoKeyA/W`. The W functions spell names and string data in
//! UTF-16; lengths count UTF-16 units.
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
    ERROR_SUCCESS, Enc, gap, key_path, value_bytes_as,
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
        ("RegEnumKeyExW", RegEnumKeyExW as *const () as u32),
        ("RegEnumKeyW", RegEnumKeyW as *const () as u32),
        ("RegEnumValueA", RegEnumValueA as *const () as u32),
        ("RegEnumValueW", RegEnumValueW as *const () as u32),
        ("RegQueryInfoKeyA", RegQueryInfoKeyA as *const () as u32),
        ("RegQueryInfoKeyW", RegQueryInfoKeyW as *const () as u32),
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

/// A name in `enc`, without a NUL: its bytes and its length in units.
fn name_units(name: &str, enc: Enc) -> (Vec<u8>, usize) {
    match enc {
        Enc::Wide => {
            let units: Vec<u16> = name.encode_utf16().collect();
            let len = units.len();
            (units.into_iter().flat_map(u16::to_le_bytes).collect(), len)
        }
        Enc::Ansi => {
            let pages = with_current(|p| p.params.code_pages);
            let units: Vec<u16> = name.encode_utf16().collect();
            let bytes = match codepage::single_byte(pages.ansi) {
                Some(table) => table.encode(&units, true, table.default_byte).0,
                None => name
                    .bytes()
                    .map(|b| if b.is_ascii() { b } else { b'?' })
                    .collect(),
            };
            let len = bytes.len();
            (bytes, len)
        }
    }
}

fn unit(enc: Enc) -> usize {
    if enc == Enc::Wide { 2 } else { 1 }
}

/// Stores `name` and a NUL in a buffer of `*len` units, and its length in
/// `*len`. ERROR_MORE_DATA when it does not fit.
fn store_name(name: &str, enc: Enc, buf: *mut u8, len: *mut u32) -> i32 {
    if buf.is_null() || len.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let (bytes, units) = name_units(name, enc);
    // SAFETY: readable and writable (the API's contract).
    let room = unsafe { *len } as usize;
    if units + 1 > room {
        return ERROR_MORE_DATA;
    }
    // SAFETY: buf holds `room` units; the name and NUL fit.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
        std::ptr::write_bytes(buf.add(bytes.len()), 0, unit(enc));
        *len = units as u32;
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
fn no_class(class: *mut u8, class_len: *mut u32, enc: Enc) {
    // SAFETY: NULL or writable (the API's contract).
    unsafe {
        if !class.is_null() && !class_len.is_null() && *class_len > 0 {
            std::ptr::write_bytes(class, 0, unit(enc));
        }
        if let Some(l) = class_len.as_mut() {
            *l = 0;
        }
    }
}

/// The subkey at `index`, with its class and last write time.
#[allow(clippy::too_many_arguments)]
fn enum_key(
    caller: Caller,
    enc: Enc,
    hkey: u32,
    index: u32,
    name: *mut u8,
    name_len: *mut u32,
    reserved: *mut u32,
    class: *mut u8,
    class_len: *mut u32,
    written: *mut u64,
) -> i32 {
    if !reserved.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let path = match key_path(caller, hkey) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let subkeys = match ask(caller, "reg.enum_subkeys", &path) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let Some(subkey) = subkeys.get(index as usize).and_then(Value::as_str) else {
        return ERROR_NO_MORE_ITEMS;
    };
    let rc = store_name(subkey, enc, name, name_len);
    if rc != ERROR_SUCCESS {
        return rc;
    }
    no_class(class, class_len, enc);
    if !written.is_null() {
        let time = match ask(caller, "reg.key_info", &format!("{path}\\{subkey}")) {
            Ok(info) => last_write(caller, &info),
            Err(code) => return code,
        };
        // SAFETY: writable (the API's contract).
        unsafe { written.write_unaligned(time) };
    }
    ERROR_SUCCESS
}

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
    let caller = ("advapi32.dll", "RegEnumKeyExA");
    enum_key(
        caller,
        Enc::Ansi,
        hkey,
        index,
        name.cast(),
        name_len,
        reserved,
        class.cast(),
        class_len,
        written,
    )
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn RegEnumKeyExW(
    hkey: u32,
    index: u32,
    name: *mut u16,
    name_len: *mut u32,
    reserved: *mut u32,
    class: *mut u16,
    class_len: *mut u32,
    written: *mut u64,
) -> i32 {
    let caller = ("advapi32.dll", "RegEnumKeyExW");
    enum_key(
        caller,
        Enc::Wide,
        hkey,
        index,
        name.cast(),
        name_len,
        reserved,
        class.cast(),
        class_len,
        written,
    )
}

/// The older form: a buffer of `size` units, no class or time.
#[allow(non_snake_case)]
extern "stdcall" fn RegEnumKeyW(hkey: u32, index: u32, name: *mut u16, size: u32) -> i32 {
    let mut len = size;
    let none = std::ptr::null_mut();
    let caller = ("advapi32.dll", "RegEnumKeyW");
    enum_key(
        caller,
        Enc::Wide,
        hkey,
        index,
        name.cast(),
        &mut len,
        none,
        none.cast(),
        none,
        none.cast(),
    )
}

/// The value at `index`: its name, type and data.
#[allow(clippy::too_many_arguments)]
fn enum_value(
    caller: Caller,
    enc: Enc,
    hkey: u32,
    index: u32,
    name: *mut u8,
    name_len: *mut u32,
    reserved: *mut u32,
    kind: *mut u32,
    data: *mut u8,
    size: *mut u32,
) -> i32 {
    if !reserved.is_null() || (!data.is_null() && size.is_null()) {
        return ERROR_INVALID_PARAMETER;
    }
    let path = match key_path(caller, hkey) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let values = match ask(caller, "reg.enum_values", &path) {
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
    let rc = store_name(value_name, enc, name, name_len);
    if rc != ERROR_SUCCESS {
        return rc;
    }
    let Some((code, bytes)) = value_bytes_as(caller, value, enc) else {
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
    let caller = ("advapi32.dll", "RegEnumValueA");
    enum_value(
        caller,
        Enc::Ansi,
        hkey,
        index,
        name.cast(),
        name_len,
        reserved,
        kind,
        data,
        size,
    )
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn RegEnumValueW(
    hkey: u32,
    index: u32,
    name: *mut u16,
    name_len: *mut u32,
    reserved: *mut u32,
    kind: *mut u32,
    data: *mut u8,
    size: *mut u32,
) -> i32 {
    let caller = ("advapi32.dll", "RegEnumValueW");
    enum_value(
        caller,
        Enc::Wide,
        hkey,
        index,
        name.cast(),
        name_len,
        reserved,
        kind,
        data,
        size,
    )
}

/// Counts and longest lengths of a key's subkeys and values.
#[allow(clippy::too_many_arguments)]
fn query_info(
    caller: Caller,
    enc: Enc,
    hkey: u32,
    class: *mut u8,
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
    if !reserved.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let path = match key_path(caller, hkey) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let (info, subkeys, values) = match (
        ask(caller, "reg.key_info", &path),
        ask(caller, "reg.enum_subkeys", &path),
        ask(caller, "reg.enum_values", &path),
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
        names.map(|n| name_units(n, enc).1).max().unwrap_or(0) as u32
    };
    let max_subkey = longest(&mut subkeys.iter().copied());
    let max_value_name = longest(&mut values.iter().filter_map(|v| v.get("name")?.as_str()));
    let max_value = values
        .iter()
        .filter_map(|v| value_bytes_as(caller, v, enc))
        .map(|(_, b)| b.len())
        .max()
        .unwrap_or(0) as u32;
    no_class(class, class_len, enc);
    if !security_len.is_null() {
        gap(caller, "security descriptors are not modelled");
    }
    let time = if written.is_null() {
        0
    } else {
        last_write(caller, &info)
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
    let caller = ("advapi32.dll", "RegQueryInfoKeyA");
    query_info(
        caller,
        Enc::Ansi,
        hkey,
        class.cast(),
        class_len,
        reserved,
        subkey_count,
        max_subkey_len,
        max_class_len,
        value_count,
        max_value_name_len,
        max_value_len,
        security_len,
        written,
    )
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn RegQueryInfoKeyW(
    hkey: u32,
    class: *mut u16,
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
    let caller = ("advapi32.dll", "RegQueryInfoKeyW");
    query_info(
        caller,
        Enc::Wide,
        hkey,
        class.cast(),
        class_len,
        reserved,
        subkey_count,
        max_subkey_len,
        max_class_len,
        value_count,
        max_value_name_len,
        max_value_len,
        security_len,
        written,
    )
}

#[cfg(test)]
mod tests {
    use super::super::tests::host;
    use super::super::{HKEY_LOCAL_MACHINE, RegOpenKeyExA, RegOpenKeyExW, RegQueryValueExW};
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

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    #[test]
    fn wide_forms_use_utf16() {
        let runtime = host();
        let _thread = runtime.attach().unwrap();
        let mut cv = 0;
        let path = w("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
        assert_eq!(
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, 0x100, &mut cv),
            0
        );
        let (mut kind, mut size) = (0u32, 0u32);
        let name = w("ProductName");
        assert_eq!(
            RegQueryValueExW(
                cv,
                name.as_ptr(),
                0,
                &mut kind,
                std::ptr::null_mut(),
                &mut size
            ),
            0
        );
        let expected = w("Windows Server 2022 Caf\u{e9}");
        assert_eq!((kind, size), (1, expected.len() as u32 * 2));
        let mut data = vec![0u16; expected.len()];
        assert_eq!(
            RegQueryValueExW(
                cv,
                name.as_ptr(),
                0,
                &mut kind,
                data.as_mut_ptr().cast(),
                &mut size
            ),
            0
        );
        assert_eq!(data, expected);

        // REG_MULTI_SZ ends with two UTF-16 NULs.
        let mut vname = [0u16; 16];
        let mut vlen = 16;
        let mut bytes = [0u8; 16];
        let mut blen = 16;
        assert_eq!(
            RegEnumValueW(
                cv,
                2,
                vname.as_mut_ptr(),
                &mut vlen,
                std::ptr::null_mut(),
                &mut kind,
                bytes.as_mut_ptr(),
                &mut blen
            ),
            0
        );
        assert_eq!(String::from_utf16(&vname[..vlen as usize]).unwrap(), "Tags");
        assert_eq!(
            &bytes[..blen as usize],
            &[b'a', 0, 0, 0, b'b', 0, b'c', 0, 0, 0, 0, 0]
        );

        let (mut values, mut longest_name) = (0, 0);
        assert_eq!(
            RegQueryInfoKeyW(
                cv,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut values,
                &mut longest_name,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            0
        );
        assert_eq!(
            (values, longest_name),
            (4, "CurrentMajorVersionNumber".len() as u32)
        );

        let mut software = 0;
        let s = w("SOFTWARE");
        assert_eq!(
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, s.as_ptr(), 0, 0x100, &mut software),
            0
        );
        let mut key = [0u16; 4];
        assert_eq!(
            RegEnumKeyW(software, 0, key.as_mut_ptr(), 4),
            ERROR_MORE_DATA,
            "Microsoft needs 10"
        );
        let mut key = [0u16; 16];
        assert_eq!(RegEnumKeyW(software, 0, key.as_mut_ptr(), 16), 0);
        let end = key.iter().position(|&u| u == 0).unwrap();
        assert_eq!(String::from_utf16(&key[..end]).unwrap(), "Microsoft");
        let mut klen = 16;
        assert_eq!(
            RegEnumKeyExW(
                software,
                1,
                key.as_mut_ptr(),
                &mut klen,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            0
        );
        assert_eq!(String::from_utf16(&key[..klen as usize]).unwrap(), "Wazuh");
    }
}
