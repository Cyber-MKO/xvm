//! The registry: `RegOpenKeyExA/W`, `RegQueryValueExA/W`, `RegCloseKey`.
//! Enumeration is in `enumerate.rs`.
//!
//! Keys and values come from the host-state engine. A key handle is a
//! kernel handle that holds the key's path in the engine. Following the
//! functions' pages and "Registry Redirector" on Microsoft Learn:
//!
//! | Case | Behaviour |
//! | --- | --- |
//! | 32-bit process, 64-bit Windows, `HKLM\SOFTWARE\...` | Read through `HKLM\SOFTWARE\WOW6432Node` unless `KEY_WOW64_64KEY` |
//! | That 32-bit key is not in the profile | The 64-bit key, as a logged gap: captures export the 64-bit view |
//! | String values | Converted to the profile's ANSI code page (A functions) or UTF-16 (W functions), with their NUL |
//! | No subkey (NULL or empty) | A predefined key returns itself; an open key gets a new handle to the same key |
//! | `HKEY_CURRENT_USER`, `HKEY_CLASSES_ROOT` and other roots | Logged gaps |
//!
//! Return values are Win32 error codes, not the last error.

mod enumerate;

use std::ffi::c_char;

use serde_json::{Value, json};

use crate::codepage;
use crate::gap::GapKind;
use crate::handles::Object;
use crate::runtime::with_current;
use crate::win::facts::{self, Caller, Failure};
use crate::win::text::{ansi, wide};

const HKEY_CLASSES_ROOT: u32 = 0x8000_0000;
const HKEY_CURRENT_USER: u32 = 0x8000_0001;
const HKEY_LOCAL_MACHINE: u32 = 0x8000_0002;
const HKEY_USERS: u32 = 0x8000_0003;
const KEY_WOW64_64KEY: u32 = 0x100;
const KEY_WOW64_32KEY: u32 = 0x200;

const ERROR_SUCCESS: i32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_INVALID_HANDLE: i32 = 6;
const ERROR_INVALID_PARAMETER: i32 = 87;
const ERROR_MORE_DATA: i32 = 234;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("RegOpenKeyExA", RegOpenKeyExA as *const () as u32),
        ("RegOpenKeyExW", RegOpenKeyExW as *const () as u32),
        ("RegQueryValueExA", RegQueryValueExA as *const () as u32),
        ("RegQueryValueExW", RegQueryValueExW as *const () as u32),
        ("RegCloseKey", RegCloseKey as *const () as u32),
    ]
    .into_iter()
    .chain(enumerate::exports())
    .collect()
}

fn gap(caller: Caller, what: &str) {
    let symbol = format!("{}: {what}", caller.1);
    with_current(|p| p.record_runtime_gap(GapKind::Feature, caller.0, &symbol));
}

/// The engine path of an open key or predefined root.
fn key_path(caller: Caller, hkey: u32) -> Result<String, i32> {
    match hkey {
        HKEY_LOCAL_MACHINE => Ok("HKLM".into()),
        HKEY_USERS => Ok("HKU".into()),
        HKEY_CLASSES_ROOT | HKEY_CURRENT_USER => {
            gap(caller, &format!("root key {hkey:#x}"));
            Err(ERROR_FILE_NOT_FOUND)
        }
        _ => with_current(|p| match p.handles.get(hkey) {
            Some(Object::RegKey(path)) => Ok(path.clone()),
            _ => Err(ERROR_INVALID_HANDLE),
        }),
    }
}

fn exists(caller: Caller, key: &str) -> Result<bool, i32> {
    match facts::call(caller, "reg.key_exists", json!({ "key": key })) {
        Ok(v) => Ok(v.as_bool().unwrap_or(false)),
        Err(Failure::NotFound) => Ok(false),
        Err(Failure::Unavailable) => Err(ERROR_ACCESS_DENIED),
    }
}

/// The key a 32-bit process reaches at `path`, as the redirector maps it.
fn redirected(path: &str) -> Option<String> {
    let rest = path.strip_prefix("HKLM\\").unwrap_or("");
    let (first, tail) = rest.split_once('\\').unwrap_or((rest, ""));
    if !first.eq_ignore_ascii_case("SOFTWARE") {
        return None;
    }
    if tail
        .split('\\')
        .next()
        .is_some_and(|c| c.eq_ignore_ascii_case("WOW6432Node"))
    {
        return None;
    }
    Some(if tail.is_empty() {
        "HKLM\\SOFTWARE\\WOW6432Node".into()
    } else {
        format!("HKLM\\SOFTWARE\\WOW6432Node\\{tail}")
    })
}

/// How a function spells strings: ANSI (A) or UTF-16 (W).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Enc {
    Ansi,
    Wide,
}

/// Opens `subkey` under `hkey` and writes a new handle to `result`.
#[allow(non_snake_case)]
extern "stdcall" fn RegOpenKeyExA(
    hkey: u32,
    subkey: *const c_char,
    _options: u32,
    access: u32,
    result: *mut u32,
) -> i32 {
    // SAFETY: NUL-terminated or NULL (the API's contract).
    let sub = unsafe { ansi(subkey) }.unwrap_or_default();
    open_key(
        ("advapi32.dll", "RegOpenKeyExA"),
        hkey,
        &sub,
        access,
        result,
    )
}

#[allow(non_snake_case)]
extern "stdcall" fn RegOpenKeyExW(
    hkey: u32,
    subkey: *const u16,
    _options: u32,
    access: u32,
    result: *mut u32,
) -> i32 {
    // SAFETY: NUL-terminated or NULL (the API's contract).
    let sub = unsafe { wide(subkey) }.unwrap_or_default();
    open_key(
        ("advapi32.dll", "RegOpenKeyExW"),
        hkey,
        &sub,
        access,
        result,
    )
}

fn open_key(caller: Caller, hkey: u32, sub: &str, access: u32, result: *mut u32) -> i32 {
    if result.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let base = match key_path(caller, hkey) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let sub = sub.trim_matches('\\');
    if sub.is_empty() {
        let handle = if matches!(hkey, HKEY_LOCAL_MACHINE | HKEY_USERS) {
            hkey
        } else {
            with_current(|p| p.handles.insert(Object::RegKey(base)))
        };
        // SAFETY: writable (the API's contract).
        unsafe { *result = handle };
        return ERROR_SUCCESS;
    }
    let path = format!("{base}\\{sub}");
    let mut candidates = vec![path.clone()];
    let wow64 = access & KEY_WOW64_64KEY == 0 && facts::is_64bit(caller) == Some(true);
    if access & KEY_WOW64_32KEY != 0 && !wow64 {
        gap(caller, "KEY_WOW64_32KEY on a 64-bit view");
    }
    if let Some(r) = redirected(&path).filter(|_| wow64) {
        candidates.insert(0, r);
    }
    for (i, candidate) in candidates.iter().enumerate() {
        match exists(caller, candidate) {
            Ok(true) => {
                if i == 1 {
                    gap(
                        caller,
                        &format!("32-bit view of {path} is not in the profile"),
                    );
                }
                let handle = with_current(|p| p.handles.insert(Object::RegKey(candidate.clone())));
                // SAFETY: writable (the API's contract).
                unsafe { *result = handle };
                return ERROR_SUCCESS;
            }
            Ok(false) => {}
            Err(code) => return code,
        }
    }
    ERROR_FILE_NOT_FOUND
}

/// A value's type code and bytes, strings in `enc`.
pub(super) fn value_bytes_as(caller: Caller, value: &Value, enc: Enc) -> Option<(u32, Vec<u8>)> {
    let kind = value.get("type")?.as_str()?;
    let data = value.get("data")?;
    let pages = with_current(|p| p.params.code_pages);
    let table = codepage::single_byte(pages.ansi)?;
    let text = |s: &str| {
        let units: Vec<u16> = s.encode_utf16().collect();
        match enc {
            Enc::Ansi => {
                let mut bytes = table.encode(&units, true, table.default_byte).0;
                bytes.push(0);
                bytes
            }
            Enc::Wide => units
                .iter()
                .chain([&0])
                .flat_map(|u| u.to_le_bytes())
                .collect(),
        }
    };
    Some(match kind {
        "REG_SZ" => (1, text(data.as_str()?)),
        "REG_EXPAND_SZ" => (2, text(data.as_str()?)),
        "REG_BINARY" => {
            let hex = data.as_str()?;
            let bytes = (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
                .ok()?;
            (3, bytes)
        }
        "REG_DWORD" => (
            4,
            u32::try_from(data.as_u64()?).ok()?.to_le_bytes().to_vec(),
        ),
        "REG_MULTI_SZ" => {
            let mut bytes: Vec<u8> = data
                .as_array()?
                .iter()
                .filter_map(Value::as_str)
                .flat_map(text)
                .collect();
            bytes.push(0);
            if enc == Enc::Wide {
                bytes.push(0);
            }
            (7, bytes)
        }
        "REG_QWORD" => (11, data.as_u64()?.to_le_bytes().to_vec()),
        other => {
            gap(caller, &format!("value type {other}"));
            return None;
        }
    })
}

/// Reads a value. With `data` NULL, only the size; with a buffer too
/// small, ERROR_MORE_DATA and the size needed.
#[allow(non_snake_case)]
extern "stdcall" fn RegQueryValueExA(
    hkey: u32,
    name: *const c_char,
    reserved: u32,
    kind: *mut u32,
    data: *mut u8,
    size: *mut u32,
) -> i32 {
    // SAFETY: NUL-terminated or NULL (the API's contract).
    let name = unsafe { ansi(name) }.unwrap_or_default();
    let caller = ("advapi32.dll", "RegQueryValueExA");
    query_value(caller, Enc::Ansi, hkey, name, reserved, kind, data, size)
}

#[allow(non_snake_case)]
extern "stdcall" fn RegQueryValueExW(
    hkey: u32,
    name: *const u16,
    reserved: u32,
    kind: *mut u32,
    data: *mut u8,
    size: *mut u32,
) -> i32 {
    // SAFETY: NUL-terminated or NULL (the API's contract).
    let name = unsafe { wide(name) }.unwrap_or_default();
    let caller = ("advapi32.dll", "RegQueryValueExW");
    query_value(caller, Enc::Wide, hkey, name, reserved, kind, data, size)
}

#[allow(clippy::too_many_arguments)]
fn query_value(
    caller: Caller,
    enc: Enc,
    hkey: u32,
    name: String,
    reserved: u32,
    kind: *mut u32,
    data: *mut u8,
    size: *mut u32,
) -> i32 {
    if reserved != 0 || (!data.is_null() && size.is_null()) {
        return ERROR_INVALID_PARAMETER;
    }
    let path = match key_path(caller, hkey) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let value = match facts::call(
        caller,
        "reg.query_value",
        json!({"key": path, "name": name}),
    ) {
        Ok(v) => v,
        Err(Failure::NotFound) => return ERROR_FILE_NOT_FOUND,
        Err(Failure::Unavailable) => return ERROR_ACCESS_DENIED,
    };
    let Some((code, bytes)) = value_bytes_as(caller, &value, enc) else {
        return ERROR_FILE_NOT_FOUND;
    };
    if !kind.is_null() {
        // SAFETY: writable (the API's contract).
        unsafe { *kind = code };
    }
    if size.is_null() {
        return ERROR_SUCCESS;
    }
    // SAFETY: as above.
    let room = unsafe { *size } as usize;
    // SAFETY: as above.
    unsafe { *size = bytes.len() as u32 };
    if data.is_null() {
        return ERROR_SUCCESS;
    }
    if room < bytes.len() {
        return ERROR_MORE_DATA;
    }
    // SAFETY: data holds `room` bytes (the API's contract).
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), data, bytes.len()) };
    ERROR_SUCCESS
}

#[allow(non_snake_case)]
extern "stdcall" fn RegCloseKey(hkey: u32) -> i32 {
    if matches!(
        hkey,
        HKEY_CLASSES_ROOT | HKEY_CURRENT_USER | HKEY_LOCAL_MACHINE | HKEY_USERS
    ) {
        return ERROR_SUCCESS;
    }
    with_current(|p| match p.handles.get(hkey) {
        Some(Object::RegKey(_)) => {
            p.handles.remove(hkey);
            ERROR_SUCCESS
        }
        _ => ERROR_INVALID_HANDLE,
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    const CV: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    pub(super) fn host() -> Runtime {
        let base = json!({
            "schema": 1, "kind": "base-image", "name": "b", "os": "windows",
            "source": {"golden_capture": "synthetic"},
            "os_info": {"version": "10.0", "build": "20348", "architecture": "x86_64"},
            "registry": {"keys": {
                CV: {
                    "ProductName": {"type": "REG_SZ", "data": "Windows Server 2022 Caf\u{e9}"},
                    "CurrentMajorVersionNumber": {"type": "REG_DWORD", "data": 10},
                    "Tags": {"type": "REG_MULTI_SZ", "data": ["a", "bc"]},
                    "Blob": {"type": "REG_BINARY", "data": "00ff10"},
                },
                r"HKLM\SOFTWARE\WOW6432Node\Wazuh": {
                    "Dir": {"type": "REG_SZ", "data": "x86"},
                },
                r"HKLM\SOFTWARE\Wazuh": {"Dir": {"type": "REG_SZ", "data": "x64"}},
            }},
        });
        let host = json!({"schema": 1, "kind": "host-profile", "name": "h", "base": "b",
                          "os": "windows", "identity": {"hostname": "H"}});
        let mut process = Process::new(Vec::new());
        process.engine = Some(facts::test_engine(base, host));
        Runtime::new(process)
    }

    fn open(root: u32, sub: &std::ffi::CStr, access: u32) -> Result<u32, i32> {
        let mut h = 0;
        match RegOpenKeyExA(root, sub.as_ptr(), 0, access, &mut h) {
            0 => Ok(h),
            e => Err(e),
        }
    }

    fn query(h: u32, name: &std::ffi::CStr) -> Result<(u32, Vec<u8>), i32> {
        let (mut kind, mut size) = (0, 0);
        let rc = RegQueryValueExA(
            h,
            name.as_ptr(),
            0,
            &mut kind,
            std::ptr::null_mut(),
            &mut size,
        );
        if rc != 0 {
            return Err(rc);
        }
        let mut buf = vec![0u8; size as usize];
        let mut short = size - 1;
        if size > 0 {
            let rc = RegQueryValueExA(h, name.as_ptr(), 0, &mut kind, buf.as_mut_ptr(), &mut short);
            assert_eq!((rc, short), (ERROR_MORE_DATA, size));
        }
        assert_eq!(
            RegQueryValueExA(h, name.as_ptr(), 0, &mut kind, buf.as_mut_ptr(), &mut size),
            0
        );
        Ok((kind, buf))
    }

    #[test]
    fn values_in_their_ansi_forms() {
        let runtime = host();
        let _thread = runtime.attach().unwrap();
        let h = open(
            HKEY_LOCAL_MACHINE,
            c"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0,
        )
        .unwrap();
        let (kind, name) = query(h, c"productname").unwrap();
        assert_eq!((kind, name), (1, b"Windows Server 2022 Caf\xe9\0".to_vec()));
        assert_eq!(
            query(h, c"CurrentMajorVersionNumber").unwrap(),
            (4, vec![10, 0, 0, 0])
        );
        assert_eq!(query(h, c"Tags").unwrap(), (7, b"a\0bc\0\0".to_vec()));
        assert_eq!(query(h, c"Blob").unwrap(), (3, vec![0, 0xff, 0x10]));
        assert_eq!(query(h, c"Missing"), Err(ERROR_FILE_NOT_FOUND));
        assert_eq!(RegCloseKey(h), 0);
        assert_eq!(RegCloseKey(h), ERROR_INVALID_HANDLE);
        let gaps: Vec<String> = runtime
            .lock()
            .gaps()
            .iter()
            .map(|g| g.symbol.clone())
            .collect();
        assert_eq!(
            gaps,
            [format!(
                "RegOpenKeyExA: 32-bit view of {CV} is not in the profile"
            )]
        );
    }

    #[test]
    fn the_32_bit_view_and_its_absence() {
        let runtime = host();
        let _thread = runtime.attach().unwrap();
        let x86 = open(HKEY_LOCAL_MACHINE, c"Software\\Wazuh", 0).unwrap();
        assert_eq!(query(x86, c"Dir").unwrap().1, b"x86\0");
        let x64 = open(HKEY_LOCAL_MACHINE, c"Software\\Wazuh", KEY_WOW64_64KEY).unwrap();
        assert_eq!(query(x64, c"Dir").unwrap().1, b"x64\0");
        let software = open(HKEY_LOCAL_MACHINE, c"SOFTWARE", 0).unwrap();
        let child = open(software, c"Wazuh", 0).unwrap();
        assert_eq!(
            query(child, c"Dir").unwrap().1,
            b"x86\0",
            "relative to WOW6432Node"
        );
        assert_eq!(
            open(HKEY_LOCAL_MACHINE, c"SOFTWARE\\Nothing", 0),
            Err(ERROR_FILE_NOT_FOUND)
        );
        assert_eq!(
            open(HKEY_CURRENT_USER, c"Software", 0),
            Err(ERROR_FILE_NOT_FOUND)
        );
        assert_eq!(open(0x1234, c"x", 0), Err(ERROR_INVALID_HANDLE));
        // No subkey: a predefined key is itself, even with nothing under
        // it; an open key gets a second handle.
        assert_eq!(open(HKEY_USERS, c"", 0), Ok(HKEY_USERS));
        let again = open(child, c"", 0).unwrap();
        assert_ne!(again, child);
        assert_eq!(query(again, c"Dir").unwrap().1, b"x86\0");
        let mut h = 0;
        assert_eq!(
            RegOpenKeyExA(HKEY_LOCAL_MACHINE, std::ptr::null(), 0, 0, &mut h),
            0
        );
        assert_eq!(h, HKEY_LOCAL_MACHINE);
    }

    #[test]
    fn without_an_engine_keys_cannot_be_read() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        assert_eq!(
            open(HKEY_LOCAL_MACHINE, c"SOFTWARE", 0),
            Err(ERROR_ACCESS_DENIED)
        );
    }
}
