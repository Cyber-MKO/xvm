//! The process environment: `GetEnvironmentVariableA/W`.
//!
//! The variables come from the host profile, as `NAME=value` strings
//! (`ProcessParams::environment`). Names match without regard to case.

use std::ffi::c_char;

use super::error::set_last_error;
use crate::runtime::with_current;
use crate::win::text::{ansi, wide};

/// `ERROR_ENVVAR_NOT_FOUND`, from "System Error Codes".
const ERROR_ENVVAR_NOT_FOUND: u32 = 203;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        (
            "GetEnvironmentVariableA",
            GetEnvironmentVariableA as *const () as u32,
        ),
        (
            "GetEnvironmentVariableW",
            GetEnvironmentVariableW as *const () as u32,
        ),
    ]
}

/// The value of `name`, or None if the process has no such variable.
pub(crate) fn lookup(name: &str) -> Option<String> {
    if name.is_empty() || name.contains('=') {
        return None;
    }
    with_current(|p| {
        p.params.environment.iter().find_map(|entry| {
            let (key, value) = entry.split_once('=')?;
            key.eq_ignore_ascii_case(name).then(|| value.to_string())
        })
    })
}

/// Copy `value` the way both functions do. Returns the length without
/// the NUL, or the size needed with it when `out` is too small.
///
/// # Safety
///
/// `out` holds `out_len` units.
unsafe fn copy_out<T: Copy + Default>(value: &[T], out: *mut T, out_len: u32) -> u32 {
    if value.is_empty() {
        set_last_error(0);
    }
    if out.is_null() || (out_len as usize) <= value.len() {
        return value.len() as u32 + 1;
    }
    // SAFETY: the caller's contract; checked to fit with the NUL.
    unsafe {
        std::ptr::copy_nonoverlapping(value.as_ptr(), out, value.len());
        *out.add(value.len()) = T::default();
    }
    value.len() as u32
}

#[allow(non_snake_case)]
extern "stdcall" fn GetEnvironmentVariableW(name: *const u16, out: *mut u16, out_len: u32) -> u32 {
    // SAFETY: a NUL-terminated string (the API's contract).
    let Some(value) = (unsafe { wide(name) }).as_deref().and_then(lookup) else {
        set_last_error(ERROR_ENVVAR_NOT_FOUND);
        return 0;
    };
    let units: Vec<u16> = value.encode_utf16().collect();
    // SAFETY: the API's contract for out.
    unsafe { copy_out(&units, out, out_len) }
}

#[allow(non_snake_case)]
extern "stdcall" fn GetEnvironmentVariableA(
    name: *const c_char,
    out: *mut c_char,
    out_len: u32,
) -> u32 {
    // SAFETY: a NUL-terminated string (the API's contract).
    let Some(value) = (unsafe { ansi(name) }).as_deref().and_then(lookup) else {
        set_last_error(ERROR_ENVVAR_NOT_FOUND);
        return 0;
    };
    // The profile holds ASCII only (profile::validate).
    // SAFETY: the API's contract for out; c_char and u8 match.
    unsafe { copy_out(value.as_bytes(), out.cast(), out_len) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    fn last_error() -> u32 {
        let value: u32;
        // SAFETY: the test thread is attached, so fs holds a TEB.
        unsafe { std::arch::asm!("mov {0}, dword ptr fs:[0x34]", out(reg) value) };
        value
    }

    #[test]
    fn variables_by_name_ignoring_case() {
        let mut process = Process::new(Vec::new());
        process.params.environment = vec![r"SystemRoot=C:\Windows".into(), "EMPTY=".into()];
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();

        let name: Vec<u16> = "systemroot\0".encode_utf16().collect();
        assert_eq!(
            GetEnvironmentVariableW(name.as_ptr(), std::ptr::null_mut(), 0),
            11
        );
        let mut small = [0x55u16; 10];
        assert_eq!(
            GetEnvironmentVariableW(name.as_ptr(), small.as_mut_ptr(), 10),
            11
        );
        assert_eq!(small, [0x55; 10], "untouched when too small");
        let mut buf = [0u16; 11];
        assert_eq!(
            GetEnvironmentVariableW(name.as_ptr(), buf.as_mut_ptr(), 11),
            10
        );
        assert_eq!(String::from_utf16(&buf[..10]).unwrap(), r"C:\Windows");
        assert_eq!(buf[10], 0);

        let mut abuf = [0 as c_char; 16];
        assert_eq!(
            GetEnvironmentVariableA(c"SYSTEMROOT".as_ptr(), abuf.as_mut_ptr(), 16),
            10
        );
        assert_eq!(
            GetEnvironmentVariableA(c"MISSING".as_ptr(), abuf.as_mut_ptr(), 16),
            0
        );
        assert_eq!(last_error(), ERROR_ENVVAR_NOT_FOUND);
        assert_eq!(
            GetEnvironmentVariableA(c"EMPTY".as_ptr(), abuf.as_mut_ptr(), 16),
            0
        );
        assert_eq!(last_error(), 0, "an empty value is not an error");
        assert_eq!(
            GetEnvironmentVariableA(c"A=B".as_ptr(), abuf.as_mut_ptr(), 16),
            0
        );
    }
}
