//! Code page conversion: `MultiByteToWideChar`, `WideCharToMultiByte`.
//!
//! `CP_UTF8` is complete, following the two functions' pages on Microsoft
//! Learn: invalid input becomes U+FFFD unless the caller asks for an
//! error. The ANSI code page (`CP_ACP`) is a host fact the profile does
//! not hold yet, so only 7-bit text converts, which every Windows ANSI
//! code page maps the same way. Anything else is a logged gap.

use super::error::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, set_last_error};
use crate::gap::GapKind;
use crate::runtime::with_current;

const CP_ACP: u32 = 0;
const CP_UTF8: u32 = 65001;
const MB_ERR_INVALID_CHARS: u32 = 0x8;
const WC_ERR_INVALID_CHARS: u32 = 0x80;

// From "System Error Codes" on Microsoft Learn.
const ERROR_INVALID_FLAGS: u32 = 1004;
const ERROR_NO_UNICODE_TRANSLATION: u32 = 1113;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        (
            "MultiByteToWideChar",
            MultiByteToWideChar as *const () as u32,
        ),
        (
            "WideCharToMultiByte",
            WideCharToMultiByte as *const () as u32,
        ),
    ]
}

fn gap(what: String) {
    with_current(|p| p.record_runtime_gap(GapKind::Feature, "kernel32.dll", &what));
}

/// The input as a slice. A length of -1 means NUL-terminated, NUL
/// included, as documented.
///
/// # Safety
///
/// `p` points at `len` units, or at a NUL-terminated string for -1.
unsafe fn input<'a, T: Copy + PartialEq + From<u8>>(p: *const T, len: i32) -> &'a [T] {
    let len = if len == -1 {
        let mut n = 0;
        // SAFETY: NUL-terminated (the caller's contract).
        while unsafe { *p.add(n) } != T::from(0) {
            n += 1;
        }
        n + 1
    } else {
        len as usize
    };
    // SAFETY: the caller's contract.
    unsafe { std::slice::from_raw_parts(p, len) }
}

/// Write `units` to `out` the way both functions do: with `out_len` 0,
/// just the size; too small, ERROR_INSUFFICIENT_BUFFER.
///
/// # Safety
///
/// `out` holds `out_len` units when `out_len` is not 0.
unsafe fn output<T: Copy>(units: &[T], out: *mut T, out_len: i32) -> i32 {
    if out_len == 0 {
        return units.len() as i32;
    }
    if (out_len as usize) < units.len() {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // SAFETY: the caller's contract; checked to fit.
    unsafe { std::ptr::copy_nonoverlapping(units.as_ptr(), out, units.len()) };
    units.len() as i32
}

#[allow(non_snake_case)]
extern "stdcall" fn MultiByteToWideChar(
    code_page: u32,
    flags: u32,
    bytes: *const u8,
    bytes_len: i32,
    out: *mut u16,
    out_len: i32,
) -> i32 {
    if bytes.is_null() || bytes_len == 0 || bytes_len < -1 || out_len < 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: the API's contract for the input.
    let bytes = unsafe { input(bytes, bytes_len) };
    let text = match code_page {
        CP_UTF8 => {
            if flags & !MB_ERR_INVALID_CHARS != 0 {
                set_last_error(ERROR_INVALID_FLAGS);
                return 0;
            }
            match std::str::from_utf8(bytes) {
                Ok(text) => text.to_string(),
                Err(_) if flags & MB_ERR_INVALID_CHARS != 0 => {
                    set_last_error(ERROR_NO_UNICODE_TRANSLATION);
                    return 0;
                }
                Err(_) => String::from_utf8_lossy(bytes).into_owned(),
            }
        }
        CP_ACP if bytes.is_ascii() => String::from_utf8(bytes.to_vec()).unwrap(),
        _ => {
            gap(format!(
                "MultiByteToWideChar code page {code_page} beyond ASCII"
            ));
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
    };
    let units: Vec<u16> = text.encode_utf16().collect();
    // SAFETY: the API's contract for the output.
    unsafe { output(&units, out, out_len) }
}

#[allow(non_snake_case)]
extern "stdcall" fn WideCharToMultiByte(
    code_page: u32,
    flags: u32,
    units: *const u16,
    units_len: i32,
    out: *mut u8,
    out_len: i32,
    default_char: *const u8,
    used_default: *mut i32,
) -> i32 {
    if units.is_null() || units_len == 0 || units_len < -1 || out_len < 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: the API's contract for the input.
    let units = unsafe { input(units, units_len) };
    let bytes = match code_page {
        CP_UTF8 => {
            if flags & !WC_ERR_INVALID_CHARS != 0 {
                set_last_error(ERROR_INVALID_FLAGS);
                return 0;
            }
            // Both must be NULL for CP_UTF8.
            if !default_char.is_null() || !used_default.is_null() {
                set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            }
            match String::from_utf16(units) {
                Ok(text) => text.into_bytes(),
                Err(_) if flags & WC_ERR_INVALID_CHARS != 0 => {
                    set_last_error(ERROR_NO_UNICODE_TRANSLATION);
                    return 0;
                }
                Err(_) => String::from_utf16_lossy(units).into_bytes(),
            }
        }
        CP_ACP if units.iter().all(|&u| u < 0x80) => {
            if !used_default.is_null() {
                // SAFETY: writable (the API's contract).
                unsafe { *used_default = 0 };
            }
            units.iter().map(|&u| u as u8).collect()
        }
        _ => {
            gap(format!(
                "WideCharToMultiByte code page {code_page} beyond ASCII"
            ));
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
    };
    // SAFETY: the API's contract for the output.
    unsafe { output(&bytes, out, out_len) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::{Attached, Runtime};

    /// Error paths call SetLastError, which needs a TEB.
    fn attached() -> (Runtime, Attached) {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let thread = runtime.attach().unwrap();
        (runtime, thread)
    }

    fn to_wide(cp: u32, flags: u32, bytes: &[u8], len: i32) -> Result<Vec<u16>, i32> {
        let n = MultiByteToWideChar(cp, flags, bytes.as_ptr(), len, std::ptr::null_mut(), 0);
        if n == 0 {
            return Err(0);
        }
        let mut out = vec![0u16; n as usize];
        assert_eq!(
            MultiByteToWideChar(cp, flags, bytes.as_ptr(), len, out.as_mut_ptr(), n),
            n
        );
        Ok(out)
    }

    fn to_bytes(cp: u32, flags: u32, units: &[u16], len: i32) -> Result<Vec<u8>, i32> {
        let none = std::ptr::null_mut();
        let n = WideCharToMultiByte(
            cp,
            flags,
            units.as_ptr(),
            len,
            none,
            0,
            std::ptr::null(),
            none.cast(),
        );
        if n == 0 {
            return Err(0);
        }
        let mut out = vec![0u8; n as usize];
        let written = WideCharToMultiByte(
            cp,
            flags,
            units.as_ptr(),
            len,
            out.as_mut_ptr(),
            n,
            std::ptr::null(),
            none.cast(),
        );
        assert_eq!(written, n);
        Ok(out)
    }

    #[test]
    fn utf8_round_trips_and_counts_the_nul() {
        let _process = attached();
        let w: Vec<u16> = "C:\\Wazuh \u{e9}\u{1f600}".encode_utf16().collect();
        let utf8 = "C:\\Wazuh \u{e9}\u{1f600}".as_bytes();
        assert_eq!(to_wide(CP_UTF8, 0, utf8, utf8.len() as i32).unwrap(), w);
        let mut with_nul = utf8.to_vec();
        with_nul.push(0);
        let mut w_nul = w.clone();
        w_nul.push(0);
        assert_eq!(to_wide(CP_UTF8, 0, &with_nul, -1).unwrap(), w_nul);
        assert_eq!(to_bytes(CP_UTF8, 0, &w_nul, -1).unwrap(), with_nul);
    }

    #[test]
    fn invalid_input_is_replaced_or_refused() {
        let _process = attached();
        assert_eq!(
            to_wide(CP_UTF8, 0, b"a\xffb", 3).unwrap(),
            [0x61, 0xfffd, 0x62]
        );
        assert!(to_wide(CP_UTF8, MB_ERR_INVALID_CHARS, b"a\xffb", 3).is_err());
        assert_eq!(
            to_bytes(CP_UTF8, 0, &[0xd800], 1).unwrap(),
            "\u{fffd}".as_bytes()
        );
        assert!(to_bytes(CP_UTF8, WC_ERR_INVALID_CHARS, &[0xd800], 1).is_err());
        assert!(
            to_wide(CP_UTF8, 0x1, b"a", 1).is_err(),
            "MB_PRECOMPOSED is not valid for UTF-8"
        );
    }

    #[test]
    fn short_buffers_fail() {
        let _process = attached();
        let mut out = [0u16; 2];
        assert_eq!(
            MultiByteToWideChar(CP_UTF8, 0, b"abc".as_ptr(), 3, out.as_mut_ptr(), 2),
            0
        );
        assert_eq!(
            MultiByteToWideChar(CP_UTF8, 0, b"abc".as_ptr(), 0, out.as_mut_ptr(), 2),
            0
        );
    }

    #[test]
    fn ansi_converts_ascii_and_logs_the_rest() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        assert_eq!(
            to_wide(CP_ACP, 0, b"ossec", 5).unwrap(),
            "ossec".encode_utf16().collect::<Vec<_>>()
        );
        assert_eq!(to_bytes(CP_ACP, 0, &[0x41, 0x42], 2).unwrap(), b"AB");
        assert!(to_wide(CP_ACP, 0, b"\xe9", 1).is_err());
        assert!(to_bytes(CP_ACP, 0, &[0xe9], 1).is_err());
        assert_eq!(runtime.lock().gaps().len(), 2);
    }
}
