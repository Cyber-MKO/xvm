//! Code page conversion: `MultiByteToWideChar`, `WideCharToMultiByte`.
//!
//! Following the two functions' pages on Microsoft Learn:
//!
//! | Code page | Conversion |
//! | --- | --- |
//! | `CP_UTF8` | Invalid input becomes U+FFFD unless the caller asks for an error |
//! | `CP_ACP`, `CP_THREAD_ACP`, `CP_OEMCP` | The profile's code pages, through `crate::codepage` |
//! | A number we have a table for | That table |
//!
//! Single-byte conversion writes the code page's default character (or
//! the caller's) for characters it lacks, using best fit unless the
//! caller passes `WC_NO_BEST_FIT_CHARS`. Composition flags, glyph
//! characters and other code pages are logged gaps.

use super::error::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, set_last_error};
use crate::codepage::{self, SingleByte};
use crate::gap::GapKind;
use crate::runtime::with_current;

const CP_ACP: u32 = 0;
const CP_OEMCP: u32 = 1;
const CP_THREAD_ACP: u32 = 3;
const CP_UTF8: u32 = 65001;
const MB_PRECOMPOSED: u32 = 0x1;
const MB_COMPOSITE: u32 = 0x2;
const MB_USEGLYPHCHARS: u32 = 0x4;
const MB_ERR_INVALID_CHARS: u32 = 0x8;
const WC_DISCARDNS: u32 = 0x10;
const WC_SEPCHARS: u32 = 0x20;
const WC_DEFAULTCHAR: u32 = 0x40;
const WC_ERR_INVALID_CHARS: u32 = 0x80;
const WC_COMPOSITECHECK: u32 = 0x200;
const WC_NO_BEST_FIT_CHARS: u32 = 0x400;

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

/// The table for `code_page`, resolving the process's ANSI and OEM code
/// pages. None (a logged gap) if we have none.
fn table(function: &str, code_page: u32) -> Option<&'static SingleByte> {
    let pages = with_current(|p| p.params.code_pages);
    let number = match code_page {
        CP_ACP | CP_THREAD_ACP => pages.ansi,
        CP_OEMCP => pages.oem,
        n => u16::try_from(n).unwrap_or(0),
    };
    let found = codepage::single_byte(number);
    if found.is_none() {
        gap(format!("{function} code page {code_page}"));
    }
    found
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
        _ => {
            let Some(table) = table("MultiByteToWideChar", code_page) else {
                set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            };
            let known = MB_PRECOMPOSED | MB_COMPOSITE | MB_USEGLYPHCHARS | MB_ERR_INVALID_CHARS;
            if flags & !known != 0
                || flags & (MB_PRECOMPOSED | MB_COMPOSITE) == MB_PRECOMPOSED | MB_COMPOSITE
            {
                set_last_error(ERROR_INVALID_FLAGS);
                return 0;
            }
            if flags & (MB_COMPOSITE | MB_USEGLYPHCHARS) != 0 {
                gap(format!("MultiByteToWideChar flags {flags:#x}"));
                set_last_error(ERROR_INVALID_FLAGS);
                return 0;
            }
            let Some(units) = table.decode(bytes, flags & MB_ERR_INVALID_CHARS != 0) else {
                set_last_error(ERROR_NO_UNICODE_TRANSLATION);
                return 0;
            };
            // SAFETY: the API's contract for the output.
            return unsafe { output(&units, out, out_len) };
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
        _ => {
            let Some(table) = table("WideCharToMultiByte", code_page) else {
                set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            };
            let known = WC_DISCARDNS
                | WC_SEPCHARS
                | WC_DEFAULTCHAR
                | WC_COMPOSITECHECK
                | WC_NO_BEST_FIT_CHARS;
            if flags & !known != 0 {
                set_last_error(ERROR_INVALID_FLAGS);
                return 0;
            }
            if flags & (WC_COMPOSITECHECK | WC_DISCARDNS | WC_SEPCHARS | WC_DEFAULTCHAR) != 0 {
                gap(format!("WideCharToMultiByte flags {flags:#x}"));
                set_last_error(ERROR_INVALID_FLAGS);
                return 0;
            }
            let default = if default_char.is_null() {
                table.default_byte
            } else {
                // SAFETY: points at the default character (the API's contract).
                unsafe { *default_char }
            };
            let (bytes, defaulted) =
                table.encode(units, flags & WC_NO_BEST_FIT_CHARS == 0, default);
            if !used_default.is_null() {
                // SAFETY: writable (the API's contract).
                unsafe { *used_default = defaulted as i32 };
            }
            bytes
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
    fn ansi_and_oem_follow_the_profile() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        // The defaults for a process without a profile: 1252 and 437.
        assert_eq!(
            to_wide(CP_ACP, 0, b"caf\xe9 \x80", 6).unwrap(),
            "caf\u{e9} \u{20ac}".encode_utf16().collect::<Vec<_>>()
        );
        assert_eq!(to_wide(CP_OEMCP, 0, b"\x82", 1).unwrap(), [0xe9]);
        assert_eq!(to_wide(437, MB_PRECOMPOSED, b"\x82", 1).unwrap(), [0xe9]);
        assert_eq!(
            to_bytes(CP_THREAD_ACP, 0, &[0xe9, 0x20ac], 2).unwrap(),
            [0xe9, 0x80]
        );
        assert_eq!(to_bytes(CP_OEMCP, 0, &[0xe9], 1).unwrap(), [0x82]);
        runtime.lock().params.code_pages.ansi = 437;
        assert_eq!(to_bytes(CP_ACP, 0, &[0xe9], 1).unwrap(), [0x82]);
        assert!(runtime.lock().gaps().is_empty());
    }

    #[test]
    fn default_characters_and_best_fit() {
        let _process = attached();
        let convert = |flags: u32, units: &[u16], default: Option<u8>| {
            let mut out = [0u8; 8];
            let mut used = -1;
            let default = default.map(|d| [d]);
            let n = WideCharToMultiByte(
                CP_ACP,
                flags,
                units.as_ptr(),
                units.len() as i32,
                out.as_mut_ptr(),
                8,
                default.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
                &mut used,
            );
            (out[..n as usize].to_vec(), used)
        };
        assert_eq!(convert(0, &[0x221e, 0x41], None), (b"8A".to_vec(), 0));
        assert_eq!(
            convert(WC_NO_BEST_FIT_CHARS, &[0x221e], None),
            (b"?".to_vec(), 1)
        );
        assert_eq!(convert(0, &[0x4e00], Some(b'#')), (b"#".to_vec(), 1));
    }

    #[test]
    fn unsupported_code_pages_and_flags_fail() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        assert!(to_wide(932, 0, b"a", 1).is_err());
        assert!(to_bytes(65000, 0, &[0x41], 1).is_err());
        assert!(to_wide(CP_ACP, MB_COMPOSITE, b"a", 1).is_err());
        assert!(to_wide(CP_ACP, MB_PRECOMPOSED | MB_COMPOSITE, b"a", 1).is_err());
        assert!(to_bytes(CP_ACP, WC_ERR_INVALID_CHARS, &[0x41], 1).is_err());
        assert!(to_bytes(CP_ACP, WC_COMPOSITECHECK, &[0x41], 1).is_err());
        let gaps: Vec<String> = runtime
            .lock()
            .gaps()
            .iter()
            .map(|g| g.symbol.clone())
            .collect();
        assert_eq!(
            gaps,
            [
                "MultiByteToWideChar code page 932",
                "WideCharToMultiByte code page 65000",
                "MultiByteToWideChar flags 0x2",
                "WideCharToMultiByte flags 0x200",
            ]
        );
    }
}
