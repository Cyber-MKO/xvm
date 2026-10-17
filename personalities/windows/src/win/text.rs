//! Strings passed in by agent code.

use std::ffi::{CStr, c_char};

/// An ANSI string. Until code pages exist (with `GetACP`), bytes outside
/// ASCII are replaced.
///
/// # Safety
///
/// `p` must be NULL or point at a NUL-terminated string.
pub unsafe fn ansi(p: *const c_char) -> Option<String> {
    // SAFETY: the caller's contract.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

/// A UTF-16 string.
///
/// # Safety
///
/// `p` must be NULL or point at a NUL-terminated UTF-16 string.
pub unsafe fn wide(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0;
    // SAFETY: the string is NUL-terminated, so every read up to it is valid.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: len units were just read.
    Some(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(p, len)
    }))
}
