//! Microsoft string extensions: `_strdup`, `_stricmp`, `_strnicmp`.
//!
//! Case-insensitive comparisons fold ASCII letters to lower case, as the
//! "C" locale does, and compare as unsigned bytes.

use std::ffi::c_char;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("_strdup", _strdup as *const () as u32),
        ("_stricmp", _stricmp as *const () as u32),
        ("_strnicmp", _strnicmp as *const () as u32),
    ]
}

/// A `malloc` copy, freed with `free`; NULL for NULL.
extern "C" fn _strdup(s: *const c_char) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: a NUL-terminated string; plain allocation.
    unsafe {
        let len = libc::strlen(s) + 1;
        let copy = libc::malloc(len).cast::<c_char>();
        if !copy.is_null() {
            std::ptr::copy_nonoverlapping(s, copy, len);
        }
        copy
    }
}

extern "C" fn _strnicmp(a: *const c_char, b: *const c_char, n: usize) -> i32 {
    for i in 0..n {
        // SAFETY: NUL-terminated strings; stops at the first NUL or
        // difference.
        let (x, y) = unsafe { (*a.add(i) as u8, *b.add(i) as u8) };
        let (x, y) = (x.to_ascii_lowercase(), y.to_ascii_lowercase());
        if x != y {
            return x as i32 - y as i32;
        }
        if x == 0 {
            return 0;
        }
    }
    0
}

extern "C" fn _stricmp(a: *const c_char, b: *const c_char) -> i32 {
    _strnicmp(a, b, usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_and_compares_ignoring_case() {
        let copy = _strdup(c"OSSEC".as_ptr());
        // SAFETY: _strdup returns a NUL-terminated malloc copy.
        unsafe {
            assert_eq!(std::ffi::CStr::from_ptr(copy).to_str().unwrap(), "OSSEC");
            libc::free(copy.cast());
        }
        assert!(_strdup(std::ptr::null()).is_null());
        assert_eq!(_stricmp(c"Agent.EXE".as_ptr(), c"agent.exe".as_ptr()), 0);
        assert!(_stricmp(c"a".as_ptr(), c"B".as_ptr()) < 0);
        assert!(_stricmp(c"ab".as_ptr(), c"A".as_ptr()) > 0);
        assert_eq!(
            _strnicmp(c"LOCALFILE x".as_ptr(), c"localfile y".as_ptr(), 9),
            0
        );
        assert!(
            _strnicmp(c"[".as_ptr(), c"a".as_ptr(), 1) < 0,
            "lower-case folding"
        );
    }
}
