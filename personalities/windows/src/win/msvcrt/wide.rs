//! Wide-string functions from the C standard, on 16-bit `wchar_t`.
//!
//! `msvcrt`'s `wchar_t` is a UTF-16 code unit, while host libc's is 32
//! bits, so these are written here rather than borrowed. Comparisons are
//! by code unit value, as the C standard specifies for these functions.

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("wcslen", wcslen as *const () as u32),
        ("wcscpy", wcscpy as *const () as u32),
        ("wcsncpy", wcsncpy as *const () as u32),
        ("wcscat", wcscat as *const () as u32),
        ("wcscmp", wcscmp as *const () as u32),
        ("wcsncmp", wcsncmp as *const () as u32),
        ("wcsrchr", wcsrchr as *const () as u32),
        ("wcsstr", wcsstr as *const () as u32),
    ]
}

// SAFETY (for every function below): the caller passes NUL-terminated
// strings and, for destinations, buffers large enough for the result, as
// each function's C contract requires.

extern "C" fn wcslen(s: *const u16) -> usize {
    let mut n = 0;
    // SAFETY: see above.
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

extern "C" fn wcscpy(dst: *mut u16, src: *const u16) -> *mut u16 {
    // SAFETY: see above; the NUL is copied too.
    unsafe { std::ptr::copy(src, dst, wcslen(src) + 1) };
    dst
}

/// Copies at most `n` units and pads with NULs to `n`; no NUL is added if
/// `src` is `n` units or longer.
extern "C" fn wcsncpy(dst: *mut u16, src: *const u16, n: usize) -> *mut u16 {
    let mut i = 0;
    // SAFETY: see above; dst holds n units.
    unsafe {
        while i < n && *src.add(i) != 0 {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
        while i < n {
            *dst.add(i) = 0;
            i += 1;
        }
    }
    dst
}

extern "C" fn wcscat(dst: *mut u16, src: *const u16) -> *mut u16 {
    // SAFETY: see above.
    wcscpy(unsafe { dst.add(wcslen(dst)) }, src);
    dst
}

extern "C" fn wcsncmp(a: *const u16, b: *const u16, n: usize) -> i32 {
    for i in 0..n {
        // SAFETY: see above; stops at the first NUL or difference.
        let (x, y) = unsafe { (*a.add(i), *b.add(i)) };
        if x != y {
            return if x < y { -1 } else { 1 };
        }
        if x == 0 {
            return 0;
        }
    }
    0
}

extern "C" fn wcscmp(a: *const u16, b: *const u16) -> i32 {
    wcsncmp(a, b, usize::MAX)
}

/// The last occurrence of `c`; searching for NUL finds the terminator.
extern "C" fn wcsrchr(s: *const u16, c: u16) -> *mut u16 {
    let len = wcslen(s);
    // SAFETY: see above; len + 1 units are readable.
    let units = unsafe { std::slice::from_raw_parts(s, len + 1) };
    match units.iter().rposition(|&u| u == c) {
        // SAFETY: inside the string.
        Some(i) => unsafe { s.add(i) }.cast_mut(),
        None => std::ptr::null_mut(),
    }
}

/// The first occurrence of `find` in `s`; an empty `find` matches at `s`.
extern "C" fn wcsstr(s: *const u16, find: *const u16) -> *mut u16 {
    // SAFETY: see above.
    let (hay, needle) = unsafe {
        (
            std::slice::from_raw_parts(s, wcslen(s)),
            std::slice::from_raw_parts(find, wcslen(find)),
        )
    };
    if needle.is_empty() {
        return s.cast_mut();
    }
    match hay.windows(needle.len()).position(|w| w == needle) {
        // SAFETY: inside the string.
        Some(i) => unsafe { s.add(i) }.cast_mut(),
        None => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    fn text(p: *const u16) -> String {
        // SAFETY: tests pass NUL-terminated strings.
        String::from_utf16(unsafe { std::slice::from_raw_parts(p, wcslen(p)) }).unwrap()
    }

    #[test]
    fn length_copy_and_concatenate() {
        assert_eq!(wcslen(w("C:\\Windows").as_ptr()), 10);
        assert_eq!(wcslen(w("").as_ptr()), 0);
        let mut buf = [0xffffu16; 32];
        wcscpy(buf.as_mut_ptr(), w("ossec").as_ptr());
        wcscat(buf.as_mut_ptr(), w("-agent").as_ptr());
        assert_eq!(text(buf.as_ptr()), "ossec-agent");

        let mut small = [0xffffu16; 6];
        wcsncpy(small.as_mut_ptr(), w("ab").as_ptr(), 4);
        assert_eq!(small, [b'a' as u16, b'b' as u16, 0, 0, 0xffff, 0xffff]);
        wcsncpy(small.as_mut_ptr(), w("abcdef").as_ptr(), 3);
        assert_eq!(&small[..4], &[b'a' as u16, b'b' as u16, b'c' as u16, 0]);
    }

    #[test]
    fn compare_and_search() {
        assert_eq!(wcscmp(w("abc").as_ptr(), w("abc").as_ptr()), 0);
        assert!(wcscmp(w("abc").as_ptr(), w("abd").as_ptr()) < 0);
        assert!(wcscmp(w("abc").as_ptr(), w("ab").as_ptr()) > 0);
        assert_eq!(
            wcsncmp(w("agent.exe").as_ptr(), w("agent.dll").as_ptr(), 6),
            0
        );
        // Code unit order: U+00E9 sorts after 'z'.
        assert!(wcscmp(w("\u{e9}").as_ptr(), w("z").as_ptr()) > 0);

        let path = w(r"C:\a\b.dll");
        assert_eq!(text(wcsrchr(path.as_ptr(), b'\\' as u16)), r"\b.dll");
        assert!(wcsrchr(path.as_ptr(), b'z' as u16).is_null());
        assert_eq!(wcslen(wcsrchr(path.as_ptr(), 0)), 0);
        assert_eq!(text(wcsstr(path.as_ptr(), w("b.").as_ptr())), "b.dll");
        assert!(wcsstr(path.as_ptr(), w("zz").as_ptr()).is_null());
        assert_eq!(
            wcsstr(path.as_ptr(), w("").as_ptr()),
            path.as_ptr().cast_mut()
        );
    }
}
