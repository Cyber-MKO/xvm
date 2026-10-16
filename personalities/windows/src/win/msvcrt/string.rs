//! Byte-string and memory functions from the C standard.
//!
//! Their behaviour is fixed by the C standard and does not depend on the
//! locale, so `msvcrt` and host libc agree. Each one calls libc.

use std::ffi::{c_char, c_int, c_void};

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("strlen", strlen as *const () as u32),
        ("memcpy", memcpy as *const () as u32),
        ("memmove", memmove as *const () as u32),
        ("memset", memset as *const () as u32),
        ("memcmp", memcmp as *const () as u32),
        ("memchr", memchr as *const () as u32),
        ("strcmp", strcmp as *const () as u32),
        ("strncmp", strncmp as *const () as u32),
        ("strcpy", strcpy as *const () as u32),
        ("strncpy", strncpy as *const () as u32),
        ("strcat", strcat as *const () as u32),
        ("strncat", strncat as *const () as u32),
        ("strchr", strchr as *const () as u32),
        ("strrchr", strrchr as *const () as u32),
        ("strstr", strstr as *const () as u32),
        ("strspn", strspn as *const () as u32),
        ("strcspn", strcspn as *const () as u32),
        ("strpbrk", strpbrk as *const () as u32),
    ]
}

extern "C" fn strlen(s: *const c_char) -> usize {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::strlen(s) }
}

extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::memcpy(dst, src, n) }
}

extern "C" fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::memmove(dst, src, n) }
}

extern "C" fn memset(dst: *mut c_void, c: c_int, n: usize) -> *mut c_void {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::memset(dst, c, n) }
}

extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::memcmp(a, b, n) }
}

extern "C" fn memchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::memchr(s, c, n) }
}

extern "C" fn strcmp(a: *const c_char, b: *const c_char) -> c_int {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::strcmp(a, b) }
}

extern "C" fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::strncmp(a, b, n) }
}

extern "C" fn strcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::strcpy(dst, src) }
}

extern "C" fn strncpy(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::strncpy(dst, src, n) }
}

extern "C" fn strcat(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::strcat(dst, src) }
}

extern "C" fn strncat(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::strncat(dst, src, n) }
}

extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::strchr(s, c) }
}

extern "C" fn strrchr(s: *const c_char, c: c_int) -> *mut c_char {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::strrchr(s, c) }
}

extern "C" fn strstr(s: *const c_char, find: *const c_char) -> *mut c_char {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::strstr(s, find) }
}

extern "C" fn strspn(s: *const c_char, set: *const c_char) -> usize {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::strspn(s, set) }
}

extern "C" fn strcspn(s: *const c_char, set: *const c_char) -> usize {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::strcspn(s, set) }
}

extern "C" fn strpbrk(s: *const c_char, set: *const c_char) -> *mut c_char {
    // SAFETY: same contract as the C function; the caller passes valid
    // pointers and sizes.
    unsafe { libc::strpbrk(s, set) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn c(s: &CStr) -> *const c_char {
        s.as_ptr()
    }

    fn text(p: *const c_char) -> String {
        // SAFETY: tests only pass NUL-terminated strings.
        unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string()
    }

    #[test]
    fn length_compare_and_search() {
        assert_eq!(strlen(c(c"wazuh")), 5);
        assert!(strcmp(c(c"a"), c(c"b")) < 0);
        assert_eq!(strncmp(c(c"agent.exe"), c(c"agent.dll"), 6), 0);
        assert_eq!(text(strchr(c(c"a=b=c"), b'=' as c_int)), "=b=c");
        assert_eq!(text(strrchr(c(c"a=b=c"), b'=' as c_int)), "=c");
        assert!(strchr(c(c"abc"), b'z' as c_int).is_null());
        assert_eq!(
            text(strstr(c(c"C:\\Program Files"), c(c"Program"))),
            "Program Files"
        );
        assert_eq!(strspn(c(c"123abc"), c(c"0123456789")), 3);
        assert_eq!(strcspn(c(c"key=value"), c(c"=")), 3);
        assert_eq!(text(strpbrk(c(c"a b,c"), c(c" ,"))), " b,c");
    }

    #[test]
    fn copy_and_concatenate() {
        let mut buf = [0 as c_char; 32];
        let b = buf.as_mut_ptr();
        assert_eq!(strcpy(b, c(c"ossec")), b);
        strcat(b, c(c"-agent"));
        assert_eq!(text(b), "ossec-agent");
        strncat(b, c(c".exe.bak"), 4);
        assert_eq!(text(b), "ossec-agent.exe");
        let mut small = [1 as c_char; 8];
        strncpy(small.as_mut_ptr(), c(c"ab"), 5);
        assert_eq!(small, [b'a' as c_char, b'b' as c_char, 0, 0, 0, 1, 1, 1]);
    }

    #[test]
    fn memory_functions() {
        let mut a = [0u8; 8];
        memset(a.as_mut_ptr().cast(), 7, 4);
        assert_eq!(a, [7, 7, 7, 7, 0, 0, 0, 0]);
        let src = [1u8, 2, 3, 4];
        memcpy(a.as_mut_ptr().cast(), src.as_ptr().cast(), 4);
        assert_eq!(&a[..4], &src);
        // Overlapping move to the right.
        memmove(a.as_mut_ptr().add_one().cast(), a.as_ptr().cast(), 4);
        assert_eq!(&a[..5], &[1, 1, 2, 3, 4]);
        assert_eq!(memcmp(a.as_ptr().cast(), [1u8, 1].as_ptr().cast(), 2), 0);
        let found = memchr(a.as_ptr().cast(), 3, 8);
        assert_eq!(found as usize - a.as_ptr() as usize, 3);
    }

    trait AddOne {
        fn add_one(self) -> Self;
    }

    impl AddOne for *mut u8 {
        fn add_one(self) -> Self {
            // SAFETY: tests stay inside their buffers.
            unsafe { self.add(1) }
        }
    }
}
