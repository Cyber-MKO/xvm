//! Path helpers: `PathIsUNCA`.

use std::ffi::c_char;

use crate::win::text::ansi;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("PathIsUNCA", PathIsUNCA as *const () as u32)]
}

/// TRUE for a path that starts with two backslashes, except the `\\?\`
/// prefix, which is UNC only as `\\?\UNC\`. These are the cases on the
/// PathIsUNC page on Microsoft Learn.
fn is_unc(path: &str) -> bool {
    match path.strip_prefix(r"\\?\") {
        Some(rest) => rest
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case(r"UNC\")),
        None => path.starts_with(r"\\"),
    }
}

#[allow(non_snake_case)]
extern "stdcall" fn PathIsUNCA(path: *const c_char) -> i32 {
    // SAFETY: NULL or a NUL-terminated string (the API's contract).
    unsafe { ansi(path) }.is_some_and(|p| is_unc(&p)) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_documented_examples() {
        assert_eq!(PathIsUNCA(c"\\\\path1\\path2".as_ptr()), 1);
        assert_eq!(PathIsUNCA(c"\\\\path1".as_ptr()), 1);
        assert_eq!(PathIsUNCA(c"acme\\\\path4\\\\path5".as_ptr()), 0);
        assert_eq!(PathIsUNCA(c"\\\\?\\UNC\\path1\\path2".as_ptr()), 1);
        assert_eq!(PathIsUNCA(c"\\\\?\\c:\\path".as_ptr()), 0);
        assert_eq!(PathIsUNCA(c"C:\\Program Files".as_ptr()), 0);
        assert_eq!(PathIsUNCA(std::ptr::null()), 0);
    }
}
