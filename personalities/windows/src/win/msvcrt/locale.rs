//! Locales: `setlocale`, `localeconv`, and collation: `strcoll`,
//! `wcscoll`, `strxfrm`, `wcsxfrm`.
//!
//! A program starts in the "C" locale (setlocale documentation), and only
//! "C" is implemented: queries return "C", and setting "C" succeeds. Any
//! other locale, including "" (the user's default, a host fact for the
//! profile), fails with NULL as documented for an unknown locale, and is
//! logged as a gap.
//!
//! `localeconv` returns the "C" locale's numeric formatting, as the C
//! standard defines it: "." as the decimal point, empty strings, and
//! CHAR_MAX for the numeric fields.
//!
//! In the "C" locale, collation is the order of the code units, so
//! `strcoll` and `wcscoll` compare as `strcmp` and `wcscmp` do, and the
//! transformed string of `strxfrm` and `wcsxfrm` is the string itself.
//! Following the strxfrm page on Microsoft Learn, they return its length
//! and store it, with its NUL, only when it fits in `count`.

use std::ffi::c_char;

use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::win::text::ansi;

/// LC_ALL to LC_TIME (locale.h): 0 to 5.
const LC_MAX: i32 = 5;

static C_LOCALE: &std::ffi::CStr = c"C";

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("setlocale", setlocale as *const () as u32),
        ("localeconv", localeconv as *const () as u32),
        ("strcoll", strcoll as *const () as u32),
        ("wcscoll", wcscoll as *const () as u32),
        ("strxfrm", strxfrm as *const () as u32),
        ("wcsxfrm", wcsxfrm as *const () as u32),
    ]
}

/// msvcrt's `struct lconv` (locale.h): ten string pointers, then eight
/// `char` fields.
#[repr(C)]
pub(super) struct Lconv {
    strings: [*const c_char; 10],
    numbers: [i8; 8],
}

/// Holds raw pointers to static strings only.
struct Shared(Lconv);
// SAFETY: the struct is never written and points at static strings.
unsafe impl Sync for Shared {}

/// CHAR_MAX for a signed `char`: "not available" in the C locale.
const CHAR_MAX: i8 = 127;

static C_LCONV: Shared = Shared(Lconv {
    strings: [
        c".".as_ptr(),
        c"".as_ptr(),
        c"".as_ptr(),
        c"".as_ptr(),
        c"".as_ptr(),
        c"".as_ptr(),
        c"".as_ptr(),
        c"".as_ptr(),
        c"".as_ptr(),
        c"".as_ptr(),
    ],
    numbers: [CHAR_MAX; 8],
});

/// The current locale's numeric formatting: always the "C" locale's.
extern "C" fn localeconv() -> *const Lconv {
    &C_LCONV.0
}

extern "C" fn setlocale(category: i32, locale: *const c_char) -> *const c_char {
    if !(0..=LC_MAX).contains(&category) {
        return std::ptr::null();
    }
    // SAFETY: NULL or a NUL-terminated string (the function's contract).
    match unsafe { ansi(locale) } {
        None => C_LOCALE.as_ptr(),
        Some(name) if name == "C" => C_LOCALE.as_ptr(),
        Some(name) => {
            with_current(|p| {
                p.record_runtime_gap(
                    GapKind::Feature,
                    "msvcrt.dll",
                    &format!("setlocale to {name:?}"),
                )
            });
            std::ptr::null()
        }
    }
}

/// The units of a NUL-terminated string, without the NUL.
///
/// # Safety
///
/// `p` must point at a NUL-terminated string of `T`.
unsafe fn units<'a, T: Copy + Default + PartialEq>(p: *const T) -> &'a [T] {
    let mut len = 0;
    // SAFETY: the caller's contract.
    while unsafe { *p.add(len) } != T::default() {
        len += 1;
    }
    // SAFETY: `len` units before the NUL.
    unsafe { std::slice::from_raw_parts(p, len) }
}

fn sign(o: std::cmp::Ordering) -> i32 {
    o as i32
}

extern "C" fn strcoll(a: *const u8, b: *const u8) -> i32 {
    // SAFETY: NUL-terminated strings (the function's contract).
    sign(unsafe { units(a).cmp(units(b)) })
}

extern "C" fn wcscoll(a: *const u16, b: *const u16) -> i32 {
    // SAFETY: NUL-terminated strings (the function's contract).
    sign(unsafe { units(a).cmp(units(b)) })
}

/// Copies `src` and its NUL to `dest` when they fit in `count` units.
/// Returns the length of `src`.
///
/// # Safety
///
/// `src` must be NUL-terminated; `dest` must hold `count` units.
unsafe fn transform<T: Copy + Default + PartialEq>(
    dest: *mut T,
    src: *const T,
    count: usize,
) -> usize {
    // SAFETY: the caller's contract.
    let s = unsafe { units(src) };
    if s.len() < count && !dest.is_null() {
        // SAFETY: as above; s.len() + 1 <= count.
        unsafe {
            std::ptr::copy(s.as_ptr(), dest, s.len());
            *dest.add(s.len()) = T::default();
        }
    }
    s.len()
}

extern "C" fn strxfrm(dest: *mut u8, src: *const u8, count: usize) -> usize {
    // SAFETY: the function's contract.
    unsafe { transform(dest, src, count) }
}

extern "C" fn wcsxfrm(dest: *mut u16, src: *const u16, count: usize) -> usize {
    // SAFETY: the function's contract.
    unsafe { transform(dest, src, count) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    fn text(p: *const c_char) -> &'static str {
        // SAFETY: setlocale returns a static NUL-terminated string.
        unsafe { std::ffi::CStr::from_ptr(p) }.to_str().unwrap()
    }

    #[test]
    fn only_the_c_locale_exists() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        assert_eq!(text(setlocale(2, std::ptr::null())), "C");
        assert_eq!(text(setlocale(0, c"C".as_ptr())), "C");
        assert!(setlocale(6, std::ptr::null()).is_null());
        assert!(setlocale(0, c"".as_ptr()).is_null());
        assert!(setlocale(2, c"English_United States.1252".as_ptr()).is_null());
        assert_eq!(runtime.lock().gaps().len(), 2);
        assert_eq!(text(setlocale(0, std::ptr::null())), "C");
    }

    #[test]
    fn collation_in_the_c_locale_is_code_unit_order() {
        assert_eq!(strcoll(c"abc".as_ptr().cast(), c"abd".as_ptr().cast()), -1);
        assert_eq!(
            strcoll(c"B".as_ptr().cast(), c"a".as_ptr().cast()),
            -1,
            "not by case"
        );
        assert_eq!(strcoll(c"x".as_ptr().cast(), c"x".as_ptr().cast()), 0);
        let (a, b): (Vec<u16>, Vec<u16>) = (
            "\u{e9}\0".encode_utf16().collect(),
            "f\0".encode_utf16().collect(),
        );
        assert_eq!(wcscoll(a.as_ptr(), b.as_ptr()), 1);
        let mut buf = [0xffu8; 8];
        assert_eq!(strxfrm(buf.as_mut_ptr(), c"hello".as_ptr().cast(), 8), 5);
        assert_eq!(&buf[..6], b"hello\0");
        let mut small = [0xffu8; 4];
        assert_eq!(strxfrm(small.as_mut_ptr(), c"hello".as_ptr().cast(), 4), 5);
        assert_eq!(small, [0xff; 4], "untouched when it does not fit");
        assert_eq!(strxfrm(std::ptr::null_mut(), c"hi".as_ptr().cast(), 0), 2);
        let mut wide = [0u16; 4];
        assert_eq!(wcsxfrm(wide.as_mut_ptr(), b.as_ptr(), 4), 1);
        assert_eq!(wide[..2], [u16::from(b'f'), 0]);
    }

    #[test]
    fn localeconv_reports_the_c_locale() {
        // SAFETY: localeconv returns a pointer to a static struct.
        let l = unsafe { &*localeconv() };
        assert_eq!(text(l.strings[0]), ".");
        assert!(l.strings[1..].iter().all(|&s| text(s).is_empty()));
        assert_eq!(l.numbers, [CHAR_MAX; 8]);
        if cfg!(target_pointer_width = "32") {
            assert_eq!(std::mem::size_of::<Lconv>(), 48);
        }
    }
}
