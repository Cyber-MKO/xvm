//! Locales: `setlocale`, `localeconv`.
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
