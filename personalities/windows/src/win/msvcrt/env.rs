//! The C environment: `getenv`.
//!
//! The CRT's environment is the `envp` that `__getmainargs` gives, built
//! from the host profile's variables. Following the getenv page on
//! Microsoft Learn, names match without regard to case, and the result
//! points into that environment, so it stays valid.

use std::ffi::{CStr, c_char};

use super::startup::main_args_of;
use crate::runtime::with_current;
use crate::win::text::ansi;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("getenv", getenv as *const () as u32)]
}

/// The value of `name`, or NULL when it is not set.
extern "C" fn getenv(name: *const c_char) -> *const c_char {
    // SAFETY: NULL or a NUL-terminated string (the function's contract).
    let Some(name) = (unsafe { ansi(name) }) else {
        return std::ptr::null();
    };
    if name.is_empty() || name.contains('=') {
        return std::ptr::null();
    }
    with_current(|p| {
        let args = main_args_of(p);
        for &entry in args.envp.iter().take_while(|e| !e.is_null()) {
            // SAFETY: envp holds NUL-terminated strings the CRT owns.
            let bytes = unsafe { CStr::from_ptr(entry) }.to_bytes();
            let Some(eq) = bytes.iter().position(|&b| b == b'=') else {
                continue;
            };
            if bytes[..eq].eq_ignore_ascii_case(name.as_bytes()) {
                // SAFETY: inside the same string, after the '='.
                return unsafe { entry.add(eq + 1) }.cast_const();
            }
        }
        std::ptr::null()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn getenv_matches_names_without_case() {
        let mut process = Process::new(Vec::new());
        process.params.environment = vec!["Path=C:\\Windows".into(), "EMPTY=".into()];
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        // SAFETY: getenv returns a NUL-terminated string.
        let value = |p: *const c_char| unsafe { CStr::from_ptr(p) }.to_str().unwrap();
        let path = getenv(c"PATH".as_ptr());
        assert_eq!(value(path), "C:\\Windows");
        assert_eq!(getenv(c"path".as_ptr()), path, "the same storage");
        assert_eq!(value(getenv(c"EMPTY".as_ptr())), "");
        assert!(getenv(c"TEMP".as_ptr()).is_null());
        assert!(getenv(c"Pa=th".as_ptr()).is_null());
        assert!(getenv(std::ptr::null()).is_null());
    }
}
