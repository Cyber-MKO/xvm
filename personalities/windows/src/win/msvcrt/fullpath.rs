//! Absolute paths: `_fullpath`.
//!
//! The `_fullpath` page on Microsoft Learn: the result is the absolute
//! form of the path against the process's current directory. With a NULL
//! buffer it is allocated with `malloc` (at least 260 bytes, `_MAX_PATH`)
//! and the caller frees it; a buffer too small gives NULL and ERANGE.

use std::ffi::c_char;

use super::errno::{self, EINVAL, ENOMEM, ERANGE};
use crate::paths::DriveMap;
use crate::runtime::with_current;
use crate::win::text::ansi;

const MAX_PATH: usize = 260;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("_fullpath", _fullpath as *const () as u32)]
}

extern "C" fn _fullpath(out: *mut c_char, path: *const c_char, size: usize) -> *mut c_char {
    // SAFETY: NUL-terminated or NULL (the function's contract).
    let path = unsafe { ansi(path) }.filter(|p| !p.is_empty());
    let current = with_current(|p| p.params.current_directory.clone());
    let full = match path {
        None => current,
        Some(path) => match DriveMap::full_path(&path, &current) {
            Ok(full) => full,
            Err(_) => {
                errno::set(EINVAL);
                return std::ptr::null_mut();
            }
        },
    };
    let bytes = full.as_bytes();
    let (buffer, room) = if out.is_null() {
        let room = MAX_PATH.max(bytes.len() + 1);
        (super::heap::malloc(room).cast::<c_char>(), room)
    } else {
        (out, size)
    };
    if buffer.is_null() {
        errno::set(ENOMEM);
        return std::ptr::null_mut();
    }
    if bytes.len() + 1 > room {
        errno::set(ERANGE);
        return std::ptr::null_mut();
    }
    // SAFETY: buffer holds `room` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.cast::<u8>(), bytes.len());
        *buffer.add(bytes.len()) = 0;
    }
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use std::ffi::CStr;

    #[test]
    fn absolute_forms_in_the_callers_buffer_or_a_new_one() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        runtime.lock().params.current_directory = r"C:\Program Files (x86)\ossec-agent".into();
        let _thread = runtime.attach().unwrap();
        let mut buf = [0 as c_char; 64];
        let got = _fullpath(buf.as_mut_ptr(), c"queue\\..\\ossec.conf".as_ptr(), 64);
        // SAFETY: NUL-terminated on success.
        let text = unsafe { CStr::from_ptr(got) }.to_str().unwrap();
        assert_eq!(text, r"C:\Program Files (x86)\ossec-agent\ossec.conf");
        assert!(_fullpath(buf.as_mut_ptr(), c"a".as_ptr(), 8).is_null());
        assert_eq!(errno::get(), ERANGE);
        let new = _fullpath(std::ptr::null_mut(), c"\\x".as_ptr(), 0);
        // SAFETY: as above.
        assert_eq!(unsafe { CStr::from_ptr(new) }.to_str().unwrap(), r"C:\x");
    }
}
