//! Directories: `_chdir`.
//!
//! The current directory is a Windows path kept on the process
//! (`ProcessParams::current_directory`). It never changes the host
//! process's directory.

use std::ffi::c_char;

use super::errno::{self, EINVAL, ENOENT, ENOMEM, ENOTDIR, ERANGE};
use crate::paths::DriveMap;
use crate::runtime::with_current;
use crate::win::text::ansi;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("_chdir", _chdir as *const () as u32),
        ("_getcwd", _getcwd as *const () as u32),
    ]
}

/// Copies the current directory into `buffer`. With a NULL `buffer`,
/// allocates at least `max_len` bytes with `malloc` (more if the path needs
/// it); the caller frees it. Returns the buffer, or NULL with `errno` set
/// to ERANGE if `max_len` is too small for the path and its NUL.
extern "C" fn _getcwd(buffer: *mut c_char, max_len: i32) -> *mut c_char {
    let cwd = with_current(|p| p.params.current_directory.clone());
    let needed = cwd.len() + 1;
    let out = if buffer.is_null() {
        let size = needed.max(max_len.max(0) as usize);
        // SAFETY: plain allocation, freed by the caller with free().
        let out = unsafe { libc::malloc(size) }.cast::<c_char>();
        if out.is_null() {
            errno::set(ENOMEM);
            return out;
        }
        out
    } else if max_len < 0 || (max_len as usize) < needed {
        errno::set(ERANGE);
        return std::ptr::null_mut();
    } else {
        buffer
    };
    // SAFETY: out holds at least `needed` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(cwd.as_ptr().cast(), out, cwd.len());
        *out.add(cwd.len()) = 0;
    }
    out
}

/// Changes the current directory. Returns 0, or -1 with `errno` set to
/// ENOENT if the path does not name a directory.
extern "C" fn _chdir(path: *const c_char) -> i32 {
    // SAFETY: NULL or a NUL-terminated string (the function's contract).
    let Some(path) = (unsafe { ansi(path) }) else {
        errno::set(EINVAL);
        return -1;
    };
    with_current(|p| {
        let params = &mut p.params;
        let full = match DriveMap::full_path(&path, &params.current_directory) {
            Ok(full) => full,
            Err(_) => {
                errno::set(ENOENT);
                return -1;
            }
        };
        match params.drives.to_host(&full, &params.current_directory) {
            Ok(host) if host.is_dir() => {
                params.current_directory = full;
                0
            }
            Ok(host) if host.exists() => {
                errno::set(ENOTDIR);
                -1
            }
            _ => {
                errno::set(ENOENT);
                -1
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use std::collections::BTreeMap;

    #[test]
    fn changes_only_to_existing_directories() {
        let root = std::env::temp_dir().join(format!("xvm-chdir-{}", std::process::id()));
        let c = root.join("c");
        std::fs::create_dir_all(c.join("Program Files (x86)/ossec-agent")).unwrap();
        std::fs::write(c.join("file.txt"), "").unwrap();
        let mut process = Process::new(Vec::new());
        process.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), c)]));
        process.params.current_directory = r"C:\".into();
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();

        assert_eq!(_chdir(c"c:\\program files (x86)\\OSSEC-AGENT".as_ptr()), 0);
        assert_eq!(
            runtime.lock().params.current_directory,
            r"C:\program files (x86)\OSSEC-AGENT"
        );
        assert_eq!(_chdir(c"..".as_ptr()), 0);
        assert_eq!(
            runtime.lock().params.current_directory,
            r"C:\program files (x86)"
        );
        assert_eq!(_chdir(c"\\missing".as_ptr()), -1);
        assert_eq!(errno::get(), ENOENT);
        assert_eq!(_chdir(c"\\file.txt".as_ptr()), -1);
        assert_eq!(errno::get(), ENOTDIR);
        assert_eq!(
            runtime.lock().params.current_directory,
            r"C:\program files (x86)"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn getcwd_copies_allocates_and_checks_size() {
        let mut process = Process::new(Vec::new());
        process.params.current_directory = r"C:\Windows\system32".into();
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        let text = |p: *const c_char| {
            // SAFETY: _getcwd returns a NUL-terminated string.
            unsafe { std::ffi::CStr::from_ptr(p) }
                .to_str()
                .unwrap()
                .to_string()
        };

        let mut buf = [0 as c_char; 64];
        assert_eq!(_getcwd(buf.as_mut_ptr(), 64), buf.as_mut_ptr());
        assert_eq!(text(buf.as_ptr()), r"C:\Windows\system32");

        assert!(_getcwd(buf.as_mut_ptr(), 19).is_null());
        assert_eq!(errno::get(), ERANGE);
        assert!(!_getcwd(buf.as_mut_ptr(), 20).is_null());

        let owned = _getcwd(std::ptr::null_mut(), 0);
        assert_eq!(text(owned), r"C:\Windows\system32");
        // SAFETY: allocated by _getcwd with malloc.
        unsafe { libc::free(owned.cast()) };
    }
}
