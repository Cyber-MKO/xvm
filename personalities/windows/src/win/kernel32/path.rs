//! Path names: `GetFullPathNameA/W`.
//!
//! Paths are made absolute against the process's current directory, with
//! `.` and `..` resolved (`DriveMap::full_path`). The file need not exist.
//! A trailing separator is kept. Not done: removing trailing dots and
//! spaces from components. Forms we do not map (UNC, `C:file`) fail with
//! ERROR_INVALID_NAME and are logged as gaps.

use std::ffi::c_char;

use super::error::{ERROR_INVALID_NAME, set_last_error};
use crate::gap::GapKind;
use crate::paths::DriveMap;
use crate::runtime::with_current;
use crate::win::text::{ansi, wide};

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("GetFullPathNameA", GetFullPathNameA as *const () as u32),
        ("GetFullPathNameW", GetFullPathNameW as *const () as u32),
    ]
}

fn full_path_name(path: Option<String>) -> Option<String> {
    let path = path.filter(|p| !p.is_empty())?;
    with_current(
        |p| match DriveMap::full_path(&path, &p.params.current_directory) {
            Ok(mut full) => {
                if path.ends_with(['\\', '/']) && !full.ends_with('\\') {
                    full.push('\\');
                }
                Some(full)
            }
            Err(_) => {
                p.record_runtime_gap(
                    GapKind::Feature,
                    "kernel32.dll",
                    &format!("GetFullPathName of {path}"),
                );
                None
            }
        },
    )
}

/// Copy `full` (units, no NUL) into `out`, the GetFullPathName way.
/// `file_part` gets the address of the last component, or NULL if the
/// path ends with a separator.
///
/// # Safety
///
/// `out` holds `out_len` units; `file_part` is NULL or writable.
unsafe fn copy_out<T: Copy + From<u8> + PartialEq>(
    full: &[T],
    out: *mut T,
    out_len: u32,
    file_part: *mut *mut T,
) -> u32 {
    let needed = full.len() as u32 + 1;
    if out.is_null() || out_len < needed {
        return needed;
    }
    let sep = T::from(b'\\');
    // SAFETY: the caller's contract; out_len >= needed.
    unsafe {
        std::ptr::copy_nonoverlapping(full.as_ptr(), out, full.len());
        *out.add(full.len()) = T::from(0);
        if !file_part.is_null() {
            *file_part = match full.iter().rposition(|&c| c == sep) {
                Some(i) if i + 1 < full.len() => out.add(i + 1),
                _ => std::ptr::null_mut(),
            };
        }
    }
    full.len() as u32
}

/// Returns the length without the NUL, or the size needed with the NUL if
/// the buffer is too small, or 0 on failure.
#[allow(non_snake_case)]
extern "stdcall" fn GetFullPathNameW(
    path: *const u16,
    out_len: u32,
    out: *mut u16,
    file_part: *mut *mut u16,
) -> u32 {
    // SAFETY: a NUL-terminated string (the API's contract).
    let Some(full) = full_path_name(unsafe { wide(path) }) else {
        set_last_error(ERROR_INVALID_NAME);
        return 0;
    };
    let units: Vec<u16> = full.encode_utf16().collect();
    // SAFETY: the API's contract for out and file_part.
    unsafe { copy_out(&units, out, out_len, file_part) }
}

#[allow(non_snake_case)]
extern "stdcall" fn GetFullPathNameA(
    path: *const c_char,
    out_len: u32,
    out: *mut c_char,
    file_part: *mut *mut c_char,
) -> u32 {
    // SAFETY: a NUL-terminated string (the API's contract).
    let Some(full) = full_path_name(unsafe { ansi(path) }) else {
        set_last_error(ERROR_INVALID_NAME);
        return 0;
    };
    // Paths are ASCII until code pages exist.
    let bytes: Vec<u8> = full
        .bytes()
        .map(|b| if b.is_ascii() { b } else { b'?' })
        .collect();
    // SAFETY: as above; c_char and u8 have the same layout.
    unsafe { copy_out(&bytes, out.cast(), out_len, file_part.cast()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    fn attached() -> (Runtime, crate::runtime::Attached) {
        let mut process = Process::new(Vec::new());
        process.params.current_directory = r"C:\Program Files (x86)\ossec-agent".into();
        let runtime = Runtime::new(process);
        let thread = runtime.attach().unwrap();
        (runtime, thread)
    }

    #[test]
    fn wide_paths_resolve_against_the_current_directory() {
        let (_runtime, _thread) = attached();
        let input: Vec<u16> = r"..\ossec-agent\.\wazuh-agent.exe"
            .encode_utf16()
            .chain([0])
            .collect();
        let expected = r"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe";
        let mut part = std::ptr::null_mut();
        assert_eq!(
            GetFullPathNameW(input.as_ptr(), 0, std::ptr::null_mut(), &mut part),
            expected.len() as u32 + 1
        );
        let mut buf = [0u16; 260];
        let n = GetFullPathNameW(input.as_ptr(), 260, buf.as_mut_ptr(), &mut part);
        assert_eq!(String::from_utf16(&buf[..n as usize]).unwrap(), expected);
        // SAFETY: part points into buf.
        let offset = unsafe { part.offset_from(buf.as_ptr()) } as usize;
        assert_eq!(
            String::from_utf16(&buf[offset..n as usize]).unwrap(),
            "wazuh-agent.exe"
        );
    }

    #[test]
    fn ansi_keeps_trailing_separators_and_rejects_unc() {
        let (runtime, _thread) = attached();
        let mut buf = [0 as c_char; 64];
        let mut part = std::ptr::null_mut();
        let n = GetFullPathNameA(c"c:/temp/logs/".as_ptr(), 64, buf.as_mut_ptr(), &mut part);
        // SAFETY: NUL-terminated by GetFullPathNameA.
        let text = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_str()
            .unwrap();
        assert_eq!((n, text), (13, r"C:\temp\logs\"));
        assert!(part.is_null(), "no file part after a trailing separator");

        assert_eq!(
            GetFullPathNameA(
                c"\\\\server\\share".as_ptr(),
                64,
                buf.as_mut_ptr(),
                &mut part
            ),
            0
        );
        assert_eq!(runtime.lock().gaps().len(), 1);
    }
}
