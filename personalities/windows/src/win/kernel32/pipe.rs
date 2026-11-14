//! Anonymous pipes and child processes: `CreatePipe`, `CreateProcessA`,
//! `CreateProcessW`.
//!
//! Kasim decided (2026-11-13) that commands fail and are logged for now.
//! `CreateProcess` logs the command line as a gap and fails as Windows
//! does for a program that does not exist (ERROR_FILE_NOT_FOUND). Nothing
//! runs on the real machine (CLAUDE.md rule 7).
//!
//! `CreatePipe` makes a host pipe. Its two ends are ordinary file handles,
//! so `ReadFile`, `WriteFile` and `CloseHandle` work on them. A pipe's
//! inheritance flag matters only to a child process, and none starts.

use std::ffi::c_char;
use std::os::fd::FromRawFd;
use std::sync::Arc;

use super::error::{ERROR_INVALID_PARAMETER, set_last_error};
use crate::gap::GapKind;
use crate::handles::{FileObject, Object};
use crate::runtime::with_current;
use crate::win::text::{ansi, wide};

const ERROR_FILE_NOT_FOUND: u32 = 2;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("CreatePipe", CreatePipe as *const () as u32),
        ("CreateProcessA", CreateProcessA as *const () as u32),
        ("CreateProcessW", CreateProcessW as *const () as u32),
    ]
}

fn end(fd: i32, read: bool) -> Object {
    // SAFETY: a new descriptor from pipe2 that nothing else owns.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    Object::File(FileObject {
        file: Arc::new(file),
        host_path: format!("pipe:[{fd}]").into(),
        windows_path: String::new(),
        can_read: read,
        can_write: !read,
        can_delete: false,
        share: 7,
        is_directory: false,
        overlapped: false,
    })
}

/// Stores the read and write ends' handles. The size hint is the host's
/// business.
#[allow(non_snake_case)]
extern "stdcall" fn CreatePipe(read: *mut u32, write: *mut u32, _security: u32, _size: u32) -> i32 {
    if read.is_null() || write.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let mut fds = [0i32; 2];
    // SAFETY: a plain pipe2 call into a two-element array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        set_last_error(8); // ERROR_NOT_ENOUGH_MEMORY
        return 0;
    }
    let (r, w) = with_current(|p| {
        (
            p.handles.insert(end(fds[0], true)),
            p.handles.insert(end(fds[1], false)),
        )
    });
    // SAFETY: writable (the API's contract).
    unsafe {
        *read = r;
        *write = w;
    }
    1
}

/// Logs the command and fails as for a missing program.
fn refuse(function: &str, application: Option<String>, command_line: Option<String>) -> i32 {
    let command = command_line
        .filter(|c| !c.is_empty())
        .or(application)
        .unwrap_or_default();
    with_current(|p| {
        p.record_runtime_gap(
            GapKind::Feature,
            "kernel32.dll",
            &format!("{function}: {command}"),
        )
    });
    set_last_error(ERROR_FILE_NOT_FOUND);
    0
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn CreateProcessA(
    application: *const c_char,
    command_line: *const c_char,
    _process_security: u32,
    _thread_security: u32,
    _inherit: i32,
    _flags: u32,
    _environment: u32,
    _directory: *const c_char,
    _startup: u32,
    _information: u32,
) -> i32 {
    // SAFETY: NULL or NUL-terminated strings (the API's contract).
    let (application, command_line) = unsafe { (ansi(application), ansi(command_line)) };
    refuse("CreateProcessA", application, command_line)
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn CreateProcessW(
    application: *const u16,
    command_line: *const u16,
    _process_security: u32,
    _thread_security: u32,
    _inherit: i32,
    _flags: u32,
    _environment: u32,
    _directory: *const u16,
    _startup: u32,
    _information: u32,
) -> i32 {
    // SAFETY: NULL or NUL-terminated strings (the API's contract).
    let (application, command_line) = unsafe { (wide(application), wide(command_line)) };
    refuse("CreateProcessW", application, command_line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use crate::win::kernel32::error::GetLastError;

    #[test]
    fn pipes_carry_bytes_and_commands_never_run() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let (mut r, mut w) = (0, 0);
        assert_eq!(CreatePipe(&mut r, &mut w, 0, 0), 1);
        let (rf, wf) = (
            super::super::file::file_of(r).unwrap(),
            super::super::file::file_of(w).unwrap(),
        );
        assert_eq!((rf.1, rf.2, wf.1, wf.2), (true, false, false, true));
        use std::io::{Read, Write};
        (&*wf.0).write_all(b"ok").unwrap();
        let mut got = [0u8; 2];
        (&*rf.0).read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ok");
        assert_eq!(super::super::file::CloseHandle(w), 1);
        assert_eq!(super::super::file::CloseHandle(r), 1);

        let line: Vec<u16> = "cmd.exe /c net accounts\0".encode_utf16().collect();
        let none = std::ptr::null();
        assert_eq!(
            CreateProcessW(none, line.as_ptr(), 0, 0, 1, 0, 0, none, 0, 0),
            0
        );
        assert_eq!(GetLastError(), ERROR_FILE_NOT_FOUND);
        assert_eq!(
            CreateProcessA(
                c"C:\\x\\a.exe".as_ptr(),
                std::ptr::null(),
                0,
                0,
                0,
                0,
                0,
                std::ptr::null(),
                0,
                0
            ),
            0
        );
        let gaps: Vec<String> = runtime
            .lock()
            .gaps()
            .iter()
            .map(|g| g.symbol.clone())
            .collect();
        assert_eq!(
            gaps,
            [
                "CreateProcessW: cmd.exe /c net accounts",
                "CreateProcessA: C:\\x\\a.exe"
            ]
        );
    }
}
