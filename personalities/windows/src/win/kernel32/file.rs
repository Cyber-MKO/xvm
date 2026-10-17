//! Files: `CreateFileA/W`, `ReadFile`, `CloseHandle`.
//!
//! Windows paths go through the drive table to host files. Creation
//! dispositions, access rights, share modes and error codes follow the
//! CreateFile page and "Creating and Opening Files" on Microsoft Learn.
//! Share modes are checked against the handles of this process; other
//! processes of the same host are not seen yet.
//!
//! I/O is synchronous. Overlapped I/O, delete-on-close, security
//! descriptors, inheritable handles and template files are logged gaps.

use std::ffi::c_char;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::error::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BAD_PATHNAME, ERROR_FILE_EXISTS,
    ERROR_FILE_NOT_FOUND, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_PATH_NOT_FOUND,
    ERROR_SHARING_VIOLATION, set_last_error,
};
use crate::gap::GapKind;
use crate::handles::{FileObject, Object};
use crate::paths::{DriveMap, PathError};
use crate::process::Process;
use crate::runtime::with_current;
use crate::win::text::{ansi, wide};

pub(crate) const INVALID_HANDLE_VALUE: u32 = 0xffff_ffff;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const FILE_READ_DATA: u32 = 0x1;
const FILE_WRITE_DATA: u32 = 0x2;
const FILE_APPEND_DATA: u32 = 0x4;
const DELETE: u32 = 0x1_0000;

const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const FILE_SHARE_DELETE: u32 = 4;

const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;

const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;

const ERROR_INVALID_FUNCTION: u32 = 1;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("CreateFileA", CreateFileA as *const () as u32),
        ("CreateFileW", CreateFileW as *const () as u32),
        ("ReadFile", ReadFile as *const () as u32),
        ("CloseHandle", CloseHandle as *const () as u32),
    ]
}

fn gap(p: &mut Process, what: &str) {
    p.record_runtime_gap(GapKind::Feature, "kernel32.dll", what);
}

/// Whether a new open conflicts with an existing one, by the share mode
/// rules in "Creating and Opening Files".
fn conflicts(old: &FileObject, read: bool, write: bool, delete: bool, share: u32) -> bool {
    (read && old.share & FILE_SHARE_READ == 0)
        || (write && old.share & FILE_SHARE_WRITE == 0)
        || (delete && old.share & FILE_SHARE_DELETE == 0)
        || (old.can_read && share & FILE_SHARE_READ == 0)
        || (old.can_write && share & FILE_SHARE_WRITE == 0)
        || (old.can_delete && share & FILE_SHARE_DELETE == 0)
}

struct Request {
    access: u32,
    share: u32,
    security: *const u32,
    disposition: u32,
    flags: u32,
    template: u32,
}

/// The full Windows path of `name` and the host path behind it, or a
/// Win32 error code. Path forms we do not support are logged for
/// `function`.
pub(super) fn resolve(
    p: &mut Process,
    name: &str,
    function: &str,
) -> Result<(String, PathBuf), u32> {
    let params = &p.params;
    let full = DriveMap::full_path(name, &params.current_directory).map_err(|_| ERROR_BAD_PATHNAME);
    let host = full.as_ref().map_err(|e| *e).and_then(|full| {
        match params.drives.to_host(full, &params.current_directory) {
            Ok(host) => Ok(host),
            Err(PathError::NoSuchDrive(_)) => Err(ERROR_PATH_NOT_FOUND),
            Err(PathError::Unsupported(_)) => Err(ERROR_BAD_PATHNAME),
        }
    });
    match (full, host) {
        (Ok(full), Ok(host)) => Ok((full, host)),
        (_, Err(code)) | (Err(code), _) => {
            if code == ERROR_BAD_PATHNAME {
                gap(p, &format!("{function} path form {name}"));
            }
            Err(code)
        }
    }
}

/// Open or create the file; returns the handle or a Win32 error code.
fn create_file(p: &mut Process, name: &str, r: &Request) -> Result<u32, u32> {
    if r.flags & FILE_FLAG_OVERLAPPED != 0 {
        gap(p, "CreateFile with FILE_FLAG_OVERLAPPED");
    }
    if r.flags & FILE_FLAG_DELETE_ON_CLOSE != 0 {
        gap(p, "CreateFile with FILE_FLAG_DELETE_ON_CLOSE");
    }
    if r.template != 0 {
        gap(p, "CreateFile with a template file");
    }
    if !r.security.is_null() {
        // SAFETY: SECURITY_ATTRIBUTES { nLength, lpSecurityDescriptor,
        // bInheritHandle } (the API's contract).
        let (descriptor, inherit) = unsafe { (*r.security.add(1), *r.security.add(2)) };
        if descriptor != 0 {
            gap(p, "CreateFile with a security descriptor");
        }
        if inherit != 0 {
            gap(p, "CreateFile with an inheritable handle");
        }
    }

    let (full, host) = resolve(p, name, "CreateFile")?;

    let read = r.access & (GENERIC_READ | GENERIC_ALL | FILE_READ_DATA) != 0;
    let write_data = r.access & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA) != 0;
    let append_only = !write_data && r.access & FILE_APPEND_DATA != 0;
    let write = write_data || append_only;
    let delete = r.access & (DELETE | GENERIC_ALL) != 0;

    let exists = host.exists();
    if host.is_dir() {
        if r.flags & FILE_FLAG_BACKUP_SEMANTICS == 0 || write {
            return Err(ERROR_ACCESS_DENIED);
        }
    } else if !exists && !host.parent().is_some_and(Path::is_dir) {
        return Err(ERROR_PATH_NOT_FOUND);
    }
    let canonical = host.canonicalize().ok();
    let busy = canonical.as_ref().is_some_and(|c| {
        p.handles
            .files()
            .any(|f| &f.host_path == c && conflicts(f, read, write, delete, r.share))
    });
    if busy {
        return Err(ERROR_SHARING_VIOLATION);
    }

    let mut options = OpenOptions::new();
    options
        .read(read || !write)
        .write(write_data)
        .append(append_only);
    // CREATE_ALWAYS and OPEN_ALWAYS report whether the file was there.
    let existed = Some(if exists { ERROR_ALREADY_EXISTS } else { 0 });
    let last_error = match r.disposition {
        CREATE_NEW if exists => return Err(ERROR_FILE_EXISTS),
        CREATE_NEW => {
            options.write(true).create_new(true);
            None
        }
        CREATE_ALWAYS => {
            options.write(true).create(true).truncate(true);
            existed
        }
        OPEN_EXISTING if !exists => return Err(ERROR_FILE_NOT_FOUND),
        OPEN_EXISTING => None,
        OPEN_ALWAYS => {
            if !exists {
                options.write(true).create(true);
            }
            existed
        }
        TRUNCATE_EXISTING if !exists => return Err(ERROR_FILE_NOT_FOUND),
        TRUNCATE_EXISTING if !write_data => return Err(ERROR_INVALID_PARAMETER),
        TRUNCATE_EXISTING => {
            options.truncate(true);
            None
        }
        _ => return Err(ERROR_INVALID_PARAMETER),
    };
    let file = match options.open(&host) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ERROR_FILE_NOT_FOUND),
        Err(_) => return Err(ERROR_ACCESS_DENIED),
    };
    let handle = p.handles.insert(Object::File(FileObject {
        file: Arc::new(file),
        host_path: host.canonicalize().unwrap_or(host.clone()),
        windows_path: full,
        can_read: read,
        can_write: write,
        can_delete: delete,
        share: r.share,
        is_directory: host.is_dir(),
    }));
    if let Some(code) = last_error {
        set_last_error(code);
    }
    Ok(handle)
}

fn create(name: Option<String>, request: Request) -> u32 {
    let Some(name) = name else {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    };
    match with_current(|p| create_file(p, &name, &request)) {
        Ok(handle) => handle,
        Err(code) => {
            set_last_error(code);
            INVALID_HANDLE_VALUE
        }
    }
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn CreateFileW(
    name: *const u16,
    access: u32,
    share: u32,
    security: *const u32,
    disposition: u32,
    flags: u32,
    template: u32,
) -> u32 {
    // SAFETY: a NUL-terminated string (the API's contract).
    let name = unsafe { wide(name) };
    create(
        name,
        Request {
            access,
            share,
            security,
            disposition,
            flags,
            template,
        },
    )
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn CreateFileA(
    name: *const c_char,
    access: u32,
    share: u32,
    security: *const u32,
    disposition: u32,
    flags: u32,
    template: u32,
) -> u32 {
    // SAFETY: a NUL-terminated string (the API's contract).
    let name = unsafe { ansi(name) };
    create(
        name,
        Request {
            access,
            share,
            security,
            disposition,
            flags,
            template,
        },
    )
}

/// The open file behind a handle, for I/O outside the process lock.
pub(crate) fn file_of(handle: u32) -> Result<(Arc<File>, bool, bool, bool), u32> {
    with_current(|p| match p.handles.get(handle) {
        Some(Object::File(f)) => Ok((f.file.clone(), f.can_read, f.can_write, f.is_directory)),
        _ => Err(ERROR_INVALID_HANDLE),
    })
}

/// Reads until `len` bytes or the end of the file. Returns TRUE with 0
/// bytes at the end of the file, as documented for synchronous handles.
#[allow(non_snake_case)]
extern "stdcall" fn ReadFile(
    handle: u32,
    buffer: *mut u8,
    len: u32,
    read: *mut u32,
    overlapped: u32,
) -> i32 {
    if overlapped != 0 {
        with_current(|p| gap(p, "ReadFile with OVERLAPPED"));
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if !read.is_null() {
        // SAFETY: writable (the API's contract).
        unsafe { *read = 0 };
    }
    let (file, can_read, _, is_directory) = match file_of(handle) {
        Ok(f) => f,
        Err(code) => {
            set_last_error(code);
            return 0;
        }
    };
    if is_directory {
        set_last_error(ERROR_INVALID_FUNCTION);
        return 0;
    }
    if !can_read {
        set_last_error(ERROR_ACCESS_DENIED);
        return 0;
    }
    // SAFETY: buffer holds len bytes (the API's contract).
    let buf = unsafe { std::slice::from_raw_parts_mut(buffer, len as usize) };
    let mut done = 0;
    while done < buf.len() {
        match (&*file).read(&mut buf[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                set_last_error(ERROR_ACCESS_DENIED);
                return 0;
            }
        }
    }
    if !read.is_null() {
        // SAFETY: as above.
        unsafe { *read = done as u32 };
    }
    1
}

/// Closes a handle. The process and thread pseudo-handles need no
/// closing and always succeed.
#[allow(non_snake_case)]
extern "stdcall" fn CloseHandle(handle: u32) -> i32 {
    if handle == super::process::CURRENT_PROCESS || handle == super::process::CURRENT_THREAD {
        return 1;
    }
    match with_current(|p| p.handles.remove(handle)) {
        Some(_) => 1,
        None => {
            set_last_error(ERROR_INVALID_HANDLE);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{Attached, Runtime};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    struct Host {
        runtime: Runtime,
        _thread: Attached,
        root: PathBuf,
    }

    impl Drop for Host {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn host(tag: &str) -> Host {
        let root = std::env::temp_dir().join(format!("xvm-file-{tag}-{}", std::process::id()));
        let c = root.join("c");
        std::fs::create_dir_all(c.join("agent")).unwrap();
        std::fs::write(c.join("agent/local_internal_options.conf"), b"key=value\n").unwrap();
        let mut process = Process::new(Vec::new());
        process.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), c)]));
        process.params.current_directory = r"C:\agent".into();
        let runtime = Runtime::new(process);
        let thread = runtime.attach().unwrap();
        Host {
            runtime,
            _thread: thread,
            root,
        }
    }

    fn open(name: &str, access: u32, share: u32, disposition: u32, flags: u32) -> u32 {
        let w: Vec<u16> = name.encode_utf16().chain([0]).collect();
        CreateFileW(
            w.as_ptr(),
            access,
            share,
            std::ptr::null(),
            disposition,
            flags,
            0,
        )
    }

    fn last_error() -> u32 {
        let value: u32;
        // SAFETY: the test thread is attached, so fs holds a TEB.
        unsafe { std::arch::asm!("mov {0}, dword ptr fs:[0x34]", out(reg) value) };
        value
    }

    #[test]
    fn opens_reads_and_closes_like_the_agent() {
        let _h = host("read");
        // The agent's call: relative name, GENERIC_READ, share all,
        // OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL.
        let h = open(
            "LOCAL_internal_options.conf",
            GENERIC_READ,
            7,
            OPEN_EXISTING,
            0x80,
        );
        assert_ne!(h, INVALID_HANDLE_VALUE);
        let mut buf = [0u8; 64];
        let mut n = 0;
        assert_eq!(ReadFile(h, buf.as_mut_ptr(), 64, &mut n, 0), 1);
        assert_eq!(&buf[..n as usize], b"key=value\n");
        assert_eq!(ReadFile(h, buf.as_mut_ptr(), 64, &mut n, 0), 1);
        assert_eq!(n, 0, "end of file");
        assert_eq!(CloseHandle(h), 1);
        assert_eq!(CloseHandle(h), 0);
        assert_eq!(last_error(), ERROR_INVALID_HANDLE);
    }

    #[test]
    fn dispositions_and_their_errors() {
        let h = host("disp");
        assert_eq!(
            open("missing.conf", GENERIC_READ, 0, OPEN_EXISTING, 0),
            INVALID_HANDLE_VALUE
        );
        assert_eq!(last_error(), ERROR_FILE_NOT_FOUND);
        assert_eq!(
            open(r"nodir\x.conf", GENERIC_READ, 0, OPEN_EXISTING, 0),
            INVALID_HANDLE_VALUE
        );
        assert_eq!(last_error(), ERROR_PATH_NOT_FOUND);

        let a = open("new.log", GENERIC_WRITE, 0, CREATE_NEW, 0);
        assert_ne!(a, INVALID_HANDLE_VALUE);
        CloseHandle(a);
        assert_eq!(
            open("new.log", GENERIC_WRITE, 0, CREATE_NEW, 0),
            INVALID_HANDLE_VALUE
        );
        assert_eq!(last_error(), ERROR_FILE_EXISTS);

        let b = open("new.log", GENERIC_WRITE, 0, OPEN_ALWAYS, 0);
        assert_eq!(last_error(), ERROR_ALREADY_EXISTS);
        CloseHandle(b);
        let c = open("other.log", GENERIC_WRITE, 0, CREATE_ALWAYS, 0);
        assert_eq!(last_error(), 0);
        CloseHandle(c);
        assert!(h.root.join("c/agent/other.log").exists());

        assert_eq!(
            open("new.log", GENERIC_READ, 0, TRUNCATE_EXISTING, 0),
            INVALID_HANDLE_VALUE
        );
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        assert_eq!(open("new.log", GENERIC_READ, 0, 9, 0), INVALID_HANDLE_VALUE);
    }

    #[test]
    fn share_modes_and_directories() {
        let _h = host("share");
        let a = open(
            "local_internal_options.conf",
            GENERIC_READ,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            0,
        );
        let b = open(
            "local_internal_options.conf",
            GENERIC_READ,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            0,
        );
        assert!(a != INVALID_HANDLE_VALUE && b != INVALID_HANDLE_VALUE);
        let w = open(
            "local_internal_options.conf",
            GENERIC_WRITE,
            7,
            OPEN_EXISTING,
            0,
        );
        assert_eq!(w, INVALID_HANDLE_VALUE);
        assert_eq!(last_error(), ERROR_SHARING_VIOLATION);
        CloseHandle(a);
        CloseHandle(b);
        let w = open(
            "local_internal_options.conf",
            GENERIC_WRITE,
            7,
            OPEN_EXISTING,
            0,
        );
        assert_ne!(w, INVALID_HANDLE_VALUE);
        CloseHandle(w);

        assert_eq!(
            open(r"C:\agent", GENERIC_READ, 7, OPEN_EXISTING, 0),
            INVALID_HANDLE_VALUE
        );
        assert_eq!(last_error(), ERROR_ACCESS_DENIED);
        let d = open(
            r"C:\agent",
            GENERIC_READ,
            7,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
        );
        assert_ne!(d, INVALID_HANDLE_VALUE);
        let mut n = 0;
        assert_eq!(ReadFile(d, [0u8; 4].as_mut_ptr(), 4, &mut n, 0), 0);
        CloseHandle(d);
    }

    #[test]
    fn unsupported_options_are_gaps() {
        let h = host("gaps");
        let f = open(
            "local_internal_options.conf",
            GENERIC_READ,
            7,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
        );
        assert_ne!(f, INVALID_HANDLE_VALUE);
        let mut n = 0;
        assert_eq!(ReadFile(f, [0u8; 4].as_mut_ptr(), 4, &mut n, 0x1000), 0);
        assert_eq!(
            open(r"\\server\share\x", GENERIC_READ, 7, OPEN_EXISTING, 0),
            INVALID_HANDLE_VALUE
        );
        assert_eq!(last_error(), ERROR_BAD_PATHNAME);
        assert_eq!(h.runtime.lock().gaps().len(), 3);
        assert_eq!(CloseHandle(u32::MAX), 1);
    }
}
