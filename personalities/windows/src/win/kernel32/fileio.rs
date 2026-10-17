//! File I/O on open handles, and deleting files: `GetFileSize`,
//! `GetFileSizeEx`, `SetFilePointer`, `WriteFile`, `FlushFileBuffers`,
//! `SetEndOfFile`, `GetFileType`, `DeleteFileA`, `DeleteFileW`.
//!
//! Following each function's page on Microsoft Learn. I/O is synchronous;
//! an OVERLAPPED on `WriteFile` names the offset, as for `ReadFile`.
//! `SetFilePointer` sets the last error to 0 on success, so a low part of
//! 0xffffffff can be told from a failure. `DeleteFile` refuses folders and
//! read-only files (ERROR_ACCESS_DENIED) and files another handle holds
//! without FILE_SHARE_DELETE (ERROR_SHARING_VIOLATION).

use std::ffi::c_char;
use std::io::{Seek, SeekFrom, Write};

use super::error::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, ERROR_PATH_NOT_FOUND,
    ERROR_SHARING_VIOLATION, set_last_error,
};
use super::file::{file_of, resolve};
use crate::runtime::with_current;
use crate::win::text::{ansi, wide};

const INVALID_FILE_SIZE: u32 = 0xffff_ffff;
const INVALID_SET_FILE_POINTER: u32 = 0xffff_ffff;
const FILE_BEGIN: u32 = 0;
const FILE_CURRENT: u32 = 1;
const FILE_END: u32 = 2;
const ERROR_NEGATIVE_SEEK: u32 = 131;
const FILE_TYPE_UNKNOWN: u32 = 0;
const FILE_TYPE_DISK: u32 = 1;
const FILE_SHARE_DELETE: u32 = 4;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("GetFileSize", GetFileSize as *const () as u32),
        ("GetFileSizeEx", GetFileSizeEx as *const () as u32),
        ("SetFilePointer", SetFilePointer as *const () as u32),
        ("WriteFile", WriteFile as *const () as u32),
        ("FlushFileBuffers", FlushFileBuffers as *const () as u32),
        ("SetEndOfFile", SetEndOfFile as *const () as u32),
        ("GetFileType", GetFileType as *const () as u32),
        ("DeleteFileA", DeleteFileA as *const () as u32),
        ("DeleteFileW", DeleteFileW as *const () as u32),
    ]
}

fn size_of(handle: u32) -> Result<u64, u32> {
    let (file, ..) = file_of(handle)?;
    file.metadata()
        .map(|m| m.len())
        .map_err(|_| ERROR_ACCESS_DENIED)
}

#[allow(non_snake_case)]
extern "stdcall" fn GetFileSize(handle: u32, high: *mut u32) -> u32 {
    match size_of(handle) {
        Ok(size) => {
            if !high.is_null() {
                // SAFETY: writable (the API's contract).
                unsafe { *high = (size >> 32) as u32 };
            }
            set_last_error(0);
            size as u32
        }
        Err(code) => {
            set_last_error(code);
            INVALID_FILE_SIZE
        }
    }
}

#[allow(non_snake_case)]
extern "stdcall" fn GetFileSizeEx(handle: u32, size: *mut i64) -> i32 {
    match size_of(handle) {
        Ok(n) if !size.is_null() => {
            // SAFETY: writable (the API's contract).
            unsafe { *size = n as i64 };
            1
        }
        Ok(_) => {
            set_last_error(ERROR_INVALID_PARAMETER);
            0
        }
        Err(code) => {
            set_last_error(code);
            0
        }
    }
}

/// Moves the file pointer. The distance is the signed 32-bit `low`, or,
/// with `high`, the signed 64-bit value of both. Returns the new low part
/// and writes the new high part to `high`.
#[allow(non_snake_case)]
extern "stdcall" fn SetFilePointer(handle: u32, low: i32, high: *mut i32, method: u32) -> u32 {
    let (file, ..) = match file_of(handle) {
        Ok(f) => f,
        Err(code) => {
            set_last_error(code);
            return INVALID_SET_FILE_POINTER;
        }
    };
    let distance = if high.is_null() {
        low as i64
    } else {
        // SAFETY: readable (the API's contract).
        ((unsafe { *high } as i64) << 32) | (low as u32 as i64)
    };
    let base = match method {
        FILE_BEGIN => 0,
        FILE_CURRENT => (&*file).stream_position().unwrap_or(0) as i64,
        FILE_END => file.metadata().map_or(0, |m| m.len() as i64),
        _ => {
            set_last_error(ERROR_INVALID_PARAMETER);
            return INVALID_SET_FILE_POINTER;
        }
    };
    let Some(target) = base.checked_add(distance).filter(|&t| t >= 0) else {
        set_last_error(ERROR_NEGATIVE_SEEK);
        return INVALID_SET_FILE_POINTER;
    };
    if (&*file).seek(SeekFrom::Start(target as u64)).is_err() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_SET_FILE_POINTER;
    }
    if !high.is_null() {
        // SAFETY: as above.
        unsafe { *high = (target >> 32) as i32 };
    }
    set_last_error(0);
    target as u32
}

#[allow(non_snake_case)]
extern "stdcall" fn WriteFile(
    handle: u32,
    buffer: *const u8,
    len: u32,
    written: *mut u32,
    overlapped: *mut u32,
) -> i32 {
    if !written.is_null() {
        // SAFETY: writable (the API's contract).
        unsafe { *written = 0 };
    }
    let (file, _, can_write, is_directory) = match file_of(handle) {
        Ok(f) => f,
        Err(code) => {
            set_last_error(code);
            return 0;
        }
    };
    if is_directory || !can_write {
        set_last_error(ERROR_ACCESS_DENIED);
        return 0;
    }
    let mut f = &*file;
    if !overlapped.is_null() {
        // SAFETY: an OVERLAPPED (the API's contract); Offset at +8.
        let offset = unsafe { (*overlapped.add(3) as u64) << 32 | *overlapped.add(2) as u64 };
        if f.seek(SeekFrom::Start(offset)).is_err() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
    }
    // SAFETY: buffer holds len bytes (the API's contract).
    let data = unsafe { std::slice::from_raw_parts(buffer, len as usize) };
    if f.write_all(data).is_err() {
        set_last_error(ERROR_ACCESS_DENIED);
        return 0;
    }
    if !written.is_null() {
        // SAFETY: as above.
        unsafe { *written = len };
    }
    if !overlapped.is_null() {
        // SAFETY: as above; Internal and InternalHigh.
        unsafe {
            *overlapped = 0;
            *overlapped.add(1) = len;
        }
    }
    1
}

#[allow(non_snake_case)]
extern "stdcall" fn FlushFileBuffers(handle: u32) -> i32 {
    match file_of(handle) {
        Ok((file, _, true, _)) => {
            let _ = file.sync_data();
            1
        }
        Ok(_) => {
            set_last_error(ERROR_ACCESS_DENIED);
            0
        }
        Err(code) => {
            set_last_error(code);
            0
        }
    }
}

/// Ends the file at the file pointer, growing or shrinking it.
#[allow(non_snake_case)]
extern "stdcall" fn SetEndOfFile(handle: u32) -> i32 {
    match file_of(handle) {
        Ok((file, _, true, false)) => {
            let at = (&*file).stream_position().unwrap_or(0);
            if file.set_len(at).is_ok() {
                1
            } else {
                set_last_error(ERROR_ACCESS_DENIED);
                0
            }
        }
        Ok(_) => {
            set_last_error(ERROR_ACCESS_DENIED);
            0
        }
        Err(code) => {
            set_last_error(code);
            0
        }
    }
}

/// Every handle that names a file is on a disk.
#[allow(non_snake_case)]
extern "stdcall" fn GetFileType(handle: u32) -> u32 {
    match file_of(handle) {
        Ok(_) => FILE_TYPE_DISK,
        Err(code) => {
            set_last_error(code);
            FILE_TYPE_UNKNOWN
        }
    }
}

fn delete(name: Option<String>) -> i32 {
    let Some(name) = name else {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return 0;
    };
    let result = with_current(|p| {
        let (_, host) = resolve(p, &name, "DeleteFile")?;
        let meta = std::fs::symlink_metadata(&host).map_err(|_| {
            if host.parent().is_some_and(|d| d.is_dir()) {
                ERROR_FILE_NOT_FOUND
            } else {
                ERROR_PATH_NOT_FOUND
            }
        })?;
        if meta.is_dir() || meta.permissions().readonly() {
            return Err(ERROR_ACCESS_DENIED);
        }
        let canonical = host.canonicalize().map_err(|_| ERROR_FILE_NOT_FOUND)?;
        if p.handles
            .files()
            .any(|f| f.host_path == canonical && f.share & FILE_SHARE_DELETE == 0)
        {
            return Err(ERROR_SHARING_VIOLATION);
        }
        std::fs::remove_file(&host).map_err(|_| ERROR_ACCESS_DENIED)
    });
    match result {
        Ok(()) => 1,
        Err(code) => {
            set_last_error(code);
            0
        }
    }
}

#[allow(non_snake_case)]
extern "stdcall" fn DeleteFileA(name: *const c_char) -> i32 {
    // SAFETY: a NUL-terminated string (the API's contract).
    delete(unsafe { ansi(name) })
}

#[allow(non_snake_case)]
extern "stdcall" fn DeleteFileW(name: *const u16) -> i32 {
    // SAFETY: as above.
    delete(unsafe { wide(name) })
}

#[cfg(test)]
mod tests {
    use super::super::error::GetLastError;
    use super::super::file::{CloseHandle, open_handle};
    use super::*;
    use crate::paths::DriveMap;
    use crate::process::Process;
    use crate::runtime::{Attached, Runtime};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn host(tag: &str) -> (Runtime, Attached, PathBuf) {
        let root = std::env::temp_dir().join(format!("xvm-fileio-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(root.join("c/d")).unwrap();
        let mut process = Process::new(Vec::new());
        process.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), root.join("c"))]));
        process.params.current_directory = r"C:\".into();
        let runtime = Runtime::new(process);
        let thread = runtime.attach().unwrap();
        (runtime, thread, root)
    }

    #[test]
    fn write_seek_size_and_truncate_like_sqlite() {
        let (_r, _t, root) = host("io");
        // GENERIC_READ | GENERIC_WRITE, share read and write, CREATE_ALWAYS.
        let h = open_handle(r"C:\x.db", 0xc000_0000, 3, 2).unwrap();
        assert_eq!(GetFileType(h), FILE_TYPE_DISK);
        let mut n = 0;
        assert_eq!(
            WriteFile(h, b"hello world".as_ptr(), 11, &mut n, std::ptr::null_mut()),
            1
        );
        assert_eq!(n, 11);
        let mut high = 0u32;
        assert_eq!(GetFileSize(h, &mut high), 11);
        // A positioned write at 6.
        let mut o = [0u32, 0, 6, 0, 0];
        assert_eq!(
            WriteFile(h, b"WORLD".as_ptr(), 5, &mut n, o.as_mut_ptr()),
            1
        );
        assert_eq!(o[1], 5);
        assert_eq!(std::fs::read(root.join("c/x.db")).unwrap(), b"hello WORLD");
        assert_eq!(SetFilePointer(h, -6, std::ptr::null_mut(), FILE_END), 5);
        assert_eq!(SetEndOfFile(h), 1);
        let mut size = 0i64;
        assert_eq!(GetFileSizeEx(h, &mut size), 1);
        assert_eq!(size, 5);
        let mut far = 1i32;
        assert_eq!(SetFilePointer(h, 0, &mut far, FILE_BEGIN), 0);
        assert_eq!(
            (far, GetLastError()),
            (1, 0),
            "4 GiB: low 0, high 1, success"
        );
        assert_eq!(
            SetFilePointer(h, -10, std::ptr::null_mut(), FILE_BEGIN),
            INVALID_SET_FILE_POINTER
        );
        assert_eq!(GetLastError(), ERROR_NEGATIVE_SEEK);
        assert_eq!(FlushFileBuffers(h), 1);
        // Held without delete sharing.
        assert_eq!(DeleteFileA(c"C:\\x.db".as_ptr()), 0);
        assert_eq!(GetLastError(), ERROR_SHARING_VIOLATION);
        CloseHandle(h);
        let w: Vec<u16> = "C:\\X.DB\0".encode_utf16().collect();
        assert_eq!(DeleteFileW(w.as_ptr()), 1);
        assert_eq!(DeleteFileA(c"C:\\x.db".as_ptr()), 0);
        assert_eq!(GetLastError(), ERROR_FILE_NOT_FOUND);
        assert_eq!(DeleteFileA(c"C:\\d".as_ptr()), 0);
        assert_eq!(GetLastError(), ERROR_ACCESS_DENIED);
        assert_eq!(GetFileType(0x1234), FILE_TYPE_UNKNOWN);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
