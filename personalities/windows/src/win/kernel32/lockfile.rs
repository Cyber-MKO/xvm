//! File locks: `LockFile`, `LockFileEx`, `UnlockFile`, `UnlockFileEx`.
//!
//! Byte ranges of an open file, with the rules in `crate::filelock`.
//! `LockFile` takes an exclusive lock and fails at once; `LockFileEx`
//! takes its range's offset from an OVERLAPPED and waits unless asked to
//! fail at once. A refused lock is ERROR_LOCK_VIOLATION; unlocking a
//! range that is not locked is ERROR_NOT_LOCKED.

use std::path::PathBuf;

use super::error::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, set_last_error};
use crate::handles::Object;
use crate::runtime::{current, with_current};

const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x1;
const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x2;
const ERROR_LOCK_VIOLATION: u32 = 33;
const ERROR_NOT_LOCKED: u32 = 158;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("LockFile", LockFile as *const () as u32),
        ("LockFileEx", LockFileEx as *const () as u32),
        ("UnlockFile", UnlockFile as *const () as u32),
        ("UnlockFileEx", UnlockFileEx as *const () as u32),
    ]
}

fn file(handle: u32) -> Option<PathBuf> {
    with_current(|p| match p.handles.get(handle) {
        Some(Object::File(f)) => Some(f.host_path.clone()),
        _ => None,
    })
}

fn join(low: u32, high: u32) -> u64 {
    (high as u64) << 32 | low as u64
}

/// The offset an OVERLAPPED names (Offset at +8, OffsetHigh at +12).
fn offset(overlapped: *const u32) -> Option<u64> {
    if overlapped.is_null() {
        return None;
    }
    // SAFETY: an OVERLAPPED (the API's contract).
    Some(unsafe { join(*overlapped.add(2), *overlapped.add(3)) })
}

fn lock(handle: u32, start: u64, len: u64, exclusive: bool, wait: bool) -> i32 {
    let Some(path) = file(handle) else {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };
    if current()
        .unwrap()
        .file_locks()
        .lock(&path, handle, start, len, exclusive, wait)
    {
        1
    } else {
        set_last_error(ERROR_LOCK_VIOLATION);
        0
    }
}

fn unlock(handle: u32, start: u64, len: u64) -> i32 {
    let Some(path) = file(handle) else {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };
    if current()
        .unwrap()
        .file_locks()
        .unlock(&path, handle, start, len)
    {
        1
    } else {
        set_last_error(ERROR_NOT_LOCKED);
        0
    }
}

#[allow(non_snake_case)]
extern "stdcall" fn LockFile(handle: u32, low: u32, high: u32, len_low: u32, len_high: u32) -> i32 {
    lock(
        handle,
        join(low, high),
        join(len_low, len_high),
        true,
        false,
    )
}

#[allow(non_snake_case)]
extern "stdcall" fn LockFileEx(
    handle: u32,
    flags: u32,
    reserved: u32,
    len_low: u32,
    len_high: u32,
    overlapped: *const u32,
) -> i32 {
    let Some(start) = offset(overlapped).filter(|_| reserved == 0) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    lock(
        handle,
        start,
        join(len_low, len_high),
        flags & LOCKFILE_EXCLUSIVE_LOCK != 0,
        flags & LOCKFILE_FAIL_IMMEDIATELY == 0,
    )
}

#[allow(non_snake_case)]
extern "stdcall" fn UnlockFile(
    handle: u32,
    low: u32,
    high: u32,
    len_low: u32,
    len_high: u32,
) -> i32 {
    unlock(handle, join(low, high), join(len_low, len_high))
}

#[allow(non_snake_case)]
extern "stdcall" fn UnlockFileEx(
    handle: u32,
    reserved: u32,
    len_low: u32,
    len_high: u32,
    overlapped: *const u32,
) -> i32 {
    let Some(start) = offset(overlapped).filter(|_| reserved == 0) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    unlock(handle, start, join(len_low, len_high))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::DriveMap;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use std::collections::BTreeMap;

    #[test]
    fn sqlite_style_locking_between_two_handles() {
        let root = std::env::temp_dir().join(format!("xvm-lockfile-{}", std::process::id()));
        std::fs::create_dir_all(root.join("c")).unwrap();
        std::fs::write(root.join("c/db"), b"x").unwrap();
        let mut process = Process::new(Vec::new());
        process.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), root.join("c"))]));
        process.params.current_directory = r"C:\".into();
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        let open = || super::super::file::open_handle(r"C:\db", 0xc000_0000, 3, 3).unwrap();
        let (a, b) = (open(), open());
        // OVERLAPPED with Offset 0x40000000 (SQLite's PENDING byte).
        let o = [0u32, 0, 0x4000_0000, 0, 0];
        assert_eq!(LockFileEx(a, 3, 0, 1, 0, o.as_ptr()), 1);
        assert_eq!(LockFileEx(b, 3, 0, 1, 0, o.as_ptr()), 0);
        assert_eq!(super::super::error::GetLastError(), ERROR_LOCK_VIOLATION);
        assert_eq!(LockFile(b, 0x4000_0001, 0, 1, 0), 1, "another byte");
        assert_eq!(
            UnlockFileEx(a, 0, 2, 0, o.as_ptr()),
            0,
            "not the locked range"
        );
        assert_eq!(super::super::error::GetLastError(), ERROR_NOT_LOCKED);
        assert_eq!(UnlockFileEx(a, 0, 1, 0, o.as_ptr()), 1);
        assert_eq!(LockFileEx(b, 1, 0, 1, 0, o.as_ptr()), 1, "shared, now free");
        assert_eq!(UnlockFile(b, 0x4000_0001, 0, 1, 0), 1);
        assert_eq!(super::super::file::CloseHandle(b), 1);
        assert_eq!(
            LockFileEx(a, 3, 0, 1, 0, o.as_ptr()),
            1,
            "closing released b's lock"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
