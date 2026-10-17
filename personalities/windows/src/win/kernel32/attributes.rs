//! File attributes: `GetFileAttributesA`, `GetFileAttributesW`,
//! `GetFileAttributesExW`, `GetFileInformationByHandle`.
//!
//! The drive folders hold no Windows attributes, so they are derived, as
//! the "File Attribute Constants" page on Microsoft Learn defines them:
//!
//! | Host file | Attributes |
//! | --- | --- |
//! | Directory | `FILE_ATTRIBUTE_DIRECTORY` |
//! | File | `FILE_ATTRIBUTE_ARCHIVE`, which Windows sets on files it writes |
//! | Read-only (no write permission) | Adds `FILE_ATTRIBUTE_READONLY` |
//!
//! Hidden and system attributes are not modelled for drive files.
//! `GetFileAttributesExW` adds the creation (or, where the host has none,
//! change), access and write times as FILETIMEs, and the size.
//!
//! `GetFileInformationByHandle` adds the link count and a file index
//! from the host inode, which, like the Windows index, stays the same
//! while the file exists. The volume serial number is not in the host
//! profile yet: it is 0, a logged gap.

use std::ffi::c_char;

use super::error::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, set_last_error};
use super::file::resolve;
use crate::runtime::with_current;
use crate::win::text::{ansi, wide};

const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
pub(crate) const INVALID_FILE_ATTRIBUTES: u32 = 0xffff_ffff;

const GET_FILE_EX_INFO_STANDARD: u32 = 0;
/// Seconds from 1601-01-01, where FILETIMEs start, to 1970-01-01.
const EPOCH_DIFFERENCE: i64 = 11_644_473_600;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("GetFileAttributesA", GetFileAttributesA as *const () as u32),
        ("GetFileAttributesW", GetFileAttributesW as *const () as u32),
        (
            "GetFileAttributesExW",
            GetFileAttributesExW as *const () as u32,
        ),
        (
            "GetFileInformationByHandle",
            GetFileInformationByHandle as *const () as u32,
        ),
    ]
}

/// A Unix time as a FILETIME: 100-nanosecond intervals since 1601.
pub(crate) fn filetime(seconds: i64, nanos: i64) -> u64 {
    ((seconds + EPOCH_DIFFERENCE) * 10_000_000 + nanos / 100).max(0) as u64
}

/// The attributes and metadata of `name`, or a Win32 error code.
fn lookup(name: &str, function: &str) -> Result<(u32, std::fs::Metadata), u32> {
    let (_, host) = with_current(|p| resolve(p, name, function))?;
    let Ok(meta) = std::fs::metadata(&host) else {
        let folder = host.parent().is_some_and(|p| p.is_dir());
        return Err(if folder {
            ERROR_FILE_NOT_FOUND
        } else {
            ERROR_PATH_NOT_FOUND
        });
    };
    Ok((attributes_of_meta(&meta), meta))
}

fn attributes_of_meta(meta: &std::fs::Metadata) -> u32 {
    let mut attributes = if meta.is_dir() {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_ARCHIVE
    };
    if meta.permissions().readonly() {
        attributes |= FILE_ATTRIBUTE_READONLY;
    }
    attributes
}

/// WIN32_FILE_ATTRIBUTE_DATA for `meta` (36 bytes): attributes, creation,
/// access and write FILETIMEs, size high and low.
fn attribute_data(meta: &std::fs::Metadata) -> [u8; 36] {
    use std::os::unix::fs::MetadataExt;
    let created = meta
        .created()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(filetime(meta.ctime(), meta.ctime_nsec()), |d| {
            filetime(d.as_secs() as i64, d.subsec_nanos() as i64)
        });
    let size = if meta.is_dir() { 0 } else { meta.len() };
    let mut buf = [0u8; 36];
    buf[0..4].copy_from_slice(&attributes_of_meta(meta).to_le_bytes());
    buf[4..12].copy_from_slice(&created.to_le_bytes());
    buf[12..20].copy_from_slice(&filetime(meta.atime(), meta.atime_nsec()).to_le_bytes());
    buf[20..28].copy_from_slice(&filetime(meta.mtime(), meta.mtime_nsec()).to_le_bytes());
    buf[28..32].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
    buf[32..36].copy_from_slice(&(size as u32).to_le_bytes());
    buf
}

/// The attributes of a file or directory, or INVALID_FILE_ATTRIBUTES with
/// ERROR_FILE_NOT_FOUND, or ERROR_PATH_NOT_FOUND when its folder is
/// missing too.
#[allow(non_snake_case)]
extern "stdcall" fn GetFileAttributesA(name: *const c_char) -> u32 {
    // SAFETY: a NUL-terminated string (the API's contract).
    let Some(name) = (unsafe { ansi(name) }) else {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    };
    match lookup(&name, "GetFileAttributesA") {
        Ok((attributes, _)) => attributes,
        Err(code) => {
            set_last_error(code);
            INVALID_FILE_ATTRIBUTES
        }
    }
}

fn attributes_of(name: Option<String>, function: &str) -> u32 {
    let Some(name) = name else {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    };
    match lookup(&name, function) {
        Ok((attributes, _)) => attributes,
        Err(code) => {
            set_last_error(code);
            INVALID_FILE_ATTRIBUTES
        }
    }
}

#[allow(non_snake_case)]
extern "stdcall" fn GetFileAttributesW(name: *const u16) -> u32 {
    // SAFETY: a NUL-terminated string (the API's contract).
    attributes_of(unsafe { wide(name) }, "GetFileAttributesW")
}

/// Fills WIN32_FILE_ATTRIBUTE_DATA (36 bytes): attributes, creation,
/// access and write FILETIMEs, size high and low. Only the standard
/// level exists.
#[allow(non_snake_case)]
extern "stdcall" fn GetFileAttributesExW(name: *const u16, level: u32, out: *mut u8) -> i32 {
    if level != GET_FILE_EX_INFO_STANDARD || out.is_null() {
        set_last_error(super::error::ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: a NUL-terminated string (the API's contract).
    let Some(name) = (unsafe { wide(name) }) else {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return 0;
    };
    let meta = match lookup(&name, "GetFileAttributesExW") {
        Ok((_, meta)) => meta,
        Err(code) => {
            set_last_error(code);
            return 0;
        }
    };
    let buf = attribute_data(&meta);
    // SAFETY: out holds a WIN32_FILE_ATTRIBUTE_DATA (the API's contract).
    unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, buf.len()) };
    1
}

/// Fills BY_HANDLE_FILE_INFORMATION (52 bytes): attributes, three
/// FILETIMEs, volume serial, size high and low, links, index high and
/// low. FALSE with ERROR_INVALID_HANDLE for a handle that is not a file.
#[allow(non_snake_case)]
extern "stdcall" fn GetFileInformationByHandle(handle: u32, out: *mut u8) -> i32 {
    use std::os::unix::fs::MetadataExt;
    let meta = match super::file::file_of(handle) {
        Ok((file, ..)) => file.metadata(),
        Err(code) => {
            set_last_error(code);
            return 0;
        }
    };
    let Ok(meta) = meta else {
        set_last_error(super::error::ERROR_INVALID_HANDLE);
        return 0;
    };
    with_current(|p| {
        p.record_runtime_gap(
            crate::gap::GapKind::Feature,
            "kernel32.dll",
            "GetFileInformationByHandle: volume serial number",
        )
    });
    let data = attribute_data(&meta);
    let mut buf = [0u8; 52];
    buf[0..28].copy_from_slice(&data[0..28]);
    buf[32..40].copy_from_slice(&data[28..36]);
    buf[40..44].copy_from_slice(&(meta.nlink() as u32).to_le_bytes());
    buf[44..48].copy_from_slice(&((meta.ino() >> 32) as u32).to_le_bytes());
    buf[48..52].copy_from_slice(&(meta.ino() as u32).to_le_bytes());
    // SAFETY: out holds a BY_HANDLE_FILE_INFORMATION (the API's contract).
    unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, buf.len()) };
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::DriveMap;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use std::collections::BTreeMap;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn directories_files_and_missing_paths() {
        let root = std::env::temp_dir().join(format!("xvm-attr-{}", std::process::id()));
        let c = root.join("c");
        std::fs::create_dir_all(c.join("agent/queue")).unwrap();
        std::fs::write(c.join("agent/ossec.conf"), b"x").unwrap();
        std::fs::write(c.join("agent/ro.txt"), b"x").unwrap();
        let mut perms = std::fs::metadata(c.join("agent/ro.txt"))
            .unwrap()
            .permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(c.join("agent/ro.txt"), perms).unwrap();
        let mut process = Process::new(Vec::new());
        process.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), c.clone())]));
        process.params.current_directory = r"C:\agent".into();
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        assert_eq!(
            GetFileAttributesA(c"C:\\AGENT\\queue".as_ptr()),
            FILE_ATTRIBUTE_DIRECTORY
        );
        assert_eq!(
            GetFileAttributesA(c"ossec.conf".as_ptr()),
            FILE_ATTRIBUTE_ARCHIVE
        );
        // Root runs tests with every permission, so only check the bit when it shows.
        let ro = GetFileAttributesA(c"ro.txt".as_ptr());
        assert_eq!(ro & FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_ARCHIVE);
        assert_eq!(
            GetFileAttributesA(c"missing.txt".as_ptr()),
            INVALID_FILE_ATTRIBUTES
        );
        assert_eq!(super::super::error::GetLastError(), ERROR_FILE_NOT_FOUND);
        assert_eq!(
            GetFileAttributesA(c"nodir\\x.txt".as_ptr()),
            INVALID_FILE_ATTRIBUTES
        );
        assert_eq!(super::super::error::GetLastError(), ERROR_PATH_NOT_FOUND);
        let queue: Vec<u16> = "C:\\agent\\QUEUE\0".encode_utf16().collect();
        assert_eq!(GetFileAttributesW(queue.as_ptr()), FILE_ATTRIBUTE_DIRECTORY);
        let w: Vec<u16> = "ossec.conf\0".encode_utf16().collect();
        let mut data = [0u8; 36];
        assert_eq!(GetFileAttributesExW(w.as_ptr(), 0, data.as_mut_ptr()), 1);
        assert_eq!(
            u32::from_le_bytes(data[0..4].try_into().unwrap()),
            FILE_ATTRIBUTE_ARCHIVE
        );
        assert_eq!(u32::from_le_bytes(data[32..36].try_into().unwrap()), 1);
        let mtime = std::fs::metadata(c.join("agent/ossec.conf"))
            .unwrap()
            .mtime();
        let write = u64::from_le_bytes(data[20..28].try_into().unwrap());
        assert_eq!(write / 10_000_000, (mtime + EPOCH_DIFFERENCE) as u64);
        assert_eq!(GetFileAttributesExW(w.as_ptr(), 1, data.as_mut_ptr()), 0);
        let missing: Vec<u16> = "gone.txt\0".encode_utf16().collect();
        assert_eq!(
            GetFileAttributesExW(missing.as_ptr(), 0, data.as_mut_ptr()),
            0
        );
        assert_eq!(super::super::error::GetLastError(), ERROR_FILE_NOT_FOUND);

        // By handle: the same data, plus links and the inode as index.
        let handle =
            super::super::file::open_handle(r"C:\agent\ossec.conf", 0x8000_0000, 7, 3).unwrap();
        let mut info = [0u8; 52];
        assert_eq!(GetFileInformationByHandle(handle, info.as_mut_ptr()), 1);
        assert_eq!(info[0..28], data[0..28]);
        assert_eq!(info[32..40], data[28..36]);
        let field = |o: usize| u32::from_le_bytes(info[o..o + 4].try_into().unwrap());
        let meta = std::fs::metadata(c.join("agent/ossec.conf")).unwrap();
        assert_eq!(field(40), 1);
        assert_eq!(field(48), meta.ino() as u32);
        assert_eq!(GetFileInformationByHandle(0x1234, info.as_mut_ptr()), 0);
        let gaps = runtime.lock().gaps().len();
        assert_eq!(gaps, 1, "the volume serial number");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
