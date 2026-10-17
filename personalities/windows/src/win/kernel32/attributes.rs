//! File attributes: `GetFileAttributesA`.
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

use std::ffi::c_char;

use super::error::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, set_last_error};
use super::file::resolve;
use crate::runtime::with_current;
use crate::win::text::ansi;

const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
pub(crate) const INVALID_FILE_ATTRIBUTES: u32 = 0xffff_ffff;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("GetFileAttributesA", GetFileAttributesA as *const () as u32)]
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
    let host = match with_current(|p| resolve(p, &name, "GetFileAttributesA")) {
        Ok((_, host)) => host,
        Err(code) => {
            set_last_error(code);
            return INVALID_FILE_ATTRIBUTES;
        }
    };
    let Ok(meta) = std::fs::metadata(&host) else {
        let folder = host.parent().is_some_and(|p| p.is_dir());
        set_last_error(if folder {
            ERROR_FILE_NOT_FOUND
        } else {
            ERROR_PATH_NOT_FOUND
        });
        return INVALID_FILE_ATTRIBUTES;
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::DriveMap;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use std::collections::BTreeMap;

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
        std::fs::remove_dir_all(&root).unwrap();
    }
}
