//! Deleting files: `remove`.
//!
//! The `remove` page on Microsoft Learn: 0 on success, else -1 with
//! `errno` ENOENT (no such file) or EACCES (a directory, a read-only
//! file, or a file open elsewhere). Windows refuses to delete a file
//! another handle holds open without FILE_SHARE_DELETE.

use std::ffi::c_char;

use super::errno::{self, EACCES, EINVAL, ENOENT};
use super::stat::resolve;
use crate::runtime::with_current;
use crate::win::text::ansi;

const FILE_SHARE_DELETE: u32 = 4;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("remove", remove as *const () as u32)]
}

extern "C" fn remove(path: *const c_char) -> i32 {
    // SAFETY: a NUL-terminated string (the function's contract).
    let Some(path) = (unsafe { ansi(path) }) else {
        errno::set(EINVAL);
        return -1;
    };
    let result = resolve(&path).and_then(|(host, _)| {
        let meta = std::fs::symlink_metadata(&host).map_err(|_| ENOENT)?;
        if meta.is_dir() || meta.permissions().readonly() {
            return Err(EACCES);
        }
        let canonical = host.canonicalize().map_err(|_| ENOENT)?;
        let held = with_current(|p| {
            p.handles
                .files()
                .any(|f| f.host_path == canonical && f.share & FILE_SHARE_DELETE == 0)
        });
        if held {
            return Err(EACCES);
        }
        std::fs::remove_file(&host).map_err(|_| EACCES)
    });
    match result {
        Ok(()) => 0,
        Err(code) => {
            errno::set(code);
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::DriveMap;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use std::collections::BTreeMap;

    #[test]
    fn removes_files_but_not_folders_or_open_files() {
        let root = std::env::temp_dir().join(format!("xvm-remove-{}", std::process::id()));
        let c = root.join("c");
        std::fs::create_dir_all(c.join("q")).unwrap();
        std::fs::write(c.join("a.db"), b"x").unwrap();
        std::fs::write(c.join("held.db"), b"x").unwrap();
        let mut process = Process::new(Vec::new());
        process.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), c.clone())]));
        process.params.current_directory = r"C:\".into();
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        assert_eq!(remove(c"A.DB".as_ptr()), 0);
        assert!(!c.join("a.db").exists());
        assert_eq!(remove(c"a.db".as_ptr()), -1);
        assert_eq!(errno::get(), ENOENT);
        assert_eq!(remove(c"q".as_ptr()), -1);
        assert_eq!(errno::get(), EACCES);
        let handle =
            crate::win::kernel32::file::open_handle(r"C:\held.db", 0x8000_0000, 1, 3).unwrap();
        assert_eq!(
            remove(c"held.db".as_ptr()),
            -1,
            "open without delete sharing"
        );
        assert_eq!(errno::get(), EACCES);
        runtime.lock().handles.remove(handle);
        assert_eq!(remove(c"held.db".as_ptr()), 0);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
