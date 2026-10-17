//! File status: `_stat`.
//!
//! Fields as the `_stat` page on Microsoft Learn describes them for
//! `msvcrt`'s 32-bit `struct _stat` (36 bytes):
//!
//! | Offset | Field | Value |
//! | --- | --- | --- |
//! | 0 | `st_dev` | Drive number (A is 0, C is 2) |
//! | 4 | `st_ino` | 0 |
//! | 6 | `st_mode` | Type, then read, write and execute bits copied to group and other |
//! | 8 | `st_nlink` | 1 |
//! | 10, 12 | `st_uid`, `st_gid` | 0 |
//! | 16 | `st_rdev` | As `st_dev` |
//! | 20 | `st_size` | Size; EOVERFLOW past 2 GB |
//! | 24, 28, 32 | `st_atime`, `st_mtime`, `st_ctime` | Access, change and creation times |
//!
//! Execute is set for directories and for `.exe`, `.com`, `.bat` and `.cmd`
//! files. Write is clear for read-only files.

use std::ffi::c_char;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::errno::{self, EINVAL, ENOENT, EOVERFLOW};
use crate::paths::DriveMap;
use crate::runtime::with_current;
use crate::win::text::ansi;

const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const S_IREAD: u16 = 0x100;
const S_IWRITE: u16 = 0x80;
const S_IEXEC: u16 = 0x40;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("_stat", _stat as *const () as u32)]
}

/// Status of a file, ready for the 32-bit or 64-bit structures.
pub(super) struct Status {
    pub drive: u32,
    pub mode: u16,
    pub size: u64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
}

/// The status of `host`, a file or directory the Windows path `full`
/// names, or an `errno` value.
pub(super) fn status(host: &Path, full: &str) -> Result<Status, i32> {
    let meta = std::fs::metadata(host).map_err(|_| ENOENT)?;
    let is_dir = meta.is_dir();
    let extension = full.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    let exec = is_dir || matches!(extension.as_deref(), Some("exe" | "com" | "bat" | "cmd"));
    let mut perms = S_IREAD;
    if !meta.permissions().readonly() {
        perms |= S_IWRITE;
    }
    if exec {
        perms |= S_IEXEC;
    }
    let mode = if is_dir { S_IFDIR } else { S_IFREG } | perms | (perms >> 3) | (perms >> 6);
    // Creation time where the host records it, else the change time.
    let ctime = meta
        .created()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(meta.ctime(), |d| d.as_secs() as i64);
    Ok(Status {
        drive: (full.as_bytes()[0].to_ascii_uppercase() - b'A') as u32,
        mode,
        size: if is_dir { 0 } else { meta.len() },
        atime: meta.atime(),
        mtime: meta.mtime(),
        ctime,
    })
}

/// Resolve a Windows path against the process's drives and directory.
pub(super) fn resolve(path: &str) -> Result<(std::path::PathBuf, String), i32> {
    with_current(|p| {
        let params = &p.params;
        let full = DriveMap::full_path(path, &params.current_directory).map_err(|_| ENOENT)?;
        let host = params
            .drives
            .to_host(&full, &params.current_directory)
            .map_err(|_| ENOENT)?;
        Ok((host, full))
    })
}

/// Returns 0, or -1 with `errno` set.
extern "C" fn _stat(path: *const c_char, out: *mut u8) -> i32 {
    // SAFETY: a NUL-terminated string (the function's contract).
    let Some(path) = (unsafe { ansi(path) }) else {
        errno::set(EINVAL);
        return -1;
    };
    // A trailing separator only names a directory (or a drive root).
    let trailing = path.len() > 3 && path.ends_with(['\\', '/']);
    let status = resolve(&path).and_then(|(host, full)| {
        let s = status(&host, &full)?;
        if trailing && s.mode & S_IFDIR == 0 {
            return Err(ENOENT);
        }
        Ok(s)
    });
    let s = match status {
        Ok(s) => s,
        Err(code) => {
            errno::set(code);
            return -1;
        }
    };
    if s.size > i32::MAX as u64 {
        errno::set(EOVERFLOW);
        return -1;
    }
    let mut buf = [0u8; 36];
    buf[0..4].copy_from_slice(&s.drive.to_le_bytes());
    buf[6..8].copy_from_slice(&s.mode.to_le_bytes());
    buf[8..10].copy_from_slice(&1u16.to_le_bytes());
    buf[16..20].copy_from_slice(&s.drive.to_le_bytes());
    buf[20..24].copy_from_slice(&(s.size as i32).to_le_bytes());
    buf[24..28].copy_from_slice(&(s.atime as i32).to_le_bytes());
    buf[28..32].copy_from_slice(&(s.mtime as i32).to_le_bytes());
    buf[32..36].copy_from_slice(&(s.ctime as i32).to_le_bytes());
    // SAFETY: out holds a struct _stat (the function's contract).
    unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, buf.len()) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use std::collections::BTreeMap;

    #[test]
    fn reports_files_and_directories_like_msvcrt() {
        let root = std::env::temp_dir().join(format!("xvm-stat-{}", std::process::id()));
        let c = root.join("c");
        std::fs::create_dir_all(c.join("agent")).unwrap();
        std::fs::write(c.join("agent/ossec.conf"), b"0123456789").unwrap();
        std::fs::write(c.join("agent/agent.exe"), b"MZ").unwrap();
        let mut process = Process::new(Vec::new());
        process.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), c.clone())]));
        process.params.current_directory = r"C:\agent".into();
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();

        let stat = |p: &std::ffi::CStr| {
            let mut buf = [0xaau8; 36];
            let rc = _stat(p.as_ptr(), buf.as_mut_ptr());
            let u16_at = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]);
            let i32_at = |o: usize| i32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
            (rc, i32_at(0), u16_at(6), u16_at(8), i32_at(20), i32_at(28))
        };

        let (rc, drive, mode, links, size, mtime) = stat(c"OSSEC.CONF");
        assert_eq!((rc, drive, links, size), (0, 2, 1, 10));
        // Read and write for owner, group and other; not executable.
        assert_eq!(mode, S_IFREG | 0x180 | 0x30 | 0x06);
        let host_mtime = std::fs::metadata(c.join("agent/ossec.conf"))
            .unwrap()
            .mtime();
        assert_eq!(mtime as i64, host_mtime);

        let (_, _, mode, ..) = stat(c"agent.exe");
        assert_eq!(mode & 0x49, 0x49, "executable by extension, for all");
        let (rc, _, mode, ..) = stat(c"C:\\agent\\");
        assert_eq!(rc, 0);
        assert_eq!(mode & S_IFDIR, S_IFDIR);
        assert_eq!(mode & S_IEXEC, S_IEXEC);

        assert_eq!(stat(c"missing.conf").0, -1);
        assert_eq!(errno::get(), ENOENT);
        assert_eq!(
            stat(c"ossec.conf\\").0,
            -1,
            "a file with a trailing separator"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
