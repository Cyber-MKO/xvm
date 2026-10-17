//! Low-level I/O on file descriptors: `_open_osfhandle`,
//! `_get_osfhandle`, `_filelengthi64`, `_read`.
//!
//! A descriptor wraps an OS handle and its `_O_*` flags. Descriptors 0 to
//! 2 are the standard handles when the process has them; a service has
//! none, so its first descriptor can be 0, as with `msvcrt`.
//!
//! `_read` in text mode follows the `_read` page on Microsoft Learn: each
//! CR LF pair becomes LF, and CTRL+Z ends the file. A CR at the end of a
//! read is checked against the next byte, which is put back when it is
//! not LF.

use std::io::{Read, Seek, SeekFrom};

use super::errno::{self, EBADF, EINVAL, EMFILE};
use crate::process::{CrtFd, O_TEXT, Process};
use crate::runtime::with_current;
use crate::win::kernel32::file::file_of;

const O_BINARY: i32 = 0x8000;
const CTRL_Z: u8 = 0x1a;

/// `msvcrt` allows 2048 descriptors.
const MAX_FDS: usize = 2048;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("_open_osfhandle", _open_osfhandle as *const () as u32),
        ("_get_osfhandle", _get_osfhandle as *const () as u32),
        ("_filelengthi64", _filelengthi64 as *const () as u32),
        ("_read", _read as *const () as u32),
    ]
}

/// The OS handle behind descriptor `fd`, or -1 with EBADF.
extern "C" fn _get_osfhandle(fd: i32) -> isize {
    match with_current(|p| p.crt.fd(fd)) {
        Some(entry) => entry.handle as isize,
        None => {
            errno::set(EBADF);
            -1
        }
    }
}

/// The length in bytes of the file behind descriptor `fd`, or -1 with
/// EBADF.
extern "C" fn _filelengthi64(fd: i32) -> i64 {
    let length = with_current(|p| p.crt.fd(fd))
        .and_then(|entry| file_of(entry.handle).ok())
        .and_then(|(file, ..)| file.metadata().ok())
        .map(|meta| meta.len() as i64);
    length.unwrap_or_else(|| {
        errno::set(EBADF);
        -1
    })
}

/// Whether descriptor flags mean text mode: `_O_BINARY`, `_O_TEXT`, else
/// the process's `_fmode`.
pub(super) fn is_text(p: &Process, flags: i32) -> bool {
    if flags & O_BINARY != 0 {
        false
    } else if flags & O_TEXT != 0 {
        true
    } else {
        *p.crt.fmode & O_BINARY == 0
    }
}

/// Reads up to `count` bytes from descriptor `fd` into `buf`. Returns the
/// number of bytes stored, 0 at the end of the file, or -1 with `errno`
/// set.
extern "C" fn _read(fd: i32, buf: *mut u8, count: u32) -> i32 {
    let Some((handle, text)) = with_current(|p| {
        let entry = p.crt.fd(fd)?;
        Some((entry.handle, is_text(p, entry.flags)))
    }) else {
        errno::set(EBADF);
        return -1;
    };
    if buf.is_null() || count > i32::MAX as u32 {
        errno::set(EINVAL);
        return -1;
    }
    let Ok((file, true, _, false)) = file_of(handle) else {
        errno::set(EBADF);
        return -1;
    };
    // SAFETY: `count` writable bytes (the function's contract).
    let out = unsafe { std::slice::from_raw_parts_mut(buf, count as usize) };
    let mut f = &*file;
    let Ok(n) = f.read(out) else {
        errno::set(EBADF);
        return -1;
    };
    if !text {
        return n as i32;
    }
    let mut kept = 0;
    let mut i = 0;
    while i < n {
        match out[i] {
            CTRL_Z => {
                // The rest of the file is not text: leave it unread.
                let _ = f.seek(SeekFrom::Current(i as i64 - n as i64));
                return kept as i32;
            }
            b'\r' if i + 1 < n && out[i + 1] == b'\n' => {}
            b'\r' if i + 1 == n => {
                let mut next = [0u8; 1];
                match f.read(&mut next) {
                    Ok(1) if next[0] == b'\n' => {
                        out[kept] = b'\n';
                        return kept as i32 + 1;
                    }
                    Ok(1) => {
                        let _ = f.seek(SeekFrom::Current(-1));
                    }
                    _ => {}
                }
                out[kept] = b'\r';
                kept += 1;
            }
            b => {
                out[kept] = b;
                kept += 1;
            }
        }
        i += 1;
    }
    kept as i32
}

/// Wraps `handle` in the lowest free descriptor. Returns it, or -1 with
/// `errno` set.
extern "C" fn _open_osfhandle(handle: isize, flags: i32) -> i32 {
    let handle = handle as u32;
    if handle == 0 || handle == u32::MAX {
        errno::set(EBADF);
        return -1;
    }
    with_current(|p| {
        if p.crt.fds.iter().flatten().count() >= MAX_FDS {
            errno::set(EMFILE);
            return -1;
        }
        p.crt.insert_fd(CrtFd { handle, flags })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn descriptors_start_at_the_lowest_free_one() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        assert_eq!(_open_osfhandle(0x40, 0x4000), 0);
        assert_eq!(_open_osfhandle(0x44, 0x8000), 1);
        runtime.lock().crt.fds[0] = None;
        assert_eq!(_open_osfhandle(0x48, 0), 0);
        assert_eq!(
            runtime.lock().crt.fd(1),
            Some(CrtFd {
                handle: 0x44,
                flags: 0x8000
            })
        );
        assert_eq!(_get_osfhandle(1), 0x44);
        assert_eq!(_get_osfhandle(7), -1);
        assert_eq!(_open_osfhandle(-1, 0), -1);
        assert_eq!(errno::get(), EBADF);
    }

    /// Descriptor 0 on a file holding `contents`, with `flags`.
    fn with_file(tag: &str, contents: &[u8], flags: i32) -> (Runtime, crate::runtime::Attached) {
        use crate::handles::FileObject;
        use crate::handles::Object;
        let path = std::env::temp_dir().join(format!("xvm-lowio-{tag}-{}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        let mut process = Process::new(Vec::new());
        let handle = process.handles.insert(Object::File(FileObject {
            file: std::sync::Arc::new(std::fs::File::open(&path).unwrap()),
            host_path: path.clone(),
            windows_path: r"C:\x".into(),
            can_read: true,
            can_write: false,
            can_delete: false,
            share: 7,
            is_directory: false,
            overlapped: false,
        }));
        std::fs::remove_file(&path).unwrap();
        process.crt.insert_fd(CrtFd { handle, flags });
        let runtime = Runtime::new(process);
        let thread = runtime.attach().unwrap();
        (runtime, thread)
    }

    fn read_all(chunk: u32) -> Vec<u8> {
        let mut all = Vec::new();
        let mut buf = vec![0u8; chunk as usize];
        loop {
            let n = _read(0, buf.as_mut_ptr(), chunk);
            assert!(n >= 0);
            if n == 0 {
                return all;
            }
            all.extend(&buf[..n as usize]);
        }
    }

    #[test]
    fn read_in_text_mode_joins_crlf_and_stops_at_ctrl_z() {
        {
            let _host = with_file("text", b"a\r\nb\rc\r\n\x1ahidden", O_TEXT);
            assert_eq!(_filelengthi64(0), 15);
            assert_eq!(read_all(2), b"a\nb\rc\n");
        }
        let _host = with_file("binary", b"a\r\n\x1az", O_BINARY);
        assert_eq!(read_all(3), b"a\r\n\x1az");
        assert_eq!(_read(5, std::ptr::null_mut(), 1), -1);
        assert_eq!(_filelengthi64(5), -1);
        assert_eq!(errno::get(), EBADF);
    }
}
