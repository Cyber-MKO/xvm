//! Streams: `_fdopen`, `fgets`, `feof`, `ferror`, `fclose`.
//!
//! A `FILE *` points at a 32-byte block with `msvcrt`'s `_iobuf` layout,
//! with `_flag` and `_file` filled in. Agent code reaches streams only
//! through functions, so the stream's real state is kept beside it, in
//! the process's CRT state.
//!
//! Text mode, from the `_open` and `fopen` pages on Microsoft Learn: on
//! input, CR LF becomes LF and CTRL+Z ends the file.

use std::collections::VecDeque;
use std::ffi::c_char;
use std::io::Read;

use super::errno::{self, EBADF, EINVAL};
use crate::process::{O_TEXT, Process};
use crate::runtime::with_current;
use crate::win::kernel32::file::file_of;
use crate::win::text::ansi;

const O_BINARY: i32 = 0x8000;
const EOF: i32 = -1;
const CTRL_Z: u8 = 0x1a;

// `_iobuf._flag` bits from stdio.h.
const IOREAD: u32 = 0x1;
const IOWRT: u32 = 0x2;
const IORW: u32 = 0x80;

/// The state behind one `FILE *`.
#[derive(Debug)]
pub struct Stream {
    /// The `_iobuf` block agent code holds a pointer to.
    pub block: Box<[u32; 8]>,
    pub fd: i32,
    pub read: bool,
    pub write: bool,
    pub text: bool,
    pub eof: bool,
    pub error: bool,
    /// Bytes read from the descriptor and not yet consumed.
    pub pending: VecDeque<u8>,
    /// A CR at the end of the last read, waiting to see if LF follows.
    pub held_cr: bool,
}

impl Stream {
    pub fn address(&self) -> u32 {
        self.block.as_ptr() as u32
    }
}

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("_fdopen", _fdopen as *const () as u32),
        ("fgets", fgets as *const () as u32),
        ("feof", feof as *const () as u32),
        ("ferror", ferror as *const () as u32),
        ("fclose", fclose as *const () as u32),
    ]
}

struct Mode {
    read: bool,
    write: bool,
    text: Option<bool>,
}

/// Parse an `fopen` mode string: `r`, `w` or `a`, then any of `+`, `t`,
/// `b`, and the hints `c`, `n`, `S`, `R`, `T`, `D`, `N`, which change
/// nothing here.
fn parse_mode(mode: &str) -> Option<Mode> {
    let mut chars = mode.chars();
    let (mut read, mut write) = match chars.next()? {
        'r' => (true, false),
        'w' | 'a' => (false, true),
        _ => return None,
    };
    let mut text = None;
    for c in chars {
        match c {
            '+' => {
                read = true;
                write = true;
            }
            't' => text = Some(true),
            'b' => text = Some(false),
            'c' | 'n' | 'S' | 'R' | 'T' | 'D' | 'N' => {}
            _ => return None,
        }
    }
    Some(Mode { read, write, text })
}

fn stream_mut(p: &mut Process, file: u32) -> Option<&mut Stream> {
    p.crt.streams.iter_mut().find(|s| s.address() == file)
}

/// Opens a stream on descriptor `fd`. Text or binary comes from the mode,
/// else from the descriptor's flags, else from `_fmode`.
extern "C" fn _fdopen(fd: i32, mode: *const c_char) -> u32 {
    // SAFETY: a NUL-terminated string (the function's contract).
    let Some(mode) = unsafe { ansi(mode) }.as_deref().and_then(parse_mode) else {
        errno::set(EINVAL);
        return 0;
    };
    with_current(|p| {
        let Some(entry) = p.crt.fd(fd) else {
            errno::set(EBADF);
            return 0;
        };
        let text = mode.text.unwrap_or(if entry.flags & O_BINARY != 0 {
            false
        } else if entry.flags & O_TEXT != 0 {
            true
        } else {
            *p.crt.fmode & O_BINARY == 0
        });
        let mut block = Box::new([0u32; 8]);
        block[3] = match (mode.read, mode.write) {
            (true, true) => IORW,
            (true, false) => IOREAD,
            _ => IOWRT,
        };
        block[4] = fd as u32;
        let stream = Stream {
            block,
            fd,
            read: mode.read,
            write: mode.write,
            text,
            eof: false,
            error: false,
            pending: VecDeque::new(),
            held_cr: false,
        };
        let address = stream.address();
        p.crt.streams.push(stream);
        address
    })
}

/// Read more bytes into the stream's pending queue, applying text mode.
/// Returns false at the end of the file or on an error.
fn fill(file: u32) -> bool {
    let fd_handle = with_current(|p| {
        let s = stream_mut(p, file)?;
        let fd = s.fd;
        p.crt.fd(fd).map(|e| e.handle)
    });
    let Some(handle) = fd_handle else {
        return false;
    };
    let mut buf = [0u8; 4096];
    let read = match file_of(handle) {
        Ok((f, true, _, false)) => (&*f).read(&mut buf).ok(),
        _ => None,
    };
    with_current(|p| {
        let Some(s) = stream_mut(p, file) else {
            return false;
        };
        match read {
            None => {
                s.error = true;
                false
            }
            Some(0) => {
                if std::mem::take(&mut s.held_cr) {
                    s.pending.push_back(b'\r');
                    return true;
                }
                s.eof = true;
                false
            }
            Some(n) if !s.text => {
                s.pending.extend(&buf[..n]);
                true
            }
            Some(n) => {
                let mut bytes: Vec<u8> = Vec::with_capacity(n + 1);
                if std::mem::take(&mut s.held_cr) {
                    bytes.push(b'\r');
                }
                bytes.extend(&buf[..n]);
                let mut out = Vec::with_capacity(bytes.len());
                let mut i = 0;
                while i < bytes.len() {
                    match bytes[i] {
                        CTRL_Z => {
                            s.eof = true;
                            break;
                        }
                        b'\r' if i + 1 == bytes.len() => s.held_cr = true,
                        b'\r' if bytes[i + 1] == b'\n' => {}
                        b => out.push(b),
                    }
                    i += 1;
                }
                let got = !out.is_empty() || s.held_cr;
                s.pending.extend(out);
                got || !s.eof
            }
        }
    })
}

/// Next byte, or None at the end of the file or on an error.
fn next_byte(file: u32) -> Option<u8> {
    loop {
        let (byte, eof) = with_current(|p| {
            let s = stream_mut(p, file)?;
            Some((s.pending.pop_front(), s.eof))
        })?;
        if let Some(b) = byte {
            return Some(b);
        }
        if eof || !fill(file) {
            return None;
        }
    }
}

/// Reads up to `n - 1` bytes, stopping after a newline. Returns `buf`, or
/// NULL if nothing was read before the end of the file or an error.
extern "C" fn fgets(buf: *mut c_char, n: i32, file: u32) -> *mut c_char {
    let known = with_current(|p| stream_mut(p, file).map(|s| s.read));
    match known {
        None => {
            errno::set(EINVAL);
            return std::ptr::null_mut();
        }
        Some(false) => {
            with_current(|p| stream_mut(p, file).map(|s| s.error = true));
            return std::ptr::null_mut();
        }
        Some(true) if n <= 0 || buf.is_null() => {
            errno::set(EINVAL);
            return std::ptr::null_mut();
        }
        Some(true) => {}
    }
    let mut len = 0usize;
    while len + 1 < n as usize {
        let Some(b) = next_byte(file) else { break };
        // SAFETY: buf holds n bytes (the function's contract).
        unsafe { *buf.add(len) = b as c_char };
        len += 1;
        if b == b'\n' {
            break;
        }
    }
    if len == 0 && n > 1 {
        return std::ptr::null_mut();
    }
    // SAFETY: as above; len < n.
    unsafe { *buf.add(len) = 0 };
    buf
}

extern "C" fn feof(file: u32) -> i32 {
    with_current(|p| stream_mut(p, file).is_some_and(|s| s.eof && s.pending.is_empty())) as i32
}

extern "C" fn ferror(file: u32) -> i32 {
    with_current(|p| stream_mut(p, file).is_some_and(|s| s.error)) as i32
}

/// Closes the stream, its descriptor and the descriptor's OS handle.
/// Returns 0, or EOF if `file` is not an open stream.
extern "C" fn fclose(file: u32) -> i32 {
    with_current(|p| {
        let Some(i) = p.crt.streams.iter().position(|s| s.address() == file) else {
            errno::set(EINVAL);
            return EOF;
        };
        let stream = p.crt.streams.remove(i);
        if let Some(entry) = p.crt.fd(stream.fd) {
            p.crt.fds[stream.fd as usize] = None;
            p.handles.remove(entry.handle);
        }
        0
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handles::{FileObject, Object};
    use crate::process::CrtFd;
    use crate::runtime::Runtime;
    use std::sync::Arc;

    /// A process with `contents` open as descriptor 0.
    fn with_file(tag: &str, contents: &[u8]) -> (Runtime, crate::runtime::Attached, i32) {
        let path = std::env::temp_dir().join(format!("xvm-stdio-{tag}-{}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        let mut process = Process::new(Vec::new());
        let handle = process.handles.insert(Object::File(FileObject {
            file: Arc::new(std::fs::File::open(&path).unwrap()),
            host_path: path.clone(),
            windows_path: r"C:\x".into(),
            can_read: true,
            can_write: false,
            can_delete: false,
            share: 7,
            is_directory: false,
        }));
        std::fs::remove_file(&path).unwrap();
        let fd = process.crt.insert_fd(CrtFd { handle, flags: 0 });
        let runtime = Runtime::new(process);
        let thread = runtime.attach().unwrap();
        (runtime, thread, fd)
    }

    fn lines(file: u32, size: i32) -> Vec<String> {
        let mut out = Vec::new();
        let mut buf = vec![0 as c_char; size as usize];
        while !fgets(buf.as_mut_ptr(), size, file).is_null() {
            // SAFETY: fgets NUL-terminates.
            let line = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
            out.push(line.to_str().unwrap().to_string());
        }
        out
    }

    #[test]
    fn text_mode_turns_crlf_into_lf_and_stops_at_ctrl_z() {
        let (_r, _t, fd) = with_file("text", b"a=1\r\nb=2\r\nlone\rcr\r\n\x1ahidden\n");
        let f = _fdopen(fd, c"rt".as_ptr());
        assert_ne!(f, 0);
        assert_eq!(lines(f, 64), ["a=1\n", "b=2\n", "lone\rcr\n"]);
        assert_eq!(feof(f), 1);
        assert_eq!(ferror(f), 0);
        assert_eq!(fclose(f), 0);
        assert_eq!(fclose(f), EOF);
    }

    #[test]
    fn binary_mode_keeps_bytes_and_short_buffers_split_lines() {
        let (_r, _t, fd) = with_file("bin", b"abcdef\r\nxy");
        let f = _fdopen(fd, c"rb".as_ptr());
        assert_eq!(lines(f, 4), ["abc", "def", "\r\n", "xy"]);
        fclose(f);
    }

    #[test]
    fn default_mode_follows_fmode_and_descriptor_flags() {
        let (runtime, _t, fd) = with_file("fmode", b"x\r\n");
        let f = _fdopen(fd, c"r".as_ptr());
        assert_eq!(lines(f, 16), ["x\n"], "_fmode starts as _O_TEXT");
        assert!(runtime.lock().crt.streams[0].text);
        assert_eq!(_fdopen(fd, c"q".as_ptr()), 0);
        assert_eq!(_fdopen(99, c"r".as_ptr()), 0);
        fclose(f);
        assert!(
            runtime.lock().handles.files().next().is_none(),
            "handle closed too"
        );
    }

    #[test]
    fn crlf_split_across_reads_is_still_one_newline() {
        let mut data = vec![b'a'; 4095];
        data.extend(b"\r\nz\n");
        let (_r, _t, fd) = with_file("split", &data);
        let f = _fdopen(fd, c"r".as_ptr());
        let got = lines(f, 8192);
        assert_eq!(got.len(), 2);
        assert!(got[0].ends_with("a\n") && !got[0].contains('\r'));
        assert_eq!(got[1], "z\n");
        fclose(f);
    }
}
