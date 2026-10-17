//! Streams: `fopen`, `_fdopen`, reading, writing, `fflush`, `fclose`.
//!
//! `stdin`, `stdout` and `stderr` are the first three of the 20 `FILE`s
//! in `msvcrt!_iob`. A service has no standard handles, so they have no
//! descriptor (-2, from the `_fileno` page on Microsoft Learn), and
//! reading or writing them fails.
//!
//! Any other `FILE *` points at a 56-byte `_FILEX` block: the 32-byte `_iobuf`,
//! with `_flag` and `_file` filled in, then the stream's 24-byte
//! `CRITICAL_SECTION`. MinGW's `_lock_file` enters that section at
//! `FILE *` + 32 itself, so it must be there; zeroed, it is a free
//! section. Agent code reaches the rest of a stream only through
//! functions, so the stream's real state is kept beside it, in the
//! process's CRT state.
//!
//! Text mode, from the `_open` and `fopen` pages on Microsoft Learn: on
//! input, CR LF becomes LF and CTRL+Z ends the file; on output, LF
//! becomes CR LF. A descriptor opened with `_O_APPEND` writes at the end
//! of the file.
//!
//! Output is buffered, as in `msvcrt`: bytes reach the file when
//! `_INTERNAL_BUFSIZ` (4096, stdio.h) are waiting, and at `fflush` and
//! `fclose`.

use std::collections::VecDeque;
use std::ffi::c_char;
use std::io::{Read, Seek, SeekFrom, Write};

use super::errno::{self, EACCES, EBADF, EEXIST, EINVAL, ENOENT};
use crate::gap::GapKind;
use crate::process::CrtFd;
use crate::process::{O_TEXT, Process};
use crate::runtime::with_current;
use crate::win::kernel32::file::{self, file_of};
use crate::win::text::ansi;

const O_APPEND: i32 = 0x8;
const O_BINARY: i32 = 0x8000;
const EOF: i32 = -1;
const CTRL_Z: u8 = 0x1a;
const INTERNAL_BUFSIZ: usize = 4096;

// `_iobuf._flag` bits from stdio.h.
const IOREAD: u32 = 0x1;
const IOWRT: u32 = 0x2;
const IORW: u32 = 0x80;

/// `_IOB_ENTRIES` from stdio.h: the number of `FILE`s in `_iob`.
pub(super) const IOB_ENTRIES: u32 = 20;
/// The descriptor of a standard stream without an OS handle.
const NO_DESCRIPTOR: i32 = -2;

/// The state behind one `FILE *`.
#[derive(Debug)]
pub struct Stream {
    /// The `FILE *` agent code holds.
    pub address: u32,
    /// The `_FILEX` block at `address` for streams we open: `_iobuf` in
    /// words 0 to 7, the `CRITICAL_SECTION` in words 8 to 13. None for
    /// the standard streams, which live in `_iob`.
    pub block: Option<Box<[u32; 14]>>,
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
    /// Bytes written and not yet passed to the descriptor.
    pub out: Vec<u8>,
    /// False for `stderr`, which `msvcrt` writes at once.
    pub buffered: bool,
}

/// Fills in `stdin`, `stdout` and `stderr` at the start of `_iob`, which
/// is at `iob` in `msvcrt`'s `.data`.
pub(crate) fn init_standard_streams(p: &mut Process, iob: u32) {
    for i in 0..3u32 {
        let address = iob + 32 * i;
        let read = i == 0;
        let words = [if read { IOREAD } else { IOWRT }, NO_DESCRIPTOR as u32];
        // SAFETY: _iob holds IOB_ENTRIES 32-byte FILEs; _flag and _file
        // are at +12 and +16.
        unsafe { std::ptr::copy_nonoverlapping(words.as_ptr(), (address + 12) as *mut u32, 2) };
        p.crt.streams.push(Stream {
            address,
            block: None,
            fd: NO_DESCRIPTOR,
            read,
            write: !read,
            text: true,
            eof: false,
            error: false,
            pending: VecDeque::new(),
            held_cr: false,
            out: Vec::new(),
            buffered: i != 2,
        });
    }
}

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("fopen", fopen as *const () as u32),
        ("_fdopen", _fdopen as *const () as u32),
        ("fgets", fgets as *const () as u32),
        ("fgetc", fgetc as *const () as u32),
        ("getc", fgetc as *const () as u32),
        ("ungetc", ungetc as *const () as u32),
        ("feof", feof as *const () as u32),
        ("ferror", ferror as *const () as u32),
        ("fputc", fputc as *const () as u32),
        ("putc", fputc as *const () as u32),
        ("fputs", fputs as *const () as u32),
        ("fwrite", fwrite as *const () as u32),
        ("fflush", fflush as *const () as u32),
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
    p.crt.streams.iter_mut().find(|s| s.address == file)
}

/// A stream on descriptor `fd`, or 0 with `errno` set.
fn open_stream(p: &mut Process, fd: i32, mode: &Mode) -> u32 {
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
    let mut block = Box::new([0u32; 14]);
    block[3] = match (mode.read, mode.write) {
        (true, true) => IORW,
        (true, false) => IOREAD,
        _ => IOWRT,
    };
    block[4] = fd as u32;
    let stream = Stream {
        address: block.as_ptr() as u32,
        block: Some(block),
        fd,
        read: mode.read,
        write: mode.write,
        text,
        eof: false,
        error: false,
        pending: VecDeque::new(),
        held_cr: false,
        out: Vec::new(),
        buffered: true,
    };
    let address = stream.address;
    p.crt.streams.push(stream);
    address
}

/// Opens a file as a stream, following the `fopen` page on Microsoft
/// Learn: `r` opens an existing file, `w` creates or truncates, `a`
/// creates or opens and always writes at the end; `+` adds the other
/// direction. Others may read and write it meanwhile (`_SH_DENYNO`).
/// Returns the stream, or NULL with `errno` set.
extern "C" fn fopen(name: *const c_char, mode: *const c_char) -> u32 {
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const SHARE_READ_WRITE: u32 = 3;
    const CREATE_ALWAYS: u32 = 2;
    const OPEN_EXISTING: u32 = 3;
    const OPEN_ALWAYS: u32 = 4;
    // SAFETY: NUL-terminated strings (the function's contract).
    let (name, mode_text) = unsafe { (ansi(name), ansi(mode)) };
    let (Some(name), Some(mode_text)) = (name, mode_text) else {
        errno::set(EINVAL);
        return 0;
    };
    let Some(mode) = parse_mode(&mode_text) else {
        errno::set(EINVAL);
        return 0;
    };
    let append = mode_text.starts_with('a');
    let disposition = match mode_text.chars().next() {
        Some('r') => OPEN_EXISTING,
        Some('w') => CREATE_ALWAYS,
        _ => OPEN_ALWAYS,
    };
    let mut access = 0;
    if mode.read {
        access |= GENERIC_READ;
    }
    if mode.write {
        access |= GENERIC_WRITE;
    }
    let handle = match file::open_handle(&name, access, SHARE_READ_WRITE, disposition) {
        Ok(h) => h,
        Err(code) => {
            errno::set(match code {
                2 | 3 => ENOENT,
                5 | 32 => EACCES,
                80 => EEXIST,
                _ => EINVAL,
            });
            return 0;
        }
    };
    with_current(|p| {
        let mut flags = if append { O_APPEND } else { 0 };
        flags |= match mode.text {
            Some(true) => O_TEXT,
            Some(false) => O_BINARY,
            None => 0,
        };
        let fd = p.crt.insert_fd(CrtFd { handle, flags });
        open_stream(p, fd, &mode)
    })
}

/// Opens a stream on descriptor `fd`. Text or binary comes from the mode,
/// else from the descriptor's flags, else from `_fmode`.
extern "C" fn _fdopen(fd: i32, mode: *const c_char) -> u32 {
    // SAFETY: a NUL-terminated string (the function's contract).
    let Some(mode) = unsafe { ansi(mode) }.as_deref().and_then(parse_mode) else {
        errno::set(EINVAL);
        return 0;
    };
    with_current(|p| open_stream(p, fd, &mode))
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

/// The next byte as an unsigned value, or EOF at the end of the file or
/// on an error. `getc` is the same function.
extern "C" fn fgetc(file: u32) -> i32 {
    let readable = with_current(|p| stream_mut(p, file).map(|s| s.read));
    match readable {
        Some(true) => next_byte(file).map_or(EOF, i32::from),
        Some(false) => {
            with_current(|p| stream_mut(p, file).map(|s| s.error = true));
            EOF
        }
        None => {
            errno::set(EINVAL);
            EOF
        }
    }
}

/// Pushes `c` back so the next read returns it, and clears end of file.
/// Pushing back EOF fails, as the C standard says.
extern "C" fn ungetc(c: i32, file: u32) -> i32 {
    if c == EOF {
        return EOF;
    }
    with_current(|p| match stream_mut(p, file) {
        Some(s) => {
            s.pending.push_front(c as u8);
            s.eof = false;
            c & 0xff
        }
        None => {
            errno::set(EINVAL);
            EOF
        }
    })
}

extern "C" fn feof(file: u32) -> i32 {
    with_current(|p| stream_mut(p, file).is_some_and(|s| s.eof && s.pending.is_empty())) as i32
}

extern "C" fn ferror(file: u32) -> i32 {
    with_current(|p| stream_mut(p, file).is_some_and(|s| s.error)) as i32
}

/// Writes `bytes` to the file behind `handle`.
fn write_handle(handle: u32, flags: i32, text: bool, bytes: &[u8]) -> bool {
    let Ok((file, _, true, false)) = file_of(handle) else {
        return false;
    };
    let mut translated;
    let mut data = bytes;
    if text {
        translated = Vec::with_capacity(bytes.len() + bytes.len() / 16);
        for &b in bytes {
            if b == b'\n' {
                translated.push(b'\r');
            }
            translated.push(b);
        }
        data = &translated;
    }
    let mut f = &*file;
    if flags & O_APPEND != 0 && f.seek(SeekFrom::End(0)).is_err() {
        return false;
    }
    f.write_all(data).is_ok()
}

/// Passes the stream's waiting output to its descriptor, outside the
/// process lock. Returns false on an error, which also sets the stream's
/// error flag.
fn flush(file: u32) -> bool {
    let job = with_current(|p| {
        let s = stream_mut(p, file)?;
        let bytes = std::mem::take(&mut s.out);
        let (fd, text) = (s.fd, s.text);
        Some((bytes, text, p.crt.fd(fd)))
    });
    let Some((bytes, text, entry)) = job else {
        return false;
    };
    if bytes.is_empty() {
        return true;
    }
    let ok = entry.is_some_and(|e| write_handle(e.handle, e.flags, text, &bytes));
    if !ok {
        with_current(|p| stream_mut(p, file).map(|s| s.error = true));
    }
    ok
}

/// Adds `bytes` to the stream's output, flushing a full buffer. Returns
/// false if `file` is not a stream open for writing, or on an error.
fn put(file: u32, bytes: &[u8]) -> bool {
    let full = with_current(|p| match stream_mut(p, file) {
        Some(s) if s.write => {
            s.out.extend_from_slice(bytes);
            Some(!s.buffered || s.out.len() >= INTERNAL_BUFSIZ)
        }
        Some(s) => {
            s.error = true;
            None
        }
        None => {
            errno::set(EINVAL);
            None
        }
    });
    match full {
        Some(true) => flush(file),
        Some(false) => true,
        None => false,
    }
}

/// Writes one byte. Returns it as an unsigned value, or EOF. `putc` is
/// the same function.
extern "C" fn fputc(c: i32, file: u32) -> i32 {
    if put(file, &[c as u8]) { c & 0xff } else { EOF }
}

/// Writes a string without its NUL. Returns 0, or EOF.
extern "C" fn fputs(text: *const c_char, file: u32) -> i32 {
    if text.is_null() {
        errno::set(EINVAL);
        return EOF;
    }
    // SAFETY: a NUL-terminated string (the function's contract).
    let bytes = unsafe { std::ffi::CStr::from_ptr(text) }.to_bytes();
    if put(file, bytes) { 0 } else { EOF }
}

/// Writes `count` items of `size` bytes. Returns how many were written.
extern "C" fn fwrite(buf: *const u8, size: u32, count: u32, file: u32) -> u32 {
    let Some(len) = size.checked_mul(count).filter(|&n| n > 0) else {
        return 0;
    };
    if buf.is_null() {
        errno::set(EINVAL);
        return 0;
    }
    // SAFETY: buf holds size * count bytes (the function's contract).
    let bytes = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    if put(file, bytes) { count } else { 0 }
}

/// Writes the waiting output of every stream. Returns false if a write
/// failed.
pub(super) fn flush_all() -> bool {
    let all: Vec<u32> = with_current(|p| {
        p.crt
            .streams
            .iter()
            .filter(|s| s.write)
            .map(|s| s.address)
            .collect()
    });
    all.into_iter().filter(|&f| !flush(f)).count() == 0
}

/// Writes waiting output; with NULL, for every stream. Returns 0, or EOF
/// if a write failed. `msvcrt` drops an input stream's read-ahead here;
/// that is a logged gap, and the read-ahead is kept.
extern "C" fn fflush(file: u32) -> i32 {
    if file == 0 {
        return if flush_all() { 0 } else { EOF };
    }
    let write = with_current(|p| {
        let write = stream_mut(p, file).map(|s| s.write);
        if write == Some(false) {
            p.record_runtime_gap(GapKind::Feature, "msvcrt.dll", "fflush on an input stream");
        }
        write
    });
    match write {
        Some(true) if !flush(file) => EOF,
        Some(_) => 0,
        None => {
            errno::set(EINVAL);
            EOF
        }
    }
}

/// Writes waiting output, then closes the stream, its descriptor and the
/// descriptor's OS handle. Returns 0, or EOF if `file` is not an open
/// stream or the write failed.
extern "C" fn fclose(file: u32) -> i32 {
    let flushed = flush(file);
    with_current(|p| {
        let Some(i) = p.crt.streams.iter().position(|s| s.address == file) else {
            errno::set(EINVAL);
            return EOF;
        };
        let stream = p.crt.streams.remove(i);
        if let Some(entry) = p.crt.fd(stream.fd) {
            p.crt.fds[stream.fd as usize] = None;
            p.handles.remove(entry.handle);
        }
        if flushed { 0 } else { EOF }
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
    fn fgetc_ungetc_and_end_of_file() {
        let (_r, _t, fd) = with_file("getc", b"ab\r\n");
        let f = _fdopen(fd, c"r".as_ptr());
        assert_eq!(fgetc(f), b'a' as i32);
        assert_eq!(ungetc(b'z' as i32, f), b'z' as i32);
        assert_eq!(fgetc(f), b'z' as i32);
        assert_eq!(fgetc(f), b'b' as i32);
        assert_eq!(fgetc(f), b'\n' as i32, "text mode");
        assert_eq!(fgetc(f), EOF);
        assert_eq!(feof(f), 1);
        assert_eq!(ungetc(0xe9, f), 0xe9);
        assert_eq!(feof(f), 0, "ungetc clears end of file");
        assert_eq!(fgetc(f), 0xe9, "bytes come back unsigned");
        assert_eq!(ungetc(EOF, f), EOF);
        fclose(f);
    }

    #[test]
    fn the_stream_lock_follows_the_iobuf() {
        use crate::win::kernel32::critsec::{
            CriticalSection, EnterCriticalSection, LeaveCriticalSection,
        };
        let (runtime, _t, fd) = with_file("lock", b"x");
        let f = _fdopen(fd, c"r".as_ptr());
        // What MinGW's _lock_file does.
        let cs = (f + 32) as *mut CriticalSection;
        EnterCriticalSection(cs);
        EnterCriticalSection(cs);
        LeaveCriticalSection(cs);
        LeaveCriticalSection(cs);
        let block = *runtime.lock().crt.streams[0]
            .block
            .as_ref()
            .unwrap()
            .clone();
        assert_eq!(block[3], IOREAD);
        assert_eq!(block[4], fd as u32);
        assert_eq!(block[8..], [0; 6], "free again");
        fclose(f);
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

    /// A process with `contents` in a file opened for writing as
    /// descriptor 0, with `flags`. Returns the host path too.
    fn with_output(
        tag: &str,
        contents: &[u8],
        flags: i32,
    ) -> (Runtime, crate::runtime::Attached, i32, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("xvm-stdio-{tag}-{}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let mut process = Process::new(Vec::new());
        let handle = process.handles.insert(Object::File(FileObject {
            file: Arc::new(file),
            host_path: path.clone(),
            windows_path: r"C:\x.log".into(),
            can_read: false,
            can_write: true,
            can_delete: false,
            share: 7,
            is_directory: false,
        }));
        let fd = process.crt.insert_fd(CrtFd { handle, flags });
        let runtime = Runtime::new(process);
        let thread = runtime.attach().unwrap();
        (runtime, thread, fd, path)
    }

    #[test]
    fn text_output_is_buffered_appended_and_gets_crlf() {
        let (_r, _t, fd, path) = with_output("append", b"old\r\n", O_APPEND | O_TEXT);
        let f = _fdopen(fd, c"a".as_ptr());
        assert_eq!(fputc(0x141, f), 0x41, "the byte, unsigned");
        assert_eq!(fputs(c"line\n".as_ptr(), f), 0);
        assert_eq!(fwrite(b"x\ny".as_ptr(), 1, 3, f), 3);
        assert_eq!(fwrite(b"z".as_ptr(), 0, 5, f), 0);
        assert_eq!(std::fs::read(&path).unwrap(), b"old\r\n", "still buffered");
        assert_eq!(fflush(f), 0);
        assert_eq!(std::fs::read(&path).unwrap(), b"old\r\nAline\r\nx\r\ny");
        assert_eq!(fputs(c"!\n".as_ptr(), f), 0);
        assert_eq!(fclose(f), 0, "fclose flushes");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"old\r\nAline\r\nx\r\ny!\r\n"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn binary_output_flushes_a_full_buffer() {
        let (_r, _t, fd, path) = with_output("full", b"", 0);
        let f = _fdopen(fd, c"wb".as_ptr());
        let chunk = [b'\n'; 1000];
        for _ in 0..4 {
            assert_eq!(fwrite(chunk.as_ptr(), 1, 1000, f), 1000);
        }
        assert_eq!(std::fs::read(&path).unwrap().len(), 0);
        assert_eq!(fwrite(chunk.as_ptr(), 100, 1, f), 1);
        assert_eq!(std::fs::read(&path).unwrap(), vec![b'\n'; 4100]);
        assert_eq!(fflush(0), 0, "NULL flushes every stream");
        fclose(f);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn writes_to_input_streams_and_strangers_fail() {
        let (runtime, _t, fd) = with_file("noput", b"x");
        let f = _fdopen(fd, c"r".as_ptr());
        assert_eq!(fputc(b'a' as i32, f), EOF);
        assert_eq!(ferror(f), 1);
        assert_eq!(fputs(c"a".as_ptr(), 0x1234), EOF);
        assert_eq!(errno::get(), EINVAL);
        assert_eq!(fflush(0x1234), EOF);
        assert_eq!(fflush(f), 0);
        assert_eq!(
            runtime.lock().gaps().last().unwrap().symbol,
            "fflush on an input stream"
        );
        assert_eq!(fgetc(f), b'x' as i32, "read-ahead kept");
        fclose(f);
    }

    #[test]
    fn standard_streams_of_a_service_go_nowhere() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let mut iob = vec![0u32; 8 * IOB_ENTRIES as usize];
        let base = iob.as_mut_ptr() as u32;
        init_standard_streams(&mut runtime.lock(), base);
        assert_eq!(iob[3..5], [IOREAD, NO_DESCRIPTOR as u32]);
        assert_eq!(iob[16 + 3..16 + 5], [IOWRT, NO_DESCRIPTOR as u32]);
        let (stdin, stdout, stderr) = (base, base + 32, base + 64);
        assert_eq!(fgetc(stdin), EOF);
        assert_eq!(fputs(c"buffered".as_ptr(), stdout), 0);
        assert_eq!(fflush(stdout), EOF);
        assert_eq!(fputc(b'x' as i32, stderr), EOF, "stderr is unbuffered");
        assert_eq!(ferror(stderr), 1);
    }

    #[test]
    fn fopen_creates_truncates_appends_and_reads() {
        use crate::paths::DriveMap;
        use std::collections::BTreeMap;
        let root = std::env::temp_dir().join(format!("xvm-fopen-{}", std::process::id()));
        std::fs::create_dir_all(root.join("c/agent")).unwrap();
        let mut process = Process::new(Vec::new());
        process.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), root.join("c"))]));
        process.params.current_directory = r"C:\agent".into();
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        let host = root.join("c/agent/state.txt");

        let f = fopen(c"state.txt".as_ptr(), c"w".as_ptr());
        assert_ne!(f, 0);
        fputs(c"one\n".as_ptr(), f);
        assert_eq!(fclose(f), 0);
        assert_eq!(std::fs::read(&host).unwrap(), b"one\r\n");
        let f = fopen(c"C:\\AGENT\\STATE.TXT".as_ptr(), c"a".as_ptr());
        fputs(c"two\n".as_ptr(), f);
        fclose(f);
        let f = fopen(c"state.txt".as_ptr(), c"r".as_ptr());
        assert_eq!(lines(f, 64), ["one\n", "two\n"]);
        fclose(f);
        let f = fopen(c"state.txt".as_ptr(), c"rb".as_ptr());
        assert_eq!(lines(f, 64), ["one\r\n", "two\r\n"]);
        fclose(f);
        let f = fopen(c"state.txt".as_ptr(), c"w".as_ptr());
        fclose(f);
        assert_eq!(std::fs::read(&host).unwrap(), b"", "w truncates");
        assert_eq!(fopen(c"missing.txt".as_ptr(), c"r".as_ptr()), 0);
        assert_eq!(errno::get(), ENOENT);
        assert_eq!(fopen(c"state.txt".as_ptr(), c"q".as_ptr()), 0);
        assert_eq!(errno::get(), EINVAL);
        assert!(
            runtime.lock().handles.files().next().is_none(),
            "all closed"
        );
        std::fs::remove_dir_all(&root).unwrap();
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
