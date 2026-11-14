//! System messages and the local heap: `FormatMessageA`, `FormatMessageW`,
//! `LocalAlloc`, `LocalFree`.
//!
//! Following the FormatMessage page on Microsoft Learn, for
//! `FORMAT_MESSAGE_FROM_SYSTEM`. The text of each code comes from the
//! "System Error Codes" and "Windows Sockets Error Codes" pages, as
//! `strerror`'s does from Learn (Decisions, 2026-10-17), until the golden
//! capture provides the strings. Only the codes this personality returns
//! are listed. Any other code fails with ERROR_MR_MID_NOT_FOUND and is a
//! logged gap.
//!
//! | Flag | Behaviour |
//! | --- | --- |
//! | `FORMAT_MESSAGE_ALLOCATE_BUFFER` | The text goes in a `LocalAlloc` block whose address is stored in the buffer argument |
//! | `FORMAT_MESSAGE_IGNORE_INSERTS` | Accepted: these texts have no inserts |
//! | `FORMAT_MESSAGE_MAX_WIDTH_MASK` | 0xff drops the line break; other widths are a logged gap |
//! | `FROM_STRING`, `FROM_HMODULE`, `ARGUMENT_ARRAY` | Logged gaps |
//!
//! Language 0 or English (United States). System messages end with CR LF.
//!
//! `LocalAlloc` and `LocalFree` use host libc's heap. `LMEM_FIXED`, with
//! `LMEM_ZEROINIT`, is all the census callers need; moveable memory is a
//! logged gap.

use super::error::{ERROR_INVALID_PARAMETER, set_last_error};
use crate::gap::GapKind;
use crate::runtime::with_current;

const FORMAT_MESSAGE_ALLOCATE_BUFFER: u32 = 0x100;
const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x200;
const FORMAT_MESSAGE_FROM_STRING: u32 = 0x400;
const FORMAT_MESSAGE_FROM_HMODULE: u32 = 0x800;
const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x1000;
const FORMAT_MESSAGE_ARGUMENT_ARRAY: u32 = 0x2000;
const FORMAT_MESSAGE_MAX_WIDTH_MASK: u32 = 0xff;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_MR_MID_NOT_FOUND: u32 = 317;
const ERROR_RESOURCE_LANG_NOT_FOUND: u32 = 15100;
const LMEM_MOVEABLE: u32 = 0x2;
const LMEM_ZEROINIT: u32 = 0x40;

/// Codes and their text, from the Learn pages named above.
const MESSAGES: &[(u32, &str)] = &[
    (0, "The operation completed successfully."),
    (2, "The system cannot find the file specified."),
    (3, "The system cannot find the path specified."),
    (5, "Access is denied."),
    (6, "The handle is invalid."),
    (
        8,
        "Not enough memory resources are available to process this command.",
    ),
    (18, "There are no more files."),
    (
        24,
        "The program issued a command but the command length is incorrect.",
    ),
    (
        32,
        "The process cannot access the file because it is being used by another process.",
    ),
    (50, "The request is not supported."),
    (87, "The parameter is incorrect."),
    (111, "The file name is too long."),
    (122, "The data area passed to a system call is too small."),
    (126, "The specified module could not be found."),
    (127, "The specified procedure could not be found."),
    (183, "Cannot create a file when that file already exists."),
    (
        203,
        "The system could not find the environment option that was entered.",
    ),
    (234, "More data is available."),
    (259, "No more data is available."),
    (
        10035,
        "A non-blocking socket operation could not be completed immediately.",
    ),
    (
        10038,
        "An operation was attempted on something that is not a socket.",
    ),
    (
        10054,
        "An existing connection was forcibly closed by the remote host.",
    ),
    (
        10060,
        "A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.",
    ),
    (
        10061,
        "No connection could be made because the target machine actively refused it.",
    ),
    (
        10065,
        "A socket operation was attempted to an unreachable host.",
    ),
    (
        10093,
        "Either the application has not called WSAStartup, or WSAStartup failed.",
    ),
];

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("FormatMessageA", FormatMessageA as *const () as u32),
        ("FormatMessageW", FormatMessageW as *const () as u32),
        ("LocalAlloc", LocalAlloc as *const () as u32),
        ("LocalFree", LocalFree as *const () as u32),
    ]
}

fn gap(what: &str) {
    with_current(|p| p.record_runtime_gap(GapKind::Feature, "kernel32.dll", what));
}

/// The text for `code`, or the Win32 error that says why there is none.
fn text(function: &str, flags: u32, code: u32, language: u32) -> Result<String, u32> {
    let unsupported = FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_FROM_HMODULE;
    if flags & FORMAT_MESSAGE_FROM_SYSTEM == 0 || flags & unsupported != 0 {
        gap(&format!(
            "{function}: message sources other than the system"
        ));
        return Err(ERROR_INVALID_PARAMETER);
    }
    if flags & FORMAT_MESSAGE_ARGUMENT_ARRAY != 0 && flags & FORMAT_MESSAGE_IGNORE_INSERTS == 0 {
        gap(&format!("{function}: inserts"));
    }
    // LANG_NEUTRAL with any sublanguage, or English (United States).
    if language & 0x3ff != 0 && language != 0x409 {
        gap(&format!("{function}: language 0x{language:x}"));
        return Err(ERROR_RESOURCE_LANG_NOT_FOUND);
    }
    let Some(&(_, message)) = MESSAGES.iter().find(|(c, _)| *c == code) else {
        gap(&format!("{function}: the text of error {code}"));
        return Err(ERROR_MR_MID_NOT_FOUND);
    };
    Ok(match flags & FORMAT_MESSAGE_MAX_WIDTH_MASK {
        0 => format!("{message}\r\n"),
        FORMAT_MESSAGE_MAX_WIDTH_MASK => message.to_string(),
        width => {
            gap(&format!("{function}: line width {width}"));
            format!("{message}\r\n")
        }
    })
}

/// Stores `units` and a NUL as FormatMessage does. Returns the count
/// without the NUL, or 0 with the last error set.
fn deliver<T: Copy + Default>(flags: u32, units: &[T], buffer: *mut T, size: u32) -> u32 {
    if buffer.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let target = if flags & FORMAT_MESSAGE_ALLOCATE_BUFFER != 0 {
        let count = units.len().max(size as usize) + 1;
        let block = LocalAlloc(LMEM_ZEROINIT, (count * size_of::<T>()) as u32).cast::<T>();
        if block.is_null() {
            set_last_error(8);
            return 0;
        }
        // SAFETY: the buffer argument holds a pointer (the API's contract).
        unsafe { buffer.cast::<*mut T>().write_unaligned(block) };
        block
    } else {
        if units.len() + 1 > size as usize {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        buffer
    };
    // SAFETY: the target holds at least units.len() + 1 elements.
    unsafe {
        std::ptr::copy_nonoverlapping(units.as_ptr(), target, units.len());
        *target.add(units.len()) = T::default();
    }
    units.len() as u32
}

#[allow(non_snake_case)]
extern "stdcall" fn FormatMessageA(
    flags: u32,
    _source: u32,
    code: u32,
    language: u32,
    buffer: *mut u8,
    size: u32,
    _arguments: u32,
) -> u32 {
    match text("FormatMessageA", flags, code, language) {
        // The texts are ASCII, the same in every ANSI code page.
        Ok(t) => deliver(flags, t.as_bytes(), buffer, size),
        Err(e) => {
            set_last_error(e);
            0
        }
    }
}

#[allow(non_snake_case)]
extern "stdcall" fn FormatMessageW(
    flags: u32,
    _source: u32,
    code: u32,
    language: u32,
    buffer: *mut u16,
    size: u32,
    _arguments: u32,
) -> u32 {
    match text("FormatMessageW", flags, code, language) {
        Ok(t) => {
            let units: Vec<u16> = t.encode_utf16().collect();
            deliver(flags, &units, buffer, size)
        }
        Err(e) => {
            set_last_error(e);
            0
        }
    }
}

/// A fixed block of `size` bytes, zeroed with LMEM_ZEROINIT, or NULL.
#[allow(non_snake_case)]
pub(crate) extern "stdcall" fn LocalAlloc(flags: u32, size: u32) -> *mut u8 {
    if flags & LMEM_MOVEABLE != 0 {
        gap("LocalAlloc: moveable memory");
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null_mut();
    }
    // SAFETY: plain allocations.
    unsafe {
        if flags & LMEM_ZEROINIT != 0 {
            libc::calloc(1, size.max(1) as usize).cast()
        } else {
            libc::malloc(size.max(1) as usize).cast()
        }
    }
}

/// Frees a block from `LocalAlloc`. Returns NULL on success, as
/// documented.
#[allow(non_snake_case)]
extern "stdcall" fn LocalFree(block: *mut u8) -> *mut u8 {
    // SAFETY: NULL or a block from LocalAlloc (the API's contract).
    unsafe { libc::free(block.cast()) };
    std::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use crate::win::kernel32::error::GetLastError;

    #[test]
    fn system_messages() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let mut buf = [0u8; 128];
        let n = FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            0,
            2,
            0,
            buf.as_mut_ptr(),
            128,
            0,
        );
        assert_eq!(
            &buf[..n as usize],
            b"The system cannot find the file specified.\r\n"
        );
        assert_eq!(buf[n as usize], 0);

        // An allocated buffer, without the line break.
        let mut block: *mut u8 = std::ptr::null_mut();
        let flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | 0xff;
        let n = FormatMessageA(flags, 0, 10061, 0x409, (&raw mut block).cast(), 0, 0);
        // SAFETY: FormatMessageA allocated n + 1 bytes.
        let got = unsafe { std::slice::from_raw_parts(block, n as usize) };
        assert!(got.starts_with(b"No connection could be made"));
        assert!(!got.ends_with(b"\r\n"));
        assert!(LocalFree(block).is_null());

        let mut wide = [0u16; 64];
        let n = FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM,
            0,
            5,
            0,
            wide.as_mut_ptr(),
            64,
            0,
        );
        assert_eq!(
            String::from_utf16(&wide[..n as usize]).unwrap(),
            "Access is denied.\r\n"
        );

        assert_eq!(
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, 0, 2, 0, buf.as_mut_ptr(), 10, 0),
            0
        );
        assert_eq!(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
        assert_eq!(
            FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM,
                0,
                4242,
                0,
                buf.as_mut_ptr(),
                128,
                0
            ),
            0
        );
        assert_eq!(GetLastError(), ERROR_MR_MID_NOT_FOUND);
        assert_eq!(
            FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM,
                0,
                2,
                0x407,
                buf.as_mut_ptr(),
                128,
                0
            ),
            0
        );
        assert_eq!(GetLastError(), ERROR_RESOURCE_LANG_NOT_FOUND);
        assert_eq!(runtime.lock().gaps().len(), 2);
    }

    #[test]
    fn local_blocks() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let block = LocalAlloc(LMEM_ZEROINIT, 32);
        // SAFETY: 32 bytes just allocated.
        assert!(
            unsafe { std::slice::from_raw_parts(block, 32) }
                .iter()
                .all(|&b| b == 0)
        );
        assert!(LocalFree(block).is_null());
        assert!(LocalFree(std::ptr::null_mut()).is_null());
        assert!(LocalAlloc(LMEM_MOVEABLE, 8).is_null());
        assert_eq!(runtime.lock().gaps().len(), 1);
    }
}
