//! Error messages: `strerror`.
//!
//! Decision (docs/BRIEF.md): the text is the first sentence of each
//! value's description on the "errno constants" page of Microsoft Learn,
//! until strings from the golden capture replace it as data. Numbers the
//! page does not list get "Unknown error", which is not documented either.
//! The string is in a buffer per thread, as the strerror page says.

use std::cell::UnsafeCell;
use std::ffi::c_char;

const MESSAGES: &[(i32, &str)] = &[
    (1, "Operation not permitted"),
    (2, "No such file or directory"),
    (3, "No such process"),
    (4, "Interrupted function"),
    (5, "I/O error"),
    (6, "No such device or address"),
    (7, "Argument list too long"),
    (8, "Exec format error"),
    (9, "Bad file number"),
    (10, "No spawned processes"),
    (
        11,
        "No more processes or not enough memory or maximum nesting level reached",
    ),
    (
        12,
        "Not enough memory is available for the attempted operation",
    ),
    (13, "Permission denied"),
    (14, "Bad address"),
    (16, "Device or resource busy"),
    (17, "File exists"),
    (18, "Cross-device link"),
    (19, "No such device"),
    (20, "Not a directory"),
    (21, "Is a directory"),
    (22, "Invalid argument"),
    (23, "Too many files open in system"),
    (24, "Too many open files"),
    (25, "Inappropriate I/O control operation"),
    (27, "File too large"),
    (28, "No space left on device"),
    (29, "Invalid seek"),
    (30, "Read-only file system"),
    (31, "Too many links"),
    (32, "Broken pipe"),
    (33, "Math argument"),
    (34, "Result too large"),
    (36, "Resource deadlock would occur"),
    (38, "Filename too long"),
    (39, "No locks available"),
    (40, "Function not supported"),
    (41, "Directory not empty"),
    (
        42,
        "Illegal sequence of bytes (for example, in an MBCS string)",
    ),
    (
        80,
        "A string copy or concatenation resulted in a truncated string",
    ),
    (100, "Address in use"),
    (101, "Address not available"),
    (102, "Address family not supported"),
    (103, "Connection already in progress"),
    (104, "Bad message"),
    (105, "Operation canceled"),
    (106, "Connection aborted"),
    (107, "Connection refused"),
    (108, "Connection reset"),
    (109, "Destination address required"),
    (110, "Host unreachable"),
    (111, "Identifier removed"),
    (112, "Operation in progress"),
    (113, "Already connected"),
    (114, "Too many levels of symbolic links"),
    (115, "Message too long"),
    (116, "Network down"),
    (117, "Network reset"),
    (118, "Network unreachable"),
    (119, "No buffer space"),
    (120, "No message available"),
    (121, "No link"),
    (122, "No message"),
    (123, "No protocol option"),
    (124, "No stream resources"),
    (125, "Not a stream"),
    (126, "Not connected"),
    (127, "State not recoverable"),
    (128, "Not a socket"),
    (129, "Not supported"),
    (130, "Operation not supported"),
    (131, "Other"),
    (132, "Value too large"),
    (133, "Owner dead"),
    (134, "Protocol error"),
    (135, "Protocol not supported"),
    (136, "Wrong protocol type"),
    (137, "Stream timeout"),
    (138, "Timed out"),
    (139, "Text file busy"),
    (140, "Operation would block"),
];

thread_local! {
    static BUFFER: UnsafeCell<[u8; 128]> = const { UnsafeCell::new([0; 128]) };
}

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("strerror", strerror as *const () as u32)]
}

fn message(errnum: i32) -> &'static str {
    MESSAGES
        .iter()
        .find(|m| m.0 == errnum)
        .map_or("Unknown error", |m| m.1)
}

/// The message for `errnum`, in the calling thread's buffer.
extern "C" fn strerror(errnum: i32) -> *mut c_char {
    let text = message(errnum).as_bytes();
    BUFFER.with(|b| {
        let buf = b.get().cast::<u8>();
        // SAFETY: the thread's own buffer; every message is under 128 bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(text.as_ptr(), buf, text.len());
            *buf.add(text.len()) = 0;
        }
        buf.cast()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn text(p: *mut c_char) -> String {
        // SAFETY: strerror returns a NUL-terminated string.
        unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string()
    }

    #[test]
    fn documented_messages_in_a_buffer_per_thread() {
        let first = strerror(2);
        assert_eq!(text(first), "No such file or directory");
        assert_eq!(text(strerror(13)), "Permission denied");
        assert_eq!(first, strerror(0), "one buffer, overwritten");
        assert_eq!(text(first), "Unknown error");
        let other = std::thread::spawn(|| strerror(22) as usize).join().unwrap();
        assert_ne!(other, first as usize);
        assert!(MESSAGES.iter().all(|m| m.1.len() < 128));
    }
}
