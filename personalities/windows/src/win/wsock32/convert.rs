//! Byte order and IPv4 text: `htonl`, `htons`, `ntohl`, `ntohs`,
//! `inet_addr`, `inet_ntoa`.
//!
//! Network order is big-endian. `inet_addr` takes the forms on its
//! Microsoft Learn page: `a.b.c.d`, `a.b.c` (the last part 16 bits),
//! `a.b` (24 bits) and `a` (32 bits), each part decimal, octal (leading
//! 0) or hex (leading 0x). Anything else is INADDR_NONE. `inet_ntoa`
//! writes dotted decimal into a buffer of the calling thread, valid until
//! its next call there, as documented.

use std::cell::UnsafeCell;
use std::ffi::c_char;

use crate::win::text::ansi;

const INADDR_NONE: u32 = u32::MAX;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("htonl", htonl as *const () as u32),
        ("htons", htons as *const () as u32),
        ("ntohl", htonl as *const () as u32),
        ("ntohs", htons as *const () as u32),
        ("inet_addr", inet_addr as *const () as u32),
        ("inet_ntoa", inet_ntoa as *const () as u32),
    ]
}

/// The functions `ws2_32.dll` exports under the same names.
pub(crate) fn shared(names: &[&str]) -> Vec<(&'static str, u32)> {
    exports()
        .into_iter()
        .filter(|(n, _)| names.contains(n))
        .collect()
}

/// Also `ntohl`: swapping is its own inverse.
extern "stdcall" fn htonl(v: u32) -> u32 {
    v.to_be()
}

/// Also `ntohs`.
extern "stdcall" fn htons(v: u16) -> u16 {
    v.to_be()
}

fn part(text: &str) -> Option<u32> {
    if text.is_empty() {
        return None;
    }
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return if hex.is_empty() {
            Some(0)
        } else {
            u32::from_str_radix(hex, 16).ok()
        };
    }
    if text.len() > 1 && text.starts_with('0') {
        return u32::from_str_radix(&text[1..], 8).ok();
    }
    text.parse().ok()
}

/// The address in host order, or None.
fn parse(text: &str) -> Option<u32> {
    let parts = text.split('.').map(part).collect::<Option<Vec<u32>>>()?;
    let fits = |v: u32, bits: u32| bits == 32 || v < (1 << bits);
    let (last, head) = parts.split_last()?;
    if head.len() > 3 || head.iter().any(|&p| p > 255) || !fits(*last, 32 - 8 * head.len() as u32) {
        return None;
    }
    Some(
        head.iter()
            .enumerate()
            .fold(*last, |acc, (i, &p)| acc | (p << (24 - 8 * i))),
    )
}

/// The address as stored in an `in_addr` (network order), or
/// INADDR_NONE.
extern "stdcall" fn inet_addr(text: *const c_char) -> u32 {
    // SAFETY: NULL or a NUL-terminated string (the API's contract).
    match unsafe { ansi(text) }.as_deref().and_then(parse) {
        Some(a) => a.to_be(),
        None => INADDR_NONE,
    }
}

thread_local! {
    static TEXT: UnsafeCell<[u8; 16]> = const { UnsafeCell::new([0; 16]) };
}

/// Dotted decimal for an `in_addr` passed by value.
extern "stdcall" fn inet_ntoa(addr: u32) -> *const c_char {
    let [a, b, c, d] = addr.to_ne_bytes();
    let text = format!("{a}.{b}.{c}.{d}");
    TEXT.with(|cell| {
        // SAFETY: this thread's buffer; the text and NUL fit in 16 bytes.
        unsafe {
            let buf = &mut *cell.get();
            buf.fill(0);
            buf[..text.len()].copy_from_slice(text.as_bytes());
        }
        cell.get().cast()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(p: *const c_char) -> String {
        // SAFETY: inet_ntoa's NUL-terminated buffer.
        unsafe { std::ffi::CStr::from_ptr(p) }
            .to_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn byte_order_and_ipv4_text() {
        assert_eq!(htons(0x1234), 0x3412);
        assert_eq!(htonl(0x0102_0304), 0x0403_0201);
        let a = inet_addr(c"192.0.2.11".as_ptr());
        assert_eq!(a.to_ne_bytes(), [192, 0, 2, 11]);
        assert_eq!(text(inet_ntoa(a)), "192.0.2.11");
        assert_eq!(inet_addr(c"10.1".as_ptr()).to_ne_bytes(), [10, 0, 0, 1]);
        assert_eq!(inet_addr(c"0x7f.1".as_ptr()).to_ne_bytes(), [127, 0, 0, 1]);
        assert_eq!(inet_addr(c"010.0.0.1".as_ptr()).to_ne_bytes(), [8, 0, 0, 1]);
        assert_eq!(inet_addr(c"1.2.3.256".as_ptr()), INADDR_NONE);
        assert_eq!(inet_addr(c"1.2.3.4.5".as_ptr()), INADDR_NONE);
        assert_eq!(inet_addr(c"".as_ptr()), INADDR_NONE);
        assert_eq!(inet_addr(c"host".as_ptr()), INADDR_NONE);
        assert_eq!(inet_addr(std::ptr::null()), INADDR_NONE);
    }
}
