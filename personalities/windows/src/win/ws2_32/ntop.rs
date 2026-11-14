//! Addresses as text and back: `inet_ntop`, `inet_pton`.
//!
//! The agent finds both with `GetProcAddress`; the census records them as
//! run-time lookups. Following its Microsoft Learn page: `AF_INET` (2)
//! gives dotted decimal, `AF_INET6` (23) the RFC 5952 form. It returns
//! the buffer, or NULL with WSAEAFNOSUPPORT for another family and
//! ERROR_INVALID_PARAMETER when the text and its NUL do not fit.
//!
//! `inet_pton` reads the same forms (IPv4 as four decimal parts) and
//! returns 1, 0 for text that is not an address, or -1 with
//! WSAEAFNOSUPPORT or WSAEFAULT.

use std::ffi::c_char;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::win::kernel32::error::{ERROR_INVALID_PARAMETER, set_last_error};

const WSAEAFNOSUPPORT: u32 = 10047;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("inet_ntop", inet_ntop as *const () as u32),
        ("inet_pton", inet_pton as *const () as u32),
    ]
}

extern "stdcall" fn inet_ntop(
    family: i32,
    addr: *const u8,
    buf: *mut c_char,
    size: usize,
) -> *const c_char {
    if addr.is_null() || buf.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null();
    }
    // SAFETY: an in_addr or in6_addr (the API's contract).
    let text = unsafe {
        match family {
            2 => Ipv4Addr::from(addr.cast::<[u8; 4]>().read_unaligned()).to_string(),
            23 => Ipv6Addr::from(addr.cast::<[u8; 16]>().read_unaligned()).to_string(),
            _ => {
                set_last_error(WSAEAFNOSUPPORT);
                return std::ptr::null();
            }
        }
    };
    if text.len() + 1 > size {
        set_last_error(ERROR_INVALID_PARAMETER);
        return std::ptr::null();
    }
    // SAFETY: `size` writable bytes; the text and NUL fit.
    unsafe {
        std::ptr::copy_nonoverlapping(text.as_ptr(), buf.cast::<u8>(), text.len());
        *buf.add(text.len()) = 0;
    }
    buf
}

extern "stdcall" fn inet_pton(family: i32, text: *const c_char, out: *mut u8) -> i32 {
    const WSAEFAULT: u32 = 10014;
    if text.is_null() || out.is_null() {
        set_last_error(WSAEFAULT);
        return -1;
    }
    // SAFETY: a NUL-terminated string (the API's contract).
    let text = unsafe { std::ffi::CStr::from_ptr(text) }
        .to_str()
        .unwrap_or("");
    let bytes: Vec<u8> = match family {
        2 => match text.parse::<Ipv4Addr>() {
            Ok(a) => a.octets().to_vec(),
            Err(_) => return 0,
        },
        23 => match text.parse::<Ipv6Addr>() {
            Ok(a) => a.octets().to_vec(),
            Err(_) => return 0,
        },
        _ => {
            set_last_error(WSAEAFNOSUPPORT);
            return -1;
        }
    };
    // SAFETY: room for an in_addr or in6_addr (the API's contract).
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use crate::win::kernel32::error::GetLastError;

    fn text(family: i32, addr: &[u8], size: usize) -> Option<String> {
        let mut buf = vec![0 as c_char; size.max(1)];
        let r = inet_ntop(family, addr.as_ptr(), buf.as_mut_ptr(), size);
        // SAFETY: inet_ntop wrote a NUL-terminated string.
        (!r.is_null()).then(|| {
            unsafe { std::ffi::CStr::from_ptr(r) }
                .to_str()
                .unwrap()
                .into()
        })
    }

    #[test]
    fn both_families_and_short_buffers() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        assert_eq!(
            text(2, &[192, 168, 1, 78], 16).as_deref(),
            Some("192.168.1.78")
        );
        let mut v6 = [0u8; 16];
        v6[0..2].copy_from_slice(&[0x20, 0x01]);
        v6[2..4].copy_from_slice(&[0x0d, 0xb8]);
        v6[15] = 1;
        assert_eq!(text(23, &v6, 46).as_deref(), Some("2001:db8::1"));
        assert_eq!(text(2, &[192, 168, 1, 78], 12), None, "no room for the NUL");
        assert_eq!(GetLastError(), ERROR_INVALID_PARAMETER);
        assert_eq!(text(17, &[0; 4], 16), None);
        assert_eq!(GetLastError(), WSAEAFNOSUPPORT);
        let mut a = [0u8; 16];
        assert_eq!(inet_pton(2, c"192.168.1.78".as_ptr(), a.as_mut_ptr()), 1);
        assert_eq!(a[..4], [192, 168, 1, 78]);
        assert_eq!(inet_pton(23, c"2001:db8::1".as_ptr(), a.as_mut_ptr()), 1);
        assert_eq!(a, v6);
        assert_eq!(inet_pton(2, c"192.168.1".as_ptr(), a.as_mut_ptr()), 0);
        assert_eq!(inet_pton(2, c"manager".as_ptr(), a.as_mut_ptr()), 0);
        assert_eq!(inet_pton(9, c"1.2.3.4".as_ptr(), a.as_mut_ptr()), -1);
    }
}
