//! Winsock start-up: `WSAStartup`, `WSACleanup`.
//!
//! A per-process count of `WSAStartup` calls, as the WSAStartup page
//! describes. `WSADATA` (32-bit layout): wVersion, wHighVersion,
//! szDescription[257], szSystemStatus[129], iMaxSockets, iMaxUdpDg,
//! lpVendorInfo.

use crate::runtime::with_current;

// From "Windows Sockets Error Codes" on Microsoft Learn.
pub(crate) const WSANOTINITIALISED: i32 = 10093;
const WSAVERNOTSUPPORTED: i32 = 10092;
const WSAEFAULT: i32 = 10014;

const HIGHEST_VERSION: u16 = 0x0202;
const DESCRIPTION: &[u8] = b"WinSock 2.0";
const STATUS: &[u8] = b"Running";

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("WSAStartup", WSAStartup as *const () as u32),
        ("WSACleanup", WSACleanup as *const () as u32),
    ]
}

/// Returns 0 or an error code (WSAStartup does not use the last error).
/// The version granted is the lower of the requested one and 2.2.
#[allow(non_snake_case)]
extern "stdcall" fn WSAStartup(requested: u16, data: *mut u8) -> i32 {
    let (major, minor) = (requested & 0xff, requested >> 8);
    if major == 0 {
        return WSAVERNOTSUPPORTED;
    }
    if data.is_null() {
        return WSAEFAULT;
    }
    let granted = if (major, minor) > (2, 2) {
        HIGHEST_VERSION
    } else {
        requested
    };
    // SAFETY: data holds a WSADATA (398 bytes; the API's contract).
    unsafe {
        std::ptr::write_bytes(data, 0, 398);
        data.cast::<u16>().write_unaligned(granted);
        data.add(2).cast::<u16>().write_unaligned(HIGHEST_VERSION);
        std::ptr::copy_nonoverlapping(DESCRIPTION.as_ptr(), data.add(4), DESCRIPTION.len());
        std::ptr::copy_nonoverlapping(STATUS.as_ptr(), data.add(261), STATUS.len());
    }
    with_current(|p| p.winsock_starts += 1);
    0
}

/// Returns 0, or SOCKET_ERROR (-1) with WSANOTINITIALISED as the last
/// error when there was no matching `WSAStartup`.
#[allow(non_snake_case)]
extern "stdcall" fn WSACleanup() -> i32 {
    let started = with_current(|p| {
        let started = p.winsock_starts > 0;
        p.winsock_starts = p.winsock_starts.saturating_sub(1);
        started
    });
    if started {
        0
    } else {
        crate::win::kernel32::error::set_last_error(WSANOTINITIALISED as u32);
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn startup_fills_wsadata_and_counts() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let mut data = [0xffu8; 400];
        assert_eq!(WSAStartup(0x0202, data.as_mut_ptr()), 0);
        assert_eq!(u16::from_le_bytes([data[0], data[1]]), 0x0202);
        assert_eq!(u16::from_le_bytes([data[2], data[3]]), 0x0202);
        assert_eq!(&data[4..16], b"WinSock 2.0\0");
        assert_eq!(&data[261..269], b"Running\0");
        assert_eq!(WSAStartup(0x0101, data.as_mut_ptr()), 0);
        assert_eq!(u16::from_le_bytes([data[0], data[1]]), 0x0101);
        assert_eq!(WSAStartup(0x0303, data.as_mut_ptr()), 0);
        assert_eq!(u16::from_le_bytes([data[0], data[1]]), 0x0202);
        assert_eq!(WSAStartup(0x0000, data.as_mut_ptr()), WSAVERNOTSUPPORTED);
        assert_eq!(runtime.lock().winsock_starts, 3);
        for _ in 0..3 {
            assert_eq!(WSACleanup(), 0);
        }
        assert_eq!(WSACleanup(), -1);
    }
}
