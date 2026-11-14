//! `wtsapi32.dll`: Remote Desktop sessions. `WTSEnumerateSessionsW`,
//! `WTSQuerySessionInformationW`, `WTSFreeMemory`.
//!
//! Kasim decided (2026-11-14) that only session 0, the services session
//! every Windows has, exists until scenarios model logons. It is named
//! "Services" and is disconnected, as session 0 shows on Windows.
//! Interactive sessions are a logged gap. Only the local server
//! (`WTS_CURRENT_SERVER_HANDLE`) is answered.

use crate::gap::GapKind;
use crate::runtime::with_current;

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NOT_SUPPORTED: u32 = 50;
const WTS_DISCONNECTED: u32 = 4;
const STATION: &str = "Services";

// WTS_INFO_CLASS values from the WTSQuerySessionInformation page.
const WTS_SESSION_ID: u32 = 4;
const WTS_USER_NAME: u32 = 5;
const WTS_WIN_STATION_NAME: u32 = 6;
const WTS_DOMAIN_NAME: u32 = 7;
const WTS_CONNECT_STATE: u32 = 8;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        (
            "WTSEnumerateSessionsW",
            WTSEnumerateSessionsW as *const () as u32,
        ),
        (
            "WTSQuerySessionInformationW",
            WTSQuerySessionInformationW as *const () as u32,
        ),
        ("WTSFreeMemory", WTSFreeMemory as *const () as u32),
    ]
}

fn gap(what: &str) {
    with_current(|p| p.record_runtime_gap(GapKind::Feature, "wtsapi32.dll", what));
}

fn fail(code: u32) -> i32 {
    crate::win::kernel32::error::set_last_error(code);
    0
}

/// A block with `head` followed by UTF-16 `text`; returns the block and
/// the text's address.
fn block(head: &[u8], text: &str) -> (*mut u8, u32) {
    let units: Vec<u8> = text
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    // SAFETY: a plain allocation; freed by WTSFreeMemory.
    let base = unsafe { libc::calloc(1, head.len() + units.len()) }.cast::<u8>();
    if base.is_null() {
        return (base, 0);
    }
    // SAFETY: the block holds both parts.
    unsafe {
        std::ptr::copy_nonoverlapping(head.as_ptr(), base, head.len());
        std::ptr::copy_nonoverlapping(units.as_ptr(), base.add(head.len()), units.len());
    }
    (base, base as u32 + head.len() as u32)
}

/// One `WTS_SESSION_INFOW` (12 bytes): id, station name, state.
#[allow(non_snake_case)]
extern "stdcall" fn WTSEnumerateSessionsW(
    server: u32,
    reserved: u32,
    version: u32,
    out: *mut u32,
    count: *mut u32,
) -> i32 {
    if server != 0 {
        gap("WTSEnumerateSessionsW on another server");
        return fail(ERROR_NOT_SUPPORTED);
    }
    if reserved != 0 || version != 1 || out.is_null() || count.is_null() {
        return fail(ERROR_INVALID_PARAMETER);
    }
    gap("WTSEnumerateSessionsW: interactive sessions are not modelled");
    let (base, name) = block(&[0u8; 12], STATION);
    if base.is_null() {
        return fail(8);
    }
    // SAFETY: the 12-byte record at the start of the block; out and count
    // are writable (the API's contract).
    unsafe {
        base.add(4).cast::<u32>().write_unaligned(name);
        base.add(8).cast::<u32>().write_unaligned(WTS_DISCONNECTED);
        *out = base as u32;
        *count = 1;
    }
    1
}

#[allow(non_snake_case)]
extern "stdcall" fn WTSQuerySessionInformationW(
    server: u32,
    session: u32,
    class: u32,
    out: *mut u32,
    returned: *mut u32,
) -> i32 {
    if server != 0 {
        gap("WTSQuerySessionInformationW on another server");
        return fail(ERROR_NOT_SUPPORTED);
    }
    if out.is_null() || returned.is_null() {
        return fail(ERROR_INVALID_PARAMETER);
    }
    if session != 0 {
        gap("WTSQuerySessionInformationW: interactive sessions are not modelled");
        return fail(ERROR_INVALID_PARAMETER);
    }
    let (base, size) = match class {
        WTS_SESSION_ID | WTS_CONNECT_STATE => {
            let v = if class == WTS_SESSION_ID {
                0
            } else {
                WTS_DISCONNECTED
            };
            let (b, _) = block(&v.to_le_bytes(), "");
            (b, 4)
        }
        WTS_USER_NAME | WTS_DOMAIN_NAME => (block(&[], "").0, 2),
        WTS_WIN_STATION_NAME => (block(&[], STATION).0, (STATION.len() as u32 + 1) * 2),
        _ => {
            gap(&format!("WTSQuerySessionInformationW class {class}"));
            return fail(ERROR_NOT_SUPPORTED);
        }
    };
    if base.is_null() {
        return fail(8);
    }
    // SAFETY: writable (checked above).
    unsafe {
        *out = base as u32;
        *returned = size;
    }
    1
}

#[allow(non_snake_case)]
extern "stdcall" fn WTSFreeMemory(p: u32) {
    // SAFETY: NULL or a block from the functions above.
    unsafe { libc::free(p as usize as *mut libc::c_void) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use crate::win::text::wide;

    #[test]
    fn only_the_services_session() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let (mut list, mut count) = (0u32, 0u32);
        assert_eq!(WTSEnumerateSessionsW(0, 0, 1, &mut list, &mut count), 1);
        assert_eq!(count, 1);
        // SAFETY: one WTS_SESSION_INFOW.
        let (id, name, state) = unsafe {
            let p = list as usize as *const u32;
            (*p, *p.add(1), *p.add(2))
        };
        // SAFETY: a NUL-terminated string inside the block.
        let name = unsafe { wide(name as usize as *const u16) }.unwrap();
        assert_eq!(
            (id, name.as_str(), state),
            (0, "Services", WTS_DISCONNECTED)
        );
        WTSFreeMemory(list);

        let (mut buf, mut size) = (0u32, 0u32);
        assert_eq!(
            WTSQuerySessionInformationW(0, 0, WTS_USER_NAME, &mut buf, &mut size),
            1
        );
        // SAFETY: as above.
        assert_eq!(
            unsafe { wide(buf as usize as *const u16) }.as_deref(),
            Some("")
        );
        WTSFreeMemory(buf);
        assert_eq!(
            WTSQuerySessionInformationW(0, 0, WTS_CONNECT_STATE, &mut buf, &mut size),
            1
        );
        // SAFETY: a DWORD.
        assert_eq!(
            (unsafe { *(buf as usize as *const u32) }, size),
            (WTS_DISCONNECTED, 4)
        );
        WTSFreeMemory(buf);
        assert_eq!(
            WTSQuerySessionInformationW(0, 1, WTS_USER_NAME, &mut buf, &mut size),
            0
        );
        assert_eq!(
            WTSQuerySessionInformationW(0, 0, 99, &mut buf, &mut size),
            0
        );
        assert_eq!(runtime.lock().gaps().len(), 3);
    }
}
