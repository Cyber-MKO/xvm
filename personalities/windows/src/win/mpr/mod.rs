//! `mpr.dll`: network connections. `WNetGetConnectionA`.
//!
//! Every drive the host has is a local disk: the launch gives drive
//! folders, and no profile section describes mapped network drives. So,
//! as the WNetGetConnection page on Microsoft Learn says for a local
//! device, the answer is ERROR_NOT_CONNECTED; for a name that is no
//! drive of the host, ERROR_BAD_DEVICE.

use std::ffi::c_char;

use crate::runtime::with_current;
use crate::win::text::ansi;

const ERROR_BAD_DEVICE: u32 = 1200;
const ERROR_NOT_CONNECTED: u32 = 2250;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("WNetGetConnectionA", WNetGetConnectionA as *const () as u32)]
}

/// The remote name behind a local device name such as `C:`.
#[allow(non_snake_case)]
extern "stdcall" fn WNetGetConnectionA(
    local: *const c_char,
    _remote: *mut c_char,
    _len: *mut u32,
) -> u32 {
    // SAFETY: NUL-terminated or NULL (the API's contract).
    let local = unsafe { ansi(local) }.unwrap_or_default();
    let mut chars = local.chars();
    let drive = match (chars.next(), chars.next(), chars.next()) {
        (Some(letter), Some(':'), None) if letter.is_ascii_alphabetic() => Some(letter),
        _ => None,
    };
    let known = drive.is_some_and(|d| with_current(|p| p.params.drives.has_drive(d)));
    if known {
        ERROR_NOT_CONNECTED
    } else {
        ERROR_BAD_DEVICE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::DriveMap;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use std::collections::BTreeMap;

    #[test]
    fn host_drives_are_local() {
        let mut process = Process::new(Vec::new());
        process.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), "/tmp".into())]));
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        let (mut buf, mut len) = ([0 as c_char; 64], 64u32);
        assert_eq!(
            WNetGetConnectionA(c"c:".as_ptr(), buf.as_mut_ptr(), &mut len),
            ERROR_NOT_CONNECTED
        );
        assert_eq!(
            WNetGetConnectionA(c"Z:".as_ptr(), buf.as_mut_ptr(), &mut len),
            ERROR_BAD_DEVICE
        );
        assert_eq!(
            WNetGetConnectionA(c"LPT1".as_ptr(), buf.as_mut_ptr(), &mut len),
            ERROR_BAD_DEVICE
        );
    }
}
