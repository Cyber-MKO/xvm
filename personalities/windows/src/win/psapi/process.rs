//! Process details: `GetProcessImageFileNameA`, `GetProcessMemoryInfo`.
//!
//! Following their Microsoft Learn pages. `GetProcessImageFileNameA`
//! returns the image path in device form (`\Device\HarddiskVolumeN\...`).
//! The host profile does not say which volume device each drive is, so
//! it fails with ERROR_NOT_SUPPORTED, a logged gap. `GetProcessMemoryInfo`
//! fills `PROCESS_MEMORY_COUNTERS` (40 bytes, or 44 for the `_EX` form)
//! with zeros: per-process memory use is not modelled, a logged gap.

use std::ffi::c_char;

use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::win::kernel32::error::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, set_last_error};
use crate::win::kernel32::procinfo::pid_of;

const ERROR_NOT_SUPPORTED: u32 = 50;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        (
            "GetProcessImageFileNameA",
            GetProcessImageFileNameA as *const () as u32,
        ),
        (
            "GetProcessMemoryInfo",
            GetProcessMemoryInfo as *const () as u32,
        ),
    ]
}

fn gap(what: &str) {
    with_current(|p| p.record_runtime_gap(GapKind::Feature, "psapi.dll", what));
}

#[allow(non_snake_case)]
extern "stdcall" fn GetProcessImageFileNameA(handle: u32, _name: *mut c_char, _size: u32) -> u32 {
    if pid_of(handle).is_none() {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    gap("GetProcessImageFileNameA: volume device names are not in the host profile");
    set_last_error(ERROR_NOT_SUPPORTED);
    0
}

#[allow(non_snake_case)]
extern "stdcall" fn GetProcessMemoryInfo(handle: u32, counters: *mut u8, size: u32) -> i32 {
    if pid_of(handle).is_none() {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    if counters.is_null() || size < 40 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    gap("GetProcessMemoryInfo: per-process memory use is not modelled");
    let len = if size >= 44 { 44 } else { 40 };
    // SAFETY: `size` writable bytes (the API's contract).
    unsafe {
        std::ptr::write_bytes(counters, 0, len);
        counters.cast::<u32>().write_unaligned(len as u32);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use crate::win::kernel32::error::GetLastError;

    #[test]
    fn details_not_in_the_profile_are_gaps() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let me = 0xffff_ffff;
        let mut counters = [0xffu8; 44];
        counters[0..4].copy_from_slice(&44u32.to_le_bytes());
        assert_eq!(GetProcessMemoryInfo(me, counters.as_mut_ptr(), 44), 1);
        assert_eq!(u32::from_le_bytes(counters[0..4].try_into().unwrap()), 44);
        assert!(counters[4..].iter().all(|&b| b == 0));
        assert_eq!(GetProcessMemoryInfo(me, counters.as_mut_ptr(), 8), 0);
        let mut name = [0 as c_char; 260];
        assert_eq!(GetProcessImageFileNameA(me, name.as_mut_ptr(), 260), 0);
        assert_eq!(GetLastError(), ERROR_NOT_SUPPORTED);
        assert_eq!(GetProcessMemoryInfo(0x1234, counters.as_mut_ptr(), 44), 0);
        assert_eq!(GetLastError(), ERROR_INVALID_HANDLE);
        assert_eq!(runtime.lock().gaps().len(), 2);
    }
}
