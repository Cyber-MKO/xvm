//! Virtual memory: `VirtualQuery`, `VirtualProtect`.
//!
//! Both work on the pages of mapped images (`crate::memory`), which is
//! what the MinGW start-up code asks about: it makes its own pages
//! writable to apply pseudo-relocations, then restores them. Other
//! addresses, guard pages and caching flags are logged gaps.

use super::error::{ERROR_INVALID_ADDRESS, ERROR_INVALID_PARAMETER, set_last_error};
use crate::gap::GapKind;
use crate::memory::{MEM_COMMIT, PAGE, host_protection};
use crate::runtime::with_current;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("VirtualQuery", VirtualQuery as *const () as u32),
        ("VirtualProtect", VirtualProtect as *const () as u32),
    ]
}

/// Fills a `MEMORY_BASIC_INFORMATION` (28 bytes) for the region around
/// `address`. Returns the bytes written, or 0.
#[allow(non_snake_case)]
extern "stdcall" fn VirtualQuery(address: u32, info: *mut u32, len: u32) -> u32 {
    if len < 28 || info.is_null() {
        set_last_error(super::error::ERROR_BAD_LENGTH);
        return 0;
    }
    let region = with_current(|p| {
        let region = p.memory.region(address);
        if region.is_none() {
            p.record_runtime_gap(
                GapKind::Feature,
                "kernel32.dll",
                "VirtualQuery outside mapped images",
            );
        }
        region
    });
    let Some(r) = region else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let fields = [
        r.base,
        r.info.allocation_base,
        r.info.allocation_protect,
        r.size,
        MEM_COMMIT,
        r.info.protect,
        r.info.kind,
    ];
    // SAFETY: info holds len >= 28 bytes (the API's contract).
    unsafe { std::ptr::copy_nonoverlapping(fields.as_ptr(), info, fields.len()) };
    28
}

/// Changes the protection of whole pages of an image and reports the old
/// protection of the first page.
#[allow(non_snake_case)]
extern "stdcall" fn VirtualProtect(address: u32, size: u32, protect: u32, old: *mut u32) -> i32 {
    let Some(host) = host_protection(protect) else {
        with_current(|p| {
            p.record_runtime_gap(
                GapKind::Feature,
                "kernel32.dll",
                &format!("VirtualProtect to 0x{protect:x}"),
            )
        });
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let result = with_current(|p| {
        let Some(pages) = p.memory.pages_of(address, size) else {
            p.record_runtime_gap(
                GapKind::Feature,
                "kernel32.dll",
                "VirtualProtect outside mapped images",
            );
            return Err(ERROR_INVALID_ADDRESS);
        };
        let mut prot = libc::PROT_NONE;
        if host.read {
            prot |= libc::PROT_READ;
        }
        if host.write {
            prot |= libc::PROT_WRITE;
        }
        if host.execute {
            prot |= libc::PROT_EXEC;
        }
        let start = pages[0] as usize as *mut libc::c_void;
        // SAFETY: the pages belong to an image this process mapped.
        if unsafe { libc::mprotect(start, pages.len() * PAGE as usize, prot) } != 0 {
            return Err(ERROR_INVALID_ADDRESS);
        }
        Ok(p.memory.set_protect(&pages, protect).unwrap_or(0))
    });
    match result {
        Ok(previous) => {
            if !old.is_null() {
                // SAFETY: writable (the API's contract).
                unsafe { *old = previous };
            }
            1
        }
        Err(code) => {
            set_last_error(code);
            0
        }
    }
}
