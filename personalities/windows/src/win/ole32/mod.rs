//! `ole32.dll`: COM start-up and object creation. `CoInitializeEx`,
//! `CoUninitialize`, `CoCreateInstance`, `CoSetProxyBlanket`.
//!
//! Following each function's page on Microsoft Learn:
//!
//! | Function | Behaviour |
//! | --- | --- |
//! | `CoInitializeEx` | Per thread: S_OK the first time, S_FALSE after, RPC_E_CHANGED_MODE for another concurrency model |
//! | `CoUninitialize` | Undoes one successful `CoInitializeEx` |
//! | `CoCreateInstance` | Only the WMI locator (`wbem.rs`). Any other class is a logged gap and REGDB_E_CLASSNOTREG |
//! | `CoSetProxyBlanket` | S_OK: our objects are in-process, so there is no proxy to configure |

mod wbem;

use std::cell::Cell;

use crate::com::{self, Guid};
use crate::gap::GapKind;
use crate::runtime::with_current;

pub(crate) const S_OK: u32 = 0;
pub(crate) const S_FALSE: u32 = 1;
pub(crate) const E_NOINTERFACE: u32 = 0x8000_4002;
pub(crate) const E_POINTER: u32 = 0x8000_4003;
pub(crate) const E_OUTOFMEMORY: u32 = 0x8007_000e;
pub(crate) const E_INVALIDARG: u32 = 0x8007_0057;
const RPC_E_CHANGED_MODE: u32 = 0x8001_0106;
const CO_E_NOTINITIALIZED: u32 = 0x8004_01f0;
const REGDB_E_CLASSNOTREG: u32 = 0x8004_0154;
const CLASS_E_NOAGGREGATION: u32 = 0x8004_0110;

pub(crate) const IID_IUNKNOWN: Guid = com::guid("00000000-0000-0000-c000-000000000046");

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("CoInitializeEx", CoInitializeEx as *const () as u32),
        ("CoUninitialize", CoUninitialize as *const () as u32),
        ("CoCreateInstance", CoCreateInstance as *const () as u32),
        ("CoSetProxyBlanket", CoSetProxyBlanket as *const () as u32),
    ]
}

pub(crate) fn gap(what: &str) {
    with_current(|p| p.record_runtime_gap(GapKind::Feature, "ole32.dll", what));
}

thread_local! {
    /// This thread's successful `CoInitializeEx` calls, and its model.
    static INIT: Cell<(u32, u32)> = const { Cell::new((0, 0)) };
}

/// `COINIT_APARTMENTTHREADED` (2) or `COINIT_MULTITHREADED` (0), from
/// the low bits of `flags`.
fn model(flags: u32) -> u32 {
    flags & 0x2
}

#[allow(non_snake_case)]
extern "stdcall" fn CoInitializeEx(_reserved: u32, flags: u32) -> u32 {
    INIT.with(|init| {
        let (count, current) = init.get();
        if count > 0 && current != model(flags) {
            return RPC_E_CHANGED_MODE;
        }
        init.set((count + 1, model(flags)));
        if count == 0 { S_OK } else { S_FALSE }
    })
}

#[allow(non_snake_case)]
extern "stdcall" fn CoUninitialize() {
    INIT.with(|init| {
        let (count, current) = init.get();
        init.set((count.saturating_sub(1), current));
    });
}

/// Creates the class `clsid` and returns its `iid` interface in `*out`.
#[allow(non_snake_case)]
extern "stdcall" fn CoCreateInstance(
    clsid: *const u8,
    outer: u32,
    _context: u32,
    iid: *const u8,
    out: *mut u32,
) -> u32 {
    if out.is_null() {
        return E_POINTER;
    }
    // SAFETY: writable (the API's contract).
    unsafe { *out = 0 };
    // SAFETY: NULL or 16-byte GUIDs (the API's contract).
    let (Some(clsid), Some(iid)) = (unsafe { com::read_guid(clsid) }, unsafe {
        com::read_guid(iid)
    }) else {
        return E_INVALIDARG;
    };
    if INIT.with(|i| i.get().0) == 0 {
        return CO_E_NOTINITIALIZED;
    }
    if clsid != wbem::CLSID_WBEM_LOCATOR {
        gap(&format!(
            "CoCreateInstance of class {{{}}}",
            com::guid_text(&clsid)
        ));
        return REGDB_E_CLASSNOTREG;
    }
    if outer != 0 {
        return CLASS_E_NOAGGREGATION;
    }
    match wbem::locator(&iid) {
        Ok(object) => {
            // SAFETY: writable (checked above).
            unsafe { *out = object };
            S_OK
        }
        Err(hr) => hr,
    }
}

/// Our objects run in-process, so there is no proxy whose security
/// needs setting.
#[allow(non_snake_case)]
extern "stdcall" fn CoSetProxyBlanket(
    proxy: u32,
    _authn: u32,
    _authz: u32,
    _principal: u32,
    _level: u32,
    _impersonation: u32,
    _identity: u32,
    _capabilities: u32,
) -> u32 {
    if proxy == 0 { E_INVALIDARG } else { S_OK }
}

#[cfg(test)]
mod tests;
