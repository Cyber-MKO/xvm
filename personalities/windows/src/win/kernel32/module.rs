//! Module handles and exports: `GetModuleHandleA/W`, `GetModuleHandleExW`,
//! `GetProcAddress`.
//!
//! An `HMODULE` is the module's base address, as on Windows.
//!
//! `GetModuleHandleExW` follows its page on Microsoft Learn: the module
//! is named, or with `GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS` found by an
//! address inside it. It counts as a `LoadLibrary` unless
//! `..._UNCHANGED_REFCOUNT` is given. Modules are never unmapped, so
//! `..._PIN` changes nothing that can be seen.

use std::ffi::c_char;

use super::error::{
    ERROR_INVALID_HANDLE, ERROR_MOD_NOT_FOUND, ERROR_PROC_NOT_FOUND, set_last_error,
};
use crate::gap::GapKind;
use crate::image::Symbol;
use crate::process::Process;
use crate::runtime::with_current;
use crate::win::text::{ansi, wide};

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("GetModuleHandleA", GetModuleHandleA as *const () as u32),
        ("GetModuleHandleW", GetModuleHandleW as *const () as u32),
        ("GetModuleHandleExW", GetModuleHandleExW as *const () as u32),
        ("GetProcAddress", GetProcAddress as *const () as u32),
    ]
}

/// NULL asks for the main module. A miss is the right answer for a bundled
/// DLL that is not loaded yet; any other miss is a DLL we do not provide,
/// which Windows would have, so it is logged as a gap.
fn module_handle(p: &mut Process, name: Option<String>) -> u32 {
    if let Some(base) = p.module_handle(name.as_deref()) {
        return base;
    }
    if let Some(name) = name
        && !p.is_bundled(&name)
    {
        p.record_runtime_gap(GapKind::Module, &name, "*");
    }
    set_last_error(ERROR_MOD_NOT_FOUND);
    0
}

#[allow(non_snake_case)]
extern "stdcall" fn GetModuleHandleA(name: *const c_char) -> u32 {
    // SAFETY: NULL or a NUL-terminated string (the API's contract).
    let name = unsafe { ansi(name) };
    with_current(|p| module_handle(p, name))
}

#[allow(non_snake_case)]
extern "stdcall" fn GetModuleHandleW(name: *const u16) -> u32 {
    // SAFETY: NULL or a NUL-terminated string (the API's contract).
    let name = unsafe { wide(name) };
    with_current(|p| module_handle(p, name))
}

const FLAG_PIN: u32 = 0x1;
const FLAG_UNCHANGED_REFCOUNT: u32 = 0x2;
const FLAG_FROM_ADDRESS: u32 = 0x4;

/// Stores the module's handle in `*module` and returns TRUE, or stores
/// NULL and returns FALSE.
#[allow(non_snake_case)]
extern "stdcall" fn GetModuleHandleExW(flags: u32, name: *const u16, module: *mut u32) -> i32 {
    if module.is_null()
        || flags & !(FLAG_PIN | FLAG_UNCHANGED_REFCOUNT | FLAG_FROM_ADDRESS) != 0
        || flags & (FLAG_PIN | FLAG_UNCHANGED_REFCOUNT) == FLAG_PIN | FLAG_UNCHANGED_REFCOUNT
    {
        if !module.is_null() {
            // SAFETY: writable (the API's contract).
            unsafe { *module = 0 };
        }
        set_last_error(super::error::ERROR_INVALID_PARAMETER);
        return 0;
    }
    let base = with_current(|p| {
        let base = if flags & FLAG_FROM_ADDRESS != 0 {
            let found = p.module_containing(name as u32).map(|m| m.base());
            if found.is_none() {
                set_last_error(ERROR_MOD_NOT_FOUND);
            }
            found.unwrap_or(0)
        } else {
            // SAFETY: NULL or a NUL-terminated string (the API's contract).
            module_handle(p, unsafe { wide(name) })
        };
        if base != 0
            && flags & FLAG_UNCHANGED_REFCOUNT == 0
            && let Some(m) = p.module_at_mut(base)
        {
            m.load_count += 1;
        }
        base
    });
    // SAFETY: writable (the API's contract).
    unsafe { *module = base };
    i32::from(base != 0)
}

/// `name` is an export name, or an ordinal in its low word when its high
/// word is zero. A miss in an emulated module is logged as a gap; a miss
/// in an agent's own DLL is ordinary behaviour.
#[allow(non_snake_case)]
extern "stdcall" fn GetProcAddress(module: u32, name: *const c_char) -> u32 {
    let symbol = if (name as u32) >> 16 == 0 {
        Symbol::Ordinal(name as u32 as u16)
    } else {
        Symbol::Name {
            hint: 0,
            // SAFETY: a NUL-terminated string when the high word is set.
            name: unsafe { ansi(name) }.unwrap_or_default(),
        }
    };
    with_current(|p| {
        let Some(m) = p.module_at(module) else {
            set_last_error(ERROR_INVALID_HANDLE);
            return 0;
        };
        let (dll, emulated) = (m.name.clone(), m.emulated);
        match p.proc_address(module, &symbol) {
            Some(address) => address,
            None => {
                if emulated {
                    p.record_runtime_gap(GapKind::ProcAddress, &dll, &symbol.to_string());
                }
                set_last_error(ERROR_PROC_NOT_FOUND);
                0
            }
        }
    })
}
