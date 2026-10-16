//! Loading DLLs at run time: `LoadLibraryA/W`, `LoadLibraryExA`,
//! `FreeLibrary`.
//!
//! Search order: modules already loaded, the system DLLs we emulate, the
//! application directory, then the current directory. A name with a path
//! is looked up through the drive table. New modules are mapped under the
//! process lock; then, without it, the agent's `LdrRegisterDllNotification`
//! callbacks run for each, followed by TLS callbacks and `DllMain`,
//! dependencies first.
//!
//! `FreeLibrary` only counts: modules are never unmapped.

use std::ffi::c_char;

use super::error::{ERROR_INVALID_HANDLE, ERROR_MOD_NOT_FOUND, set_last_error};
use crate::gap::GapKind;
use crate::process::{LoadLibraryError, Process};
use crate::runtime::{current, run_init};
use crate::win::text::{ansi, wide};

/// `ERROR_DLL_INIT_FAILED`, from "System Error Codes".
const ERROR_DLL_INIT_FAILED: u32 = 1114;
/// `LDR_DLL_NOTIFICATION_REASON_LOADED`.
const REASON_LOADED: u32 = 1;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("LoadLibraryA", LoadLibraryA as *const () as u32),
        ("LoadLibraryW", LoadLibraryW as *const () as u32),
        ("LoadLibraryExA", LoadLibraryExA as *const () as u32),
        ("FreeLibrary", FreeLibrary as *const () as u32),
    ]
}

/// One loaded-DLL notification: the strings and the
/// `LDR_DLL_NOTIFICATION_DATA` that points at them.
struct Notification {
    _full: Vec<u16>,
    _base: Vec<u16>,
    _strings: Box<[u32; 4]>,
    data: Box<[u32; 5]>,
}

fn notification(p: &Process, index: usize) -> Notification {
    let m = &p.modules()[index];
    let full: Vec<u16> = m
        .windows_path(&p.params)
        .unwrap_or_else(|| m.name.clone())
        .encode_utf16()
        .chain([0])
        .collect();
    let base: Vec<u16> = m.name.encode_utf16().chain([0]).collect();
    // Two UNICODE_STRINGs: { USHORT Length, USHORT MaximumLength, PWSTR }.
    // Length leaves out the NUL that ends each buffer; callers read the
    // buffers as C strings, as they can on Windows.
    let unicode = |s: &Vec<u16>| {
        let bytes = (s.len() as u32 - 1) * 2;
        [bytes | ((bytes + 2) << 16), s.as_ptr() as u32]
    };
    let strings = Box::new({
        let (a, b) = (unicode(&full), unicode(&base));
        [a[0], a[1], b[0], b[1]]
    });
    let data = Box::new([
        0,
        strings.as_ptr() as u32,
        strings.as_ptr() as u32 + 8,
        m.base(),
        m.size_of_image,
    ]);
    Notification {
        _full: full,
        _base: base,
        _strings: strings,
        data,
    }
}

fn load_library(name: Option<String>) -> u32 {
    let Some(name) = name else {
        set_last_error(ERROR_MOD_NOT_FOUND);
        return 0;
    };
    let runtime = current().expect("emulated call from a thread outside any process");
    let (base, notices, callbacks, steps) = {
        let mut p = runtime.lock();
        let before = p.modules().len();
        let index = match p.load_library(&name) {
            Ok(index) => index,
            Err(e) => {
                if matches!(e, LoadLibraryError::NotFound) && !p.is_bundled(&name) {
                    p.record_runtime_gap(GapKind::Module, &name, "*");
                }
                if let LoadLibraryError::Load(e) = e {
                    eprintln!("LoadLibrary {name}: {e}");
                }
                drop(p);
                set_last_error(ERROR_MOD_NOT_FOUND);
                return 0;
            }
        };
        let notices: Vec<Notification> = (before..p.modules().len())
            .filter(|&i| !p.modules()[i].emulated)
            .map(|i| notification(&p, i))
            .collect();
        let callbacks = p.dll_notifications.clone();
        (
            p.modules()[index].base(),
            notices,
            callbacks,
            p.take_pending_init(),
        )
    };
    for notice in &notices {
        for c in &callbacks {
            // SAFETY: VOID CALLBACK LdrDllNotification(ULONG Reason,
            // PCLDR_DLL_NOTIFICATION_DATA Data, PVOID Context).
            let f: extern "stdcall" fn(u32, *const u32, u32) =
                unsafe { std::mem::transmute(c.function as usize) };
            f(REASON_LOADED, notice.data.as_ptr(), c.context);
        }
    }
    for step in &steps {
        // SAFETY: newly committed modules with bound imports, on a thread
        // with a TEB (agent code called us).
        if unsafe { run_init(step) }.is_err() {
            set_last_error(ERROR_DLL_INIT_FAILED);
            return 0;
        }
    }
    base
}

#[allow(non_snake_case)]
extern "stdcall" fn LoadLibraryA(name: *const c_char) -> u32 {
    // SAFETY: a NUL-terminated string (the API's contract).
    load_library(unsafe { ansi(name) })
}

#[allow(non_snake_case)]
extern "stdcall" fn LoadLibraryW(name: *const u16) -> u32 {
    // SAFETY: a NUL-terminated string (the API's contract).
    load_library(unsafe { wide(name) })
}

/// Flags other than 0 are logged as gaps and the DLL is loaded normally.
#[allow(non_snake_case)]
extern "stdcall" fn LoadLibraryExA(name: *const c_char, _file: u32, flags: u32) -> u32 {
    if flags != 0
        && let Some(runtime) = current()
    {
        runtime.lock().record_runtime_gap(
            GapKind::Feature,
            "kernel32.dll",
            &format!("LoadLibraryExA flags 0x{flags:x}"),
        );
    }
    // SAFETY: a NUL-terminated string (the API's contract).
    load_library(unsafe { ansi(name) })
}

#[allow(non_snake_case)]
extern "stdcall" fn FreeLibrary(module: u32) -> i32 {
    let runtime = current().expect("emulated call from a thread outside any process");
    let mut p = runtime.lock();
    match p.module_at_mut(module) {
        Some(m) => {
            m.load_count = m.load_count.saturating_sub(1);
            1
        }
        None => {
            drop(p);
            set_last_error(ERROR_INVALID_HANDLE);
            0
        }
    }
}
