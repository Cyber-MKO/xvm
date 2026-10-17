//! Modules of a process: `EnumProcessModules`, `GetModuleFileNameExW`.
//!
//! Only the current process is supported. Another process is logged as a
//! gap until the host-state engine provides other processes.

use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::win::kernel32::error::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_HANDLE, ERROR_MOD_NOT_FOUND, set_last_error,
};
use crate::win::kernel32::process::CURRENT_PROCESS;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("EnumProcessModules", EnumProcessModules as *const () as u32),
        (
            "GetModuleFileNameExW",
            GetModuleFileNameExW as *const () as u32,
        ),
    ]
}

/// Copies the module's full Windows path (the main module for NULL) and
/// returns the characters copied. A path longer than the buffer is
/// truncated and NUL-terminated, as documented.
#[allow(non_snake_case)]
extern "stdcall" fn GetModuleFileNameExW(
    process: u32,
    module: u32,
    out: *mut u16,
    out_chars: u32,
) -> u32 {
    let path = with_current(|p| {
        if process != CURRENT_PROCESS {
            p.record_runtime_gap(
                GapKind::Feature,
                "psapi.dll",
                "GetModuleFileNameExW of another process",
            );
            return Err(ERROR_INVALID_HANDLE);
        }
        let m = if module == 0 {
            p.main_module()
        } else {
            p.module_at(module)
        };
        let Some(m) = m else {
            return Err(ERROR_INVALID_HANDLE);
        };
        match m.windows_path(&p.params) {
            Some(path) => Ok(path),
            None => {
                p.record_runtime_gap(
                    GapKind::Feature,
                    "psapi.dll",
                    "GetModuleFileNameExW: no system_module_directory in the host profile",
                );
                Err(ERROR_MOD_NOT_FOUND)
            }
        }
    });
    let path = match path {
        Ok(path) => path,
        Err(code) => {
            set_last_error(code);
            return 0;
        }
    };
    if out.is_null() || out_chars == 0 {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    let units: Vec<u16> = path.encode_utf16().collect();
    let n = units.len().min(out_chars as usize - 1);
    // SAFETY: out holds out_chars units (the API's contract).
    unsafe {
        std::ptr::copy_nonoverlapping(units.as_ptr(), out, n);
        *out.add(n) = 0;
    }
    n as u32
}

/// Writes up to `size / 4` module handles, the executable first and then
/// the DLLs in load order, and sets `needed` to the bytes the full list
/// takes. Returns TRUE even when the array was too small, as documented.
#[allow(non_snake_case)]
extern "stdcall" fn EnumProcessModules(
    process: u32,
    modules: *mut u32,
    size: u32,
    needed: *mut u32,
) -> i32 {
    with_current(|p| {
        if process != CURRENT_PROCESS {
            p.record_runtime_gap(
                GapKind::Feature,
                "psapi.dll",
                "EnumProcessModules of another process",
            );
            set_last_error(ERROR_INVALID_HANDLE);
            return 0;
        }
        let main = p.main_module().map(|m| m.base());
        let handles: Vec<u32> = main
            .into_iter()
            .chain(
                p.modules()
                    .iter()
                    .map(|m| m.base())
                    .filter(|&b| Some(b) != main),
            )
            .collect();
        // SAFETY: the caller passes writable memory (the API's contract).
        unsafe {
            if !needed.is_null() {
                *needed = handles.len() as u32 * 4;
            }
            if !modules.is_null() {
                let room = (size / 4) as usize;
                std::ptr::copy_nonoverlapping(handles.as_ptr(), modules, room.min(handles.len()));
            }
        }
        1
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn other_processes_are_a_gap() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let mut needed = 0;
        assert_eq!(
            EnumProcessModules(0x44, std::ptr::null_mut(), 0, &mut needed),
            0
        );
        assert_eq!(runtime.lock().gaps().len(), 1);
        assert_eq!(
            EnumProcessModules(CURRENT_PROCESS, std::ptr::null_mut(), 0, &mut needed),
            1
        );
        assert_eq!(needed, 0);
    }
}
