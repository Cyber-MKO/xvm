//! Modules of a process: `EnumProcessModules`.
//!
//! Only the current process is supported. Another process is logged as a
//! gap until the host-state engine provides other processes.

use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::win::kernel32::error::{ERROR_INVALID_HANDLE, set_last_error};
use crate::win::kernel32::process::CURRENT_PROCESS;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("EnumProcessModules", EnumProcessModules as *const () as u32)]
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
