//! Handle duplication: `DuplicateHandle`.
//!
//! Within the current process only. Real handles of any kind are
//! duplicated, and so is the current-thread pseudo-handle, which becomes
//! a real handle to the calling thread. Duplicating into or from another
//! process, and duplicating the process pseudo-handle, are logged gaps.
//! Access rights are kept as they are: our handles do not carry separate
//! rights.

use super::error::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, set_last_error};
use super::process::{CURRENT_PROCESS, CURRENT_THREAD};
use crate::gap::GapKind;
use crate::handles::Object;
use crate::runtime::{current_thread, with_current};

const DUPLICATE_CLOSE_SOURCE: u32 = 1;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("DuplicateHandle", DuplicateHandle as *const () as u32)]
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn DuplicateHandle(
    source_process: u32,
    source: u32,
    target_process: u32,
    target: *mut u32,
    _access: u32,
    _inherit: i32,
    options: u32,
) -> i32 {
    let result = with_current(|p| {
        if source_process != CURRENT_PROCESS || target_process != CURRENT_PROCESS {
            p.record_runtime_gap(
                GapKind::Feature,
                "kernel32.dll",
                "DuplicateHandle across processes",
            );
            return Err(ERROR_INVALID_HANDLE);
        }
        let object = match source {
            CURRENT_THREAD => Object::Thread(current_thread().ok_or(ERROR_INVALID_HANDLE)?),
            CURRENT_PROCESS => {
                p.record_runtime_gap(
                    GapKind::Feature,
                    "kernel32.dll",
                    "DuplicateHandle of the process",
                );
                return Err(ERROR_INVALID_HANDLE);
            }
            h => p.handles.get(h).cloned().ok_or(ERROR_INVALID_HANDLE)?,
        };
        if options & DUPLICATE_CLOSE_SOURCE != 0 && source != CURRENT_THREAD {
            p.handles.remove(source);
        }
        Ok(p.handles.insert(object))
    });
    match result {
        Ok(handle) if !target.is_null() => {
            // SAFETY: writable (the API's contract).
            unsafe { *target = handle };
            1
        }
        Ok(_) => {
            set_last_error(ERROR_INVALID_PARAMETER);
            0
        }
        Err(code) => {
            set_last_error(code);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use std::sync::Arc;

    #[test]
    fn duplicates_the_current_thread_and_real_handles() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let thread = runtime.attach().unwrap();
        let mut dup = 0;
        assert_eq!(
            DuplicateHandle(
                CURRENT_PROCESS,
                CURRENT_THREAD,
                CURRENT_PROCESS,
                &mut dup,
                0,
                0,
                2
            ),
            1
        );
        match runtime.lock().handles.get(dup) {
            Some(Object::Thread(t)) => assert!(Arc::ptr_eq(t, thread.thread())),
            other => panic!("{other:?}"),
        }

        let mut again = 0;
        assert_eq!(
            DuplicateHandle(
                CURRENT_PROCESS,
                dup,
                CURRENT_PROCESS,
                &mut again,
                0,
                0,
                DUPLICATE_CLOSE_SOURCE
            ),
            1
        );
        assert_ne!(again, dup);
        assert!(runtime.lock().handles.get(dup).is_none(), "source closed");
        assert!(runtime.lock().handles.get(again).is_some());

        assert_eq!(
            DuplicateHandle(
                CURRENT_PROCESS,
                0x1234,
                CURRENT_PROCESS,
                &mut again,
                0,
                0,
                0
            ),
            0
        );
        assert_eq!(
            DuplicateHandle(0x88, CURRENT_THREAD, CURRENT_PROCESS, &mut again, 0, 0, 0),
            0
        );
        assert_eq!(runtime.lock().gaps().len(), 1);
    }
}
