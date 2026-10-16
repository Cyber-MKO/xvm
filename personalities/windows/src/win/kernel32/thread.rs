//! Thread properties: `GetThreadPriority`, `SetThreadPriority`.
//!
//! Priorities are kept on the thread object and reported back. They are
//! not applied to the host: emulated hosts share the real scheduler.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::error::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, set_last_error};
use super::process::CURRENT_THREAD;
use crate::gap::GapKind;
use crate::handles::Object;
use crate::runtime::{current_thread, with_current};
use crate::sync::ThreadObject;

/// `THREAD_PRIORITY_ERROR_RETURN`.
const PRIORITY_ERROR: i32 = 0x7fff_ffff;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("GetThreadPriority", GetThreadPriority as *const () as u32),
        ("SetThreadPriority", SetThreadPriority as *const () as u32),
    ]
}

/// The thread a handle names: the pseudo-handle or a thread handle.
pub(crate) fn thread_of(handle: u32) -> Option<Arc<ThreadObject>> {
    if handle == CURRENT_THREAD {
        return current_thread();
    }
    with_current(|p| match p.handles.get(handle) {
        Some(Object::Thread(t)) => Some(t.clone()),
        _ => None,
    })
}

#[allow(non_snake_case)]
extern "stdcall" fn GetThreadPriority(handle: u32) -> i32 {
    match thread_of(handle) {
        Some(t) => t.priority.load(Ordering::SeqCst),
        None => {
            set_last_error(ERROR_INVALID_HANDLE);
            PRIORITY_ERROR
        }
    }
}

/// The documented levels: idle (-15), -2 to 2, time critical (15).
/// Background mode values are a logged gap.
#[allow(non_snake_case)]
extern "stdcall" fn SetThreadPriority(handle: u32, priority: i32) -> i32 {
    let Some(t) = thread_of(handle) else {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };
    if !matches!(priority, -15 | -2..=2 | 15) {
        if matches!(priority, 0x1_0000 | 0x2_0000) {
            with_current(|p| {
                p.record_runtime_gap(GapKind::Feature, "kernel32.dll", "thread background mode")
            });
        }
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    t.priority.store(priority, Ordering::SeqCst);
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn priorities_are_kept_per_thread() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        assert_eq!(GetThreadPriority(CURRENT_THREAD), 0);
        assert_eq!(SetThreadPriority(CURRENT_THREAD, 2), 1);
        assert_eq!(GetThreadPriority(CURRENT_THREAD), 2);
        assert_eq!(SetThreadPriority(CURRENT_THREAD, 7), 0);
        assert_eq!(SetThreadPriority(CURRENT_THREAD, 0x1_0000), 0);
        assert_eq!(runtime.lock().gaps().len(), 1);
        assert_eq!(GetThreadPriority(0x1234), PRIORITY_ERROR);
    }
}
