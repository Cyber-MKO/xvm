//! Threads: `CreateThread`, `GetThreadPriority`, `SetThreadPriority`.
//!
//! `CreateThread` runs the start routine on a new host thread with its own
//! TEB, through `Runtime::spawn_thread`, so modules see the thread attach
//! and detach. The routine's return value is the exit code. Security
//! attributes and `CREATE_SUSPENDED` are logged gaps.
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
        ("CreateThread", CreateThread as *const () as u32),
        ("GetThreadPriority", GetThreadPriority as *const () as u32),
        ("SetThreadPriority", SetThreadPriority as *const () as u32),
    ]
}

const CREATE_SUSPENDED: u32 = 0x4;
const STACK_SIZE_PARAM_IS_A_RESERVATION: u32 = 0x1_0000;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;

fn gap(what: &str) {
    with_current(|p| p.record_runtime_gap(GapKind::Feature, "kernel32.dll", what));
}

/// Starts `start(parameter)` on a new thread. Returns a handle to it and
/// writes its ID to `thread_id` when that is not NULL; NULL on failure.
#[allow(non_snake_case)]
extern "stdcall" fn CreateThread(
    attributes: u32,
    stack_size: u32,
    start: u32,
    parameter: u32,
    flags: u32,
    thread_id: *mut u32,
) -> u32 {
    if start == 0 || flags & !(CREATE_SUSPENDED | STACK_SIZE_PARAM_IS_A_RESERVATION) != 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if attributes != 0 {
        gap("CreateThread security attributes");
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if flags & CREATE_SUSPENDED != 0 {
        gap("CreateThread CREATE_SUSPENDED");
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let Some(runtime) = crate::runtime::current() else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let spawned = runtime.spawn_thread(stack_size as usize, move || {
        // SAFETY: DWORD WINAPI ThreadProc(LPVOID), given by the caller.
        let f: extern "stdcall" fn(u32) -> u32 = unsafe { std::mem::transmute(start as usize) };
        f(parameter)
    });
    let Ok((_, thread)) = spawned else {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    };
    if !thread_id.is_null() {
        // SAFETY: writable (the API's contract).
        unsafe { *thread_id = thread.id };
    }
    with_current(|p| p.handles.insert(Object::Thread(thread)))
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

    static SEEN_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    extern "stdcall" fn routine(parameter: u32) -> u32 {
        SEEN_ID.store(
            super::super::process::GetCurrentThreadId(),
            Ordering::SeqCst,
        );
        parameter + 1
    }

    #[test]
    fn create_thread_runs_the_routine_and_keeps_its_exit_code() {
        use super::super::sync::WaitForSingleObject;
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let mut id = 0;
        let handle = CreateThread(0, 0, routine as *const () as u32, 41, 0, &mut id);
        assert_ne!(handle, 0);
        assert_eq!(WaitForSingleObject(handle, u32::MAX), 0);
        assert_eq!(thread_of(handle).unwrap().exit_code(), Some(42));
        assert_eq!(SEEN_ID.load(Ordering::SeqCst), id);
        assert_eq!(
            CreateThread(
                0,
                0,
                routine as *const () as u32,
                0,
                CREATE_SUSPENDED,
                &mut id
            ),
            0
        );
        assert_eq!(CreateThread(0, 0, 0, 0, 0, &mut id), 0);
        let gaps: Vec<String> = runtime
            .lock()
            .gaps()
            .iter()
            .map(|g| g.symbol.clone())
            .collect();
        assert_eq!(gaps, ["CreateThread CREATE_SUSPENDED"]);
    }

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
