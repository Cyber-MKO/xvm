//! Events, semaphores and waits: `CreateEventA`, `SetEvent`,
//! `ResetEvent`, `CreateSemaphoreA`, `ReleaseSemaphore`,
//! `WaitForSingleObject`, `WaitForSingleObjectEx`.
//!
//! Objects and waits are in `crate::sync`. Named objects (a namespace
//! shared by the host's processes) and alertable waits (APCs) are logged
//! gaps: the object is created unnamed and the wait is not alertable.

use std::ffi::c_char;
use std::sync::Arc;
use std::time::Duration;

use super::error::{ERROR_INVALID_HANDLE, set_last_error};
use crate::gap::GapKind;
use crate::handles::Object;
use crate::runtime::{current, with_current};
use crate::sync::{EventObject, SemaphoreObject};

/// `ERROR_TOO_MANY_POSTS`, from "System Error Codes".
const ERROR_TOO_MANY_POSTS: u32 = 298;

pub(crate) const INFINITE: u32 = 0xffff_ffff;
pub(crate) const WAIT_OBJECT_0: u32 = 0;
pub(crate) const WAIT_TIMEOUT: u32 = 0x102;
pub(crate) const WAIT_FAILED: u32 = 0xffff_ffff;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("CreateEventA", CreateEventA as *const () as u32),
        ("SetEvent", SetEvent as *const () as u32),
        ("ResetEvent", ResetEvent as *const () as u32),
        ("CreateSemaphoreA", CreateSemaphoreA as *const () as u32),
        ("ReleaseSemaphore", ReleaseSemaphore as *const () as u32),
        (
            "WaitForSingleObject",
            WaitForSingleObject as *const () as u32,
        ),
        (
            "WaitForSingleObjectEx",
            WaitForSingleObjectEx as *const () as u32,
        ),
    ]
}

pub(crate) fn timeout(ms: u32) -> Option<Duration> {
    (ms != INFINITE).then(|| Duration::from_millis(ms as u64))
}

#[allow(non_snake_case)]
extern "stdcall" fn CreateEventA(
    _security: u32,
    manual_reset: i32,
    initial_state: i32,
    name: *const c_char,
) -> u32 {
    with_current(|p| {
        if !name.is_null() {
            p.record_runtime_gap(GapKind::Feature, "kernel32.dll", "CreateEventA with a name");
        }
        let event = EventObject::new(manual_reset != 0, initial_state != 0);
        p.handles.insert(Object::Event(Arc::new(event)))
    })
}

/// Fails with ERROR_INVALID_PARAMETER unless 0 <= initial <= maximum
/// and maximum > 0, as documented. A name is a logged gap.
#[allow(non_snake_case)]
extern "stdcall" fn CreateSemaphoreA(
    _security: u32,
    initial: i32,
    maximum: i32,
    name: *const c_char,
) -> u32 {
    if maximum <= 0 || initial < 0 || initial > maximum {
        set_last_error(super::error::ERROR_INVALID_PARAMETER);
        return 0;
    }
    with_current(|p| {
        if !name.is_null() {
            p.record_runtime_gap(
                GapKind::Feature,
                "kernel32.dll",
                "CreateSemaphoreA with a name",
            );
        }
        let semaphore = SemaphoreObject::new(initial, maximum);
        p.handles.insert(Object::Semaphore(Arc::new(semaphore)))
    })
}

#[allow(non_snake_case)]
extern "stdcall" fn ReleaseSemaphore(handle: u32, count: i32, previous: *mut i32) -> i32 {
    let semaphore = with_current(|p| match p.handles.get(handle) {
        Some(Object::Semaphore(s)) => Some(s.clone()),
        _ => None,
    });
    let Some(semaphore) = semaphore else {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };
    match current()
        .unwrap()
        .sync()
        .release_semaphore(&semaphore, count)
    {
        Some(before) => {
            if !previous.is_null() {
                // SAFETY: writable (the API's contract).
                unsafe { *previous = before };
            }
            1
        }
        None => {
            set_last_error(if count <= 0 {
                super::error::ERROR_INVALID_PARAMETER
            } else {
                ERROR_TOO_MANY_POSTS
            });
            0
        }
    }
}

fn event(handle: u32) -> Option<Arc<EventObject>> {
    with_current(|p| match p.handles.get(handle) {
        Some(Object::Event(e)) => Some(e.clone()),
        _ => None,
    })
}

#[allow(non_snake_case)]
extern "stdcall" fn SetEvent(handle: u32) -> i32 {
    match event(handle) {
        Some(e) => {
            current().unwrap().sync().set_event(&e);
            1
        }
        None => {
            set_last_error(ERROR_INVALID_HANDLE);
            0
        }
    }
}

#[allow(non_snake_case)]
extern "stdcall" fn ResetEvent(handle: u32) -> i32 {
    match event(handle) {
        Some(e) => {
            current().unwrap().sync().reset_event(&e);
            1
        }
        None => {
            set_last_error(ERROR_INVALID_HANDLE);
            0
        }
    }
}

#[allow(non_snake_case)]
pub(crate) extern "stdcall" fn WaitForSingleObject(handle: u32, ms: u32) -> u32 {
    let runtime = current().expect("emulated call from a thread outside any process");
    let waitable = runtime
        .lock()
        .handles
        .get(handle)
        .and_then(Object::waitable);
    let Some(waitable) = waitable else {
        if runtime.lock().handles.get(handle).is_some() {
            runtime.lock().record_runtime_gap(
                GapKind::Feature,
                "kernel32.dll",
                "WaitForSingleObject on an object that is not waitable yet",
            );
        }
        set_last_error(ERROR_INVALID_HANDLE);
        return WAIT_FAILED;
    };
    match runtime.sync().wait(&[waitable], false, timeout(ms)) {
        Some(_) => WAIT_OBJECT_0,
        None => WAIT_TIMEOUT,
    }
}

#[allow(non_snake_case)]
extern "stdcall" fn WaitForSingleObjectEx(handle: u32, ms: u32, alertable: i32) -> u32 {
    if alertable != 0 {
        with_current(|p| {
            p.record_runtime_gap(GapKind::Feature, "kernel32.dll", "alertable waits (APCs)")
        });
    }
    WaitForSingleObject(handle, ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn events_through_the_handle_table() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let auto = CreateEventA(0, 0, 0, std::ptr::null());
        assert_eq!(auto % 4, 0);
        assert_eq!(WaitForSingleObject(auto, 0), WAIT_TIMEOUT);
        assert_eq!(SetEvent(auto), 1);
        assert_eq!(WaitForSingleObject(auto, 0), WAIT_OBJECT_0);
        assert_eq!(WaitForSingleObject(auto, 10), WAIT_TIMEOUT);

        let manual = CreateEventA(0, 1, 1, std::ptr::null());
        assert_eq!(WaitForSingleObjectEx(manual, INFINITE, 0), WAIT_OBJECT_0);
        assert_eq!(WaitForSingleObject(manual, 0), WAIT_OBJECT_0);
        assert_eq!(ResetEvent(manual), 1);
        assert_eq!(WaitForSingleObject(manual, 0), WAIT_TIMEOUT);

        let waiter = {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                let _thread = runtime.attach().unwrap();
                WaitForSingleObject(auto, INFINITE)
            })
        };
        std::thread::sleep(Duration::from_millis(20));
        SetEvent(auto);
        assert_eq!(waiter.join().unwrap(), WAIT_OBJECT_0);

        let sem = CreateSemaphoreA(0, 1, 2, std::ptr::null());
        assert_eq!(WaitForSingleObject(sem, 0), WAIT_OBJECT_0);
        assert_eq!(WaitForSingleObject(sem, 0), WAIT_TIMEOUT);
        let mut before = -1;
        assert_eq!(ReleaseSemaphore(sem, 2, &mut before), 1);
        assert_eq!(before, 0);
        assert_eq!(ReleaseSemaphore(sem, 1, &mut before), 0);
        assert_eq!(CreateSemaphoreA(0, 3, 2, std::ptr::null()), 0);

        assert_eq!(WaitForSingleObject(0x1234, 0), WAIT_FAILED);
        assert_eq!(SetEvent(0x1234), 0);
        CreateEventA(0, 0, 0, c"Global\\x".as_ptr());
        assert_eq!(runtime.lock().gaps().len(), 1);
    }
}
