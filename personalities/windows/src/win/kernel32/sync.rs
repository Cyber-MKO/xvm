//! Events, semaphores, mutexes and waits: `CreateEventA`, `SetEvent`,
//! `ResetEvent`, `CreateSemaphoreA`, `ReleaseSemaphore`, `CreateMutexA`,
//! `ReleaseMutex`, `WaitForSingleObject`, `WaitForSingleObjectEx`, `Sleep`,
//! `WaitForMultipleObjects`.
//!
//! Objects and waits are in `crate::sync`. Mutex names live in a
//! namespace of the process; `Global\` and `Local\` name the same one,
//! as they do for a service in session 0, and names are case-sensitive
//! ("Object Names" on Microsoft Learn). Sharing names with the host's
//! other processes waits until there are any. Named events and
//! semaphores and alertable waits (APCs) are logged gaps: the object is
//! created unnamed and the wait is not alertable.

use std::ffi::c_char;
use std::sync::Arc;
use std::time::Duration;

use super::error::{ERROR_INVALID_HANDLE, set_last_error};
use crate::gap::GapKind;
use crate::handles::Object;
use crate::runtime::{current, current_thread, with_current};
use crate::sync::{EventObject, SemaphoreObject, Waitable, Woken};

/// `ERROR_TOO_MANY_POSTS`, from "System Error Codes".
const ERROR_TOO_MANY_POSTS: u32 = 298;

pub(crate) const INFINITE: u32 = 0xffff_ffff;
pub(crate) const WAIT_OBJECT_0: u32 = 0;
pub(crate) const WAIT_TIMEOUT: u32 = 0x102;
pub(crate) const WAIT_ABANDONED_0: u32 = 0x80;
const MAXIMUM_WAIT_OBJECTS: u32 = 64;
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_NOT_OWNER: u32 = 288;
pub(crate) const WAIT_FAILED: u32 = 0xffff_ffff;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("CreateEventA", CreateEventA as *const () as u32),
        ("SetEvent", SetEvent as *const () as u32),
        ("ResetEvent", ResetEvent as *const () as u32),
        ("CreateSemaphoreA", CreateSemaphoreA as *const () as u32),
        ("ReleaseSemaphore", ReleaseSemaphore as *const () as u32),
        ("CreateMutexA", CreateMutexA as *const () as u32),
        ("ReleaseMutex", ReleaseMutex as *const () as u32),
        (
            "WaitForMultipleObjects",
            WaitForMultipleObjects as *const () as u32,
        ),
        ("Sleep", Sleep as *const () as u32),
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

/// Suspends the thread for `ms` milliseconds; 0 gives up the rest of
/// its time slice, INFINITE never returns.
#[allow(non_snake_case)]
extern "stdcall" fn Sleep(ms: u32) {
    match timeout(ms) {
        Some(d) if d.is_zero() => std::thread::yield_now(),
        Some(d) => std::thread::sleep(d),
        None => loop {
            std::thread::park();
        },
    }
}

fn me() -> u32 {
    current_thread().map_or(0, |t| t.id)
}

/// Opens the mutex `name` if it exists (ERROR_ALREADY_EXISTS; the
/// initial owner is then ignored), else creates it. A name used by
/// another kind of object fails with ERROR_INVALID_HANDLE.
#[allow(non_snake_case)]
extern "stdcall" fn CreateMutexA(_security: u32, initial_owner: i32, name: *const c_char) -> u32 {
    let runtime = current().expect("emulated call from a thread outside any process");
    let owner = if initial_owner != 0 { me() } else { 0 };
    // SAFETY: NUL-terminated or NULL (the API's contract).
    let name = (!name.is_null()).then(|| unsafe { std::ffi::CStr::from_ptr(name) });
    let Some(name) = name else {
        let mutex = runtime.sync().new_mutex(owner);
        set_last_error(0);
        return runtime.lock().handles.insert(Object::Mutex(mutex));
    };
    let name = name.to_string_lossy();
    let key = name
        .strip_prefix("Global\\")
        .or_else(|| name.strip_prefix("Local\\"))
        .unwrap_or(&name)
        .to_string();
    let mut p = runtime.lock();
    if let Some(existing) = p.named_mutexes.get(&key).and_then(std::sync::Weak::upgrade) {
        set_last_error(ERROR_ALREADY_EXISTS);
        return p.handles.insert(Object::Mutex(existing));
    }
    let mutex = runtime.sync().new_mutex(owner);
    p.named_mutexes.insert(key, Arc::downgrade(&mutex));
    set_last_error(0);
    p.handles.insert(Object::Mutex(mutex))
}

/// Releases one hold of a mutex the calling thread owns; otherwise
/// fails with ERROR_NOT_OWNER.
#[allow(non_snake_case)]
extern "stdcall" fn ReleaseMutex(handle: u32) -> i32 {
    let mutex = with_current(|p| match p.handles.get(handle) {
        Some(Object::Mutex(m)) => Some(m.clone()),
        _ => None,
    });
    let Some(mutex) = mutex else {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };
    if current().unwrap().sync().release_mutex(&mutex, me()) {
        1
    } else {
        set_last_error(ERROR_NOT_OWNER);
        0
    }
}

fn wait_result(woken: Option<Woken>) -> u32 {
    match woken {
        Some(Woken {
            index,
            abandoned: false,
        }) => WAIT_OBJECT_0 + index as u32,
        Some(Woken {
            index,
            abandoned: true,
        }) => WAIT_ABANDONED_0 + index as u32,
        None => WAIT_TIMEOUT,
    }
}

/// Waits for one (or, with `wait_all`, all) of `count` handles. Fails
/// with ERROR_INVALID_PARAMETER for 0 or more than 64 handles.
#[allow(non_snake_case)]
extern "stdcall" fn WaitForMultipleObjects(
    count: u32,
    handles: *const u32,
    wait_all: i32,
    ms: u32,
) -> u32 {
    if count == 0 || count > MAXIMUM_WAIT_OBJECTS || handles.is_null() {
        set_last_error(super::error::ERROR_INVALID_PARAMETER);
        return WAIT_FAILED;
    }
    // SAFETY: an array of `count` handles (the API's contract).
    let handles = unsafe { std::slice::from_raw_parts(handles, count as usize) };
    let runtime = current().expect("emulated call from a thread outside any process");
    let objects: Option<Vec<Waitable>> = {
        let p = runtime.lock();
        handles
            .iter()
            .map(|&h| p.handles.get(h).and_then(Object::waitable))
            .collect()
    };
    let Some(objects) = objects else {
        set_last_error(ERROR_INVALID_HANDLE);
        return WAIT_FAILED;
    };
    wait_result(
        runtime
            .sync()
            .wait_as(me(), &objects, wait_all != 0, timeout(ms)),
    )
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
    wait_result(
        runtime
            .sync()
            .wait_as(me(), &[waitable], false, timeout(ms)),
    )
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

    fn other_thread<T: Send + 'static>(
        runtime: &Runtime,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let runtime = runtime.clone();
        std::thread::spawn(move || {
            let _thread = runtime.attach().unwrap();
            f()
        })
        .join()
        .unwrap()
    }

    #[test]
    fn mutexes_count_their_owner_and_can_be_abandoned() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let m = CreateMutexA(0, 1, std::ptr::null());
        assert_eq!(
            WaitForSingleObject(m, 0),
            WAIT_OBJECT_0,
            "the owner may re-enter"
        );
        assert_eq!(
            other_thread(&runtime, move || WaitForSingleObject(m, 0)),
            WAIT_TIMEOUT
        );
        assert_eq!(
            other_thread(&runtime, move || ReleaseMutex(m)),
            0,
            "not the owner"
        );
        assert_eq!((ReleaseMutex(m), ReleaseMutex(m)), (1, 1));
        assert_eq!(ReleaseMutex(m), 0, "no holds left");
        // A thread that ends holding it abandons it.
        assert_eq!(
            other_thread(&runtime, move || WaitForSingleObject(m, 0)),
            WAIT_OBJECT_0
        );
        assert_eq!(WaitForSingleObject(m, 0), WAIT_ABANDONED_0);
        assert_eq!(WaitForSingleObject(m, 0), WAIT_OBJECT_0, "reported once");
    }

    #[test]
    fn named_mutexes_open_the_same_object() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let a = CreateMutexA(0, 1, c"Global\\wazuh".as_ptr());
        assert_eq!(super::super::error::GetLastError(), 0);
        let b = CreateMutexA(0, 0, c"wazuh".as_ptr());
        assert_eq!(super::super::error::GetLastError(), ERROR_ALREADY_EXISTS);
        assert_ne!(a, b);
        assert_eq!(
            other_thread(&runtime, move || WaitForSingleObject(b, 0)),
            WAIT_TIMEOUT
        );
        let c = CreateMutexA(0, 0, c"WAZUH".as_ptr());
        assert_eq!(
            super::super::error::GetLastError(),
            0,
            "names are case-sensitive"
        );
        assert_ne!(c, 0);
    }

    #[test]
    fn wait_for_multiple_objects_any_and_all() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let (e1, e2) = (
            CreateEventA(0, 1, 0, std::ptr::null()),
            CreateEventA(0, 1, 0, std::ptr::null()),
        );
        let both = [e1, e2];
        assert_eq!(WaitForMultipleObjects(2, both.as_ptr(), 0, 0), WAIT_TIMEOUT);
        SetEvent(e2);
        assert_eq!(
            WaitForMultipleObjects(2, both.as_ptr(), 0, 0),
            WAIT_OBJECT_0 + 1
        );
        assert_eq!(WaitForMultipleObjects(2, both.as_ptr(), 1, 0), WAIT_TIMEOUT);
        SetEvent(e1);
        assert_eq!(
            WaitForMultipleObjects(2, both.as_ptr(), 1, INFINITE),
            WAIT_OBJECT_0
        );
        assert_eq!(WaitForMultipleObjects(0, both.as_ptr(), 0, 0), WAIT_FAILED);
        let bad = [e1, 0x1234];
        assert_eq!(WaitForMultipleObjects(2, bad.as_ptr(), 0, 0), WAIT_FAILED);
    }

    #[test]
    fn sleep_waits_at_least_the_time_asked() {
        let start = std::time::Instant::now();
        Sleep(0);
        Sleep(20);
        assert!(start.elapsed() >= Duration::from_millis(20));
    }

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
