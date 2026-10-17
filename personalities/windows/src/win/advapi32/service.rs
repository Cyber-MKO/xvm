//! The service side of the Service Control Manager: the control
//! dispatcher, control handlers and status reports.
//!
//! The host profile says whether the process was started as a service
//! (`windows.agent.service`). If so, `StartServiceCtrlDispatcherA` runs the
//! service's `ServiceMain` on a new thread and then, on the calling thread,
//! hands control codes to the handler the service registered. It returns
//! once the service reports `SERVICE_STOPPED`. Control codes come from the
//! control plane through `Runtime::service_control`.
//!
//! Only own-process services are supported: the first table entry is the
//! service, whatever its name, as the documentation for
//! `SERVICE_TABLE_ENTRY` allows for `SERVICE_WIN32_OWN_PROCESS`.

use std::ffi::{CString, c_char};

use crate::process::{MainArgs, ServiceStatus};
use crate::runtime::{ServiceEvent, current};
use crate::win::kernel32::error::{
    ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY, set_last_error,
};

// From "System Error Codes" on Microsoft Learn.
const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: u32 = 1063;

pub const SERVICE_STOPPED: u32 = 1;

/// The only service status handle: one service per process.
const STATUS_HANDLE: u32 = 1;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        (
            "StartServiceCtrlDispatcherA",
            StartServiceCtrlDispatcherA as *const () as u32,
        ),
        (
            "RegisterServiceCtrlHandlerA",
            RegisterServiceCtrlHandlerA as *const () as u32,
        ),
        ("SetServiceStatus", SetServiceStatus as *const () as u32),
    ]
}

/// `SERVICE_TABLE_ENTRYA`.
#[repr(C)]
struct ServiceTableEntry {
    name: *const c_char,
    service_main: u32,
}

fn state_name(state: u32) -> &'static str {
    match state {
        1 => "SERVICE_STOPPED",
        2 => "SERVICE_START_PENDING",
        3 => "SERVICE_STOP_PENDING",
        4 => "SERVICE_RUNNING",
        5 => "SERVICE_CONTINUE_PENDING",
        6 => "SERVICE_PAUSE_PENDING",
        7 => "SERVICE_PAUSED",
        _ => "unknown state",
    }
}

#[allow(non_snake_case)]
extern "stdcall" fn StartServiceCtrlDispatcherA(table: *const ServiceTableEntry) -> i32 {
    let runtime = current().expect("emulated call from a thread outside any process");
    let started = {
        let mut p = runtime.lock();
        match p.params.service.clone() {
            None => Err(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT),
            Some(_) if p.services.dispatcher_started => Err(ERROR_SERVICE_ALREADY_RUNNING),
            // SAFETY: the table is a readable array (the API's contract).
            Some(_) if table.is_null() || unsafe { (*table).service_main } == 0 => {
                Err(ERROR_INVALID_PARAMETER)
            }
            Some(name) => {
                p.services.dispatcher_started = true;
                let name = CString::new(name).expect("validated profile string");
                let mut argv = MainArgs {
                    argv: vec![name.as_ptr().cast_mut(), std::ptr::null_mut()],
                    envp: vec![std::ptr::null_mut()],
                    strings: vec![name],
                };
                let argv_address = argv.argv.as_mut_ptr() as usize;
                p.services.argv = Some(argv);
                // SAFETY: checked non-null above.
                Ok((unsafe { (*table).service_main }, argv_address))
            }
        }
    };
    let (service_main, argv) = match started {
        Ok(started) => started,
        Err(code) => {
            set_last_error(code);
            return 0;
        }
    };

    let spawned = runtime.spawn(move || {
        // SAFETY: VOID WINAPI ServiceMain(DWORD dwNumServicesArgs,
        // LPSTR *lpServiceArgVectors). argv lives in the process's
        // service state for as long as the process does.
        let main: extern "stdcall" fn(u32, usize) =
            unsafe { std::mem::transmute(service_main as usize) };
        main(1, argv);
        0
    });
    if spawned.is_err() {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }

    loop {
        match runtime.next_service_event() {
            ServiceEvent::Stopped => return 1,
            ServiceEvent::Control(code) => {
                let mut p = runtime.lock();
                if p.services.handler == 0 {
                    p.services.pending_controls.push(code);
                    continue;
                }
                let handler = p.services.handler;
                drop(p);
                call_handler(handler, code);
            }
            ServiceEvent::HandlerRegistered => {
                let (handler, pending) = {
                    let mut p = runtime.lock();
                    (
                        p.services.handler,
                        std::mem::take(&mut p.services.pending_controls),
                    )
                };
                for code in pending {
                    call_handler(handler, code);
                }
            }
        }
    }
}

fn call_handler(handler: u32, code: u32) {
    // SAFETY: VOID WINAPI Handler(DWORD dwControl), registered by the
    // service. Called without the process lock held.
    let handler: extern "stdcall" fn(u32) = unsafe { std::mem::transmute(handler as usize) };
    handler(code);
}

/// Registers the function the dispatcher calls with control codes.
/// Returns the service status handle.
#[allow(non_snake_case)]
extern "stdcall" fn RegisterServiceCtrlHandlerA(_name: *const c_char, handler: u32) -> u32 {
    let runtime = current().expect("emulated call from a thread outside any process");
    if handler == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    runtime.lock().services.handler = handler;
    runtime.post_service_event(ServiceEvent::HandlerRegistered);
    STATUS_HANDLE
}

/// Records the service's status and logs each change of state. Reporting
/// `SERVICE_STOPPED` lets the dispatcher return.
#[allow(non_snake_case)]
extern "stdcall" fn SetServiceStatus(handle: u32, status: *const ServiceStatus) -> i32 {
    let runtime = current().expect("emulated call from a thread outside any process");
    if handle != STATUS_HANDLE {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    if status.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: a readable SERVICE_STATUS (the API's contract).
    let status = unsafe { *status };
    let changed = {
        let mut p = runtime.lock();
        let previous = p.services.status.replace(status);
        let name = p.params.service.clone().unwrap_or_default();
        (previous.map(|s| s.current_state) != Some(status.current_state)).then_some(name)
    };
    if let Some(name) = changed {
        eprintln!("service {name}: {}", state_name(status.current_state));
    }
    if status.current_state == SERVICE_STOPPED {
        runtime.post_service_event(ServiceEvent::Stopped);
    }
    1
}
