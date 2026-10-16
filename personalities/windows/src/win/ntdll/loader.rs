//! Loader notifications: `LdrRegisterDllNotification`, from its page on
//! Microsoft Learn.
//!
//! Callbacks are recorded. They are called when a DLL is loaded or
//! unloaded at run time, which needs `LoadLibrary`; until that exists,
//! nothing calls them.

use crate::process::DllNotification;
use crate::runtime::with_current;

// From "NTSTATUS Values" on Microsoft Learn.
const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![(
        "LdrRegisterDllNotification",
        LdrRegisterDllNotification as *const () as u32,
    )]
}

/// `flags` must be 0. Returns a cookie for unregistering in `*cookie`.
#[allow(non_snake_case)]
extern "stdcall" fn LdrRegisterDllNotification(
    flags: u32,
    function: u32,
    context: u32,
    cookie: *mut u32,
) -> u32 {
    if flags != 0 || function == 0 || cookie.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let id = with_current(|p| {
        let id = p.dll_notifications.len() as u32 + 1;
        p.dll_notifications.push(DllNotification {
            cookie: id,
            function,
            context,
        });
        id
    });
    // SAFETY: checked non-null; writable (the API's contract).
    unsafe { *cookie = id };
    STATUS_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn registers_callbacks_and_checks_arguments() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let mut cookie = 0;
        assert_eq!(
            LdrRegisterDllNotification(0, 0x1000, 7, &mut cookie),
            STATUS_SUCCESS
        );
        assert_ne!(cookie, 0);
        assert_eq!(
            runtime.lock().dll_notifications,
            [DllNotification {
                cookie,
                function: 0x1000,
                context: 7
            }]
        );
        assert_eq!(
            LdrRegisterDllNotification(1, 0x1000, 0, &mut cookie),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            LdrRegisterDllNotification(0, 0, 0, &mut cookie),
            STATUS_INVALID_PARAMETER
        );
    }
}
