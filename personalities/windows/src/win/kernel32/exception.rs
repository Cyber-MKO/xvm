//! Exception handler registration.
//!
//! Handlers are recorded on the process in call order. Dispatch is not
//! implemented: `RaiseException` is still a gap, and a hardware fault stops
//! the process with its Linux signal.

use crate::runtime::with_current;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        (
            "AddVectoredExceptionHandler",
            AddVectoredExceptionHandler as *const () as u32,
        ),
        (
            "RemoveVectoredExceptionHandler",
            RemoveVectoredExceptionHandler as *const () as u32,
        ),
    ]
}

/// Returns a handle for `RemoveVectoredExceptionHandler`, never NULL.
#[allow(non_snake_case)]
extern "stdcall" fn AddVectoredExceptionHandler(first: u32, handler: u32) -> u32 {
    with_current(|p| p.vectored_handlers.add(handler, first != 0))
}

/// Returns nonzero if the handle was registered.
#[allow(non_snake_case)]
extern "stdcall" fn RemoveVectoredExceptionHandler(handle: u32) -> u32 {
    with_current(|p| p.vectored_handlers.remove(handle)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn handlers_keep_call_order_and_remove_by_handle() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let last = AddVectoredExceptionHandler(0, 0x1000);
        let first = AddVectoredExceptionHandler(1, 0x2000);
        AddVectoredExceptionHandler(0, 0x3000);
        assert!(last != 0 && first != 0 && last != first);
        assert_eq!(
            runtime.lock().vectored_handlers.handlers(),
            [0x2000, 0x1000, 0x3000]
        );
        assert_eq!(RemoveVectoredExceptionHandler(last), 1);
        assert_eq!(RemoveVectoredExceptionHandler(last), 0);
        assert_eq!(
            runtime.lock().vectored_handlers.handlers(),
            [0x2000, 0x3000]
        );
    }
}
