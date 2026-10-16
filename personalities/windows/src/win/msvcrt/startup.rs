//! Start-up support called by the MinGW CRT start-up code.

use crate::runtime::with_current;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("_initterm", _initterm as *const () as u32),
        ("__set_app_type", __set_app_type as *const () as u32),
        ("__p__fmode", __p__fmode as *const () as u32),
        ("__p__commode", __p__commode as *const () as u32),
        ("__lconv_init", __lconv_init as *const () as u32),
    ]
}

/// Undocumented. Prepares the data `localeconv` returns. Ours builds that
/// data when `localeconv` is called, so there is nothing to prepare.
extern "C" fn __lconv_init() -> i32 {
    0
}

/// Address of `_fmode`, the default file translation mode.
#[allow(non_snake_case)]
extern "C" fn __p__fmode() -> *mut i32 {
    with_current(|p| &mut *p.crt.fmode as *mut i32)
}

/// Address of `_commode`, the default stream commit mode.
#[allow(non_snake_case)]
extern "C" fn __p__commode() -> *mut i32 {
    with_current(|p| &mut *p.crt.commode as *mut i32)
}

/// Records whether the program is a console (1) or GUI (2) application.
/// The CRT uses it to choose where runtime error messages go; ours always
/// go to stderr, since there is no GUI (rule 6).
extern "C" fn __set_app_type(app_type: u32) {
    with_current(|p| p.crt.app_type = app_type);
}

type Initializer = Option<extern "C" fn()>;

/// Calls every non-null function pointer in `[begin, end)`, in order.
extern "C" fn _initterm(begin: *const Initializer, end: *const Initializer) {
    let mut at = begin;
    while at < end {
        // SAFETY: the caller passes a table of function pointers, with NULL
        // entries allowed.
        if let Some(f) = unsafe { at.read() } {
            f();
        }
        // SAFETY: still inside or one past the table.
        at = unsafe { at.add(1) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use std::sync::Mutex;

    #[test]
    fn set_app_type_is_kept_per_process() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        __set_app_type(1);
        assert_eq!(runtime.lock().crt.app_type, 1);
    }

    #[test]
    fn lconv_init_succeeds() {
        assert_eq!(__lconv_init(), 0);
    }

    #[test]
    fn mode_globals_have_documented_defaults_and_stable_addresses() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let fmode = __p__fmode();
        // SAFETY: points into the process's CRT state, alive with runtime.
        unsafe {
            assert_eq!(*fmode, crate::process::O_TEXT);
            assert_eq!(*__p__commode(), 0);
            *fmode = 0x8000;
        }
        assert_eq!(__p__fmode(), fmode);
        assert_eq!(*runtime.lock().crt.fmode, 0x8000);
    }

    static CALLS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    extern "C" fn one() {
        CALLS.lock().unwrap().push(1);
    }
    extern "C" fn two() {
        CALLS.lock().unwrap().push(2);
    }

    #[test]
    fn calls_entries_in_order_and_skips_null() {
        let table: [Initializer; 4] = [None, Some(one), None, Some(two)];
        let range = table.as_ptr_range();
        _initterm(range.start, range.end);
        assert_eq!(*CALLS.lock().unwrap(), [1, 2]);
        _initterm(range.start, range.start);
        assert_eq!(CALLS.lock().unwrap().len(), 2);
    }
}
