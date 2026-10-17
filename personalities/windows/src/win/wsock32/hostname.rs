//! The host name: `gethostname`.
//!
//! The name is the host profile's `identity.hostname`, from the engine.
//! Following the gethostname page on Microsoft Learn: it needs a prior
//! `WSAStartup`, and a buffer too small for the name and its NUL fails
//! with WSAEFAULT.

use std::ffi::c_char;

use serde_json::Value;

use super::startup::WSANOTINITIALISED;
use crate::runtime::with_current;
use crate::win::facts::{self, Caller};
use crate::win::kernel32::error::set_last_error;

const CALLER: Caller = ("wsock32.dll", "gethostname");
const SOCKET_ERROR: i32 = -1;
const WSAEFAULT: u32 = 10014;
/// Not a documented gethostname error, but the closest one for a host
/// whose profile has no name: "a nonrecoverable error occurred".
const WSANO_RECOVERY: u32 = 11003;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("gethostname", gethostname as *const () as u32)]
}

/// Copies the host name and a NUL into `name`. Returns 0, or
/// SOCKET_ERROR with the error in the last error.
extern "stdcall" fn gethostname(name: *mut c_char, len: i32) -> i32 {
    let fail = |code: u32| {
        set_last_error(code);
        SOCKET_ERROR
    };
    if with_current(|p| p.winsock_starts) == 0 {
        return fail(WSANOTINITIALISED as u32);
    }
    let host = facts::section(CALLER, "identity").and_then(|i| {
        i.get("hostname")
            .and_then(Value::as_str)
            .map(str::to_string)
    });
    let Some(host) = host else {
        return fail(WSANO_RECOVERY);
    };
    if name.is_null() || len < 0 || host.len() >= len as usize {
        return fail(WSAEFAULT);
    }
    // SAFETY: `len` writable bytes (the API's contract); the name and
    // its NUL fit.
    unsafe {
        std::ptr::copy_nonoverlapping(host.as_ptr(), name.cast(), host.len());
        *name.add(host.len()) = 0;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use crate::win::kernel32::error::GetLastError;
    use serde_json::json;

    #[test]
    fn the_name_comes_from_the_profile() {
        let base = json!({"schema": 1, "kind": "base-image", "name": "b", "os": "windows",
                          "source": {"golden_capture": "synthetic"}});
        let host = json!({"schema": 1, "kind": "host-profile", "name": "h", "base": "b",
                          "os": "windows", "identity": {"hostname": "WIN-WEB-01"}});
        let mut process = Process::new(Vec::new());
        process.engine = Some(facts::test_engine(base, host));
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        let mut buf = [0x55 as c_char; 16];
        assert_eq!(gethostname(buf.as_mut_ptr(), 16), SOCKET_ERROR);
        assert_eq!(GetLastError(), WSANOTINITIALISED as u32);
        runtime.lock().winsock_starts = 1;
        assert_eq!(gethostname(buf.as_mut_ptr(), 16), 0);
        // SAFETY: NUL-terminated by gethostname.
        let got = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(got.to_str().unwrap(), "WIN-WEB-01");
        assert_eq!(gethostname(buf.as_mut_ptr(), 10), SOCKET_ERROR);
        assert_eq!(GetLastError(), WSAEFAULT);
        assert_eq!(gethostname(buf.as_mut_ptr(), 11), 0);
    }
}
