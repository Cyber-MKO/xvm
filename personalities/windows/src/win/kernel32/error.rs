//! Last-error code: `GetLastError`, `SetLastError`.

use crate::teb::LAST_ERROR_VALUE;

// From "System Error Codes" on Microsoft Learn.
pub(crate) const ERROR_FILE_NOT_FOUND: u32 = 2;
pub(crate) const ERROR_PATH_NOT_FOUND: u32 = 3;
pub(crate) const ERROR_ACCESS_DENIED: u32 = 5;
pub(crate) const ERROR_INVALID_HANDLE: u32 = 6;
pub(crate) const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub(crate) const ERROR_SHARING_VIOLATION: u32 = 32;
pub(crate) const ERROR_FILE_EXISTS: u32 = 80;
pub(crate) const ERROR_BAD_LENGTH: u32 = 24;
pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;
pub(crate) const ERROR_BAD_PATHNAME: u32 = 161;
pub(crate) const ERROR_ALREADY_EXISTS: u32 = 183;
pub(crate) const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub(crate) const ERROR_INVALID_NAME: u32 = 123;
pub(crate) const ERROR_INVALID_ADDRESS: u32 = 487;
pub(crate) const ERROR_MOD_NOT_FOUND: u32 = 126;
pub(crate) const ERROR_PROC_NOT_FOUND: u32 = 127;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("GetLastError", GetLastError as *const () as u32),
        ("SetLastError", SetLastError as *const () as u32),
    ]
}

/// Returns the calling thread's last-error code, kept in its TEB.
#[allow(non_snake_case)]
pub(crate) extern "stdcall" fn GetLastError() -> u32 {
    let value: u32;
    // SAFETY: fs points at this thread's TEB (thread::ThreadEnv) whenever
    // agent code runs, and the TEB covers LastErrorValue.
    unsafe {
        std::arch::asm!(
            "mov {0}, dword ptr fs:[{1}]",
            out(reg) value,
            const LAST_ERROR_VALUE,
            options(nostack, readonly, preserves_flags),
        )
    };
    value
}

/// For emulated functions that fail.
pub(crate) fn set_last_error(code: u32) {
    SetLastError(code);
}

/// Sets the calling thread's last-error code.
#[allow(non_snake_case)]
extern "stdcall" fn SetLastError(code: u32) {
    // SAFETY: as in GetLastError.
    unsafe {
        std::arch::asm!(
            "mov dword ptr fs:[{1}], {0}",
            in(reg) code,
            const LAST_ERROR_VALUE,
            options(nostack, preserves_flags),
        )
    };
}
