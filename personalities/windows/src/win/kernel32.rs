//! `kernel32.dll`.

use crate::teb::LAST_ERROR_VALUE;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("GetLastError", GetLastError as *const () as u32),
        ("SetLastError", SetLastError as *const () as u32),
    ]
}

/// Returns the calling thread's last-error code, kept in its TEB.
#[allow(non_snake_case)]
extern "stdcall" fn GetLastError() -> u32 {
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
