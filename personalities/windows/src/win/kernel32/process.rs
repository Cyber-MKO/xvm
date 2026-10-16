//! The current process.

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("GetCurrentProcess", GetCurrentProcess as *const () as u32)]
}

/// The pseudo-handle for the current process, `(HANDLE)-1`, as documented.
/// It needs no closing.
pub(crate) const CURRENT_PROCESS: u32 = 0xffff_ffff;

#[allow(non_snake_case)]
extern "stdcall" fn GetCurrentProcess() -> u32 {
    CURRENT_PROCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_is_the_documented_pseudo_handle() {
        assert_eq!(GetCurrentProcess(), u32::MAX);
    }
}
