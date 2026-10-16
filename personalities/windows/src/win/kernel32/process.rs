//! The current process and thread.

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("GetCurrentProcess", GetCurrentProcess as *const () as u32),
        ("GetCurrentThreadId", GetCurrentThreadId as *const () as u32),
        ("GetCurrentThread", GetCurrentThread as *const () as u32),
    ]
}

/// The pseudo-handle for the calling thread, `(HANDLE)-2`, as documented.
pub(crate) const CURRENT_THREAD: u32 = 0xffff_fffe;

#[allow(non_snake_case)]
extern "stdcall" fn GetCurrentThread() -> u32 {
    CURRENT_THREAD
}

/// The Linux thread ID times 4: unique while the thread lives, and a
/// multiple of 4 like every Windows thread ID.
#[allow(non_snake_case)]
extern "stdcall" fn GetCurrentThreadId() -> u32 {
    // SAFETY: gettid has no preconditions.
    (unsafe { libc::gettid() } as u32) << 2
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
        assert_eq!(GetCurrentThread(), u32::MAX - 1);
    }

    #[test]
    fn thread_ids_are_per_thread_multiples_of_four() {
        let mine = GetCurrentThreadId();
        assert_eq!(mine % 4, 0);
        assert_eq!(GetCurrentThreadId(), mine);
        let other = std::thread::spawn(|| GetCurrentThreadId()).join().unwrap();
        assert_ne!(other, mine);
    }
}
