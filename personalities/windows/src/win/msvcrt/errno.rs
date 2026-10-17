//! The CRT's `errno`: one per thread, with the values from "errno
//! constants" on Microsoft Learn (some differ from Linux's).

use std::cell::Cell;

pub(super) const ENOENT: i32 = 2;
pub(super) const EBADF: i32 = 9;
pub(super) const EMFILE: i32 = 24;
pub(super) const ENOTDIR: i32 = 20;
pub(super) const EINVAL: i32 = 22;
pub(super) const ERANGE: i32 = 34;
pub(super) const EOVERFLOW: i32 = 132;
pub(super) const ENOMEM: i32 = 12;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("_errno", _errno as *const () as u32)]
}

thread_local! {
    static ERRNO: Cell<i32> = const { Cell::new(0) };
}

/// Address of the calling thread's `errno`, stable while the thread
/// lives. Agent code and our functions share it.
extern "C" fn _errno() -> *mut i32 {
    ERRNO.with(|e| e.as_ptr())
}

pub(super) fn set(value: i32) {
    ERRNO.with(|e| e.set(value));
}

#[cfg(test)]
pub(super) fn get() -> i32 {
    ERRNO.with(|e| e.get())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_is_per_thread_and_shared_with_our_functions() {
        let mine = _errno();
        set(ENOENT);
        // SAFETY: points at this thread's errno.
        unsafe {
            assert_eq!(*mine, ENOENT);
            *mine = EINVAL;
        }
        assert_eq!(get(), EINVAL);
        assert_eq!(_errno(), mine);
        let other = std::thread::spawn(|| {
            set(ERANGE);
            _errno() as usize
        })
        .join()
        .unwrap();
        assert_ne!(other, mine as usize);
        assert_eq!(get(), EINVAL);
    }
}
