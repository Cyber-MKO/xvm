//! Low-level I/O on file descriptors: `_open_osfhandle`.
//!
//! A descriptor wraps an OS handle and its `_O_*` flags. Descriptors 0 to
//! 2 are the standard handles when the process has them; a service has
//! none, so its first descriptor can be 0, as with `msvcrt`.

use super::errno::{self, EBADF, EMFILE};
use crate::process::CrtFd;
use crate::runtime::with_current;

/// `msvcrt` allows 2048 descriptors.
const MAX_FDS: usize = 2048;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("_open_osfhandle", _open_osfhandle as *const () as u32)]
}

/// Wraps `handle` in the lowest free descriptor. Returns it, or -1 with
/// `errno` set.
extern "C" fn _open_osfhandle(handle: isize, flags: i32) -> i32 {
    let handle = handle as u32;
    if handle == 0 || handle == u32::MAX {
        errno::set(EBADF);
        return -1;
    }
    with_current(|p| {
        if p.crt.fds.iter().flatten().count() >= MAX_FDS {
            errno::set(EMFILE);
            return -1;
        }
        p.crt.insert_fd(CrtFd { handle, flags })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn descriptors_start_at_the_lowest_free_one() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        assert_eq!(_open_osfhandle(0x40, 0x4000), 0);
        assert_eq!(_open_osfhandle(0x44, 0x8000), 1);
        runtime.lock().crt.fds[0] = None;
        assert_eq!(_open_osfhandle(0x48, 0), 0);
        assert_eq!(
            runtime.lock().crt.fd(1),
            Some(CrtFd {
                handle: 0x44,
                flags: 0x8000
            })
        );
        assert_eq!(_open_osfhandle(-1, 0), -1);
        assert_eq!(errno::get(), EBADF);
    }
}
