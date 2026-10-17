//! Byte-range file locks, as the LockFileEx and UnlockFileEx pages on
//! Microsoft Learn describe them.
//!
//! | Rule | Behaviour |
//! | --- | --- |
//! | Exclusive lock | May not overlap any locked range, the caller's own included |
//! | Shared lock | May overlap shared locks only |
//! | Unlock | Must name exactly a range the handle locked |
//! | Closing a handle | Releases its locks |
//!
//! A lock that cannot be granted fails at once or waits, as the caller
//! asks. Locks are per process for now: one agent process per host.

use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Range {
    file: PathBuf,
    handle: u32,
    start: u64,
    len: u64,
    exclusive: bool,
}

impl Range {
    fn overlaps(&self, file: &Path, start: u64, len: u64) -> bool {
        self.file == file
            && len > 0
            && self.len > 0
            && start < self.start.saturating_add(self.len)
            && self.start < start.saturating_add(len)
    }
}

#[derive(Debug, Default)]
pub struct FileLocks {
    ranges: Mutex<Vec<Range>>,
    released: Condvar,
}

impl FileLocks {
    /// Lock `len` bytes at `start` of `file` for `handle`. Returns false
    /// if it conflicts and `wait` is false; otherwise waits until it can.
    pub fn lock(
        &self,
        file: &Path,
        handle: u32,
        start: u64,
        len: u64,
        exclusive: bool,
        wait: bool,
    ) -> bool {
        let mut ranges = self.ranges.lock().unwrap();
        loop {
            let conflict = ranges
                .iter()
                .any(|r| r.overlaps(file, start, len) && (exclusive || r.exclusive));
            if !conflict {
                ranges.push(Range {
                    file: file.to_path_buf(),
                    handle,
                    start,
                    len,
                    exclusive,
                });
                return true;
            }
            if !wait {
                return false;
            }
            ranges = self.released.wait(ranges).unwrap();
        }
    }

    /// Release the range exactly as locked. False if there is none.
    pub fn unlock(&self, file: &Path, handle: u32, start: u64, len: u64) -> bool {
        let mut ranges = self.ranges.lock().unwrap();
        let found = ranges
            .iter()
            .position(|r| r.file == file && r.handle == handle && r.start == start && r.len == len);
        match found {
            Some(i) => {
                ranges.remove(i);
                self.released.notify_all();
                true
            }
            None => false,
        }
    }

    /// Release every lock `handle` holds.
    pub fn release(&self, handle: u32) {
        let mut ranges = self.ranges.lock().unwrap();
        let before = ranges.len();
        ranges.retain(|r| r.handle != handle);
        if ranges.len() != before {
            self.released.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn exclusive_and_shared_rules() {
        let locks = FileLocks::default();
        let f = Path::new("/db");
        assert!(locks.lock(f, 4, 0, 10, false, false));
        assert!(locks.lock(f, 8, 5, 10, false, false), "shared over shared");
        assert!(
            !locks.lock(f, 8, 9, 1, true, false),
            "exclusive over shared"
        );
        assert!(
            !locks.lock(f, 4, 0, 10, true, false),
            "even the same handle"
        );
        assert!(locks.lock(f, 8, 20, 1, true, false));
        assert!(
            !locks.lock(f, 4, 20, 1, false, false),
            "shared over exclusive"
        );
        assert!(locks.lock(Path::new("/other"), 4, 20, 1, true, false));
        assert!(!locks.unlock(f, 8, 20, 2), "not the exact range");
        assert!(locks.unlock(f, 8, 20, 1));
        locks.release(4);
        locks.release(8);
        assert!(locks.lock(f, 12, 0, 100, true, false));
    }

    #[test]
    fn a_waiting_lock_gets_the_range_when_it_is_released() {
        let locks = Arc::new(FileLocks::default());
        let f = Path::new("/db");
        assert!(locks.lock(f, 4, 0, 1, true, false));
        let waiter = {
            let locks = locks.clone();
            std::thread::spawn(move || locks.lock(Path::new("/db"), 8, 0, 1, true, true))
        };
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(!waiter.is_finished());
        locks.release(4);
        assert!(waiter.join().unwrap());
    }
}
