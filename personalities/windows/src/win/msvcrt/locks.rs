//! The CRT's numbered internal locks: `_lock`, `_unlock`.
//!
//! Undocumented exports that MinGW code uses, around `atexit` for one.
//! Each number is a re-entrant lock, a critical section. Numbers past the
//! table are logged as gaps.

use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::win::kernel32::critsec::{CriticalSection, EnterCriticalSection, LeaveCriticalSection};

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("_lock", _lock as *const () as u32),
        ("_unlock", _unlock as *const () as u32),
    ]
}

/// The critical section for lock `n`, which lives as long as the process.
fn section(n: i32) -> Option<*mut CriticalSection> {
    with_current(|p| {
        let slot = usize::try_from(n).ok().filter(|&i| i < p.crt.locks.len());
        if slot.is_none() {
            p.record_runtime_gap(GapKind::Feature, "msvcrt.dll", &format!("_lock number {n}"));
        }
        slot.map(|i| p.crt.locks[i].as_mut_ptr().cast())
    })
}

/// Blocks until lock `n` is free, without holding the process lock.
extern "C" fn _lock(n: i32) {
    if let Some(cs) = section(n) {
        EnterCriticalSection(cs);
    }
}

extern "C" fn _unlock(n: i32) {
    if let Some(cs) = section(n) {
        LeaveCriticalSection(cs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn locks_are_reentrant_and_exclusive() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        _lock(9);
        _lock(9);
        let other = {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                let _thread = runtime.attach().unwrap();
                let started = std::time::Instant::now();
                _lock(9);
                _unlock(9);
                started.elapsed()
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        _unlock(9);
        _unlock(9);
        assert!(other.join().unwrap() >= std::time::Duration::from_millis(40));
        _lock(64);
        assert_eq!(runtime.lock().gaps().len(), 1);
    }
}
