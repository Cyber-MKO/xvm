//! Critical sections.
//!
//! `CRITICAL_SECTION` is 24 bytes of agent memory (the `RTL_CRITICAL_SECTION`
//! layout in winnt.h). Its contents are documented as opaque, and no agent
//! code reads them, so we keep our own state in its fields:
//!
//! | Offset | Field | Our use |
//! | --- | --- | --- |
//! | 4 | `LockCount` | Futex word: 0 free, 1 held, 2 held with waiters |
//! | 8 | `RecursionCount` | How many times the owner has entered |
//! | 12 | `OwningThread` | Owner's thread ID, 0 when free |
//! | 20 | `SpinCount` | Stored, not used |
//!
//! All-zero memory is a valid, unlocked section.
//!
//! The lock is the classic three-state futex mutex. Re-entry by the owner
//! only counts, as the EnterCriticalSection documentation requires.

use std::sync::atomic::{AtomicU32, Ordering};

#[repr(C)]
pub(crate) struct CriticalSection {
    debug_info: AtomicU32,
    lock: AtomicU32,
    recursion: AtomicU32,
    owner: AtomicU32,
    lock_semaphore: AtomicU32,
    spin_count: AtomicU32,
}

const FREE: u32 = 0;
const HELD: u32 = 1;
const CONTENDED: u32 = 2;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        (
            "InitializeCriticalSection",
            InitializeCriticalSection as *const () as u32,
        ),
        (
            "InitializeCriticalSectionAndSpinCount",
            InitializeCriticalSectionAndSpinCount as *const () as u32,
        ),
        (
            "EnterCriticalSection",
            EnterCriticalSection as *const () as u32,
        ),
        (
            "TryEnterCriticalSection",
            TryEnterCriticalSection as *const () as u32,
        ),
        (
            "LeaveCriticalSection",
            LeaveCriticalSection as *const () as u32,
        ),
        (
            "DeleteCriticalSection",
            DeleteCriticalSection as *const () as u32,
        ),
    ]
}

fn thread_id() -> u32 {
    // SAFETY: gettid has no preconditions.
    unsafe { libc::gettid() as u32 }
}

#[allow(non_snake_case)]
extern "stdcall" fn InitializeCriticalSection(cs: *mut CriticalSection) {
    InitializeCriticalSectionAndSpinCount(cs, 0);
}

/// Always succeeds, as on Windows Vista and later.
#[allow(non_snake_case)]
extern "stdcall" fn InitializeCriticalSectionAndSpinCount(
    cs: *mut CriticalSection,
    spin_count: u32,
) -> i32 {
    // SAFETY: the caller passes a writable CRITICAL_SECTION. Nothing else
    // can use it before it is initialised.
    unsafe {
        cs.write(CriticalSection {
            debug_info: AtomicU32::new(0),
            lock: AtomicU32::new(FREE),
            recursion: AtomicU32::new(0),
            owner: AtomicU32::new(0),
            lock_semaphore: AtomicU32::new(0),
            spin_count: AtomicU32::new(spin_count),
        })
    };
    1
}

#[allow(non_snake_case)]
pub(crate) extern "stdcall" fn EnterCriticalSection(cs: *mut CriticalSection) {
    // SAFETY: the caller passes an initialised CRITICAL_SECTION.
    let cs = unsafe { &*cs };
    let me = thread_id();
    if cs.owner.load(Ordering::Relaxed) == me {
        cs.recursion.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if let Err(mut state) =
        cs.lock
            .compare_exchange(FREE, HELD, Ordering::Acquire, Ordering::Relaxed)
    {
        if state != CONTENDED {
            state = cs.lock.swap(CONTENDED, Ordering::Acquire);
        }
        while state != FREE {
            futex(
                &cs.lock,
                libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                CONTENDED,
            );
            state = cs.lock.swap(CONTENDED, Ordering::Acquire);
        }
    }
    cs.owner.store(me, Ordering::Relaxed);
    cs.recursion.store(1, Ordering::Relaxed);
}

#[allow(non_snake_case)]
extern "stdcall" fn TryEnterCriticalSection(cs: *mut CriticalSection) -> i32 {
    // SAFETY: the caller passes an initialised CRITICAL_SECTION.
    let cs = unsafe { &*cs };
    let me = thread_id();
    if cs.owner.load(Ordering::Relaxed) == me {
        cs.recursion.fetch_add(1, Ordering::Relaxed);
        return 1;
    }
    if cs
        .lock
        .compare_exchange(FREE, HELD, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return 0;
    }
    cs.owner.store(me, Ordering::Relaxed);
    cs.recursion.store(1, Ordering::Relaxed);
    1
}

#[allow(non_snake_case)]
pub(crate) extern "stdcall" fn LeaveCriticalSection(cs: *mut CriticalSection) {
    // SAFETY: the caller passes an initialised CRITICAL_SECTION it owns.
    let cs = unsafe { &*cs };
    if cs.recursion.fetch_sub(1, Ordering::Relaxed) > 1 {
        return;
    }
    cs.owner.store(0, Ordering::Relaxed);
    if cs.lock.swap(FREE, Ordering::Release) == CONTENDED {
        futex(&cs.lock, libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG, 1);
    }
}

#[allow(non_snake_case)]
extern "stdcall" fn DeleteCriticalSection(cs: *mut CriticalSection) {
    // We hold no resources outside the structure. Clearing it makes a use
    // after delete look like a fresh, unowned section.
    InitializeCriticalSection(cs);
}

fn futex(word: &AtomicU32, op: libc::c_int, value: u32) {
    // SAFETY: word is a valid, aligned u32 for the duration of the call.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word.as_ptr(),
            op,
            value,
            std::ptr::null::<libc::timespec>(),
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;

    fn new() -> Box<CriticalSection> {
        let mut cs = Box::new(MaybeUninit::<CriticalSection>::uninit());
        InitializeCriticalSection(cs.as_mut_ptr());
        // SAFETY: initialised just above.
        unsafe { Box::from_raw(Box::into_raw(cs).cast()) }
    }

    fn ptr(cs: &CriticalSection) -> *mut CriticalSection {
        cs as *const _ as *mut _
    }

    #[test]
    fn layout_is_rtl_critical_section() {
        assert_eq!(std::mem::size_of::<CriticalSection>(), 24);
    }

    #[test]
    fn owner_can_reenter_and_others_cannot() {
        let cs = new();
        EnterCriticalSection(ptr(&cs));
        assert_eq!(TryEnterCriticalSection(ptr(&cs)), 1);
        assert_eq!(cs.recursion.load(Ordering::Relaxed), 2);
        let addr = ptr(&cs) as usize;
        let other = std::thread::spawn(move || TryEnterCriticalSection(addr as *mut _));
        assert_eq!(other.join().unwrap(), 0);

        LeaveCriticalSection(ptr(&cs));
        LeaveCriticalSection(ptr(&cs));
        assert_eq!(cs.owner.load(Ordering::Relaxed), 0);
        let other = std::thread::spawn(move || {
            let got = TryEnterCriticalSection(addr as *mut _);
            LeaveCriticalSection(addr as *mut _);
            got
        });
        assert_eq!(other.join().unwrap(), 1);
        DeleteCriticalSection(ptr(&cs));
    }

    #[test]
    fn spin_count_is_kept() {
        let mut cs = MaybeUninit::<CriticalSection>::uninit();
        assert_eq!(
            InitializeCriticalSectionAndSpinCount(cs.as_mut_ptr(), 4000),
            1
        );
        // SAFETY: initialised just above.
        assert_eq!(
            unsafe { cs.assume_init_ref() }
                .spin_count
                .load(Ordering::Relaxed),
            4000
        );
    }

    #[test]
    fn excludes_under_contention() {
        let cs = new();
        let counter = std::cell::UnsafeCell::new(0u32);
        struct Shared(*mut CriticalSection, *mut u32);
        // SAFETY: the counter is only touched inside the critical section.
        unsafe impl Sync for Shared {}
        let shared = Shared(ptr(&cs), counter.get());
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    let shared = &shared;
                    for _ in 0..10_000 {
                        EnterCriticalSection(shared.0);
                        // SAFETY: we hold the critical section.
                        unsafe { *shared.1 += 1 };
                        LeaveCriticalSection(shared.0);
                    }
                });
            }
        });
        assert_eq!(counter.into_inner(), 40_000);
    }
}
