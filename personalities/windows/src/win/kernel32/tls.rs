//! Dynamic thread-local storage: `TlsAlloc`, `TlsGetValue`,
//! `TlsSetValue`, `TlsFree`.
//!
//! Values live in each thread's TEB, in `TlsSlots[64]`. Allocating or
//! freeing a slot zeroes it in every live thread, as the TlsAlloc and
//! TlsFree pages describe. The 1024 `TlsExpansionSlots` beyond the first
//! 64 are not implemented: when the 64 run out, that is a logged gap.

use super::error::{ERROR_INVALID_PARAMETER, set_last_error};
use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::teb::TLS_SLOTS;

pub(crate) const TLS_OUT_OF_INDEXES: u32 = 0xffff_ffff;
const SLOT_COUNT: u32 = 64;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("TlsAlloc", TlsAlloc as *const () as u32),
        ("TlsGetValue", TlsGetValue as *const () as u32),
        ("TlsSetValue", TlsSetValue as *const () as u32),
        ("TlsFree", TlsFree as *const () as u32),
    ]
}

/// Zero slot `index` in every attached thread's TEB.
fn clear_everywhere(tebs: &[u32], index: u32) {
    for &teb in tebs {
        // SAFETY: each TEB page stays mapped while its thread is attached,
        // and the slot is ours to clear.
        unsafe { *((teb as usize + TLS_SLOTS + index as usize * 4) as *mut u32) = 0 };
    }
}

#[allow(non_snake_case)]
extern "stdcall" fn TlsAlloc() -> u32 {
    with_current(|p| match p.tls_slots.iter().position(|used| !used) {
        Some(i) => {
            p.tls_slots[i] = true;
            clear_everywhere(&p.tebs, i as u32);
            i as u32
        }
        None => {
            p.record_runtime_gap(GapKind::Feature, "kernel32.dll", "TlsAlloc beyond 64 slots");
            TLS_OUT_OF_INDEXES
        }
    })
}

/// Clears the last error on success, as documented, so callers can tell a
/// stored 0 from a failure.
#[allow(non_snake_case)]
extern "stdcall" fn TlsGetValue(index: u32) -> u32 {
    if index >= SLOT_COUNT {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let value: u32;
    // SAFETY: fs is this thread's TEB, which covers TlsSlots.
    unsafe {
        std::arch::asm!(
            "mov {0}, dword ptr fs:[{1} + {2} * 4]",
            out(reg) value,
            in(reg) TLS_SLOTS,
            in(reg) index,
            options(nostack, readonly, preserves_flags),
        )
    };
    set_last_error(0);
    value
}

#[allow(non_snake_case)]
extern "stdcall" fn TlsSetValue(index: u32, value: u32) -> i32 {
    if index >= SLOT_COUNT {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: as in TlsGetValue.
    unsafe {
        std::arch::asm!(
            "mov dword ptr fs:[{1} + {2} * 4], {0}",
            in(reg) value,
            in(reg) TLS_SLOTS,
            in(reg) index,
            options(nostack, preserves_flags),
        )
    };
    1
}

#[allow(non_snake_case)]
extern "stdcall" fn TlsFree(index: u32) -> i32 {
    let freed = with_current(|p| {
        if index >= SLOT_COUNT || !p.tls_slots[index as usize] {
            return false;
        }
        p.tls_slots[index as usize] = false;
        clear_everywhere(&p.tebs, index);
        true
    });
    if freed {
        1
    } else {
        set_last_error(ERROR_INVALID_PARAMETER);
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn slots_are_per_thread_and_zeroed_on_alloc_and_free() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let a = TlsAlloc();
        let b = TlsAlloc();
        assert_eq!((a, b), (0, 1));
        assert_eq!(TlsSetValue(a, 0x1234), 1);
        assert_eq!(TlsGetValue(a), 0x1234);
        assert_eq!(TlsGetValue(b), 0);

        let (other_teb, seen) = {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                let thread = runtime.attach().unwrap();
                let seen = TlsGetValue(a);
                TlsSetValue(b, 7);
                // Hand back the TEB while this thread is still attached.
                (thread.teb(), seen)
            })
            .join()
            .unwrap()
        };
        assert_ne!(other_teb, 0);
        assert_eq!(seen, 0, "a new thread starts with zeroes");
        assert_eq!(TlsGetValue(a), 0x1234, "other threads do not touch ours");

        assert_eq!(TlsFree(a), 1);
        assert_eq!(TlsGetValue(a), 0, "freeing zeroes the slot");
        assert_eq!(TlsFree(a), 0);
        TlsSetValue(b, 5);
        TlsFree(b);
        assert_eq!(TlsAlloc(), 0, "lowest free index");
        assert_eq!(TlsAlloc(), 1);
        assert_eq!(TlsGetValue(1), 0, "a reused slot starts at zero");
        assert_eq!(TlsGetValue(64), 0);
    }

    #[test]
    fn running_out_is_a_gap() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        for _ in 0..64 {
            assert_ne!(TlsAlloc(), TLS_OUT_OF_INDEXES);
        }
        assert_eq!(TlsAlloc(), TLS_OUT_OF_INDEXES);
        assert_eq!(runtime.lock().gaps().len(), 1);
    }
}
