//! The process heap: `GetProcessHeap`, `HeapAlloc`, `HeapFree`.
//!
//! The process heap is host libc's heap, as for `msvcrt!malloc`. Its
//! handle is the address of a private byte, so it is non-NULL and unique.
//! Following the HeapAlloc and HeapFree pages on Microsoft Learn:
//! `HEAP_ZERO_MEMORY` zeroes the block, and a failed allocation returns
//! NULL. Other heaps (`HeapCreate`) are not implemented: a handle that is
//! not the process heap fails and is a logged gap, as is
//! `HEAP_GENERATE_EXCEPTIONS`, which would raise an exception.

use std::ffi::c_void;

use super::error::{ERROR_INVALID_HANDLE, set_last_error};
use crate::gap::GapKind;
use crate::runtime::with_current;

const HEAP_NO_SERIALIZE: u32 = 0x1;
const HEAP_GENERATE_EXCEPTIONS: u32 = 0x4;
const HEAP_ZERO_MEMORY: u32 = 0x8;

static PROCESS_HEAP: u8 = 0;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("GetProcessHeap", GetProcessHeap as *const () as u32),
        ("HeapAlloc", HeapAlloc as *const () as u32),
        ("HeapFree", HeapFree as *const () as u32),
    ]
}

fn gap(what: &str) {
    with_current(|p| p.record_runtime_gap(GapKind::Feature, "kernel32.dll", what));
}

#[allow(non_snake_case)]
extern "stdcall" fn GetProcessHeap() -> u32 {
    &PROCESS_HEAP as *const u8 as u32
}

/// Whether `heap` is the process heap; logs a gap for any other.
fn known(heap: u32, function: &str) -> bool {
    if heap == GetProcessHeap() {
        return true;
    }
    gap(&format!("{function} on a heap other than the process heap"));
    false
}

/// A block of `size` bytes from `heap`, zeroed with HEAP_ZERO_MEMORY, or
/// NULL.
#[allow(non_snake_case)]
extern "stdcall" fn HeapAlloc(heap: u32, flags: u32, size: usize) -> *mut c_void {
    if !known(heap, "HeapAlloc") {
        return std::ptr::null_mut();
    }
    if flags & HEAP_GENERATE_EXCEPTIONS != 0 {
        gap("HeapAlloc: HEAP_GENERATE_EXCEPTIONS");
    }
    let flags = flags & !(HEAP_NO_SERIALIZE | HEAP_GENERATE_EXCEPTIONS);
    // A zero-byte request still gets a unique block, as on Windows.
    let size = size.max(1);
    // SAFETY: plain allocations.
    unsafe {
        if flags & HEAP_ZERO_MEMORY != 0 {
            libc::calloc(1, size)
        } else {
            libc::malloc(size)
        }
    }
}

/// Frees a block from `heap`. A NULL block is nothing to free.
#[allow(non_snake_case)]
extern "stdcall" fn HeapFree(heap: u32, _flags: u32, block: *mut c_void) -> i32 {
    if !known(heap, "HeapFree") {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    // SAFETY: NULL or a block from HeapAlloc (the API's contract).
    unsafe { libc::free(block) };
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn the_process_heap_allocates_and_frees() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let heap = GetProcessHeap();
        assert_ne!(heap, 0);
        assert_eq!(heap, GetProcessHeap());
        let block = HeapAlloc(heap, HEAP_ZERO_MEMORY, 64).cast::<u8>();
        assert!(!block.is_null());
        assert_eq!(block as usize % 8, 0);
        // SAFETY: 64 bytes just allocated.
        assert!(
            unsafe { std::slice::from_raw_parts(block, 64) }
                .iter()
                .all(|&b| b == 0)
        );
        assert_eq!(HeapFree(heap, 0, block.cast()), 1);
        assert_eq!(HeapFree(heap, 0, std::ptr::null_mut()), 1);
        assert!(runtime.lock().gaps().is_empty());
        assert!(HeapAlloc(0x1234, 0, 8).is_null());
        assert_eq!(HeapFree(0x1234, 0, std::ptr::null_mut()), 0);
        assert_eq!(runtime.lock().gaps().len(), 2);
    }
}
