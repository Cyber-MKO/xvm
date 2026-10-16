//! C heap: `malloc`, `calloc`, `realloc`, `free`, on host libc's heap.
//!
//! Edge cases follow the Microsoft Learn pages for each function, where
//! they differ from what C allows:
//! - `realloc(p, 0)` frees `p` and returns NULL.
//! - `realloc(NULL, n)` behaves like `malloc(n)`.
//!
//! On failure the functions return NULL. Setting the CRT's `errno` comes
//! with `_errno`.

use std::ffi::c_void;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("malloc", malloc as *const () as u32),
        ("calloc", calloc as *const () as u32),
        ("realloc", realloc as *const () as u32),
        ("free", free as *const () as u32),
    ]
}

extern "C" fn malloc(size: usize) -> *mut c_void {
    // SAFETY: plain allocation.
    unsafe { libc::malloc(size) }
}

extern "C" fn calloc(count: usize, size: usize) -> *mut c_void {
    // SAFETY: plain allocation; libc checks count * size for overflow.
    unsafe { libc::calloc(count, size) }
}

extern "C" fn realloc(block: *mut c_void, size: usize) -> *mut c_void {
    if !block.is_null() && size == 0 {
        free(block);
        return std::ptr::null_mut();
    }
    // SAFETY: block is NULL or came from this heap (caller's contract).
    unsafe { libc::realloc(block, size) }
}

extern "C" fn free(block: *mut c_void) {
    // SAFETY: block is NULL or came from this heap (caller's contract).
    unsafe { libc::free(block) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_grows_and_frees() {
        let p = malloc(16).cast::<u8>();
        assert!(!p.is_null());
        // SAFETY: 16 bytes were allocated, then grown to 64.
        unsafe {
            p.write_bytes(0xab, 16);
            let q = realloc(p.cast(), 64).cast::<u8>();
            assert!(!q.is_null());
            assert_eq!(*q.add(15), 0xab);
            free(q.cast());
        }
    }

    #[test]
    fn calloc_zeroes_and_refuses_overflow() {
        let p = calloc(8, 4).cast::<u8>();
        // SAFETY: 32 zeroed bytes.
        assert!(
            unsafe { std::slice::from_raw_parts(p, 32) }
                .iter()
                .all(|&b| b == 0)
        );
        free(p.cast());
        assert!(calloc(usize::MAX / 2, 4).is_null());
    }

    #[test]
    fn realloc_edge_cases_follow_the_documentation() {
        let p = realloc(std::ptr::null_mut(), 8);
        assert!(!p.is_null());
        assert!(realloc(p, 0).is_null());
        free(std::ptr::null_mut());
    }
}
