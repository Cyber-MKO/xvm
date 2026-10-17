//! Sorting: `qsort`.
//!
//! An in-place heapsort over `count` elements of `width` bytes, ordered
//! by the caller's `compare` function, as the qsort page on Microsoft
//! Learn describes it. Like `qsort`, it is not stable. It never fails,
//! whatever the comparison returns.

use std::ffi::c_void;

type Compare = extern "C" fn(*const c_void, *const c_void) -> i32;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("qsort", qsort as *const () as u32)]
}

extern "C" fn qsort(base: *mut u8, count: usize, width: usize, compare: Option<Compare>) {
    let Some(compare) = compare else { return };
    if base.is_null() || width == 0 || count < 2 {
        return;
    }
    // SAFETY: `count` elements of `width` bytes at `base` (the contract).
    let at = |i: usize| unsafe { base.add(i * width) };
    let less = |a: usize, b: usize| compare(at(a).cast(), at(b).cast()) < 0;
    // SAFETY: distinct elements inside the array.
    let swap = |a: usize, b: usize| unsafe { std::ptr::swap_nonoverlapping(at(a), at(b), width) };
    let sift_down = |mut root: usize, end: usize| loop {
        let mut child = 2 * root + 1;
        if child >= end {
            break;
        }
        if child + 1 < end && less(child, child + 1) {
            child += 1;
        }
        if !less(root, child) {
            break;
        }
        swap(root, child);
        root = child;
    };
    for start in (0..count / 2).rev() {
        sift_down(start, count);
    }
    for end in (1..count).rev() {
        swap(0, end);
        sift_down(0, end);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn by_value(a: *const c_void, b: *const c_void) -> i32 {
        // SAFETY: elements of the test's u32 array.
        let (a, b) = unsafe { (*a.cast::<u32>(), *b.cast::<u32>()) };
        a.cmp(&b) as i32
    }

    extern "C" fn nonsense(_: *const c_void, _: *const c_void) -> i32 {
        -1
    }

    #[test]
    fn sorts_with_the_callers_order() {
        let mut v: Vec<u32> = vec![5, 3, 9, 1, 3, 7, 0, 2, 8];
        qsort(v.as_mut_ptr().cast(), v.len(), 4, Some(by_value));
        assert_eq!(v, [0, 1, 2, 3, 3, 5, 7, 8, 9]);
        // Wide elements: 3-byte records sorted by their first byte.
        let mut records = [3u8, b'c', b'c', 1, b'a', b'a', 2, b'b', b'b'];
        extern "C" fn first(a: *const c_void, b: *const c_void) -> i32 {
            // SAFETY: records of the test array.
            let (a, b) = unsafe { (*a.cast::<u8>(), *b.cast::<u8>()) };
            i32::from(a) - i32::from(b)
        }
        qsort(records.as_mut_ptr(), 3, 3, Some(first));
        assert_eq!(records, [1, b'a', b'a', 2, b'b', b'b', 3, b'c', b'c']);
        // A comparison that is no order at all still ends, with the same
        // elements.
        let mut w: Vec<u32> = (0..50).collect();
        qsort(w.as_mut_ptr().cast(), w.len(), 4, Some(nonsense));
        w.sort();
        assert_eq!(w, (0..50).collect::<Vec<_>>());
        qsort(std::ptr::null_mut(), 3, 4, Some(by_value));
    }
}
