//! Number parsing: `strtol`, `strtoul`, `atoi`, `atol`.
//!
//! Written here because overflow must set the CRT's `errno`, not libc's.
//! Rules from the C standard and the functions' pages on Microsoft Learn:
//! leading white space, an optional sign, `0x` for base 16 (and base 0
//! picks 8, 10 or 16 from the prefix). On overflow, `strtol` returns
//! LONG_MAX or LONG_MIN, `strtoul` ULONG_MAX, and both set ERANGE.
//! `strtoul` negates a value with a minus sign. `atoi` and `atol` behave
//! like `strtol` in base 10.

use std::ffi::c_char;

use super::errno::{self, ERANGE};

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("strtol", strtol as *const () as u32),
        ("strtoul", strtoul as *const () as u32),
        ("atoi", atoi as *const () as u32),
        ("atol", atol as *const () as u32),
    ]
}

struct Parsed {
    negative: bool,
    /// The magnitude, or None if it overflowed `u32`.
    magnitude: Option<u32>,
    /// Bytes consumed; 0 when no digits were found.
    consumed: usize,
}

fn digit(b: u8) -> Option<u32> {
    (b as char).to_digit(36)
}

/// # Safety
///
/// `s` points at a NUL-terminated string.
unsafe fn parse(s: *const c_char, base: i32) -> Option<Parsed> {
    // SAFETY: the caller's contract.
    let bytes = unsafe { std::ffi::CStr::from_ptr(s) }.to_bytes();
    if base != 0 && !(2..=36).contains(&base) {
        return None;
    }
    let mut i = bytes
        .iter()
        .take_while(|b| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
        .count();
    let negative = bytes.get(i) == Some(&b'-');
    if matches!(bytes.get(i), Some(b'-' | b'+')) {
        i += 1;
    }
    let hex_prefix = bytes.get(i) == Some(&b'0')
        && matches!(bytes.get(i + 1), Some(b'x' | b'X'))
        && bytes
            .get(i + 2)
            .and_then(|&b| digit(b))
            .is_some_and(|d| d < 16);
    let base = match base {
        0 if hex_prefix => 16,
        0 if bytes.get(i) == Some(&b'0') => 8,
        0 => 10,
        b => b as u32,
    };
    if base == 16 && hex_prefix {
        i += 2;
    }
    let start = i;
    let mut magnitude = Some(0u32);
    while let Some(d) = bytes.get(i).and_then(|&b| digit(b)).filter(|&d| d < base) {
        magnitude = magnitude
            .and_then(|m| m.checked_mul(base))
            .and_then(|m| m.checked_add(d));
        i += 1;
    }
    Some(Parsed {
        negative,
        magnitude,
        consumed: if i == start { 0 } else { i },
    })
}

/// # Safety
///
/// `end` is NULL or writable.
unsafe fn set_end(s: *const c_char, end: *mut *mut c_char, consumed: usize) {
    if !end.is_null() {
        // SAFETY: the caller's contract; consumed is within the string.
        unsafe { *end = s.add(consumed).cast_mut() };
    }
}

fn to_long(p: &Parsed) -> i32 {
    match (p.magnitude, p.negative) {
        (Some(m), false) if m <= i32::MAX as u32 => m as i32,
        (Some(m), true) if m <= 1 << 31 => (m as i64).wrapping_neg() as i32,
        (_, false) => {
            errno::set(ERANGE);
            i32::MAX
        }
        (_, true) => {
            errno::set(ERANGE);
            i32::MIN
        }
    }
}

extern "C" fn strtol(s: *const c_char, end: *mut *mut c_char, base: i32) -> i32 {
    // SAFETY: a NUL-terminated string and a NULL or writable end pointer.
    unsafe {
        let Some(p) = parse(s, base) else {
            errno::set(super::errno::EINVAL);
            set_end(s, end, 0);
            return 0;
        };
        set_end(s, end, p.consumed);
        to_long(&p)
    }
}

extern "C" fn strtoul(s: *const c_char, end: *mut *mut c_char, base: i32) -> u32 {
    // SAFETY: as for strtol.
    unsafe {
        let Some(p) = parse(s, base) else {
            errno::set(super::errno::EINVAL);
            set_end(s, end, 0);
            return 0;
        };
        set_end(s, end, p.consumed);
        match p.magnitude {
            Some(m) if p.negative => m.wrapping_neg(),
            Some(m) => m,
            None => {
                errno::set(ERANGE);
                u32::MAX
            }
        }
    }
}

extern "C" fn atol(s: *const c_char) -> i32 {
    strtol(s, std::ptr::null_mut(), 10)
}

extern "C" fn atoi(s: *const c_char) -> i32 {
    atol(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long(s: &std::ffi::CStr, base: i32) -> (i32, usize) {
        let mut end = std::ptr::null_mut();
        let v = strtol(s.as_ptr(), &mut end, base);
        (v, end as usize - s.as_ptr() as usize)
    }

    #[test]
    fn strtol_bases_signs_and_ends() {
        assert_eq!(long(c"  -42abc", 10), (-42, 5));
        assert_eq!(long(c"+17", 10), (17, 3));
        assert_eq!(long(c"0x1F", 0), (31, 4));
        assert_eq!(long(c"0x1F", 16), (31, 4));
        assert_eq!(long(c"017", 0), (15, 3));
        assert_eq!(long(c"0xg", 0), (0, 1), "0 then a stray x");
        assert_eq!(long(c"z", 36), (35, 1));
        assert_eq!(long(c"abc", 10), (0, 0), "no digits: end is the start");
        assert_eq!(long(c"-2147483648", 10), (i32::MIN, 11));
    }

    #[test]
    fn overflow_clamps_and_sets_erange() {
        errno::set(0);
        assert_eq!(long(c"2147483648", 10).0, i32::MAX);
        assert_eq!(errno::get(), ERANGE);
        assert_eq!(long(c"-99999999999", 10).0, i32::MIN);
        errno::set(0);
        assert_eq!(
            strtoul(c"4294967295".as_ptr(), std::ptr::null_mut(), 10),
            u32::MAX
        );
        assert_eq!(errno::get(), 0);
        assert_eq!(
            strtoul(c"4294967296".as_ptr(), std::ptr::null_mut(), 10),
            u32::MAX
        );
        assert_eq!(errno::get(), ERANGE);
        assert_eq!(strtoul(c"-1".as_ptr(), std::ptr::null_mut(), 10), u32::MAX);
    }

    #[test]
    fn atoi_and_atol_are_base_ten() {
        assert_eq!(atoi(c" 1514 ".as_ptr()), 1514);
        assert_eq!(atol(c"0x10".as_ptr()), 0);
        assert_eq!(atoi(c"-7".as_ptr()), -7);
    }
}
