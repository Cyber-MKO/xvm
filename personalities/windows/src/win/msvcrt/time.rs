//! Time: `time`.
//!
//! `msvcrt.dll`'s `time` is the 32-bit `_time32`: seconds since 1970 as
//! a signed 32-bit value, and -1 once that no longer fits (January 2038).
//! It reads the host clock. Per-host clock offsets (brief, section 8)
//! would apply here.

use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("time", time as *const () as u32)]
}

fn now32(now: SystemTime) -> i32 {
    now.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i32::try_from(d.as_secs()).ok())
        .unwrap_or(-1)
}

/// Returns the time and, if `out` is not NULL, stores it there too.
extern "C" fn time(out: *mut i32) -> i32 {
    let t = now32(SystemTime::now());
    if !out.is_null() {
        // SAFETY: writable (the function's contract).
        unsafe { *out = t };
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn seconds_since_1970_in_32_bits() {
        let mut stored = 0;
        let t = time(&mut stored);
        assert_eq!(t, stored);
        let host = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!((host - t as i64).abs() <= 2);
        assert_eq!(
            now32(UNIX_EPOCH + Duration::from_secs(i32::MAX as u64)),
            i32::MAX
        );
        assert_eq!(
            now32(UNIX_EPOCH + Duration::from_secs(i32::MAX as u64 + 1)),
            -1
        );
    }
}
