//! Time: `time`, `localtime`, `gmtime`, `mktime`, `clock`.
//!
//! `msvcrt.dll`'s `time` is the 32-bit `_time32`: seconds since 1970 as
//! a signed 32-bit value, and -1 once that no longer fits (January 2038).
//! It reads the host clock. Per-host clock offsets (brief, section 8)
//! would apply here.
//!
//! `localtime` converts with the host profile's time zone, as the CRT
//! does through `GetTimeZoneInformation`. A `TZ` environment variable,
//! which the CRT would follow instead, is a logged gap.
//!
//! `gmtime` converts to UTC. It shares `localtime`'s buffer: the `gmtime`
//! page on Microsoft Learn says both use one `struct tm` per thread.
//!
//! `mktime` is the inverse of `localtime`, following its Learn page: out
//! of range fields carry over (minute 75 is 1:15 later), `tm_isdst` above
//! 0 means daylight time, 0 standard time, below 0 "work it out". It
//! writes the normalized fields, weekday and day of year back, and gives
//! -1 for a time a 32-bit `time_t` cannot hold.
//!
//! `clock` is the wall-clock time since the CRT started, in
//! `CLOCKS_PER_SEC` (1000) units, as the `clock` page on Learn says.

use std::cell::UnsafeCell;
use std::time::{SystemTime, UNIX_EPOCH};

use super::errno::{self, EINVAL};
use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::timezone::Tm;
use crate::win::kernel32::env::lookup;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("time", time as *const () as u32),
        ("localtime", localtime as *const () as u32),
        ("gmtime", gmtime as *const () as u32),
        ("mktime", mktime as *const () as u32),
        ("clock", clock as *const () as u32),
    ]
}

thread_local! {
    /// The `struct tm` that `localtime` returns, one per thread, as the
    /// CRT keeps it. Each call overwrites it.
    static TM: UnsafeCell<[i32; 9]> = const { UnsafeCell::new([0; 9]) };
}

/// A pointer to this thread's `struct tm` holding local time at `*t`, or
/// NULL with EINVAL for a NULL pointer or a negative time.
extern "C" fn localtime(t: *const i32) -> *mut i32 {
    // SAFETY: NULL or readable (the function's contract).
    let Some(&t) = (unsafe { t.as_ref() }) else {
        errno::set(EINVAL);
        return std::ptr::null_mut();
    };
    if t < 0 {
        errno::set(EINVAL);
        return std::ptr::null_mut();
    }
    if lookup("TZ").is_some() {
        with_current(|p| {
            p.record_runtime_gap(
                GapKind::Feature,
                "msvcrt.dll",
                "the TZ environment variable",
            )
        });
    }
    let tz = with_current(|p| p.params.time_zone.clone());
    let utc = t as i64;
    store(Tm::from_seconds(tz.to_local(utc), tz.is_daylight(utc)))
}

/// A pointer to this thread's `struct tm` holding UTC at `*t`, or NULL
/// with EINVAL for a NULL pointer or a negative time.
extern "C" fn gmtime(t: *const i32) -> *mut i32 {
    // SAFETY: NULL or readable (the function's contract).
    match unsafe { t.as_ref() } {
        Some(&t) if t >= 0 => store(Tm::from_seconds(t as i64, false)),
        _ => {
            errno::set(EINVAL);
            std::ptr::null_mut()
        }
    }
}

/// Seconds since 1970 for the local time in `*tm`, or -1.
extern "C" fn mktime(tm: *mut i32) -> i32 {
    if tm.is_null() {
        errno::set(EINVAL);
        return -1;
    }
    // SAFETY: a struct tm, nine ints (the function's contract).
    let f = unsafe { std::ptr::read_unaligned(tm.cast::<[i32; 9]>()) };
    let months = i64::from(f[5]) * 12 + i64::from(f[4]);
    let (year, month) = (1900 + months.div_euclid(12), months.rem_euclid(12) + 1);
    let local = (crate::timezone::days_from_civil(year, month, 1) + i64::from(f[3]) - 1) * 86_400
        + i64::from(f[2]) * 3600
        + i64::from(f[1]) * 60
        + i64::from(f[0]);
    let tz = with_current(|p| p.params.time_zone.clone());
    let standard = local + i64::from(tz.bias + tz.standard_bias) * 60;
    let daylight = local + i64::from(tz.bias + tz.daylight_bias) * 60;
    let utc = match f[8] {
        d if d > 0 => daylight,
        0 => standard,
        _ if tz.is_daylight(daylight) && tz.is_daylight(standard) => daylight,
        _ => standard,
    };
    let Ok(t) = i32::try_from(utc) else {
        return -1;
    };
    if t < 0 {
        return -1;
    }
    let out = Tm::from_seconds(tz.to_local(utc), tz.is_daylight(utc));
    let fields = [
        out.sec, out.min, out.hour, out.mday, out.mon, out.year, out.wday, out.yday, out.isdst,
    ];
    // SAFETY: as above.
    unsafe { std::ptr::write_unaligned(tm.cast::<[i32; 9]>(), fields) };
    t
}

/// Fills this thread's `struct tm` and returns it.
fn store(tm: Tm) -> *mut i32 {
    let fields = [
        tm.sec, tm.min, tm.hour, tm.mday, tm.mon, tm.year, tm.wday, tm.yday, tm.isdst,
    ];
    TM.with(|cell| {
        // SAFETY: the cell belongs to this thread; agent code holds the
        // pointer only until its next call, as with the CRT.
        unsafe { *cell.get() = fields };
        cell.get().cast()
    })
}

/// Milliseconds since the CRT started, or -1 once that no longer fits.
extern "C" fn clock() -> i32 {
    let started = with_current(|p| p.crt.started);
    i32::try_from(started.elapsed().as_millis()).unwrap_or(-1)
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
    fn localtime_follows_the_profile_zone() {
        use crate::process::Process;
        use crate::runtime::Runtime;
        use crate::timezone::{TimeZone, Transition};

        let mut process = Process::new(Vec::new());
        process.params.time_zone = TimeZone {
            key_name: "W. Europe Standard Time".into(),
            standard_name: "W. Europe Standard Time".into(),
            daylight_name: "W. Europe Daylight Time".into(),
            bias: -60,
            standard_bias: 0,
            daylight_bias: -60,
            standard_date: Some(Transition {
                month: 10,
                day_of_week: 0,
                week: 5,
                hour: 3,
                minute: 0,
                second: 0,
            }),
            daylight_date: Some(Transition {
                month: 3,
                day_of_week: 0,
                week: 5,
                hour: 2,
                minute: 0,
                second: 0,
            }),
        };
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        let read = |p: *mut i32| {
            // SAFETY: localtime returns this thread's struct tm.
            unsafe { std::slice::from_raw_parts(p, 9).to_vec() }
        };

        // 2026-07-15 12:00:00 UTC is 14:00 summer time in Berlin.
        let summer = 1_784_116_800;
        assert_eq!(read(localtime(&summer)), [0, 0, 14, 15, 6, 126, 3, 195, 1]);
        // 2026-01-15 12:00:00 UTC is 13:00 winter time.
        let winter = 1_768_478_400;
        assert_eq!(read(localtime(&winter)), [0, 0, 13, 15, 0, 126, 4, 14, 0]);
        assert_eq!(
            localtime(&summer),
            localtime(&winter),
            "one buffer per thread"
        );
        assert_eq!(read(gmtime(&summer)), [0, 0, 12, 15, 6, 126, 3, 195, 0]);
        assert_eq!(gmtime(&summer), localtime(&summer), "a shared buffer");
        assert!(gmtime(&-1).is_null());
        // mktime undoes localtime, normalizing on the way.
        let mut tm = read(localtime(&summer));
        assert_eq!(mktime(tm.as_mut_ptr()), summer);
        let mut late = [0, 75, 13, 15, 6, 126, 0, 0, -1];
        assert_eq!(mktime(late.as_mut_ptr()), summer + 15 * 60, "14:15 local");
        assert_eq!(late, [0, 15, 14, 15, 6, 126, 3, 195, 1]);
        let mut winter_tm = [0, 0, 13, 15, 0, 126, 0, 0, -1];
        assert_eq!(mktime(winter_tm.as_mut_ptr()), winter);
        assert_eq!(winter_tm[8], 0);
        let mut ancient = [0, 0, 0, 1, 0, 60, 0, 0, 0];
        assert_eq!(mktime(ancient.as_mut_ptr()), -1, "1960");
        assert!(localtime(&-1).is_null());
        assert!(localtime(std::ptr::null()).is_null());
        assert!(runtime.lock().gaps().is_empty());
    }

    #[test]
    fn clock_counts_milliseconds_since_the_crt_started() {
        use crate::process::Process;
        use crate::runtime::Runtime;
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let first = clock();
        std::thread::sleep(Duration::from_millis(30));
        let second = clock();
        assert!(first >= 0 && second - first >= 30, "{first} {second}");
    }

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
