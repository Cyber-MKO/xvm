//! UTC time and uptime: `GetSystemTime`, `GetSystemTimeAsFileTime`,
//! `FileTimeToSystemTime`, `SystemTimeToFileTime`, `GetTickCount`.
//!
//! `GetTickCount` counts milliseconds since the host booted, wrapping
//! after 49.7 days. The boot time is the `start_time` the engine gives
//! the System process (PID 4): the profile's `os_info.last_boot`, or when
//! the engine loaded the host. Without it, a logged gap counts from the
//! process's start.
//!
//! `QueryPerformanceCounter` counts from the same boot at the frequency
//! `QueryPerformanceFrequency` gives: 10 MHz, the value "Acquiring
//! high-resolution time stamps" on Microsoft Learn documents for Windows
//! running under a hypervisor, as the hosts we model do.
//!
//! The clock is the real machine's. A FILETIME counts 100-nanosecond
//! intervals since 1601-01-01 UTC; a SYSTEMTIME is wYear, wMonth,
//! wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds (16 bytes),
//! as their pages on Microsoft Learn describe. Conversions accept years
//! 1601 to 30827.

use super::error::{ERROR_INVALID_PARAMETER, set_last_error};
use crate::timezone::{civil_from_days, days_from_civil};

/// Days from 1601-01-01 to 1970-01-01.
const DAYS_1601_TO_1970: i64 = 134_774;
const TICKS_PER_DAY: u64 = 864_000_000_000;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("GetSystemTime", GetSystemTime as *const () as u32),
        (
            "GetSystemTimeAsFileTime",
            GetSystemTimeAsFileTime as *const () as u32,
        ),
        (
            "FileTimeToSystemTime",
            FileTimeToSystemTime as *const () as u32,
        ),
        (
            "SystemTimeToFileTime",
            SystemTimeToFileTime as *const () as u32,
        ),
        ("GetTickCount", GetTickCount as *const () as u32),
        (
            "QueryPerformanceCounter",
            QueryPerformanceCounter as *const () as u32,
        ),
        (
            "QueryPerformanceFrequency",
            QueryPerformanceFrequency as *const () as u32,
        ),
    ]
}

/// Now, as a FILETIME.
pub(crate) fn now() -> u64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    super::attributes::filetime(d.as_secs() as i64, d.subsec_nanos() as i64)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// Unix milliseconds of an ISO 8601 UTC time such as
/// `2026-10-17T13:32:07.954Z`.
pub(crate) fn parse_utc(text: &str) -> Option<i64> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let mut d = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let (hms, fraction) = time.split_once('.').unwrap_or((time, "0"));
    let mut t = hms.split(':').map(|p| p.parse::<i64>().ok());
    let (h, min, sec) = (t.next()??, t.next()??, t.next()??);
    let ms: i64 = format!("{fraction:0<3}")[..3].parse().ok()?;
    Some(((days_from_civil(y, m, day) * 24 + h) * 60 + min) * 60_000 + sec * 1000 + ms)
}

fn boot_ms() -> i64 {
    if let Some(boot) = crate::runtime::with_current(|p| p.boot_ms) {
        return boot;
    }
    const CALLER: crate::win::facts::Caller = ("kernel32.dll", "GetTickCount");
    let found = crate::win::facts::call(CALLER, "proc.get", serde_json::json!({"pid": 4}))
        .ok()
        .and_then(|p| {
            p.get("start_time")
                .and_then(|t| t.as_str())
                .and_then(parse_utc)
        });
    let boot = found.unwrap_or_else(|| {
        crate::runtime::with_current(|p| {
            p.record_runtime_gap(
                crate::gap::GapKind::Feature,
                CALLER.0,
                "GetTickCount: no boot time from the engine",
            )
        });
        now_ms()
    });
    crate::runtime::with_current(|p| *p.boot_ms.get_or_insert(boot))
}

/// Milliseconds since the host booted.
#[allow(non_snake_case)]
extern "stdcall" fn GetTickCount() -> u32 {
    (now_ms() - boot_ms()) as u32
}

const QPC_FREQUENCY: i64 = 10_000_000;

#[allow(non_snake_case)]
extern "stdcall" fn QueryPerformanceFrequency(out: *mut i64) -> i32 {
    // SAFETY: a LARGE_INTEGER (the API's contract).
    unsafe { out.write_unaligned(QPC_FREQUENCY) };
    1
}

/// 100-nanosecond ticks since the host booted.
#[allow(non_snake_case)]
extern "stdcall" fn QueryPerformanceCounter(out: *mut i64) -> i32 {
    let boot_ticks = boot_ms() * 10_000;
    let now_ticks = (now() as i64) - 11_644_473_600 * 10_000_000;
    // SAFETY: as above.
    unsafe { out.write_unaligned((now_ticks - boot_ticks).max(0)) };
    1
}

fn to_systemtime(ft: u64) -> Option<[u16; 8]> {
    if ft >= 0x8000_0000_0000_0000 {
        return None;
    }
    let days = (ft / TICKS_PER_DAY) as i64 - DAYS_1601_TO_1970;
    let rest = ft % TICKS_PER_DAY;
    let (year, month, day) = civil_from_days(days);
    let ms = rest / 10_000;
    Some([
        year as u16,
        month as u16,
        // 1970-01-01 was a Thursday (4).
        (days + 4).rem_euclid(7) as u16,
        day as u16,
        (ms / 3_600_000) as u16,
        (ms / 60_000 % 60) as u16,
        (ms / 1000 % 60) as u16,
        (ms % 1000) as u16,
    ])
}

fn from_systemtime(st: [u16; 8]) -> Option<u64> {
    let [year, month, _, day, hour, minute, second, ms] = st.map(u64::from);
    let days_in_month = days_from_civil(
        year as i64 + (month == 12) as i64,
        (month % 12 + 1) as i64,
        1,
    ) - days_from_civil(year as i64, month as i64, 1);
    let valid = (1601..=30827).contains(&year)
        && (1..=12).contains(&month)
        && day >= 1
        && (day as i64) <= days_in_month
        && hour < 24
        && minute < 60
        && second < 60
        && ms < 1000;
    if !valid {
        return None;
    }
    let days = (days_from_civil(year as i64, month as i64, day as i64) + DAYS_1601_TO_1970) as u64;
    Some(days * TICKS_PER_DAY + ((hour * 60 + minute) * 60 + second) * 10_000_000 + ms * 10_000)
}

fn write<const N: usize, T: Copy>(out: *mut T, value: [T; N]) {
    // SAFETY: out holds N values (the APIs' contracts).
    unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), out, N) };
}

#[allow(non_snake_case)]
extern "stdcall" fn GetSystemTime(out: *mut u16) {
    write(out, to_systemtime(now()).expect("a time after 1601"));
}

#[allow(non_snake_case)]
extern "stdcall" fn GetSystemTimeAsFileTime(out: *mut u32) {
    let ft = now();
    write(out, [ft as u32, (ft >> 32) as u32]);
}

#[allow(non_snake_case)]
extern "stdcall" fn FileTimeToSystemTime(ft: *const u32, out: *mut u16) -> i32 {
    // SAFETY: a FILETIME (the API's contract).
    let value = unsafe { (*ft.add(1) as u64) << 32 | *ft as u64 };
    match to_systemtime(value) {
        Some(st) => {
            write(out, st);
            1
        }
        None => {
            set_last_error(ERROR_INVALID_PARAMETER);
            0
        }
    }
}

/// wDayOfWeek is ignored, as documented.
#[allow(non_snake_case)]
extern "stdcall" fn SystemTimeToFileTime(st: *const u16, out: *mut u32) -> i32 {
    let mut fields = [0u16; 8];
    // SAFETY: a SYSTEMTIME (the API's contract).
    unsafe { std::ptr::copy_nonoverlapping(st, fields.as_mut_ptr(), 8) };
    match from_systemtime(fields) {
        Some(ft) => {
            write(out, [ft as u32, (ft >> 32) as u32]);
            1
        }
        None => {
            set_last_error(ERROR_INVALID_PARAMETER);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn conversions_both_ways() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        // 2026-10-17 09:30:15.250 UTC was a Saturday.
        let st = [2026u16, 10, 6, 17, 9, 30, 15, 250];
        let mut ft = [0u32; 2];
        assert_eq!(SystemTimeToFileTime(st.as_ptr(), ft.as_mut_ptr()), 1);
        let value = (ft[1] as u64) << 32 | ft[0] as u64;
        let unix = (value / 10_000_000) as i64 - 11_644_473_600;
        assert_eq!(
            unix,
            days_from_civil(2026, 10, 17) * 86_400 + 9 * 3600 + 30 * 60 + 15
        );
        let mut back = [0u16; 8];
        assert_eq!(FileTimeToSystemTime(ft.as_ptr(), back.as_mut_ptr()), 1);
        assert_eq!(back, st);
        let mut bad = st;
        bad[3] = 31;
        bad[1] = 2;
        assert_eq!(
            SystemTimeToFileTime(bad.as_ptr(), ft.as_mut_ptr()),
            0,
            "31 February"
        );
        assert_eq!(to_systemtime(0).unwrap()[..4], [1601, 1, 1, 1], "a Monday");
    }

    #[test]
    fn ticks_count_from_the_engine_boot_time() {
        assert_eq!(parse_utc("1970-01-02T00:00:01.5Z"), Some(86_401_500));
        assert_eq!(parse_utc("2026-10-17T13:32:07Z").unwrap() % 1000, 0);
        let base = serde_json::json!({
            "schema": 1, "kind": "base-image", "name": "b", "os": "windows",
            "source": {"golden_capture": "synthetic"},
            "os_info": {"last_boot": "2026-10-01T00:00:00Z"},
            "processes": [{"id": "system", "image": "System", "pid": 4, "start_offset_s": 0}],
        });
        let host = serde_json::json!({"schema": 1, "kind": "host-profile", "name": "h",
            "base": "b", "os": "windows", "identity": {"hostname": "H"}});
        let mut process = Process::new(Vec::new());
        process.engine = Some(crate::win::facts::test_engine(base, host));
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        let expected = now_ms() - parse_utc("2026-10-01T00:00:00Z").unwrap();
        assert!((GetTickCount() as i64 - expected as u32 as i64).abs() < 5000);
        let (mut freq, mut a, mut b) = (0i64, 0i64, 0i64);
        assert_eq!(QueryPerformanceFrequency(&mut freq), 1);
        assert_eq!(QueryPerformanceCounter(&mut a), 1);
        std::thread::sleep(std::time::Duration::from_millis(10));
        QueryPerformanceCounter(&mut b);
        assert!(b - a >= freq / 100, "10 ms of ticks");
        assert!((a / freq - expected / 1000).abs() < 5, "counted from boot");
        assert!(runtime.lock().gaps().is_empty());
    }

    #[test]
    fn now_is_the_real_clock() {
        let mut ft = [0u32; 2];
        GetSystemTimeAsFileTime(ft.as_mut_ptr());
        let mut st = [0u16; 8];
        GetSystemTime(st.as_mut_ptr());
        let unix = ((ft[1] as u64) << 32 | ft[0] as u64) / 10_000_000 - 11_644_473_600;
        let real = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(real.abs_diff(unix) < 5);
        assert!(st[0] >= 2026);
    }
}
