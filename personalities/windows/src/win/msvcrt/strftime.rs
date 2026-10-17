//! Formatting times: `strftime`.
//!
//! The "C" locale and the specifiers on the strftime page on Microsoft
//! Learn that `msvcrt.dll` supports:
//!
//! | Specifier | Output |
//! | --- | --- |
//! | `%a %A %b %B` | English day and month names, short and long |
//! | `%c %x %X` | `%m/%d/%y %H:%M:%S`, `%m/%d/%y`, `%H:%M:%S`; with `#`, `%c` and `%x` give the long date (`Tuesday, March 14, 1995`) |
//! | `%d %H %I %j %m %M %S %U %w %W %y %Y` | Numbers; `#` drops leading zeros |
//! | `%p` | AM or PM |
//! | `%z %Z` | The profile's time zone name: standard or daylight by `tm_isdst` |
//! | `%%` | `%` |
//!
//! It returns the length written without the NUL, or 0 when that and
//! the NUL do not fit. Any other specifier is a logged gap: 0 and EINVAL.

use std::ffi::c_char;

use super::errno::{self, EINVAL};
use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::win::text::ansi;

const DAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("strftime", strftime as *const () as u32)]
}

/// `struct tm` as nine ints.
#[derive(Clone, Copy)]
struct Fields([i32; 9]);

impl Fields {
    fn sec(&self) -> i32 {
        self.0[0]
    }
    fn min(&self) -> i32 {
        self.0[1]
    }
    fn hour(&self) -> i32 {
        self.0[2]
    }
    fn mday(&self) -> i32 {
        self.0[3]
    }
    fn mon(&self) -> i32 {
        self.0[4]
    }
    fn year(&self) -> i32 {
        self.0[5] + 1900
    }
    fn wday(&self) -> i32 {
        self.0[6]
    }
    fn yday(&self) -> i32 {
        self.0[7]
    }
    fn isdst(&self) -> i32 {
        self.0[8]
    }
}

fn name<'a>(names: &[&'a str], i: i32) -> Option<&'a str> {
    names.get(usize::try_from(i).ok()?).copied()
}

/// Week of the year with weeks starting on `first` (0 Sunday, 1 Monday).
fn week(t: &Fields, first: i32) -> i32 {
    (t.yday() + 7 - (t.wday() - first + 7) % 7) / 7
}

/// Formats `format`, or None for a specifier we do not support (its
/// letter) or a field out of range.
fn format(format: &str, t: &Fields, zone: &(String, String)) -> Result<String, String> {
    let mut out = String::new();
    let mut chars = format.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let mut spec = chars.next().ok_or("%")?;
        let alternate = spec == '#';
        if alternate {
            spec = chars.next().ok_or("%#")?;
        }
        let num = |v: i32, width: usize| {
            if alternate {
                v.to_string()
            } else {
                format!("{v:0width$}")
            }
        };
        let bad = || format!("%{spec}");
        let day = || name(&DAYS, t.wday()).ok_or_else(bad);
        let month = || name(&MONTHS, t.mon()).ok_or_else(bad);
        let piece = match spec {
            'a' => day()?[..3].to_string(),
            'A' => day()?.to_string(),
            'b' => month()?[..3].to_string(),
            'B' => month()?.to_string(),
            'c' if alternate => format!(
                "{}, {} {}, {} {:02}:{:02}:{:02}",
                day()?,
                month()?,
                t.mday(),
                t.year(),
                t.hour(),
                t.min(),
                t.sec()
            ),
            'c' => format!(
                "{:02}/{:02}/{:02} {:02}:{:02}:{:02}",
                t.mon() + 1,
                t.mday(),
                t.year().rem_euclid(100),
                t.hour(),
                t.min(),
                t.sec()
            ),
            'x' if alternate => format!("{}, {} {}, {}", day()?, month()?, t.mday(), t.year()),
            'x' => format!(
                "{:02}/{:02}/{:02}",
                t.mon() + 1,
                t.mday(),
                t.year().rem_euclid(100)
            ),
            'X' => format!("{:02}:{:02}:{:02}", t.hour(), t.min(), t.sec()),
            'd' => num(t.mday(), 2),
            'H' => num(t.hour(), 2),
            'I' => num((t.hour() + 11) % 12 + 1, 2),
            'j' => num(t.yday() + 1, 3),
            'm' => num(t.mon() + 1, 2),
            'M' => num(t.min(), 2),
            'S' => num(t.sec(), 2),
            'U' => num(week(t, 0), 2),
            'W' => num(week(t, 1), 2),
            'w' => t.wday().to_string(),
            'y' => num(t.year().rem_euclid(100), 2),
            'Y' => num(t.year(), 4),
            'p' => (if t.hour() < 12 { "AM" } else { "PM" }).to_string(),
            'z' | 'Z' => if t.isdst() > 0 { &zone.1 } else { &zone.0 }.clone(),
            '%' => "%".to_string(),
            _ => return Err(bad()),
        };
        out.push_str(&piece);
    }
    Ok(out)
}

extern "C" fn strftime(dest: *mut u8, max: usize, fmt: *const c_char, tm: *const i32) -> usize {
    if dest.is_null() || fmt.is_null() || tm.is_null() || max == 0 {
        errno::set(EINVAL);
        return 0;
    }
    // SAFETY: a NUL-terminated format and a struct tm (the contract).
    let (Some(text), fields) = (unsafe { ansi(fmt) }, unsafe {
        Fields(std::ptr::read_unaligned(tm.cast::<[i32; 9]>()))
    }) else {
        errno::set(EINVAL);
        return 0;
    };
    let zone = with_current(|p| {
        let tz = &p.params.time_zone;
        (tz.standard_name.clone(), tz.daylight_name.clone())
    });
    let out = match format(&text, &fields, &zone) {
        Ok(out) => out,
        Err(spec) => {
            with_current(|p| {
                p.record_runtime_gap(GapKind::Feature, "msvcrt.dll", &format!("strftime {spec}"))
            });
            errno::set(EINVAL);
            // SAFETY: at least one writable byte.
            unsafe { *dest = 0 };
            return 0;
        }
    };
    if out.len() + 1 > max {
        return 0;
    }
    // SAFETY: `max` writable bytes; the text and NUL fit.
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr(), dest, out.len());
        *dest.add(out.len()) = 0;
    }
    out.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    /// Tuesday 14 March 1995, 12:41:29, the 73rd day, winter time.
    const T: [i32; 9] = [29, 41, 12, 14, 2, 95, 2, 72, 0];

    fn run(fmt: &std::ffi::CStr, max: usize) -> (usize, String) {
        let mut buf = vec![0u8; max.max(1)];
        let n = strftime(buf.as_mut_ptr(), max, fmt.as_ptr(), T.as_ptr());
        let end = buf.iter().position(|&b| b == 0).unwrap_or(0);
        (n, String::from_utf8(buf[..end].to_vec()).unwrap())
    }

    #[test]
    fn the_c_locale_specifiers() {
        let mut process = Process::new(Vec::new());
        process.params.time_zone.standard_name = "Coordinated Universal Time".into();
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        assert_eq!(run(c"%Y/%m/%d %H:%M:%S", 64).1, "1995/03/14 12:41:29");
        assert_eq!(run(c"%c", 64).1, "03/14/95 12:41:29");
        assert_eq!(run(c"%#c", 64).1, "Tuesday, March 14, 1995 12:41:29");
        assert_eq!(run(c"%#x", 64).1, "Tuesday, March 14, 1995");
        assert_eq!(run(c"%a %b %#d %I%p %j %w", 64).1, "Tue Mar 14 12PM 073 2");
        assert_eq!(run(c"%U %W %y %%", 64).1, "11 11 95 %");
        assert_eq!(run(c"%Z", 64).1, "Coordinated Universal Time");
        assert_eq!(run(c"%Y", 5), (4, "1995".to_string()));
        assert_eq!(run(c"%Y", 4).0, 0, "no room for the NUL");
        assert_eq!(run(c"%F", 64).0, 0);
        assert_eq!(runtime.lock().gaps().len(), 1);
    }
}
