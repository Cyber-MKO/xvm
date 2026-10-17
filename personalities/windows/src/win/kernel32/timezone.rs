//! The time zone: `GetTimeZoneInformation`.
//!
//! The zone comes from the host profile (`windows.time_zone`).
//! `TIME_ZONE_INFORMATION` is 172 bytes: Bias, StandardName[32],
//! StandardDate (SYSTEMTIME), StandardBias, DaylightName[32],
//! DaylightDate, DaylightBias.

use crate::runtime::with_current;
use crate::timezone::Transition;

const TIME_ZONE_ID_UNKNOWN: u32 = 0;
const TIME_ZONE_ID_STANDARD: u32 = 1;
const TIME_ZONE_ID_DAYLIGHT: u32 = 2;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![(
        "GetTimeZoneInformation",
        GetTimeZoneInformation as *const () as u32,
    )]
}

/// A `SYSTEMTIME` in day-in-month form (wYear 0); all zero for none.
fn systemtime(t: Option<Transition>) -> [u16; 8] {
    t.map_or([0; 8], |t| {
        [
            0,
            t.month,
            t.day_of_week,
            t.week,
            t.hour,
            t.minute,
            t.second,
            0,
        ]
    })
}

fn name(s: &str) -> [u16; 32] {
    let mut out = [0u16; 32];
    for (slot, unit) in out.iter_mut().zip(s.encode_utf16().take(31)) {
        *slot = unit;
    }
    out
}

/// Returns whether daylight time is in effect now: TIME_ZONE_ID_UNKNOWN
/// for a zone without it, else STANDARD or DAYLIGHT.
#[allow(non_snake_case)]
extern "stdcall" fn GetTimeZoneInformation(out: *mut u8) -> u32 {
    let tz = with_current(|p| p.params.time_zone.clone());
    let mut buf = [0u8; 172];
    let mut put = |off: usize, bytes: &[u8]| buf[off..off + bytes.len()].copy_from_slice(bytes);
    let wide = |units: &[u16]| {
        units
            .iter()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<u8>>()
    };
    put(0, &tz.bias.to_le_bytes());
    put(4, &wide(&name(&tz.standard_name)));
    put(68, &wide(&systemtime(tz.standard_date)));
    put(84, &tz.standard_bias.to_le_bytes());
    put(88, &wide(&name(&tz.daylight_name)));
    put(152, &wide(&systemtime(tz.daylight_date)));
    put(168, &tz.daylight_bias.to_le_bytes());
    // SAFETY: out holds a TIME_ZONE_INFORMATION (the API's contract).
    unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, buf.len()) };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    if !tz.has_daylight_time() {
        TIME_ZONE_ID_UNKNOWN
    } else if tz.is_daylight(now) {
        TIME_ZONE_ID_DAYLIGHT
    } else {
        TIME_ZONE_ID_STANDARD
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use crate::timezone::TimeZone;

    #[test]
    fn fills_time_zone_information() {
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
        let mut buf = [0xaau8; 172];
        let id = GetTimeZoneInformation(buf.as_mut_ptr());
        assert!(id == TIME_ZONE_ID_STANDARD || id == TIME_ZONE_ID_DAYLIGHT);
        let i32_at = |o: usize| i32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
        let u16_at = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]);
        assert_eq!((i32_at(0), i32_at(84), i32_at(168)), (-60, 0, -60));
        let text = |o: usize| {
            let units: Vec<u16> = (0..32)
                .map(|i| u16_at(o + 2 * i))
                .take_while(|&u| u != 0)
                .collect();
            String::from_utf16(&units).unwrap()
        };
        assert_eq!(text(4), "W. Europe Standard Time");
        assert_eq!(text(88), "W. Europe Daylight Time");
        // StandardDate: wYear 0, wMonth 10, wDayOfWeek 0, wDay 5, wHour 3.
        assert_eq!(
            [u16_at(68), u16_at(70), u16_at(72), u16_at(74), u16_at(76)],
            [0, 10, 0, 5, 3]
        );
        assert_eq!([u16_at(154), u16_at(158), u16_at(160)], [3, 5, 2]);

        runtime.lock().params.time_zone = TimeZone::default();
        let mut utc = [0xaau8; 172];
        assert_eq!(
            GetTimeZoneInformation(utc.as_mut_ptr()),
            TIME_ZONE_ID_UNKNOWN
        );
        assert_eq!([utc[70], utc[71]], [0, 0], "no StandardDate");
    }
}
