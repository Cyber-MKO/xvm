//! Local time from Windows time-zone rules.
//!
//! The rules are those `GetTimeZoneInformation` returns
//! (`TIME_ZONE_INFORMATION` on Microsoft Learn): UTC = local time + bias,
//! where the bias is `Bias + StandardBias` in standard time and
//! `Bias + DaylightBias` in daylight time. Each switch is "the Nth
//! weekday of a month at a time of day" (N = 5 means the last one).
//! Daylight time starts at `DaylightDate`, given in standard time, and
//! ends at `StandardDate`, given in daylight time.

use serde::Deserialize;

/// One yearly switch: `SYSTEMTIME` in its day-in-month form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub month: u16,
    /// 0 is Sunday.
    pub day_of_week: u16,
    /// Which occurrence of that weekday, 1 to 5; 5 is the last.
    pub week: u16,
    pub hour: u16,
    #[serde(default)]
    pub minute: u16,
    #[serde(default)]
    pub second: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeZone {
    /// The zone's registry key name, such as "W. Europe Standard Time".
    pub key_name: String,
    pub standard_name: String,
    pub daylight_name: String,
    /// Minutes: UTC = local time + bias.
    pub bias: i32,
    #[serde(default)]
    pub standard_bias: i32,
    #[serde(default)]
    pub daylight_bias: i32,
    /// Both absent for a zone without daylight time.
    pub standard_date: Option<Transition>,
    pub daylight_date: Option<Transition>,
}

/// UTC, for processes built without a host profile (tests). The runner
/// always takes the zone from the profile.
impl Default for TimeZone {
    fn default() -> Self {
        TimeZone {
            key_name: "UTC".into(),
            standard_name: "Coordinated Universal Time".into(),
            daylight_name: "Coordinated Universal Time".into(),
            bias: 0,
            standard_bias: 0,
            daylight_bias: 0,
            standard_date: None,
            daylight_date: None,
        }
    }
}

impl Transition {
    fn validate(&self) -> Result<(), String> {
        let ok = (1..=12).contains(&self.month)
            && self.day_of_week <= 6
            && (1..=5).contains(&self.week)
            && self.hour <= 23
            && self.minute <= 59
            && self.second <= 59;
        ok.then_some(())
            .ok_or_else(|| format!("bad transition {self:?}"))
    }

    /// The switch in `year`, as seconds since 1970 counted in the local
    /// clock the transition is given in.
    fn local_seconds(&self, year: i64) -> i64 {
        let month = self.month as i64;
        let first = days_from_civil(year, month, 1);
        // 1970-01-01 was a Thursday (4).
        let first_weekday = (first + 4).rem_euclid(7);
        let offset = (self.day_of_week as i64 - first_weekday).rem_euclid(7);
        let mut day = 1 + offset + 7 * (self.week as i64 - 1);
        while day > days_in_month(year, month) {
            day -= 7;
        }
        (first + day - 1) * 86_400
            + self.hour as i64 * 3600
            + self.minute as i64 * 60
            + self.second as i64
    }
}

impl TimeZone {
    pub fn validate(&self) -> Result<(), String> {
        for name in [&self.key_name, &self.standard_name, &self.daylight_name] {
            // WCHAR[32] in TIME_ZONE_INFORMATION, with its NUL.
            if name.encode_utf16().count() > 31 {
                return Err(format!(
                    "time zone name {name:?} is longer than 31 characters"
                ));
            }
        }
        match (&self.standard_date, &self.daylight_date) {
            (Some(s), Some(d)) => {
                s.validate()?;
                d.validate()
            }
            (None, None) => Ok(()),
            _ => Err("give both standard_date and daylight_date, or neither".into()),
        }
    }

    pub fn has_daylight_time(&self) -> bool {
        self.daylight_date.is_some()
    }

    /// Whether daylight time is in effect at `utc` (seconds since 1970).
    pub fn is_daylight(&self, utc: i64) -> bool {
        let (Some(standard), Some(daylight)) = (self.standard_date, self.daylight_date) else {
            return false;
        };
        let year = civil_from_days((utc - self.bias as i64 * 60).div_euclid(86_400)).0;
        let start = daylight.local_seconds(year) + (self.bias + self.standard_bias) as i64 * 60;
        let end = standard.local_seconds(year) + (self.bias + self.daylight_bias) as i64 * 60;
        if start < end {
            start <= utc && utc < end
        } else {
            // Southern hemisphere: daylight time spans the new year.
            !(end <= utc && utc < start)
        }
    }

    /// Minutes to subtract from UTC to get local time at `utc`.
    pub fn bias_at(&self, utc: i64) -> i32 {
        if self.is_daylight(utc) {
            self.bias + self.daylight_bias
        } else {
            self.bias + self.standard_bias
        }
    }

    /// Local time at `utc`, as seconds since 1970 on the local clock.
    pub fn to_local(&self, utc: i64) -> i64 {
        utc - self.bias_at(utc) as i64 * 60
    }
}

/// Broken-down time, the fields of C's `struct tm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tm {
    pub sec: i32,
    pub min: i32,
    pub hour: i32,
    pub mday: i32,
    /// 0 to 11.
    pub mon: i32,
    /// Years since 1900.
    pub year: i32,
    /// 0 is Sunday.
    pub wday: i32,
    /// 0 to 365.
    pub yday: i32,
    pub isdst: i32,
}

impl Tm {
    /// Break down `seconds` since 1970 (on whatever clock they count).
    pub fn from_seconds(seconds: i64, isdst: bool) -> Tm {
        let days = seconds.div_euclid(86_400);
        let rest = seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        Tm {
            sec: (rest % 60) as i32,
            min: (rest / 60 % 60) as i32,
            hour: (rest / 3600) as i32,
            mday: day as i32,
            mon: month as i32 - 1,
            year: year as i32 - 1900,
            wday: (days + 4).rem_euclid(7) as i32,
            yday: (days - days_from_civil(year, 1, 1)) as i32,
            isdst: isdst as i32,
        }
    }
}

/// Days from 1970-01-01 to a date in the proleptic Gregorian calendar.
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date `days` after 1970-01-01, as (year, month, day).
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + (month <= 2) as i64;
    (year, month, day)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    days_from_civil(year + (month == 12) as i64, month % 12 + 1, 1)
        - days_from_civil(year, month, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(y: i64, mo: i64, d: i64, h: i64, mi: i64) -> i64 {
        days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60
    }

    /// Central Europe: UTC+1, daylight time from the last Sunday of March
    /// at 02:00 to the last Sunday of October at 03:00.
    fn europe() -> TimeZone {
        TimeZone {
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
        }
    }

    #[test]
    fn calendar_round_trips() {
        for days in [-1, 0, 59, 365, 11_016, 19_000, 25_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_in_month(2024, 2), 29);
        assert_eq!(days_in_month(2026, 12), 31);
    }

    #[test]
    fn european_switches_happen_at_the_documented_instants() {
        let z = europe();
        z.validate().unwrap();
        // 2026: daylight time from 29 March 01:00 UTC to 25 October 01:00 UTC.
        assert!(!z.is_daylight(utc(2026, 3, 29, 0, 59)));
        assert!(z.is_daylight(utc(2026, 3, 29, 1, 0)));
        assert!(z.is_daylight(utc(2026, 10, 25, 0, 59)));
        assert!(!z.is_daylight(utc(2026, 10, 25, 1, 0)));
        assert_eq!(z.to_local(utc(2026, 1, 15, 12, 0)), utc(2026, 1, 15, 13, 0));
        assert_eq!(z.to_local(utc(2026, 7, 15, 12, 0)), utc(2026, 7, 15, 14, 0));
    }

    #[test]
    fn southern_hemisphere_daylight_time_spans_the_new_year() {
        // AUS Eastern: UTC+10, daylight time from the first Sunday of
        // October at 02:00 to the first Sunday of April at 03:00.
        let z = TimeZone {
            key_name: "AUS Eastern Standard Time".into(),
            standard_name: "AUS Eastern Standard Time".into(),
            daylight_name: "AUS Eastern Daylight Time".into(),
            bias: -600,
            standard_bias: 0,
            daylight_bias: -60,
            standard_date: Some(Transition {
                month: 4,
                day_of_week: 0,
                week: 1,
                hour: 3,
                minute: 0,
                second: 0,
            }),
            daylight_date: Some(Transition {
                month: 10,
                day_of_week: 0,
                week: 1,
                hour: 2,
                minute: 0,
                second: 0,
            }),
        };
        assert!(z.is_daylight(utc(2026, 1, 10, 0, 0)));
        assert!(!z.is_daylight(utc(2026, 6, 10, 0, 0)));
        // 2026-10-04 02:00 local standard = 2026-10-03 16:00 UTC.
        assert!(!z.is_daylight(utc(2026, 10, 3, 15, 59)));
        assert!(z.is_daylight(utc(2026, 10, 3, 16, 0)));
    }

    #[test]
    fn zones_without_daylight_time_and_bad_rules() {
        let mut z = europe();
        z.standard_date = None;
        assert!(z.validate().is_err(), "one date without the other");
        z.daylight_date = None;
        z.validate().unwrap();
        assert!(!z.is_daylight(utc(2026, 7, 1, 0, 0)));
        let mut bad = europe();
        bad.daylight_date.as_mut().unwrap().week = 6;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn tm_fields() {
        // 2026-10-17 was a Saturday, day 289 of the year.
        let tm = Tm::from_seconds(utc(2026, 10, 17, 21, 5) + 9, true);
        assert_eq!(
            tm,
            Tm {
                sec: 9,
                min: 5,
                hour: 21,
                mday: 17,
                mon: 9,
                year: 126,
                wday: 6,
                yday: 289,
                isdst: 1
            }
        );
    }
}
