//! Calendar dates: birthdates and ages.

use crate::epoch::Timestamp;
use time::{Date, Month};

/// The calendar date in `zone` at `at`. Ages turn over at local
/// midnight, not at midnight UTC, which in Australia is 8 to 11 hours later.
pub(crate) fn local_date(at: Timestamp, zone: &jiff::tz::TimeZone) -> Option<Date> {
    let date = jiff::Timestamp::from_second(at.unix())
        .ok()?
        .to_zoned(zone.clone())
        .date();
    let month = Month::try_from(u8::try_from(date.month()).ok()?).ok()?;
    let day = u8::try_from(date.day()).ok()?;
    Date::from_calendar_date(i32::from(date.year()), month, day).ok()
}

/// Parse an OpenID Connect `birthdate` (`YYYY-MM-DD`).
pub(crate) fn parse_date(text: &str) -> Option<Date> {
    let mut parts = text.splitn(3, '-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u8 = parts.next()?.parse().ok()?;
    let day: u8 = parts.next()?.parse().ok()?;
    Date::from_calendar_date(year, Month::try_from(month).ok()?, day).ok()
}

/// Whole years between `born` and `today`; `None` if born in the future.
pub(crate) fn age_on(born: Date, today: Date) -> Option<i32> {
    let had_birthday = (today.month() as u8, today.day()) >= (born.month() as u8, born.day());
    let age = today.year() - born.year() - i32::from(!had_birthday);
    (age >= 0).then_some(age)
}
