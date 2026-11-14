//! Points in time and lengths of time, as distinct types.
//!
//! Protocol time is whole seconds (JWT `NumericDate`, RFC 7519 §2). A
//! [`Timestamp`] is a point, seconds since the Unix epoch; [`Seconds`] is a
//! length. They cannot be swapped by accident, and their arithmetic
//! saturates instead of overflowing: an absurd configured lifetime gives a
//! time far in the future, not a panic in debug or a wrap in release.
//!
//! Both serialise as a bare integer, so stored records, configuration and
//! JSON claims look exactly as they did when they were `i64`.

use std::fmt;
use std::ops::{Add, Sub};

use serde::{Deserialize, Serialize};

/// A point in time: whole seconds since the Unix epoch.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl Timestamp {
    pub const fn from_unix(seconds: i64) -> Self {
        Self(seconds)
    }

    /// Seconds since the Unix epoch.
    pub const fn unix(self) -> i64 {
        self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A length of time in whole seconds. Usually positive; a difference
/// between two [`Timestamp`]s may be negative.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Seconds(i64);

impl Seconds {
    pub const ZERO: Self = Self(0);

    pub const fn new(seconds: i64) -> Self {
        Self(seconds)
    }

    pub const fn minutes(minutes: i64) -> Self {
        Self(minutes.saturating_mul(60))
    }

    pub const fn hours(hours: i64) -> Self {
        Self(hours.saturating_mul(60 * 60))
    }

    pub const fn days(days: i64) -> Self {
        Self(days.saturating_mul(24 * 60 * 60))
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    /// In milliseconds, saturating.
    pub const fn millis(self) -> i64 {
        self.0.saturating_mul(1000)
    }

    /// As a [`std::time::Duration`]; zero when negative.
    pub const fn to_std(self) -> std::time::Duration {
        if self.0 > 0 {
            std::time::Duration::from_secs(self.0.unsigned_abs())
        } else {
            std::time::Duration::ZERO
        }
    }
}

impl fmt::Display for Seconds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Add<Seconds> for Timestamp {
    type Output = Self;

    fn add(self, rhs: Seconds) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl Sub<Seconds> for Timestamp {
    type Output = Self;

    fn sub(self, rhs: Seconds) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl Sub for Timestamp {
    type Output = Seconds;

    fn sub(self, rhs: Self) -> Seconds {
        Seconds(self.0.saturating_sub(rhs.0))
    }
}

impl Add for Seconds {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl Sub for Seconds {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_saturates_instead_of_overflowing() {
        let far = Timestamp::from_unix(i64::MAX - 1);
        assert_eq!(far + Seconds::days(1), Timestamp::from_unix(i64::MAX));
        assert_eq!(
            Timestamp::from_unix(i64::MIN + 1) - Seconds::days(1),
            Timestamp::from_unix(i64::MIN)
        );
        assert_eq!(Seconds::new(i64::MAX) + Seconds::new(1), Seconds::new(i64::MAX));
        assert_eq!(Seconds::days(i64::MAX), Seconds::new(i64::MAX));
    }

    #[test]
    fn differences_and_conversions() {
        let t = Timestamp::from_unix(1_000);
        assert_eq!(t + Seconds::minutes(1) - t, Seconds::new(60));
        assert_eq!(t - (t + Seconds::new(5)), Seconds::new(-5));
        assert_eq!(Seconds::new(3).millis(), 3_000);
        assert_eq!(Seconds::new(3).to_std(), std::time::Duration::from_secs(3));
        assert_eq!(Seconds::new(-3).to_std(), std::time::Duration::ZERO);
    }

    #[test]
    fn they_serialise_as_bare_integers() {
        assert_eq!(serde_json::to_string(&Timestamp::from_unix(5)).unwrap(), "5");
        assert_eq!(serde_json::from_str::<Seconds>("60").unwrap(), Seconds::minutes(1));
    }
}
