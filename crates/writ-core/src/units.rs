//! Time and size values: timestamps (UTC, whole seconds), durations and byte sizes.
//!
//! The policy never reads a clock: the daemon passes `now` in.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Errors from parsing a time or size value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnitError {
    #[error("invalid timestamp {0:?}: expected YYYY-MM-DDTHH:MM:SSZ (UTC, whole seconds)")]
    Timestamp(String),
    #[error("timestamp out of range: {0}")]
    TimestampRange(i64),
    #[error("invalid duration {0:?}: expected a number and a unit (s, m, h or d), e.g. 4h")]
    Duration(String),
    #[error(
        "invalid size {0:?}: expected bytes, or a number and a unit (KB, MB, GB, KiB, MiB, GiB)"
    )]
    Size(String),
}

/// The latest timestamp accepted: 9999-12-31T23:59:59Z.
const MAX_UNIX: i64 = 253_402_300_799;

/// A point in time, UTC, whole seconds since the Unix epoch, between 1970 and 9999.
///
/// Its text form is the only one accepted: `YYYY-MM-DDTHH:MM:SSZ`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// From seconds since the Unix epoch.
    pub fn from_unix(seconds: i64) -> Result<Self, UnitError> {
        if (0..=MAX_UNIX).contains(&seconds) {
            Ok(Self(seconds))
        } else {
            Err(UnitError::TimestampRange(seconds))
        }
    }

    /// Seconds since the Unix epoch.
    pub fn unix(self) -> i64 {
        self.0
    }

    /// `self + duration`, or `None` past the representable range.
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let seconds = i64::try_from(duration.seconds()).ok()?;
        Self::from_unix(self.0.checked_add(seconds)?).ok()
    }

    /// `self - seconds`, clamped to the epoch.
    pub fn saturating_sub_seconds(self, seconds: i64) -> Self {
        Self(self.0.saturating_sub(seconds).clamp(0, MAX_UNIX))
    }

    /// Seconds from `self` to `later` (negative if `later` is before `self`).
    pub fn seconds_until(self, later: Timestamp) -> i64 {
        later.0 - self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match jiff::Timestamp::from_second(self.0) {
            Ok(ts) => write!(f, "{}", ts.strftime("%Y-%m-%dT%H:%M:%SZ")),
            // Unreachable: the range is checked on construction.
            Err(_) => write!(f, "@{}", self.0),
        }
    }
}

impl FromStr for Timestamp {
    type Err = UnitError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || UnitError::Timestamp(text.to_owned());
        // Cheap shape check first: jiff accepts more forms than the one we allow.
        let bytes = text.as_bytes();
        let shape_ok = bytes.len() == 20
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':'
            && bytes[19] == b'Z';
        if !shape_ok {
            return Err(invalid());
        }
        let parsed: jiff::Timestamp = text.parse().map_err(|_| invalid())?;
        let ts = Self::from_unix(parsed.as_second()).map_err(|_| invalid())?;
        // Only the canonical form round-trips (rejects e.g. a leap second or fractions).
        if ts.to_string() != text || parsed.subsec_nanosecond() != 0 {
            return Err(invalid());
        }
        Ok(ts)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(de::Error::custom)
    }
}

/// A length of time in whole seconds. Text form: a number and one unit, `90s`, `30m`, `4h`, `1d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(u64);

impl Duration {
    pub const fn from_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    pub const fn seconds(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        if s != 0 && s.is_multiple_of(86_400) {
            write!(f, "{}d", s / 86_400)
        } else if s != 0 && s.is_multiple_of(3_600) {
            write!(f, "{}h", s / 3_600)
        } else if s != 0 && s.is_multiple_of(60) {
            write!(f, "{}m", s / 60)
        } else {
            write!(f, "{s}s")
        }
    }
}

impl FromStr for Duration {
    type Err = UnitError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || UnitError::Duration(text.to_owned());
        let (number, unit) = split_number(text).ok_or_else(invalid)?;
        let factor = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3_600,
            "d" => 86_400,
            _ => return Err(invalid()),
        };
        number.checked_mul(factor).map(Self).ok_or_else(invalid)
    }
}

impl Serialize for Duration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(de::Error::custom)
    }
}

/// A size in bytes. Read from an integer (bytes) or a string with a unit (`50MB`, `1GiB`);
/// written as an integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSize(u64);

impl ByteSize {
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    pub const fn bytes(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes", self.0)
    }
}

impl FromStr for ByteSize {
    type Err = UnitError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || UnitError::Size(text.to_owned());
        let (number, unit) = split_number(text).ok_or_else(invalid)?;
        let factor: u64 = match unit {
            "" | "B" => 1,
            "KB" => 1_000,
            "MB" => 1_000_000,
            "GB" => 1_000_000_000,
            "KiB" => 1 << 10,
            "MiB" => 1 << 20,
            "GiB" => 1 << 30,
            _ => return Err(invalid()),
        };
        number.checked_mul(factor).map(Self).ok_or_else(invalid)
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SizeVisitor;

        impl Visitor<'_> for SizeVisitor {
            type Value = ByteSize;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a size: bytes, or a string such as 50MB")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<ByteSize, E> {
                Ok(ByteSize(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<ByteSize, E> {
                u64::try_from(v)
                    .map(ByteSize)
                    .map_err(|_| E::custom("a size can't be negative"))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<ByteSize, E> {
                v.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_any(SizeVisitor)
    }
}

/// Splits `"50MB"` into `(50, "MB")`. The number is plain ASCII digits, no sign, no spaces.
fn split_number(text: &str) -> Option<(u64, &str)> {
    let end = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    if end == 0 || end > 19 {
        return None;
    }
    let number = text[..end].parse().ok()?;
    Some((number, &text[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_have_one_text_form() {
        let ts: Timestamp = "2026-10-31T14:02:11Z".parse().unwrap();
        assert_eq!(ts.unix(), 1_793_455_331);
        assert_eq!(ts.to_string(), "2026-10-31T14:02:11Z");
        assert_eq!(
            Timestamp::from_unix(0).unwrap().to_string(),
            "1970-01-01T00:00:00Z"
        );
        for bad in [
            "2026-10-31T14:02:11+00:00",
            "2026-10-31T14:02:11.5Z",
            "2026-10-31 14:02:11Z",
            "2026-10-31T14:02:60Z",
            "2026-13-01T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "1969-12-31T23:59:59Z",
            "",
        ] {
            assert!(bad.parse::<Timestamp>().is_err(), "{bad} should be refused");
        }
        assert!(Timestamp::from_unix(-1).is_err());
        assert!(Timestamp::from_unix(MAX_UNIX + 1).is_err());
    }

    #[test]
    fn durations_parse_and_print() {
        assert_eq!("4h".parse::<Duration>().unwrap().seconds(), 14_400);
        assert_eq!("90s".parse::<Duration>().unwrap().to_string(), "90s");
        assert_eq!("120m".parse::<Duration>().unwrap().to_string(), "2h");
        assert_eq!("1d".parse::<Duration>().unwrap().seconds(), 86_400);
        for bad in [
            "",
            "4",
            "h",
            "-1h",
            "4 h",
            "4H",
            "1.5h",
            "99999999999999999999s",
        ] {
            assert!(bad.parse::<Duration>().is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn sizes_parse() {
        assert_eq!("50MB".parse::<ByteSize>().unwrap().bytes(), 50_000_000);
        assert_eq!("1GiB".parse::<ByteSize>().unwrap().bytes(), 1 << 30);
        assert_eq!("512".parse::<ByteSize>().unwrap().bytes(), 512);
        for bad in ["", "MB", "50mb", "50 MB", "-1"] {
            assert!(bad.parse::<ByteSize>().is_err(), "{bad} should be refused");
        }
        let json: ByteSize = serde_json::from_str("1024").unwrap();
        assert_eq!(json.bytes(), 1024);
        assert_eq!(serde_json::to_string(&json).unwrap(), "1024");
    }

    #[test]
    fn timestamp_arithmetic_stays_in_range() {
        let ts = Timestamp::from_unix(100).unwrap();
        assert_eq!(
            ts.checked_add(Duration::from_seconds(5)).unwrap().unix(),
            105
        );
        assert!(ts.checked_add(Duration::from_seconds(u64::MAX)).is_none());
        assert_eq!(ts.saturating_sub_seconds(1_000).unix(), 0);
        assert_eq!(ts.seconds_until(Timestamp::from_unix(40).unwrap()), -60);
    }
}
