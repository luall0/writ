//! Network addresses in the configuration: the sources a listener accepts connections from.
//! Parsed at the edge (`writd.yaml`), never re-checked.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Deserializer};

/// An address range in CIDR notation (`10.0.0.0/24`, `192.0.2.7`, `fd00::/8`). A bare address
/// is that one address. `0.0.0.0/0` (or `::/0`) means anyone, and must be written out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpRange {
    network: IpAddr,
    prefix: u8,
}

impl IpRange {
    /// Whether `addr` is in the range. An IPv4 address seen as IPv6 (`::ffff:10.0.0.1`, as a
    /// dual-stack socket reports it) is compared as IPv4.
    pub fn contains(&self, addr: IpAddr) -> bool {
        let addr = match addr {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
            v4 => v4,
        };
        match (self.network, addr) {
            (IpAddr::V4(net), IpAddr::V4(a)) => {
                masked(u128::from(u32::from(net)), self.prefix, 32)
                    == masked(u128::from(u32::from(a)), self.prefix, 32)
            }
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                masked(u128::from(net), self.prefix, 128) == masked(u128::from(a), self.prefix, 128)
            }
            _ => false,
        }
    }
}

/// The top `prefix` bits of a `width`-bit address.
fn masked(value: u128, prefix: u8, width: u32) -> u128 {
    let host_bits = width.saturating_sub(u32::from(prefix));
    if host_bits >= 128 {
        0
    } else {
        (value >> host_bits) << host_bits
    }
}

impl FromStr for IpRange {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let invalid = |why: &str| format!("invalid address range {text:?}: {why}");
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let network: IpAddr = addr.parse().map_err(|_| invalid("not an IP address"))?;
        let width: u8 = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => width,
            Some(p) if !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()) => {
                p.parse::<u8>().map_err(|_| invalid("bad prefix length"))?
            }
            Some(_) => return Err(invalid("bad prefix length")),
        };
        if prefix > width {
            return Err(invalid("prefix length longer than the address"));
        }
        let range = Self { network, prefix };
        // `10.0.0.1/24` is almost always a typo for one address or for `10.0.0.0/24`.
        if !range.contains(network) || range.to_string() != canonical(network, prefix, width) {
            return Err(invalid("host bits set after the prefix"));
        }
        Ok(range)
    }
}

/// The range as written with its host bits cleared.
fn canonical(network: IpAddr, prefix: u8, width: u8) -> String {
    let cleared = match network {
        IpAddr::V4(v4) => IpAddr::V4(std::net::Ipv4Addr::from(
            u32::try_from(masked(u128::from(u32::from(v4)), prefix, 32)).unwrap_or(0),
        )),
        IpAddr::V6(v6) => IpAddr::V6(std::net::Ipv6Addr::from(masked(
            u128::from(v6),
            prefix,
            128,
        ))),
    };
    if prefix == width {
        cleared.to_string()
    } else {
        format!("{cleared}/{prefix}")
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let width = if self.network.is_ipv4() { 32 } else { 128 };
        if self.prefix == width {
            write!(f, "{}", self.network)
        } else {
            write!(f, "{}/{}", self.network, self.prefix)
        }
    }
}

impl<'de> Deserialize<'de> for IpRange {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// The group an address counts in for per-source limits: an IPv4 address on its own (an
/// IPv4-mapped IPv6 address as that IPv4 address), an IPv6 address by its /64, since one host
/// holds a whole /64 and could otherwise rotate through 2^64 "sources".
pub fn source_group(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => addr,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(std::net::Ipv6Addr::from(masked(u128::from(v6), 64, 128))),
        },
    }
}

/// Who may connect to a listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sources {
    /// Any caller the transport lets in (a Unix socket, guarded by its file mode and the
    /// caller attestor; an approval listener, guarded by the readers key).
    Any,
    /// Only callers whose source address is in one of these ranges. A caller without a
    /// source address is refused.
    Only(Vec<IpRange>),
}

impl Sources {
    /// Whether a caller with this source address may connect.
    pub fn allows(&self, source: Option<IpAddr>) -> bool {
        match self {
            Self::Any => true,
            Self::Only(ranges) => {
                source.is_some_and(|addr| ranges.iter().any(|r| r.contains(addr)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(text: &str) -> IpRange {
        text.parse().unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_range_holds_exactly_its_addresses() {
        let lan = range("10.0.0.0/24");
        assert!(lan.contains(ip("10.0.0.0")));
        assert!(lan.contains(ip("10.0.0.255")));
        assert!(!lan.contains(ip("10.0.1.0")));
        assert!(!lan.contains(ip("9.255.255.255")));
        assert!(lan.contains(ip("::ffff:10.0.0.7")), "IPv4 seen as IPv6");
        assert!(!lan.contains(ip("::a00:7")), "not an IPv4-mapped address");
        let one = range("192.0.2.7");
        assert!(one.contains(ip("192.0.2.7")));
        assert!(!one.contains(ip("192.0.2.8")));
        let v6 = range("fd00::/8");
        assert!(v6.contains(ip("fd12::1")));
        assert!(!v6.contains(ip("fe80::1")));
        assert!(!v6.contains(ip("10.0.0.1")));
        assert!(range("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(!range("0.0.0.0/0").contains(ip("2001:db8::1")));
        assert!(range("::/0").contains(ip("2001:db8::1")));
        assert!(range("10.0.0.0/31").contains(ip("10.0.0.1")));
        assert!(!range("10.0.0.0/31").contains(ip("10.0.0.2")));
    }

    #[test]
    fn only_exact_ranges_parse() {
        for good in [
            "10.0.0.0/24",
            "192.0.2.7",
            "192.0.2.7/32",
            "fd00::/8",
            "::1",
            "0.0.0.0/0",
        ] {
            assert!(good.parse::<IpRange>().is_ok(), "{good}");
        }
        for (bad, why) in [
            ("10.0.0.1/24", "host bits"),
            ("10.0.0.0/33", "longer than the address"),
            ("::/129", "longer than the address"),
            ("10.0.0.0/", "bad prefix"),
            ("10.0.0.0/+8", "bad prefix"),
            ("10.0.0.0/0008", "bad prefix"),
            ("10.0.0.0/ 8", "bad prefix"),
            ("10.0.0", "not an IP address"),
            ("example.org", "not an IP address"),
            ("", "not an IP address"),
            ("10.0.0.0/8/8", "bad prefix"),
        ] {
            let error = bad.parse::<IpRange>().unwrap_err();
            assert!(error.contains(why), "{bad}: {error}");
        }
    }

    #[test]
    fn an_ipv6_host_counts_as_its_slash_64() {
        assert_eq!(
            source_group(ip("2001:db8::1")),
            source_group(ip("2001:db8::ffff:1"))
        );
        assert_eq!(source_group(ip("2001:db8::1")), ip("2001:db8::"));
        assert_ne!(
            source_group(ip("2001:db8::1")),
            source_group(ip("2001:db8:0:1::1"))
        );
        assert_eq!(source_group(ip("192.0.2.7")), ip("192.0.2.7"));
        assert_ne!(source_group(ip("192.0.2.7")), source_group(ip("192.0.2.8")));
        assert_eq!(source_group(ip("::ffff:192.0.2.7")), ip("192.0.2.7"));
    }

    #[test]
    fn only_listed_sources_get_in() {
        let only = Sources::Only(vec![range("10.0.0.0/24")]);
        assert!(only.allows(Some(ip("10.0.0.9"))));
        assert!(!only.allows(Some(ip("10.0.1.9"))));
        assert!(!only.allows(None), "no source address: refused");
        assert!(!Sources::Only(Vec::new()).allows(Some(ip("10.0.0.9"))));
        assert!(Sources::Any.allows(None));
    }
}
