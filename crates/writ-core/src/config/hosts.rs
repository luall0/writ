//! `upstream_hosts`: the upstream host keys the daemon's ssh accepts, pinned by signed
//! changes. Each entry is a host as ssh looks it up (`host`, or `[host]:port` off port 22)
//! and the keys it may present, as OpenSSH writes them (`ssh-ed25519 AAAA…`). Nothing is
//! learned on first use, and nothing but a plain pin is taken: no wildcard, negation, hashed
//! name or marker. The policy checks the form; the daemon reads each key whole.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::names::NameError;

/// The most hosts the policy pins.
pub const MAX_HOSTS: usize = 256;

/// The most keys one host may have pinned.
pub const MAX_HOST_KEYS: usize = 16;

/// The longest key line taken (an RSA 16384-bit key's base64 is under 3 KiB).
pub const MAX_HOST_KEY: usize = 8 * 1024;

/// The key types a pin may hold: every OpenSSH host key type but DSA.
pub const HOST_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
];

/// A host name or address alone (no port, no brackets): what a scan reaches.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HostName(String);

impl HostName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for HostName {
    type Error = NameError;

    fn try_from(value: String) -> Result<Self, NameError> {
        let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_');
        if value.is_empty()
            || value.len() > 253
            || value.starts_with('-')
            || !value.chars().all(plain)
        {
            return Err(NameError {
                kind: "host",
                value: value.chars().take(64).collect(),
                why: "a plain host name or address (no port, brackets or wildcard)",
            });
        }
        Ok(Self(value))
    }
}

impl From<HostName> for String {
    fn from(value: HostName) -> String {
        value.0
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A pinned host, as ssh looks it up: a plain host name or address, or `[host]:port` for a
/// port other than 22.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct UpstreamHost(String);

impl UpstreamHost {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The host and port it names (22 when it has none).
    pub fn host_port(&self) -> (&str, u16) {
        match self
            .0
            .strip_prefix('[')
            .and_then(|rest| rest.split_once("]:"))
        {
            Some((host, port)) => (host, port.parse().unwrap_or(22)),
            None => (&self.0, 22),
        }
    }

    /// The entry for `host` and `port`, as ssh looks it up.
    pub fn of(host: &str, port: u16) -> Result<Self, NameError> {
        match port {
            22 => Self::try_from(host.to_owned()),
            _ => Self::try_from(format!("[{host}]:{port}")),
        }
    }
}

fn check_host(value: &str) -> Result<(), &'static str> {
    let host = match value.strip_prefix('[') {
        Some(rest) => {
            let (host, port) = rest
                .split_once("]:")
                .ok_or("a bracketed host needs its port: [host]:port")?;
            let port = port
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or("invalid port")?;
            if port == 22 {
                return Err("port 22 is written without brackets: host");
            }
            host
        }
        None => value,
    };
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_');
    if host.is_empty() || host.len() > 253 || host.starts_with('-') || !host.chars().all(plain) {
        return Err(
            "only a plain host name or address, or [host]:port (no wildcard, negation \
                    or hashed name)",
        );
    }
    Ok(())
}

impl TryFrom<String> for UpstreamHost {
    type Error = NameError;

    fn try_from(value: String) -> Result<Self, NameError> {
        match check_host(&value) {
            Ok(()) => Ok(Self(value)),
            Err(why) => Err(NameError {
                kind: "upstream host",
                value: value.chars().take(64).collect(),
                why,
            }),
        }
    }
}

impl fmt::Display for UpstreamHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A pinned host key: `<type> <base64>`, as OpenSSH writes it, without a comment. Its type is
/// one of [`HOST_KEY_TYPES`]; the daemon decodes it whole before the policy is in force.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct HostKey(String);

impl HostKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Its type (`ssh-ed25519`).
    pub fn key_type(&self) -> &str {
        self.0.split(' ').next().unwrap_or_default()
    }
}

fn check_host_key(value: &str) -> Result<(), &'static str> {
    if value.len() > MAX_HOST_KEY {
        return Err("too long");
    }
    let (kind, data) = value
        .split_once(' ')
        .ok_or("must be `<type> <base64>`, as OpenSSH writes it")?;
    if !HOST_KEY_TYPES.contains(&kind) {
        return Err(
            "not a host key type Writ takes (ssh-ed25519, ecdsa-sha2-nistp256, \
                    ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, ssh-rsa; never DSA)",
        );
    }
    let base64 = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=');
    if data.is_empty() || !data.bytes().all(base64) {
        return Err("the key must be base64, with no comment after it");
    }
    Ok(())
}

impl TryFrom<String> for HostKey {
    type Error = NameError;

    fn try_from(value: String) -> Result<Self, NameError> {
        match check_host_key(&value) {
            Ok(()) => Ok(Self(value)),
            Err(why) => Err(NameError {
                kind: "host key",
                value: value.chars().take(64).collect(),
                why,
            }),
        }
    }
}

impl fmt::Display for HostKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    #[test]
    fn hosts_are_plain_pins_as_ssh_looks_them_up() {
        for good in [
            "github.com",
            "[forgejo.home]:2222",
            "10.0.0.5",
            "[2001:db8::1]:2222",
        ] {
            let host: UpstreamHost = good.to_owned().try_into().unwrap();
            assert_eq!(host.as_str(), good);
        }
        assert_eq!(
            UpstreamHost::of("forgejo.home", 2222).unwrap().host_port(),
            ("forgejo.home", 2222)
        );
        assert_eq!(
            UpstreamHost::of("github.com", 22).unwrap().as_str(),
            "github.com"
        );
        for (bad, why) in [
            ("*.github.com", "plain host"),
            ("!github.com", "plain host"),
            ("|1|abc=|def=", "plain host"),
            ("@cert-authority", "plain host"),
            ("github.com,gitlab.com", "plain host"),
            ("-oProxyCommand", "plain host"),
            ("[github.com]", "needs its port"),
            ("[github.com]:22", "without brackets"),
            ("[github.com]:0", "invalid port"),
            ("[github.com]:x", "invalid port"),
            ("", "plain host"),
        ] {
            let error = UpstreamHost::try_from(bad.to_owned()).unwrap_err();
            assert!(error.why.contains(why), "{bad:?}: {error}");
        }
    }

    #[test]
    fn keys_are_a_type_and_base64_with_no_comment() {
        assert_eq!(
            HostKey::try_from(KEY.to_owned()).unwrap().key_type(),
            "ssh-ed25519"
        );
        for (bad, why) in [
            ("ssh-dss AAAAB3NzaC1kc3M=", "never DSA"),
            ("ssh-ed25519", "<type> <base64>"),
            (&format!("{KEY} a comment") as &str, "no comment"),
            ("ssh-ed25519 AAAA\u{1b}[2J", "base64"),
            ("ssh-ed25519 ", "base64"),
            (&format!("ssh-rsa {}", "A".repeat(MAX_HOST_KEY)), "too long"),
        ] {
            let error = HostKey::try_from(bad.to_owned()).unwrap_err();
            assert!(error.why.contains(why), "{bad:?}: {error}");
        }
    }
}
