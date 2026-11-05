//! The upstream host keys an approver pinned (the policy's `upstream_hosts`): the only host
//! keys the daemon's ssh accepts. Nothing is learned on first use.
//!
//! The policy checked each entry's form (`writ_core::config::hosts`); here each key is decoded
//! whole, and the file ssh reads is written in a normal form the daemon made, so ssh never
//! reads a line the daemon didn't understand: plain host names or `[host]:port` only (no
//! wildcard, no negation, no hashed name, no `@cert-authority` or `@revoked` marker), and no
//! DSA key.

use std::collections::{BTreeMap, BTreeSet};

#[cfg(any(test, feature = "testing"))]
use ssh_key::known_hosts::{HostPatterns, KnownHosts};
use ssh_key::{Algorithm, PublicKey};
use writ_core::config::{HostKey, UpstreamHost};

use crate::{MirrorError, Result};

/// The most entries the file may hold (each remote has a few keys).
pub const MAX_ENTRIES: usize = 1_000;

/// The pinned host keys, as the daemon writes them for ssh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedHosts {
    entries: Vec<(Vec<String>, PublicKey)>,
}

impl PinnedHosts {
    /// The pins of a policy in force: each key decoded (one that doesn't decode, or a DSA key,
    /// refuses them all, naming its host). None at all is valid: a registry with no `ssh://`
    /// repo reaches no host.
    pub fn from_policy(pins: &BTreeMap<UpstreamHost, Vec<HostKey>>) -> Result<Self> {
        let mut entries = Vec::new();
        for (host, keys) in pins {
            for (index, key) in keys.iter().enumerate() {
                let refuse = |why: &str| {
                    MirrorError::Config(format!("upstream_hosts.{host}[{index}]: {why}"))
                };
                let key = PublicKey::from_openssh(key.as_str())
                    .map_err(|_| refuse("not an OpenSSH public key"))?;
                if matches!(key.algorithm(), Algorithm::Dsa) {
                    return Err(refuse("DSA keys are not taken"));
                }
                entries.push((vec![host.as_str().to_owned()], key));
            }
        }
        Ok(Self { entries })
    }

    /// Parses a file in OpenSSH's `known_hosts` format, for tests (the daemon's pins come from
    /// the policy). Any line the daemon doesn't take as a plain pin refuses the whole file.
    #[cfg(any(test, feature = "testing"))]
    pub fn parse(text: &str) -> Result<Self> {
        let invalid = |line: usize, why: &str| {
            MirrorError::Config(format!("upstream known_hosts, entry {line}: {why}"))
        };
        let mut entries = Vec::new();
        for (index, entry) in KnownHosts::new(text).enumerate() {
            let line = index.saturating_add(1);
            if entries.len() >= MAX_ENTRIES {
                return Err(invalid(line, "too many entries"));
            }
            let entry = entry.map_err(|_| invalid(line, "not a known_hosts line"))?;
            if let Some(marker) = entry.marker() {
                return Err(invalid(
                    line,
                    &format!("marker @{} not taken: pin each host's key", marker.as_str()),
                ));
            }
            let patterns = match entry.host_patterns() {
                HostPatterns::HashedName { .. } => {
                    return Err(invalid(line, "hashed host names are not taken"));
                }
                HostPatterns::Patterns(patterns) => patterns.clone(),
            };
            for pattern in &patterns {
                check_pattern(pattern).map_err(|why| invalid(line, why))?;
            }
            let key = entry.public_key().clone();
            if matches!(key.algorithm(), Algorithm::Dsa) {
                return Err(invalid(line, "DSA keys are not taken"));
            }
            entries.push((patterns, key));
        }
        if entries.is_empty() {
            return Err(MirrorError::Config(
                "upstream known_hosts pins no host: no upstream could be reached".to_owned(),
            ));
        }
        Ok(Self { entries })
    }

    /// Whether `host` (as ssh looks it up: `name`, or `[name]:port` off port 22) has a pin.
    pub fn covers(&self, host: &str) -> bool {
        self.entries
            .iter()
            .any(|(patterns, _)| patterns.iter().any(|p| p == host))
    }

    /// The file ssh reads: one `<hosts> <key>` line per entry, no comment.
    pub fn to_file(&self) -> Result<String> {
        let mut text = String::new();
        for (patterns, key) in &self.entries {
            let key = key
                .to_openssh()
                .map_err(|_| MirrorError::Config("unencodable host key".to_owned()))?;
            // The comment is the operator's: left out.
            let key = key.split(' ').take(2).collect::<Vec<_>>().join(" ");
            text.push_str(&format!("{} {key}\n", patterns.join(",")));
        }
        Ok(text)
    }

    /// The host names pinned (for the daemon's log).
    pub fn hosts(&self) -> BTreeSet<&str> {
        self.entries
            .iter()
            .flat_map(|(patterns, _)| patterns.iter().map(String::as_str))
            .collect()
    }
}

/// A plain host name or address, or `[host]:port`: no wildcard, negation or anything ssh
/// would read as more than one host.
#[cfg(any(test, feature = "testing"))]
fn check_pattern(pattern: &str) -> std::result::Result<(), &'static str> {
    let host = match pattern.strip_prefix('[') {
        Some(rest) => {
            let (host, port) = rest
                .split_once("]:")
                .ok_or("a bracketed host needs its port: [host]:port")?;
            port.parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or("invalid port")?;
            host
        }
        None => pattern,
    };
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_');
    if host.is_empty() || host.starts_with('-') || !host.chars().all(plain) {
        return Err("only plain host names and addresses are taken (no wildcard or negation)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    #[test]
    fn a_policy_s_pins_are_decoded_whole_and_written_for_ssh() {
        let host = |name: &str| UpstreamHost::try_from(name.to_owned()).unwrap();
        let key = |line: &str| HostKey::try_from(line.to_owned()).unwrap();
        let pins = BTreeMap::from([
            (host("github.com"), vec![key(KEY)]),
            (host("[forgejo.home]:2222"), vec![key(KEY)]),
        ]);
        let pinned = PinnedHosts::from_policy(&pins).unwrap();
        assert!(pinned.covers("github.com") && pinned.covers("[forgejo.home]:2222"));
        assert!(
            !pinned.covers("forgejo.home"),
            "another port is another host"
        );
        assert_eq!(
            pinned.to_file().unwrap(),
            format!("[forgejo.home]:2222 {KEY}\ngithub.com {KEY}\n")
        );
        // None: valid, and ssh reads an empty file (no host is reached).
        let none = PinnedHosts::from_policy(&BTreeMap::new()).unwrap();
        assert_eq!(none.to_file().unwrap(), "");
        // A key of the right form that doesn't decode refuses them all, naming its place.
        let broken =
            BTreeMap::from([(host("github.com"), vec![key(KEY), key("ssh-ed25519 AAAA")])]);
        assert!(matches!(
            PinnedHosts::from_policy(&broken),
            Err(MirrorError::Config(m)) if m == "upstream_hosts.github.com[1]: not an OpenSSH public key"
        ));
    }

    #[test]
    fn plain_pins_are_taken_and_written_back_without_comments() {
        let text =
            format!("# GitHub\ngithub.com {KEY} a comment\n[forgejo.home]:2222,10.0.0.5 {KEY}\n\n");
        let pins = PinnedHosts::parse(&text).unwrap();
        assert!(pins.covers("github.com"));
        assert!(pins.covers("[forgejo.home]:2222"));
        assert!(pins.covers("10.0.0.5"));
        assert!(!pins.covers("forgejo.home"), "another port is another host");
        assert!(!pins.covers("GitHub.com"), "compared exactly");
        assert_eq!(
            pins.to_file().unwrap(),
            format!("github.com {KEY}\n[forgejo.home]:2222,10.0.0.5 {KEY}\n")
        );
    }

    #[test]
    fn anything_but_a_plain_pin_refuses_the_file() {
        for (line, why) in [
            (format!("*.github.com {KEY}"), "wildcard"),
            (format!("gith?b.com {KEY}"), "wildcard"),
            (format!("!evil.com,github.com {KEY}"), "negation"),
            (format!("@cert-authority *.home {KEY}"), "marker"),
            (format!("@revoked github.com {KEY}"), "marker"),
            (format!("[github.com] {KEY}"), "bracket without port"),
            (format!("[github.com]:0 {KEY}"), "port 0"),
            (format!("[github.com]:x {KEY}"), "bad port"),
            (format!("-oProxyCommand=x {KEY}"), "option-like"),
            (
                format!("|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg= {KEY}"),
                "hashed",
            ),
            ("github.com ssh-ed25519 notbase64".to_owned(), "bad key"),
            ("github.com".to_owned(), "no key"),
        ] {
            let result = PinnedHosts::parse(&format!("good.com {KEY}\n{line}\n"));
            assert!(
                matches!(&result, Err(MirrorError::Config(m)) if m.contains("entry 2")),
                "{why}: {result:?}"
            );
        }
        // The same file without the bad line is taken: the refusal is the line's doing.
        assert!(PinnedHosts::parse(&format!("good.com {KEY}\n")).is_ok());
    }

    #[test]
    fn an_empty_file_pins_nothing_and_is_refused() {
        for text in ["", "# nothing\n\n"] {
            assert!(matches!(
                PinnedHosts::parse(text),
                Err(MirrorError::Config(m)) if m.contains("pins no host")
            ));
        }
    }

    #[test]
    fn the_entry_count_is_bounded_on_both_sides() {
        let line = format!("h.com {KEY}\n");
        assert!(PinnedHosts::parse(&line.repeat(MAX_ENTRIES)).is_ok());
        let result = PinnedHosts::parse(&line.repeat(MAX_ENTRIES + 1));
        assert!(
            matches!(&result, Err(MirrorError::Config(m)) if m.contains("too many entries")),
            "{result:?}"
        );
    }
}
