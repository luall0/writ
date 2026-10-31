//! The daemon's `approvers` file, in git's `allowed_signers` format
//! (`ssh-keygen(1)`, ALLOWED SIGNERS): one key per line,
//! `principals [options] keytype base64 [comment]`.
//!
//! Options are honored or refused, never ignored: `namespaces="…"` keeps the key only if it
//! lists `writ-approval`; `cert-authority`, `valid-after` and `valid-before` are refused (the
//! whole file fails to load), since silently dropping a restriction would widen it.

use ssh_key::{HashAlg, PublicKey};

use crate::{Error, Result};

/// One approver key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedSigner {
    /// The principals field, kept as a label for logs and the CLI.
    pub principals: String,
    pub key: PublicKey,
}

impl AllowedSigner {
    pub fn fingerprint(&self) -> String {
        self.key.fingerprint(HashAlg::Sha256).to_string()
    }
}

const KEY_TYPES: [&str; 7] = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-rsa",
];

/// Parses an `allowed_signers` file, keeping the keys allowed for `namespace`. Any line it
/// can't read, or any option it can't honor, fails the whole file.
pub fn parse(text: &str, namespace: &str) -> Result<Vec<AllowedSigner>> {
    let mut signers = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fail = |why: &str| Error::AllowedSigners(format!("line {}: {why}", index + 1));
        let mut fields = line.split_whitespace();
        let principals = fields.next().ok_or_else(|| fail("empty line"))?;
        let mut next = fields.next().ok_or_else(|| fail("missing key"))?;
        let mut allowed = true;
        if !KEY_TYPES.contains(&next) {
            allowed = options_allow(next, namespace).map_err(|why| fail(&why))?;
            next = fields.next().ok_or_else(|| fail("missing key"))?;
        }
        if !KEY_TYPES.contains(&next) {
            return Err(fail(&format!("unknown key type {next:?}")));
        }
        let blob = fields.next().ok_or_else(|| fail("missing key data"))?;
        let key = PublicKey::from_openssh(&format!("{next} {blob}"))
            .map_err(|e| fail(&format!("invalid key: {e}")))?;
        if allowed {
            signers.push(AllowedSigner {
                principals: principals.to_owned(),
                key,
            });
        }
    }
    Ok(signers)
}

/// Whether the options keep the key for `namespace`; refuses options that can't be honored.
fn options_allow(options: &str, namespace: &str) -> std::result::Result<bool, String> {
    let mut allowed = true;
    for option in options.split(',').filter(|o| !o.is_empty()) {
        let (name, value) = match option.split_once('=') {
            Some((name, value)) => (name, Some(value.trim_matches('"'))),
            None => (option, None),
        };
        match (name.to_ascii_lowercase().as_str(), value) {
            ("namespaces", Some(list)) => {
                allowed = list.split(['|', ' ']).any(|n| n == namespace)
                    || list.split(',').any(|n| n == namespace);
            }
            ("cert-authority" | "valid-after" | "valid-before", _) => {
                return Err(format!("option {name} is not supported"));
            }
            _ => return Err(format!("unknown option {option:?}")),
        }
    }
    Ok(allowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyKind, generate};

    fn line(prefix: &str) -> (String, PublicKey) {
        let key = generate(KeyKind::Ed25519).unwrap().public_key().clone();
        (format!("{prefix} {}", key.to_openssh().unwrap()), key)
    }

    #[test]
    fn reads_keys_and_honors_namespaces() {
        let (a, key_a) = line("me@mac");
        let (b, key_b) = line("backup namespaces=\"writ-approval\"");
        let (c, _) = line("git-only namespaces=\"git\"");
        let text = format!("# approvers\n\n{a}\n{b} comment here\n{c}\n");
        let signers = parse(&text, "writ-approval").unwrap();
        let keys: Vec<_> = signers.iter().map(|s| s.key.clone()).collect();
        assert_eq!(keys, vec![key_a, key_b]);
        assert_eq!(signers[0].principals, "me@mac");
    }

    #[test]
    fn refuses_what_it_cannot_honor() {
        for prefix in [
            "ca cert-authority",
            "old valid-before=\"20300101\"",
            "x valid-after=\"20200101\"",
            "x restrict",
        ] {
            let (text, _) = line(prefix);
            assert!(parse(&text, "writ-approval").is_err(), "{prefix}");
        }
        assert!(parse("me ssh-ed25519 not-base64", "writ-approval").is_err());
        assert!(parse("me", "writ-approval").is_err());
        assert!(parse("me ssh-dss AAAA", "writ-approval").is_err());
        assert!(parse("", "writ-approval").unwrap().is_empty());
    }
}
