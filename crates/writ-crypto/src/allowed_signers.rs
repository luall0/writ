//! The daemon's `approvers` file, in git's `allowed_signers` format
//! (`ssh-keygen(1)`, ALLOWED SIGNERS): one key per line,
//! `principals [options] keytype base64 [comment]`.
//!
//! Options are honored or refused, never ignored: `namespaces="…"` keeps the key only if it
//! lists `writ-approval`; `cert-authority`, `valid-after` and `valid-before` are refused (the
//! whole file fails to load), since silently dropping a restriction would widen it. An option
//! given twice is refused (OpenSSH refuses a second `namespaces`).
//!
//! Key types are decided here, not by which algorithms happen to be compiled in: an approver
//! key is Ed25519 or ECDSA P-256, or their security-key forms ([`APPROVER_KEY_TYPES`]).

use ssh_key::{HashAlg, PublicKey};

use crate::{CryptoError, Result};

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

/// The key types this parser recognizes (to tell an option from a key).
const KEY_TYPES: [&str; 7] = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-rsa",
];

/// The key types accepted for an approver: what the daemon verifies, by policy.
pub const APPROVER_KEY_TYPES: [&str; 4] = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
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
        let fail = |why: &str| CryptoError::AllowedSigners {
            line: index.saturating_add(1),
            why: why.to_owned(),
        };
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
        if !APPROVER_KEY_TYPES.contains(&next) {
            return Err(fail(&format!(
                "key type {next} is not accepted for approvers (ssh-ed25519, \
                 ecdsa-sha2-nistp256, or their sk- forms)"
            )));
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
    let mut seen = std::collections::BTreeSet::new();
    for (name, value) in split_options(options)? {
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(format!("option {name} is given twice"));
        }
        match (name.to_ascii_lowercase().as_str(), value) {
            ("namespaces", Some(list)) => allowed = namespaces_allow(list, namespace)?,
            ("cert-authority" | "valid-after" | "valid-before", _) => {
                return Err(format!("option {name} is not supported"));
            }
            _ => return Err(format!("unknown option {name:?}")),
        }
    }
    Ok(allowed)
}

/// Splits `name[="value"],…` on the commas outside quotes. A quote left open, an empty
/// option or a value that is only partly quoted is an error.
fn split_options(options: &str) -> std::result::Result<Vec<(&str, Option<&str>)>, String> {
    let mut parts = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (i, c) in options.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                // Boundaries come from char_indices; a miss would be an empty option, refused.
                parts.push(options.get(start..i).unwrap_or_default());
                start = i.saturating_add(1);
            }
            _ => {}
        }
    }
    if quoted {
        return Err("unterminated quote in the options".to_owned());
    }
    parts.push(options.get(start..).unwrap_or_default());
    parts
        .into_iter()
        .map(|option| {
            if option.is_empty() {
                return Err("empty option".to_owned());
            }
            match option.split_once('=') {
                None if !option.contains('"') => Ok((option, None)),
                Some((name, value)) if !name.contains('"') => {
                    let inner = value.strip_prefix('"').and_then(|v| v.strip_suffix('"'));
                    match inner {
                        Some(inner) if !inner.contains('"') => Ok((name, Some(inner))),
                        // A value always in quotes, as `ssh-keygen -Y verify` reads the file
                        // (`bad options: missing start quote`): an unquoted one is refused, not
                        // read where OpenSSH would refuse the line (the review after M7.6, K-8).
                        None if !value.contains('"') => {
                            Err(format!("option {name}'s value is not in quotes"))
                        }
                        _ => Err(format!("malformed option {option:?}")),
                    }
                }
                _ => Err(format!("malformed option {option:?}")),
            }
        })
        .collect()
}

/// Whether a `namespaces` list names `namespace`. OpenSSH reads it as a pattern list
/// (`*`, `?`, `!`); patterns aren't supported here, so a list using them is refused rather
/// than read as plain names.
fn namespaces_allow(list: &str, namespace: &str) -> std::result::Result<bool, String> {
    let names: Vec<&str> = list.split(',').collect();
    if names
        .iter()
        .any(|n| n.is_empty() || n.contains(['*', '?', '!']))
    {
        return Err(format!(
            "namespaces={list:?}: only plain names are supported, not patterns"
        ));
    }
    Ok(names.contains(&namespace))
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
        let (d, key_d) = line("both namespaces=\"git,writ-approval\"");
        let (e, _) = line("near namespaces=\"writ-approval2,git\"");
        let text = format!("# approvers\n\n{a}\n{b} comment here\n{c}\n{d}\n{e}\n");
        let signers = parse(&text, "writ-approval").unwrap();
        let keys: Vec<_> = signers.iter().map(|s| s.key.clone()).collect();
        assert_eq!(keys, vec![key_a, key_b, key_d]);
        assert_eq!(signers[0].principals, "me@mac");
    }

    /// The reason a file was refused; anything else fails the test.
    fn refused(text: &str) -> String {
        match parse(text, "writ-approval") {
            Err(CryptoError::AllowedSigners { why, .. }) => why,
            other => panic!("{text:?}: expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn refuses_what_it_cannot_honor() {
        for (prefix, why) in [
            (
                "ca cert-authority",
                "option cert-authority is not supported",
            ),
            (
                "old valid-before=\"20300101\"",
                "option valid-before is not supported",
            ),
            (
                "x valid-after=\"20200101\"",
                "option valid-after is not supported",
            ),
            ("x restrict", "unknown option \"restrict\""),
            ("x namespaces=\"writ-*\"", "only plain names are supported"),
            ("x namespaces=\"!git\"", "only plain names are supported"),
            ("x namespaces=\"git,\"", "only plain names are supported"),
            ("x namespaces=\"writ-approval", "unterminated quote"),
            ("x namespaces=writ\"-approval\"", "malformed option"),
            // Unquoted: OpenSSH refuses the line (`missing start quote`), so does this (the
            // review after M7.6, K-8); quoted, it is read (`reads_keys_and_honors_namespaces`).
            (
                "x namespaces=writ-approval",
                "option namespaces's value is not in quotes",
            ),
            ("x namespaces=\"writ-approval\",", "empty option"),
            (
                "x namespaces=\"writ-approval\",cert-authority",
                "cert-authority is not supported",
            ),
            (
                "x namespaces=\"writ-approval\",valid-before=\"20300101\"",
                "valid-before is not supported",
            ),
            // Repeated: the last one would win, in either order.
            (
                "x namespaces=\"git\",namespaces=\"writ-approval\"",
                "given twice",
            ),
            (
                "x namespaces=\"writ-approval\",namespaces=\"git\"",
                "given twice",
            ),
            (
                "x namespaces=\"git\",NAMESPACES=\"writ-approval\"",
                "given twice",
            ),
        ] {
            let (text, _) = line(prefix);
            let found = refused(&text);
            assert!(found.contains(why), "{prefix}: {found}");
        }
        assert!(refused("me ssh-ed25519 not-base64").starts_with("invalid key"));
        assert_eq!(refused("me"), "missing key");
        assert_eq!(refused("me ssh-dss AAAA"), "unknown option \"ssh-dss\"");
        // Recognized, but not accepted for approvers: decided here, not by build features.
        for kind in ["ssh-rsa", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"] {
            let found = refused(&format!("me {kind} AAAA"));
            assert!(
                found.contains("is not accepted for approvers"),
                "{kind}: {found}"
            );
        }
        assert!(parse("", "writ-approval").unwrap().is_empty());
    }

    #[test]
    fn accepts_p256_approvers() {
        let key = generate(KeyKind::P256).unwrap().public_key().clone();
        let text = format!("se {}", key.to_openssh().unwrap());
        assert_eq!(parse(&text, "writ-approval").unwrap()[0].key, key);
    }
}
