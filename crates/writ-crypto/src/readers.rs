//! The `readers` file: the keys that may use the approval API (list and show tickets, and
//! send approvals, refusals and revocations, which are signed on top). One key per line:
//!
//! ```text
//! # name   key
//! mac      ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI… optional comment
//! ```
//!
//! A reader key is a client key `writ` generates on the approver's machine (`writ reader`),
//! never the approver's Secretive key (hard rule 8). It authenticates the SSH connection to
//! the approval listener, and, over HTTPS, the client certificate `writ` makes from it
//! (mutual TLS). Ed25519 only: the daemon compares the certificate's public key with these.
//! A line that can't be read refuses the whole file, like `allowed_signers`.

use std::collections::BTreeSet;

use ssh_key::{Algorithm, PublicKey};

use crate::{CryptoError, Result};

/// A key allowed on the approval API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reader {
    /// The name in the file, for logs.
    pub name: String,
    pub key: PublicKey,
}

/// The DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410), before the 32 key bytes.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

impl Reader {
    /// The key as a SubjectPublicKeyInfo, as it appears in the reader's client certificate.
    pub fn spki(&self) -> Option<Vec<u8>> {
        let key = self.key.key_data().ed25519()?;
        let mut spki = ED25519_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(key.as_ref());
        Some(spki)
    }
}

/// Parses a `readers` file. Blank lines and `#` comments are skipped; any other line must be
/// a name and an Ed25519 key. Names and keys are unique.
pub fn parse(text: &str) -> Result<Vec<Reader>> {
    let mut readers = Vec::new();
    let (mut names, mut keys) = (BTreeSet::new(), BTreeSet::new());
    for (number, line) in text.lines().enumerate() {
        let error = |why: &str| CryptoError::Readers {
            line: number + 1,
            why: why.to_owned(),
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, key) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| error("expected a name and a key"))?;
        let valid_name = name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'));
        if !valid_name {
            return Err(error(
                "a name is up to 64 letters, digits, '-', '_', '.' or '@'",
            ));
        }
        let key = PublicKey::from_openssh(key.trim_start()).map_err(|_| error("unreadable key"))?;
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(error("a reader key must be ssh-ed25519"));
        }
        if !names.insert(name.to_owned()) {
            return Err(error("this name is already listed"));
        }
        if !keys.insert(key.key_data().clone()) {
            return Err(error("this key is already listed"));
        }
        readers.push(Reader {
            name: name.to_owned(),
            key,
        });
    }
    Ok(readers)
}

/// The reader holding `key`, if it is listed (compared on the whole key, never a fingerprint).
pub fn find<'a>(readers: &'a [Reader], key: &PublicKey) -> Option<&'a Reader> {
    readers.iter().find(|r| r.key.key_data() == key.key_data())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyKind, generate};

    fn line(name: &str, kind: KeyKind) -> (String, PublicKey) {
        let key = generate(kind).unwrap().public_key().clone();
        (
            format!("{name} {} a comment", key.to_openssh().unwrap()),
            key,
        )
    }

    #[test]
    fn reads_names_and_ed25519_keys() {
        let (mac, mac_key) = line("mac", KeyKind::Ed25519);
        let (phone, _) = line("phone.app", KeyKind::Ed25519);
        let readers = parse(&format!("# who may read\n\n{mac}\n  {phone}\n")).unwrap();
        assert_eq!(readers.len(), 2);
        assert_eq!(readers[0].name, "mac");
        assert_eq!(
            find(&readers, &mac_key).map(|r| r.name.as_str()),
            Some("mac")
        );
        let stranger = generate(KeyKind::Ed25519).unwrap().public_key().clone();
        assert_eq!(find(&readers, &stranger), None);
        let spki = readers[0].spki().unwrap();
        assert_eq!(spki.len(), 44);
        assert_eq!(&spki[..12], &ED25519_SPKI_PREFIX);
        assert!(parse("").unwrap().is_empty());
    }

    #[test]
    fn a_bad_line_refuses_the_whole_file() {
        let (mac, _) = line("mac", KeyKind::Ed25519);
        let (p256, _) = line("p256", KeyKind::P256);
        let mac_key = mac.split_once(' ').unwrap().1;
        for (text, why) in [
            (p256.clone(), "must be ssh-ed25519"),
            ("mac".to_owned(), "a name and a key"),
            ("mac ssh-ed25519 AAAA".to_owned(), "unreadable key"),
            (format!("bad\u{202e}name {mac_key}"), "a name is up to 64"),
            (
                format!("{} {mac_key}", "n".repeat(65)),
                "a name is up to 64",
            ),
            (format!("{mac}\n{mac}"), "name is already listed"),
            (format!("{mac}\nother {mac_key}"), "key is already listed"),
        ] {
            match parse(&text) {
                Err(CryptoError::Readers { why: found, .. }) => {
                    assert!(found.contains(why), "{text:?}: {found}")
                }
                other => panic!("{text:?}: {other:?}"),
            }
        }
        // At the limit, the name is fine.
        assert!(parse(&format!("{} {mac_key}", "n".repeat(64))).is_ok());
    }
}
