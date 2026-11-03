//! How an agent signing key is written in the daemon's keystore: its private half (the
//! plaintext of its age file, or a development keystore's file) and its public half (in clear
//! beside it, read by the commands that print a key without an unseal).
//!
//! An SSH key is written as it always was: an OpenSSH private key (or, for RSA, PKCS#8), and
//! an OpenSSH public key line. A key made for another format starts with a `writ-key/1`
//! header saying so, and, for OpenPGP, the key's creation time (it is part of the key's
//! fingerprint, so it is kept for good):
//!
//! ```text
//! writ-key/1
//! format: openpgp
//! created: 1762128000
//! <the private key, or the OpenSSH public key line>
//! ```
//!
//! A file without the header is an SSH key: every key made before M5.5 reads as one. The
//! daemon reads only the files it wrote, from its own keystore; anything but this exact layout
//! is refused.

use ssh_key::PublicKey;
use zeroize::Zeroizing;

use crate::algorithm::SignatureFormat;
use crate::keypair::KeyPair;
use crate::{CryptoError, Result};

/// The first line of a key file that isn't a plain SSH key.
const MAGIC: &str = "writ-key/1\n";

/// The latest creation time accepted: 2^32 - 1, OpenPGP's 32-bit time field.
const MAX_CREATED: u64 = u32::MAX as u64;

/// What a key is besides its key material: the format it signs in, and for OpenPGP, the time
/// it was made (seconds since the epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMeta {
    pub format: SignatureFormat,
    /// Set for an OpenPGP key, none for an SSH key.
    pub created: Option<u32>,
}

impl KeyMeta {
    /// An SSH key.
    pub const SSH: KeyMeta = KeyMeta {
        format: SignatureFormat::Ssh,
        created: None,
    };

    /// A new key's metadata for `format`, made at `now` (seconds since the epoch).
    pub fn new(format: SignatureFormat, now: u64) -> Result<Self> {
        match format {
            SignatureFormat::Ssh => Ok(Self::SSH),
            SignatureFormat::Openpgp => {
                let created = u32::try_from(now.min(MAX_CREATED))
                    .map_err(|_| malformed("a creation time past 2106"))?;
                Ok(Self {
                    format,
                    created: Some(created),
                })
            }
        }
    }

    /// The header written before the key, none for an SSH key.
    fn header(&self) -> Option<String> {
        match (self.format, self.created) {
            (SignatureFormat::Ssh, _) => None,
            (format, Some(created)) => {
                Some(format!("{MAGIC}format: {format}\ncreated: {created}\n"))
            }
            (format, None) => Some(format!("{MAGIC}format: {format}\n")),
        }
    }
}

fn malformed(why: &str) -> CryptoError {
    CryptoError::Unsupported(format!("a key file with {why}"))
}

/// Splits a key file into its metadata and the key's own text.
fn split(text: &[u8]) -> Result<(KeyMeta, &[u8])> {
    let Some(rest) = text.strip_prefix(MAGIC.as_bytes()) else {
        return Ok((KeyMeta::SSH, text));
    };
    let (format, rest) = field(rest, "format")?;
    let format: SignatureFormat = format.parse().map_err(|_| malformed("an unknown format"))?;
    match format {
        // An SSH key is never written with a header: one that has it isn't Writ's.
        SignatureFormat::Ssh => Err(malformed("a header for an SSH key")),
        SignatureFormat::Openpgp => {
            let (created, rest) = field(rest, "created")?;
            let canonical = !created.is_empty()
                && created.bytes().all(|b| b.is_ascii_digit())
                && (created == "0" || !created.starts_with('0'));
            let created: u32 = created
                .parse()
                .ok()
                .filter(|_| canonical)
                .ok_or_else(|| malformed("a malformed creation time"))?;
            Ok((
                KeyMeta {
                    format,
                    created: Some(created),
                },
                rest,
            ))
        }
    }
}

/// The value of the line `<name>: <value>` at the start of `text`, and what follows it.
fn field<'a>(text: &'a [u8], name: &str) -> Result<(&'a str, &'a [u8])> {
    let newline = text
        .iter()
        .take(64)
        .position(|&b| b == b'\n')
        .ok_or_else(|| malformed("a header line cut short"))?;
    let (line, rest) = text
        .split_at_checked(newline)
        .ok_or_else(|| malformed("a header line cut short"))?;
    let rest = rest.get(1..).unwrap_or_default();
    let line = std::str::from_utf8(line).map_err(|_| malformed("a header that isn't text"))?;
    let value = line
        .strip_prefix(name)
        .and_then(|v| v.strip_prefix(": "))
        .ok_or_else(|| malformed(&format!("no `{name}` line where it belongs")))?;
    Ok((value, rest))
}

/// A key's private half as stored: wiped on drop.
pub fn encode_secret(key: &KeyPair, meta: KeyMeta) -> Result<Zeroizing<String>> {
    let pem = key.to_pem()?;
    let mut text = Zeroizing::new(String::with_capacity(pem.len().saturating_add(64)));
    if let Some(header) = meta.header() {
        text.push_str(&header);
    }
    text.push_str(&pem);
    Ok(text)
}

/// A key's private half, from what [`encode_secret`] wrote.
pub fn decode_secret(text: &[u8]) -> Result<(KeyPair, KeyMeta)> {
    let (meta, key) = split(text)?;
    Ok((KeyPair::from_pem(key)?, meta))
}

/// A key's public half as stored: the OpenSSH public key line, after the header.
pub fn encode_public(public: &PublicKey, meta: KeyMeta) -> Result<String> {
    let mut text = meta.header().unwrap_or_default();
    text.push_str(&public.to_openssh()?);
    text.push('\n');
    Ok(text)
}

/// A key's public half, from what [`encode_public`] wrote (or a plain OpenSSH line).
pub fn decode_public(text: &[u8]) -> Result<(PublicKey, KeyMeta)> {
    let (meta, line) = split(text)?;
    let line = std::str::from_utf8(line).map_err(|_| malformed("a public key that isn't text"))?;
    Ok((PublicKey::from_openssh(line.trim())?, meta))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::KeyAlgorithm;

    #[test]
    fn a_key_reads_back_with_its_format_and_creation_time() {
        for algorithm in [
            KeyAlgorithm::Ed25519,
            KeyAlgorithm::P384,
            KeyAlgorithm::Rsa3072,
        ] {
            let key = KeyPair::generate(algorithm).unwrap();
            for meta in [
                KeyMeta::SSH,
                KeyMeta::new(SignatureFormat::Openpgp, 1_762_128_000).unwrap(),
            ] {
                let secret = encode_secret(&key, meta).unwrap();
                let (again, read) = decode_secret(secret.as_bytes()).unwrap();
                assert_eq!((again.public_key(), read), (key.public_key(), meta));
                let public = encode_public(&key.public_key(), meta).unwrap();
                assert_eq!(
                    decode_public(public.as_bytes()).unwrap(),
                    (key.public_key(), meta)
                );
                assert_eq!(
                    public.starts_with("writ-key/1\n"),
                    meta.format == SignatureFormat::Openpgp,
                    "an SSH key is written as it always was"
                );
            }
        }
    }

    #[test]
    fn a_key_made_before_m5_5_reads_as_an_ssh_key() {
        let key = crate::keys::generate(crate::keys::KeyKind::Ed25519).unwrap();
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let (read, meta) = decode_secret(pem.as_bytes()).unwrap();
        assert_eq!(
            (read.public_key(), meta),
            (key.public_key().clone(), KeyMeta::SSH)
        );
        let line = format!("{}\n", key.public_key().to_openssh().unwrap());
        assert_eq!(decode_public(line.as_bytes()).unwrap().1, KeyMeta::SSH);
    }

    #[test]
    fn anything_but_the_exact_layout_is_refused() {
        let key = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let pem = key.to_pem().unwrap();
        let refused = |text: String, why: &str| {
            let error = decode_secret(text.as_bytes()).unwrap_err().to_string();
            assert_eq!(
                error,
                format!("not supported: a key file with {why}"),
                "{text:?}"
            );
        };
        refused(
            format!("writ-key/1\nformat: ssh\n{}", pem.as_str()),
            "a header for an SSH key",
        );
        refused(
            format!("writ-key/1\nformat: x509\n{}", pem.as_str()),
            "an unknown format",
        );
        refused(
            format!("writ-key/1\nformat: openpgp\n{}", pem.as_str()),
            "no `created` line where it belongs",
        );
        for created in ["", "01", "-1", "4294967296", "1e9", " 1"] {
            refused(
                format!(
                    "writ-key/1\nformat: openpgp\ncreated: {created}\n{}",
                    pem.as_str()
                ),
                "a malformed creation time",
            );
        }
        refused(
            "writ-key/1\nformat: openpgp".to_owned(),
            "a header line cut short",
        );
        refused(
            format!("writ-key/1\ncreated: 1\nformat: openpgp\n{}", pem.as_str()),
            "no `format` line where it belongs",
        );
    }

    #[test]
    fn a_creation_time_past_32_bits_is_capped_never_wrapped() {
        let meta = KeyMeta::new(SignatureFormat::Openpgp, u64::MAX).unwrap();
        assert_eq!(meta.created, Some(u32::MAX));
    }
}
