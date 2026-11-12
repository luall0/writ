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
//! A key held by a device (M7.5: the Secure Enclave) adds a `backend` line, in either format,
//! and its private half is what the device's backend gave the daemon to keep (its framed
//! blob), in lowercase hex on one line:
//!
//! ```text
//! writ-key/1
//! format: ssh
//! backend: se-cryptokit
//! <hex of the stored bytes, or the OpenSSH public key line>
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

/// The longest backend name.
const MAX_BACKEND: usize = 32;

/// The most bytes a device key's stored part may hold (its hex is twice that).
pub const MAX_STORED: usize = 64 * 1024;

/// The backend a key file names (`se-cryptokit`): `[a-z0-9-]`, a letter first, at most 32
/// bytes. Absent for a key held in the daemon's memory (software).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyBackend {
    bytes: [u8; MAX_BACKEND],
    len: usize,
}

impl KeyBackend {
    pub fn new(name: &str) -> Result<Self> {
        let valid = !name.is_empty()
            && name.len() <= MAX_BACKEND
            && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !valid {
            return Err(malformed("a malformed backend"));
        }
        let mut bytes = [0u8; MAX_BACKEND];
        bytes
            .get_mut(..name.len())
            .ok_or_else(|| malformed("a malformed backend"))?
            .copy_from_slice(name.as_bytes());
        Ok(Self {
            bytes,
            len: name.len(),
        })
    }

    pub fn as_str(&self) -> &str {
        self.bytes
            .get(..self.len)
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or_default()
    }
}

impl std::fmt::Debug for KeyBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyBackend({:?})", self.as_str())
    }
}

impl std::fmt::Display for KeyBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a key is besides its key material: the format it signs in, for OpenPGP the time it
/// was made (seconds since the epoch), and the device backend holding it (none: software).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMeta {
    pub format: SignatureFormat,
    /// Set for an OpenPGP key, none for an SSH key.
    pub created: Option<u32>,
    /// Set for a key a device holds (its file keeps what the device gave the daemon).
    pub backend: Option<KeyBackend>,
}

impl KeyMeta {
    /// An SSH key.
    pub const SSH: KeyMeta = KeyMeta {
        format: SignatureFormat::Ssh,
        created: None,
        backend: None,
    };

    /// The same key's metadata, held by the device backend `backend`.
    pub fn on(self, backend: KeyBackend) -> Self {
        Self {
            backend: Some(backend),
            ..self
        }
    }

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
                    backend: None,
                })
            }
        }
    }

    /// The header written before the key, none for an SSH key held in software.
    fn header(&self) -> Option<String> {
        let mut header = match (self.format, self.created, self.backend) {
            (SignatureFormat::Ssh, _, None) => return None,
            (SignatureFormat::Ssh, _, Some(_)) => format!("{MAGIC}format: ssh\n"),
            (format, Some(created), _) => format!("{MAGIC}format: {format}\ncreated: {created}\n"),
            (format, None, _) => format!("{MAGIC}format: {format}\n"),
        };
        if let Some(backend) = self.backend {
            header.push_str(&format!("backend: {backend}\n"));
        }
        Some(header)
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
    let (meta, rest) = match format {
        SignatureFormat::Ssh => (KeyMeta::SSH, rest),
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
            (
                KeyMeta {
                    format,
                    created: Some(created),
                    backend: None,
                },
                rest,
            )
        }
    };
    if !rest.starts_with(b"backend: ") {
        // An SSH key in software is never written with a header: one that has it isn't Writ's.
        if format == SignatureFormat::Ssh {
            return Err(malformed("a header for an SSH key"));
        }
        return Ok((meta, rest));
    }
    let (backend, rest) = field(rest, "backend")?;
    Ok((meta.on(KeyBackend::new(backend)?), rest))
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

/// A key's private half as stored: wiped on drop. A key in software only.
pub fn encode_secret(key: &KeyPair, meta: KeyMeta) -> Result<Zeroizing<String>> {
    if meta.backend.is_some() {
        return Err(malformed("a backend for a key held in software"));
    }
    let pem = key.to_pem()?;
    let mut text = Zeroizing::new(String::with_capacity(pem.len().saturating_add(64)));
    if let Some(header) = meta.header() {
        text.push_str(&header);
    }
    text.push_str(&pem);
    Ok(text)
}

/// A key's private half, from what [`encode_secret`] wrote. A device key's file is refused.
pub fn decode_secret(text: &[u8]) -> Result<(KeyPair, KeyMeta)> {
    match decode_held(text)? {
        (Held::Software(key), meta) => Ok((key, meta)),
        (Held::Device(_), _) => Err(malformed("a device's key where a software key belongs")),
    }
}

/// A key's private half as read: a key in software, or what a device's backend gave the
/// daemon to keep (wiped on drop).
pub enum Held {
    Software(KeyPair),
    Device(Zeroizing<Vec<u8>>),
}

/// A device key's private half as stored: the header (its backend named in `meta`), then
/// `stored` in lowercase hex on one line. Wiped on drop.
pub fn encode_device(stored: &[u8], meta: KeyMeta) -> Result<Zeroizing<String>> {
    let Some(header) = meta.header().filter(|_| meta.backend.is_some()) else {
        return Err(malformed("a device's key with no backend"));
    };
    if stored.is_empty() || stored.len() > MAX_STORED {
        return Err(malformed("a device's stored bytes out of bounds"));
    }
    let mut text = Zeroizing::new(String::with_capacity(
        header
            .len()
            .saturating_add(stored.len().saturating_mul(2))
            .saturating_add(1),
    ));
    text.push_str(&header);
    for b in stored {
        text.push_str(&format!("{b:02x}"));
    }
    text.push('\n');
    Ok(text)
}

/// A key's private half, from what [`encode_secret`] or [`encode_device`] wrote.
pub fn decode_held(text: &[u8]) -> Result<(Held, KeyMeta)> {
    let (meta, body) = split(text)?;
    if meta.backend.is_none() {
        return Ok((Held::Software(KeyPair::from_pem(body)?), meta));
    }
    let hex = body
        .strip_suffix(b"\n")
        .ok_or_else(|| malformed("a device's stored bytes not ended by a newline"))?;
    if hex.is_empty() || hex.len() > MAX_STORED.saturating_mul(2) || hex.len() % 2 != 0 {
        return Err(malformed("a device's stored bytes out of bounds"));
    }
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    let mut stored = Zeroizing::new(Vec::with_capacity(hex.len() / 2));
    for &[hi, lo] in hex.as_chunks::<2>().0 {
        let (Some(hi), Some(lo)) = (digit(hi), digit(lo)) else {
            return Err(malformed(
                "a device's stored bytes that aren't lowercase hex",
            ));
        };
        stored.push(hi.wrapping_shl(4) | lo);
    }
    Ok((Held::Device(stored), meta))
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
    fn a_device_key_reads_back_with_its_backend_in_either_format() {
        let backend = KeyBackend::new("se-cryptokit").unwrap();
        let public = KeyPair::generate(KeyAlgorithm::P256).unwrap().public_key();
        let stored = [0u8, 1, 0xfe, 0xff, 0x5a];
        for meta in [
            KeyMeta::SSH.on(backend),
            KeyMeta::new(SignatureFormat::Openpgp, 7)
                .unwrap()
                .on(backend),
        ] {
            let secret = encode_device(&stored, meta).unwrap();
            assert!(
                secret.ends_with("backend: se-cryptokit\n0001feff5a\n"),
                "{:?}",
                *secret
            );
            let (held, read) = decode_held(secret.as_bytes()).unwrap();
            assert_eq!(read, meta);
            assert!(matches!(held, Held::Device(bytes) if bytes.as_slice() == stored));
            // Never read as a software key, nor written as one.
            assert_eq!(
                decode_secret(secret.as_bytes())
                    .err()
                    .map(|e| e.to_string()),
                Some(
                    "not supported: a key file with a device's key where a software key belongs"
                        .to_owned()
                )
            );
            let line = encode_public(&public, meta).unwrap();
            assert_eq!(
                decode_public(line.as_bytes()).unwrap(),
                (public.clone(), meta)
            );
        }
        let key = KeyPair::generate(KeyAlgorithm::P256).unwrap();
        assert!(
            encode_secret(&key, KeyMeta::SSH.on(backend)).is_err_and(|e| e.to_string()
                == "not supported: a key file with a backend for a key held in software")
        );
        assert!(
            encode_device(&stored, KeyMeta::SSH).is_err_and(|e| e.to_string()
                == "not supported: a key file with a device's key with no backend")
        );
        // The stored bytes on both sides of their bound.
        encode_device(&vec![7; MAX_STORED], KeyMeta::SSH.on(backend)).unwrap();
        for bytes in [Vec::new(), vec![7; MAX_STORED + 1]] {
            assert!(
                encode_device(&bytes, KeyMeta::SSH.on(backend)).is_err_and(|e| e.to_string()
                    == "not supported: a key file with a device's stored bytes out of bounds")
            );
        }
    }

    #[test]
    fn a_device_key_file_is_read_exactly() {
        let head = "writ-key/1\nformat: ssh\nbackend: se-cryptokit\n";
        let refused = |text: String, why: &str| {
            let error = decode_held(text.as_bytes()).err().map(|e| e.to_string());
            assert_eq!(
                error.as_deref(),
                Some(format!("not supported: a key file with {why}").as_str()),
                "{text:?}"
            );
        };
        refused(
            format!("{head}00ff"),
            "a device's stored bytes not ended by a newline",
        );
        refused(format!("{head}\n"), "a device's stored bytes out of bounds");
        refused(
            format!("{head}0ff\n"),
            "a device's stored bytes out of bounds",
        );
        refused(
            format!("{head}00FF\n"),
            "a device's stored bytes that aren't lowercase hex",
        );
        refused(
            format!("{head}00 f\n"),
            "a device's stored bytes that aren't lowercase hex",
        );
        refused(
            format!("{head}{}\n", "ab".repeat(MAX_STORED + 1)),
            "a device's stored bytes out of bounds",
        );
        for name in [
            "",
            "SE",
            "-se",
            "se_cryptokit",
            &"a".repeat(33),
            "se cryptokit",
        ] {
            refused(
                format!("writ-key/1\nformat: ssh\nbackend: {name}\n00\n"),
                "a malformed backend",
            );
        }
        KeyBackend::new(&"a".repeat(32)).unwrap();
        // The backend line goes after format (and created): anywhere else isn't Writ's.
        refused(
            "writ-key/1\nbackend: se-cryptokit\nformat: ssh\n00\n".to_owned(),
            "no `format` line where it belongs",
        );
        refused(
            "writ-key/1\nformat: openpgp\nbackend: se-cryptokit\ncreated: 1\n00\n".to_owned(),
            "no `created` line where it belongs",
        );
    }

    #[test]
    fn a_creation_time_past_32_bits_is_capped_never_wrapped() {
        let meta = KeyMeta::new(SignatureFormat::Openpgp, u64::MAX).unwrap();
        assert_eq!(meta.created, Some(u32::MAX));
    }
}
