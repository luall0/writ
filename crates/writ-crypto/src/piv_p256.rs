//! The `piv-p256` age stanza (M7.6): a file key wrapped to a P-256 key-agreement key held by
//! hardware, the format age-plugin-yubikey and age-plugin-se both write, implemented here so
//! no plugin binary is ever run.
//!
//! ```text
//! -> piv-p256 <base64(tag)> <base64(epk)>
//! <base64(body)>
//! ```
//!
//! - `tag`: the first 4 bytes of SHA-256 over the recipient's compressed SEC1 point;
//! - `epk`: the ephemeral public key, a compressed SEC1 point (33 bytes);
//! - `body`: the file key under ChaCha20-Poly1305 (age's `aead_encrypt`, a zero nonce), keyed
//!   by HKDF-SHA256 over the ECDH shared secret's x coordinate, salt `epk ‖ recipient` (both
//!   compressed), info `piv-p256` (32 bytes: 16 of file key, 16 of tag).
//!
//! Wrapping needs the recipient's public point alone ([`P256Recipient`], an `age::Recipient`).
//! Unwrapping needs the ECDH, which the hardware does: [`Line::parse`] reads and checks a
//! stanza before any device sees its point, [`Line::peer_point`] is what the device is given,
//! and [`Line::unwrap`] turns the shared secret it answers into the file key.

use std::collections::HashSet;

use age::secrecy::ExposeSecret;
use age_core::format::{FileKey, Stanza};
use base64ct::{Base64Unpadded, Encoding};
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The stanza's tag in an age header.
pub const STANZA_TAG: &str = "piv-p256";
/// HKDF's info, the same word.
const LABEL: &[u8] = b"piv-p256";
/// The recipient's tag: the first bytes of SHA-256 over its compressed point.
pub const TAG_BYTES: usize = 4;
/// A compressed SEC1 P-256 point.
pub const POINT_BYTES: usize = 33;
/// An uncompressed SEC1 P-256 point (what a device is handed).
pub const UNCOMPRESSED_BYTES: usize = 65;
/// The file key and ChaCha20-Poly1305's tag.
const BODY_BYTES: usize = 32;
/// An age file key.
const FILE_KEY_BYTES: usize = 16;
/// The ECDH shared secret: the shared point's x coordinate.
pub const SHARED_BYTES: usize = 32;

/// Why a `piv-p256` stanza, a recipient or an unwrap was refused. Never holds a secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PivError {
    #[error("a piv-p256 stanza takes 2 arguments, not {0}")]
    Arguments(usize),
    #[error("its tag is not 4 bytes of base64")]
    Tag,
    #[error("its ephemeral key is not a compressed P-256 point on the curve")]
    Point,
    #[error("its body is {0} bytes, not 32")]
    Body(usize),
    #[error("the shared secret is not 32 bytes")]
    Shared,
    /// The tag was this recipient's and the body didn't open: a damaged stanza, or a shared
    /// secret that isn't this key's.
    #[error("the file key does not open (a damaged stanza, or the wrong key)")]
    Open,
    #[error("not a P-256 recipient ({0})")]
    Recipient(&'static str),
    #[error("cannot draw an ephemeral key")]
    Random,
}

/// A P-256 key-agreement key's public half: what a file key is wrapped to.
#[derive(Clone, PartialEq, Eq)]
pub struct P256Recipient {
    point: p256::PublicKey,
    /// The bech32 prefix it prints with: `age1se` (the Secure Enclave), `age1yubikey`.
    hrp: &'static str,
}

impl std::fmt::Debug for P256Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "P256Recipient({self})")
    }
}

impl P256Recipient {
    /// The recipient whose point is `sec1` (compressed or uncompressed, on the curve, never
    /// the identity), printed with the prefix `hrp`.
    pub fn from_sec1(sec1: &[u8], hrp: &'static str) -> Result<Self, PivError> {
        let point = p256::PublicKey::from_sec1_bytes(sec1)
            .map_err(|_| PivError::Recipient("not a point on the curve"))?;
        Ok(Self { point, hrp })
    }

    /// The recipient a string `age1se1…` (or another `hrp`) names: bech32 over the compressed
    /// point.
    pub fn parse(text: &str, hrp: &'static str) -> Result<Self, PivError> {
        use bech32::FromBase32;
        let (found, data, variant) =
            bech32::decode(text).map_err(|_| PivError::Recipient("not bech32"))?;
        if found != hrp || variant != bech32::Variant::Bech32 {
            return Err(PivError::Recipient("another kind of recipient"));
        }
        let bytes = Vec::<u8>::from_base32(&data).map_err(|_| PivError::Recipient("not bech32"))?;
        if bytes.len() != POINT_BYTES {
            return Err(PivError::Recipient("not a compressed point"));
        }
        Self::from_sec1(&bytes, hrp)
    }

    /// The compressed SEC1 point.
    pub fn compressed(&self) -> [u8; POINT_BYTES] {
        compressed(&self.point)
    }

    /// The uncompressed SEC1 point (what a device answers for its key).
    pub fn uncompressed(&self) -> [u8; UNCOMPRESSED_BYTES] {
        let encoded = self.point.to_sec1_point(false);
        let mut out = [0u8; UNCOMPRESSED_BYTES];
        for (o, b) in out.iter_mut().zip(encoded.as_bytes()) {
            *o = *b;
        }
        out
    }

    /// The first 4 bytes of SHA-256 over the compressed point, as in the stanza.
    pub fn tag(&self) -> [u8; TAG_BYTES] {
        let digest = Sha256::digest(self.compressed());
        let mut tag = [0u8; TAG_BYTES];
        for (out, byte) in tag.iter_mut().zip(digest.iter()) {
            *out = *byte;
        }
        tag
    }

    /// [`Self::tag`] as the stanza writes it (unpadded base64).
    pub fn tag_text(&self) -> String {
        Base64Unpadded::encode_string(&self.tag())
    }

    /// Wraps `file_key` with a fresh ephemeral key: the stanza.
    pub fn wrap(&self, file_key: &FileKey) -> Result<Stanza, PivError> {
        let scalar = loop {
            let bytes =
                Zeroizing::new(crate::keys::random_array::<32>().map_err(|_| PivError::Random)?);
            // A random 32-byte string is a valid scalar but for a 2^-32 chance: drawn again.
            if let Ok(secret) = p256::SecretKey::from_slice(bytes.as_slice()) {
                break secret;
            }
        };
        let epk = compressed(&scalar.public_key());
        let shared = p256::elliptic_curve::ecdh::diffie_hellman(
            scalar.to_nonzero_scalar(),
            self.point.as_affine(),
        );
        let key = enc_key(
            &epk,
            &self.compressed(),
            shared.raw_secret_bytes().as_slice(),
        );
        let body = age_core::primitives::aead_encrypt(&key, file_key.expose_secret());
        Ok(Stanza {
            tag: STANZA_TAG.to_owned(),
            args: vec![
                Base64Unpadded::encode_string(&self.tag()),
                Base64Unpadded::encode_string(&epk),
            ],
            body,
        })
    }
}

impl std::fmt::Display for P256Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use bech32::ToBase32;
        match bech32::encode(
            self.hrp,
            self.compressed().to_base32(),
            bech32::Variant::Bech32,
        ) {
            Ok(text) => f.write_str(&text),
            Err(_) => f.write_str("<a recipient bech32 can't print>"),
        }
    }
}

impl age::Recipient for P256Recipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let stanza = self.wrap(file_key).map_err(|_| {
            age::EncryptError::Io(std::io::Error::other("cannot draw an ephemeral key"))
        })?;
        Ok((vec![stanza], HashSet::new()))
    }
}

/// A `piv-p256` stanza, read and checked: its tag, its ephemeral point (on the curve), its
/// body. Nothing here is secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    tag: [u8; TAG_BYTES],
    epk: p256::PublicKey,
    body: [u8; BODY_BYTES],
}

impl Line {
    /// `None` for another kind of stanza; a refusal for a `piv-p256` one that isn't well made
    /// (two arguments, a tag of 4 bytes, a compressed point on the curve, a body of 32
    /// bytes): checked before any device is asked.
    pub fn parse(stanza: &Stanza) -> Option<Result<Self, PivError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        Some(Self::read(stanza))
    }

    fn read(stanza: &Stanza) -> Result<Self, PivError> {
        let [tag, epk] = stanza.args.as_slice() else {
            return Err(PivError::Arguments(stanza.args.len()));
        };
        let mut tag_bytes = [0u8; TAG_BYTES];
        match Base64Unpadded::decode(tag, &mut tag_bytes) {
            Ok(decoded) if decoded.len() == TAG_BYTES => {}
            _ => return Err(PivError::Tag),
        }
        let mut point = [0u8; POINT_BYTES];
        match Base64Unpadded::decode(epk, &mut point) {
            Ok(decoded) if decoded.len() == POINT_BYTES => {}
            _ => return Err(PivError::Point),
        }
        // Compressed only (0x02 or 0x03), as the plugins write it; on the curve.
        if !matches!(point.first(), Some(0x02 | 0x03)) {
            return Err(PivError::Point);
        }
        let encoded = p256::Sec1Point::from_bytes(point).map_err(|_| PivError::Point)?;
        let epk: Option<p256::PublicKey> = p256::PublicKey::from_sec1_point(&encoded).into();
        let epk = epk.ok_or(PivError::Point)?;
        let body: [u8; BODY_BYTES] = stanza
            .body
            .as_slice()
            .try_into()
            .map_err(|_| PivError::Body(stanza.body.len()))?;
        Ok(Self {
            tag: tag_bytes,
            epk,
            body,
        })
    }

    /// Whether the stanza names `recipient` (its tag): another one's is not this key's to try.
    pub fn is_for(&self, recipient: &P256Recipient) -> bool {
        self.tag == recipient.tag()
    }

    /// The ephemeral point, uncompressed: what the device's ECDH takes.
    pub fn peer_point(&self) -> [u8; UNCOMPRESSED_BYTES] {
        let encoded = self.epk.to_sec1_point(false);
        let mut out = [0u8; UNCOMPRESSED_BYTES];
        for (o, b) in out.iter_mut().zip(encoded.as_bytes()) {
            *o = *b;
        }
        out
    }

    /// The file key, from the ECDH shared secret of `recipient`'s key and this stanza's point.
    pub fn unwrap(&self, recipient: &P256Recipient, shared: &[u8]) -> Result<FileKey, PivError> {
        if shared.len() != SHARED_BYTES {
            return Err(PivError::Shared);
        }
        let key = enc_key(&compressed(&self.epk), &recipient.compressed(), shared);
        let plaintext = age_core::primitives::aead_decrypt(&key, FILE_KEY_BYTES, &self.body)
            .map_err(|_| PivError::Open)?;
        let plaintext = Zeroizing::new(plaintext);
        let bytes: [u8; FILE_KEY_BYTES] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| PivError::Open)?;
        Ok(FileKey::new(Box::new(bytes)))
    }
}

fn compressed(point: &p256::PublicKey) -> [u8; POINT_BYTES] {
    let encoded = point.to_sec1_point(true);
    let mut out = [0u8; POINT_BYTES];
    for (o, b) in out.iter_mut().zip(encoded.as_bytes()) {
        *o = *b;
    }
    out
}

fn enc_key(
    epk: &[u8; POINT_BYTES],
    recipient: &[u8; POINT_BYTES],
    shared: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut salt = [0u8; POINT_BYTES * 2];
    for (o, b) in salt.iter_mut().zip(epk.iter().chain(recipient.iter())) {
        *o = *b;
    }
    Zeroizing::new(age_core::primitives::hkdf(&salt, LABEL, shared))
}

/// A software key-agreement key, for tests: the ECDH a device would do.
#[cfg(any(test, feature = "testing"))]
pub mod software {
    use super::{Line, P256Recipient, PivError, SHARED_BYTES};

    /// A P-256 key in memory, standing for one in hardware.
    pub struct SoftwareKey {
        secret: p256::SecretKey,
        recipient: P256Recipient,
    }

    impl SoftwareKey {
        /// The key whose scalar is `bytes` (refused unless one: zero, or past the order).
        pub fn from_scalar(bytes: &[u8; 32], hrp: &'static str) -> Result<Self, PivError> {
            let secret = p256::SecretKey::from_slice(bytes)
                .map_err(|_| PivError::Recipient("not a P-256 scalar"))?;
            let point = secret.public_key();
            let recipient = P256Recipient { point, hrp };
            Ok(Self { secret, recipient })
        }

        pub fn recipient(&self) -> &P256Recipient {
            &self.recipient
        }

        /// The shared secret with the stanza's point, as a device answers it.
        pub fn agree(&self, line: &Line) -> [u8; SHARED_BYTES] {
            let shared = p256::elliptic_curve::ecdh::diffie_hellman(
                self.secret.to_nonzero_scalar(),
                line.epk.as_affine(),
            );
            let mut out = [0u8; SHARED_BYTES];
            out.copy_from_slice(shared.raw_secret_bytes().as_slice());
            out
        }

        /// The shared secret with `peer` (a SEC1 point), as a device answers it; none for a
        /// peer that isn't a point on the curve.
        pub fn agree_with(&self, peer: &[u8]) -> Option<[u8; SHARED_BYTES]> {
            let peer = p256::PublicKey::from_sec1_bytes(peer).ok()?;
            let shared = p256::elliptic_curve::ecdh::diffie_hellman(
                self.secret.to_nonzero_scalar(),
                peer.as_affine(),
            );
            let mut out = [0u8; SHARED_BYTES];
            out.copy_from_slice(shared.raw_secret_bytes().as_slice());
            Some(out)
        }

        /// The file key from a stanza of this key's: parse, tag, agree, unwrap.
        pub fn unwrap(
            &self,
            stanza: &age_core::format::Stanza,
        ) -> Option<Result<age_core::format::FileKey, PivError>> {
            let line = match Line::parse(stanza)? {
                Ok(line) => line,
                Err(e) => return Some(Err(e)),
            };
            if !line.is_for(&self.recipient) {
                return None;
            }
            Some(line.unwrap(&self.recipient, &self.agree(&line)))
        }
    }
}
