//! OpenPGP v4 (RFC 4880, RFC 6637, and EdDSA as GnuPG writes it): what the daemon writes for
//! an agent signing key declared `format: openpgp`. Writing only: nothing here parses OpenPGP,
//! so OpenPGP adds no untrusted input to the daemon.
//!
//! - [`OpenpgpKey`]: a key's public key packet, from its SSH public half and its creation
//!   time (both fix its fingerprint), and its fingerprint.
//! - [`ToSign`]: a signature prepared ([`detached`] over a document, git's `-bsau`;
//!   [`certification`] of a user id, a self-signature): what the key must sign through the
//!   `Signer`, then [`ToSign::packet`] wraps the raw signature.
//! - [`certificate`] and [`armor`]: the armored text a remote imports, and git reads.
//!
//! Split like `sshsig`: the bytes are built here, a key signs them (anywhere), the signature
//! is wrapped here. Keys are v4 (GnuPG reads no v6): Ed25519 as EdDSA (algorithm 22), P-256
//! and P-384 as ECDSA (19), RSA (1). Every signature carries its creation time and its
//! issuer's fingerprint (hashed) and key id (not hashed).

use ssh_key::PublicKey;
use ssh_key::public::{EcdsaPublicKey, KeyData};

use crate::algorithm::{Hash, KeyAlgorithm, SignatureFormat, SignerHash};
use crate::keypair::RawSignature;
use crate::{CryptoError, Result};

/// OpenPGP public key algorithm ids.
const RSA: u8 = 1;
const ECDSA: u8 = 19;
const EDDSA: u8 = 22;

/// The curve OIDs (their DER content, without tag and length).
const OID_ED25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];

/// Packet tags.
const TAG_SIGNATURE: u8 = 2;
const TAG_PUBLIC_KEY: u8 = 6;
const TAG_USER_ID: u8 = 13;

/// Signature types.
const BINARY_DOCUMENT: u8 = 0x00;
const POSITIVE_CERTIFICATION: u8 = 0x13;

/// Subpacket types.
const SUB_CREATION_TIME: u8 = 2;
const SUB_ISSUER: u8 = 16;
const SUB_PREFERRED_HASHES: u8 = 21;
const SUB_KEY_FLAGS: u8 = 27;
const SUB_FEATURES: u8 = 30;
const SUB_ISSUER_FINGERPRINT: u8 = 33;

/// The OpenPGP id of a hash.
fn hash_id(hash: Hash) -> u8 {
    match hash {
        Hash::Sha256 => 8,
        Hash::Sha384 => 9,
        Hash::Sha512 => 10,
    }
}

fn too_large() -> CryptoError {
    CryptoError::Unsupported("an OpenPGP packet larger than 4 GiB".to_owned())
}

/// `bytes` (big-endian, unsigned) as an MPI: its bit count, then its bytes without leading
/// zeros.
fn mpi(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let digits = bytes.get(start..).unwrap_or_default();
    let bits = match digits.first() {
        Some(&first) => {
            let top = u32::BITS.saturating_sub(u32::from(first).leading_zeros());
            let rest = digits
                .len()
                .saturating_sub(1)
                .checked_mul(8)
                .and_then(|r| u32::try_from(r).ok())
                .ok_or_else(too_large)?;
            rest.checked_add(top).ok_or_else(too_large)?
        }
        None => 0,
    };
    let bits = u16::try_from(bits).map_err(|_| too_large())?;
    out.extend_from_slice(&bits.to_be_bytes());
    out.extend_from_slice(digits);
    Ok(())
}

/// A packet: a new-format header (tag, length), then `body`.
fn packet(tag: u8, body: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0xC0 | tag];
    let len = body.len();
    if len < 192 {
        out.push(u8::try_from(len).map_err(|_| too_large())?);
    } else if len < 8384 {
        let rest = len.checked_sub(192).ok_or_else(too_large)?;
        let high = u8::try_from((rest >> 8).checked_add(192).ok_or_else(too_large)?)
            .map_err(|_| too_large())?;
        out.push(high);
        out.push(u8::try_from(rest & 0xFF).map_err(|_| too_large())?);
    } else {
        out.push(0xFF);
        out.extend_from_slice(&u32::try_from(len).map_err(|_| too_large())?.to_be_bytes());
    }
    out.extend_from_slice(body);
    Ok(out)
}

/// A subpacket: its length (type included), its type, its data.
fn subpacket(out: &mut Vec<u8>, kind: u8, data: &[u8]) -> Result<()> {
    let len = data.len().checked_add(1).ok_or_else(too_large)?;
    out.push(
        u8::try_from(len)
            .ok()
            .filter(|l| *l < 192)
            .ok_or_else(too_large)?,
    );
    out.push(kind);
    out.extend_from_slice(data);
    Ok(())
}

/// A key as OpenPGP knows it: its v4 public key packet, and the fingerprint that names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenpgpKey {
    algorithm: KeyAlgorithm,
    created: u32,
    /// The public key packet's body (version, time, algorithm, key material).
    body: Vec<u8>,
    fingerprint: [u8; 20],
}

impl OpenpgpKey {
    /// The OpenPGP key of an SSH public key, made at `created` (seconds since the epoch).
    pub fn new(public: &PublicKey, created: u32) -> Result<Self> {
        let algorithm = KeyAlgorithm::of_public(public.key_data())
            .ok_or_else(|| CryptoError::Unsupported(format!("a {} key", public.algorithm())))?;
        let mut body = vec![4];
        body.extend_from_slice(&created.to_be_bytes());
        match public.key_data() {
            KeyData::Ed25519(key) => {
                body.push(EDDSA);
                oid(&mut body, OID_ED25519)?;
                let mut point = vec![0x40];
                point.extend_from_slice(&key.0);
                mpi(&mut body, &point)?;
            }
            KeyData::Ecdsa(EcdsaPublicKey::NistP256(point)) => {
                body.push(ECDSA);
                oid(&mut body, OID_P256)?;
                mpi(&mut body, point.as_bytes())?;
            }
            KeyData::Ecdsa(EcdsaPublicKey::NistP384(point)) => {
                body.push(ECDSA);
                oid(&mut body, OID_P384)?;
                mpi(&mut body, point.as_bytes())?;
            }
            KeyData::Rsa(rsa) => {
                body.push(RSA);
                let digits = |m: &ssh_key::Mpint| {
                    m.as_positive_bytes()
                        .map(<[u8]>::to_vec)
                        .ok_or(CryptoError::BadSignature)
                };
                mpi(&mut body, &digits(rsa.n())?)?;
                mpi(&mut body, &digits(rsa.e())?)?;
            }
            _ => {
                return Err(CryptoError::Unsupported(format!(
                    "a {} key",
                    public.algorithm()
                )));
            }
        }
        let fingerprint = fingerprint(&body)?;
        Ok(Self {
            algorithm,
            created,
            body,
            fingerprint,
        })
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    pub fn created(&self) -> u32 {
        self.created
    }

    pub fn fingerprint(&self) -> [u8; 20] {
        self.fingerprint
    }

    /// The fingerprint in uppercase hex (what `gpg --list-keys` and git's
    /// `user.signingkey` take).
    pub fn fingerprint_hex(&self) -> String {
        hex(&self.fingerprint)
    }

    /// The key id: the fingerprint's last 8 bytes.
    pub fn key_id(&self) -> [u8; 8] {
        let mut id = [0u8; 8];
        if let Some(tail) = self.fingerprint.get(12..) {
            id.copy_from_slice(tail);
        }
        id
    }

    /// The key id in uppercase hex.
    pub fn key_id_hex(&self) -> String {
        hex(&self.key_id())
    }

    /// The key packet as signatures hash it: `0x99`, its length on two bytes, its body.
    fn hashed_form(&self) -> Result<Vec<u8>> {
        let len = u16::try_from(self.body.len()).map_err(|_| too_large())?;
        let mut out = vec![0x99];
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    /// The public key packet.
    pub fn packet(&self) -> Result<Vec<u8>> {
        packet(TAG_PUBLIC_KEY, &self.body)
    }
}

/// A curve OID: its length on one byte, then its bytes.
fn oid(out: &mut Vec<u8>, oid: &[u8]) -> Result<()> {
    out.push(u8::try_from(oid.len()).map_err(|_| too_large())?);
    out.extend_from_slice(oid);
    Ok(())
}

/// The v4 fingerprint of a key packet body: SHA-1 of `0x99`, its length, the body (SHA-1 is
/// what v4 fingerprints are; the bytes are the daemon's own).
fn fingerprint(body: &[u8]) -> Result<[u8; 20]> {
    let len = u16::try_from(body.len()).map_err(|_| too_large())?;
    let mut data = vec![0x99];
    data.extend_from_slice(&len.to_be_bytes());
    data.extend_from_slice(body);
    let digest = sha1_checked::Sha1::try_digest(&data);
    let mut out = [0u8; 20];
    out.copy_from_slice(digest.hash().as_slice());
    Ok(out)
}

/// Uppercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// A signature prepared: what the key must sign ([`ToSign::signer_input`]), and what wraps
/// the result into a signature packet ([`ToSign::packet`]).
#[derive(Debug, Clone)]
pub struct ToSign {
    algorithm: KeyAlgorithm,
    hash: Hash,
    /// The signature packet's hashed part: version, type, algorithms, hashed subpackets.
    hashed: Vec<u8>,
    /// The unhashed subpackets (the issuer's key id).
    unhashed: Vec<u8>,
    /// Everything the signature covers: the data, the hashed part, the trailer.
    preimage: Vec<u8>,
    /// The hash of the preimage.
    digest: Vec<u8>,
}

impl ToSign {
    fn new(
        key: &OpenpgpKey,
        hash: Hash,
        kind: u8,
        subpackets: &[u8],
        mut data: Vec<u8>,
    ) -> Result<Self> {
        if !crate::algorithm::hashes(SignatureFormat::Openpgp, key.algorithm).contains(&hash) {
            return Err(CryptoError::Unsupported(format!(
                "an OpenPGP signature of a {} key with {hash}",
                key.algorithm
            )));
        }
        let algorithm_id = match key.algorithm {
            KeyAlgorithm::Ed25519 => EDDSA,
            KeyAlgorithm::P256 | KeyAlgorithm::P384 => ECDSA,
            KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => RSA,
        };
        let mut hashed = vec![4, kind, algorithm_id, hash_id(hash)];
        let mut issuer = vec![4];
        issuer.extend_from_slice(&key.fingerprint);
        let mut all = subpackets.to_vec();
        subpacket(&mut all, SUB_ISSUER_FINGERPRINT, &issuer)?;
        let len = u16::try_from(all.len()).map_err(|_| too_large())?;
        hashed.extend_from_slice(&len.to_be_bytes());
        hashed.extend_from_slice(&all);
        let mut unhashed = Vec::new();
        subpacket(&mut unhashed, SUB_ISSUER, &key.key_id())?;
        data.extend_from_slice(&hashed);
        data.extend_from_slice(&[4, 0xFF]);
        let hashed_len = u32::try_from(hashed.len()).map_err(|_| too_large())?;
        data.extend_from_slice(&hashed_len.to_be_bytes());
        let digest = hash.digest(&data);
        Ok(Self {
            algorithm: key.algorithm,
            hash,
            hashed,
            unhashed,
            preimage: data,
            digest,
        })
    }

    /// What the `Signer` signs, and the signer hash to ask it for: the digest itself for
    /// Ed25519 (EdDSA signs the digest), the whole preimage with the hash for ECDSA and RSA
    /// (the backend hashes it to the same digest).
    pub fn signer_input(&self) -> (&[u8], SignerHash) {
        match crate::algorithm::signer_hash(SignatureFormat::Openpgp, self.algorithm, self.hash) {
            None => (&self.digest, None),
            Some(hash) => (&self.preimage, Some(hash)),
        }
    }

    /// The signature packet, with `signature` (made over [`ToSign::signer_input`]).
    pub fn packet(&self, signature: &RawSignature) -> Result<Vec<u8>> {
        let (_, expected) = self.signer_input();
        if signature.algorithm() != self.algorithm || signature.hash() != expected {
            return Err(CryptoError::BadSignature);
        }
        let mut body = self.hashed.clone();
        let len = u16::try_from(self.unhashed.len()).map_err(|_| too_large())?;
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(&self.unhashed);
        body.extend_from_slice(self.digest.get(..2).ok_or(CryptoError::BadSignature)?);
        match self.algorithm {
            KeyAlgorithm::Ed25519 => {
                let (r, s) = signature
                    .as_bytes()
                    .split_at_checked(32)
                    .ok_or(CryptoError::BadSignature)?;
                mpi(&mut body, r)?;
                mpi(&mut body, s)?;
            }
            KeyAlgorithm::P256 | KeyAlgorithm::P384 => {
                let (r, s) = signature.ecdsa_halves().ok_or(CryptoError::BadSignature)?;
                mpi(&mut body, r)?;
                mpi(&mut body, s)?;
            }
            KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => mpi(&mut body, signature.as_bytes())?,
        }
        packet(TAG_SIGNATURE, &body)
    }
}

/// A detached signature of `data` (a binary document: git's `gpg -bsau`), made at `time`.
pub fn detached(key: &OpenpgpKey, hash: Hash, data: &[u8], time: u32) -> Result<ToSign> {
    let mut subpackets = Vec::new();
    subpacket(&mut subpackets, SUB_CREATION_TIME, &time.to_be_bytes())?;
    ToSign::new(key, hash, BINARY_DOCUMENT, &subpackets, data.to_vec())
}

/// The self-signature certifying `uid` on `key`: made at the key's creation time, so a
/// certificate depends only on the key, its creation time and its user ids. It says the key
/// certifies and signs, and prefers SHA-512, SHA-384 and SHA-256.
pub fn certification(key: &OpenpgpKey, hash: Hash, uid: &str) -> Result<ToSign> {
    let mut subpackets = Vec::new();
    subpacket(
        &mut subpackets,
        SUB_CREATION_TIME,
        &key.created.to_be_bytes(),
    )?;
    subpacket(&mut subpackets, SUB_KEY_FLAGS, &[0x03])?;
    subpacket(&mut subpackets, SUB_PREFERRED_HASHES, &[10, 9, 8])?;
    subpacket(&mut subpackets, SUB_FEATURES, &[0x01])?;
    let mut data = key.hashed_form()?;
    data.push(0xB4);
    let len = u32::try_from(uid.len()).map_err(|_| too_large())?;
    data.extend_from_slice(&len.to_be_bytes());
    data.extend_from_slice(uid.as_bytes());
    ToSign::new(key, hash, POSITIVE_CERTIFICATION, &subpackets, data)
}

/// The certificate: the public key packet, then each user id and its self-signature packet.
pub fn certificate(key: &OpenpgpKey, uids: &[(&str, Vec<u8>)]) -> Result<String> {
    let mut packets = key.packet()?;
    for (uid, signature) in uids {
        packets.extend(packet(TAG_USER_ID, uid.as_bytes())?);
        packets.extend_from_slice(signature);
    }
    Ok(armor(Armor::PublicKey, &packets))
}

/// What an armored block holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Armor {
    Signature,
    PublicKey,
}

impl Armor {
    fn label(self) -> &'static str {
        match self {
            Armor::Signature => "PGP SIGNATURE",
            Armor::PublicKey => "PGP PUBLIC KEY BLOCK",
        }
    }
}

/// `packets` armored: the header line, a blank line, base64 in lines of 64, the CRC-24
/// checksum, the footer line; every line ended.
pub fn armor(kind: Armor, packets: &[u8]) -> String {
    use base64ct::Encoding as _;
    let body = base64ct::Base64::encode_string(packets);
    let mut text = format!("-----BEGIN {}-----\n\n", kind.label());
    let mut rest = body.as_str();
    while !rest.is_empty() {
        let (line, after) = rest.split_at(rest.len().min(64));
        text.push_str(line);
        text.push('\n');
        rest = after;
    }
    let crc = crc24(packets).to_be_bytes();
    text.push('=');
    text.push_str(&base64ct::Base64::encode_string(
        crc.get(1..).unwrap_or_default(),
    ));
    text.push('\n');
    text.push_str(&format!("-----END {}-----\n", kind.label()));
    text
}

/// The largest armored certificate read back ([`certificate_fingerprint`]).
const MAX_ARMORED: usize = 64 * 1024;

/// The fingerprint of the key in an armored certificate (what [`certificate`] writes): its
/// first packet must be a v4 public key packet. Reads only that much, strictly: the
/// armor's lines, its checksum, the first packet's header; anything else is refused. For a
/// client wiring git (`user.signingkey`), from the certificate its pinned daemon sent.
pub fn certificate_fingerprint(armored: &str) -> Result<String> {
    use base64ct::Encoding as _;
    let refused = || CryptoError::Unsupported("an armored OpenPGP certificate".to_owned());
    if armored.len() > MAX_ARMORED {
        return Err(refused());
    }
    let label = Armor::PublicKey.label();
    let body = armored
        .strip_prefix(&format!("-----BEGIN {label}-----\n\n"))
        .and_then(|rest| rest.strip_suffix(&format!("-----END {label}-----\n")))
        .ok_or_else(refused)?;
    let mut lines: Vec<&str> = body.lines().collect();
    let checksum = lines
        .pop()
        .and_then(|l| l.strip_prefix('='))
        .ok_or_else(refused)?;
    let packets = base64ct::Base64::decode_vec(&lines.concat()).map_err(|_| refused())?;
    let crc = base64ct::Base64::decode_vec(checksum).map_err(|_| refused())?;
    if crc.as_slice() != crc24(&packets).to_be_bytes().get(1..).unwrap_or_default() {
        return Err(refused());
    }
    let (&tag, rest) = packets.split_first().ok_or_else(refused)?;
    if tag != 0xC0 | TAG_PUBLIC_KEY {
        return Err(refused());
    }
    let (len, rest) = match rest.split_first() {
        Some((&first, rest)) if first < 192 => (usize::from(first), rest),
        Some((&first, rest)) if first < 224 => {
            let (&second, rest) = rest.split_first().ok_or_else(refused)?;
            let len = usize::from(first)
                .checked_sub(192)
                .and_then(|h| h.checked_mul(256))
                .and_then(|h| h.checked_add(usize::from(second)))
                .and_then(|h| h.checked_add(192))
                .ok_or_else(refused)?;
            (len, rest)
        }
        _ => return Err(refused()),
    };
    let body = rest.get(..len).ok_or_else(refused)?;
    if body.first() != Some(&4) {
        return Err(refused());
    }
    Ok(hex(&fingerprint(body)?))
}

/// OpenPGP's CRC-24 (RFC 4880 § 6.1).
fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0x00B7_04CE;
    for &byte in data {
        crc ^= u32::from(byte) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4CFB;
            }
        }
    }
    crc & 0x00FF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::KeyPair;

    #[test]
    fn crc24_is_the_rfc_s() {
        // The CRC-24 of no data is the initial value.
        assert_eq!(crc24(b""), 0x00B7_04CE);
        // A known value: "123456789".
        assert_eq!(crc24(b"123456789"), 0x0021_CF02);
    }

    #[test]
    fn mpis_count_bits_without_leading_zeros() {
        let mut out = Vec::new();
        mpi(&mut out, &[0x00, 0x01, 0xFF]).unwrap();
        assert_eq!(out, [0x00, 0x09, 0x01, 0xFF]);
        let mut out = Vec::new();
        mpi(&mut out, &[0x40, 0x00]).unwrap();
        assert_eq!(out, [0x00, 0x0F, 0x40, 0x00]);
        let mut out = Vec::new();
        mpi(&mut out, &[]).unwrap();
        assert_eq!(out, [0x00, 0x00]);
    }

    #[test]
    fn packet_lengths_take_one_two_or_five_bytes() {
        assert_eq!(packet(2, &[0; 191]).unwrap()[..2], [0xC2, 191]);
        assert_eq!(packet(2, &[0; 192]).unwrap()[..3], [0xC2, 192, 0]);
        assert_eq!(packet(2, &[0; 8383]).unwrap()[..3], [0xC2, 223, 255]);
        assert_eq!(
            packet(2, &[0; 8384]).unwrap()[..6],
            [0xC2, 0xFF, 0, 0, 0x20, 0xC0]
        );
    }

    #[test]
    fn a_key_s_fingerprint_depends_on_its_creation_time() {
        let key = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let a = OpenpgpKey::new(&key.public_key(), 1_700_000_000).unwrap();
        let b = OpenpgpKey::new(&key.public_key(), 1_700_000_001).unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.fingerprint_hex().len(), 40);
        assert!(a.fingerprint_hex().ends_with(&a.key_id_hex()));
        assert_eq!(
            a,
            OpenpgpKey::new(&key.public_key(), 1_700_000_000).unwrap()
        );
    }

    #[test]
    fn a_certificate_s_fingerprint_reads_back_and_anything_else_is_refused() {
        for algorithm in [KeyAlgorithm::Ed25519, KeyAlgorithm::Rsa4096] {
            let key = KeyPair::generate(algorithm).unwrap();
            let pgp = OpenpgpKey::new(&key.public_key(), 7).unwrap();
            let prepared = certification(&pgp, Hash::Sha256, "<a@b>").unwrap();
            let (data, hash) = prepared.signer_input();
            let packet = prepared.packet(&key.sign(data, hash).unwrap()).unwrap();
            let armored = certificate(&pgp, &[("<a@b>", packet)]).unwrap();
            assert_eq!(
                certificate_fingerprint(&armored).unwrap(),
                pgp.fingerprint_hex()
            );
            // A byte changed: the checksum fails.
            let tampered = armored.replacen("\n\nx", "\n\ny", 1);
            let tampered = if tampered == armored {
                armored.replacen("\n\n", "\n\nA", 1)
            } else {
                tampered
            };
            assert!(matches!(
                certificate_fingerprint(&tampered),
                Err(CryptoError::Unsupported(_))
            ));
            // A signature block, not a certificate.
            let signature = armored.replace("PUBLIC KEY BLOCK", "SIGNATURE");
            assert!(matches!(
                certificate_fingerprint(&signature),
                Err(CryptoError::Unsupported(_))
            ));
        }
        assert!(matches!(
            certificate_fingerprint(&"A".repeat(MAX_ARMORED + 1)),
            Err(CryptoError::Unsupported(_))
        ));
    }

    #[test]
    fn a_hash_the_format_does_not_take_is_refused() {
        let key = KeyPair::generate(KeyAlgorithm::P256).unwrap();
        let pgp = OpenpgpKey::new(&key.public_key(), 1).unwrap();
        assert!(matches!(
            detached(&pgp, Hash::Sha512, b"x", 2),
            Err(CryptoError::Unsupported(_))
        ));
        let prepared = detached(&pgp, Hash::Sha256, b"x", 2).unwrap();
        // A signature made with another pair is refused.
        let other = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let wrong = other.sign(b"x", None).unwrap();
        assert!(matches!(
            prepared.packet(&wrong),
            Err(CryptoError::BadSignature)
        ));
    }
}
