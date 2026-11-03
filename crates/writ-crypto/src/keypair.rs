//! A signing key held in memory ([`KeyPair`]), the raw signature a `Signer` answers
//! ([`RawSignature`]), and its check against a public key ([`verify`]).
//!
//! `ssh-key`'s `PrivateKey` holds Ed25519, P-256 and P-384 keys and signs with them in pure
//! Rust; it would sign RSA only through the `rsa` crate, which Writ bans (a timing side
//! channel, and agents can ask for signatures and time them). [`KeyPair`] is Writ's own type
//! over both, so a backend takes one kind of key whatever its algorithm.
//!
//! A [`RawSignature`] is the signature alone, in one fixed encoding per algorithm (Ed25519's
//! 64 bytes, ECDSA's `r ‖ s` with each half the curve's size, RSA's `s` the modulus's size),
//! with the algorithm and the hash it was made with. Adapters turn it into an SSH signature
//! ([`RawSignature::to_ssh`]), TLS's DER, or OpenPGP's MPIs.

use std::fmt;

use signature::{Signer as _, Verifier as _};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey, PublicKey, Signature};
use zeroize::Zeroizing;

use crate::algorithm::{Hash, KeyAlgorithm, SignerHash};
use crate::{CryptoError, Result};

/// A private key Writ signs with, wiped on drop, never printed.
pub struct KeyPair(Inner);

enum Inner {
    /// Ed25519, P-256 or P-384, through `ssh-key` (which wipes it on drop).
    Ssh {
        key: Box<PrivateKey>,
        algorithm: KeyAlgorithm,
    },
    /// RSA 3072 or 4096, through `aws-lc-rs` (AWS-LC frees a key's numbers with
    /// `OPENSSL_free`, which wipes them), with its public half as an SSH key.
    Rsa {
        key: Box<aws_lc_rs::rsa::KeyPair>,
        public: PublicKey,
        algorithm: KeyAlgorithm,
    },
}

/// The PEM label of a PKCS#8 private key (an RSA key's storage).
const PKCS8_LABEL: &str = "PRIVATE KEY";

/// The SSH public key of an RSA key pair, from its modulus and exponent.
fn rsa_public(key: &aws_lc_rs::rsa::KeyPair) -> Result<PublicKey> {
    use aws_lc_rs::signature::KeyPair as _;
    let public = key.public_key();
    let rsa = ssh_key::public::RsaPublicKey::new(
        ssh_key::Mpint::from_positive_bytes(public.exponent().big_endian_without_leading_zero()),
        ssh_key::Mpint::from_positive_bytes(public.modulus().big_endian_without_leading_zero()),
    )?;
    Ok(PublicKey::from(ssh_key::public::KeyData::Rsa(rsa)))
}

/// An RSA key pair checked to be one Writ signs with: 3072 or 4096 bits.
fn rsa(key: aws_lc_rs::rsa::KeyPair) -> Result<KeyPair> {
    let public = rsa_public(&key)?;
    let algorithm = KeyAlgorithm::of_public(public.key_data())
        .filter(|a| a.is_rsa())
        .ok_or_else(|| {
            CryptoError::Unsupported(format!(
                "an RSA key of {} bits (3072 or 4096)",
                key.public_modulus_len().saturating_mul(8)
            ))
        })?;
    Ok(KeyPair(Inner::Rsa {
        key: Box::new(key),
        public,
        algorithm,
    }))
}

/// The `aws-lc-rs` PKCS#1 v1.5 encoding for `hash`.
fn rsa_encoding(hash: Hash) -> &'static aws_lc_rs::signature::RsaSignatureEncoding {
    match hash {
        Hash::Sha256 => &aws_lc_rs::signature::RSA_PKCS1_SHA256,
        Hash::Sha384 => &aws_lc_rs::signature::RSA_PKCS1_SHA384,
        Hash::Sha512 => &aws_lc_rs::signature::RSA_PKCS1_SHA512,
    }
}

/// The `aws-lc-rs` PKCS#1 v1.5 verification parameters for `hash` (keys of 2048 to 8192
/// bits: the key's own size is checked by its algorithm first).
fn rsa_parameters(hash: Hash) -> &'static aws_lc_rs::signature::RsaParameters {
    match hash {
        Hash::Sha256 => &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
        Hash::Sha384 => &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA384,
        Hash::Sha512 => &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA512,
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The algorithm only: never a key.
        f.debug_struct("KeyPair")
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

/// The SSH algorithm `ssh-key` names an algorithm Writ signs through it with.
fn ssh_algorithm(algorithm: KeyAlgorithm) -> Option<Algorithm> {
    match algorithm {
        KeyAlgorithm::Ed25519 => Some(Algorithm::Ed25519),
        KeyAlgorithm::P256 => Some(Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        }),
        KeyAlgorithm::P384 => Some(Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        }),
        KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => None,
    }
}

/// The only signer hash a key of `algorithm` signs with in `ssh-key`: none for Ed25519, the
/// curve's for ECDSA.
fn ssh_signer_hash(algorithm: KeyAlgorithm) -> Option<SignerHash> {
    match algorithm {
        KeyAlgorithm::Ed25519 => Some(None),
        KeyAlgorithm::P256 => Some(Some(Hash::Sha256)),
        KeyAlgorithm::P384 => Some(Some(Hash::Sha384)),
        KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => None,
    }
}

impl KeyPair {
    /// A new key of `algorithm`, from the system's random source.
    pub fn generate(algorithm: KeyAlgorithm) -> Result<Self> {
        match (ssh_algorithm(algorithm), algorithm) {
            (Some(ssh), _) => {
                let key = crate::keys::with_rng(|rng| Ok(PrivateKey::random(rng, ssh.clone())?))?;
                Ok(Self(Inner::Ssh {
                    key: Box::new(key),
                    algorithm,
                }))
            }
            (None, KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096) => {
                let size = if algorithm == KeyAlgorithm::Rsa3072 {
                    aws_lc_rs::rsa::KeySize::Rsa3072
                } else {
                    aws_lc_rs::rsa::KeySize::Rsa4096
                };
                let key =
                    aws_lc_rs::rsa::KeyPair::generate(size).map_err(|_| CryptoError::Random)?;
                rsa(key)
            }
            (None, _) => Err(CryptoError::Unsupported(format!(
                "{algorithm} keys are not generated by this build"
            ))),
        }
    }

    /// Takes an OpenSSH key (moved in): Ed25519, P-256 or P-384, not encrypted.
    pub fn from_ssh(key: PrivateKey) -> Result<Self> {
        if key.is_encrypted() {
            return Err(CryptoError::Unsupported("an encrypted key".to_owned()));
        }
        let algorithm = KeyAlgorithm::of_public(key.public_key().key_data())
            .filter(|a| ssh_algorithm(*a).is_some())
            .ok_or_else(|| {
                CryptoError::Unsupported(format!("a {} key", key.algorithm().as_str()))
            })?;
        Ok(Self(Inner::Ssh {
            key: Box::new(key),
            algorithm,
        }))
    }

    /// Reads a key written by [`KeyPair::to_pem`]: an OpenSSH private key, or an RSA key as
    /// PKCS#8 (`PRIVATE KEY`).
    pub fn from_pem(text: &[u8]) -> Result<Self> {
        let begin = format!("-----BEGIN {PKCS8_LABEL}-----");
        if !text.starts_with(begin.as_bytes()) {
            return Self::from_ssh(PrivateKey::from_openssh(text)?);
        }
        let der = pem_decode(text, PKCS8_LABEL)?;
        let key = aws_lc_rs::rsa::KeyPair::from_pkcs8(&der)
            .map_err(|_| CryptoError::Unsupported("a PKCS#8 key that isn't RSA".to_owned()))?;
        rsa(key)
    }

    /// The key as text to store (a private file, or an age file): an OpenSSH private key, or
    /// an RSA key as PKCS#8 PEM. Wiped on drop.
    pub fn to_pem(&self) -> Result<Zeroizing<String>> {
        match &self.0 {
            Inner::Ssh { key, .. } => Ok(key.to_openssh(LineEnding::LF)?),
            Inner::Rsa { key, .. } => {
                use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
                let der: Pkcs8V1Der<'_> = key.as_der().map_err(|_| CryptoError::SigningFailed)?;
                Ok(pem_encode(PKCS8_LABEL, der.as_ref()))
            }
        }
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        match &self.0 {
            Inner::Ssh { algorithm, .. } | Inner::Rsa { algorithm, .. } => *algorithm,
        }
    }

    /// Its public half, as an SSH public key (what is printed, registered and checked).
    pub fn public_key(&self) -> PublicKey {
        match &self.0 {
            Inner::Ssh { key, .. } => key.public_key().clone(),
            Inner::Rsa { public, .. } => public.clone(),
        }
    }

    /// Whether it signs with `hash` (see [`crate::algorithm::signer_hash`]): RSA with each
    /// SHA-2, never without a hash.
    pub fn signs_with(&self, hash: SignerHash) -> bool {
        match &self.0 {
            Inner::Ssh { algorithm, .. } => ssh_signer_hash(*algorithm) == Some(hash),
            Inner::Rsa { .. } => hash.is_some(),
        }
    }

    /// Signs `data` with `hash` (`None` for Ed25519, which signs the bytes themselves; the
    /// curve's hash for ECDSA). Any other pair is refused, never replaced.
    pub fn sign(&self, data: &[u8], hash: SignerHash) -> Result<RawSignature> {
        if !self.signs_with(hash) {
            return Err(CryptoError::Unsupported(pair(self.algorithm(), hash)));
        }
        match &self.0 {
            Inner::Ssh { key, algorithm } => {
                let signature = key.try_sign(data).map_err(|_| CryptoError::SigningFailed)?;
                RawSignature::from_ssh(*algorithm, &signature)
            }
            Inner::Rsa { key, algorithm, .. } => {
                let hash = hash.ok_or_else(|| CryptoError::Unsupported(pair(*algorithm, None)))?;
                let mut signature = vec![0u8; key.public_modulus_len()];
                // PKCS#1 v1.5 is deterministic: AWS-LC ignores the generator.
                let rng = aws_lc_rs::rand::SystemRandom::new();
                key.sign(rsa_encoding(hash), &rng, data, &mut signature)
                    .map_err(|_| CryptoError::SigningFailed)?;
                RawSignature::new(*algorithm, Some(hash), signature)
            }
        }
    }
}

/// `der` as PEM text under `label`, in memory wiped on drop.
fn pem_encode(label: &str, der: &[u8]) -> Zeroizing<String> {
    use base64ct::Encoding as _;
    let body = Zeroizing::new(base64ct::Base64::encode_string(der));
    let mut text = Zeroizing::new(String::with_capacity(body.len().saturating_add(128)));
    text.push_str("-----BEGIN ");
    text.push_str(label);
    text.push_str("-----\n");
    let mut rest = body.as_str();
    while !rest.is_empty() {
        let (line, after) = rest.split_at(rest.len().min(64));
        text.push_str(line);
        text.push('\n');
        rest = after;
    }
    text.push_str("-----END ");
    text.push_str(label);
    text.push_str("-----\n");
    text
}

/// The DER inside PEM `text` under `label`: exactly one block, nothing around it but a final
/// newline. Wiped on drop.
fn pem_decode(text: &[u8], label: &str) -> Result<Zeroizing<Vec<u8>>> {
    use base64ct::Encoding as _;
    let malformed = || CryptoError::Unsupported(format!("a malformed {label} PEM block"));
    let text = std::str::from_utf8(text).map_err(|_| malformed())?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut lines = text.trim_end_matches('\n').split('\n');
    if lines.next() != Some(begin.as_str()) || lines.next_back() != Some(end.as_str()) {
        return Err(malformed());
    }
    let mut body = Zeroizing::new(String::new());
    for line in lines {
        body.push_str(line.trim_end_matches('\r'));
    }
    Ok(Zeroizing::new(
        base64ct::Base64::decode_vec(&body).map_err(|_| malformed())?,
    ))
}

/// What becomes a [`KeyPair`]: one already, or an OpenSSH key (moved in).
pub trait IntoKeyPair {
    fn into_keypair(self) -> Result<KeyPair>;
}

impl IntoKeyPair for KeyPair {
    fn into_keypair(self) -> Result<KeyPair> {
        Ok(self)
    }
}

impl IntoKeyPair for PrivateKey {
    fn into_keypair(self) -> Result<KeyPair> {
        KeyPair::from_ssh(self)
    }
}

/// An (algorithm, signer hash) pair, for a message.
pub fn pair(algorithm: KeyAlgorithm, hash: SignerHash) -> String {
    match hash {
        Some(hash) => format!("{algorithm} with {hash}"),
        None => format!("{algorithm} without a hash"),
    }
}

/// A signature alone, with what it was made with. See the module documentation.
#[derive(Clone, PartialEq, Eq)]
pub struct RawSignature {
    algorithm: KeyAlgorithm,
    hash: SignerHash,
    bytes: Vec<u8>,
}

impl fmt::Debug for RawSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawSignature")
            .field("algorithm", &self.algorithm)
            .field("hash", &self.hash)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// The size of a signature of `algorithm`, in its fixed encoding.
fn signature_len(algorithm: KeyAlgorithm) -> usize {
    match algorithm {
        KeyAlgorithm::Ed25519 | KeyAlgorithm::P256 => 64,
        KeyAlgorithm::P384 => 96,
        KeyAlgorithm::Rsa3072 => 384,
        KeyAlgorithm::Rsa4096 => 512,
    }
}

impl RawSignature {
    /// A signature of `algorithm` made with `hash`, in its fixed encoding: refused if its
    /// size isn't the algorithm's, or the pair isn't one Writ signs with.
    pub fn new(algorithm: KeyAlgorithm, hash: SignerHash, bytes: Vec<u8>) -> Result<Self> {
        let paired = match algorithm {
            KeyAlgorithm::Ed25519 => hash.is_none(),
            KeyAlgorithm::P256 => hash == Some(Hash::Sha256),
            KeyAlgorithm::P384 => hash == Some(Hash::Sha384),
            KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => hash.is_some(),
        };
        if !paired {
            return Err(CryptoError::Unsupported(pair(algorithm, hash)));
        }
        if bytes.len() != signature_len(algorithm) {
            return Err(CryptoError::BadSignature);
        }
        Ok(Self {
            algorithm,
            hash,
            bytes,
        })
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    pub fn hash(&self) -> SignerHash {
        self.hash
    }

    /// The signature in its fixed encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// ECDSA's `r` and `s`, each the curve's size; none for another algorithm.
    pub fn ecdsa_halves(&self) -> Option<(&[u8], &[u8])> {
        match self.algorithm {
            KeyAlgorithm::P256 | KeyAlgorithm::P384 => {
                self.bytes.split_at_checked(self.bytes.len() / 2)
            }
            _ => None,
        }
    }

    /// From an SSH signature made by a key of `algorithm`.
    pub fn from_ssh(algorithm: KeyAlgorithm, signature: &Signature) -> Result<Self> {
        let expected = match algorithm {
            KeyAlgorithm::Ed25519 | KeyAlgorithm::P256 | KeyAlgorithm::P384 => {
                ssh_algorithm(algorithm) == Some(signature.algorithm())
            }
            KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
                matches!(signature.algorithm(), Algorithm::Rsa { hash: Some(_) })
            }
        };
        if !expected {
            return Err(CryptoError::Unsupported(format!(
                "an {} signature for a {algorithm} key",
                signature.algorithm().as_str()
            )));
        }
        match algorithm {
            KeyAlgorithm::Ed25519 => Self::new(algorithm, None, signature.as_bytes().to_vec()),
            KeyAlgorithm::P256 | KeyAlgorithm::P384 => {
                let size = signature_len(algorithm) / 2;
                let mut rest = signature.as_bytes();
                let mut raw = Vec::with_capacity(signature_len(algorithm));
                for _ in 0..2 {
                    let (digits, after) = read_mpint(rest).ok_or(CryptoError::BadSignature)?;
                    rest = after;
                    let start = size
                        .checked_sub(digits.len())
                        .ok_or(CryptoError::BadSignature)?;
                    raw.extend(std::iter::repeat_n(0u8, start));
                    raw.extend_from_slice(digits);
                }
                if !rest.is_empty() {
                    return Err(CryptoError::BadSignature);
                }
                Self::new(algorithm, ssh_signer_hash(algorithm).flatten(), raw)
            }
            KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
                let hash = match signature.algorithm() {
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    } => Hash::Sha256,
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha512),
                    } => Hash::Sha512,
                    _ => return Err(CryptoError::BadSignature),
                };
                Self::new(algorithm, Some(hash), signature.as_bytes().to_vec())
            }
        }
    }

    /// As an SSH signature: `ssh-ed25519`, `ecdsa-sha2-nistp256`/`384`, or `rsa-sha2-256`/
    /// `512` (never `ssh-rsa`, SHA-1). RSA with SHA-384 has no SSH name: refused.
    pub fn to_ssh(&self) -> Result<Signature> {
        match self.algorithm {
            KeyAlgorithm::Ed25519 => Ok(Signature::new(Algorithm::Ed25519, self.bytes.clone())?),
            KeyAlgorithm::P256 | KeyAlgorithm::P384 => {
                let (r, s) = self.ecdsa_halves().ok_or(CryptoError::BadSignature)?;
                let mut blob = Vec::new();
                write_mpint(&mut blob, r)?;
                write_mpint(&mut blob, s)?;
                let algorithm = ssh_algorithm(self.algorithm).ok_or(CryptoError::BadSignature)?;
                Ok(Signature::new(algorithm, blob)?)
            }
            KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
                let hash = match self.hash {
                    Some(Hash::Sha256) => HashAlg::Sha256,
                    Some(Hash::Sha512) => HashAlg::Sha512,
                    other => {
                        return Err(CryptoError::Unsupported(format!(
                            "an SSH signature of {}",
                            pair(self.algorithm, other)
                        )));
                    }
                };
                Ok(Signature::new(
                    Algorithm::Rsa { hash: Some(hash) },
                    self.bytes.clone(),
                )?)
            }
        }
    }
}

/// An SSH `mpint` at the start of `bytes` (a 4-byte length, then big-endian digits with a zero
/// byte in front when the high bit is set): its digits without that zero, and what follows.
fn read_mpint(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, after) = bytes.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
    let (digits, rest) = after.split_at_checked(len)?;
    let digits = match digits.split_first() {
        Some((0, tail)) => tail,
        _ => digits,
    };
    Some((digits, rest))
}

/// Appends `digits` (big-endian, unsigned) as an SSH `mpint`.
fn write_mpint(out: &mut Vec<u8>, digits: &[u8]) -> Result<()> {
    let start = digits.iter().position(|&b| b != 0).unwrap_or(digits.len());
    let digits = digits.get(start..).unwrap_or_default();
    let pad = digits.first().is_some_and(|&b| b & 0x80 != 0);
    let len = digits
        .len()
        .checked_add(usize::from(pad))
        .and_then(|len| u32::try_from(len).ok())
        .ok_or(CryptoError::BadSignature)?;
    out.extend_from_slice(&len.to_be_bytes());
    if pad {
        out.push(0);
    }
    out.extend_from_slice(digits);
    Ok(())
}

/// Checks `signature` over `data` against `public`: the algorithm must be the key's, and the
/// signature the one that key made over those bytes with its hash.
pub fn verify(public: &PublicKey, data: &[u8], signature: &RawSignature) -> Result<()> {
    let algorithm = KeyAlgorithm::of_public(public.key_data())
        .ok_or_else(|| CryptoError::Unsupported(format!("a {} key", public.algorithm())))?;
    if algorithm != signature.algorithm() {
        return Err(CryptoError::BadSignature);
    }
    match algorithm {
        KeyAlgorithm::Ed25519 | KeyAlgorithm::P256 | KeyAlgorithm::P384 => public
            .key_data()
            .verify(data, &signature.to_ssh()?)
            .map_err(|_| CryptoError::BadSignature),
        KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
            let ssh_key::public::KeyData::Rsa(rsa) = public.key_data() else {
                return Err(CryptoError::BadSignature);
            };
            let hash = signature.hash().ok_or(CryptoError::BadSignature)?;
            let digits = |m: &ssh_key::Mpint| m.as_positive_bytes().map(<[u8]>::to_vec);
            let components = aws_lc_rs::signature::RsaPublicKeyComponents {
                n: digits(rsa.n()).ok_or(CryptoError::BadSignature)?,
                e: digits(rsa.e()).ok_or(CryptoError::BadSignature)?,
            };
            components
                .verify(rsa_parameters(hash), data, signature.as_bytes())
                .map_err(|_| CryptoError::BadSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNED: &[(KeyAlgorithm, SignerHash)] = &[
        (KeyAlgorithm::Ed25519, None),
        (KeyAlgorithm::P256, Some(Hash::Sha256)),
        (KeyAlgorithm::P384, Some(Hash::Sha384)),
    ];

    #[test]
    fn each_algorithm_signs_with_its_hash_and_verifies_only_its_bytes() {
        for &(algorithm, hash) in SIGNED {
            let key = KeyPair::generate(algorithm).unwrap();
            assert_eq!(key.algorithm(), algorithm);
            let signature = key.sign(b"data", hash).unwrap();
            assert_eq!((signature.algorithm(), signature.hash()), (algorithm, hash));
            verify(&key.public_key(), b"data", &signature).unwrap();
            assert!(matches!(
                verify(&key.public_key(), b"other", &signature),
                Err(CryptoError::BadSignature)
            ));
            let other = KeyPair::generate(algorithm).unwrap();
            assert!(matches!(
                verify(&other.public_key(), b"data", &signature),
                Err(CryptoError::BadSignature)
            ));
            // Through SSH and back, the same signature.
            let ssh = signature.to_ssh().unwrap();
            assert_eq!(RawSignature::from_ssh(algorithm, &ssh).unwrap(), signature);
            // Stored and read back, the same key.
            let again = KeyPair::from_pem(key.to_pem().unwrap().as_bytes()).unwrap();
            assert_eq!(again.public_key(), key.public_key());
        }
    }

    #[test]
    fn rsa_signs_with_each_sha2_in_constant_time_code_and_is_stored_as_pkcs8() {
        for algorithm in [KeyAlgorithm::Rsa3072, KeyAlgorithm::Rsa4096] {
            let key = KeyPair::generate(algorithm).unwrap();
            assert_eq!(key.algorithm(), algorithm);
            assert_eq!(
                KeyAlgorithm::of_public(key.public_key().key_data()),
                Some(algorithm)
            );
            for hash in [Hash::Sha256, Hash::Sha384, Hash::Sha512] {
                let signature = key.sign(b"data", Some(hash)).unwrap();
                assert_eq!(
                    signature.as_bytes().len(),
                    algorithm.rsa_modulus_len().unwrap()
                );
                verify(&key.public_key(), b"data", &signature).unwrap();
                assert!(matches!(
                    verify(&key.public_key(), b"other", &signature),
                    Err(CryptoError::BadSignature)
                ));
                // Deterministic (PKCS#1 v1.5): the same bytes sign the same.
                assert_eq!(key.sign(b"data", Some(hash)).unwrap(), signature);
                match hash {
                    Hash::Sha384 => assert!(matches!(
                        signature.to_ssh(),
                        Err(CryptoError::Unsupported(_))
                    )),
                    _ => {
                        let ssh = signature.to_ssh().unwrap();
                        assert_eq!(
                            ssh.algorithm().as_str(),
                            if hash == Hash::Sha256 {
                                "rsa-sha2-256"
                            } else {
                                "rsa-sha2-512"
                            }
                        );
                        assert_eq!(RawSignature::from_ssh(algorithm, &ssh).unwrap(), signature);
                    }
                }
            }
            assert!(matches!(
                key.sign(b"data", None),
                Err(CryptoError::Unsupported(_))
            ));
            let pem = key.to_pem().unwrap();
            assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"), "PKCS#8");
            let again = KeyPair::from_pem(pem.as_bytes()).unwrap();
            assert_eq!(again.public_key(), key.public_key());
            // Its public half is an ordinary ssh-rsa key.
            assert!(
                key.public_key()
                    .to_openssh()
                    .unwrap()
                    .starts_with("ssh-rsa AAAA")
            );
        }
    }

    #[test]
    fn a_malformed_or_foreign_pkcs8_block_is_refused() {
        let key = KeyPair::generate(KeyAlgorithm::Rsa3072).unwrap();
        let pem = key.to_pem().unwrap();
        let cut = pem.get(..pem.len() - 30).unwrap();
        assert!(matches!(
            KeyPair::from_pem(cut.as_bytes()),
            Err(CryptoError::Unsupported(what)) if what == "a malformed PRIVATE KEY PEM block"
        ));
        let trailing = format!("{}junk\n", pem.as_str());
        assert!(matches!(
            KeyPair::from_pem(trailing.as_bytes()),
            Err(CryptoError::Unsupported(what)) if what == "a malformed PRIVATE KEY PEM block"
        ));
        // A PKCS#8 that isn't RSA (an Ed25519 key in PKCS#8).
        let ed = aws_lc_rs::signature::Ed25519KeyPair::generate().unwrap();
        let der =
            aws_lc_rs::encoding::AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&ed).unwrap();
        let foreign = pem_encode(PKCS8_LABEL, der.as_ref());
        assert!(matches!(
            KeyPair::from_pem(foreign.as_bytes()),
            Err(CryptoError::Unsupported(what)) if what == "a PKCS#8 key that isn't RSA"
        ));
    }

    #[test]
    fn rsa_under_3072_bits_is_refused() {
        let small = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        assert!(matches!(
            rsa(small),
            Err(CryptoError::Unsupported(what)) if what == "an RSA key of 2048 bits (3072 or 4096)"
        ));
    }

    #[test]
    fn a_pair_a_key_does_not_sign_with_is_refused_by_name() {
        let ed = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let refused = ed.sign(b"data", Some(Hash::Sha256)).unwrap_err();
        assert_eq!(
            refused.to_string(),
            "not supported: ed25519 with sha256",
            "{refused}"
        );
        let p256 = KeyPair::generate(KeyAlgorithm::P256).unwrap();
        for hash in [None, Some(Hash::Sha384), Some(Hash::Sha512)] {
            assert!(matches!(
                p256.sign(b"data", hash),
                Err(CryptoError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn a_signature_of_the_wrong_size_or_pair_is_refused() {
        assert!(matches!(
            RawSignature::new(KeyAlgorithm::Ed25519, None, vec![0; 63]),
            Err(CryptoError::BadSignature)
        ));
        assert!(matches!(
            RawSignature::new(KeyAlgorithm::P256, Some(Hash::Sha512), vec![0; 64]),
            Err(CryptoError::Unsupported(_))
        ));
        assert!(matches!(
            RawSignature::new(KeyAlgorithm::Rsa3072, None, vec![0; 384]),
            Err(CryptoError::Unsupported(_))
        ));
        assert!(matches!(
            RawSignature::new(KeyAlgorithm::Rsa4096, Some(Hash::Sha256), vec![0; 384]),
            Err(CryptoError::BadSignature)
        ));
        let rsa384 =
            RawSignature::new(KeyAlgorithm::Rsa3072, Some(Hash::Sha384), vec![1; 384]).unwrap();
        assert!(matches!(rsa384.to_ssh(), Err(CryptoError::Unsupported(_))));
    }

    #[test]
    fn ecdsa_halves_with_leading_zeros_survive_ssh_encoding() {
        let mut bytes = vec![0u8; 64];
        bytes[31] = 1; // r = 1
        bytes[32] = 0x80; // s with its high bit set
        let raw = RawSignature::new(KeyAlgorithm::P256, Some(Hash::Sha256), bytes).unwrap();
        let ssh = raw.to_ssh().unwrap();
        assert_eq!(ssh.as_bytes()[..5], [0, 0, 0, 1, 1]);
        assert_eq!(
            RawSignature::from_ssh(KeyAlgorithm::P256, &ssh).unwrap(),
            raw
        );
    }

    #[test]
    fn a_key_is_never_printed() {
        let key = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let printed = format!("{key:?}");
        assert!(
            printed.contains("Ed25519") && !printed.contains("PRIVATE"),
            "{printed}"
        );
    }
}
