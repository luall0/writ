//! What a signing key is: its algorithm, the hash it signs with, and the signature format it
//! signs in, and the table of what goes together
//! (`docs/architecture/signer.md#formats-algorithms-and-hashes`).
//!
//! Two hashes are at play. The **format's hash** is the one a key is declared with: the
//! SSHSIG message hash (`ssh`), or the digest an OpenPGP signature covers (`openpgp`). The
//! **signer's hash** is what [`crate::keypair::KeyPair::sign`] and a `Signer` backend are
//! asked for: `None` for Ed25519, which signs the bytes themselves; the curve's own hash for
//! ECDSA (in both formats: P-256 with SHA-256, P-384 with SHA-384); the declared hash for
//! RSA (PKCS#1 v1.5, never SHA-1). [`signer_hash`] maps one to the other.

use std::fmt;
use std::str::FromStr;

/// A signing key's algorithm. RSA under 3072 bits is refused (about 112-bit security,
/// deprecated after 2030), and so are the others Writ doesn't sign with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyAlgorithm {
    Ed25519,
    P256,
    P384,
    Rsa3072,
    Rsa4096,
}

impl KeyAlgorithm {
    /// Every algorithm, in the order the documentation lists them.
    pub const ALL: [KeyAlgorithm; 5] = [
        KeyAlgorithm::Ed25519,
        KeyAlgorithm::P256,
        KeyAlgorithm::P384,
        KeyAlgorithm::Rsa3072,
        KeyAlgorithm::Rsa4096,
    ];

    /// Its name in configuration (`ed25519`, `p256`, `p384`, `rsa3072`, `rsa4096`).
    pub fn name(self) -> &'static str {
        match self {
            KeyAlgorithm::Ed25519 => "ed25519",
            KeyAlgorithm::P256 => "p256",
            KeyAlgorithm::P384 => "p384",
            KeyAlgorithm::Rsa3072 => "rsa3072",
            KeyAlgorithm::Rsa4096 => "rsa4096",
        }
    }

    /// Whether it is RSA.
    pub fn is_rsa(self) -> bool {
        matches!(self, KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096)
    }

    /// An RSA modulus's size in bytes (its signatures have that size), or none.
    pub fn rsa_modulus_len(self) -> Option<usize> {
        match self {
            KeyAlgorithm::Rsa3072 => Some(384),
            KeyAlgorithm::Rsa4096 => Some(512),
            _ => None,
        }
    }

    /// The algorithm of an SSH public key, if Writ signs with it (an RSA key by its modulus
    /// size: 3072 or 4096 bits).
    pub fn of_public(key: &ssh_key::public::KeyData) -> Option<Self> {
        use ssh_key::public::{EcdsaPublicKey, KeyData};
        match key {
            KeyData::Ed25519(_) => Some(KeyAlgorithm::Ed25519),
            KeyData::Ecdsa(EcdsaPublicKey::NistP256(_)) => Some(KeyAlgorithm::P256),
            KeyData::Ecdsa(EcdsaPublicKey::NistP384(_)) => Some(KeyAlgorithm::P384),
            KeyData::Rsa(rsa) => {
                // The modulus as an mpint may carry one leading zero byte.
                let n = rsa.n().as_bytes();
                let n = match n.split_first() {
                    Some((0, rest)) => rest,
                    _ => n,
                };
                match n.len() {
                    384 => Some(KeyAlgorithm::Rsa3072),
                    512 => Some(KeyAlgorithm::Rsa4096),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a name is not one of the accepted values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{value:?} is not {what}: expected one of {expected}")]
pub struct UnknownName {
    pub what: &'static str,
    pub value: String,
    pub expected: &'static str,
}

impl FromStr for KeyAlgorithm {
    type Err = UnknownName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let expected = "ed25519, p256, p384, rsa3072, rsa4096";
        match s {
            "ed25519" => Ok(KeyAlgorithm::Ed25519),
            "p256" => Ok(KeyAlgorithm::P256),
            "p384" => Ok(KeyAlgorithm::P384),
            "rsa3072" => Ok(KeyAlgorithm::Rsa3072),
            "rsa4096" => Ok(KeyAlgorithm::Rsa4096),
            "rsa2048" | "rsa" => Err(UnknownName {
                what: "an accepted key algorithm (RSA keys are 3072 or 4096 bits: 2048 is about \
                       112-bit security, deprecated after 2030)",
                value: s.to_owned(),
                expected,
            }),
            _ => Err(UnknownName {
                what: "a key algorithm",
                value: s.to_owned(),
                expected,
            }),
        }
    }
}

/// A hash a signature is made with. Nothing under SHA-256 exists to choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    /// Its name in configuration (`sha256`, `sha384`, `sha512`).
    pub fn name(self) -> &'static str {
        match self {
            Hash::Sha256 => "sha256",
            Hash::Sha384 => "sha384",
            Hash::Sha512 => "sha512",
        }
    }

    /// The digest of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Hash::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Hash::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Hash::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Hash {
    type Err = UnknownName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha256" => Ok(Hash::Sha256),
            "sha384" => Ok(Hash::Sha384),
            "sha512" => Ok(Hash::Sha512),
            _ => Err(UnknownName {
                what: "a hash (nothing under SHA-256 is offered)",
                value: s.to_owned(),
                expected: "sha256, sha384, sha512",
            }),
        }
    }
}

/// What a signer is asked to hash with: `None` when the algorithm signs the bytes themselves
/// (Ed25519).
pub type SignerHash = Option<Hash>;

/// The way a signature is written for git: `gpg.format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureFormat {
    /// An SSHSIG in namespace `git` (`gpg.format = ssh`).
    Ssh,
    /// An OpenPGP v4 detached signature (`gpg.format = openpgp`).
    Openpgp,
}

impl SignatureFormat {
    pub const ALL: [SignatureFormat; 2] = [SignatureFormat::Ssh, SignatureFormat::Openpgp];

    /// Its name in configuration and on the wire (`ssh`, `openpgp`).
    pub fn name(self) -> &'static str {
        match self {
            SignatureFormat::Ssh => "ssh",
            SignatureFormat::Openpgp => "openpgp",
        }
    }
}

impl fmt::Display for SignatureFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for SignatureFormat {
    type Err = UnknownName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ssh" => Ok(SignatureFormat::Ssh),
            "openpgp" => Ok(SignatureFormat::Openpgp),
            _ => Err(UnknownName {
                what: "a signature format (x509 is not supported)",
                value: s.to_owned(),
                expected: "ssh, openpgp",
            }),
        }
    }
}

/// The format's hashes a key of `algorithm` may be declared with in `format`, weakest first.
/// Empty when the format doesn't take the algorithm (none today: both take every one).
pub fn hashes(format: SignatureFormat, algorithm: KeyAlgorithm) -> &'static [Hash] {
    use KeyAlgorithm::*;
    match (format, algorithm) {
        // The SSHSIG message hash: OpenSSH knows these two.
        (SignatureFormat::Ssh, _) => &[Hash::Sha256, Hash::Sha512],
        // ECDSA with its curve's own hash only (RFC 6637's pairing).
        (SignatureFormat::Openpgp, P256) => &[Hash::Sha256],
        (SignatureFormat::Openpgp, P384) => &[Hash::Sha384],
        (SignatureFormat::Openpgp, Ed25519 | Rsa3072 | Rsa4096) => {
            &[Hash::Sha256, Hash::Sha384, Hash::Sha512]
        }
    }
}

/// What the signer is asked to hash with, for a key of `algorithm` declared with the format's
/// `hash` in `format`: `None` for Ed25519 (it signs the SSHSIG's data, or the OpenPGP digest,
/// itself), the curve's hash for ECDSA, the declared hash for RSA. `None` too when the
/// combination is not in [`hashes`]; [`check`] refuses it first.
pub fn signer_hash(format: SignatureFormat, algorithm: KeyAlgorithm, hash: Hash) -> SignerHash {
    match algorithm {
        KeyAlgorithm::Ed25519 => None,
        KeyAlgorithm::P256 => Some(Hash::Sha256),
        KeyAlgorithm::P384 => Some(Hash::Sha384),
        KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
            hashes(format, algorithm).contains(&hash).then_some(hash)
        }
    }
}

/// Why a declared combination is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("{format} does not take {algorithm} keys")]
    Algorithm {
        format: SignatureFormat,
        algorithm: KeyAlgorithm,
    },
    #[error("{format} signs {algorithm} keys with {allowed}, not {hash}")]
    Hash {
        format: SignatureFormat,
        algorithm: KeyAlgorithm,
        hash: Hash,
        allowed: String,
    },
    #[error(
        "the {backend} backend can't sign with {algorithm}{}",
        signer_hash.map(|h| format!(" and {h}")).unwrap_or_default()
    )]
    Backend {
        backend: String,
        algorithm: KeyAlgorithm,
        signer_hash: SignerHash,
    },
    #[error("the {backend} backend can't sign {algorithm} in {format} with any of {allowed}")]
    NoHash {
        backend: String,
        format: SignatureFormat,
        algorithm: KeyAlgorithm,
        allowed: String,
    },
}

/// The names of `hashes`, for a message.
fn names(hashes: &[Hash]) -> String {
    hashes
        .iter()
        .map(|h| h.name())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Checks a declared key: its format takes its algorithm, its hash (when set) is one the
/// format allows for it, and `supports` (the backend's (algorithm, signer hash) pairs, named
/// `backend` in errors) can sign with what that asks. Answers the hash to use: the one set,
/// or, left out, the strongest the format, algorithm and backend allow. Never adjusts a hash
/// that was set.
pub fn check(
    format: SignatureFormat,
    algorithm: KeyAlgorithm,
    hash: Option<Hash>,
    backend: &str,
    supports: &[(KeyAlgorithm, SignerHash)],
) -> Result<Hash, Refused> {
    let allowed = hashes(format, algorithm);
    if allowed.is_empty() {
        return Err(Refused::Algorithm { format, algorithm });
    }
    let backend_can = |h: Hash| supports.contains(&(algorithm, signer_hash(format, algorithm, h)));
    match hash {
        Some(hash) => {
            if !allowed.contains(&hash) {
                return Err(Refused::Hash {
                    format,
                    algorithm,
                    hash,
                    allowed: names(allowed),
                });
            }
            if !backend_can(hash) {
                return Err(Refused::Backend {
                    backend: backend.to_owned(),
                    algorithm,
                    signer_hash: signer_hash(format, algorithm, hash),
                });
            }
            Ok(hash)
        }
        None => allowed
            .iter()
            .rev()
            .copied()
            .find(|&h| backend_can(h))
            .ok_or_else(|| {
                if supports.iter().any(|(a, _)| *a == algorithm) {
                    Refused::NoHash {
                        backend: backend.to_owned(),
                        format,
                        algorithm,
                        allowed: names(allowed),
                    }
                } else {
                    Refused::Backend {
                        backend: backend.to_owned(),
                        algorithm,
                        signer_hash: None,
                    }
                }
            }),
    }
}

/// The (algorithm, signer hash) pairs a backend that signs everything Writ knows supports:
/// Ed25519 pure, ECDSA with its curve's hash, RSA with each SHA-2.
pub fn every_pair() -> Vec<(KeyAlgorithm, SignerHash)> {
    let mut pairs = vec![
        (KeyAlgorithm::Ed25519, None),
        (KeyAlgorithm::P256, Some(Hash::Sha256)),
        (KeyAlgorithm::P384, Some(Hash::Sha384)),
    ];
    for rsa in [KeyAlgorithm::Rsa3072, KeyAlgorithm::Rsa4096] {
        for hash in [Hash::Sha256, Hash::Sha384, Hash::Sha512] {
            pairs.push((rsa, Some(hash)));
        }
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_unknown_ones_are_refused_by_name() {
        for algorithm in KeyAlgorithm::ALL {
            assert_eq!(algorithm.name().parse::<KeyAlgorithm>(), Ok(algorithm));
        }
        for hash in [Hash::Sha256, Hash::Sha384, Hash::Sha512] {
            assert_eq!(hash.name().parse::<Hash>(), Ok(hash));
        }
        for format in SignatureFormat::ALL {
            assert_eq!(format.name().parse::<SignatureFormat>(), Ok(format));
        }
        let rsa2048 = "rsa2048".parse::<KeyAlgorithm>().unwrap_err().to_string();
        assert!(rsa2048.contains("3072 or 4096"), "{rsa2048}");
        assert_eq!(
            "sha1".parse::<Hash>().unwrap_err().to_string(),
            "\"sha1\" is not a hash (nothing under SHA-256 is offered): expected one of \
             sha256, sha384, sha512"
        );
        assert_eq!("x509".parse::<SignatureFormat>().unwrap_err().value, "x509");
        assert_eq!(
            "Ed25519".parse::<KeyAlgorithm>().unwrap_err().what,
            "a key algorithm",
            "names are exact"
        );
    }

    #[test]
    fn left_out_the_hash_is_the_strongest_the_combination_allows() {
        use KeyAlgorithm::*;
        use SignatureFormat::*;
        let all = every_pair();
        let expected = [
            (Ssh, Ed25519, Hash::Sha512),
            (Ssh, P256, Hash::Sha512),
            (Ssh, P384, Hash::Sha512),
            (Ssh, Rsa3072, Hash::Sha512),
            (Ssh, Rsa4096, Hash::Sha512),
            (Openpgp, Ed25519, Hash::Sha512),
            (Openpgp, P256, Hash::Sha256),
            (Openpgp, P384, Hash::Sha384),
            (Openpgp, Rsa3072, Hash::Sha512),
            (Openpgp, Rsa4096, Hash::Sha512),
        ];
        for (format, algorithm, hash) in expected {
            assert_eq!(
                check(format, algorithm, None, "software", &all),
                Ok(hash),
                "{format} {algorithm}"
            );
        }
        // A backend that signs RSA with SHA-256 only: the strongest it allows.
        let limited = [(Rsa3072, Some(Hash::Sha256))];
        assert_eq!(
            check(Openpgp, Rsa3072, None, "limited", &limited),
            Ok(Hash::Sha256)
        );
        assert_eq!(
            check(Ssh, Rsa3072, None, "limited", &limited),
            Ok(Hash::Sha256)
        );
    }

    #[test]
    fn a_hash_set_is_checked_never_adjusted() {
        use KeyAlgorithm::*;
        use SignatureFormat::*;
        let all = every_pair();
        assert_eq!(
            check(Ssh, Ed25519, Some(Hash::Sha256), "software", &all),
            Ok(Hash::Sha256)
        );
        assert_eq!(
            check(Ssh, P256, Some(Hash::Sha384), "software", &all),
            Err(Refused::Hash {
                format: Ssh,
                algorithm: P256,
                hash: Hash::Sha384,
                allowed: "sha256, sha512".to_owned()
            })
        );
        assert_eq!(
            check(Openpgp, P256, Some(Hash::Sha512), "software", &all),
            Err(Refused::Hash {
                format: Openpgp,
                algorithm: P256,
                hash: Hash::Sha512,
                allowed: "sha256".to_owned()
            })
        );
        // Backend × hash: an ssh-agent signs P-256 with SHA-256 only, and RSA with SHA-512.
        let agent = [(P256, Some(Hash::Sha256)), (Rsa4096, Some(Hash::Sha512))];
        assert_eq!(
            check(Openpgp, Rsa4096, Some(Hash::Sha384), "ssh-agent", &agent),
            Err(Refused::Backend {
                backend: "ssh-agent".to_owned(),
                algorithm: Rsa4096,
                signer_hash: Some(Hash::Sha384)
            })
        );
        // Backend × algorithm: a Secure Enclave signs P-256 only.
        let enclave = [(P256, Some(Hash::Sha256))];
        let refused = check(Ssh, Ed25519, None, "se-cryptokit", &enclave).unwrap_err();
        assert_eq!(
            refused,
            Refused::Backend {
                backend: "se-cryptokit".to_owned(),
                algorithm: Ed25519,
                signer_hash: None
            }
        );
        assert_eq!(
            refused.to_string(),
            "the se-cryptokit backend can't sign with ed25519"
        );
        // A backend that holds the algorithm but signs it with no hash the format allows.
        assert_eq!(
            check(Openpgp, Rsa4096, None, "ssh-agent", &[(Rsa4096, None)]),
            Err(Refused::NoHash {
                backend: "ssh-agent".to_owned(),
                format: Openpgp,
                algorithm: Rsa4096,
                allowed: "sha256, sha384, sha512".to_owned()
            })
        );
    }

    #[test]
    fn the_signer_hash_follows_the_algorithm() {
        use KeyAlgorithm::*;
        use SignatureFormat::*;
        assert_eq!(signer_hash(Ssh, Ed25519, Hash::Sha512), None);
        assert_eq!(signer_hash(Openpgp, Ed25519, Hash::Sha256), None);
        assert_eq!(signer_hash(Ssh, P256, Hash::Sha512), Some(Hash::Sha256));
        assert_eq!(signer_hash(Ssh, P384, Hash::Sha256), Some(Hash::Sha384));
        assert_eq!(signer_hash(Ssh, Rsa3072, Hash::Sha256), Some(Hash::Sha256));
        assert_eq!(
            signer_hash(Openpgp, Rsa4096, Hash::Sha384),
            Some(Hash::Sha384)
        );
        assert_eq!(
            signer_hash(Ssh, Rsa4096, Hash::Sha384),
            None,
            "not an SSH pair"
        );
    }
}
