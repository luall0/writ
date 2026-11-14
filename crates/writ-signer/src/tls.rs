//! The HTTPS approval API's TLS key behind a [`Signer`]: [`TlsSigner`], what rustls signs
//! each handshake through (`writ_crypto::tls::remote::TlsKey`), and what signs the
//! self-signed certificate. The key stays in the signer; this asks it for a P-256 signature
//! with SHA-256 and hands back its raw `r || s`.

use std::sync::Arc;

use writ_core::names::KeyId;
use writ_crypto::CryptoError;
use writ_crypto::algorithm::{Hash, KeyAlgorithm};
use writ_crypto::keypair::RawSignature;
use writ_crypto::ssh_key::public::EcdsaPublicKey;
use writ_crypto::tls::remote::{P256_POINT_LEN, TlsKey};

use crate::{Signer, SignerError, public_key};

/// A P-256 key of a [`Signer`], as the approval API's TLS key.
pub struct TlsSigner {
    signer: Arc<dyn Signer>,
    id: KeyId,
    point: Vec<u8>,
}

impl std::fmt::Debug for TlsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsSigner").field("id", &self.id).finish()
    }
}

impl TlsSigner {
    /// The signer's key `id`, which must be ECDSA P-256.
    pub fn new(signer: Arc<dyn Signer>, id: KeyId) -> Result<Self, SignerError> {
        let public = public_key(&*signer, &id)?;
        let point = match public.key_data().ecdsa() {
            Some(EcdsaPublicKey::NistP256(point)) => point.as_bytes().to_vec(),
            _ => {
                return Err(SignerError::Unsupported {
                    what: format!("a {} TLS key (the TLS key is P-256)", public.algorithm()),
                    id,
                });
            }
        };
        if point.len() != P256_POINT_LEN {
            return Err(SignerError::Unsupported {
                what: "a compressed P-256 point".to_owned(),
                id,
            });
        }
        Ok(Self { signer, id, point })
    }
}

impl TlsKey for TlsSigner {
    fn public_point(&self) -> &[u8] {
        &self.point
    }

    fn sign(&self, message: &[u8]) -> writ_crypto::Result<[u8; 64]> {
        let signature = self
            .signer
            .sign(&self.id, message, Some(Hash::Sha256))
            .map_err(|e| {
                // A key refused when it was opened is said once, at start: never a line per
                // handshake, which anyone reaching the listener could flood.
                if !matches!(e, crate::SignerError::Unusable(_)) {
                    tracing::warn!(key = %self.id, error = %e, "the TLS key did not sign");
                }
                CryptoError::SigningFailed
            })?;
        ecdsa_p256_raw(&signature).ok_or(CryptoError::SigningFailed)
    }
}

/// The raw `r || s` of a P-256 signature made with SHA-256. `None` for anything else.
pub fn ecdsa_p256_raw(signature: &RawSignature) -> Option<[u8; 64]> {
    if (signature.algorithm(), signature.hash()) != (KeyAlgorithm::P256, Some(Hash::Sha256)) {
        return None;
    }
    signature.as_bytes().try_into().ok()
}

#[cfg(test)]
mod tests {
    use writ_crypto::keypair::KeyPair;
    use writ_crypto::ssh_key::Signature;

    use super::*;
    use crate::software::SoftwareSigner;

    fn signer(algorithm: KeyAlgorithm) -> Arc<dyn Signer> {
        let key = KeyPair::generate(algorithm).unwrap();
        Arc::new(SoftwareSigner::new([("tls-01".parse().unwrap(), key)]).unwrap())
    }

    #[test]
    fn a_tls_key_is_p256_and_signs_raw_halves_that_verify() {
        let tls = TlsSigner::new(signer(KeyAlgorithm::P256), "tls-01".parse().unwrap()).unwrap();
        assert_eq!(tls.public_point().len(), P256_POINT_LEN);
        assert_eq!(format!("{tls:?}"), "TlsSigner { id: KeyId(\"tls-01\") }");
        // A certificate signed through it, then served: rustls checks the key matches it.
        let pem = writ_crypto::tls::remote::self_signed(&tls).unwrap();
        let identity = writ_crypto::tls::TlsIdentity::with_key(&pem, Arc::new(tls)).unwrap();
        assert!(identity.fingerprint().starts_with("SHA256:"));

        // A certificate of another key: refused, so a replaced certificate never serves.
        let other = TlsSigner::new(signer(KeyAlgorithm::P256), "tls-01".parse().unwrap()).unwrap();
        let foreign = writ_crypto::tls::remote::self_signed(&other).unwrap();
        let mine = TlsSigner::new(signer(KeyAlgorithm::P256), "tls-01".parse().unwrap()).unwrap();
        assert!(matches!(
            writ_crypto::tls::TlsIdentity::with_key(&foreign, Arc::new(mine)),
            Err(CryptoError::Tls(rustls::Error::InconsistentKeys(_)))
        ));

        for wrong in [KeyAlgorithm::Ed25519, KeyAlgorithm::P384] {
            let refused = TlsSigner::new(signer(wrong), "tls-01".parse().unwrap());
            assert!(
                matches!(&refused, Err(SignerError::Unsupported { what, .. }) if what.ends_with("(the TLS key is P-256)")),
                "{refused:?}"
            );
        }
        let unknown = TlsSigner::new(signer(KeyAlgorithm::P256), "tls-02".parse().unwrap());
        assert!(
            matches!(unknown, Err(SignerError::UnknownKey(_))),
            "{unknown:?}"
        );
    }

    #[test]
    fn only_a_well_formed_p256_signature_gives_halves() {
        let key = KeyPair::generate(KeyAlgorithm::P256).unwrap();
        let signed = key.sign(b"message", Some(Hash::Sha256)).unwrap();
        let raw = ecdsa_p256_raw(&signed).unwrap();
        assert_ne!(raw, [0u8; 64]);
        // An SSH blob cut short, or with bytes after: never a signature.
        let ssh = signed.to_ssh().unwrap();
        let blob = ssh.as_bytes();
        for bad in [
            &blob[..blob.len() - 1],
            &[blob, &[0][..]].concat()[..],
            &[][..],
        ] {
            if let Ok(forged) = Signature::new(ssh.algorithm(), bad.to_vec()) {
                assert!(matches!(
                    RawSignature::from_ssh(KeyAlgorithm::P256, &forged),
                    Err(CryptoError::BadSignature)
                ));
            }
        }
        // Another algorithm.
        for other in [KeyAlgorithm::Ed25519, KeyAlgorithm::P384] {
            let key = KeyPair::generate(other).unwrap();
            let hash = writ_crypto::algorithm::signer_hash(
                writ_crypto::algorithm::SignatureFormat::Ssh,
                other,
                Hash::Sha512,
            );
            assert_eq!(ecdsa_p256_raw(&key.sign(b"message", hash).unwrap()), None);
        }
    }
}
