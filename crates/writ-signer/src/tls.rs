//! The HTTPS approval API's TLS key behind a [`Signer`]: [`TlsSigner`], what rustls signs
//! each handshake through (`writ_crypto::tls::remote::TlsKey`), and what signs the
//! self-signed certificate. The key stays in the signer; this asks it for an SSH signature
//! and hands back its raw `r || s`.

use std::sync::Arc;

use writ_core::names::KeyId;
use writ_crypto::CryptoError;
use writ_crypto::ssh_key::public::EcdsaPublicKey;
use writ_crypto::ssh_key::{Algorithm, EcdsaCurve, Signature};
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
                    algorithm: format!("{} (the TLS key is P-256)", public.algorithm()),
                    id,
                });
            }
        };
        if point.len() != P256_POINT_LEN {
            return Err(SignerError::Unsupported {
                algorithm: "a compressed P-256 point".to_owned(),
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
        let signature = self.signer.sign(&self.id, message).map_err(|e| {
            tracing::warn!(key = %self.id, error = %e, "the TLS key did not sign");
            CryptoError::SigningFailed
        })?;
        ecdsa_p256_raw(&signature).ok_or(CryptoError::SigningFailed)
    }
}

/// The raw `r || s` of an `ecdsa-sha2-nistp256` SSH signature, whose blob is `mpint r`,
/// `mpint s` and nothing else. `None` for anything else.
pub fn ecdsa_p256_raw(signature: &Signature) -> Option<[u8; 64]> {
    if signature.algorithm()
        != (Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        })
    {
        return None;
    }
    let mut rest = signature.as_bytes();
    let mut raw = [0u8; 64];
    for half in raw.chunks_mut(32) {
        let (len, after) = rest.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
        let digits = after.get(..len)?;
        rest = after.get(len..)?;
        // An mpint: big-endian, a zero byte in front when the high bit is set.
        let digits = match digits.split_first() {
            Some((0, tail)) => tail,
            _ => digits,
        };
        let start = half.len().checked_sub(digits.len())?;
        half.get_mut(start..)?.copy_from_slice(digits);
    }
    rest.is_empty().then_some(raw)
}

#[cfg(test)]
mod tests {
    use writ_crypto::keys::{KeyKind, generate};

    use super::*;
    use crate::software::SoftwareSigner;

    fn signer(kind: KeyKind) -> Arc<dyn Signer> {
        let key = generate(kind).unwrap();
        Arc::new(SoftwareSigner::new([("tls-01".parse().unwrap(), key)]).unwrap())
    }

    #[test]
    fn a_tls_key_is_p256_and_signs_raw_halves_that_verify() {
        let tls = TlsSigner::new(signer(KeyKind::P256), "tls-01".parse().unwrap()).unwrap();
        assert_eq!(tls.public_point().len(), P256_POINT_LEN);
        assert_eq!(format!("{tls:?}"), "TlsSigner { id: KeyId(\"tls-01\") }");
        // A certificate signed through it, then served: rustls checks the key matches it.
        let pem = writ_crypto::tls::remote::self_signed(&tls).unwrap();
        let identity = writ_crypto::tls::TlsIdentity::with_key(&pem, Arc::new(tls)).unwrap();
        assert!(identity.fingerprint().starts_with("SHA256:"));

        // A certificate of another key: refused, so a replaced certificate never serves.
        let other = TlsSigner::new(signer(KeyKind::P256), "tls-01".parse().unwrap()).unwrap();
        let foreign = writ_crypto::tls::remote::self_signed(&other).unwrap();
        let mine = TlsSigner::new(signer(KeyKind::P256), "tls-01".parse().unwrap()).unwrap();
        assert!(matches!(
            writ_crypto::tls::TlsIdentity::with_key(&foreign, Arc::new(mine)),
            Err(CryptoError::Tls(rustls::Error::InconsistentKeys(_)))
        ));

        let ed25519 = TlsSigner::new(signer(KeyKind::Ed25519), "tls-01".parse().unwrap());
        assert!(
            matches!(&ed25519, Err(SignerError::Unsupported { algorithm, .. }) if algorithm.ends_with("(the TLS key is P-256)")),
            "{ed25519:?}"
        );
        let unknown = TlsSigner::new(signer(KeyKind::P256), "tls-02".parse().unwrap());
        assert!(
            matches!(unknown, Err(SignerError::UnknownKey(_))),
            "{unknown:?}"
        );
    }

    #[test]
    fn only_a_well_formed_p256_signature_gives_halves() {
        let key = generate(KeyKind::P256).unwrap();
        let signed = signature::Signer::try_sign(&key, b"message").unwrap();
        let raw = ecdsa_p256_raw(&signed).unwrap();
        assert_ne!(raw, [0u8; 64]);
        // Cut short, or with bytes after: refused.
        let blob = signed.as_bytes();
        for bad in [
            &blob[..blob.len() - 1],
            &[blob, &[0][..]].concat()[..],
            &[][..],
        ] {
            let forged = Signature::new(signed.algorithm(), bad.to_vec());
            if let Ok(forged) = forged {
                assert_eq!(ecdsa_p256_raw(&forged), None);
            }
        }
        // Another algorithm.
        let ed = generate(KeyKind::Ed25519).unwrap();
        let other = signature::Signer::try_sign(&ed, b"message").unwrap();
        assert_eq!(ecdsa_p256_raw(&other), None);
    }
}
