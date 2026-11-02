//! The approval API's TLS key held elsewhere (the daemon's `Signer`): [`TlsKey`], what this
//! crate asks of it, the rustls signing key that asks it for each handshake signature, and
//! the self-signed certificate made by signing through it. The key never comes here.
//!
//! The key is ECDSA P-256; every signature is over SHA-256 of the message
//! (`ecdsa_secp256r1_sha256` in TLS 1.3, `ecdsa-with-SHA256` in the certificate).

use std::sync::Arc;

use rustls::SignatureScheme;
use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::pki_types::alg_id;
use rustls::sign::{Signer, SigningKey};

use crate::{CryptoError, Result};

/// The length of an uncompressed SEC1 P-256 point: `04 || x || y`.
pub const P256_POINT_LEN: usize = 65;

/// A P-256 key that signs elsewhere. Its signature is the raw `r || s` (64 bytes) of ECDSA
/// over SHA-256 of `message`.
pub trait TlsKey: Send + Sync + std::fmt::Debug {
    /// The public key, as an uncompressed SEC1 point ([`P256_POINT_LEN`] bytes).
    fn public_point(&self) -> &[u8];
    /// Signs `message`. Fails, never panics, when the key can't sign (a busy or stuck device).
    fn sign(&self, message: &[u8]) -> Result<[u8; 64]>;
}

/// The DER `ECDSA-Sig-Value` (`SEQUENCE { INTEGER r, INTEGER s }`) of a raw `r || s`: what
/// TLS and X.509 carry.
pub fn der_signature(raw: &[u8; 64]) -> Vec<u8> {
    let (r, s) = raw.split_at(32);
    let mut body = Vec::with_capacity(72);
    for half in [r, s] {
        // Minimal: no leading zero byte, unless the next byte's high bit would make it
        // negative. A half of all zeros is the single byte 0.
        let start = half.iter().position(|&b| b != 0).unwrap_or(31);
        let digits = half.get(start..).unwrap_or(&[0]);
        let pad = digits.first().is_some_and(|b| b & 0x80 != 0);
        let len = digits.len().saturating_add(usize::from(pad));
        body.push(0x02);
        // At most 33: one length byte.
        body.push(u8::try_from(len).unwrap_or(u8::MAX));
        if pad {
            body.push(0);
        }
        body.extend_from_slice(digits);
    }
    let mut der = Vec::with_capacity(body.len().saturating_add(2));
    der.push(0x30);
    // At most 70: one length byte.
    der.push(u8::try_from(body.len()).unwrap_or(u8::MAX));
    der.extend(body);
    der
}

/// The key's SubjectPublicKeyInfo (DER), as certificates and rustls hold it.
fn spki(key: &dyn TlsKey) -> Result<SubjectPublicKeyInfoDer<'static>> {
    let point = key.public_point();
    if point.len() != P256_POINT_LEN || point.first() != Some(&4) {
        return Err(CryptoError::Pem(
            "public key (not an uncompressed P-256 point)",
        ));
    }
    Ok(rustls::sign::public_key_to_spki(&alg_id::ECDSA_P256, point))
}

/// rustls's signing key for a [`TlsKey`].
#[derive(Debug)]
pub struct RemoteSigningKey(pub Arc<dyn TlsKey>);

impl SigningKey for RemoteSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(RemoteSigner(self.0.clone())) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        spki(&*self.0).ok()
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}

#[derive(Debug)]
struct RemoteSigner(Arc<dyn TlsKey>);

impl Signer for RemoteSigner {
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rustls::Error> {
        let raw = self.0.sign(message).map_err(|e| {
            // The handshake fails; the reason is the daemon's to log, never the key.
            rustls::Error::General(format!("the TLS key did not sign: {e}"))
        })?;
        Ok(der_signature(&raw))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

/// rcgen's view of a [`TlsKey`], to sign a certificate.
struct CertificateKey<'a>(&'a dyn TlsKey);

impl rcgen::PublicKeyData for CertificateKey<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.0.public_point()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for CertificateKey<'_> {
    fn sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        let raw = self.0.sign(msg).map_err(|_| rcgen::Error::RemoteKeyError)?;
        Ok(der_signature(&raw))
    }
}

/// A self-signed certificate (PEM) for the approval API, signed through `key`.
pub fn self_signed(key: &dyn TlsKey) -> Result<String> {
    spki(key)?;
    let params = rcgen::CertificateParams::new(vec!["writd".to_owned()])?;
    Ok(params.self_signed(&CertificateKey(key))?.pem())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_signatures_are_minimal_integers() {
        let mut raw = [0u8; 64];
        raw[31] = 1; // r = 1
        raw[32] = 0x80; // s has its high bit set: a zero byte in front
        assert_eq!(
            der_signature(&raw)[..7],
            [0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21]
        );
        assert_eq!(der_signature(&raw)[7], 0);
        assert_eq!(der_signature(&raw).len(), 2 + 3 + 2 + 33);
        // A zero half is one zero byte; the largest is 33 bytes.
        let zero = [0u8; 64];
        assert_eq!(
            der_signature(&zero),
            [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]
        );
        let full = [0xffu8; 64];
        let der = der_signature(&full);
        assert_eq!(der.len(), 2 + 2 * (2 + 33));
        assert_eq!(der[1] as usize, der.len() - 2);
    }
}
