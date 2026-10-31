//! The HTTPS approval API's TLS identity: a self-signed certificate, which clients pin by its
//! SHA-256 fingerprint (no certificate authority is trusted, like the pinned SSH host key).

use base64ct::{Base64Unpadded, Encoding};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// A freshly generated certificate and its private key, both PEM.
pub struct SelfSigned {
    pub cert_pem: String,
    /// The private key: zeroized on drop, never printed.
    pub key_pem: Zeroizing<String>,
}

impl std::fmt::Debug for SelfSigned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelfSigned")
            .field("cert_pem", &self.cert_pem)
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// Generates a self-signed certificate (ECDSA P-256) for the approval API.
pub fn generate_self_signed() -> Result<SelfSigned> {
    let certified = rcgen::generate_simple_self_signed(vec!["writd".to_owned()])
        .map_err(|e| Error::Tls(format!("cannot generate the TLS certificate: {e}")))?;
    Ok(SelfSigned {
        cert_pem: certified.cert.pem(),
        key_pem: Zeroizing::new(certified.signing_key.serialize_pem()),
    })
}

/// The pin of a certificate: `SHA256:` and the unpadded base64 of the SHA-256 of its DER
/// bytes (the format of SSH key fingerprints).
pub fn fingerprint(cert_der: &[u8]) -> String {
    format!(
        "SHA256:{}",
        Base64Unpadded::encode_string(&Sha256::digest(cert_der))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_distinct_certificates_with_stable_pins() {
        let a = generate_self_signed().unwrap();
        let b = generate_self_signed().unwrap();
        assert!(a.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(a.key_pem.contains("PRIVATE KEY"));
        assert_ne!(a.cert_pem, b.cert_pem);
        assert!(!format!("{a:?}").contains("PRIVATE KEY"));
        let pin = fingerprint(b"some der bytes");
        assert_eq!(pin, fingerprint(b"some der bytes"));
        assert!(pin.starts_with("SHA256:") && pin.len() == 7 + 43, "{pin}");
        assert_ne!(pin, fingerprint(b"other der bytes"));
    }
}
