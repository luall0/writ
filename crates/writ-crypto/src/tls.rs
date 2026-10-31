//! The HTTPS approval API's TLS: a self-signed certificate, which clients pin by its SHA-256
//! fingerprint (no certificate authority is trusted, like the pinned SSH host key). Both sides
//! are configured here, the same way: rustls with the ring provider, TLS 1.3 only, ALPN
//! `http/1.1`.
//!
//! - the daemon: [`TlsIdentity`], its certificate and key as a server configuration;
//! - clients: [`pinned_client_config`], which accepts exactly the pinned certificate.

use std::sync::Arc;

use base64ct::{Base64Unpadded, Encoding};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{CryptoError, Result};

/// The only application protocol spoken over the approval API's TLS.
const ALPN: &[u8] = b"http/1.1";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

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
        .map_err(CryptoError::CertificateGeneration)?;
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

/// The approval API's TLS server configuration (certificate and key), and the fingerprint
/// clients pin.
///
/// The private key is moved straight into rustls when the identity is made: no other copy is
/// kept (rustls holds it for the daemon's life, without zeroizing it: see the threat model's
/// residual risks).
pub struct TlsIdentity {
    config: Arc<rustls::ServerConfig>,
    fingerprint: String,
}

impl std::fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIdentity")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl TlsIdentity {
    /// Reads a PEM certificate and its PEM private key.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let cert = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|_| CryptoError::Pem("certificate"))?;
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .map_err(|_| CryptoError::Pem("private key"))?;
        let fingerprint = fingerprint(&cert);
        let mut config = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        Ok(Self {
            config: Arc::new(config),
            fingerprint,
        })
    }

    /// The pin clients check: `SHA256:<base64>` of the certificate.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The server configuration, for a TLS acceptor.
    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        self.config.clone()
    }
}

/// A client configuration that accepts exactly the certificate pinned as `fingerprint`
/// (`SHA256:<base64>`), and checks that the server holds its key. No certificate authority,
/// host name or expiry is trusted or checked: the pin is the whole identity.
pub fn pinned_client_config(fingerprint: &str) -> Result<rustls::ClientConfig> {
    let provider = provider();
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            fingerprint: fingerprint.to_owned(),
            provider,
        }))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(config)
}

/// Accepts exactly the pinned certificate, and checks that the server holds its key.
#[derive(Debug)]
struct Pinned {
    fingerprint: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if fingerprint(end_entity) == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "the daemon's certificate doesn't match the pinned fingerprint".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
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

    #[test]
    fn an_identity_reads_its_pem_and_pins_its_certificate() {
        let generated = generate_self_signed().unwrap();
        let identity = TlsIdentity::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
        let der = CertificateDer::from_pem_slice(generated.cert_pem.as_bytes()).unwrap();
        assert_eq!(identity.fingerprint(), fingerprint(&der));
        assert_eq!(identity.server_config().alpn_protocols, vec![ALPN.to_vec()]);
        assert!(!format!("{identity:?}").contains("PRIVATE"));
        let other = generate_self_signed().unwrap();
        assert!(TlsIdentity::from_pem(&generated.cert_pem, "not a key").is_err());
        assert!(TlsIdentity::from_pem("not a cert", &generated.key_pem).is_err());
        // A key that isn't the certificate's.
        assert!(TlsIdentity::from_pem(&generated.cert_pem, &other.key_pem).is_err());
        assert!(pinned_client_config(identity.fingerprint()).is_ok());
    }
}
