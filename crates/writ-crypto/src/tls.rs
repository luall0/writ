//! The HTTPS approval API's TLS: a self-signed certificate, which clients pin by its SHA-256
//! fingerprint (no certificate authority is trusted, like the pinned SSH host key), and a
//! client certificate made from a reader key, which the daemon checks against its `readers`
//! file (mutual TLS: only readers reach the API, as over SSH). Both sides are configured
//! here, the same way: rustls with the ring provider, TLS 1.3 only, ALPN `http/1.1`.
//!
//! - the daemon: [`TlsIdentity`], its certificate and key, as a server configuration that
//!   requires a reader's client certificate ([`TlsIdentity::server_config`]);
//! - clients: [`pinned_client_config`], which accepts exactly the pinned certificate and
//!   presents the reader key's certificate.

use std::sync::Arc;

use base64ct::{Base64Unpadded, Encoding};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use sha2::{Digest, Sha256};
use ssh_key::PrivateKey;
use zeroize::Zeroizing;

use crate::readers::Reader;
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

/// The approval API's TLS certificate and key, and the fingerprint clients pin.
///
/// The private key is moved straight into rustls when the identity is made: no other copy is
/// kept (rustls holds it for the daemon's life, without zeroizing it: see the threat model's
/// residual risks).
pub struct TlsIdentity {
    certified: Arc<CertifiedKey>,
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
    /// Reads a PEM certificate and its PEM private key (which must be the certificate's).
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let cert = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|_| CryptoError::Pem("certificate"))?;
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .map_err(|_| CryptoError::Pem("private key"))?;
        let fingerprint = fingerprint(&cert);
        let certified =
            CertifiedKey::new(vec![cert], provider().key_provider.load_private_key(key)?);
        // Unlike `from_der`, an unknown consistency is refused too.
        certified.keys_match()?;
        Ok(Self {
            certified: Arc::new(certified),
            fingerprint,
        })
    }

    /// The pin clients check: `SHA256:<base64>` of the certificate.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The server configuration, for a TLS acceptor: a client must present a certificate
    /// for one of the `readers` keys (and prove it holds it). No reader: nobody gets in.
    pub fn server_config(&self, readers: &[Reader]) -> Result<Arc<rustls::ServerConfig>> {
        let provider = provider();
        let verifier = Arc::new(ReaderVerifier {
            spkis: readers.iter().filter_map(Reader::spki).collect(),
            provider: provider.clone(),
        });
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(Single(self.certified.clone())));
        config.alpn_protocols = vec![ALPN.to_vec()];
        Ok(Arc::new(config))
    }
}

/// Always the daemon's one certificate (no SNI: clients pin it).
#[derive(Debug)]
struct Single(Arc<CertifiedKey>);

impl ResolvesServerCert for Single {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Accepts a client certificate whose public key is a reader's, and checks that the client
/// holds that key (the handshake signature). Nothing else in the certificate is trusted or
/// checked: like the daemon's own, it is self-signed and stands only for its key.
#[derive(Debug)]
struct ReaderVerifier {
    /// Each reader key as a SubjectPublicKeyInfo.
    spkis: Vec<Vec<u8>>,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for ReaderVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        let cert = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|_| rustls::Error::General("unreadable client certificate".to_owned()))?;
        let spki = cert.subject_public_key_info();
        if self
            .spkis
            .iter()
            .any(|known| known.as_slice() == spki.as_ref())
        {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "the client certificate is not for a reader key".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.3 only: never reached, refused if it ever is.
        Err(rustls::Error::General("TLS 1.2 is not served".to_owned()))
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
        vec![SignatureScheme::ED25519]
    }
}

/// The client certificate for a reader key: self-signed with that key (Ed25519), so the
/// daemon sees the key it lists in `readers`. Returns the certificate and the key as PKCS#8.
fn reader_certificate(
    reader: &PrivateKey,
) -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> {
    let keypair = reader
        .key_data()
        .ed25519()
        .ok_or(CryptoError::Pem("reader key (must be ssh-ed25519)"))?;
    // PKCS#8 v1 for an Ed25519 seed (RFC 8410): a fixed prefix, then the 32-byte seed.
    let mut pkcs8 = Zeroizing::new(vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    pkcs8.extend_from_slice(keypair.private.as_ref());
    let der = PrivatePkcs8KeyDer::from(pkcs8.to_vec());
    let signing = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&der, &rcgen::PKCS_ED25519)?;
    let cert =
        rcgen::CertificateParams::new(vec!["writ-reader".to_owned()])?.self_signed(&signing)?;
    Ok((cert.der().clone(), der))
}

/// A client configuration that accepts exactly the certificate pinned as `fingerprint`
/// (`SHA256:<base64>`), and checks that the server holds its key. No certificate authority,
/// host name or expiry is trusted or checked: the pin is the whole identity. The client
/// presents a certificate for its `reader` key (Ed25519), which the daemon must list.
pub fn pinned_client_config(
    fingerprint: &str,
    reader: &PrivateKey,
) -> Result<rustls::ClientConfig> {
    let provider = provider();
    let (cert, key) = reader_certificate(reader)?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            fingerprint: fingerprint.to_owned(),
            provider,
        }))
        .with_client_auth_cert(vec![cert], PrivateKeyDer::Pkcs8(key))?;
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
    use crate::keys::{KeyKind, generate};

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
        assert_eq!(
            identity.server_config(&[]).unwrap().alpn_protocols,
            vec![ALPN.to_vec()]
        );
        assert!(!format!("{identity:?}").contains("PRIVATE"));
        let other = generate_self_signed().unwrap();
        assert!(matches!(
            TlsIdentity::from_pem(&generated.cert_pem, "not a key"),
            Err(CryptoError::Pem("private key"))
        ));
        assert!(matches!(
            TlsIdentity::from_pem("not a cert", &generated.key_pem),
            Err(CryptoError::Pem("certificate"))
        ));
        // A key that isn't the certificate's.
        assert!(matches!(
            TlsIdentity::from_pem(&generated.cert_pem, &other.key_pem),
            Err(CryptoError::Tls(rustls::Error::InconsistentKeys(_)))
        ));
        let reader = generate(KeyKind::Ed25519).unwrap();
        assert!(pinned_client_config(identity.fingerprint(), &reader).is_ok());
        let p256 = generate(KeyKind::P256).unwrap();
        assert!(matches!(
            pinned_client_config(identity.fingerprint(), &p256),
            Err(CryptoError::Pem("reader key (must be ssh-ed25519)"))
        ));
    }

    /// One TLS handshake in memory between a client and the daemon's server configuration.
    fn handshake(
        server: Arc<rustls::ServerConfig>,
        client: rustls::ClientConfig,
    ) -> std::result::Result<(), rustls::Error> {
        let mut server = rustls::ServerConnection::new(server)?;
        let name = ServerName::try_from("writd").map_err(|_| rustls::Error::DecryptError)?;
        let mut client = rustls::ClientConnection::new(Arc::new(client), name)?;
        for _ in 0..10 {
            let mut buffer = Vec::new();
            while client.wants_write() {
                client
                    .write_tls(&mut buffer)
                    .map_err(|_| rustls::Error::DecryptError)?;
            }
            server
                .read_tls(&mut buffer.as_slice())
                .map_err(|_| rustls::Error::DecryptError)?;
            server.process_new_packets()?;
            let mut buffer = Vec::new();
            while server.wants_write() {
                server
                    .write_tls(&mut buffer)
                    .map_err(|_| rustls::Error::DecryptError)?;
            }
            client
                .read_tls(&mut buffer.as_slice())
                .map_err(|_| rustls::Error::DecryptError)?;
            client.process_new_packets()?;
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        Err(rustls::Error::General(
            "the handshake did not finish".to_owned(),
        ))
    }

    #[test]
    fn only_a_reader_key_gets_through_mutual_tls() {
        let generated = generate_self_signed().unwrap();
        let identity = TlsIdentity::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
        let reader = generate(KeyKind::Ed25519).unwrap();
        let readers = crate::readers::parse(&format!(
            "mac {}",
            reader.public_key().to_openssh().unwrap()
        ))
        .unwrap();
        let server = identity.server_config(&readers).unwrap();
        let client = |key: &PrivateKey| pinned_client_config(identity.fingerprint(), key).unwrap();

        assert_eq!(handshake(server.clone(), client(&reader)), Ok(()));
        let stranger = generate(KeyKind::Ed25519).unwrap();
        assert_eq!(
            handshake(server.clone(), client(&stranger)),
            Err(rustls::Error::General(
                "the client certificate is not for a reader key".to_owned()
            ))
        );
        // No reader at all: nobody gets in.
        assert_eq!(
            handshake(identity.server_config(&[]).unwrap(), client(&reader)),
            Err(rustls::Error::General(
                "the client certificate is not for a reader key".to_owned()
            ))
        );
        // No client certificate: refused by the server.
        let anonymous = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned {
                fingerprint: identity.fingerprint().to_owned(),
                provider: provider(),
            }))
            .with_no_client_auth();
        assert_eq!(
            handshake(server, anonymous),
            Err(rustls::Error::NoCertificatesPresented)
        );
    }
}
