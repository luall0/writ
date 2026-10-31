//! The approval API over HTTPS, client side. The daemon's certificate is self-signed and
//! pinned: the server is trusted only if its certificate's SHA-256 fingerprint is the one in
//! `<home>/tls_pins` (lines `<host> SHA256:<base64>`, the host written like in
//! `known_hosts`: `[host]:port`, or `host` on port 443). No certificate authority is trusted.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde::de::DeserializeOwned;
use writ_proto::{ApiError, Command};

/// The largest reply read from the daemon.
const MAX_REPLY: usize = 8 * 1024 * 1024;

/// Finds the pinned fingerprint for `name` in the pins file. None pinned: an error saying how
/// to pin it.
pub fn pinned_fingerprint(pins: &Path, name: &str) -> anyhow::Result<String> {
    let text = crate::client::read_pins(pins)?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        if let (Some(hosts), Some(pin)) = (fields.next(), fields.next())
            && hosts.split(',').any(|h| h == name)
        {
            if !pin.starts_with("SHA256:") {
                bail!(
                    "invalid pin for {name} in {}: expected SHA256:…",
                    pins.display()
                );
            }
            return Ok(pin.to_owned());
        }
    }
    bail!(
        "the daemon's TLS certificate for {name} is not pinned in {}: add the line \
         `{name} <fingerprint>` (`writd tls-fingerprint` prints it)",
        pins.display()
    )
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
    ) -> Result<ServerCertVerified, rustls::Error> {
        if writ_crypto::tls::fingerprint(end_entity) == self.fingerprint {
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
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
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
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// An HTTPS client of the approval API, for one pinned daemon.
pub struct Client {
    host: String,
    port: u16,
    connector: tokio_rustls::TlsConnector,
}

impl Client {
    pub fn new(host: &str, port: u16, fingerprint: String) -> anyhow::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned {
                fingerprint,
                provider,
            }))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            host: host.to_owned(),
            port,
            connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
        })
    }

    /// Runs an approval command and decodes its reply, like `Session::call` over SSH.
    pub async fn call<T: DeserializeOwned>(
        &self,
        command: &Command,
        body: &[u8],
    ) -> anyhow::Result<Result<T, ApiError>> {
        let (method, path) = command
            .http_route()
            .context("this command isn't served over HTTPS")?;
        let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
            .await
            .with_context(|| {
                format!(
                    "cannot connect to the daemon at {}:{}",
                    self.host, self.port
                )
            })?;
        let name = ServerName::try_from(self.host.clone()).context("invalid host name")?;
        let tls = self
            .connector
            .connect(name, tcp)
            .await
            .context("TLS with the daemon failed")?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .context("HTTP with the daemon failed")?;
        tokio::spawn(connection);
        let request = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header(hyper::header::HOST, format!("{}:{}", self.host, self.port))
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_vec())))?;
        let response = sender
            .send_request(request)
            .await
            .context("the daemon didn't answer")?;
        let status = response.status();
        let bytes = Limited::new(response.into_body(), MAX_REPLY)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("cannot read the daemon's reply: {e}"))?
            .to_bytes();
        if bytes.is_empty() {
            bail!("no reply from the daemon (HTTP {status})");
        }
        Ok(writ_proto::decode_reply(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_pins_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tls_pins");
        let pin = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
        std::fs::write(&file, format!("# pins\n[h]:8443 {pin}\nbad:1 md5:x\n")).unwrap();
        assert_eq!(pinned_fingerprint(&file, "[h]:8443").unwrap(), pin);
        assert!(pinned_fingerprint(&file, "h").is_err());
        assert!(pinned_fingerprint(&file, "bad:1").is_err());
        assert!(pinned_fingerprint(&dir.path().join("missing"), "[h]:8443").is_err());
    }
}
