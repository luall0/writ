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
use rustls::pki_types::ServerName;
use serde::de::DeserializeOwned;
use writ_proto::{ApiError, Command};

/// The largest reply read from the daemon.
/// The most of a reply read, over HTTPS and SSH alike.
pub const MAX_REPLY: usize = 8 * 1024 * 1024;

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

/// Replaces the pin `old` of `name` with `new` in the pins file (M7.5, `writ admin tls rotate`:
/// the daemon's new certificate, given over a connection its old one authenticated). Only a
/// line naming `name` with `old` changes; the file is read with the same checks as for a
/// connection, written whole beside it (mode 0600), then renamed over it. None such: refused.
pub fn repin(pins: &Path, name: &str, old: &str, new: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let text = crate::client::read_pins(pins)?;
    let mut changed = false;
    let mut out = String::with_capacity(text.len().saturating_add(64));
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let hit = matches!(
            (fields.next(), fields.next(), fields.next()),
            (Some(hosts), Some(pin), None)
                if !line.trim_start().starts_with('#')
                    && pin == old
                    && hosts.split(',').any(|h| h == name)
        );
        if hit {
            let hosts = line.split_whitespace().next().unwrap_or_default();
            out.push_str(&format!("{hosts} {new}\n"));
            changed = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !changed {
        bail!(
            "{}: no line pins {name} to {old}: add `{name} {new}` yourself",
            pins.display()
        );
    }
    let temporary = pins.with_extension(format!(
        "new-{}",
        writ_crypto::keys::random_hex(8).map_err(|e| anyhow::anyhow!("{e}"))?
    ));
    let written = (|| -> anyhow::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .with_context(|| format!("cannot create {}", temporary.display()))?;
        file.write_all(out.as_bytes())
            .and_then(|()| file.sync_all())
            .with_context(|| format!("cannot write {}", temporary.display()))?;
        std::fs::rename(&temporary, pins)
            .with_context(|| format!("cannot replace {}", pins.display()))
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

/// An HTTPS client of the approval API, for one pinned daemon.
pub struct Client {
    host: String,
    port: u16,
    /// The certificate fingerprint every connection is checked against.
    pin: String,
    connector: tokio_rustls::TlsConnector,
}

impl Client {
    pub fn new(
        host: &str,
        port: u16,
        fingerprint: String,
        reader: &writ_crypto::ssh_key::PrivateKey,
    ) -> anyhow::Result<Self> {
        let config = writ_crypto::tls::pinned_client_config(&fingerprint, reader)?;
        Ok(Self {
            host: host.to_owned(),
            port,
            pin: fingerprint,
            connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
        })
    }

    /// The certificate fingerprint every connection of this client is checked against: the
    /// certificate the daemon showed, since a handshake with any other one fails.
    pub fn pin(&self) -> &str {
        &self.pin
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
        let error = crate::error_of(pinned_fingerprint(&file, "h"));
        assert!(error.starts_with("the daemon's TLS certificate for h is not pinned"));
        let error = crate::error_of(pinned_fingerprint(&file, "bad:1"));
        assert!(error.starts_with("invalid pin for bad:1"), "{error}");
        let error = crate::error_of(pinned_fingerprint(&dir.path().join("missing"), "[h]:8443"));
        assert!(error.contains("is not pinned"), "{error}");
    }
}
