//! The daemon's SSH protocol, client side: connect to an endpoint, check the daemon's host key
//! against the pinned one, authenticate with a key, run commands.
//!
//! The client never uses the user's `~/.ssh`, ssh config or ssh-agent: it would offer personal
//! keys (Secretive's among them) to the daemon. It authenticates only with the key it is given
//! (a session key, or a throwaway key for the approval API).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use russh::ChannelMsg;
use russh::client::{self, Handle};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use serde::de::DeserializeOwned;
use writ_proto::{ApiError, Command};

/// Where the daemon listens: `ssh://[user@]host[:port]`, `unix:<path>` (both SSH), or
/// `https://host[:port]` (the approval API only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Tcp { host: String, port: u16 },
    Unix { path: PathBuf },
    Https { host: String, port: u16 },
}

/// The host name a Unix socket endpoint is pinned under in `known_hosts` (like ssh's
/// `HostKeyAlias`).
pub const UNIX_HOST_ALIAS: &str = "writ-local";

impl Endpoint {
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        if let Some(path) = url.strip_prefix("unix:") {
            if path.is_empty() {
                bail!("invalid endpoint {url}: no socket path");
            }
            return Ok(Self::Unix {
                path: PathBuf::from(path),
            });
        }
        let (rest, https) = match (url.strip_prefix("ssh://"), url.strip_prefix("https://")) {
            (Some(rest), _) => (rest, false),
            (None, Some(rest)) => (rest, true),
            (None, None) => bail!(
                "invalid endpoint {url}: use ssh://host[:port], https://host[:port] or unix:<path>"
            ),
        };
        let rest = rest.trim_end_matches('/');
        let rest = match rest.rsplit_once('@') {
            Some(_) if https => bail!("invalid endpoint {url}: no user in an https URL"),
            Some((_, host)) => host,
            None => rest,
        };
        let default_port = if https { 443 } else { 22 };
        // `[v6]:port`, `[v6]`, `host:port` or `host`. A bare IPv6 address is ambiguous and
        // refused.
        let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
            let (ip, after) = bracketed
                .split_once(']')
                .with_context(|| format!("invalid endpoint {url}: unclosed ["))?;
            if ip.parse::<std::net::Ipv6Addr>().is_err() {
                bail!("invalid endpoint {url}: {ip:?} is not an IPv6 address");
            }
            let port = match after {
                "" => default_port,
                _ => after
                    .strip_prefix(':')
                    .and_then(|p| p.parse::<u16>().ok())
                    .with_context(|| format!("invalid port in {url}"))?,
            };
            (ip, port)
        } else {
            match rest.split_once(':') {
                Some((host, port)) => (
                    host,
                    port.parse::<u16>()
                        .with_context(|| format!("invalid port in {url}"))?,
                ),
                None => (rest, default_port),
            }
        };
        if host.is_empty()
            || host.starts_with('-')
            || host.contains(['/', '[', ']', '@', ' '])
            || (host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_err())
        {
            bail!("invalid endpoint {url}");
        }
        let host = host.to_owned();
        Ok(if https {
            Self::Https { host, port }
        } else {
            Self::Tcp { host, port }
        })
    }

    /// The host as written in `known_hosts`: `host`, `[host]:port`, or [`UNIX_HOST_ALIAS`].
    pub fn known_hosts_name(&self) -> String {
        match self {
            Self::Tcp { host, port: 22 } => host.clone(),
            Self::Tcp { host, port } => format!("[{host}]:{port}"),
            Self::Unix { .. } => UNIX_HOST_ALIAS.to_owned(),
            Self::Https { host, port: 443 } => host.clone(),
            Self::Https { host, port } => format!("[{host}]:{port}"),
        }
    }
}

/// Finds the pinned host key for `name` in an OpenSSH `known_hosts` file (plain host names,
/// comma-separated; hashed names and markers are not read). None pinned: an error saying how
/// to pin it.
pub fn pinned_host_key(known_hosts: &Path, name: &str) -> anyhow::Result<PublicKey> {
    let text = read_pins(known_hosts)?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(hosts), Some(kind), Some(blob)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if hosts.split(',').any(|h| h == name) {
            return PublicKey::from_openssh(&format!("{kind} {blob}"))
                .with_context(|| format!("invalid key for {name} in {}", known_hosts.display()));
        }
    }
    bail!(
        "the daemon's host key for {name} is not pinned in {}: add the line \
         `{name} <host key>` (`writd host-key <config>` prints it)",
        known_hosts.display()
    )
}

/// A pins file's text; a missing file pins nothing, any other read error is reported.
pub fn read_pins(path: &Path) -> anyhow::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

struct Pinned {
    expected: PublicKey,
}

impl client::Handler for Pinned {
    type Error = russh::Error;

    /// Only the pinned plain key; a host certificate is never trusted.
    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                key.key_data() == self.expected.key_data()
            }
            PublicKeyOrCertificate::Certificate(_) => false,
        })
    }
}

/// An authenticated connection to the daemon.
pub struct Session {
    handle: Handle<Pinned>,
}

/// What a command printed, and how it exited.
#[derive(Debug, Default)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: Option<u32>,
}

impl Session {
    /// Connects to `endpoint`, checks its host key against `known_hosts`, and authenticates
    /// as `user` with `key`.
    pub async fn connect(
        endpoint: &Endpoint,
        known_hosts: &Path,
        user: &str,
        key: PrivateKey,
    ) -> anyhow::Result<Self> {
        let expected = pinned_host_key(known_hosts, &endpoint.known_hosts_name())?;
        let config = Arc::new(client::Config {
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 4,
            inactivity_timeout: None,
            ..Default::default()
        });
        let handler = Pinned { expected };
        let refused = || format!("cannot connect to the daemon at {endpoint:?}");
        let mut handle = match endpoint {
            Endpoint::Tcp { host, port } => {
                client::connect(config, (host.as_str(), *port), handler)
                    .await
                    .with_context(refused)?
            }
            Endpoint::Https { .. } => {
                bail!("{endpoint:?} is an HTTPS endpoint: this listener speaks SSH (ssh://, unix:)")
            }
            Endpoint::Unix { path } => {
                let stream = tokio::net::UnixStream::connect(path)
                    .await
                    .with_context(refused)?;
                client::connect_stream(config, stream, handler)
                    .await
                    .with_context(refused)?
            }
        };
        let auth = handle
            .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), None))
            .await
            .context("authentication with the daemon failed")?;
        if !auth.success() {
            bail!("the daemon refused the connection");
        }
        Ok(Self { handle })
    }

    /// Ends the connection politely (SSH disconnect), and waits a moment for it to go out.
    /// Dropping it instead would leave the daemon reading a connection cut mid-stream.
    pub async fn close(self) {
        let _ = self
            .handle
            .disconnect(russh::Disconnect::ByApplication, "done", "en")
            .await;
        let _ = tokio::time::timeout(Duration::from_secs(2), self.handle).await;
    }

    /// Runs `work` on the session, then closes it, whatever `work` returned.
    pub async fn run<T>(
        self,
        work: impl AsyncFnOnce(&Self) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let result = work(&self).await;
        self.close().await;
        result
    }

    /// Runs one exec command with `body` on stdin.
    pub async fn exec(&self, line: &str, body: &[u8]) -> anyhow::Result<Output> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .context("the daemon refused a channel")?;
        channel.exec(true, line).await?;
        if !body.is_empty() {
            channel.data_bytes(body.to_vec()).await?;
        }
        channel.eof().await?;
        let mut output = Output::default();
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => output.stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => output.stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => output.status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok(output)
    }

    /// Runs a command and decodes its reply. A failure comes back as the daemon's
    /// [`ApiError`]; a lost connection or an unreadable reply as an error too.
    pub async fn call<T: DeserializeOwned>(
        &self,
        command: &Command,
        body: &[u8],
    ) -> anyhow::Result<Result<T, ApiError>> {
        let output = self.exec(&command.line(), body).await?;
        if output.stdout.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "no reply from the daemon{}",
                if stderr.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", stderr.trim())
                }
            );
        }
        Ok(writ_proto::decode_reply(&output.stdout))
    }
}

/// A connection to the approval API, over SSH or HTTPS: the same commands and replies.
pub enum Approvals {
    Ssh(Session),
    Https(crate::https::Client),
}

impl Approvals {
    /// Connects to the approval listener at `url`, checking the daemon against its pin
    /// (`known_hosts` for SSH, `tls_pins` for HTTPS), with the reader key: SSH authentication,
    /// or the HTTPS client certificate. The daemon lets only its readers in.
    pub async fn connect(paths: &crate::Paths, url: &str) -> anyhow::Result<Self> {
        let endpoint = Endpoint::parse(url)?;
        let reader = crate::reader::load(&paths.reader)?;
        match &endpoint {
            Endpoint::Https { host, port } => {
                let name = endpoint.known_hosts_name();
                let pin = crate::https::pinned_fingerprint(&paths.tls_pins, &name)?;
                Ok(Self::Https(crate::https::Client::new(
                    host, *port, pin, &reader,
                )?))
            }
            _ => Ok(Self::Ssh(
                Session::connect(
                    &endpoint,
                    &paths.known_hosts,
                    writ_proto::CLIENT_USER,
                    reader,
                )
                .await?,
            )),
        }
    }

    /// Ends the connection (an SSH disconnect; HTTPS connections close after each call).
    pub async fn close(self) {
        if let Self::Ssh(session) = self {
            session.close().await;
        }
    }

    /// Runs `work` on the connection, then closes it, whatever `work` returned.
    pub async fn run<T>(
        self,
        work: impl AsyncFnOnce(&Self) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let result = work(&self).await;
        self.close().await;
        result
    }

    pub async fn call<T: DeserializeOwned>(
        &self,
        command: &Command,
        body: &[u8],
    ) -> anyhow::Result<Result<T, ApiError>> {
        match self {
            Self::Ssh(session) => session.call(command, body).await,
            Self::Https(client) => client.call(command, body).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unreadable_pins_file_is_an_error_not_an_empty_one() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_pins(&dir.path().join("missing")).unwrap(), "");
        let locked = dir.path().join("known_hosts");
        std::fs::write(&locked, "host ssh-ed25519 AAAA\n").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let error = format!("{:#}", pinned_host_key(&locked, "host").unwrap_err());
        assert!(error.starts_with("cannot read"), "{error}");
        assert!(!error.contains("not pinned"), "{error}");
        // A directory can't be read as a file either.
        assert!(crate::error_of(read_pins(dir.path())).starts_with("cannot read"));
    }

    #[test]
    fn parses_endpoints() {
        let tcp = |host: &str, port| Endpoint::Tcp {
            host: host.into(),
            port,
        };
        assert_eq!(
            Endpoint::parse("ssh://writ.home:2222").unwrap(),
            tcp("writ.home", 2222)
        );
        assert_eq!(
            Endpoint::parse("ssh://git@writ.home:8443/").unwrap(),
            tcp("writ.home", 8443)
        );
        assert_eq!(
            Endpoint::parse("ssh://writ.home").unwrap(),
            tcp("writ.home", 22)
        );
        assert_eq!(
            Endpoint::parse("ssh://[::1]:2222").unwrap(),
            tcp("::1", 2222)
        );
        assert_eq!(Endpoint::parse("ssh://[::1]").unwrap(), tcp("::1", 22));
        assert_eq!(
            Endpoint::parse("https://[fe80::1]:8443").unwrap(),
            Endpoint::Https {
                host: "fe80::1".into(),
                port: 8443
            }
        );
        assert_eq!(
            Endpoint::parse("unix:/tmp/w.sock").unwrap(),
            Endpoint::Unix {
                path: "/tmp/w.sock".into()
            }
        );
        for bad in [
            "writ.home:2222",
            "ssh://",
            "ssh://host:port",
            "ssh://-oProxy",
            "unix:",
            "ssh://a/b",
            "ssh://::1",
            "ssh://[::1",
            "ssh://[not-ip]:22",
            "ssh://[::1]x",
            "ssh://[::1]:",
            "ssh://host:",
            "ssh://host:99999",
            "ssh://a:1:2",
            "https://git@host",
        ] {
            let error = crate::error_of(Endpoint::parse(bad));
            assert!(
                error.starts_with("invalid ") && error.contains(bad),
                "{bad}: {error}"
            );
        }
        assert_eq!(
            Endpoint::parse("https://writ.home:8443").unwrap(),
            Endpoint::Https {
                host: "writ.home".into(),
                port: 8443
            }
        );
        assert!(matches!(
            Endpoint::parse("https://writ.home").unwrap(),
            Endpoint::Https { port: 443, .. }
        ));
        assert_eq!(
            crate::error_of(Endpoint::parse("https://me@writ.home")),
            "invalid endpoint https://me@writ.home: no user in an https URL"
        );
        assert!(
            crate::error_of(Endpoint::parse("http://writ.home"))
                .starts_with("invalid endpoint http://writ.home: use ssh://")
        );
        assert_eq!(tcp("h", 2222).known_hosts_name(), "[h]:2222");
        assert_eq!(tcp("h", 22).known_hosts_name(), "h");
    }

    #[test]
    fn finds_pinned_keys_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("known_hosts");
        let key = writ_crypto::keys::generate(writ_crypto::keys::KeyKind::Ed25519).unwrap();
        let line = key.public_key().to_openssh().unwrap();
        std::fs::write(&file, format!("# pins\nother,[h]:2222 {line} comment\n")).unwrap();
        assert_eq!(
            &pinned_host_key(&file, "[h]:2222").unwrap(),
            key.public_key()
        );
        for missing in [file.clone(), dir.path().join("missing")] {
            let error = crate::error_of(pinned_host_key(&missing, "h"));
            assert!(
                error.starts_with("the daemon's host key for h is not pinned"),
                "{error}"
            );
        }
    }
}
