//! A relay in front of the daemon's SSH approval listener, as an agent running as the
//! approver's user could set one up in local mode (the review after M7.6, L-1): its own host
//! key, which the test pins for it in place of the daemon's, and the approver's reader key to
//! reach the real daemon. It forwards each command and its reply as they are, or changes the
//! reply first ([`Change`]), and records every command line it was sent.

use std::path::Path;
use std::sync::{Arc, Mutex};

use russh::server::{Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelMsg};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::PrivateKey;

/// What the relay does to a reply before it hands it on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Nothing: the reply as the daemon sent it, the relay's own host key the only change.
    Nothing,
    /// In the reply to `writ admin show <target>`, the text in force with `from` replaced by
    /// `to`, its daemon, version and digest kept: a text of the relay's under the real
    /// daemon's name.
    AdminText { from: String, to: String },
}

struct State {
    daemon_port: u16,
    reader: PrivateKey,
    change: Change,
    lines: Mutex<Vec<String>>,
}

/// A running relay.
pub struct Relay {
    pub port: u16,
    pub host_key: PrivateKey,
    state: Arc<State>,
}

impl Relay {
    /// Starts a relay on `runtime` to the daemon's SSH approval listener on `daemon_port`,
    /// reaching it with the reader key at `reader`. Its host key is a new one, or `host_key`:
    /// the daemon's own, standing for a relay the name check can't tell from the daemon (a
    /// copy of the boot tier; any relay over HTTPS, where the client never sees the host key).
    pub fn start(
        runtime: &tokio::runtime::Runtime,
        daemon_port: u16,
        reader: &Path,
        host_key: Option<PrivateKey>,
        change: Change,
    ) -> Self {
        let reader = PrivateKey::from_openssh(std::fs::read_to_string(reader).unwrap()).unwrap();
        let host_key = host_key.unwrap_or_else(|| generate(KeyKind::Ed25519).unwrap());
        let state = Arc::new(State {
            daemon_port,
            reader,
            change,
            lines: Mutex::new(Vec::new()),
        });
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = Arc::new(russh::server::Config {
            methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]),
            keys: vec![host_key.clone()],
            auth_rejection_time: std::time::Duration::from_millis(10),
            auth_rejection_time_initial: Some(std::time::Duration::ZERO),
            ..Default::default()
        });
        let served = state.clone();
        runtime.spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let handler = Handler {
                    state: served.clone(),
                    channels: Vec::new(),
                };
                let config = config.clone();
                tokio::spawn(async move {
                    if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                        let _ = session.await;
                    }
                });
            }
        });
        Self {
            port,
            host_key,
            state,
        }
    }

    /// The line pinning the relay's host key for its port in a `known_hosts` file.
    pub fn known_hosts_line(&self) -> String {
        format!(
            "[127.0.0.1]:{} {}",
            self.port,
            self.host_key.public_key().to_openssh().unwrap()
        )
    }

    /// Every command line the relay was sent, in order.
    pub fn lines(&self) -> Vec<String> {
        self.state.lines.lock().unwrap().clone()
    }
}

struct Handler {
    state: Arc<State>,
    channels: Vec<Channel<Msg>>,
}

impl russh::server::Handler for Handler {
    type Error = russh::Error;

    /// Anyone: the relay stands where the daemon would, and lets the approver's `writ` in.
    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.push(channel);
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(index) = self.channels.iter().position(|c| c.id() == channel_id) else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };
        let channel = self.channels.swap_remove(index);
        session.channel_success(channel_id)?;
        let line = String::from_utf8_lossy(data).into_owned();
        self.state.lines.lock().unwrap().push(line.clone());
        let state = self.state.clone();
        tokio::spawn(async move {
            let (mut rx, tx) = channel.split();
            let mut body = Vec::new();
            let _ = rx.make_reader().read_to_end(&mut body).await;
            let (stdout, stderr, status) = forward(&state, &line, &body).await;
            let stdout = changed(&state.change, &line, stdout);
            let mut out = tx.make_writer();
            let _ = out.write_all(&stdout).await;
            let _ = out.flush().await;
            let mut err = tx.make_writer_ext(Some(1));
            let _ = err.write_all(&stderr).await;
            let _ = err.flush().await;
            let _ = tx.exit_status(status).await;
            let _ = tx.eof().await;
            let _ = tx.close().await;
        });
        Ok(())
    }
}

struct Daemon;

impl russh::client::Handler for Daemon {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Runs `line` with `body` on the real daemon, with the reader key: what it printed, and how
/// it exited.
async fn forward(state: &State, line: &str, body: &[u8]) -> (Vec<u8>, Vec<u8>, u32) {
    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(config, ("127.0.0.1", state.daemon_port), Daemon)
        .await
        .unwrap();
    let auth = handle
        .authenticate_publickey(
            writ_proto::CLIENT_USER,
            russh::keys::PrivateKeyWithHashAlg::new(Arc::new(state.reader.clone()), None),
        )
        .await
        .unwrap();
    assert!(auth.success(), "the daemon refused the relay's reader key");
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, line).await.unwrap();
    if !body.is_empty() {
        channel.data_bytes(body.to_vec()).await.unwrap();
    }
    channel.eof().await.unwrap();
    let (mut stdout, mut stderr, mut status) = (Vec::new(), Vec::new(), 1);
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => status = exit_status,
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await;
    (stdout, stderr, status)
}

/// The reply as the relay hands it on.
fn changed(change: &Change, line: &str, stdout: Vec<u8>) -> Vec<u8> {
    match change {
        Change::Nothing => stdout,
        Change::AdminText { from, to } if line.starts_with("writ admin show ") => {
            let mut reply: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
            let text = reply["ok"]["text"].as_str().unwrap().to_owned();
            assert!(
                text.contains(from.as_str()),
                "{from:?} not in the text in force"
            );
            reply["ok"]["text"] = serde_json::Value::String(text.replacen(from, to, 1));
            let mut bytes = serde_json::to_vec(&reply).unwrap();
            bytes.push(b'\n');
            bytes
        }
        Change::AdminText { .. } => stdout,
    }
}
