//! One SSH connection: certificate authentication, then exec requests.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use russh::server::{Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};
use writ_crypto::ca::validate_user_certificate;
use writ_crypto::ssh_key::Certificate;

use crate::{Command, Error, Gateway, process};

/// Who is on the other end, once their certificate was accepted.
#[derive(Debug, Clone)]
pub(crate) struct Identity {
    /// The certificate's key id: the lease id.
    pub lease: String,
    pub serial: u64,
}

pub(crate) struct Server(pub Gateway);

impl russh::server::Server for Server {
    type Handler = Connection;

    fn new_client(&mut self, _peer: Option<SocketAddr>) -> Connection {
        Connection::new(self.0.clone())
    }

    fn handle_session_error(&mut self, error: Error) {
        eprintln!("writ gateway: session error: {error}");
    }
}

pub(crate) struct Connection {
    gateway: Gateway,
    identity: Option<Identity>,
    channels: HashMap<ChannelId, Channel<Msg>>,
    git_protocol: Option<String>,
}

impl Connection {
    pub(crate) fn new(gateway: Gateway) -> Self {
        Self {
            gateway,
            identity: None,
            channels: HashMap::new(),
            git_protocol: None,
        }
    }
}

impl russh::server::Handler for Connection {
    type Error = Error;

    /// Plain keys are never accepted: only certificates issued for a lease.
    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Error> {
        Ok(Auth::reject())
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Error> {
        let Some(revoked) = self.gateway.revoked_snapshot() else {
            return Ok(Auth::reject());
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX);
        let authorities = &self.gateway.shared.config.authorities;
        match validate_user_certificate(certificate, authorities, &revoked, user, now) {
            Ok(()) => {
                self.identity = Some(Identity {
                    lease: certificate.key_id().to_owned(),
                    serial: certificate.serial(),
                });
                Ok(Auth::Accept)
            }
            Err(reason) => {
                eprintln!("writ gateway: refused certificate: {reason}");
                Ok(Auth::reject())
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Error> {
        if self.identity.is_some() {
            self.channels.insert(channel.id(), channel);
            reply.accept().await;
        }
        Ok(())
    }

    /// Only `GIT_PROTOCOL` (protocol v2 negotiation) is taken from the client's environment.
    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Error> {
        let valid = value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '=' | ':' | '.'));
        if name == "GIT_PROTOCOL" && valid && value.len() < 64 {
            self.git_protocol = Some(value.to_owned());
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Error> {
        let Some(channel) = self.channels.remove(&channel_id) else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };
        session.channel_success(channel_id)?;
        let identity = match &self.identity {
            Some(identity) if !self.gateway.is_revoked(identity.serial) => identity.clone(),
            _ => {
                tokio::spawn(process::refuse(channel, "lease revoked".into()));
                return Ok(());
            }
        };
        let Some(command) = Command::parse(data) else {
            let shown = String::from_utf8_lossy(data)
                .chars()
                .take(80)
                .collect::<String>();
            tokio::spawn(process::refuse(
                channel,
                format!("command not allowed: {}", shown.escape_debug()),
            ));
            return Ok(());
        };
        tokio::spawn(process::run(
            self.gateway.clone(),
            identity,
            command,
            self.git_protocol.clone(),
            channel,
        ));
        Ok(())
    }
}
