//! One SSH connection: authentication by role, then exec requests.

use std::collections::HashMap;

use russh::server::{Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};
use writ_core::caller::CallerFacts;
use writ_core::policy::CertIdentity;
use writ_crypto::ca::validate_user_certificate;
use writ_crypto::ssh_key::{Certificate, HashAlg, PublicKey};

use crate::{CLIENT_USER, Command, Error, Gateway, LEASE_USER, Role, process};

/// Who is on the other end, once authenticated.
#[derive(Debug, Clone)]
pub(crate) enum Identity {
    /// A lease holder: a valid certificate for an active lease.
    Lease(CertIdentity),
    /// A client submitting or waiting on a ticket: the key is its session key.
    SessionKey(PublicKey),
    /// A client of the approval API.
    Approver,
}

pub(crate) struct Connection {
    gateway: Gateway,
    role: Role,
    /// What the transport and the attestor say about the caller.
    facts: CallerFacts,
    number: u64,
    identity: Option<Identity>,
    channels: HashMap<ChannelId, Channel<Msg>>,
    git_protocol: Option<String>,
}

impl Connection {
    pub(crate) fn new(gateway: Gateway, role: Role, facts: CallerFacts) -> Self {
        let number = gateway.connection_number();
        Self {
            gateway,
            role,
            facts,
            number,
            identity: None,
            channels: HashMap::new(),
            git_protocol: None,
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(Identity::Lease(cert)) = &self.identity {
            self.gateway.unregister_session(cert.serial, self.number);
        }
    }
}

impl russh::server::Handler for Connection {
    type Error = Error;

    /// Plain keys: the session key of a ticket (agents, user `writ`), or anyone on the
    /// approval API. Lease holders always use a certificate.
    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Error> {
        self.identity = match (self.role, user) {
            (Role::Agents, CLIENT_USER) => Some(Identity::SessionKey(key.public_key.clone())),
            (Role::Approvals, _) => Some(Identity::Approver),
            _ => None,
        };
        Ok(if self.identity.is_some() {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Error> {
        if self.role == Role::Approvals {
            self.identity = Some(Identity::Approver);
            return Ok(Auth::Accept);
        }
        let service = self.gateway.service();
        let serial = certificate.serial();
        let refused = |reason: String| {
            service.certificate_refused(serial, certificate.key_id(), &reason, &self.facts);
            Ok(Auth::reject())
        };
        if user != LEASE_USER {
            return refused(format!(
                "lease holders connect as {LEASE_USER}, not {user:?}"
            ));
        }
        let revoked = if service.is_revoked(serial) {
            std::iter::once(serial).collect()
        } else {
            std::collections::HashSet::new()
        };
        let authorities = &self.gateway.shared.authorities;
        if let Err(reason) =
            validate_user_certificate(certificate, authorities, &revoked, user, service.now_unix())
        {
            return refused(reason.to_string());
        }
        let cert = CertIdentity {
            key_id: certificate.key_id().to_owned(),
            serial,
            session_key: match certificate
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .to_string()
                .parse()
            {
                Ok(fingerprint) => fingerprint,
                Err(_) => return refused("unreadable session key".to_owned()),
            },
        };
        // The service logs the outcome (event `connect`).
        match service.authorize(&cert, &self.facts, None) {
            Ok(_) => {
                self.identity = Some(Identity::Lease(cert));
                Ok(Auth::Accept)
            }
            Err(_) => Ok(Auth::reject()),
        }
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Error> {
        if let Some(Identity::Lease(cert)) = &self.identity {
            self.gateway
                .register_session(cert.serial, self.number, session.handle());
        }
        Ok(())
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
        let Some(identity) = self.identity.clone() else {
            tokio::spawn(process::refuse(channel, "not authenticated".into()));
            return Ok(());
        };
        let command = Command::parse(data);
        let allowed = match (&identity, &command) {
            (Identity::Lease(_), Some(Command::UploadPack { .. }))
            | (Identity::Lease(_), Some(Command::ReceivePack { .. }))
            | (Identity::Lease(_), Some(Command::Sign { .. })) => true,
            (Identity::SessionKey(_), Some(Command::Writ(writ))) => !writ.is_approval(),
            (Identity::Approver, Some(Command::Writ(writ))) => writ.is_approval(),
            _ => false,
        };
        let Some(command) = command.filter(|_| allowed) else {
            let shown = String::from_utf8_lossy(data)
                .chars()
                .take(80)
                .collect::<String>();
            tokio::spawn(process::refuse(
                channel,
                format!("command not allowed here: {}", shown.escape_debug()),
            ));
            return Ok(());
        };
        tokio::spawn(process::run(
            self.gateway.clone(),
            identity,
            self.facts.clone(),
            command,
            self.git_protocol.clone(),
            channel,
        ));
        Ok(())
    }
}
