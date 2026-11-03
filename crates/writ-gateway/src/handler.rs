//! One SSH connection: authentication by role, then exec requests.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use russh::server::{Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use writ_approval::{EventKind, GatewayDenial};
use writ_core::caller::CallerFacts;
use writ_core::policy::CertIdentity;
use writ_crypto::ca::validate_user_certificate;
use writ_crypto::ssh_key::{Certificate, HashAlg, PublicKey};

use crate::channel::refuse;
use crate::command::{Command, LeaseCommand};
use crate::limits::{self, MAX_CHANNELS, MAX_LOGGED_TEXT};
use crate::{CLIENT_USER, Gateway, GatewayError, LEASE_USER, Role, api, exec};

/// Who is on the other end, once authenticated.
#[derive(Debug, Clone)]
pub(crate) enum Identity {
    /// A lease holder: a valid certificate for an active lease.
    Lease(CertIdentity),
    /// A client submitting or waiting on a ticket: the key is its session key.
    SessionKey(PublicKey),
    /// A client of the approval API: a key in the `readers` in force (checked again at each
    /// command: an admin change may have removed it).
    Reader(PublicKey),
}

pub(crate) struct Connection {
    gateway: Gateway,
    role: Role,
    /// What the transport and the attestor say about the caller.
    facts: CallerFacts,
    number: u64,
    identity: Option<Identity>,
    /// Channels opened and not yet running a command, each holding one of the connection's
    /// [`MAX_CHANNELS`] slots (a running command keeps its slot until it ends).
    channels: HashMap<ChannelId, (Channel<Msg>, OwnedSemaphorePermit)>,
    channel_slots: Arc<Semaphore>,
    /// Set once authenticated: the gateway disconnects a connection that isn't in time.
    authenticated: Arc<AtomicBool>,
}

impl Connection {
    pub(crate) fn new(
        gateway: Gateway,
        role: Role,
        facts: CallerFacts,
        authenticated: Arc<AtomicBool>,
    ) -> Self {
        let number = gateway.connection_number();
        Self {
            gateway,
            role,
            facts,
            number,
            identity: None,
            channels: HashMap::new(),
            channel_slots: Arc::new(Semaphore::new(MAX_CHANNELS)),
            authenticated,
        }
    }

    /// Logs a refusal before authentication (event `connect`), coalesced per source.
    async fn refused(&self, kind: &'static str, reason: String, cert: Option<&Certificate>) {
        let source = self.facts.source_addr;
        let Some(suppressed) = self.gateway.shared.throttle.admit(source, kind) else {
            return;
        };
        let mut denial = GatewayDenial::new(
            EventKind::Connect,
            limits::with_suppressed(reason, suppressed),
        );
        if let Some(cert) = cert {
            denial.serial = Some(cert.serial());
            denial.key_id = Some(limits::shown(cert.key_id(), MAX_LOGGED_TEXT));
        }
        self.gateway.log_denial(denial, self.facts.clone()).await;
    }
}

impl Connection {
    /// The certificate's identity, if the gateway can trust it at all: issued by the daemon's
    /// CA for the lease user, valid now, not revoked.
    fn check_certificate(
        &self,
        user: &str,
        certificate: &Certificate,
    ) -> Result<CertIdentity, String> {
        if user != LEASE_USER {
            return Err(format!(
                "lease holders connect as {LEASE_USER}, not {user:?}"
            ));
        }
        let service = self.gateway.service();
        let serial = certificate.serial();
        validate_user_certificate(
            certificate,
            &self.gateway.shared.authorities,
            |serial| service.is_revoked(serial),
            user,
            service.now_unix(),
        )
        .map_err(|e| e.to_string())?;
        let session_key = certificate
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
            .parse()
            .map_err(|_| "unreadable session key".to_owned())?;
        Ok(CertIdentity {
            key_id: certificate.key_id().to_owned(),
            serial,
            session_key,
        })
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
    type Error = GatewayError;

    /// Plain keys: the session key of a ticket (agents, user `writ`), or a reader key on the
    /// approval API. Lease holders always use a certificate.
    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, GatewayError> {
        self.identity = match (self.role, user) {
            (Role::Agents, CLIENT_USER) => Some(Identity::SessionKey(key.public_key.clone())),
            (Role::Approvals, _) => {
                if self
                    .gateway
                    .shared
                    .config
                    .readers
                    .find(key.public_key)
                    .is_some()
                {
                    Some(Identity::Reader(key.public_key.clone()))
                } else {
                    let reason = "key refused: not in readers".to_owned();
                    self.refused("reader", reason, None).await;
                    None
                }
            }
            (Role::Agents, _) => {
                let reason = format!(
                    "key refused: user {:?} takes a certificate, not a plain key",
                    limits::shown(user, MAX_LOGGED_TEXT)
                );
                self.refused("user", reason, None).await;
                None
            }
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
    ) -> Result<Auth, GatewayError> {
        if self.role == Role::Approvals {
            // Only reader keys, as plain keys, reach the approval API.
            let reason = "certificate refused: the approval API takes reader keys".to_owned();
            self.refused("reader", reason, Some(certificate)).await;
            return Ok(Auth::reject());
        }
        match self.check_certificate(user, certificate) {
            Ok(cert) => {
                // The service logs the outcome (event `connect`).
                match self.gateway.authorize(&cert, &self.facts, None).await {
                    Ok(_) => {
                        self.identity = Some(Identity::Lease(cert));
                        Ok(Auth::Accept)
                    }
                    // A sealed service logs nothing itself: the gateway does, coalesced.
                    Err(denial) if denial.code == writ_core::policy::DenyCode::Sealed => {
                        self.gateway.refused_sealed(self.facts.clone()).await;
                        Ok(Auth::reject())
                    }
                    Err(_) => Ok(Auth::reject()),
                }
            }
            Err(reason) => {
                let reason = format!(
                    "certificate refused: {}",
                    limits::shown(&reason, 4 * MAX_LOGGED_TEXT)
                );
                self.refused("certificate", reason, Some(certificate)).await;
                Ok(Auth::reject())
            }
        }
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), GatewayError> {
        self.authenticated.store(true, Ordering::Release);
        if let Some(Identity::Lease(cert)) = &self.identity {
            self.gateway
                .register_session(cert.serial, self.number, session.handle())?;
        }
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), GatewayError> {
        if self.identity.is_none() {
            return Ok(());
        }
        // Past the cap the open is refused (the reply is dropped unanswered: a failure), and
        // logged, coalesced per source.
        if let Ok(permit) = self.channel_slots.clone().try_acquire_owned() {
            self.channels.insert(channel.id(), (channel, permit));
            reply.accept().await;
        } else {
            let reason = format!("channel refused: at most {MAX_CHANNELS} per connection");
            self.gateway
                .turned_away(self.facts.clone(), "channels", reason)
                .await;
        }
        Ok(())
    }

    /// A channel closed before running anything gives its slot back.
    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), GatewayError> {
        self.channels.remove(&channel);
        Ok(())
    }

    /// Nothing is taken from the client's environment, `GIT_PROTOCOL` included: every request
    /// is refused, and nothing of it kept. `upload-pack` speaks protocol v0 only, where
    /// `uploadpack.allow*SHA1InWant` hold (in v2, git ignores them and serves any object the
    /// mirror holds by its id); a client asking for v2 gets v0 (git falls back on its own).
    async fn env_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        _value: &str,
        session: &mut Session,
    ) -> Result<(), GatewayError> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), GatewayError> {
        // A channel runs one command: a second exec on it (or one on a channel never
        // opened) is refused, and logged.
        let Some((channel, permit)) = self.channels.remove(&channel_id) else {
            session.channel_failure(channel_id)?;
            let reason = "exec refused: a channel runs one command".to_owned();
            self.gateway
                .turned_away(self.facts.clone(), "exec", reason)
                .await;
            return Ok(());
        };
        session.channel_success(channel_id)?;
        let identity = self.identity.clone();
        let (gateway, facts) = (self.gateway.clone(), self.facts.clone());
        match route(identity, Command::parse(data)) {
            Ok(Route::Lease(cert, command)) => {
                let request = exec::LeaseRequest {
                    cert,
                    facts,
                    command,
                    connection: self.number,
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    exec::run(gateway, request, channel).await;
                });
            }
            Ok(Route::Agent(key, command)) => {
                tokio::spawn(async move {
                    let _permit = permit;
                    api::run_agent(gateway, key, facts, command, channel).await;
                });
            }
            Ok(Route::Approval(command)) => {
                let removed = match &identity_reader(&self.identity) {
                    Some(key) => gateway.shared.config.readers.find(key).is_none(),
                    None => true,
                };
                if removed {
                    let reason = "key refused: no longer in readers".to_owned();
                    let denial = GatewayDenial::new(EventKind::Command, reason.clone());
                    tokio::spawn(async move {
                        let _permit = permit;
                        gateway.log_denial(denial, facts).await;
                        refuse(channel, reason).await;
                    });
                    return Ok(());
                }
                tokio::spawn(async move {
                    let _permit = permit;
                    api::run_approval(gateway, facts, command, channel).await;
                });
            }
            Err(cert) => {
                let shown = String::from_utf8_lossy(data)
                    .chars()
                    .take(80)
                    .collect::<String>();
                let reason = format!("command not allowed here: {}", shown.escape_debug());
                let mut denial = GatewayDenial::new(EventKind::Command, reason.clone());
                if let Some(cert) = &cert {
                    denial = denial.cert(cert);
                }
                tokio::spawn(async move {
                    let _permit = permit;
                    gateway.log_denial(denial, facts).await;
                    refuse(channel, reason).await;
                });
            }
        }
        Ok(())
    }
}

/// The reader key an approval-API connection authenticated with.
fn identity_reader(identity: &Option<Identity>) -> Option<PublicKey> {
    match identity {
        Some(Identity::Reader(key)) => Some(key.clone()),
        _ => None,
    }
}

/// Where an exec request goes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    /// A lease holder's git or sign command.
    Lease(CertIdentity, LeaseCommand),
    /// An agent's `writ request` or `writ wait`, for its session key.
    Agent(PublicKey, writ_proto::Command),
    /// An approval command, on the approval listener.
    Approval(writ_proto::Command),
}

/// Who may run what: the one place it is decided. Lease holders run git and `writ-sign`;
/// session keys run `writ request` and `writ wait`; the approval listener runs the approval
/// commands; nothing else runs. A refusal carries the certificate, if any, for the log.
fn route(
    identity: Option<Identity>,
    command: Option<Command>,
) -> Result<Route, Option<CertIdentity>> {
    match (identity, command) {
        (Some(Identity::Lease(cert)), Some(Command::Lease(command))) => {
            Ok(Route::Lease(cert, command))
        }
        (Some(Identity::SessionKey(key)), Some(Command::Writ(writ))) if !writ.is_approval() => {
            Ok(Route::Agent(key, writ))
        }
        (Some(Identity::Reader(_)), Some(Command::Writ(writ))) if writ.is_approval() => {
            Ok(Route::Approval(writ))
        }
        (Some(Identity::Lease(cert)), _) => Err(Some(cert)),
        _ => Err(None),
    }
}

#[cfg(test)]
mod tests {
    use writ_crypto::keys::{KeyKind, generate};

    use super::*;

    fn writ(line: &str) -> Option<Command> {
        Command::parse(line.as_bytes())
    }

    #[test]
    fn each_identity_reaches_only_its_own_commands() {
        let key = generate(KeyKind::Ed25519).unwrap().public_key().clone();
        let cert = CertIdentity {
            key_id: "wrt_01JD8X0000000000000000000A".into(),
            serial: 7,
            session_key: key
                .fingerprint(HashAlg::Sha256)
                .to_string()
                .parse()
                .unwrap(),
        };
        let id = "wrt_01JD8X0000000000000000000A";
        let lease_lines = [
            "git-upload-pack 'demo.git'",
            "git-receive-pack 'demo.git'",
            "writ-sign git demo",
        ];
        let agent_lines = ["writ request".to_owned(), format!("writ wait {id}")];
        let approval_lines = [
            "writ info".to_owned(),
            "writ ls".to_owned(),
            "writ ls --all".to_owned(),
            format!("writ show {id}"),
            format!("writ approve {id}"),
            format!("writ refuse {id}"),
            format!("writ revoke {id}"),
        ];
        let lease = Some(Identity::Lease(cert.clone()));
        let session = Some(Identity::SessionKey(key.clone()));
        let approver = Some(Identity::Reader(key.clone()));

        for line in lease_lines {
            assert!(
                matches!(route(lease.clone(), writ(line)), Ok(Route::Lease(..))),
                "{line}"
            );
            assert_eq!(route(session.clone(), writ(line)), Err(None), "{line}");
            assert_eq!(route(approver.clone(), writ(line)), Err(None), "{line}");
            assert_eq!(route(None, writ(line)), Err(None), "{line}");
        }
        for line in &agent_lines {
            assert!(
                matches!(route(session.clone(), writ(line)), Ok(Route::Agent(..))),
                "{line}"
            );
            assert_eq!(
                route(lease.clone(), writ(line)),
                Err(Some(cert.clone())),
                "{line}"
            );
            assert_eq!(route(approver.clone(), writ(line)), Err(None), "{line}");
        }
        for line in &approval_lines {
            assert!(
                matches!(route(approver.clone(), writ(line)), Ok(Route::Approval(..))),
                "{line}"
            );
            assert_eq!(
                route(lease.clone(), writ(line)),
                Err(Some(cert.clone())),
                "{line}"
            );
            assert_eq!(route(session.clone(), writ(line)), Err(None), "{line}");
        }
        // Unparsable commands go nowhere, whoever asks.
        for identity in [lease.clone(), session, approver, None] {
            let expected = match &identity {
                Some(Identity::Lease(cert)) => Err(Some(cert.clone())),
                _ => Err(None),
            };
            assert_eq!(route(identity, writ("sh -c id")), expected);
        }
    }
}
