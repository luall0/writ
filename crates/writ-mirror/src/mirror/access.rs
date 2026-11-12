//! How one operation reaches upstream ([`Access`]): for `ssh://`, an agent socket serving the
//! repo's key and the ssh command that uses it through the relay (behind a proxy of the
//! policy, with the byte-capping proxy as its tunnel); for `https://`, the byte-capping proxy,
//! the credential socket serving the token to the daemon's helper, and git's HTTPS settings.
//! The byte-capping proxy reaches upstream through the repo's dialer. Each socket goes when the
//! operation ends. And git run through it.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ssh_key::PublicKey;
use writ_core::names::KeyId;

use super::in_flight::Running;
use super::{MirrorGuard, Reach, Shared};
use crate::agent::AgentSocket;
use crate::credential::{CredentialSocket, UpstreamToken};
use crate::dial::{DialError, Dialer};
use crate::git::{self, Hooks, Transport};
use crate::process::{self, RunError};
use crate::proxy::UpstreamProxy;
use crate::quarantine::Quarantine;
use crate::upstream::{HttpsUrl, SshCommand, SshTunnel, SshUrl, quote};
use crate::{MirrorError, Result};

/// How one operation reaches upstream: what its git is given, and what serves it, for this
/// operation alone (the sockets go when it is dropped).
pub(super) struct Access {
    pub(super) transport: Transport,
    pub(super) config: Vec<String>,
    pub(super) env: Vec<(&'static str, String)>,
    _agent: Option<AgentSocket>,
    _credential: Option<CredentialSocket>,
    pub(super) proxy: Option<UpstreamProxy>,
    /// Counted in flight until the operation ends: a daemon stopping waits for it.
    _running: Running,
}

impl Access {
    /// Gives git its transport, settings and environment (before its subcommand).
    pub(super) fn apply(&self, cmd: &mut tokio::process::Command) {
        git::allow(cmd, self.transport);
        for setting in &self.config {
            cmd.arg("-c").arg(setting);
        }
        for (name, value) in &self.env {
            cmd.env(name, value);
        }
    }

    /// Whether upstream sent more than the cap through the proxy (HTTPS; for ssh the relay
    /// says so in git's stderr).
    pub(super) fn too_large(&self) -> bool {
        self.proxy.as_ref().is_some_and(UpstreamProxy::too_large)
    }

    /// Why a connection to upstream couldn't be opened, if one couldn't: git only says the
    /// proxy failed.
    pub(super) fn dial_failure(&self) -> Option<DialError> {
        self.proxy.as_ref().and_then(UpstreamProxy::failure)
    }
}

impl MirrorGuard {
    /// What one operation reaches upstream with. `ssh://`: an agent socket serving the repo's
    /// key, and the ssh command that uses it through the relay. `https://`: the byte-capping
    /// proxy, the credential socket serving the token to the daemon's helper, and git's HTTPS
    /// settings. Each socket goes when the operation ends. An `https://` repo whose token
    /// isn't in the keystore yet reaches nothing: refused with the command that adds it; so is
    /// a repo behind a proxy whose password isn't.
    pub(super) fn reach_upstream(&self) -> Result<Access> {
        let running = self
            .shared
            .in_flight
            .start()
            .ok_or_else(|| MirrorError::Stopping {
                repo: self.repo.name.clone(),
            })?;
        let dialer = &self.repo.dialer;
        if let Some(route) = dialer.proxy()
            && let Some(key) = route.missing_password()
        {
            return Err(MirrorError::NoProxyPassword {
                repo: self.repo.name.clone(),
                proxy: route.name().clone(),
                key: key.clone(),
            });
        }
        match &self.repo.reach {
            Reach::Ssh {
                url,
                credential,
                public,
                identity,
            } => ssh_access(
                &self.shared,
                url,
                dialer,
                credential,
                public,
                identity,
                running,
            ),
            Reach::Https {
                url,
                token: Some(token),
                ..
            } => https_access(&self.shared, url, dialer, token, running),
            Reach::Https {
                credential,
                token: None,
                ..
            } => Err(MirrorError::NoToken {
                repo: self.repo.name.clone(),
                key: credential.clone(),
            }),
        }
    }

    /// Runs git against upstream, reading a push's objects when `quarantine` is given.
    pub(super) async fn run_upstream(
        &self,
        access: &Access,
        args: &[&str],
        quarantine: Option<&Quarantine>,
        deadline: Duration,
        max_stdout: usize,
    ) -> Result<process::Finished> {
        let mut cmd = git::command(&self.shared.config.git, Hooks::None);
        access.apply(&mut cmd);
        cmd.arg("--git-dir").arg(&self.repo.path).args(args);
        if let Some(quarantine) = quarantine {
            quarantine.objects_env(&mut cmd);
        }
        match process::run(cmd, None, deadline, max_stdout).await {
            Ok(finished) => Ok(finished),
            Err(RunError::Timeout) => Err(MirrorError::Timeout {
                repo: self.repo.name.clone(),
                seconds: self.shared.config.timeout.as_secs(),
            }),
            Err(RunError::Spawn(e) | RunError::Wait(e)) => Err(MirrorError::Spawn(e)),
        }
    }
}

/// An `ssh://` operation: an agent socket serving `credential` (whose public half is `public`,
/// written at `identity`), and the ssh command, through the relay, that uses it. Behind a
/// proxy, ssh's `ProxyCommand` is the daemon's tunnel to the byte-capping proxy, which reaches
/// `url`'s host and port alone, through `dialer`.
fn ssh_access(
    shared: &Shared,
    url: &SshUrl,
    dialer: &Dialer,
    credential: &KeyId,
    public: &PublicKey,
    identity: &Path,
    running: Running,
) -> Result<Access> {
    let agent = AgentSocket::start(
        &shared.socket_dir,
        shared.signer.clone(),
        credential.clone(),
        public,
    )?;
    let proxy = match dialer {
        Dialer::Direct => None,
        Dialer::Proxy(_) => Some(UpstreamProxy::start(
            &shared.socket_dir,
            url.host(),
            url.port(),
            shared.config.max_fetch_bytes,
            dialer.clone(),
        )?),
    };
    let ssh = SshCommand {
        relay: &shared.config.relay,
        ssh: &shared.config.ssh,
        known_hosts: &shared.known_hosts,
        agent: agent.path(),
        identity,
        max_bytes: shared.config.max_fetch_bytes,
        tunnel: proxy.as_ref().map(|proxy| SshTunnel {
            socket: proxy.path(),
            host: url.host(),
            port: url.port(),
            connect_timeout: dialer.deadline(),
        }),
    }
    .to_git_ssh_command()?;
    Ok(Access {
        transport: Transport::Ssh,
        config: Vec::new(),
        env: vec![
            ("GIT_SSH_COMMAND", ssh),
            ("GIT_SSH_VARIANT", "ssh".to_owned()),
        ],
        _agent: Some(agent),
        _credential: None,
        proxy,
        _running: running,
    })
}

/// An `https://` operation: the byte-capping proxy to `url`'s host alone, the credential socket
/// serving `token` to the daemon's helper, and git's HTTPS settings (the operator's CAs alone
/// when they gave some, an empty `HOME`).
fn https_access(
    shared: &Shared,
    url: &HttpsUrl,
    dialer: &Dialer,
    token: &Arc<UpstreamToken>,
    running: Running,
) -> Result<Access> {
    let proxy = UpstreamProxy::start(
        &shared.socket_dir,
        url.host(),
        url.port(),
        shared.config.max_fetch_bytes,
        dialer.clone(),
    )?;
    let credential = CredentialSocket::start(&shared.socket_dir, url.clone(), token.clone())?;
    let helper = format!(
        "credential.helper=!{} upstream-credential {}",
        quote(&shared.config.relay)?,
        quote(credential.path())?
    );
    let mut config: Vec<String> = git::HTTPS_HARDENING
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    config.push(helper);
    config.push(format!("http.proxy={}", proxy.url()));
    if let Some(ca) = &shared.ca_certs {
        config.push(format!("http.sslCAInfo={}", ca.file.display()));
        config.push(format!("http.sslCAPath={}", ca.empty_dir.display()));
    }
    let home = shared
        .home
        .to_str()
        .ok_or_else(|| MirrorError::Config(format!("{} is not UTF-8", shared.home.display())))?;
    Ok(Access {
        transport: Transport::Https,
        config,
        env: vec![("HOME", home.to_owned())],
        _agent: None,
        _credential: Some(credential),
        proxy: Some(proxy),
        _running: running,
    })
}
