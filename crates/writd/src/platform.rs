//! Builds the platform implementations named in the configuration. This is the only place,
//! outside the platform crates, that knows which implementations exist (and the only place
//! allowed `#[cfg(target_os = …)]` to pick platform-only ones, from M7). Asking for one this
//! build doesn't have is a startup error, never a silent fallback.

use std::sync::Arc;

use anyhow::bail;
use writ_platform::attest::NetworkAttestor;
use writ_platform::notify::{BotToken, Notifiers, TelegramNotifier};
use writ_platform::transport::TcpTransport;
use writ_platform::unlock::PassphraseUnlock;
use writ_platform::watch::NoSessionWatcher;
use writ_platform::{CallerAttestor, KeystoreUnlock, Notifier, SessionWatcher, Transport};

use crate::config::{
    AttestorConfig, Config, NotifierConfig, TransportConfig, UnlockConfig, WatcherConfig,
};

/// The implementations the daemon runs with.
pub struct Platform {
    pub agents: Vec<Arc<dyn Transport>>,
    /// The approval API over SSH.
    pub approvals_ssh: Vec<Arc<dyn Transport>>,
    /// The approval API over HTTPS.
    pub approvals_https: Vec<Arc<dyn Transport>>,
    pub attestor: Arc<dyn CallerAttestor>,
    pub watcher: Arc<dyn SessionWatcher>,
    /// Built now, used by the sealed start (M5).
    pub unlock: Option<Arc<dyn KeystoreUnlock>>,
    pub notifier: Arc<dyn Notifier>,
}

async fn transport(config: &TransportConfig) -> anyhow::Result<Arc<dyn Transport>> {
    match config {
        TransportConfig::Tcp(addr) => Ok(Arc::new(TcpTransport::bind(addr).await?)),
        TransportConfig::Unix(socket) => bail!(
            "transport unix ({}): Unix sockets come with local mode (M7) and are not in this build",
            socket.display()
        ),
    }
}

pub async fn build(config: &Config) -> anyhow::Result<Platform> {
    let mut agents = Vec::new();
    for t in &config.transports.agents {
        agents.push(transport(t).await?);
    }
    let mut approvals_ssh = Vec::new();
    for t in &config.transports.approvals.ssh {
        approvals_ssh.push(transport(t).await?);
    }
    let mut approvals_https = Vec::new();
    for t in &config.transports.approvals.https {
        approvals_https.push(transport(t).await?);
    }
    let attestor: Arc<dyn CallerAttestor> = match config.attestor {
        AttestorConfig::Network => Arc::new(NetworkAttestor::new()),
        AttestorConfig::MacosProcessChain => {
            bail!("attestor macos_process_chain is not in this build (local mode, M7)")
        }
    };
    let watcher: Arc<dyn SessionWatcher> = match config.session_watcher {
        WatcherConfig::None => Arc::new(NoSessionWatcher::new()),
        WatcherConfig::Macos => {
            bail!("session_watcher macos is not in this build (local mode, M7)")
        }
    };
    let unlock: Option<Arc<dyn KeystoreUnlock>> = match &config.unlock {
        None => None,
        Some(UnlockConfig::Passphrase(file)) => Some(Arc::new(PassphraseUnlock::new(file.clone()))),
    };
    let mut notifiers: Vec<Arc<dyn Notifier>> = Vec::new();
    for n in &config.notifiers {
        match n {
            NotifierConfig::Telegram(telegram) => {
                let token = BotToken::from_file(&telegram.token_file)?;
                let notifier = match &telegram.api_base {
                    None => TelegramNotifier::new(token, &telegram.chat_id)?,
                    Some(base) => TelegramNotifier::with_api_base(token, &telegram.chat_id, base)?,
                };
                notifiers.push(Arc::new(notifier));
            }
        }
    }
    Ok(Platform {
        agents,
        approvals_ssh,
        approvals_https,
        attestor,
        watcher,
        unlock,
        notifier: Arc::new(Notifiers(notifiers)),
    })
}
