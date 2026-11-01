//! Builds the platform implementations named in the configuration. This is the only place,
//! outside the platform crates, that knows which implementations exist (and the only place
//! allowed `#[cfg(target_os = …)]` to pick platform-only ones, from M7). Asking for one this
//! build doesn't have is a startup error, never a silent fallback.

use std::sync::Arc;

use anyhow::bail;
use writ_core::names::KeyId;
use writ_core::net::Sources;
use writ_crypto::ssh_key::PrivateKey;
use writ_platform::attest::network::NetworkAttestor;
use writ_platform::notify::Notifiers;
use writ_platform::notify::telegram::{BotToken, TelegramNotifier};
use writ_platform::transport::tcp::TcpTransport;
use writ_platform::unlock::passphrase::PassphraseUnlock;
use writ_platform::watch::none::NoSessionWatcher;
use writ_platform::{CallerAttestor, KeystoreUnlock, Notifier, SessionWatcher, Transport};
use writ_signer::Signer;
use writ_signer::software::SoftwareSigner;

use crate::config::{
    AttestorConfig, Config, NotifierConfig, TransportConfig, UnlockConfig, WatcherConfig,
};

/// A listener and who may connect to it.
pub type Listener = (Arc<dyn Transport>, Sources);

/// The implementations the daemon runs with.
pub struct Platform {
    pub agents: Vec<Listener>,
    /// The approval API over SSH.
    pub approvals_ssh: Vec<Listener>,
    /// The approval API over HTTPS.
    pub approvals_https: Vec<Listener>,
    pub attestor: Arc<dyn CallerAttestor>,
    pub watcher: Arc<dyn SessionWatcher>,
    /// Built now, used by the sealed start (M5).
    pub unlock: Option<Arc<dyn KeystoreUnlock>>,
    pub notifier: Arc<dyn Notifier>,
}

/// The `Signer` holding the keys commits are signed with. This build has the software
/// backend only, so the configuration doesn't name one yet: the `signer:` key comes with the
/// sealed keystore (M5), and hardware backends with their milestones (M7.5).
pub fn signer(keys: Vec<(KeyId, PrivateKey)>) -> anyhow::Result<Arc<dyn Signer>> {
    Ok(Arc::new(SoftwareSigner::new(keys)?))
}

async fn listener(config: &TransportConfig) -> anyhow::Result<Listener> {
    let transport: Arc<dyn Transport> = match (&config.tcp, &config.unix) {
        (Some(addr), None) => Arc::new(TcpTransport::bind(addr).await?),
        (None, Some(socket)) => bail!(
            "transport unix ({}): Unix sockets come with local mode (M7) and are not in this build",
            socket.display()
        ),
        // Refused when the configuration is loaded; refused here too.
        _ => bail!("a transport needs exactly one of tcp and unix"),
    };
    Ok((transport, config.sources()))
}

async fn listeners(configs: &[TransportConfig]) -> anyhow::Result<Vec<Listener>> {
    let mut built = Vec::new();
    for config in configs {
        built.push(listener(config).await?);
    }
    Ok(built)
}

pub async fn build(config: &Config) -> anyhow::Result<Platform> {
    let agents = listeners(&config.transports.agents).await?;
    let approvals_ssh = listeners(&config.transports.approvals.ssh).await?;
    let approvals_https = listeners(&config.transports.approvals.https).await?;
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
