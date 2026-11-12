//! Builds the platform implementations named in the configuration. This is the only place,
//! outside the platform crates, that knows which implementations exist (and the only place
//! allowed `#[cfg(target_os = …)]` to pick platform-only ones, from M7). Asking for one this
//! build doesn't have is a startup error, never a silent fallback.

use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use writ_core::names::KeyId;
use writ_core::net::Sources;
use writ_crypto::tls::TlsIdentity;
use writ_platform::attest::network::NetworkAttestor;
use writ_platform::notify::Notifiers;
use writ_platform::notify::telegram::{BotToken, TelegramNotifier};
use writ_platform::transport::tcp::TcpTransport;
use writ_platform::transport::unix::{PeerReader, UnixTransport};
use writ_platform::unlock::passphrase::PassphraseUnlock;
use writ_platform::watch::none::NoSessionWatcher;
use writ_platform::{CallerAttestor, Notifier, SessionWatcher, Transport};
use writ_signer::Signer;
use writ_signer::queue::{QueueConfig, QueuedSigner};
use writ_signer::software::SoftwareSigner;

use crate::config::{
    AttestorConfig, Config, NotifierConfig, SealedConfig, TelegramConfig, TokenConfig,
    TransportConfig, WatcherConfig,
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
    /// The boot tier's notifiers now; the sealed ones join at unseal.
    pub notifier: Arc<LateNotifiers>,
}

/// Commit signatures that may wait for the agent keys' backend while it signs one.
const AGENT_KEYS_QUEUE: usize = 16;

/// How long a commit signature waits for the agent keys' backend (a software key signs in
/// microseconds, a hardware one in milliseconds: past this, the device is stuck).
const AGENT_KEYS_DEADLINE: Duration = Duration::from_secs(10);

/// The `Signer` holding the keys commits are signed with, behind its own queue (one per use:
/// the TLS key and the upstream credential get theirs). This build has the software
/// backend only, so the configuration doesn't name one yet: the `signer:` key comes with the
/// sealed keystore (M5), and hardware backends with their milestones (M7.5).
pub fn signer(keys: Vec<crate::keystore::StoredKey>) -> anyhow::Result<Arc<dyn Signer>> {
    let backend = SoftwareSigner::new(keys.into_iter().map(|k| (k.id, k.key)))?;
    let queued = QueuedSigner::new(
        backend,
        QueueConfig {
            name: "writ-sign-agent".to_owned(),
            capacity: AGENT_KEYS_QUEUE,
            deadline: AGENT_KEYS_DEADLINE,
        },
    )?;
    Ok(Arc::new(queued))
}

/// Upstream signatures that may wait (one per ssh authentication: a sync or a push).
const UPSTREAM_QUEUE: usize = 8;

/// How long an upstream signature waits for its backend.
const UPSTREAM_DEADLINE: Duration = Duration::from_secs(10);

/// The `Signer` holding the upstream credentials, behind its own queue: a device stuck on
/// commit signing never holds up a sync or a push, nor the other way round.
pub fn upstream_signer(keys: Vec<crate::keystore::StoredKey>) -> anyhow::Result<Arc<dyn Signer>> {
    let backend = SoftwareSigner::new(keys.into_iter().map(|k| (k.id, k.key)))?;
    let queued = QueuedSigner::new(
        backend,
        QueueConfig {
            name: "writ-upstream".to_owned(),
            capacity: UPSTREAM_QUEUE,
            deadline: UPSTREAM_DEADLINE,
        },
    )?;
    Ok(Arc::new(queued))
}

/// Handshake signatures that may wait for the TLS key's backend.
const TLS_QUEUE: usize = 32;

/// How long a handshake signature waits for the TLS key's backend.
const TLS_DEADLINE: Duration = Duration::from_secs(5);

/// A TLS key whose signatures may wait for a device: each runs with the async worker thread
/// handed over to the runtime's other tasks (`block_in_place`), so a slow backend never stalls
/// the listeners. Outside a multi-thread runtime, it signs in place.
#[derive(Debug)]
struct OffAsync(writ_signer::tls::TlsSigner);

impl writ_crypto::tls::remote::TlsKey for OffAsync {
    fn public_point(&self) -> &[u8] {
        self.0.public_point()
    }

    fn sign(&self, message: &[u8]) -> writ_crypto::Result<[u8; 64]> {
        let multi_thread = tokio::runtime::Handle::try_current()
            .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
        if multi_thread {
            tokio::task::block_in_place(|| self.0.sign(message))
        } else {
            self.0.sign(message)
        }
    }
}

/// The HTTPS approval API's identity: its certificate, and its key behind a `Signer` of its
/// own (one queue per use: a device stuck on commit signing never holds up a handshake, nor
/// the other way round). The key is moved into the backend; rustls asks it for every
/// handshake signature.
pub fn tls_identity(tls: crate::keystore::TlsKeyPair) -> anyhow::Result<Arc<TlsIdentity>> {
    let id: KeyId = crate::keystore::TLS_KEY.parse()?;
    let backend = SoftwareSigner::new([(id.clone(), tls.key)])?;
    let queued: Arc<dyn Signer> = Arc::new(QueuedSigner::new(
        backend,
        QueueConfig {
            name: "writ-tls".to_owned(),
            capacity: TLS_QUEUE,
            deadline: TLS_DEADLINE,
        },
    )?);
    let key = writ_signer::tls::TlsSigner::new(queued, id)?;
    Ok(Arc::new(TlsIdentity::with_key(
        &tls.cert_pem,
        Arc::new(OffAsync(key)),
    )?))
}

/// The process hardening of this OS (docs/operators/hardening.md): Linux's or macOS's, or
/// `NoHardening` (every step refused) on another OS.
pub fn hardening() -> Box<dyn writ_platform::ProcessHardening> {
    #[cfg(target_os = "linux")]
    return Box::new(writ_platform_linux::hardening::Hardening);
    #[cfg(target_os = "macos")]
    return Box::new(writ_platform_macos::hardening::Hardening);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Box::new(writ_platform::harden::none::NoHardening);
}

/// The file holding the sealed keystore's identity, wrapped with the passphrase.
fn identity_file(sealed: &SealedConfig) -> std::path::PathBuf {
    sealed.dir.join("identity.age")
}

/// How the sealed keystore's identity is recovered at unseal: the passphrase (age scrypt) in
/// this build; M7.6 brings hardware recipients, picked here too.
pub fn unlock(sealed: &SealedConfig) -> Arc<dyn writ_platform::KeystoreUnlock> {
    Arc::new(PassphraseUnlock::new(identity_file(sealed)))
}

/// Wraps a new keystore identity with `passphrase` (`writd init`). Refuses an existing file.
pub fn enroll(
    sealed: &SealedConfig,
    passphrase: &writ_platform::Passphrase,
    key: &writ_platform::DataKey,
) -> anyhow::Result<()> {
    PassphraseUnlock::enroll(identity_file(sealed), passphrase, key)?;
    Ok(())
}

async fn listener(config: &TransportConfig) -> anyhow::Result<Listener> {
    let transport: Arc<dyn Transport> = match (&config.tcp, &config.unix) {
        (Some(addr), None) => Arc::new(TcpTransport::bind(addr).await?),
        (None, Some(socket)) => Arc::new(UnixTransport::bind(socket, unix_peer())?),
        // Refused when the configuration is loaded; refused here too.
        _ => bail!("a transport needs exactly one of tcp and unix"),
    };
    Ok((transport, config.sources()))
}

/// What the kernel says about a Unix socket's peer, on this OS: on macOS its audit token
/// (user, group, pid and the pid's generation), on Linux its credentials and its pidfd (the
/// generation its start time); elsewhere its user, group and pid.
fn unix_peer() -> PeerReader {
    #[cfg(target_os = "macos")]
    return writ_platform_macos::peer::audit_token_peer;
    #[cfg(target_os = "linux")]
    return writ_platform_linux::peer::pidfd_peer;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return writ_platform::transport::unix::portable_peer;
}

/// Local mode's attestor on macOS: the caller's process chain from the kernel.
fn macos_attestor() -> anyhow::Result<Arc<dyn CallerAttestor>> {
    #[cfg(target_os = "macos")]
    return Ok(Arc::new(writ_platform_macos::attest::ProcessChain::new()));
    #[cfg(not(target_os = "macos"))]
    bail!("attestor macos_process_chain is macOS's: this build is for another OS")
}

/// Local mode's session watcher on macOS: kqueue.
fn macos_watcher() -> anyhow::Result<Arc<dyn SessionWatcher>> {
    #[cfg(target_os = "macos")]
    return Ok(Arc::new(writ_platform_macos::watch::KqueueWatcher::new()?));
    #[cfg(not(target_os = "macos"))]
    bail!("session_watcher macos is macOS's: this build is for another OS")
}

/// How the Linux attestor reads other users' processes, settled before anything else
/// ([`start_process_reader`]). Empty on another OS.
pub struct ProcessReader {
    #[cfg(target_os = "linux")]
    reader: Arc<dyn writ_platform_linux::read::ReadProcess>,
}

/// The first thing `writd run` does on Linux (docs/architecture/platform.md): started with
/// `CAP_SYS_PTRACE` (the unit's `AmbientCapabilities`), it starts the process reader
/// (`writd proc-reader`, this same binary) which alone keeps it; then it drops every
/// capability it holds, before it reads a secret. Started without it (a development daemon
/// running as its user), the attestor reads `/proc` itself, which reaches only this user's
/// processes. On another OS, nothing.
pub fn start_process_reader() -> anyhow::Result<ProcessReader> {
    #[cfg(target_os = "linux")]
    {
        use writ_platform_linux::{caps, helper::Helper, read};
        let reader: Arc<dyn read::ReadProcess> = if caps::passes_ptrace_on()? {
            let me = std::env::current_exe()?;
            let helper = Helper::spawn(&me, &["proc-reader"])?;
            tracing::info!("the process reader started: it alone keeps CAP_SYS_PTRACE");
            Arc::new(helper)
        } else {
            Arc::new(read::Direct::new(read::Host::Myself))
        };
        if caps::holds_any()? {
            caps::drop_all()?;
            tracing::info!("every capability dropped");
        }
        Ok(ProcessReader { reader })
    }
    #[cfg(not(target_os = "linux"))]
    Ok(ProcessReader {})
}

/// `writd proc-reader`: the process reader's side, on its stdin (a socket pair's end
/// `writd run` holds). It keeps `CAP_SYS_PTRACE` alone, ends with its parent, and answers
/// one process at a time until its stdin closes.
pub fn serve_process_reader() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    return Ok(writ_platform_linux::helper::serve_stdin()?);
    #[cfg(not(target_os = "linux"))]
    bail!("proc-reader is Linux's: this build is for another OS")
}

/// Local mode's attestor on Linux: the caller's process chain from `/proc`, read through
/// `reader`, once the kernel and `/proc` are checked to give what it needs.
fn linux_attestor(reader: &ProcessReader) -> anyhow::Result<Arc<dyn CallerAttestor>> {
    #[cfg(target_os = "linux")]
    {
        writ_platform_linux::kernel::check_process_chain()
            .map_err(|e| anyhow::anyhow!("attestor linux_process_chain: {e}"))?;
        Ok(Arc::new(writ_platform_linux::attest::ProcessChain::new(
            reader.reader.clone(),
        )?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = reader;
        bail!("attestor linux_process_chain is Linux's: this build is for another OS")
    }
}

/// Local mode's session watcher on Linux: pidfds.
fn linux_watcher() -> anyhow::Result<Arc<dyn SessionWatcher>> {
    #[cfg(target_os = "linux")]
    {
        writ_platform_linux::kernel::check_pidfds()
            .map_err(|e| anyhow::anyhow!("session_watcher linux: {e}"))?;
        Ok(Arc::new(writ_platform_linux::watch::PidfdWatcher::new()?))
    }
    #[cfg(not(target_os = "linux"))]
    bail!("session_watcher linux is Linux's: this build is for another OS")
}

async fn listeners(configs: &[TransportConfig]) -> anyhow::Result<Vec<Listener>> {
    let mut built = Vec::new();
    for config in configs {
        built.push(listener(config).await?);
    }
    Ok(built)
}

pub async fn build(config: &Config, reader: &ProcessReader) -> anyhow::Result<Platform> {
    let agents = listeners(&config.transports.agents).await?;
    let approvals_ssh = listeners(&config.transports.approvals.ssh).await?;
    let approvals_https = listeners(&config.transports.approvals.https).await?;
    let attestor: Arc<dyn CallerAttestor> = match config.attestor {
        AttestorConfig::Network => Arc::new(NetworkAttestor::new()),
        AttestorConfig::MacosProcessChain => macos_attestor()?,
        AttestorConfig::LinuxProcessChain => linux_attestor(reader)?,
    };
    let watcher: Arc<dyn SessionWatcher> = match config.session_watcher {
        WatcherConfig::None => Arc::new(NoSessionWatcher::new()),
        WatcherConfig::Macos => macos_watcher()?,
        WatcherConfig::Linux => linux_watcher()?,
    };
    let notifiers = Arc::new(LateNotifiers::default());
    for n in &config.notifiers {
        match n {
            NotifierConfig::Telegram(telegram) => {
                if let TokenConfig::Boot(file) = &telegram.token {
                    notifiers.add(telegram_notifier(BotToken::from_file(file)?, telegram)?);
                }
            }
        }
    }
    Ok(Platform {
        agents,
        approvals_ssh,
        approvals_https,
        attestor,
        watcher,
        notifier: notifiers,
    })
}

/// A Telegram notifier with its token (from the boot tier, or opened at unseal).
pub fn telegram_notifier(
    token: BotToken,
    telegram: &TelegramConfig,
) -> anyhow::Result<Arc<dyn Notifier>> {
    let notifier = match &telegram.api_base {
        None => TelegramNotifier::new(token, &telegram.chat_id)?,
        Some(base) => TelegramNotifier::with_api_base(token, &telegram.chat_id, base)?,
    };
    Ok(Arc::new(notifier))
}

/// The notifiers the service tells: those whose token is in the boot tier from the start,
/// those whose token is sealed added at unseal (or when `writ admin token` adds it: a new
/// token replaces the notifier it starts). A notification goes to the ones there when it is
/// sent.
#[derive(Default)]
pub struct LateNotifiers(std::sync::RwLock<Vec<Late>>);

/// A notifier, and the id of its sealed token (`None`: its token is in the boot tier).
type Late = (Option<KeyId>, Arc<dyn Notifier>);

impl std::fmt::Debug for LateNotifiers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LateNotifiers")
    }
}

impl LateNotifiers {
    /// A notifier whose token is in the boot tier.
    pub fn add(&self, notifier: Arc<dyn Notifier>) {
        self.0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((None, notifier));
    }

    /// The notifier whose sealed token is `id`, in place of the one it had.
    pub fn set(&self, id: &KeyId, notifier: Arc<dyn Notifier>) {
        let mut all = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        all.retain(|(held, _)| held.as_ref() != Some(id));
        all.push((Some(id.clone()), notifier));
    }
}

impl Notifier for LateNotifiers {
    fn notify(&self, notification: &writ_platform::Notification) -> writ_platform::Result<()> {
        let now: Vec<Arc<dyn Notifier>> = self
            .0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(_, notifier)| notifier.clone())
            .collect();
        Notifiers(now).notify(notification)
    }
}
