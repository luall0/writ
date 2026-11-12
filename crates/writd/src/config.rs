//! `writd.yaml`: the daemon's configuration. Errors name the field; unknown fields are
//! refused. Relative paths are relative to the configuration file's directory.
//!
//! ```yaml
//! state_dir: data                    # leases.db, audit.jsonl, repos/, run/
//! policy: policy.yaml                # repo registry and templates
//! approvers: approvers               # allowed_signers format
//! readers: readers                   # who may use the approval API (`writ reader`)
//! decisions: signed                  # signed | open: refusals and revocations
//! max_pending: 20                    # tickets waiting for the approver at once
//! min_ttl: 5m                        # the shortest ticket ttl and template max_ttl (10s to 1d)
//! submissions:                       # ticket submissions a minute (each 1 or more)
//!   per_source: 10                   # per address (an IPv6 host by its /64; local: one)
//!   in_all: 60                       # all sources together
//! max_active_per_source: 1           # active leases one source may hold (no limit by default)
//! renew_grace: 24h                   # renewing an expired or used-up lease (0s to 7d)
//! sign_requests:                     # held at once (16 in all, daemon-wide)
//!   per_lease: 4                     # per lease, 1 to 16
//! keystore:
//!   sealed:                          # M5: one age file per secret, sealed at start
//!     dir: data/keys                 # every secret but the boot tier's (0700)
//!     boot: data/boot                # the host and TLS keys, readable at a sealed start (0700)
//! mirrors:                           # the keys and the upstream host keys are the policy's
//!   ca_certs: upstream_ca.pem        # HTTPS upstreams: the CAs trusted (default: the system's)
//!   git: /usr/bin/git                # git, by absolute path (2.45, or 2.47 for https://)
//!   ssh: /usr/bin/ssh                # the OpenSSH client, by absolute path
//!   fresh_for: 10s                   # a mirror synced this recently isn't synced again
//!   sync_every: 5m                   # background sync of every mirror
//!   timeout: 5m                      # one sync or upstream push, then git and ssh are killed
//!   max_fetch: 1GiB                  # the most one sync takes from upstream
//!   scan_timeout: 30s                # one handshake of a host key scan (writ admin host add)
//! signers:                           # M7.5: the device backends' programs
//!   se_cryptokit:                    # macOS: keys in the Secure Enclave (backend: se-cryptokit)
//!     helper: /opt/writ/bin/writ-se  # by absolute path (default: writ-se beside writd)
//! transports:
//!   agents:                          # TCP: `allow` is required (`0.0.0.0/0` for anyone)
//!     - { tcp: "0.0.0.0:2222", allow: ["10.0.0.0/24"] }
//!   approvals:                       # each may be omitted or [] (disabled), not both
//!     ssh: [{ tcp: "127.0.0.1:2223" }]          # `allow` optional: readers only anyway
//!     https: [{ tcp: "127.0.0.1:8443" }]
//! attestor: network
//! session_watcher: none
//! notifiers:
//!   - telegram: { token: { boot: data/boot/telegram }, chat_id: "123456789" }
//! ```

use std::path::{Path, PathBuf};

use serde::Deserialize;
use writ_core::net::{IpRange, Sources};
use writ_core::units::{ByteSize, Duration};
use writ_proto::Decisions;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub state_dir: PathBuf,
    pub policy: PathBuf,
    pub approvers: PathBuf,
    /// The keys that may use the approval API: the `readers` file.
    pub readers: PathBuf,
    #[serde(default)]
    pub decisions: Decisions,
    #[serde(default = "default_max_pending")]
    pub max_pending: usize,
    /// The shortest TTL a ticket may ask for, and the least a template's `max_ttl` may be.
    #[serde(default = "default_min_ttl")]
    pub min_ttl: Duration,
    /// The submission rates, per minute; the defaults suit one person's agents.
    #[serde(default)]
    pub submissions: SubmissionsConfig,
    /// The most active leases one source may hold at once: none by default; `1` for a host
    /// meant for one agent.
    #[serde(default)]
    pub max_active_per_source: Option<u32>,
    /// How long after its `expires_at` an expired or used-up lease can still be renewed.
    #[serde(default = "default_renew_grace")]
    pub renew_grace: Duration,
    /// Sign requests held at once per lease.
    #[serde(default)]
    pub sign_requests: SignRequestsConfig,
    pub keystore: KeystoreConfig,
    /// Before M6.2, the signing keys' declarations: refused, naming the policy's `keys`.
    #[serde(default)]
    signing_keys: Option<Moved>,
    /// The mirrors and how they reach upstream.
    #[serde(default)]
    pub mirrors: MirrorsConfig,
    /// The programs the device backends run (M7.5).
    #[serde(default)]
    pub signers: SignersConfig,
    pub transports: Transports,
    pub attestor: AttestorConfig,
    pub session_watcher: WatcherConfig,
    #[serde(default)]
    pub notifiers: Vec<NotifierConfig>,
}

fn default_max_pending() -> usize {
    writ_approval::DEFAULT_MAX_PENDING
}

fn default_min_ttl() -> Duration {
    writ_core::fit::DEFAULT_MIN_TTL
}

fn default_renew_grace() -> Duration {
    writ_core::fit::DEFAULT_RENEW_GRACE
}

/// A key that moved to the policy in M6.2: read so its refusal can name its new place.
#[derive(Debug, Clone, Copy)]
struct Moved;

impl<'de> Deserialize<'de> for Moved {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        serde::de::IgnoredAny::deserialize(d).map(|_| Moved)
    }
}

/// `submissions`: how many tickets may be submitted a minute, per source and in all.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionsConfig {
    #[serde(default = "default_per_source")]
    pub per_source: usize,
    #[serde(default = "default_in_all")]
    pub in_all: usize,
}

impl Default for SubmissionsConfig {
    fn default() -> Self {
        Self {
            per_source: default_per_source(),
            in_all: default_in_all(),
        }
    }
}

impl SubmissionsConfig {
    /// The service's limits.
    pub fn limits(&self) -> writ_approval::SubmissionLimits {
        writ_approval::SubmissionLimits {
            per_source: self.per_source,
            in_all: self.in_all,
        }
    }
}

/// `sign_requests`: how many sign requests one lease may have held at once.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequestsConfig {
    #[serde(default = "default_per_lease")]
    pub per_lease: usize,
}

impl Default for SignRequestsConfig {
    fn default() -> Self {
        Self {
            per_lease: default_per_lease(),
        }
    }
}

fn default_per_lease() -> usize {
    writ_gateway::DEFAULT_SIGN_REQUESTS_PER_LEASE
}

fn default_per_source() -> usize {
    writ_approval::DEFAULT_SUBMISSIONS_PER_SOURCE
}

fn default_in_all() -> usize {
    writ_approval::DEFAULT_SUBMISSIONS_IN_ALL
}

/// `mirrors`: the programs the mirrors run and the bounds of a sync. The upstream host keys
/// are the policy's (`upstream_hosts`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorsConfig {
    /// Before M6.2, the file of upstream host keys: refused, naming the policy's
    /// `upstream_hosts`.
    #[serde(default)]
    known_hosts: Option<Moved>,
    /// The CA certificates (PEM) an HTTPS upstream's certificate must chain to, chosen by the
    /// operator (an authority file); without it, the system's.
    #[serde(default)]
    pub ca_certs: Option<PathBuf>,
    /// The git the daemon runs on its mirrors and with upstream, by absolute path (never
    /// looked up in `PATH`); `/usr/bin/git` unless the system keeps it elsewhere.
    #[serde(default = "default_git")]
    pub git: PathBuf,
    /// The OpenSSH client the daemon reaches upstream with, by absolute path (never looked up
    /// in `PATH`); `/usr/bin/ssh` unless the system keeps it elsewhere.
    #[serde(default = "default_ssh")]
    pub ssh: PathBuf,
    #[serde(default = "default_fresh_for")]
    pub fresh_for: Duration,
    #[serde(default = "default_sync_every")]
    pub sync_every: Duration,
    #[serde(default = "default_timeout")]
    pub timeout: Duration,
    #[serde(default = "default_max_fetch")]
    pub max_fetch: ByteSize,
    /// The longest one handshake of a host key scan (`writ admin host add`) may take: some
    /// hosts are slow to answer.
    #[serde(default = "default_scan_timeout")]
    pub scan_timeout: Duration,
}

impl Default for MirrorsConfig {
    fn default() -> Self {
        Self {
            known_hosts: None,
            ca_certs: None,
            git: default_git(),
            ssh: default_ssh(),
            fresh_for: default_fresh_for(),
            sync_every: default_sync_every(),
            timeout: default_timeout(),
            max_fetch: default_max_fetch(),
            scan_timeout: default_scan_timeout(),
        }
    }
}

fn default_git() -> PathBuf {
    PathBuf::from("/usr/bin/git")
}

fn default_ssh() -> PathBuf {
    PathBuf::from("/usr/bin/ssh")
}

fn default_fresh_for() -> Duration {
    Duration::from_seconds(10)
}

fn default_sync_every() -> Duration {
    Duration::from_seconds(300)
}

fn default_timeout() -> Duration {
    Duration::from_seconds(300)
}

fn default_scan_timeout() -> Duration {
    Duration::from_seconds(writ_mirror::scan::DEFAULT_HANDSHAKE_DEADLINE.as_secs())
}

fn default_max_fetch() -> ByteSize {
    ByteSize::from_bytes(1 << 30)
}

impl MirrorsConfig {
    /// Each bound within what makes sense: a sync that can't finish, or a limit that bounds
    /// nothing, is a mistake.
    fn check(&self) -> Result<(), String> {
        for (name, path) in [("git", &self.git), ("ssh", &self.ssh)] {
            if !path.is_absolute() {
                return Err(format!(
                    "mirrors.{name}: {}, must be an absolute path (never looked up in PATH)",
                    path.display()
                ));
            }
        }
        let within = |name: &str, value: Duration, min: u64, max: u64| {
            if (min..=max).contains(&value.seconds()) {
                Ok(())
            } else {
                Err(format!(
                    "mirrors.{name}: {value}, must be from {} to {}",
                    Duration::from_seconds(min),
                    Duration::from_seconds(max)
                ))
            }
        };
        within("fresh_for", self.fresh_for, 0, 3_600)?;
        within("sync_every", self.sync_every, 10, 86_400)?;
        within("timeout", self.timeout, 10, 3_600)?;
        within("scan_timeout", self.scan_timeout, 1, 300)?;
        let (min, max) = (1u64 << 20, 64u64 << 30);
        if !(min..=max).contains(&self.max_fetch.bytes()) {
            return Err(format!(
                "mirrors.max_fetch: {}, must be from 1MiB to 64GiB",
                self.max_fetch
            ));
        }
        Ok(())
    }
}

/// `signers`: the programs the device backends run.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignersConfig {
    #[serde(default)]
    pub se_cryptokit: SeCryptokitConfig,
}

/// `signers.se_cryptokit`: the Secure Enclave backend (macOS).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeCryptokitConfig {
    /// The Secure Enclave helper (`writ-se`); left out: `writ-se` beside the running `writd`.
    #[serde(default)]
    helper: Option<PathBuf>,
}

impl SeCryptokitConfig {
    /// The helper's path: the one set (absolute once loaded), or `writ-se` beside the running
    /// `writd`.
    pub fn helper(&self) -> anyhow::Result<PathBuf> {
        if let Some(helper) = &self.helper {
            return Ok(helper.clone());
        }
        let me = std::env::current_exe()
            .map_err(|e| anyhow::anyhow!("cannot find writd's own path for writ-se: {e}"))?;
        let dir = me
            .parent()
            .ok_or_else(|| anyhow::anyhow!("writd's own path has no directory"))?;
        Ok(dir.join("writ-se"))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum KeystoreConfig {
    /// One age file per secret, made by `writd init`; the daemon starts sealed.
    Sealed(SealedConfig),
    /// Plain key files in a directory, generated on first start: for tests and development
    /// only, refused by release builds.
    Dev(PathBuf),
}

/// `keystore.sealed`: where the sealed keystore's two parts live.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedConfig {
    /// Every secret but the boot tier's, each its own age file, and the passphrase-wrapped
    /// identity that opens them.
    pub dir: PathBuf,
    /// The boot tier: the keys a sealed daemon authenticates itself with (the SSH host key,
    /// the TLS key), readable at a sealed start. Its own directory, so it can live apart
    /// from `dir` (another volume, a Docker secret).
    pub boot: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transports {
    pub agents: Vec<TransportConfig>,
    pub approvals: ApprovalTransports,
}

/// The approval API's listeners: SSH, HTTPS, or both. An empty list disables one; at least
/// one must be enabled, or nothing could ever be approved.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalTransports {
    #[serde(default)]
    pub ssh: Vec<TransportConfig>,
    #[serde(default)]
    pub https: Vec<TransportConfig>,
}

/// One listener: a TCP address or a Unix socket, and the addresses it accepts connections
/// from.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    #[serde(default)]
    pub tcp: Option<String>,
    #[serde(default)]
    pub unix: Option<PathBuf>,
    /// Source addresses allowed to connect (TCP only). Required on the agents' TCP
    /// listeners: anyone who reaches one could submit tickets (`0.0.0.0/0` must be written
    /// out to allow that).
    #[serde(default)]
    pub allow: Option<Vec<IpRange>>,
}

impl TransportConfig {
    /// Who may connect to this listener.
    pub fn sources(&self) -> Sources {
        match &self.allow {
            Some(ranges) => Sources::Only(ranges.clone()),
            None => Sources::Any,
        }
    }

    /// Exactly one of `tcp` and `unix`; `allow` only with `tcp`, and never empty.
    fn check(&self, at: &str) -> Result<(), String> {
        match (&self.tcp, &self.unix, &self.allow) {
            (Some(_), Some(_), _) | (None, None, _) => {
                Err(format!("{at}: needs exactly one of tcp and unix"))
            }
            (None, Some(_), Some(_)) => Err(format!(
                "{at}.allow: only for tcp (a Unix socket is guarded by its mode and the attestor)"
            )),
            (_, _, Some(ranges)) if ranges.is_empty() => Err(format!(
                "{at}.allow: empty (nobody could connect); list addresses, or 0.0.0.0/0 for anyone"
            )),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestorConfig {
    Network,
    MacosProcessChain,
    LinuxProcessChain,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherConfig {
    None,
    Macos,
    Linux,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NotifierConfig {
    /// A Telegram bot sending to one chat.
    Telegram(TelegramConfig),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramConfig {
    /// Where the bot token is: readable at a sealed start, or sealed with the other secrets.
    pub token: TokenConfig,
    /// The chat to send to: a numeric id, or `@channelname`.
    pub chat_id: String,
    /// Another Bot API server (self-hosted); default `https://api.telegram.org`.
    #[serde(default)]
    pub api_base: Option<String>,
}

/// `notifiers[].telegram.token`: the operator's choice, with no default.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TokenConfig {
    /// A file holding only the token (0600), read at start: a sealed restart is notified at
    /// once, and "unsealed" comes only from the real daemon; whoever holds the file can send
    /// as the bot. Put it in the boot tier's directory.
    Boot(PathBuf),
    /// A sealed secret of this id (added with `writ admin token <id>`), read at unseal: no
    /// notification before.
    Sealed(writ_core::names::KeyId),
}

/// The directory a configuration file is in: `.` for a bare name (`writd.yaml`), whose
/// parent is the empty path, not none.
fn directory_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

impl Config {
    /// Reads the file and resolves relative paths against its directory.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        // Whoever can write it decides who may connect and which files grant authority.
        let text = writ_platform::fs::read_authority(path, "configuration")?;
        let mut config: Config = writ_core::yaml::parse_yaml(&text)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        // Absolute: the daemon hands these paths to git, which resolves a relative one from
        // wherever it runs (a relative `core.hooksPath` is looked up inside the repository,
        // where there is no hook, and git then takes the push unchecked).
        let base = std::path::absolute(directory_of(path)).map_err(|e| {
            anyhow::anyhow!("{}: cannot resolve its directory: {e}", path.display())
        })?;
        let base = base.as_path();
        let resolve = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        };
        resolve(&mut config.state_dir);
        resolve(&mut config.policy);
        resolve(&mut config.approvers);
        resolve(&mut config.readers);
        if let Some(ca_certs) = &mut config.mirrors.ca_certs {
            resolve(ca_certs);
        }
        if let Some(helper) = &mut config.signers.se_cryptokit.helper {
            resolve(helper);
        }
        match &mut config.keystore {
            KeystoreConfig::Sealed(sealed) => {
                resolve(&mut sealed.dir);
                resolve(&mut sealed.boot);
            }
            KeystoreConfig::Dev(dir) => resolve(dir),
        }
        for notifier in &mut config.notifiers {
            match notifier {
                NotifierConfig::Telegram(telegram) => {
                    if let TokenConfig::Boot(file) = &mut telegram.token {
                        resolve(file);
                    }
                }
            }
        }
        let transports = &mut config.transports;
        for transport in transports
            .agents
            .iter_mut()
            .chain(transports.approvals.ssh.iter_mut())
            .chain(transports.approvals.https.iter_mut())
        {
            if let Some(socket) = &mut transport.unix {
                resolve(socket);
            }
        }
        let fail = |why: String| anyhow::anyhow!("{}: {why}", path.display());
        if config.signing_keys.is_some() {
            return Err(fail(
                "signing_keys: moved to the policy in M6.2: declare each key under the policy's \
                 keys.<id> (use: signing, with its format, algorithm, hash and backend), and \
                 remove it here"
                    .to_owned(),
            ));
        }
        if config.mirrors.known_hosts.is_some() {
            return Err(fail(
                "mirrors.known_hosts: moved to the policy in M6.2: the upstream host keys are \
                 its upstream_hosts (writ admin host add pins one), and the file is no longer \
                 read: remove the key here"
                    .to_owned(),
            ));
        }
        // Each notifier's settings checked now, as the notifier will read them; a sealed token
        // belongs to one notifier (two sharing one: the second would never get it).
        let mut sealed_tokens = std::collections::BTreeSet::new();
        for (i, notifier) in config.notifiers.iter().enumerate() {
            let NotifierConfig::Telegram(telegram) = notifier;
            writ_platform::notify::telegram::check_settings(
                &telegram.chat_id,
                telegram.api_base.as_deref(),
            )
            .map_err(|e| fail(format!("notifiers[{i}].telegram: {e}")))?;
            if let TokenConfig::Sealed(id) = &telegram.token
                && !sealed_tokens.insert(id.clone())
            {
                return Err(fail(format!(
                    "notifiers[{i}].telegram.token: sealed token {id} is another notifier's \
                     already: give each its own"
                )));
            }
        }
        let listeners = [
            ("transports.agents", &config.transports.agents),
            ("transports.approvals.ssh", &config.transports.approvals.ssh),
            (
                "transports.approvals.https",
                &config.transports.approvals.https,
            ),
        ];
        for (name, list) in listeners {
            for (i, transport) in list.iter().enumerate() {
                transport.check(&format!("{name}[{i}]")).map_err(fail)?;
                // Every caller of it would be turned away: said at start instead.
                if transport.unix.is_some() && matches!(config.attestor, AttestorConfig::Network) {
                    return Err(fail(format!(
                        "{name}[{i}].unix: the network attestor can't attest a Unix socket's \
                         callers; local mode's attestor does (attestor: macos_process_chain or \
                         linux_process_chain)"
                    )));
                }
            }
        }
        for (i, agents) in config.transports.agents.iter().enumerate() {
            if agents.tcp.is_some() && agents.allow.is_none() {
                return Err(fail(format!(
                    "transports.agents[{i}].allow: required on a TCP listener (who may submit \
                     tickets); list the agents' addresses, or 0.0.0.0/0 for anyone"
                )));
            }
        }
        if config.transports.agents.is_empty() {
            anyhow::bail!(
                "{}: transports.agents needs at least one listener",
                path.display()
            );
        }
        if config.max_pending == 0 {
            return Err(fail(
                "max_pending: 0, must be at least 1 (no ticket could ever wait for the approver)"
                    .to_owned(),
            ));
        }
        let (floor, ceiling) = (
            writ_core::fit::MIN_TTL_FLOOR,
            writ_core::fit::MIN_TTL_CEILING,
        );
        if config.min_ttl < floor || config.min_ttl > ceiling {
            return Err(fail(format!(
                "min_ttl: {}, must be from {floor} to {ceiling}",
                config.min_ttl
            )));
        }
        config.submissions.limits().check().map_err(fail)?;
        if config.max_active_per_source == Some(0) {
            return Err(fail(
                "max_active_per_source: 0, must be at least 1 (no lease could ever be granted)"
                    .to_owned(),
            ));
        }
        if config.renew_grace > writ_core::fit::RENEW_GRACE_CEILING {
            return Err(fail(format!(
                "renew_grace: {}, must be at most {}",
                config.renew_grace,
                writ_core::fit::RENEW_GRACE_CEILING
            )));
        }
        config.mirrors.check().map_err(fail)?;
        let per_lease = config.sign_requests.per_lease;
        if !(1..=writ_gateway::MAX_SIGN_REQUESTS).contains(&per_lease) {
            return Err(fail(format!(
                "sign_requests.per_lease: {per_lease}, must be from 1 to {}",
                writ_gateway::MAX_SIGN_REQUESTS
            )));
        }
        let approvals = &config.transports.approvals;
        if approvals.ssh.is_empty() && approvals.https.is_empty() {
            anyhow::bail!(
                "{}: transports.approvals.ssh and transports.approvals.https are both disabled: \
                 nothing could ever be approved",
                path.display()
            );
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(text: &str) -> anyhow::Result<Config> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("writd.yaml");
        std::fs::write(&path, text)?;
        Config::load(&path)
    }

    const MINIMAL: &str = "state_dir: data\npolicy: policy.yaml\napprovers: approvers\n\
        readers: readers\nkeystore: { dev: keys }\n\
        transports: { agents: [{ tcp: \"127.0.0.1:0\", allow: [127.0.0.1] }], approvals: { ssh: [{ tcp: \"127.0.0.1:0\" }] } }\n\
        attestor: network\nsession_watcher: none\n";

    #[test]
    fn reads_the_minimal_config_with_defaults() {
        let config = load(MINIMAL).unwrap();
        assert_eq!(config.decisions, Decisions::Signed);
        assert_eq!(config.max_pending, writ_approval::DEFAULT_MAX_PENDING);
        assert!(config.state_dir.is_absolute());
        assert!(config.readers.is_absolute());
        assert!(config.notifiers.is_empty());
        let agents = &config.transports.agents[0];
        assert_eq!(
            agents.sources(),
            Sources::Only(vec!["127.0.0.1".parse().unwrap()])
        );
        assert_eq!(config.transports.approvals.ssh[0].sources(), Sources::Any);
    }

    #[test]
    fn submission_rates_default_to_one_person_s_and_are_bounded() {
        let config = load(MINIMAL).unwrap();
        assert_eq!(
            config.submissions.limits(),
            writ_approval::SubmissionLimits::default()
        );
        let with = |yaml: &str| load(&format!("{MINIMAL}{yaml}\n"));
        let set = with("submissions: { per_source: 30, in_all: 200 }").unwrap();
        assert_eq!(
            set.submissions.limits(),
            writ_approval::SubmissionLimits {
                per_source: 30,
                in_all: 200
            }
        );
        // One given, the other keeps its default.
        let one = with("submissions: { in_all: 120 }").unwrap();
        assert_eq!(one.submissions.per_source, 10);
        // Both bounds, on both sides.
        assert!(with("submissions: { per_source: 1, in_all: 1 }").is_ok());
        assert!(with("submissions: { per_source: 1000, in_all: 10000 }").is_ok());
        for (yaml, expected) in [
            (
                "submissions: { per_source: 0 }",
                "submissions.per_source: 0, must be from 1 to 1000",
            ),
            (
                "submissions: { in_all: 0 }",
                "submissions.in_all: 0, must be from 1 to 10000",
            ),
            (
                "submissions: { per_source: 1001 }",
                "submissions.per_source: 1001, must be from 1 to 1000",
            ),
            (
                "submissions: { in_all: 10001 }",
                "submissions.in_all: 10001, must be from 1 to 10000",
            ),
            ("submissions: { per_minute: 5 }", "unknown field"),
        ] {
            let error = format!("{:#}", with(yaml).unwrap_err());
            assert!(error.contains(expected), "{yaml}: {error}");
        }
    }

    #[test]
    fn a_bare_config_name_is_in_the_current_directory() {
        // `writd run writd.yaml`, as the operator guide says it (found by `make e2e`: the
        // empty parent of a bare name could not be made absolute).
        assert_eq!(directory_of(Path::new("writd.yaml")), Path::new("."));
        assert_eq!(directory_of(Path::new("dev/writd.yaml")), Path::new("dev"));
        assert_eq!(
            directory_of(Path::new("/etc/writd.yaml")),
            Path::new("/etc")
        );
        assert_eq!(directory_of(Path::new("/")), Path::new("."));
        assert!(std::path::absolute(directory_of(Path::new("writd.yaml"))).is_ok());
        // any error: the standard library refuses an empty path; that refusal was the bug.
        assert!(std::path::absolute(Path::new("")).is_err());
    }

    #[test]
    fn a_config_named_by_a_relative_path_gives_absolute_paths() {
        // `make run` passes `dev/writd.yaml`: every path the daemon hands to git must still
        // be absolute (a relative hooks path would be looked up inside the repository).
        let dir = tempfile::tempdir_in(".").unwrap();
        let name = dir.path().file_name().unwrap().to_owned();
        let with_ca = format!("{MINIMAL}mirrors: {{ ca_certs: upstream_ca.pem }}\n");
        assert_ne!(with_ca, MINIMAL);
        std::fs::write(dir.path().join("writd.yaml"), with_ca).unwrap();
        let relative = Path::new(&name).join("writd.yaml");
        assert!(relative.is_relative());
        let config = Config::load(&relative).unwrap();
        for path in [
            &config.state_dir,
            &config.policy,
            &config.approvers,
            &config.readers,
            config.mirrors.ca_certs.as_ref().unwrap(),
        ] {
            assert!(path.is_absolute(), "{}", path.display());
            assert!(
                path.starts_with(std::env::current_dir().unwrap()),
                "{}",
                path.display()
            );
        }
    }

    #[test]
    fn mirror_bounds_have_defaults_and_are_bounded_on_both_sides() {
        let config = load(MINIMAL).unwrap();
        let mirrors = &config.mirrors;
        assert!(mirrors.ca_certs.is_none());
        assert_eq!(mirrors.git, PathBuf::from("/usr/bin/git"));
        assert_eq!(mirrors.ssh, PathBuf::from("/usr/bin/ssh"));
        assert_eq!(mirrors.fresh_for.seconds(), 10);
        assert_eq!(mirrors.sync_every.seconds(), 300);
        assert_eq!(mirrors.timeout.seconds(), 300);
        assert_eq!(mirrors.max_fetch.bytes(), 1 << 30);
        assert_eq!(mirrors.scan_timeout.seconds(), 30);
        let with = |yaml: &str| load(&format!("{MINIMAL}mirrors: {{ {yaml} }}\n"));
        for good in [
            "fresh_for: 0s",
            "fresh_for: 1h",
            "sync_every: 10s",
            "sync_every: 1d",
            "timeout: 10s",
            "timeout: 1h",
            "max_fetch: 1MiB",
            "max_fetch: 64GiB",
            "scan_timeout: 1s",
            "scan_timeout: 5m",
            "ssh: /opt/openssh/bin/ssh",
            "git: /opt/homebrew/bin/git",
        ] {
            assert!(with(good).is_ok(), "{good}");
        }
        for (bad, expected) in [
            (
                "fresh_for: 61m",
                "mirrors.fresh_for: 61m, must be from 0s to 1h",
            ),
            (
                "sync_every: 9s",
                "mirrors.sync_every: 9s, must be from 10s to 1d",
            ),
            (
                "sync_every: 25h",
                "mirrors.sync_every: 25h, must be from 10s to 1d",
            ),
            ("timeout: 9s", "mirrors.timeout: 9s, must be from 10s to 1h"),
            (
                "timeout: 61m",
                "mirrors.timeout: 61m, must be from 10s to 1h",
            ),
            (
                "max_fetch: 1048575",
                "mirrors.max_fetch: 1048575 bytes, must be from 1MiB",
            ),
            ("max_fetch: 68719476737", "must be from 1MiB to 64GiB"),
            (
                "scan_timeout: 0s",
                "mirrors.scan_timeout: 0s, must be from 1s to 5m",
            ),
            (
                "scan_timeout: 301s",
                "mirrors.scan_timeout: 301s, must be from 1s to 5m",
            ),
            ("depth: 1", "unknown field"),
            ("git: git", "mirrors.git: git, must be an absolute path"),
            (
                "git: bin/git",
                "mirrors.git: bin/git, must be an absolute path",
            ),
            ("ssh: ssh", "mirrors.ssh: ssh, must be an absolute path"),
            (
                "ssh: bin/ssh",
                "mirrors.ssh: bin/ssh, must be an absolute path",
            ),
        ] {
            let error = format!("{:#}", with(bad).unwrap_err());
            assert!(error.contains(expected), "{bad}: {error}");
        }
    }

    #[test]
    fn the_keys_that_moved_to_the_policy_are_refused_naming_their_new_place() {
        for (yaml, expected) in [
            (
                "signing_keys: { agent-01: { format: ssh, algorithm: ed25519 } }",
                "signing_keys: moved to the policy in M6.2: declare each key under the policy's \
                 keys.<id>",
            ),
            (
                "signing_keys: {}",
                "signing_keys: moved to the policy in M6.2",
            ),
            (
                "mirrors: { known_hosts: upstream_known_hosts }",
                "mirrors.known_hosts: moved to the policy in M6.2: the upstream host keys are its \
                 upstream_hosts",
            ),
        ] {
            let error = format!("{:#}", load(&format!("{MINIMAL}{yaml}\n")).unwrap_err());
            assert!(error.contains(expected), "{yaml}: {error}");
        }
    }

    #[test]
    fn max_pending_is_at_least_one() {
        let with = |yaml: &str| load(&format!("{MINIMAL}{yaml}\n"));
        assert_eq!(with("max_pending: 1").unwrap().max_pending, 1);
        assert_eq!(with("max_pending: 100000").unwrap().max_pending, 100_000);
        let error = format!("{:#}", with("max_pending: 0").unwrap_err());
        assert!(
            error.contains("max_pending: 0, must be at least 1"),
            "{error}"
        );
    }

    #[test]
    fn min_ttl_defaults_to_five_minutes_and_is_bounded_on_both_sides() {
        let with = |yaml: &str| load(&format!("{MINIMAL}{yaml}\n"));
        assert_eq!(load(MINIMAL).unwrap().min_ttl.seconds(), 300);
        assert_eq!(with("min_ttl: 10s").unwrap().min_ttl.seconds(), 10);
        assert_eq!(with("min_ttl: 1d").unwrap().min_ttl.seconds(), 86_400);
        for (yaml, said) in [
            ("min_ttl: 9s", "min_ttl: 9s, must be from 10s to 1d"),
            ("min_ttl: 86401s", "min_ttl: 86401s, must be from 10s to 1d"),
        ] {
            let error = format!("{:#}", with(yaml).unwrap_err());
            assert!(error.contains(said), "{yaml}: {error}");
        }
    }

    #[test]
    fn max_active_per_source_and_renew_grace_are_bounded_on_both_sides() {
        let with = |yaml: &str| load(&format!("{MINIMAL}{yaml}\n"));
        let defaults = load(MINIMAL).unwrap();
        assert_eq!(defaults.max_active_per_source, None);
        assert_eq!(defaults.renew_grace.seconds(), 86_400);
        assert_eq!(
            with("max_active_per_source: 1")
                .unwrap()
                .max_active_per_source,
            Some(1)
        );
        assert_eq!(with("renew_grace: 0s").unwrap().renew_grace.seconds(), 0);
        assert_eq!(
            with("renew_grace: 7d").unwrap().renew_grace.seconds(),
            7 * 86_400
        );
        for (yaml, said) in [
            (
                "max_active_per_source: 0",
                "max_active_per_source: 0, must be at least 1",
            ),
            (
                "renew_grace: 604801s",
                "renew_grace: 604801s, must be at most 7d",
            ),
        ] {
            let error = format!("{:#}", with(yaml).unwrap_err());
            assert!(error.contains(said), "{yaml}: {error}");
        }
    }

    #[test]
    fn sign_requests_per_lease_default_to_four_and_are_bounded() {
        assert_eq!(load(MINIMAL).unwrap().sign_requests.per_lease, 4);
        let with = |yaml: &str| load(&format!("{MINIMAL}{yaml}\n"));
        assert_eq!(
            with("sign_requests: { per_lease: 1 }")
                .unwrap()
                .sign_requests
                .per_lease,
            1
        );
        assert_eq!(
            with("sign_requests: { per_lease: 16 }")
                .unwrap()
                .sign_requests
                .per_lease,
            16
        );
        for (yaml, expected) in [
            (
                "sign_requests: { per_lease: 0 }",
                "sign_requests.per_lease: 0, must be from 1 to 16",
            ),
            (
                "sign_requests: { per_lease: 17 }",
                "sign_requests.per_lease: 17, must be from 1 to 16",
            ),
            ("sign_requests: { in_all: 32 }", "unknown field"),
        ] {
            let error = format!("{:#}", with(yaml).unwrap_err());
            assert!(error.contains(expected), "{yaml}: {error}");
        }
    }

    #[test]
    fn a_tcp_agents_listener_names_who_may_connect() {
        let agents = "agents: [{ tcp: \"127.0.0.1:0\", allow: [127.0.0.1] }]";
        for (replacement, expected) in [
            (
                "agents: [{ tcp: \"127.0.0.1:0\" }]",
                "transports.agents[0].allow: required on a TCP listener",
            ),
            (
                "agents: [{ tcp: \"127.0.0.1:0\", allow: [] }]",
                "transports.agents[0].allow: empty",
            ),
            (
                "agents: [{ tcp: \"127.0.0.1:0\", allow: [10.0.0.1/24] }]",
                "host bits set",
            ),
            (
                "agents: [{ tcp: \"127.0.0.1:0\", unix: /tmp/x.sock, allow: [127.0.0.1] }]",
                "transports.agents[0]: needs exactly one of tcp and unix",
            ),
            (
                "agents: [{ allow: [127.0.0.1] }]",
                "transports.agents[0]: needs exactly one of tcp and unix",
            ),
            (
                "agents: [{ unix: /tmp/x.sock, allow: [127.0.0.1] }]",
                "transports.agents[0].allow: only for tcp",
            ),
        ] {
            let e = load(&MINIMAL.replace(agents, replacement))
                .unwrap_err()
                .to_string();
            assert!(e.contains(expected), "{replacement}: {e}");
        }
        // Anyone, written out.
        let open = load(&MINIMAL.replace(
            agents,
            "agents: [{ tcp: \"127.0.0.1:0\", allow: [0.0.0.0/0, \"::/0\"] }]",
        ))
        .unwrap();
        assert!(
            open.transports.agents[0]
                .sources()
                .allows(Some("203.0.113.9".parse().unwrap()))
        );
        // A Unix socket needs no list, and local mode's attestor.
        let local = MINIMAL
            .replace(agents, "agents: [{ unix: run/agents.sock }]")
            .replace("attestor: network", "attestor: macos_process_chain");
        let local = load(&local).unwrap();
        assert!(
            local.transports.agents[0]
                .unix
                .as_ref()
                .unwrap()
                .is_absolute()
        );
        // Under the network attestor, every caller would be turned away: refused.
        for (from, to, at) in [
            (
                agents,
                "agents: [{ unix: run/agents.sock }]",
                "transports.agents[0]",
            ),
            (
                "approvals: { ssh: [{ tcp: \"127.0.0.1:0\" }] }",
                "approvals: { ssh: [{ tcp: \"127.0.0.1:0\" }, { unix: run/a.sock }] }",
                "transports.approvals.ssh[1]",
            ),
        ] {
            let text = MINIMAL.replace(from, to);
            assert_ne!(text, MINIMAL);
            let error = format!("{:#}", load(&text).unwrap_err());
            assert!(
                error.ends_with(&format!(
                    "{at}.unix: the network attestor can't attest a Unix socket's callers; \
                     local mode's attestor does (attestor: macos_process_chain or \
                     linux_process_chain)"
                )),
                "{error}"
            );
        }
    }

    #[test]
    fn reads_a_telegram_notifier_with_its_token_boot_or_sealed() {
        let config = load(&format!(
            "{MINIMAL}notifiers:\n  - telegram: {{ token: {{ boot: boot/tg }}, chat_id: \"-100123\" }}\n  \
             - telegram: {{ token: {{ sealed: telegram-01 }}, chat_id: \"7\" }}\n"
        ))
        .unwrap();
        let [
            NotifierConfig::Telegram(boot),
            NotifierConfig::Telegram(sealed),
        ] = config.notifiers.as_slice()
        else {
            panic!("two telegram notifiers expected");
        };
        assert!(matches!(&boot.token, TokenConfig::Boot(file) if file.is_absolute()));
        assert_eq!(boot.chat_id, "-100123");
        assert!(matches!(&sealed.token, TokenConfig::Sealed(id) if id.as_str() == "telegram-01"));
        // The choice is required, and it is one of the two; an id is a plain name.
        for (bad, why) in [
            (
                "{ chat_id: \"7\" }",
                "notifiers[0].telegram: line 9 column 27: missing field `token`",
            ),
            (
                "{ token_file: tg, chat_id: \"7\" }",
                "notifiers[0].telegram.token_file: line 9 column 27: unknown field `token_file`, \
                 expected one of token, chat_id, api_base",
            ),
            (
                "{ token: {}, chat_id: \"7\" }",
                "notifiers[0].telegram.token: line 9 column 35: expected string key for \
                 externally tagged enum",
            ),
            (
                "{ token: { boot: a, sealed: b }, chat_id: \"7\" }",
                "notifiers[0].telegram.token.boot: line 9 column 45: expected end of mapping \
                 after enum variant value",
            ),
            (
                "{ token: { sealed: ../escape }, chat_id: \"7\" }",
                "notifiers[0].telegram.token.sealed: line 9 column 44: invalid key id \
                 \"../escape\": only letters, digits, '.', '_' and '-' are allowed",
            ),
        ] {
            let error = load(&format!("{MINIMAL}notifiers: [{{ telegram: {bad} }}]\n"))
                .unwrap_err()
                .to_string();
            assert!(
                error.ends_with(&format!("writd.yaml: {why}")),
                "{bad}: {error}"
            );
        }
        let error = format!(
            "{:#}",
            load(&format!(
                "{MINIMAL}notifiers: [{{ ntfy: \"https://x/y\" }}]\n"
            ))
            .unwrap_err()
        );
        assert!(error.contains("unknown variant `ntfy`"), "{error}");
        // Checked at load as the notifier reads them, not found missing at unseal (the review
        // after M5.5): the chat id, the Bot API URL, one notifier per sealed token.
        for (notifiers, why) in [
            (
                "[{ telegram: { token: { sealed: t-01 }, chat_id: \"seven\" } }]",
                "notifiers[0].telegram: invalid configuration: invalid Telegram chat id",
            ),
            (
                "[{ telegram: { token: { sealed: t-01 }, chat_id: \"7\", api_base: \"http://bots.example.org\" } }]",
                "notifiers[0].telegram: invalid configuration: invalid Telegram Bot API base URL",
            ),
            (
                "[{ telegram: { token: { sealed: t-01 }, chat_id: \"7\" } }, \
                  { telegram: { token: { sealed: t-01 }, chat_id: \"8\" } }]",
                "notifiers[1].telegram.token: sealed token t-01 is another notifier's already",
            ),
        ] {
            let error = format!(
                "{:#}",
                load(&format!("{MINIMAL}notifiers: {notifiers}\n")).unwrap_err()
            );
            assert!(error.contains(why), "{notifiers}: {error}");
        }
        // Two notifiers, two tokens: fine.
        load(&format!(
            "{MINIMAL}notifiers: [{{ telegram: {{ token: {{ sealed: t-01 }}, chat_id: \"7\" }} }}, \
             {{ telegram: {{ token: {{ sealed: t-02 }}, chat_id: \"8\" }} }}]\n"
        ))
        .unwrap();
    }

    /// What the parser says it expects instead of a probe key or value: the fields of a map,
    /// or the values of an enumeration.
    fn expected(doc: &str) -> Vec<String> {
        let error = writ_core::yaml::parse_yaml::<Config>(doc)
            .unwrap_err()
            .to_string();
        let (_, list) = error
            .split_once("expected one of ")
            .unwrap_or_else(|| panic!("no list of what is expected in: {error}"));
        list.split(", ")
            .map(|name| name.trim().trim_matches('`').to_owned())
            .collect()
    }

    /// Every key of writd.yaml, as the reference writes it. The keys come from the parser
    /// itself (a probe key makes it list the fields it expects), so a new field shows up
    /// without anyone listing it; a new section is expanded by adding it below.
    fn writd_keys() -> std::collections::BTreeSet<String> {
        let mut code = std::collections::BTreeSet::new();
        let mut section = |doc: &str, prefix: &str, sections: &[&str]| {
            for name in expected(doc) {
                if !sections.contains(&name.as_str()) {
                    code.insert(format!("{prefix}{name}"));
                }
            }
        };
        section(
            "__probe__: 0",
            "",
            &[
                "submissions",
                "sign_requests",
                "keystore",
                "mirrors",
                "signers",
                "transports",
                "notifiers",
            ],
        );
        section("signers: { __probe__: 0 }", "signers.", &["se_cryptokit"]);
        section(
            "signers: { se_cryptokit: { __probe__: 0 } }",
            "signers.se_cryptokit.",
            &[],
        );
        section("submissions: { __probe__: 0 }", "submissions.", &[]);
        section("sign_requests: { __probe__: 0 }", "sign_requests.", &[]);
        section("keystore: { __probe__: 0 }", "keystore.", &["sealed"]);
        section(
            "keystore: { sealed: { __probe__: 0 } }",
            "keystore.sealed.",
            &[],
        );
        section("mirrors: { __probe__: 0 }", "mirrors.", &[]);
        section(
            "transports: { __probe__: 0 }",
            "transports.",
            &["approvals"],
        );
        section(
            "transports: { approvals: { __probe__: 0 } }",
            "transports.approvals.",
            &[],
        );
        // The three lists hold listeners, written once as `<listener>.…`.
        section(
            "transports: { agents: [{ __probe__: 0 }] }",
            "<listener>.",
            &[],
        );
        assert_eq!(
            expected("notifiers: [{ __probe__: 0 }]"),
            ["telegram"],
            "a new notifier: probe it"
        );
        section(
            "notifiers: [{ telegram: { __probe__: 0 } }]",
            "notifiers[].telegram.",
            &["token"],
        );
        section(
            "notifiers: [{ telegram: { token: { __probe__: 0 } } }]",
            "notifiers[].telegram.token.",
            &[],
        );
        // Read only to be refused, naming where they moved (M6.2): not keys.
        code.remove("signing_keys");
        code.remove("mirrors.known_hosts");
        assert!(code.len() > 25, "{code:?}");
        code
    }

    #[test]
    fn every_writd_yaml_key_is_in_the_operator_reference() {
        // AGENTS.md rule 19: every key the parser takes has its row in
        // docs/operators/writd-yaml.md and in docs/testing.md's configuration coverage
        // registry, and every row names a key it takes.
        let code = writd_keys();
        let page = include_str!("../../../docs/operators/writd-yaml.md");
        let rows: Vec<(&str, &str)> = page
            .lines()
            .filter_map(|line| line.strip_prefix("| `"))
            .filter_map(|rest| Some((rest.split_once('`')?.0, rest)))
            .filter(|(key, _)| !key.starts_with("WRIT_"))
            .collect();
        let listed: std::collections::BTreeSet<String> =
            rows.iter().map(|(key, _)| (*key).to_owned()).collect();
        assert_eq!(listed.len(), rows.len(), "a key with two rows");
        let testing = include_str!("../../../docs/testing.md");
        let (_, registry) = testing
            .split_once("## Configuration coverage: every key")
            .expect("the registry section in docs/testing.md");
        let registry = registry.split_once("\n## ").map_or(registry, |(r, _)| r);
        let covered: std::collections::BTreeSet<String> = registry
            .lines()
            .filter_map(|line| line.strip_prefix("| `writd.yaml: "))
            .filter_map(|rest| rest.split('`').next())
            .map(str::to_owned)
            .collect();
        for (what, keys) in [
            ("docs/operators/writd-yaml.md", &listed),
            (
                "docs/testing.md's configuration coverage registry",
                &covered,
            ),
        ] {
            let missing: Vec<&String> = code.difference(keys).collect();
            let unknown: Vec<&String> = keys.difference(&code).collect();
            assert!(
                missing.is_empty() && unknown.is_empty(),
                "{what}: keys the parser takes without a row {missing:?}; rows for keys it \
                 doesn't take {unknown:?}"
            );
        }
        // Each value an enumerated key takes is named in its row.
        for (key, doc) in [
            ("decisions", "decisions: __probe__"),
            ("attestor", "attestor: __probe__"),
            ("session_watcher", "session_watcher: __probe__"),
        ] {
            let (_, row) = rows.iter().find(|(k, _)| *k == key).expect("its row");
            for value in expected(doc) {
                assert!(row.contains(&format!("`{value}`")), "{key}: `{value}`");
            }
        }
    }

    /// The template with every commented-out setting (`# key: value`, `#   - key:`) taken in:
    /// prose comments start with a capital or hold no `key:` first.
    fn uncommented(template: &str) -> String {
        template
            .lines()
            .map(|line| {
                let indent = line.len() - line.trim_start().len();
                let Some(rest) = line.trim_start().strip_prefix("# ") else {
                    return line.to_owned();
                };
                let key = rest.trim_start().trim_start_matches("- ");
                let name: String = key
                    .chars()
                    .take_while(|c| c.is_ascii_lowercase() || *c == '_')
                    .collect();
                if name.is_empty()
                    || !key
                        .strip_prefix(name.as_str())
                        .is_some_and(|rest| rest.starts_with(':'))
                {
                    return line.to_owned();
                }
                format!("{}{rest}", " ".repeat(indent))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_template_parses_as_is_and_with_every_default_taken_in() {
        // docs/operators/templates/writd.yaml: the required keys set, each optional one
        // commented out at its default; taken in, they change nothing but the notifier and
        // the paths an operator names (ca_certs).
        let template = include_str!("../../../docs/operators/templates/writd.yaml");
        let as_is = load(template).unwrap();
        let taken = uncommented(template);
        assert_ne!(taken, template);
        let all = load(&taken).unwrap();
        assert_eq!(all.decisions, as_is.decisions);
        assert_eq!(all.max_pending, as_is.max_pending);
        assert_eq!(all.submissions.limits(), as_is.submissions.limits());
        assert_eq!(all.sign_requests.per_lease, as_is.sign_requests.per_lease);
        let (a, b) = (&all.mirrors, &as_is.mirrors);
        assert_eq!(
            (
                &a.git,
                &a.ssh,
                a.fresh_for,
                a.sync_every,
                a.timeout,
                a.max_fetch
            ),
            (
                &b.git,
                &b.ssh,
                b.fresh_for,
                b.sync_every,
                b.timeout,
                b.max_fetch
            ),
            "a commented-out value is not the default"
        );
        assert!(all.mirrors.ca_certs.is_some());
        assert_eq!(all.notifiers.len(), 1);
        for key in writd_keys() {
            let name = key.rsplit('.').next().unwrap();
            assert!(
                template.contains(&format!("{name}:")),
                "{key}: not in the template"
            );
        }
    }

    #[test]
    fn errors_name_the_field() {
        let e = load(&format!("{MINIMAL}decisions: maybe\n"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("decisions"), "{e}");
        let e = load(&format!("{MINIMAL}notifer: []\n"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("notifer"), "{e}");
        let e = load(&MINIMAL.replace(
            "approvals: { ssh: [{ tcp: \"127.0.0.1:0\" }] }",
            "approvals: { ssh: [], https: [] }",
        ))
        .unwrap_err()
        .to_string();
        assert!(e.contains("both disabled"), "{e}");
        let https_only = MINIMAL.replace("approvals: { ssh:", "approvals: { https:");
        let config = load(&https_only).unwrap();
        assert!(config.transports.approvals.ssh.is_empty());
        assert_eq!(config.transports.approvals.https.len(), 1);
    }
}
