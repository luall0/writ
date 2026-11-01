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
//! submissions:                       # ticket submissions a minute (each 1 or more)
//!   per_source: 10                   # per address (an IPv6 host by its /64; local: one)
//!   in_all: 60                       # all sources together
//! sign_requests:                     # held at once (16 in all, daemon-wide)
//!   per_lease: 4                     # per lease, 1 to 16
//! keystore: { dev: data/keys }       # M2: unsealed dev keystore, test only
//! mirrors:
//!   known_hosts: upstream_known_hosts  # required: the remotes' host keys, pinned by hand
//!   ssh: /usr/bin/ssh                # the OpenSSH client, by absolute path
//!   fresh_for: 10s                   # a mirror synced this recently isn't synced again
//!   sync_every: 5m                   # background sync of every mirror
//!   timeout: 5m                      # one sync or upstream push, then git and ssh are killed
//!   max_fetch: 1GiB                  # the most one sync takes from upstream
//! transports:
//!   agents:                          # TCP: `allow` is required (`0.0.0.0/0` for anyone)
//!     - { tcp: "0.0.0.0:2222", allow: ["10.0.0.0/24"] }
//!   approvals:                       # each may be omitted or [] (disabled), not both
//!     ssh: [{ tcp: "127.0.0.1:2223" }]          # `allow` optional: readers only anyway
//!     https: [{ tcp: "127.0.0.1:8443" }]
//! attestor: network
//! session_watcher: none
//! unlock: { passphrase: data/keys/data-key.age }   # used from M5
//! notifiers:
//!   - telegram: { token_file: data/keys/telegram-token, chat_id: "123456789" }
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
    /// The submission rates, per minute; the defaults suit one person's agents.
    #[serde(default)]
    pub submissions: SubmissionsConfig,
    /// Sign requests held at once per lease.
    #[serde(default)]
    pub sign_requests: SignRequestsConfig,
    pub keystore: KeystoreConfig,
    /// The mirrors and how they reach upstream.
    pub mirrors: MirrorsConfig,
    pub transports: Transports,
    pub attestor: AttestorConfig,
    pub session_watcher: WatcherConfig,
    #[serde(default)]
    pub unlock: Option<UnlockConfig>,
    #[serde(default)]
    pub notifiers: Vec<NotifierConfig>,
}

fn default_max_pending() -> usize {
    writ_approval::DEFAULT_MAX_PENDING
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

/// `mirrors`: the upstream host keys and the bounds of a sync.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorsConfig {
    /// The upstream host keys, pinned by the operator (an authority file).
    pub known_hosts: PathBuf,
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

fn default_max_fetch() -> ByteSize {
    ByteSize::from_bytes(1 << 30)
}

impl MirrorsConfig {
    /// Each bound within what makes sense: a sync that can't finish, or a limit that bounds
    /// nothing, is a mistake.
    fn check(&self) -> Result<(), String> {
        if !self.ssh.is_absolute() {
            return Err(format!(
                "mirrors.ssh: {}, must be an absolute path (never looked up in PATH)",
                self.ssh.display()
            ));
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum KeystoreConfig {
    /// Plain key files in a directory, generated on first start: for tests and development
    /// only, refused by release builds (the sealed keystore comes in M5).
    Dev(PathBuf),
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
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherConfig {
    None,
    Macos,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum UnlockConfig {
    /// The data key wrapped under a passphrase (age scrypt), in this file.
    Passphrase(PathBuf),
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
    /// A file holding only the bot token, mode 0600 (the token is a secret; it moves into the
    /// sealed keystore in M5).
    pub token_file: PathBuf,
    /// The chat to send to: a numeric id, or `@channelname`.
    pub chat_id: String,
    /// Another Bot API server (self-hosted); default `https://api.telegram.org`.
    #[serde(default)]
    pub api_base: Option<String>,
}

impl Config {
    /// Reads the file and resolves relative paths against its directory.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        // Whoever can write it decides who may connect and which files grant authority.
        let text = writ_platform::fs::read_authority(path, "configuration")?;
        let mut config: Config = writ_core::yaml::parse_yaml(&text)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        let resolve = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        };
        resolve(&mut config.state_dir);
        resolve(&mut config.policy);
        resolve(&mut config.approvers);
        resolve(&mut config.readers);
        resolve(&mut config.mirrors.known_hosts);
        match &mut config.keystore {
            KeystoreConfig::Dev(dir) => resolve(dir),
        }
        if let Some(UnlockConfig::Passphrase(file)) = &mut config.unlock {
            resolve(file);
        }
        for notifier in &mut config.notifiers {
            match notifier {
                NotifierConfig::Telegram(telegram) => resolve(&mut telegram.token_file),
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
        config.submissions.limits().check().map_err(fail)?;
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
        readers: readers\nkeystore: { dev: keys }\nmirrors: { known_hosts: upstream_known_hosts }\n\
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
    fn mirror_bounds_have_defaults_and_are_bounded_on_both_sides() {
        let config = load(MINIMAL).unwrap();
        let mirrors = &config.mirrors;
        assert!(mirrors.known_hosts.is_absolute());
        assert_eq!(mirrors.ssh, PathBuf::from("/usr/bin/ssh"));
        assert_eq!(mirrors.fresh_for.seconds(), 10);
        assert_eq!(mirrors.sync_every.seconds(), 300);
        assert_eq!(mirrors.timeout.seconds(), 300);
        assert_eq!(mirrors.max_fetch.bytes(), 1 << 30);
        let with = |yaml: &str| {
            load(&MINIMAL.replace(
                "mirrors: { known_hosts: upstream_known_hosts }",
                &format!("mirrors: {{ known_hosts: upstream_known_hosts, {yaml} }}"),
            ))
        };
        for good in [
            "fresh_for: 0s",
            "fresh_for: 1h",
            "sync_every: 10s",
            "sync_every: 1d",
            "timeout: 10s",
            "timeout: 1h",
            "max_fetch: 1MiB",
            "max_fetch: 64GiB",
            "ssh: /opt/openssh/bin/ssh",
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
            ("depth: 1", "unknown field"),
            ("ssh: ssh", "mirrors.ssh: ssh, must be an absolute path"),
            (
                "ssh: bin/ssh",
                "mirrors.ssh: bin/ssh, must be an absolute path",
            ),
        ] {
            let error = format!("{:#}", with(bad).unwrap_err());
            assert!(error.contains(expected), "{bad}: {error}");
        }
        let without = MINIMAL.replace("mirrors: { known_hosts: upstream_known_hosts }\n", "");
        let error = format!("{:#}", load(&without).unwrap_err());
        assert!(error.contains("mirrors"), "{error}");
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
        // A Unix socket needs no list.
        let local = load(&MINIMAL.replace(agents, "agents: [{ unix: run/agents.sock }]")).unwrap();
        assert!(
            local.transports.agents[0]
                .unix
                .as_ref()
                .unwrap()
                .is_absolute()
        );
    }

    #[test]
    fn reads_a_telegram_notifier() {
        let config = load(&format!(
            "{MINIMAL}notifiers:\n  - telegram: {{ token_file: keys/tg, chat_id: \"-100123\" }}\n"
        ))
        .unwrap();
        let [NotifierConfig::Telegram(telegram)] = config.notifiers.as_slice() else {
            panic!("one telegram notifier expected");
        };
        assert!(telegram.token_file.is_absolute());
        assert_eq!(telegram.chat_id, "-100123");
        assert!(
            load(&format!(
                "{MINIMAL}notifiers: [{{ ntfy: \"https://x/y\" }}]\n"
            ))
            .is_err()
        );
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
