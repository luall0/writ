//! `writd.yaml`: the daemon's configuration. Errors name the field; unknown fields are
//! refused. Relative paths are relative to the configuration file's directory.
//!
//! ```yaml
//! state_dir: data                    # leases.db, audit.jsonl, repos/, run/
//! policy: policy.yaml                # repo registry and templates
//! approvers: approvers               # allowed_signers format
//! readers: readers                   # who may use the approval API (`writ reader`)
//! decisions: signed                  # signed | open: refusals and revocations
//! keystore: { dev: data/keys }       # M2: unsealed dev keystore, test only
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
    pub keystore: KeystoreConfig,
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
