//! `writd.yaml`: the daemon's configuration. Errors name the field; unknown fields are
//! refused. Relative paths are relative to the configuration file's directory.
//!
//! ```yaml
//! state_dir: data                    # leases.db, audit.jsonl, repos/, run/
//! policy: policy.yaml                # repo registry and templates
//! approvers: approvers               # allowed_signers format
//! decisions: signed                  # signed | open: refusals and revocations
//! keystore: { dev: data/keys }       # M2: unsealed dev keystore, test only
//! transports:
//!   agents: [{ tcp: "127.0.0.1:2222" }]
//!   approvals:                       # each may be omitted or [] (disabled), not both
//!     ssh: [{ tcp: "127.0.0.1:2223" }]
//!     https: [{ tcp: "127.0.0.1:8443" }]
//! attestor: network
//! session_watcher: none
//! unlock: { passphrase: data/keys/data-key.age }   # used from M5
//! notifiers:
//!   - telegram: { token_file: data/keys/telegram-token, chat_id: "123456789" }
//! ```

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;
use writ_proto::Decisions;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub state_dir: PathBuf,
    pub policy: PathBuf,
    pub approvers: PathBuf,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TransportConfig {
    Tcp(String),
    Unix(PathBuf),
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
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let mut config: Config = writ_core::config::parse_yaml(&text)
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
            if let TransportConfig::Unix(socket) = transport {
                resolve(socket);
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
        keystore: { dev: keys }\n\
        transports: { agents: [{ tcp: \"127.0.0.1:0\" }], approvals: { ssh: [{ tcp: \"127.0.0.1:0\" }] } }\n\
        attestor: network\nsession_watcher: none\n";

    #[test]
    fn reads_the_minimal_config_with_defaults() {
        let config = load(MINIMAL).unwrap();
        assert_eq!(config.decisions, Decisions::Signed);
        assert_eq!(config.max_pending, writ_approval::DEFAULT_MAX_PENDING);
        assert!(config.state_dir.is_absolute());
        assert!(config.notifiers.is_empty());
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
