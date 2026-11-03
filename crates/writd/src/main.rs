//! `writd`, the Writ daemon.
//!
//! - `writd init <writd.yaml>`: makes the sealed keystore, once (asks for its passphrase).
//! - `writd run <writd.yaml>`: the daemon (gateway, approval API, expiry timer).
//! - `writd recover <writd.yaml> <policy|approvers|readers> <file>`: puts a file in force from
//!   the host (the daemon stopped), with the keystore's passphrase.
//! - `writd host-key <writd.yaml>`: prints the gateway's host key, to pin in clients'
//!   `known_hosts`.
//! - `writd tls-fingerprint <writd.yaml>`: prints the fingerprint of the HTTPS approval API's
//!   certificate, to pin in clients' `tls_pins`.
//! - `writd upstream-keys <writd.yaml>`: prints the upstream credentials' public keys, to add
//!   on each remote.
//! - `writd signing-keys <writd.yaml>`: prints the agent signing keys' public keys, to register
//!   on the accounts that show commits as verified.
//! - `writd hook pre-receive`: the program git's pre-receive hook runs.
//! - `writd upstream-ssh <max bytes> <ssh> <args…>`: the program git runs as its ssh for
//!   an `ssh://` upstream (it caps what upstream sends).
//! - `writd upstream-credential <socket> <operation>`: the credential helper git runs for an
//!   `https://` upstream (it asks the daemon for the token, for one operation).
//!
//! Only this binary wires the crates together and reads configuration
//! (docs/architecture/overview.md).

mod authority;
mod config;
mod daemon;
mod keystore;
mod platform;
mod recover;

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use writ_approval::{Service, ServiceConfig, ServicePlatform};
use writ_core::config::PolicyConfig;
use writ_core::names::{KeyFingerprint, KeyId};
use writ_crypto::allowed_signers::AllowedSigner;
use writ_crypto::readers::Reader;
use writ_crypto::tls::TlsIdentity;
use writ_gateway::{Gateway, GatewayConfig, Role};
use writ_mirror::known_hosts::PinnedHosts;
use writ_mirror::{MirrorConfig, SyncReport};
use writ_platform::clock::system::SystemClock;
use writ_store::{AuditLog, Store};

use crate::config::Config;
use crate::keystore::Start;

/// How often pending tickets and leases are checked for expiry.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Every command `main` dispatches, with its arguments: the usage text, and the list the
/// end-to-end coverage registry is checked against (docs/end-to-end.md).
const COMMANDS: &[(&str, &str)] = &[
    ("init", "<writd.yaml>"),
    ("run", "<writd.yaml>"),
    ("recover", "<writd.yaml> <policy|approvers|readers> <file>"),
    ("host-key", "<writd.yaml>"),
    ("tls-fingerprint", "<writd.yaml>"),
    ("upstream-keys", "<writd.yaml>"),
    ("signing-keys", "<writd.yaml>"),
    ("hook", "pre-receive"),
    ("upstream-ssh", "<max bytes> <ssh> <args…>"),
    ("upstream-credential", "<socket> <get|store|erase>"),
];

/// The usage text: one line per command.
fn usage() -> String {
    COMMANDS
        .iter()
        .enumerate()
        .map(|(i, (name, args))| {
            let lead = if i == 0 { "usage: " } else { "       " };
            format!("{lead}writd {name} {args}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["hook", "pre-receive"] => {
            return u8::try_from(writ_gateway::run_pre_receive())
                .map(ExitCode::from)
                .unwrap_or(ExitCode::FAILURE);
        }
        ["upstream-ssh", rest @ ..] => {
            return u8::try_from(writ_mirror::relay::run(rest))
                .map(ExitCode::from)
                .unwrap_or(ExitCode::FAILURE);
        }
        ["upstream-credential", rest @ ..] => {
            return u8::try_from(writ_mirror::credential::helper::run(rest))
                .map(ExitCode::from)
                .unwrap_or(ExitCode::FAILURE);
        }
        ["init", config] => keystore::init(Path::new(config)),
        ["run", config] => run(Path::new(config)),
        ["recover", config, target, file] => {
            recover::recover(Path::new(config), target, Path::new(file))
        }
        ["upstream-keys", config] => upstream_keys(Path::new(config)),
        ["host-key", config] => host_key(Path::new(config)),
        ["tls-fingerprint", config] => tls_fingerprint(Path::new(config)),
        ["signing-keys", config] => signing_keys(Path::new(config)),
        _ => {
            eprintln!("{}", usage());
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("writd: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn host_key(path: &Path) -> anyhow::Result<()> {
    let config = Config::load(path)?;
    let policy = load_registry(&config)?;
    println!("{}", keystore::public(&config, &policy)?.host.to_openssh()?);
    Ok(())
}

fn tls_fingerprint(path: &Path) -> anyhow::Result<()> {
    let config = Config::load(path)?;
    let policy = load_registry(&config)?;
    println!("{}", keystore::public(&config, &policy)?.tls_fingerprint);
    Ok(())
}

/// The repos whose upstream credential is `id`.
fn repos_using<'a>(policy: &'a PolicyConfig, id: &KeyId) -> Vec<&'a str> {
    policy
        .repos()
        .iter()
        .filter(|(_, entry)| entry.upstream_credential == *id)
        .map(|(name, _)| name.as_str())
        .collect()
}

/// The templates that sign with key `id`.
fn templates_using<'a>(policy: &'a PolicyConfig, id: &KeyId) -> Vec<&'a str> {
    policy
        .templates()
        .iter()
        .filter(|(_, template)| template.signing_key.as_ref() == Some(id))
        .map(|(name, _)| name.as_str())
        .collect()
}

/// Prints each upstream credential's public key and the repos that use it: the key to add on
/// each remote (as a deploy key, or on the account).
fn upstream_keys(path: &Path) -> anyhow::Result<()> {
    let config = Config::load(path)?;
    let policy = load_registry(&config)?;
    for (id, key) in keystore::public(&config, &policy)?.upstream {
        println!(
            "{id} {} (repos: {})",
            key.to_openssh()?,
            repos_using(&policy, &id).join(", ")
        );
    }
    Ok(())
}

/// Prints each agent signing key's public key and the templates that name it: the key to
/// register on an account (as a signing key) so the remote shows its commits as verified.
fn signing_keys(path: &Path) -> anyhow::Result<()> {
    let config = Config::load(path)?;
    let policy = load_registry(&config)?;
    for (id, key) in keystore::public(&config, &policy)?.signing {
        println!(
            "{id} {} (templates: {})",
            key.to_openssh()?,
            templates_using(&policy, &id).join(", ")
        );
    }
    Ok(())
}

/// The upstream host keys the operator pinned (an authority file: whoever writes it decides
/// which servers the daemon pushes to).
fn load_pinned_hosts(config: &Config) -> anyhow::Result<PinnedHosts> {
    let path = &config.mirrors.known_hosts;
    let text = writ_platform::fs::read_authority(path, "upstream known_hosts")?;
    PinnedHosts::parse(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
}

/// The CA certificates HTTPS upstreams must chain to, when the operator chose some (an
/// authority file: whoever writes it decides which servers the daemon sends tokens to).
fn load_ca_certs(config: &Config) -> anyhow::Result<Option<String>> {
    let Some(path) = &config.mirrors.ca_certs else {
        return Ok(None);
    };
    let text = writ_platform::fs::read_authority(path, "upstream CA certificates")?;
    writ_crypto::tls::check_ca_certs(&text)
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    Ok(Some(text))
}

/// The repo registry and templates in force: what the commands that print a key need (the
/// keystore holds one key per template signing key and repo credential). The store's version
/// once `writd init` recorded one; before, the file (an authority file, checked for owner,
/// mode and links before it is believed).
fn load_registry(config: &Config) -> anyhow::Result<PolicyConfig> {
    let db = config.state_dir.join("leases.db");
    if db.exists()
        && let Some(loaded) = authority::load(&Store::open(&db)?)?
    {
        return Ok(loaded.policy);
    }
    let policy_text = writ_platform::fs::read_authority(&config.policy, "policy")?;
    authority::parse_policy(&policy_text)
        .map_err(|e| anyhow::anyhow!("{}: {e}", config.policy.display()))
}

/// Starts every listener the platform built; returns them as a set to wait on.
fn spawn_listeners(
    gateway: &Gateway,
    platform: &platform::Platform,
    tls: &Arc<TlsIdentity>,
) -> tokio::task::JoinSet<writ_gateway::Result<()>> {
    let mut servers = tokio::task::JoinSet::new();
    for (transport, sources) in &platform.approvals_https {
        tracing::info!(listener = %transport.describe(), ?sources, "approval API (HTTPS)");
        let (gateway, transport, attestor, tls, sources) = (
            gateway.clone(),
            transport.clone(),
            platform.attestor.clone(),
            tls.clone(),
            sources.clone(),
        );
        servers.spawn(async move { gateway.serve_https(transport, attestor, tls, sources).await });
    }
    for (role, listeners) in [
        (Role::Agents, &platform.agents),
        (Role::Approvals, &platform.approvals_ssh),
    ] {
        for (transport, sources) in listeners {
            tracing::info!(listener = %transport.describe(), ?role, ?sources, "SSH");
            let (gateway, transport, attestor, sources) = (
                gateway.clone(),
                transport.clone(),
                platform.attestor.clone(),
                sources.clone(),
            );
            servers.spawn(async move { gateway.serve(transport, attestor, role, sources).await });
        }
    }
    servers
}

/// Expires pending tickets and leases every [`SWEEP_INTERVAL`], off the async threads.
fn spawn_sweeper(service: Arc<Service>) {
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            ticks.tick().await;
            let service = service.clone();
            let _ = tokio::task::spawn_blocking(move || service.sweep()).await;
        }
    });
}

/// Syncs every mirror from upstream every `every` (the first right away), one after the other,
/// unless a fetch or a push synced it more recently. A failure is logged and the mirror stays
/// stale: fetches and pushes then try again, and are refused if they fail too. After a mirror
/// synced (or was fresh), its notes are brought up to date (`Gateway::reconcile_notes`): at
/// start, and every `every`.
pub(crate) fn spawn_mirror_sync(gateway: Gateway, every: Duration) {
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(every);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            // The mirrors in force at each round: a registry change replaces them.
            let Ok(mirrors) = gateway.mirrors() else {
                continue;
            };
            let repos: Vec<_> = mirrors.repos().cloned().collect();
            for repo in repos {
                match mirrors.sync_if_stale(&repo).await {
                    Ok(SyncReport::Synced { moved, more }) if !moved.is_empty() => {
                        tracing::info!(%repo, moved = moved.len().saturating_add(more), "mirror synced");
                    }
                    Ok(_) => tracing::debug!(%repo, "mirror up to date"),
                    Err(e) => {
                        tracing::warn!(%repo, error = %e, "mirror sync failed");
                        continue;
                    }
                }
                gateway.reconcile_notes(&repo).await;
            }
        }
    });
}

/// Now, by the system clock, to the second.
pub(crate) fn now() -> anyhow::Result<writ_core::units::Timestamp> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(writ_core::units::Timestamp::from_unix(i64::try_from(
        seconds,
    )?)?)
}

/// Logs go to stderr; `WRIT_LOG` filters them (`info` by default, e.g. `WRIT_LOG=debug`).
/// They are diagnostics only: decisions are in the audit log, which never goes through them.
fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("WRIT_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
}

fn run(path: &Path) -> anyhow::Result<()> {
    init_logging();
    let config = Arc::new(Config::load(path)?);
    keystore::private_dir(&config.state_dir)?;
    let store = Store::open(&config.state_dir.join("leases.db"))?;
    let loaded = match (authority::load(&store)?, &config.keystore) {
        (Some(loaded), _) => loaded,
        // The development keystore's first start: the files as they are.
        (None, config::KeystoreConfig::Dev(dir)) => authority::seed(
            &store,
            &keystore::dev_authority_key(dir)?,
            authority::read_files(&config)?,
            now()?,
        )?,
        (None, config::KeystoreConfig::Sealed(_)) => bail!(
            "{}: no authority files in force (policy, approvers, readers): `writd init` records \
             them",
            config.state_dir.display()
        ),
    };
    let pinned = load_pinned_hosts(&config)?;
    let ca_certs = load_ca_certs(&config)?;
    let start = keystore::start(&config, &loaded.policy)?;
    let repos = config.state_dir.join("repos");
    std::fs::create_dir_all(&repos)
        .with_context(|| format!("cannot create {}", repos.display()))?;

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let mirror_config = mirror_config(&config, repos, pinned, ca_certs)?;
        let platform = platform::build(&config).await?;
        let (boot, open) = match start {
            Start::Sealed(boot) => (boot, None),
            Start::Open(boot, opened) => (boot, Some(*opened)),
        };
        let host_public = boot.host.public_key().clone();
        let daemon: KeyFingerprint = host_public
            .fingerprint(writ_crypto::ssh_key::HashAlg::Sha256)
            .to_string()
            .parse()?;
        let tls = platform::tls_identity(boot.tls)?;
        log_access(&loaded.approvers, &loaded.readers);
        let readers = writ_crypto::readers::ReaderSet::new(loaded.readers);
        let service = start_service(
            &config,
            store,
            loaded.policy.clone(),
            loaded.approvers,
            loaded.in_force,
            boot.ca_public,
            daemon,
            &platform,
        )?;
        let opener = daemon::Opener::new(
            config.clone(),
            loaded.policy,
            loaded.texts,
            mirror_config,
            service.clone(),
            platform.notifier.clone(),
        );
        let unsealer: Option<Arc<dyn writ_gateway::Unsealer>> = match open {
            Some(_) => None,
            None => Some(Arc::new(opener.clone())),
        };
        let gateway = Gateway::start(
            GatewayConfig {
                host_key: boot.host,
                mirrors: None,
                unsealer,
                admin: Some(Arc::new(opener.clone())),
                hook_program: std::env::current_exe()?,
                state_dir: config.state_dir.join("run"),
                readers,
                sign_requests_per_lease: config.sign_requests.per_lease,
            },
            service.clone(),
        )
        .await?;
        opener.set_gateway(gateway.clone());
        let sealed = open.is_none();
        match open {
            Some(opened) => {
                opener
                    .open(opened, None, &writ_core::caller::CallerFacts::default())
                    .await?;
            }
            None => service.announce_sealed(),
        }

        tracing::info!(
            host_key = %host_public.to_openssh()?,
            tls_fingerprint = %tls.fingerprint(),
            sealed,
            "started"
        );
        tracing::info!(decisions = ?config.decisions, "decisions");
        let mut servers = spawn_listeners(&gateway, &platform, &tls);
        spawn_sweeper(service);
        until_stopped(&mut servers).await
    })
}

/// The approval service, sealed, on the state's store and audit log, with a boot nonce drawn
/// now.
// What the service starts with, each from its own source.
#[allow(clippy::too_many_arguments)]
fn start_service(
    config: &Config,
    store: Store,
    policy: PolicyConfig,
    approvers: Vec<AllowedSigner>,
    in_force: writ_approval::InForce,
    ca_public: writ_crypto::ssh_key::PublicKey,
    daemon: KeyFingerprint,
    platform: &platform::Platform,
) -> anyhow::Result<Arc<Service>> {
    let audit = AuditLog::open(&config.state_dir.join("audit.jsonl"))?;
    Ok(Service::new(
        ServiceConfig {
            policy,
            approvers,
            decisions: config.decisions,
            max_pending: config.max_pending,
            submissions: config.submissions.limits(),
            ca_public,
            daemon,
            in_force,
            recipient: keystore::recipient(config)?,
        },
        writ_crypto::keys::random_array()?,
        store,
        audit,
        ServicePlatform {
            notifier: platform.notifier.clone(),
            watcher: platform.watcher.clone(),
            clock: Arc::new(SystemClock),
        },
    )?)
}

/// The mirrors' configuration, from `writd.yaml`'s `mirrors` and the files it names.
fn mirror_config(
    config: &Config,
    root: std::path::PathBuf,
    pinned: PinnedHosts,
    ca_certs: Option<String>,
) -> anyhow::Result<MirrorConfig> {
    Ok(MirrorConfig {
        root,
        run_dir: config.state_dir.join("mirror"),
        relay: std::env::current_exe()?,
        git: config.mirrors.git.clone(),
        ssh: config.mirrors.ssh.clone(),
        pinned,
        ca_certs,
        fresh_for: Duration::from_secs(config.mirrors.fresh_for.seconds()),
        timeout: Duration::from_secs(config.mirrors.timeout.seconds()),
        max_fetch_bytes: config.mirrors.max_fetch.bytes(),
    })
}

/// Who may sign and who may read, in the log at startup.
fn log_access(approvers: &[AllowedSigner], readers: &[Reader]) {
    for approver in approvers {
        tracing::info!(
            fingerprint = %approver.fingerprint(),
            principals = %approver.principals,
            "approver"
        );
    }
    for reader in readers {
        tracing::info!(
            name = %reader.name,
            fingerprint = %reader.key.fingerprint(writ_crypto::ssh_key::HashAlg::Sha256),
            "reader"
        );
    }
}

/// Runs until Ctrl-C, or until a listener ends (an error: the daemon stops with it).
async fn until_stopped(
    servers: &mut tokio::task::JoinSet<writ_gateway::Result<()>>,
) -> anyhow::Result<()> {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("stopping");
            Ok(())
        }
        Some(result) = servers.join_next() => match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(anyhow::anyhow!("a listener failed: {e}")),
            Err(e) => Err(anyhow::anyhow!("a listener stopped: {e}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// The development policy: a valid one, kept in the repo.
    const POLICY: &str = include_str!("../../../dev/policy.yaml");

    /// A configuration whose files are all in a temporary directory.
    fn setup() -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let key = writ_crypto::keys::generate(writ_crypto::keys::KeyKind::Ed25519).unwrap();
        let line = key.public_key().to_openssh().unwrap();
        std::fs::write(dir.path().join("policy.yaml"), POLICY).unwrap();
        std::fs::write(dir.path().join("approvers"), format!("me {line}\n")).unwrap();
        std::fs::write(dir.path().join("readers"), format!("mac {line}\n")).unwrap();
        let yaml = dir.path().join("writd.yaml");
        std::fs::write(
            &yaml,
            "state_dir: data\npolicy: policy.yaml\napprovers: approvers\nreaders: readers\n\
             keystore: { dev: keys }\n\
             mirrors: { known_hosts: upstream_known_hosts }\n\
             transports: { agents: [{ tcp: \"127.0.0.1:0\", allow: [127.0.0.1] }], \
             approvals: { ssh: [{ tcp: \"127.0.0.1:0\" }] } }\n\
             attestor: network\nsession_watcher: none\n",
        )
        .unwrap();
        let config = Config::load(&yaml).unwrap();
        (dir, config)
    }

    fn chmod(path: &Path, bits: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
    }

    #[test]
    fn files_that_grant_authority_are_refused_if_others_can_write_them() {
        let (dir, config) = setup();
        assert_eq!(authority::read_files(&config).unwrap().len(), 3);
        for file in ["approvers", "policy.yaml", "readers"] {
            let path = dir.path().join(file);
            chmod(&path, 0o666);
            let error = authority::read_files(&config).unwrap_err().to_string();
            assert!(
                error.contains("can be written by group or others"),
                "{file}: {error}"
            );
            chmod(&path, 0o644);
            assert!(authority::read_files(&config).is_ok(), "{file} at 0644");
        }
        let yaml = dir.path().join("writd.yaml");
        chmod(&yaml, 0o664);
        let error = Config::load(&yaml).unwrap_err().to_string();
        assert!(
            error.contains("can be written by group or others"),
            "{error}"
        );
    }

    #[test]
    fn the_upstream_ca_certificates_are_an_authority_file_of_certificates_only() {
        let (dir, mut config) = setup();
        assert_eq!(
            load_ca_certs(&config).unwrap(),
            None,
            "the system's by default"
        );
        let path = dir.path().join("upstream_ca.pem");
        config.mirrors.ca_certs = Some(path.clone());
        let pem = writ_crypto::tls::generate_self_signed().unwrap().cert_pem;
        std::fs::write(&path, &pem).unwrap();
        chmod(&path, 0o644);
        assert_eq!(load_ca_certs(&config).unwrap(), Some(pem.clone()));
        chmod(&path, 0o666);
        let error = load_ca_certs(&config).unwrap_err().to_string();
        assert!(
            error.contains("can be written by group or others"),
            "{error}"
        );
        chmod(&path, 0o644);
        std::fs::write(&path, "not a certificate").unwrap();
        let error = load_ca_certs(&config).unwrap_err().to_string();
        assert!(
            error.ends_with("invalid TLS CA certificates (none)"),
            "{error}"
        );
    }

    #[test]
    fn an_approvers_file_behind_a_link_is_refused() {
        let (dir, mut config) = setup();
        let link = dir.path().join("approvers-link");
        std::os::unix::fs::symlink(dir.path().join("approvers"), &link).unwrap();
        config.approvers = link;
        let error = authority::read_files(&config).unwrap_err().to_string();
        assert!(
            error.starts_with("invalid configuration: cannot read approvers file"),
            "{error}"
        );
    }

    #[test]
    fn every_writd_command_is_in_the_end_to_end_registry() {
        // Every command `main` dispatches is used for real by an end-to-end scenario
        // (AGENTS.md rule 18): its row in docs/end-to-end.md names it.
        let doc = include_str!("../../../docs/end-to-end.md");
        let (_, section) = doc
            .split_once("## Coverage: every command and flag")
            .unwrap();
        for (name, args) in COMMANDS {
            // A fixed word is part of the command (`hook pre-receive`), a `<value>` isn't.
            let feature = if args.starts_with('<') {
                format!("writd {name}")
            } else {
                format!("writd {name} {args}")
            };
            assert!(
                section.contains(&format!("| `{feature}`")),
                "{feature} is not in docs/end-to-end.md's coverage registry"
            );
        }
        // And what main dispatches is that table: an unknown command gets the usage.
        assert_eq!(usage().lines().count(), COMMANDS.len());
    }

    #[test]
    fn the_commands_that_print_a_key_need_no_approvers_file() {
        // `writd host-key`, `tls-fingerprint` and `upstream-keys` run before the approver is
        // set up (the manual checks pin the daemon, then list the approver).
        let (dir, config) = setup();
        std::fs::remove_file(dir.path().join("approvers")).unwrap();
        assert!(load_registry(&config).is_ok());
        let error = authority::read_files(&config).unwrap_err().to_string();
        assert!(error.contains("cannot read approvers file"), "{error}");
    }

    #[test]
    fn an_approver_key_is_never_a_reader() {
        // The fixture lists the same key as approver and reader.
        let (_dir, config) = setup();
        let texts = authority::read_files(&config).unwrap();
        let approvers =
            authority::parse_approvers(&texts[&writ_core::authority::AdminTarget::Approvers])
                .unwrap();
        let readers =
            authority::parse_readers(&texts[&writ_core::authority::AdminTarget::Readers]).unwrap();
        assert_eq!(approvers[0].key.key_data(), readers[0].key.key_data());
        let error = authority::one_key_one_purpose(&approvers, &readers)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("reader mac is also an approver key"),
            "{error}"
        );
        // Different keys: fine.
        let other = writ_crypto::keys::generate(writ_crypto::keys::KeyKind::Ed25519).unwrap();
        let readers = writ_crypto::readers::parse(&format!(
            "mac {}",
            other.public_key().to_openssh().unwrap()
        ))
        .unwrap();
        assert!(authority::one_key_one_purpose(&approvers, &readers).is_ok());
    }

    #[test]
    fn no_reader_or_approver_at_all_is_a_startup_error() {
        let error = authority::parse_readers("# nobody\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("no reader key"), "{error}");
        let error = authority::parse_approvers("# nobody\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("nothing could ever be signed"), "{error}");
    }
}
