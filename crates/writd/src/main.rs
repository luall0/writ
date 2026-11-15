//! `writd`, the Writ daemon.
//!
//! - `writd init <writd.yaml> [--tls-backend <name>] [--ca-backend <name>]`: makes the sealed
//!   keystore, once (asks for its passphrase), its TLS key and SSH CA on those backends.
//! - `writd run <writd.yaml>`: the daemon (gateway, approval API, expiry timer).
//! - `writd recover <writd.yaml> <policy|approvers|readers> <file>`: puts a file in force from
//!   the host (the daemon stopped), with the keystore's passphrase.
//! - `writd host-key <writd.yaml>`: prints the gateway's host key, to pin in clients'
//!   `known_hosts`.
//! - `writd tls-fingerprint <writd.yaml>`: prints the fingerprint of the HTTPS approval API's
//!   certificate, to pin in clients' `tls_pins`.
//! - `writd upstream-keys <writd.yaml>`: prints the upstream credentials' public keys (the
//!   policy in force declares them), to add on each remote.
//! - `writd signing-keys <writd.yaml>`: prints the agent signing keys' public keys, to register
//!   on the accounts that show commits as verified.
//! - `writd hook pre-receive`: the program git's pre-receive hook runs.
//! - `writd upstream-ssh <max bytes> <ssh> <args…>`: the program git runs as its ssh for
//!   an `ssh://` upstream (it caps what upstream sends).
//! - `writd upstream-credential <socket> <operation>`: the credential helper git runs for an
//!   `https://` upstream (it asks the daemon for the token, for one operation).
//! - `writd upstream-tunnel <socket> <host> <port>`: the `ProxyCommand` ssh runs for an
//!   `ssh://` upstream behind a proxy (it carries ssh's stream through the daemon's socket).
//! - `writd proc-reader`: local mode on Linux, the capped helper `writd run` starts to read
//!   other users' processes (M7.1).
//!
//! Only this binary wires the crates together and reads configuration
//! (docs/architecture/overview.md).

mod authority;
mod autounseal;
mod config;
mod daemon;
mod declared;
mod hardening;
mod keystore;
mod lock;
mod platform;
mod recover;
mod supervise;
mod upgrade;

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use writ_approval::{Service, ServiceConfig, ServicePlatform};
use writ_core::config::PolicyConfig;
use writ_core::names::KeyFingerprint;
use writ_crypto::allowed_signers::AllowedSigner;
use writ_crypto::readers::Reader;
use writ_crypto::tls::TlsIdentity;
use writ_gateway::{Gateway, GatewayConfig, Role};
use writ_mirror::known_hosts::PinnedHosts;
use writ_mirror::{MirrorConfig, SyncReport};

use crate::declared::Declarations;
use writ_platform::clock::system::SystemClock;
use writ_store::{AuditLog, Store};

use crate::config::Config;
use crate::keystore::Start;

/// Every block is zeroed when it is freed, whatever code freed it: a library's copy of a
/// secret too (docs/security.md#secrets). `system-allocator` is the benchmark's baseline only.
#[cfg(not(feature = "system-allocator"))]
#[global_allocator]
static ALLOCATOR: writ_alloc::Wiping = writ_alloc::Wiping::system();

/// How often pending tickets and leases are checked for expiry.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// How long the service managers wait for the orderly stop before they kill `writd`: the
/// units' `ExitTimeOut` (launchd) and `TimeoutStopSec` (systemd), in `deploy/setups/`.
const UNIT_STOP_TIMEOUT: Duration = Duration::from_secs(330);

/// The longest the orderly stop waits for what is in flight (the review after M7.6, D-5):
/// one upstream operation's deadline (`mirrors.timeout`) and its margin, never past this, so
/// it ends, its lines written, before the service manager kills the daemon.
const STOP_LIMIT: Duration = UNIT_STOP_TIMEOUT.saturating_sub(Duration::from_secs(10));

/// Every command `main` dispatches, with its arguments: the usage text, and the list the
/// end-to-end coverage registry is checked against (docs/end-to-end.md).
const COMMANDS: &[(&str, &str)] = &[
    (
        "init",
        "<writd.yaml> [--tls-backend <software|se-cryptokit>] [--ca-backend <software|se-cryptokit>]",
    ),
    ("run", "<writd.yaml>"),
    ("recover", "<writd.yaml> <policy|approvers|readers> <file>"),
    ("check-upgrade", "<writd.yaml>"),
    ("host-key", "<writd.yaml>"),
    ("tls-fingerprint", "<writd.yaml>"),
    ("upstream-keys", "<writd.yaml>"),
    ("signing-keys", "<writd.yaml>"),
    ("hook", "pre-receive"),
    ("upstream-ssh", "<max bytes> <ssh> <args…>"),
    ("upstream-credential", "<socket> <get|store|erase>"),
    ("upstream-tunnel", "<socket> <host> <port>"),
    // Started by `writd run` on Linux, never by hand (docs/architecture/platform.md).
    ("proc-reader", ""),
];

/// The usage text: one line per command.
fn usage() -> String {
    COMMANDS
        .iter()
        .enumerate()
        .map(|(i, (name, args))| {
            let lead = if i == 0 { "usage: " } else { "       " };
            format!("{lead}writd {name} {args}").trim_end().to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// How each command hardens itself before it reads anything secret (docs/operators/
/// hardening.md); `None` for the three that read none (git's hook, ssh's relay and tunnel:
/// each forwards bytes). `run` hardens itself once its process reader started (Linux).
/// The commands that print a public key decode the keys whose halves they print (the host
/// key, every key of the development keystore): hardened too (the review after M7.6, D-10).
fn hardening_of(command: &str) -> Option<hardening::Say> {
    match command {
        "hook" | "upstream-ssh" | "upstream-tunnel" => None,
        "run" => Some(hardening::Say::Log),
        "init" | "recover" => Some(hardening::Say::Stderr),
        _ => Some(hardening::Say::Refusals),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    // Before anything is read: a refused step stops the command here.
    if let Some(command) = args.first().copied()
        && command != "run"
        && COMMANDS.iter().any(|(name, _)| *name == command)
        && let Some(say) = hardening_of(command)
        && let Err(e) = hardening::harden(say)
    {
        eprintln!("writd: {e:#}");
        return ExitCode::FAILURE;
    }
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
        ["upstream-tunnel", rest @ ..] => {
            return u8::try_from(writ_mirror::tunnel::run(rest))
                .map(ExitCode::from)
                .unwrap_or(ExitCode::FAILURE);
        }
        // It receives a token: hardened first, quietly (once per git operation).
        ["upstream-credential", rest @ ..] => {
            return u8::try_from(writ_mirror::credential::helper::run(rest))
                .map(ExitCode::from)
                .unwrap_or(ExitCode::FAILURE);
        }
        // The process reader `writd run` starts on Linux: hardened first, quietly.
        ["proc-reader"] => platform::serve_process_reader(),
        ["init", config, rest @ ..] => init(Path::new(config), rest),
        ["run", config] => run(Path::new(config)),
        ["recover", config, target, file] => {
            recover::recover(Path::new(config), target, Path::new(file))
        }
        ["check-upgrade", config] => upgrade::check_upgrade(Path::new(config)),
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
    let (config, _, declared) = load_checked(path)?;
    println!(
        "{}",
        keystore::public(&config, &declared, &platform::makers(&config)?)?
            .host
            .to_openssh()?
    );
    Ok(())
}

/// `writd init <writd.yaml> [--tls-backend <name>] [--ca-backend <name>]`.
fn init(path: &Path, options: &[&str]) -> anyhow::Result<()> {
    let usage = "usage: writd init <writd.yaml> [--tls-backend <software|se-cryptokit>] \
                 [--ca-backend <software|se-cryptokit>]";
    let (mut tls, mut ca) = ("software", "software");
    let mut rest = options;
    while let [flag, backend, after @ ..] = rest {
        match *flag {
            "--tls-backend" => tls = backend,
            "--ca-backend" => ca = backend,
            _ => bail!("{usage}"),
        }
        rest = after;
    }
    if !rest.is_empty() {
        bail!("{usage}");
    }
    keystore::init(path, tls, ca)
}

fn tls_fingerprint(path: &Path) -> anyhow::Result<()> {
    let (config, _, declared) = load_checked(path)?;
    let public = keystore::public(&config, &declared, &platform::makers(&config)?)?;
    let Some(fingerprint) = public.tls_fingerprint else {
        return Err(owed("the TLS key"));
    };
    println!("{fingerprint}");
    Ok(())
}

/// Why `what`, owed to the daemon's first start, can't be printed yet.
fn owed(what: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{what} is owed to the daemon: it makes it at its first start (a key on a device is \
         made only by the running daemon); start it once, then run this again"
    )
}

/// Refuses, naming what is owed of `role` (after the keys made were printed).
fn refuse_owed(
    owed_keys: &keystore::to_make::Owed,
    role: writ_proto::KeyRole,
) -> anyhow::Result<()> {
    let names: Vec<String> = owed_keys
        .of_role(role)
        .map(|k| declared::named(role, &k.id))
        .collect();
    match names.is_empty() {
        true => Ok(()),
        false => Err(owed(&names.join(", "))),
    }
}

/// Names, joined for a line.
pub(crate) fn joined<T: AsRef<str>>(names: &[T]) -> String {
    names
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Prints each upstream credential's public key and the repos that use it: the key to add on
/// each remote (as a deploy key, or on the account).
fn upstream_keys(path: &Path) -> anyhow::Result<()> {
    let (config, policy, declared) = load_checked(path)?;
    let public = keystore::public(&config, &declared, &platform::makers(&config)?)?;
    for (id, key) in public.upstream {
        println!(
            "{id} {} (repos: {})",
            key.to_openssh()?,
            joined(&policy.key_users(&id).repos)
        );
    }
    refuse_owed(&public.owed, writ_proto::KeyRole::Upstream)
}

/// Prints each agent signing key and the templates that name it: what to register on an
/// account so the remote shows its commits as verified. An SSH key's public key; an OpenPGP
/// key's fingerprint, then its certificate (as the daemon last made it).
fn signing_keys(path: &Path) -> anyhow::Result<()> {
    let (config, policy, declared) = load_checked(path)?;
    let public = keystore::public(&config, &declared, &platform::makers(&config)?)?;
    for (id, key, meta) in public.signing {
        println!(
            "{} (templates: {})",
            declared::describe(&id, &key, &meta)?,
            joined(&policy.key_users(&id).templates)
        );
        if meta.created.is_some() {
            match keystore::read_certificate(&config, &id)? {
                Some(certificate) => print!("{certificate}"),
                None => {
                    println!(
                        "(no certificate yet: give {id} user ids in the policy's keys.{id}.uids)"
                    )
                }
            }
        }
    }
    refuse_owed(&public.owed, writ_proto::KeyRole::Signing)
}

/// The configuration, the policy in force, and the keys it declares (each checked against
/// its backend).
fn load_checked(path: &Path) -> anyhow::Result<(Config, PolicyConfig, Declarations)> {
    let config = Config::load(path)?;
    let policy = load_registry(&config)?;
    let declared = declared::declarations(&policy)?;
    Ok((config, policy, declared))
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

/// The policy in force: what the commands that print a key need (the keystore holds every key
/// it declares). The store's version
/// once `writd init` recorded one; before, the file (an authority file, checked for owner,
/// mode and links before it is believed).
fn load_registry(config: &Config) -> anyhow::Result<PolicyConfig> {
    let db = config.state_dir.join("leases.db");
    if db.exists()
        && let Some(loaded) = authority::load(&Store::open(&db)?, config.min_ttl)?
    {
        return Ok(loaded.policy);
    }
    let policy_text = writ_platform::fs::read_authority(&config.policy, "policy")?;
    authority::read_policy(&policy_text, config.min_ttl)
        .map(|(policy, _)| policy)
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

/// Expires pending tickets and leases every [`SWEEP_INTERVAL`], off the async threads, until
/// a sweep fails (a panic): said, and the task ends, for its supervisor to start it again
/// ([`supervise`]).
async fn sweeper(service: Arc<Service>) {
    let mut ticks = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        ticks.tick().await;
        let service = service.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || service.sweep()).await {
            tracing::error!(error = %e, "the sweep failed");
            return;
        }
    }
}

/// Syncs every mirror from upstream every `every` (the first right away), one after the other,
/// unless a fetch or a push synced it more recently. A failure is logged and the mirror stays
/// stale: fetches and pushes then try again, and are refused if they fail too. After a mirror
/// synced (or was fresh), its notes are brought up to date (`Gateway::reconcile_notes`): at
/// start, and every `every`. Supervised ([`supervise`]), ended first by the orderly stop.
pub(crate) async fn mirror_sync(gateway: Gateway, every: Duration) {
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
    // First: the process reader started while the capability it keeps is there, then every
    // capability dropped (Linux; nothing elsewhere).
    let process_reader = platform::start_process_reader()?;
    // Before any secret is read: a refused step stops the daemon here.
    hardening::harden(hardening::Say::Log)?;
    let config = Arc::new(Config::load(path)?);
    keystore::private_dir(&config.state_dir)?;
    // Held until the daemon ends: `writd recover` refuses meanwhile.
    let _lock = lock::hold(&config.state_dir, lock::Holder::Daemon)?;
    // An older state migrated in steps, after a copy of it whole (M7.9.6): before anything
    // reads it. A step that fails stops the start here, naming it, the copy kept.
    let (store, migrated) = Store::open_migrating(
        &config.state_dir.join("leases.db"),
        &config.state_dir.join("backups"),
        now()?,
    )?;
    if let Some(migrated) = &migrated {
        let line = format!(
            "the state migrated from version {} to {}; its copy from before: {}",
            migrated.from,
            migrated.to,
            migrated.backup.display()
        );
        tracing::info!("{line}");
        writ_store::AuditLog::open(&config.state_dir.join("audit.jsonl"))?
            .append(
                &writ_store::AuditEvent::new(
                    now()?,
                    writ_store::EventKind::Migrate,
                    writ_store::Outcome::Done,
                )
                .reason(line),
            )
            .context("the audit log can't be written (the migration is recorded in the state)")?;
    }
    let loaded = match (authority::load(&store, config.min_ttl)?, &config.keystore) {
        (Some(loaded), _) => loaded,
        // The development keystore's first start: the files as they are.
        (None, config::KeystoreConfig::Dev(dir)) => authority::seed(
            &store,
            &keystore::dev_authority_key(dir)?,
            authority::read_files(&config)?,
            now()?,
            config.min_ttl,
        )?,
        (None, config::KeystoreConfig::Sealed(_)) => bail!(
            "{}: no authority files in force (policy, approvers, readers): `writd init` records \
             them",
            config.state_dir.display()
        ),
    };
    let pinned = PinnedHosts::from_policy(loaded.policy.upstream_hosts())?;
    let ca_certs = load_ca_certs(&config)?;
    let declared = declared::declarations(&loaded.policy)?;
    // A rotation of the data key cut short (the review after M7.6, S-8) is settled from the
    // keystore's own record before anything below reads the keys directory.
    keystore::settle(&config)?;
    platform::check_devices(&config, &declared)?;
    // The device keys a command run by hand left owed (`writd init`, `writd recover`): made
    // here, by the daemon, before anything reads a key (a key on a device is made only where
    // it is used: found on the first real install, 2026-11-14). Each one logged and in the
    // audit log before its entry leaves the file.
    if let config::KeystoreConfig::Sealed(sealed) = &config.keystore {
        let audit_path = config.state_dir.join("audit.jsonl");
        let mut audit: Option<writ_store::AuditLog> = None;
        keystore::to_make::finish(sealed, &platform::makers(&config)?, &mut |made| {
            tracing::info!(key = %made.id, "{}", made.line);
            let log = match &mut audit {
                Some(log) => log,
                None => audit.insert(writ_store::AuditLog::open(&audit_path)?),
            };
            log.append(
                &writ_store::AuditEvent::new(
                    now()?,
                    writ_store::EventKind::Key,
                    writ_store::Outcome::Allowed,
                )
                .key(&made.id.parse()?)
                .reason(made.line.clone()),
            )
            .context("the audit log can't be written: the key is said again at the next start")
        })?;
    }
    // Until the unseal checks their MAC (`keystore::open`), the versions in force are only
    // read and refused from, never acted on (the review after M7.6, S-1): what follows
    // checks the policy and reads the keystore's public files, and writes nothing from them.
    // Auto-unseal (M7.6): the daemon opens itself only with every key and secret in hardware;
    // anything else refuses the start, naming each one (never adjusted). An `unseal: auto`
    // read here is the state's, unchecked: it lets the devices unwrap the keystore's identity
    // and nothing more, the MAC checked before anything is written, as at a `writ unseal`.
    let automatic = loaded.policy.unseal() == writ_core::config::Unseal::Auto;
    if automatic {
        let missing = autounseal::missing(&config, &loaded.policy)?;
        if !missing.is_empty() {
            bail!(
                "unseal: auto, and not everything is in hardware, so the daemon won't start on \
                 its own: {} (to start it by hand instead, put in force a policy with `unseal: \
                 approver` with writd recover, on this host)",
                missing.join("; ")
            );
        }
    }
    // A CA or TLS rotation cut short (M7.6, M7.5), finished or dropped before anything reads
    // them: said in the audit log once it is open (the review after M7.6, S-2).
    let mut finished = Vec::new();
    if let config::KeystoreConfig::Sealed(sealed) = &config.keystore {
        match keystore::ca::finish(sealed)? {
            keystore::ca::Finished::Completed => finished
                .push("a CA rotation cut short after its key was in force was finished at start"),
            keystore::ca::Finished::Dropped => finished.push(
                "a CA rotation cut short before its key was in force was dropped at start: the \
                 old CA stays",
            ),
            keystore::ca::Finished::Nothing => {}
        }
        if keystore::tls_files(&config).finish()? {
            finished.push(
                "a TLS key rotation cut short after it was decided was finished at start: \
                 approvers re-pin the certificate writd tls-fingerprint prints",
            );
        }
    }
    let start = keystore::start(
        &config,
        &declared,
        &loaded.policy,
        &loaded.in_force,
        &platform::makers(&config)?,
    )?;
    let repos = config.state_dir.join("repos");
    std::fs::create_dir_all(&repos)
        .with_context(|| format!("cannot create {}", repos.display()))?;

    let runtime = tokio::runtime::Runtime::new()?;
    let ended = runtime.block_on(async move {
        let mut signals = StopSignals::take()?;
        let mirror_config = mirror_config(&config, repos, pinned, ca_certs)?;
        let platform = platform::build(&config, &process_reader).await?;
        let (boot, open) = match start {
            Start::Sealed(boot) => (boot, None),
            Start::Open(boot, opened) => (boot, Some(*opened)),
        };
        let host_public = boot.host.public_key().clone();
        // The daemon's name in every document an approver signs: what `writ` computes from
        // the host key it authenticated, with the same function.
        let daemon: KeyFingerprint = writ_crypto::keys::fingerprint(&host_public).parse()?;
        let (tls, tls_refused) = platform::tls_identity_at_start(&config, boot.tls)?;
        let tls = Arc::new(tls);
        log_access(&loaded.approvers, &loaded.readers);
        let readers = writ_crypto::readers::ReaderSet::new(loaded.readers);
        let service = start_service(
            &config,
            store,
            &declared,
            loaded.policy.clone(),
            loaded.approvers,
            loaded.in_force,
            loaded.migration_owed,
            boot.ca_public,
            daemon,
            &platform,
        )?;
        for note in &finished {
            tracing::warn!("{note}");
            service.admin_note(note);
        }
        if let Some(why) = &tls_refused {
            let note = format!("the TLS key is unusable: {why}");
            tracing::error!("{note}");
            service.admin_note(&note);
        }
        // What `writ info` says of a rotation of the data key owed (S-8), before the unseal.
        service.set_keystore(
            keystore::recipient(&config)?,
            keystore::rotation_owed(&config)?,
        );
        let (spawner, mut supervisor) = supervise::Supervisor::new();
        let opener = daemon::Opener::new(
            config.clone(),
            loaded.policy,
            loaded.texts,
            mirror_config,
            service.clone(),
            platform.notifier.clone(),
            spawner.clone(),
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
        opener.set_tls(tls.clone());
        // From here on every way out goes through the orderly stop (the review after M7.6,
        // D-6): an open that fails, a listener that ends, a background task that keeps ending,
        // as much as a signal.
        let mut servers = tokio::task::JoinSet::new();
        let opened = match open {
            Some(opened) => {
                opener
                    .open(opened, None, &writ_core::caller::CallerFacts::default())
                    .await
            }
            None if automatic => opener.unseal_automatically().await,
            None => {
                service.announce_sealed();
                Ok(())
            }
        };
        let stop = match opened.and_then(|()| Ok(host_public.to_openssh()?)) {
            Ok(host_key) => {
                tracing::info!(
                    %host_key,
                    tls_fingerprint = %tls.fingerprint(),
                    sealed = service.is_sealed(),
                    "started"
                );
                tracing::info!(decisions = ?config.decisions, "decisions");
                let wait = Duration::from_secs(config.mirrors.timeout.seconds())
                    .saturating_add(writ_mirror::STOP_MARGIN);
                if wait > STOP_LIMIT {
                    tracing::warn!(
                        limit_seconds = STOP_LIMIT.as_secs(),
                        "mirrors.timeout and its margin outlast the orderly stop's limit: an \
                         upstream operation in flight when the daemon stops is cut at it"
                    );
                }
                servers = spawn_listeners(&gateway, &platform, &tls);
                let sweeping = service.clone();
                spawner.spawn(
                    "sweeper",
                    Box::new(move || Box::pin(sweeper(sweeping.clone()))),
                );
                until_stopped(&mut signals, &mut servers, &mut supervisor).await
            }
            Err(e) => Stop::Failed(format!("{e:#}")),
        };
        let reason = match &stop {
            Stop::Signal(signal) => {
                tracing::info!(signal, "stopping");
                None
            }
            Stop::Failed(why) => {
                tracing::error!(reason = %why, "stopping");
                Some(why.clone())
            }
        };
        let stopped = stop_in_order(
            &mut signals,
            Stopping {
                supervisor: &mut supervisor,
                servers: &mut servers,
                platform,
                gateway: &gateway,
                limit: STOP_LIMIT,
            },
        )
        .await;
        anyhow::Ok((stopped, reason))
    });
    match ended {
        Ok((Stopped::InOrder, None)) => Ok(()),
        Ok((Stopped::InOrder, Some(why))) => bail!("stopped: {why}"),
        // Cut by a second signal: what still runs isn't waited for, not even the blocking
        // threads a runtime's drop would wait on.
        Ok((Stopped::AtOnce(signal), _)) => {
            runtime.shutdown_background();
            bail!("stopped at once by a second {signal}")
        }
        Err(e) => Err(e),
    }
}

/// Why `writd run` stops.
enum Stop {
    /// SIGINT or SIGTERM.
    Signal(&'static str),
    /// Something it can't run without ended or failed: it stops in order, then exits with
    /// the reason (a service manager restarts it).
    Failed(String),
}

/// How the orderly stop ended.
#[derive(Debug, PartialEq, Eq)]
enum Stopped {
    /// Everything it waits for was waited for (or cut at its limit).
    InOrder,
    /// A second signal came while it waited: the daemon exits at once.
    AtOnce(&'static str),
}

/// What the orderly stop ends, in its order.
struct Stopping<'a> {
    supervisor: &'a mut supervise::Supervisor,
    servers: &'a mut tokio::task::JoinSet<writ_gateway::Result<()>>,
    platform: platform::Platform,
    gateway: &'a Gateway,
    limit: Duration,
}

/// The orderly stop, the same on every way out (the review after M7.6, D-5, D-6): the
/// background tasks end (no sync or notes push starts after this), the listeners close, then
/// the gateway refuses new work and closes upstream's intake at once, and waits once for what
/// is in flight, at most one upstream operation's deadline and never past `limit`. A second
/// SIGINT or SIGTERM meanwhile is said, and the daemon exits at once.
async fn stop_in_order(signals: &mut StopSignals, stopping: Stopping<'_>) -> Stopped {
    let Stopping {
        supervisor,
        servers,
        platform,
        gateway,
        limit,
    } = stopping;
    let work = async move {
        supervisor.shutdown().await;
        // The listeners closed: their tasks ended, then the transports dropped.
        servers.shutdown().await;
        drop(platform);
        gateway.stop(limit).await
    };
    let second = tokio::select! {
        cut = work => {
            match cut {
                0 => tracing::info!("stopped"),
                cut => tracing::warn!(
                    cut,
                    "stopped with operations still running past their deadline"
                ),
            }
            return Stopped::InOrder;
        }
        _ = signals.interrupt.recv() => "SIGINT",
        _ = signals.terminate.recv() => "SIGTERM",
    };
    tracing::warn!(
        signal = second,
        "a second signal while stopping: writd exits at once, what is in flight cut"
    );
    Stopped::AtOnce(second)
}

/// The signals that stop the daemon in order, the same way for each: SIGINT (Ctrl-C) and
/// SIGTERM (launchd, systemd, `docker stop`). Taken before anything starts, so neither kills
/// the daemon half way through its start.
struct StopSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

impl StopSignals {
    fn take() -> anyhow::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).context("cannot take SIGINT")?,
            terminate: signal(SignalKind::terminate()).context("cannot take SIGTERM")?,
        })
    }
}

/// The approval service, sealed, on the state's store and audit log, with a boot nonce drawn
/// now.
// What the service starts with, each from its own source.
#[allow(clippy::too_many_arguments)]
fn start_service(
    config: &Config,
    store: Store,
    declared: &Declarations,
    policy: PolicyConfig,
    approvers: Vec<AllowedSigner>,
    in_force: writ_approval::InForce,
    migration_owed: Option<writ_proto::MigrationOwed>,
    ca_public: writ_crypto::ssh_key::PublicKey,
    daemon: KeyFingerprint,
    platform: &platform::Platform,
) -> anyhow::Result<Arc<Service>> {
    if let Some(owed) = migration_owed {
        tracing::warn!(
            from = owed.from,
            to = owed.to,
            "the policy in force is of an older format: every request is refused until an \
             approver signs its migration with writ migrate"
        );
    }
    let audit = AuditLog::open(&config.state_dir.join("audit.jsonl"))?;
    Ok(Service::new(
        ServiceConfig {
            policy,
            approvers,
            decisions: config.decisions,
            max_pending: config.max_pending,
            min_ttl: config.min_ttl,
            submissions: config.submissions.limits(),
            max_active_per_source: config.max_active_per_source,
            renew_grace: config.renew_grace,
            ca_public,
            daemon,
            in_force,
            recipient: keystore::recipient(config)?,
            unseal: match &config.keystore {
                config::KeystoreConfig::Sealed(sealed) => {
                    Some(match keystore::hardware_wrapped(sealed)? {
                        true => writ_proto::UnsealWay::Hardware,
                        false => writ_proto::UnsealWay::Passphrase,
                    })
                }
                config::KeystoreConfig::Dev(_) => None,
            },
            signing_keys: declared::key_uses(declared),
            session_launcher: config.checked_session_launcher()?,
            migration_owed,
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
        first_sync_timeout: Duration::from_secs(config.mirrors.first_sync_timeout.seconds()),
        max_fetch_bytes: config.mirrors.max_fetch.bytes(),
        scan_timeout: Duration::from_secs(config.mirrors.scan_timeout.seconds()),
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

/// Runs until SIGINT or SIGTERM (an orderly stop follows), a listener ends, or a background
/// task keeps ending (the daemon stops in order with it).
async fn until_stopped(
    signals: &mut StopSignals,
    servers: &mut tokio::task::JoinSet<writ_gateway::Result<()>>,
    supervisor: &mut supervise::Supervisor,
) -> Stop {
    tokio::select! {
        _ = signals.interrupt.recv() => Stop::Signal("SIGINT"),
        _ = signals.terminate.recv() => Stop::Signal("SIGTERM"),
        Some(result) = servers.join_next() => Stop::Failed(match result {
            Ok(Ok(())) => "a listener ended".to_owned(),
            Ok(Err(e)) => format!("a listener failed: {e}"),
            Err(e) => format!("a listener stopped: {e}"),
        }),
        why = supervisor.until_failed() => Stop::Failed(why),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// The development policy: a valid one, kept in the repo.
    const POLICY: &str = include_str!("../../../dev/policy.yaml");

    #[test]
    #[cfg(not(feature = "system-allocator"))]
    fn the_global_allocator_wipes_every_block_freed() {
        // Only a wiping allocator counts: with any other, the count never moves.
        let before = writ_alloc::testing::wiped_blocks();
        drop(std::hint::black_box(vec![0x5au8; 4096]));
        assert!(writ_alloc::testing::wiped_blocks() > before);
    }

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
            let feature = if args.is_empty() || args.starts_with('<') {
                format!("writd {name}")
            } else {
                format!("writd {name} {args}")
            };
            assert!(
                section.contains(&format!("| `{feature}`")),
                "{feature} is not in docs/end-to-end.md's coverage registry"
            );
        }
        // And what main dispatches is that table, read from main's own match (the review
        // after M5.5: the usage is made from the table, so counting its lines proved nothing).
        let source = include_str!("main.rs");
        let dispatch = source
            .split("let result = match args.as_slice() {")
            .nth(1)
            .and_then(|rest| rest.split("        _ => {").next())
            .expect("main's dispatch");
        let mut dispatched: Vec<String> = dispatch
            .lines()
            .filter_map(|line| line.trim().strip_prefix("[\""))
            .map(|arm| {
                let words: Vec<&str> = arm
                    .split(['"', ',', ' ', ']'])
                    .filter(|w| {
                        !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase() || c == '-')
                    })
                    .collect();
                match words.as_slice() {
                    [first, ..] => (*first).to_owned(),
                    [] => String::new(),
                }
            })
            .collect();
        dispatched.sort();
        let mut listed: Vec<String> = COMMANDS
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        listed.sort();
        assert_eq!(
            dispatched, listed,
            "main dispatches exactly the commands COMMANDS lists"
        );
    }

    /// The review after M7.6 (D-5): the orderly stop's limit is under the service managers'
    /// stop timeout, the one the units in `deploy/setups/` set.
    #[test]
    fn the_orderly_stop_ends_before_the_units_stop_timeout() {
        let seconds = UNIT_STOP_TIMEOUT.as_secs();
        assert!(STOP_LIMIT < UNIT_STOP_TIMEOUT);
        let setups = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/setups");
        for (file, setting) in [
            (
                "local-macos.sh",
                format!("<key>ExitTimeOut</key><integer>{seconds}</integer>"),
            ),
            ("local-linux.sh", format!("TimeoutStopSec={seconds}")),
        ] {
            let text = std::fs::read_to_string(format!("{setups}/{file}")).unwrap();
            assert!(text.contains(&setting), "{file} doesn't say {setting}");
        }
    }

    /// The review after M7.6 (D-10): every command hardens itself before it reads anything,
    /// those that print a public key included; only the three that forward bytes don't.
    #[test]
    fn every_command_but_the_byte_forwarders_hardens_itself() {
        for (name, _) in COMMANDS {
            let hardened = hardening_of(name).is_some();
            let forwards = matches!(*name, "hook" | "upstream-ssh" | "upstream-tunnel");
            assert_eq!(hardened, !forwards, "{name}");
        }
        for name in [
            "host-key",
            "tls-fingerprint",
            "upstream-keys",
            "signing-keys",
        ] {
            assert_eq!(hardening_of(name), Some(hardening::Say::Refusals), "{name}");
        }
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
