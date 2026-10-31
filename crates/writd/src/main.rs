//! `writd`, the Writ daemon.
//!
//! - `writd run <writd.yaml>`: the daemon (gateway, approval API, expiry timer).
//! - `writd host-key <writd.yaml>`: prints the gateway's host key, to pin in clients'
//!   `known_hosts`.
//! - `writd tls-fingerprint <writd.yaml>`: prints the fingerprint of the HTTPS approval API's
//!   certificate, to pin in clients' `tls_pins`.
//! - `writd hook pre-receive`: the program git's pre-receive hook runs.
//!
//! Only this binary wires the crates together and reads configuration
//! (docs/architecture/overview.md).

mod config;
mod keystore;
mod platform;

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use writ_approval::{Service, ServiceConfig, ServicePlatform};
use writ_core::config::PolicyConfig;
use writ_core::lease::APPROVAL_NAMESPACE;
use writ_crypto::allowed_signers::{self, AllowedSigner};
use writ_crypto::ca::CertificateAuthority;
use writ_crypto::tls::TlsIdentity;
use writ_gateway::{Gateway, GatewayConfig, Role};
use writ_platform::clock::system::SystemClock;
use writ_store::{AuditLog, Store};

use crate::config::Config;

/// How often pending tickets and leases are checked for expiry.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["hook", "pre-receive"] => {
            return u8::try_from(writ_gateway::run_pre_receive())
                .map(ExitCode::from)
                .unwrap_or(ExitCode::FAILURE);
        }
        ["run", config] => run(Path::new(config)),
        ["host-key", config] => host_key(Path::new(config)),
        ["tls-fingerprint", config] => tls_fingerprint(Path::new(config)),
        _ => {
            eprintln!(
                "usage: writd run <writd.yaml>\n       \
                 writd host-key <writd.yaml>\n       \
                 writd tls-fingerprint <writd.yaml>\n       \
                 writd hook pre-receive"
            );
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
    println!(
        "{}",
        keystore::keys(&config)?.host.public_key().to_openssh()?
    );
    Ok(())
}

fn tls_fingerprint(path: &Path) -> anyhow::Result<()> {
    let config = Config::load(path)?;
    println!("{}", keystore::keys(&config)?.tls.fingerprint());
    Ok(())
}

/// The approval policy (repo registry and templates) and the approver keys, from the files
/// the configuration names. No approver key at all is a startup error.
fn load_policy(config: &Config) -> anyhow::Result<(PolicyConfig, Vec<AllowedSigner>)> {
    let policy_text = std::fs::read_to_string(&config.policy)
        .with_context(|| format!("cannot read {}", config.policy.display()))?;
    let policy = PolicyConfig::from_yaml(&policy_text)
        .map_err(|e| anyhow::anyhow!("{}: {e}", config.policy.display()))?;
    let approvers_text = std::fs::read_to_string(&config.approvers)
        .with_context(|| format!("cannot read {}", config.approvers.display()))?;
    let approvers = allowed_signers::parse(&approvers_text, APPROVAL_NAMESPACE)
        .map_err(|e| anyhow::anyhow!("{}: {e}", config.approvers.display()))?;
    if approvers.is_empty() {
        bail!(
            "{}: no approver key for {APPROVAL_NAMESPACE}: nothing could ever be signed",
            config.approvers.display()
        );
    }
    Ok((policy, approvers))
}

/// Starts every listener the platform built; returns them as a set to wait on.
fn spawn_listeners(
    gateway: &Gateway,
    platform: &platform::Platform,
    tls: &Arc<TlsIdentity>,
) -> tokio::task::JoinSet<writ_gateway::Result<()>> {
    let mut servers = tokio::task::JoinSet::new();
    for transport in &platform.approvals_https {
        tracing::info!(listener = %transport.describe(), "approval API (HTTPS)");
        let (gateway, transport, attestor, tls) = (
            gateway.clone(),
            transport.clone(),
            platform.attestor.clone(),
            tls.clone(),
        );
        servers.spawn(async move { gateway.serve_https(transport, attestor, tls).await });
    }
    for (role, transports) in [
        (Role::Agents, &platform.agents),
        (Role::Approvals, &platform.approvals_ssh),
    ] {
        for transport in transports {
            tracing::info!(listener = %transport.describe(), ?role, "SSH");
            let (gateway, transport, attestor) = (
                gateway.clone(),
                transport.clone(),
                platform.attestor.clone(),
            );
            servers.spawn(async move { gateway.serve(transport, attestor, role).await });
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
    let config = Config::load(path)?;
    let (policy, approvers) = load_policy(&config)?;
    let keys = keystore::keys(&config)?;
    keystore::private_dir(&config.state_dir)?;
    let repos = config.state_dir.join("repos");
    std::fs::create_dir_all(&repos)
        .with_context(|| format!("cannot create {}", repos.display()))?;
    let store = Store::open(&config.state_dir.join("leases.db"))?;
    let audit = AuditLog::open(&config.state_dir.join("audit.jsonl"))?;

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let platform = platform::build(&config).await?;
        let service = Service::new(
            ServiceConfig {
                policy,
                approvers: approvers.clone(),
                decisions: config.decisions,
                max_pending: config.max_pending,
            },
            CertificateAuthority::new(keys.ca),
            store,
            audit,
            ServicePlatform {
                notifier: platform.notifier.clone(),
                watcher: platform.watcher.clone(),
                clock: Arc::new(SystemClock),
            },
        )?;
        let host_public = keys.host.public_key().to_openssh()?;
        let tls = Arc::new(keys.tls);
        let gateway = Gateway::start(
            GatewayConfig {
                host_key: keys.host,
                repos_root: repos,
                signing_key: keys.agent,
                hook_program: std::env::current_exe()?,
                state_dir: config.state_dir.join("run"),
            },
            service.clone(),
        )
        .await?;

        tracing::info!(host_key = %host_public, tls_fingerprint = %tls.fingerprint(), "started");
        for approver in &approvers {
            tracing::info!(
                fingerprint = %approver.fingerprint(),
                principals = %approver.principals,
                "approver"
            );
        }
        tracing::info!(decisions = ?config.decisions, "decisions");
        if platform.unlock.is_some() {
            tracing::info!("keystore unlock configured (used by the sealed start, M5)");
        }
        let mut servers = spawn_listeners(&gateway, &platform, &tls);
        spawn_sweeper(service);
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
    })
}
