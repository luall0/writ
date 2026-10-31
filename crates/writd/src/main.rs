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
mod platform;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use writ_approval::{Platform as ServicePlatform, Service, ServiceConfig, SystemClock};
use writ_core::config::PolicyConfig;
use writ_core::lease::APPROVAL_NAMESPACE;
use writ_crypto::allowed_signers;
use writ_crypto::ca::CertificateAuthority;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{LineEnding, PrivateKey};
use writ_gateway::{Gateway, GatewayConfig, Role, TlsIdentity};
use writ_store::{AuditLog, Store};

use crate::config::{Config, KeystoreConfig};

/// How often pending tickets and leases are checked for expiry.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["hook", "pre-receive"] => {
            return u8::try_from(writ_gateway::hook::run_pre_receive())
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

fn private_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("cannot create {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// The daemon's keys. M2: plain files in a dev keystore, generated on first start.
struct Keys {
    ca: PrivateKey,
    host: PrivateKey,
    /// Signs commits until the `Signer` interface (M3).
    agent: PrivateKey,
    /// The HTTPS approval API's self-signed certificate and key.
    tls: TlsIdentity,
}

/// The TLS certificate and key of the dev keystore, generated on first start.
fn dev_tls(dir: &Path) -> anyhow::Result<TlsIdentity> {
    let (cert_path, key_path) = (dir.join("tls-cert.pem"), dir.join("tls-key.pem"));
    // The key is written first: a cert without its key (or a key alone, after a crash
    // between the two writes) is a pair to make again.
    if !(cert_path.exists() && key_path.exists()) {
        for leftover in [&cert_path, &key_path] {
            match std::fs::remove_file(leftover) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(e).with_context(|| format!("cannot remove {}", leftover.display()));
                }
                _ => {}
            }
        }
        let generated = writ_crypto::tls::generate_self_signed()?;
        write_private(&key_path, generated.key_pem.as_bytes())?;
        std::fs::write(&cert_path, &generated.cert_pem)?;
    }
    let cert = std::fs::read_to_string(&cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?;
    let key = zeroize::Zeroizing::new(
        std::fs::read_to_string(&key_path)
            .with_context(|| format!("reading {}", key_path.display()))?,
    );
    Ok(TlsIdentity::from_pem(&cert, &key)?)
}

fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = std::fs::OpenOptions::new();
    std::os::unix::fs::OpenOptionsExt::mode(file.write(true).create_new(true), 0o600);
    std::io::Write::write_all(&mut file.open(path)?, bytes)?;
    Ok(())
}

fn dev_key(dir: &Path, name: &str) -> anyhow::Result<PrivateKey> {
    let path = dir.join(name);
    if path.exists() {
        let pem = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        return Ok(PrivateKey::from_openssh(pem)?);
    }
    let key = generate(KeyKind::Ed25519)?;
    write_private(&path, key.to_openssh(LineEnding::LF)?.as_bytes())?;
    Ok(key)
}

fn keys(config: &Config) -> anyhow::Result<Keys> {
    match &config.keystore {
        KeystoreConfig::Dev(dir) => {
            if !cfg!(debug_assertions) {
                bail!(
                    "keystore.dev holds unencrypted keys for tests and development; a release \
                     build refuses it (the sealed keystore comes in M5)"
                );
            }
            private_dir(dir)?;
            Ok(Keys {
                ca: dev_key(dir, "ca")?,
                host: dev_key(dir, "host")?,
                agent: dev_key(dir, "agent")?,
                tls: dev_tls(dir)?,
            })
        }
    }
}

fn host_key(path: &Path) -> anyhow::Result<()> {
    let config = Config::load(path)?;
    println!("{}", keys(&config)?.host.public_key().to_openssh()?);
    Ok(())
}

fn tls_fingerprint(path: &Path) -> anyhow::Result<()> {
    let config = Config::load(path)?;
    println!("{}", keys(&config)?.tls.fingerprint());
    Ok(())
}

fn run(path: &Path) -> anyhow::Result<()> {
    let config = Config::load(path)?;
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
    let keys = keys(&config)?;
    private_dir(&config.state_dir)?;
    std::fs::create_dir_all(config.state_dir.join("repos"))?;
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
                repos_root: config.state_dir.join("repos"),
                signing_key: keys.agent,
                hook_program: std::env::current_exe()?,
                state_dir: config.state_dir.join("run"),
            },
            service.clone(),
        )
        .await?;

        println!("writd: host key {host_public}");
        println!("writd: TLS fingerprint {}", tls.fingerprint());
        for approver in &approvers {
            println!(
                "writd: approver {} ({})",
                approver.fingerprint(),
                approver.principals
            );
        }
        println!("writd: decisions {:?}", config.decisions);
        if platform.unlock.is_some() {
            println!("writd: keystore unlock configured (used by the sealed start, M5)");
        }
        let mut servers = tokio::task::JoinSet::new();
        for transport in &platform.approvals_https {
            println!("writd: Approvals (HTTPS) on {}", transport.describe());
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
                println!("writd: {role:?} on {}", transport.describe());
                let (gateway, transport, attestor) = (
                    gateway.clone(),
                    transport.clone(),
                    platform.attestor.clone(),
                );
                servers.spawn(async move { gateway.serve(transport, attestor, role).await });
            }
        }
        let sweeper = service.clone();
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                ticks.tick().await;
                let service = sweeper.clone();
                let _ = tokio::task::spawn_blocking(move || service.sweep()).await;
            }
        });
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("writd: stopping");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tls_pair_cut_short_by_a_crash_is_made_again() {
        let dir = tempfile::tempdir().unwrap();
        let first = dev_tls(dir.path()).unwrap().fingerprint().to_owned();
        assert_eq!(dev_tls(dir.path()).unwrap().fingerprint(), first, "kept");
        // The key written, the cert not: a crash between the two writes.
        std::fs::remove_file(dir.path().join("tls-cert.pem")).unwrap();
        let second = dev_tls(dir.path()).unwrap().fingerprint().to_owned();
        assert_ne!(second, first);
        // The cert alone.
        std::fs::remove_file(dir.path().join("tls-key.pem")).unwrap();
        assert_ne!(dev_tls(dir.path()).unwrap().fingerprint(), second);
        let mode = std::fs::metadata(dir.path().join("tls-key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
