//! `writd`, the Writ daemon.
//!
//! M0 spike: `writd spike <state-dir> <listen-addr>` runs the gateway with keys generated in
//! the state directory (test keys only), and `writd hook pre-receive` is the program git's
//! pre-receive hook runs.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, bail};
use writ_crypto::ca::{CertificateAuthority, CertificateRequest};
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{LineEnding, PrivateKey, PublicKey};
use writ_gateway::{Gateway, GatewayConfig};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["hook", "pre-receive"] => {
            return u8::try_from(writ_gateway::hook::run_pre_receive())
                .map(ExitCode::from)
                .unwrap_or(ExitCode::FAILURE);
        }
        ["spike", state, listen] => spike(Path::new(state), listen),
        ["spike-cert", state, public_key, out] => {
            spike_cert(Path::new(state), Path::new(public_key), Path::new(out))
        }
        _ => {
            eprintln!(
                "usage: writd spike <state-dir> <listen-addr>\n       \
                 writd spike-cert <state-dir> <session-key.pub> <out-cert>\n       \
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

/// Loads a key from the state directory, generating it on first use.
fn state_key(state: &Path, name: &str, kind: KeyKind) -> anyhow::Result<PrivateKey> {
    let path = state.join(name);
    if path.exists() {
        let pem = std::fs::read_to_string(&path).with_context(|| format!("reading {path:?}"))?;
        return Ok(PrivateKey::from_openssh(pem)?);
    }
    let key = generate(kind)?;
    std::fs::write(&path, key.to_openssh(LineEnding::LF)?.as_bytes())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(key)
}

fn spike(state: &Path, listen: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(state.join("repos"))?;
    let ca = CertificateAuthority::new(state_key(state, "ca", KeyKind::Ed25519)?);
    let host_key = state_key(state, "host", KeyKind::Ed25519)?;
    let signing_key = state_key(state, "agent", KeyKind::Ed25519)?;
    println!("repos:     {}", state.join("repos").display());
    println!("host key:  {}", host_key.public_key().to_openssh()?);
    println!("agent key: {}", signing_key.public_key().to_openssh()?);
    println!("listening: {listen}");

    let config = GatewayConfig {
        host_key,
        authorities: vec![ca.fingerprint()],
        repos_root: state.join("repos"),
        signing_key,
        hook_program: std::env::current_exe()?,
        state_dir: state.join("run"),
        protected_refs: vec!["refs/heads/main".into(), "refs/tags/*".into()],
    };
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let gateway = Gateway::start(config).await?;
        if let Some(socket) = listen.strip_prefix("unix:") {
            let socket = PathBuf::from(socket);
            if socket.exists() {
                std::fs::remove_file(&socket)?;
            }
            gateway
                .serve_unix(tokio::net::UnixListener::bind(socket)?)
                .await?;
        } else {
            gateway
                .serve_tcp(tokio::net::TcpListener::bind(listen).await?)
                .await?;
        }
        Ok(())
    })
}

/// Issues a one-hour session certificate for a public key, signed by the spike's CA.
fn spike_cert(state: &Path, public_key: &Path, out: &Path) -> anyhow::Result<()> {
    if !state.join("ca").exists() {
        bail!("no CA in {state:?}: run `writd spike` first");
    }
    let ca = CertificateAuthority::new(state_key(state, "ca", KeyKind::Ed25519)?);
    let subject = PublicKey::from_openssh(std::fs::read_to_string(public_key)?.trim())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let cert = ca.issue(&CertificateRequest {
        subject: &subject,
        serial: now,
        key_id: "wrt_spike",
        principals: &["git"],
        valid_after: now.saturating_sub(60),
        valid_before: now + 3600,
    })?;
    std::fs::write(out, cert.to_openssh()?)?;
    Ok(())
}
