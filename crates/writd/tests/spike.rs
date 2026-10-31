//! M0 spike, end to end: real `git` and `ssh` against the gateway, with session certificates,
//! the pre-receive callback and commits signed by the daemon through `writ-sign`.
//!
//! Needs the workspace binaries built (`make test` does it). Never touches the user's
//! `~/.ssh`, git configuration or ssh-agent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;
use writ_crypto::ca::{CertificateAuthority, CertificateRequest};
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{LineEnding, PrivateKey};
use writ_gateway::{Gateway, GatewayConfig};

const WRITD: &str = env!("CARGO_BIN_EXE_writd");

fn writ_sign() -> PathBuf {
    let path = Path::new(WRITD).with_file_name("writ-sign");
    assert!(
        path.exists(),
        "{} missing: run `cargo build --workspace --bins` first (make test does)",
        path.display()
    );
    path
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn write_secret(path: &Path, key: &PrivateKey) {
    fs::write(path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

enum Listen {
    Tcp,
    Unix,
}

/// A gateway on a temporary state directory, and a client environment to talk to it.
struct Spike {
    dir: TempDir,
    /// Keeps the gateway running for the test.
    _runtime: tokio::runtime::Runtime,
    gateway: Gateway,
    ca: CertificateAuthority,
    agent_key: PrivateKey,
    /// `ssh://git@…` base URL of the gateway.
    url: String,
    /// Extra ssh options to reach it (port or proxy command, known hosts).
    ssh_target: String,
}

impl Spike {
    fn start(agent_kind: KeyKind, listen: Listen) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for sub in ["repos", "home", "keys"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        fs::write(
            root.join("gitconfig"),
            "[user]\n\tname = Agent\n\temail = agent@writ\n[init]\n\tdefaultBranch = main\n\
             [commit]\n\tgpgsign = false\n",
        )
        .unwrap();

        let ca = CertificateAuthority::new(generate(KeyKind::Ed25519).unwrap());
        let host_key = generate(KeyKind::Ed25519).unwrap();
        let agent_key = generate(agent_kind).unwrap();
        let host_public = host_key.public_key().to_openssh().unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let config = GatewayConfig {
            host_key,
            authorities: vec![ca.fingerprint()],
            repos_root: root.join("repos"),
            signing_key: agent_key.clone(),
            hook_program: PathBuf::from(WRITD),
            state_dir: root.join("run"),
            protected_refs: vec!["refs/heads/main".into(), "refs/tags/*".into()],
        };
        let gateway = runtime.block_on(Gateway::start(config)).unwrap();

        let known_hosts = root.join("known_hosts");
        let (url, ssh_target, host) = match listen {
            Listen::Tcp => {
                let listener = runtime
                    .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
                    .unwrap();
                let port = listener.local_addr().unwrap().port();
                let g = gateway.clone();
                runtime.spawn(async move { g.serve_tcp(listener).await });
                (
                    format!("ssh://git@127.0.0.1:{port}"),
                    String::new(),
                    format!("[127.0.0.1]:{port}"),
                )
            }
            Listen::Unix => {
                let socket = root.join("writd.sock");
                let listener = {
                    let _guard = runtime.enter();
                    tokio::net::UnixListener::bind(&socket).unwrap()
                };
                let g = gateway.clone();
                runtime.spawn(async move { g.serve_unix(listener).await });
                (
                    "ssh://git@writ-local".to_owned(),
                    format!(
                        "-o HostKeyAlias=writ-local -o ProxyCommand='nc -U {}'",
                        socket.display()
                    ),
                    "writ-local".to_owned(),
                )
            }
        };
        fs::write(&known_hosts, format!("{host} {host_public}\n")).unwrap();

        let spike = Self {
            dir,
            _runtime: runtime,
            gateway,
            ca,
            agent_key,
            url,
            ssh_target,
        };
        spike.session("session", 1, 0, now() + 3600);
        spike
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    /// Writes a session key and a certificate for it (`keys/<name>`, `keys/<name>-cert.pub`).
    fn session(&self, name: &str, serial: u64, valid_after: u64, valid_before: u64) -> PathBuf {
        self.session_from(&self.ca, name, serial, valid_after, valid_before)
    }

    fn session_from(
        &self,
        ca: &CertificateAuthority,
        name: &str,
        serial: u64,
        valid_after: u64,
        valid_before: u64,
    ) -> PathBuf {
        let key = generate(KeyKind::Ed25519).unwrap();
        let path = self.root().join("keys").join(name);
        write_secret(&path, &key);
        let cert = ca
            .issue(&CertificateRequest {
                subject: key.public_key(),
                serial,
                key_id: "wrt_spike",
                principals: &["git"],
                valid_after,
                valid_before,
            })
            .unwrap();
        fs::write(
            self.root().join("keys").join(format!("{name}-cert.pub")),
            cert.to_openssh().unwrap(),
        )
        .unwrap();
        path
    }

    /// The ssh command a client uses with the given session key.
    fn ssh_command(&self, key: &Path, with_cert: bool) -> String {
        let cert = if with_cert {
            format!("{}-cert.pub", key.display())
        } else {
            "/dev/null".to_owned()
        };
        format!(
            "ssh -F /dev/null -o BatchMode=yes -o IdentityAgent=none -o IdentitiesOnly=yes \
             -o UserKnownHostsFile={} -o GlobalKnownHostsFile=/dev/null \
             -o StrictHostKeyChecking=yes -o LogLevel=ERROR {} -i {} -o CertificateFile={}",
            self.root().join("known_hosts").display(),
            self.ssh_target,
            key.display(),
            cert
        )
    }

    fn git_with(&self, ssh_command: &str, cwd: &Path, args: &[&str]) -> Output {
        Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.root().join("home"))
            .env("GIT_CONFIG_GLOBAL", self.root().join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_SSH_COMMAND", ssh_command)
            .output()
            .unwrap()
    }

    fn git(&self, cwd: &Path, args: &[&str]) -> Output {
        let key = self.root().join("keys/session");
        self.git_with(&self.ssh_command(&key, true), cwd, args)
    }

    fn git_ok(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.git(cwd, args);
        assert!(
            out.status.success(),
            "git {args:?} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A bare repo `repos/demo.git` with one commit on main, made without the gateway.
    fn seed_repo(&self) {
        let bare = self.root().join("repos/demo.git");
        let seed = self.root().join("seed");
        self.git_ok(
            self.root(),
            &["init", "-q", "--bare", bare.to_str().unwrap()],
        );
        self.git_ok(self.root(), &["init", "-q", seed.to_str().unwrap()]);
        fs::write(seed.join("README"), "demo\n").unwrap();
        self.git_ok(&seed, &["add", "README"]);
        self.git_ok(&seed, &["commit", "-q", "-m", "seed"]);
        self.git_ok(&seed, &["push", "-q", bare.to_str().unwrap(), "main"]);
    }

    fn clone(&self, name: &str) -> PathBuf {
        let work = self.root().join(name);
        self.git_ok(
            self.root(),
            &[
                "clone",
                "-q",
                &format!("{}/demo.git", self.url),
                work.to_str().unwrap(),
            ],
        );
        work
    }

    fn bare_ref(&self, name: &str) -> Option<String> {
        let out = self.git(
            &self.root().join("repos/demo.git"),
            &["rev-parse", "--verify", "-q", name],
        );
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn fetch_and_push_through_the_gateway() {
    let spike = Spike::start(KeyKind::Ed25519, Listen::Tcp);
    spike.seed_repo();
    let work = spike.clone("work");
    assert_eq!(fs::read_to_string(work.join("README")).unwrap(), "demo\n");
    let main_before = spike.bare_ref("refs/heads/main");

    fs::write(work.join("feature"), "x\n").unwrap();
    spike.git_ok(&work, &["add", "feature"]);
    spike.git_ok(&work, &["commit", "-q", "-m", "feature"]);
    spike.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    let head = spike.git_ok(&work, &["rev-parse", "HEAD"]);
    assert_eq!(
        spike.bare_ref("refs/heads/agent/x").as_deref(),
        Some(head.trim())
    );

    // A protected ref: refused by the daemon through the pre-receive callback, with its
    // reason shown by git, and nothing lands.
    let out = spike.git(&work, &["push", "origin", "HEAD:refs/heads/main"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("writ: refs/heads/main is protected"),
        "{}",
        stderr(&out)
    );
    assert_eq!(spike.bare_ref("refs/heads/main"), main_before);

    spike.git_ok(&work, &["tag", "v1"]);
    let out = spike.git(&work, &["push", "origin", "refs/tags/v1"]);
    assert!(
        stderr(&out).contains("writ: refs/tags/v1 is protected"),
        "{}",
        stderr(&out)
    );
    assert_eq!(spike.bare_ref("refs/tags/v1"), None);

    // Fetch sees the pushed branch.
    let other = spike.clone("other");
    spike.git_ok(&other, &["fetch", "-q", "origin"]);
    let fetched = spike.git_ok(&other, &["rev-parse", "origin/agent/x"]);
    assert_eq!(fetched.trim(), head.trim());
}

#[test]
fn only_valid_session_certificates_get_in() {
    let spike = Spike::start(KeyKind::Ed25519, Listen::Tcp);
    spike.seed_repo();
    let url = format!("{}/demo.git", spike.url);
    let ls_remote = |key: &Path, with_cert: bool| {
        spike.git_with(
            &spike.ssh_command(key, with_cert),
            spike.root(),
            &["ls-remote", &url],
        )
    };
    let key = |name: &str| spike.root().join("keys").join(name);

    assert!(ls_remote(&key("session"), true).status.success());

    let other_ca = CertificateAuthority::new(generate(KeyKind::Ed25519).unwrap());
    spike.session_from(&other_ca, "foreign", 2, 0, now() + 3600);
    assert!(
        !ls_remote(&key("foreign"), true).status.success(),
        "unknown CA"
    );

    spike.session("expired", 3, 0, now() - 10);
    assert!(
        !ls_remote(&key("expired"), true).status.success(),
        "expired"
    );

    spike.session("early", 4, now() + 600, now() + 3600);
    assert!(
        !ls_remote(&key("early"), true).status.success(),
        "not valid yet"
    );

    assert!(
        !ls_remote(&key("session"), false).status.success(),
        "plain key"
    );

    spike.session("revoked", 5, 0, now() + 3600);
    assert!(ls_remote(&key("revoked"), true).status.success());
    spike.gateway.revoke(5);
    assert!(
        !ls_remote(&key("revoked"), true).status.success(),
        "revoked"
    );

    // Commands other than git and writ-sign are refused with a reason.
    let ssh = spike.ssh_command(&key("session"), true);
    let host = spike.url.trim_start_matches("ssh://");
    let (destination, port) = host.rsplit_once(':').unwrap();
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("{ssh} -p {port} {destination} id"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("writ: command not allowed"),
        "{}",
        stderr(&out)
    );
}

fn signed_commit_verifies(agent_kind: KeyKind) {
    let spike = Spike::start(agent_kind, Listen::Tcp);
    spike.seed_repo();
    let work = spike.clone("work");
    let agent_public = spike.agent_key.public_key().to_openssh().unwrap();
    let allowed = spike.root().join("allowed_signers");
    fs::write(&allowed, format!("agent@writ {agent_public}\n")).unwrap();
    let shim = writ_sign();
    for (key, value) in [
        ("gpg.format", "ssh"),
        ("gpg.ssh.program", shim.to_str().unwrap()),
        ("user.signingkey", &format!("key::{agent_public}")),
        ("gpg.ssh.allowedSignersFile", allowed.to_str().unwrap()),
        ("writ.url", &spike.url),
    ] {
        spike.git_ok(&work, &["config", key, value]);
    }

    spike.git_ok(
        &work,
        &["commit", "-q", "-S", "--allow-empty", "-m", "signed"],
    );
    let out = spike.git(&work, &["verify-commit", "HEAD"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("Good \"git\" signature for agent@writ"),
        "{}",
        stderr(&out)
    );

    // Signed commits push like any other.
    spike.git_ok(
        &work,
        &["push", "-q", "origin", "HEAD:refs/heads/agent/signed"],
    );

    // No valid certificate, no signature.
    spike.gateway.revoke(1);
    let out = spike.git(
        &work,
        &["commit", "-q", "-S", "--allow-empty", "-m", "refused"],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("writ-sign: the daemon refused to sign"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn ed25519_commits_signed_by_the_daemon_verify_with_git() {
    signed_commit_verifies(KeyKind::Ed25519);
}

#[test]
fn p256_commits_signed_by_the_daemon_verify_with_git() {
    signed_commit_verifies(KeyKind::P256);
}

#[test]
fn the_same_protocol_works_over_a_unix_socket() {
    let spike = Spike::start(KeyKind::Ed25519, Listen::Unix);
    spike.seed_repo();
    let work = spike.clone("work");
    fs::write(work.join("f"), "x\n").unwrap();
    spike.git_ok(&work, &["add", "f"]);
    spike.git_ok(&work, &["commit", "-q", "-m", "over a unix socket"]);
    spike.git_ok(
        &work,
        &["push", "-q", "origin", "HEAD:refs/heads/agent/unix"],
    );
    assert!(spike.bare_ref("refs/heads/agent/unix").is_some());
    let out = spike.git(&work, &["push", "origin", "HEAD:refs/heads/main"]);
    assert!(
        stderr(&out).contains("writ: refs/heads/main is protected"),
        "{}",
        stderr(&out)
    );
}
