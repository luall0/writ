//! The gateway in-process, on a temporary state directory, with the approval service on the
//! test kit: driven by the real `git` and `ssh` over TCP or a Unix socket, with session
//! certificates from real leases and commits signed through `writ-sign`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use tempfile::TempDir;
use writ_approval::Service;
use writ_approval::testing::{TestServiceBuilder, sign_approval, sign_revocation};
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::names::TicketId;
use writ_core::net::Sources;
use writ_core::ticket::Ticket;
use writ_crypto::ca::{CertificateAuthority, CertificateRequest};
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{LineEnding, PrivateKey};
use writ_gateway::{Gateway, GatewayConfig, Role};
use writ_platform::clock::system::SystemClock;
use writ_platform::testing::FakeAttestor;
use writ_platform::transport::tcp::TcpTransport;
use writ_platform::watch::none::NoSessionWatcher;
use writ_platform::{BoxFuture, Connection, PeerInfo, Transport};
use writ_proto::Decision;

use crate::binaries::bin;

/// The policy: one repo, `main` and tags protected, one wide template.
pub const POLICY: &str = r#"
repos:
  demo:
    upstream: ssh://git@forge.invalid/demo.git
    upstream_credential: upstream-01
    protected_refs: ["refs/heads/main", "refs/tags/*"]
templates:
  spike:
    repos: [demo]
    operations: [fetch, commit_sign, push]
    branches: ["*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-01
    max_ttl: 1h
    max_signatures: 100
    max_pushes: 100
    max_ops_per_minute: 1000
    max_push_size: 50MB
"#;

/// The ticket every session is a lease for.
pub const TICKET: &str = r#"
scope:
  repos: [demo]
  operations: [fetch, commit_sign, push]
  branches: ["agent/*"]
ticket:
  title: Spike
  task: Exercise the gateway
"#;

pub enum Listen {
    Tcp,
    Unix,
}

/// A Unix socket transport for this test (the real one comes with local mode, M7).
struct UnixTransport(tokio::net::UnixListener);

impl Transport for UnixTransport {
    fn accept(&self) -> BoxFuture<'_, writ_platform::Result<Connection>> {
        Box::pin(async move {
            let (stream, _) = self.0.accept().await?;
            Ok(Connection {
                stream: Box::new(stream),
                peer: PeerInfo::Memory {
                    label: "unix (test)".into(),
                },
            })
        })
    }

    fn describe(&self) -> String {
        "unix (test)".into()
    }
}

/// A gateway on a temporary state directory, and a client environment to talk to it.
pub struct GitGateway {
    pub dir: TempDir,
    pub runtime: tokio::runtime::Runtime,
    pub service: Arc<Service>,
    /// The same key as the service's CA, to forge certificates without a lease.
    pub ca: CertificateAuthority,
    pub approver: PrivateKey,
    pub agent_key: PrivateKey,
    /// `ssh://git@…` base URL of the gateway.
    pub url: String,
    /// Extra ssh options to reach it (port or proxy command, known hosts).
    pub ssh_target: String,
}

impl GitGateway {
    pub fn start(agent_kind: KeyKind, listen: Listen) -> Self {
        crate::tools::require();
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

        let host_key = generate(KeyKind::Ed25519).unwrap();
        let agent_key = generate(agent_kind).unwrap();
        let host_public = host_key.public_key().to_openssh().unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        // The system clock: russh checks certificate validity against it itself.
        let test = TestServiceBuilder::new(POLICY)
            .clock(Arc::new(SystemClock))
            .watcher(Arc::new(NoSessionWatcher::new()))
            .build(root);
        let (service, approver, ca) = (test.service.clone(), test.approver.clone(), test.ca());
        let config = GatewayConfig {
            host_key,
            repos_root: root.join("repos"),
            signing_key: agent_key.clone(),
            hook_program: bin("writd"),
            state_dir: root.join("run"),
            // No approval listener here: the service is driven directly.
            readers: Vec::new(),
        };
        let gateway = runtime
            .block_on(Gateway::start(config, service.clone()))
            .unwrap();

        let known_hosts = root.join("known_hosts");
        let (url, ssh_target, host) = match listen {
            Listen::Tcp => {
                let listener = runtime
                    .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
                    .unwrap();
                let port = listener.local_addr().unwrap().port();
                let transport = Arc::new(TcpTransport::from_listener(listener));
                let attestor = Arc::new(writ_platform::attest::network::NetworkAttestor::new());
                let g = gateway.clone();
                let local = Sources::Only(vec!["127.0.0.1".parse().unwrap()]);
                runtime
                    .spawn(async move { g.serve(transport, attestor, Role::Agents, local).await });
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
                let transport = Arc::new(UnixTransport(listener));
                let attestor = Arc::new(FakeAttestor::fixed(CallerFacts::default()));
                let g = gateway.clone();
                runtime.spawn(async move {
                    g.serve(transport, attestor, Role::Agents, Sources::Any)
                        .await
                });
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

        let gateway = Self {
            dir,
            runtime,
            service,
            ca,
            approver,
            agent_key,
            url,
            ssh_target,
        };
        gateway.session("session");
        gateway
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    /// A lease for a fresh session key, signed by the approver: writes `keys/<name>` and
    /// `keys/<name>-cert.pub`, returns the lease id.
    pub fn session(&self, name: &str) -> TicketId {
        let key = generate(KeyKind::Ed25519).unwrap();
        let facts = CallerFacts::default();
        let submitted = self
            .service
            .submit(key.public_key(), TICKET.as_bytes(), &facts)
            .unwrap();
        let ticket = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
        self.service
            .approve(
                &submitted.id,
                &sign_approval(&self.approver, &ticket),
                &facts,
            )
            .unwrap();
        let decision = self
            .runtime
            .block_on(self.service.wait(&submitted.id, key.public_key()))
            .unwrap();
        let Decision::Active { certificate, .. } = decision else {
            panic!("expected an active lease, got {decision:?}");
        };
        write_key(&self.root().join("keys").join(name), &key);
        fs::write(
            self.root().join("keys").join(format!("{name}-cert.pub")),
            certificate,
        )
        .unwrap();
        submitted.id
    }

    /// Revokes a lease with a signed revocation.
    pub fn revoke(&self, id: &TicketId) {
        self.service
            .revoke(
                id,
                &sign_revocation(&self.approver, id),
                &CallerFacts::default(),
            )
            .unwrap();
    }

    /// A certificate made directly by `ca`, for no lease.
    pub fn forged_session(
        &self,
        ca: &CertificateAuthority,
        name: &str,
        valid_after: u64,
        valid_before: u64,
    ) -> PathBuf {
        let key = generate(KeyKind::Ed25519).unwrap();
        let path = self.root().join("keys").join(name);
        write_key(&path, &key);
        let cert = ca
            .issue(&CertificateRequest {
                subject: key.public_key(),
                serial: 77,
                key_id: "wrt_01JD8X0000000000000000000",
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
    pub fn ssh_command(&self, key: &Path, with_cert: bool) -> String {
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

    pub fn git_with(&self, ssh_command: &str, cwd: &Path, args: &[&str]) -> Output {
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

    pub fn git(&self, cwd: &Path, args: &[&str]) -> Output {
        let key = self.root().join("keys/session");
        self.git_with(&self.ssh_command(&key, true), cwd, args)
    }

    pub fn git_ok(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.git(cwd, args);
        assert!(
            out.status.success(),
            "git {args:?} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A bare repo `repos/demo.git` with one commit on main, made without the gateway.
    pub fn seed_repo(&self) {
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

    pub fn clone(&self, name: &str) -> PathBuf {
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

    pub fn bare_ref(&self, name: &str) -> Option<String> {
        let out = self.git(
            &self.root().join("repos/demo.git"),
            &["rev-parse", "--verify", "-q", name],
        );
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }
}

/// Writes a private key file (0600).
fn write_key(path: &Path, key: &PrivateKey) {
    crate::write_secret(path, key.to_openssh(LineEnding::LF).unwrap().as_bytes());
}

/// Now, in Unix seconds (for certificates made by hand).
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The `writ-sign` shim.
pub fn writ_sign() -> PathBuf {
    bin("writ-sign")
}
