//! The gateway in-process, on a temporary state directory, with the approval service on the
//! test kit: driven by the real `git` and `ssh` over TCP or a Unix socket, with session
//! certificates from real leases and commits signed through `writ-sign`. Its repo's upstream
//! is a test remote ([`TestRemote`]), reached through the real mirrors; or, started with
//! [`GitGateway::start_https`], the same repositories over HTTPS ([`HttpsRemote`]) with a
//! token.

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
use writ_crypto::algorithm::{Hash, KeyAlgorithm};
use writ_crypto::ca::{CertificateAuthority, CertificateRequest};
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{LineEnding, PrivateKey, PublicKey};
use writ_gateway::{Gateway, GatewayConfig, Role};
use writ_platform::clock::system::SystemClock;
use writ_platform::testing::FakeAttestor;
use writ_platform::transport::tcp::TcpTransport;
use writ_platform::watch::none::NoSessionWatcher;
use writ_platform::{BoxFuture, Connection, PeerInfo, Transport};
use writ_proto::Decision;
use writ_signer::software::SoftwareSigner;
use writ_signer::testing::{FailingSigner, GatedSigner};

use crate::binaries::bin;
use crate::https_remote::HttpsRemote;
use crate::remote::{PLACEHOLDER_UPSTREAM, TestRemote};

/// The token of the HTTPS upstream ([`GitGateway::start_https`]).
pub const HTTPS_TOKEN: &str = "writ-test-gateway-https-token-0123456789";

/// The policy: one repo, `main` and tags protected, one wide template.
pub const POLICY: &str = r#"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
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
    /// The same key as the service's CA, to make certificates by hand, for no lease.
    pub ca: CertificateAuthority,
    pub approver: PrivateKey,
    /// The public key commits are signed with (the template's `signing_key`).
    pub agent_key: PublicKey,
    /// The service's signer: `close()` holds each signature until the test releases it.
    pub signer: Arc<GatedSigner<FailingSigner<SoftwareSigner>>>,
    /// `ssh://git@…` base URL of the gateway.
    pub url: String,
    /// Extra ssh options to reach it (port or proxy command, known hosts).
    pub ssh_target: String,
    /// The lease of the first session (`keys/session`).
    pub lease: TicketId,
    /// The repo's upstream (its repositories, and its SSH server).
    pub remote: TestRemote,
    /// The same repositories over HTTPS, when the repo's upstream is `https://`.
    pub https: Option<HttpsRemote>,
    pub mirrors: writ_mirror::Mirrors,
    /// The gateway itself (what `writd` calls besides serving: the notes reconcile).
    pub gateway: Gateway,
}

impl GitGateway {
    pub fn start(agent_kind: KeyKind, listen: Listen) -> Self {
        Self::start_with(agent_kind, listen, POLICY)
    }

    /// With another policy (its templates' `signing_key`s are the signer's keys); the first
    /// session (`keys/session`) is a lease for [`TICKET`], which must fit it.
    pub fn start_with(agent_kind: KeyKind, listen: Listen, policy: &str) -> Self {
        Self::start_full(agent_kind, listen, policy, false, None)
    }

    /// [`GitGateway::start`] with the signing keys of `algorithm`, signing SSHSIGs with
    /// `hash`, as `writd.yaml` would declare them.
    pub fn start_signing(algorithm: KeyAlgorithm, hash: Hash) -> Self {
        Self::start_full(
            KeyKind::Ed25519,
            Listen::Tcp,
            POLICY,
            false,
            Some((algorithm, hash)),
        )
    }

    /// With the repo's upstream over HTTPS: the test remote's repositories served by an
    /// [`HttpsRemote`] taking [`HTTPS_TOKEN`], which the daemon holds for the repo's
    /// credential; its certificate is the daemon's `ca_certs`.
    pub fn start_https() -> Self {
        Self::start_https_with(POLICY)
    }

    /// [`GitGateway::start_https`], with another policy.
    pub fn start_https_with(policy: &str) -> Self {
        Self::start_full(KeyKind::Ed25519, Listen::Tcp, policy, true, None)
    }

    fn start_full(
        agent_kind: KeyKind,
        listen: Listen,
        policy: &str,
        https: bool,
        signing: Option<(KeyAlgorithm, Hash)>,
    ) -> Self {
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
        let host_public = host_key.public_key().to_openssh().unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        // The repo's upstream: a test remote, its host key pinned, the daemon's credential
        // (one key per credential the policy names) authorized on it.
        let upstream_key = generate(KeyKind::Ed25519).unwrap();
        let remote = TestRemote::start(
            &runtime,
            &root.join("remote"),
            upstream_key.public_key().clone(),
        );
        let https = https.then(|| HttpsRemote::start(&runtime, &root.join("remote"), HTTPS_TOKEN));
        let upstream_url = match &https {
            Some(https) => https.url("demo"),
            None => remote.url("demo"),
        };
        let pinned = format!("{}\n", remote.known_hosts_line());
        let policy = policy.replace(PLACEHOLDER_UPSTREAM, &upstream_url);
        let policy = policy.as_str();
        let credentials: std::collections::BTreeSet<_> =
            writ_core::config::PolicyConfig::from_yaml(policy)
                .unwrap()
                .repos()
                .values()
                .map(|r| r.upstream_credential.clone())
                .collect();
        let tokens: std::collections::BTreeMap<_, _> = match &https {
            Some(_) => credentials
                .iter()
                .map(|id| {
                    let token =
                        writ_mirror::credential::UpstreamToken::from_bytes(HTTPS_TOKEN.as_bytes())
                            .unwrap();
                    (id.clone(), Arc::new(token))
                })
                .collect(),
            None => std::collections::BTreeMap::new(),
        };
        let upstream_signer: Arc<dyn writ_signer::Signer> = Arc::new(
            SoftwareSigner::new(credentials.into_iter().map(|id| (id, upstream_key.clone())))
                .unwrap(),
        );
        let registry = writ_core::config::PolicyConfig::from_yaml(policy).unwrap();
        let mirrors = runtime
            .block_on(writ_mirror::Mirrors::open(
                writ_mirror::MirrorConfig {
                    root: root.join("repos"),
                    run_dir: root.join("mirror"),
                    relay: bin("writd"),
                    git: writ_mirror::testing::git(),
                    ssh: PathBuf::from("/usr/bin/ssh"),
                    pinned: writ_mirror::known_hosts::PinnedHosts::parse(&pinned).unwrap(),
                    ca_certs: https.as_ref().map(|h| h.ca_pem.clone()),
                    // Every fetch and push syncs first: what upstream has, always.
                    fresh_for: std::time::Duration::ZERO,
                    timeout: std::time::Duration::from_secs(60),
                    max_fetch_bytes: 64 << 20,
                },
                registry.repos(),
                upstream_signer,
                &tokens,
            ))
            .unwrap();
        // The system clock: russh checks certificate validity against it itself.
        let mut builder = TestServiceBuilder::new(policy).signer_kind(agent_kind);
        if let Some((algorithm, hash)) = signing {
            builder = builder.signing(algorithm, hash);
        }
        let test = builder
            .clock(Arc::new(SystemClock))
            .watcher(Arc::new(NoSessionWatcher::new()))
            .build(root);
        let (service, approver, ca) = (test.service.clone(), test.approver.clone(), test.ca());
        let agent_key = test.signing_key("agent-01");
        let signer = test.signer.clone();
        let config = GatewayConfig {
            host_key,
            mirrors: Some(mirrors.clone()),
            unsealer: None,
            admin: None,
            hook_program: bin("writd"),
            state_dir: root.join("run"),
            // No approval listener here: the service is driven directly.
            readers: writ_crypto::readers::ReaderSet::default(),
            sign_requests_per_lease: writ_gateway::DEFAULT_SIGN_REQUESTS_PER_LEASE,
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

        let mut gateway = Self {
            lease: "wrt_01JD8X0000000000000000000A".parse().unwrap(),
            dir,
            runtime,
            service,
            ca,
            approver,
            agent_key,
            signer,
            url,
            ssh_target,
            remote,
            https,
            mirrors,
            gateway,
        };
        gateway.lease = gateway.session("session");
        gateway
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    /// A lease for a fresh session key, signed by the approver: writes `keys/<name>` and
    /// `keys/<name>-cert.pub`, returns the lease id.
    pub fn session(&self, name: &str) -> TicketId {
        self.session_with(name, TICKET)
    }

    /// The same, for the ticket `ticket` (YAML, as an agent writes it).
    pub fn session_with(&self, name: &str, ticket: &str) -> TicketId {
        let key = generate(KeyKind::Ed25519).unwrap();
        let facts = CallerFacts::default();
        let submitted = self
            .service
            .submit(key.public_key(), ticket.as_bytes(), &facts)
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
        self.git_command(ssh_command, cwd, args).output().unwrap()
    }

    /// The git command [`GitGateway::git_with`] runs, to start in the background.
    pub fn git_command(&self, ssh_command: &str, cwd: &Path, args: &[&str]) -> Command {
        let mut command = Command::new("git");
        command
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.root().join("home"))
            .env("GIT_CONFIG_GLOBAL", self.root().join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_SSH_COMMAND", ssh_command);
        command
    }

    pub fn git(&self, cwd: &Path, args: &[&str]) -> Output {
        self.git_as("session", cwd, args)
    }

    /// git with the session `keys/<name>`.
    pub fn git_as(&self, name: &str, cwd: &Path, args: &[&str]) -> Output {
        let key = self.root().join("keys").join(name);
        self.git_with(&self.ssh_command(&key, true), cwd, args)
    }

    /// Wires a clone for signing as `writ init` would, with the harness's SSH command (from
    /// `GIT_SSH_COMMAND`): `writ.url`, `writ.repo`, the `writ-sign` shim and the daemon's
    /// signing key, trusted by `allowed_signers` for `git verify-commit`.
    pub fn wire_signing(&self, work: &Path) {
        let agent_public = self.agent_key.to_openssh().unwrap();
        let allowed = self.root().join("allowed_signers");
        fs::write(&allowed, format!("agent@writ {agent_public}\n")).unwrap();
        let shim = writ_sign();
        for (key, value) in [
            ("gpg.format", "ssh"),
            ("gpg.ssh.program", shim.to_str().unwrap()),
            ("user.signingkey", &format!("key::{agent_public}")),
            ("gpg.ssh.allowedSignersFile", allowed.to_str().unwrap()),
            ("writ.url", &self.url),
            ("writ.repo", "demo"),
        ] {
            self.git_ok(work, &["config", key, value]);
        }
    }

    /// A commit of `file` (written with `content`) signed as an agent signs one: through
    /// `writ-sign`, under the first session's lease, with its `Writ:` trailer. Returns its id.
    pub fn commit_signed(&self, work: &Path, file: &str, content: &str) -> String {
        self.commit_signed_as("session", &self.lease, work, file, content)
    }

    /// [`GitGateway::commit_signed`], with the session `keys/<key>` of `lease`.
    pub fn commit_signed_as(
        &self,
        key: &str,
        lease: &TicketId,
        work: &Path,
        file: &str,
        content: &str,
    ) -> String {
        self.commit_signed_full(key, Some(lease), work, file, content)
    }

    /// [`GitGateway::commit_signed_as`] without a `Writ:` trailer (a repo whose `ticket_link`
    /// isn't `trailer`).
    pub fn commit_signed_plain(&self, key: &str, work: &Path, file: &str, content: &str) -> String {
        self.commit_signed_full(key, None, work, file, content)
    }

    fn commit_signed_full(
        &self,
        key: &str,
        trailer: Option<&TicketId>,
        work: &Path,
        file: &str,
        content: &str,
    ) -> String {
        self.wire_signing(work);
        fs::write(work.join(file), content).unwrap();
        let ok = |args: &[&str]| {
            let out = self.git_as(key, work, args);
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };
        ok(&["add", file]);
        match trailer {
            Some(lease) => {
                let trailer = format!("Writ: {lease}");
                ok(&["commit", "-q", "-S", "-m", file, "--trailer", &trailer]);
            }
            None => {
                ok(&["commit", "-q", "-S", "-m", file]);
            }
        }
        ok(&["rev-parse", "HEAD"])
    }

    /// The ledger, read from the service's database.
    pub fn ledger(&self, lease: &TicketId) -> Vec<writ_store::LedgerEntry> {
        writ_store::Store::open(&self.root().join("leases.db"))
            .unwrap()
            .ledger_for_lease(lease)
            .unwrap()
    }

    /// git with `stdin` on its standard input (plumbing: `hash-object --stdin`, `mktree`),
    /// its output; fails the test if git does.
    pub fn git_stdin(&self, cwd: &Path, args: &[&str], stdin: &str) -> String {
        use std::io::Write as _;
        let key = self.root().join("keys").join("session");
        let mut child = self
            .git_command(&self.ssh_command(&key, true), cwd, args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
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

    /// The upstream repo `demo` with one commit on main, made without the gateway (the
    /// mirror gets it on its first sync).
    pub fn seed_repo(&self) {
        let bare = self.remote.repo("demo");
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

    /// A ref of the mirror (`repos/demo.git`).
    pub fn bare_ref(&self, name: &str) -> Option<String> {
        self.ref_in(&self.root().join("repos/demo.git"), name)
    }

    /// A ref of the upstream repo.
    pub fn upstream_ref(&self, name: &str) -> Option<String> {
        self.ref_in(&self.remote.repo("demo"), name)
    }

    /// The note of `commit` upstream under `refs/notes/commits` (the default `notes_ref`), or
    /// `None`.
    pub fn upstream_note(&self, commit: &str) -> Option<String> {
        self.upstream_note_in("refs/notes/commits", commit)
    }

    /// The note of `commit` upstream under `notes_ref`, or `None`.
    pub fn upstream_note_in(&self, notes_ref: &str, commit: &str) -> Option<String> {
        let out = self.git(
            &self.remote.repo("demo"),
            &["notes", &format!("--ref={notes_ref}"), "show", commit],
        );
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// The audit log's lines with this event and result.
    pub fn audited(&self, event: &str, result: &str) -> Vec<serde_json::Value> {
        let text = fs::read_to_string(self.root().join("audit.jsonl")).unwrap_or_default();
        crate::audit_events(&text, event, result)
    }

    /// Waits until the audit log holds `count` lines with this event and result, at most
    /// `limit`, and returns them. What writes them (a notes job) runs on its own after the
    /// push that started it, and a file gives no signal: polled, bounded by `limit`.
    pub fn wait_for_audit(
        &self,
        event: &str,
        result: &str,
        count: usize,
        limit: std::time::Duration,
    ) -> Vec<serde_json::Value> {
        let deadline = std::time::Instant::now() + limit;
        loop {
            let lines = self.audited(event, result);
            if lines.len() >= count {
                return lines;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{} {event} {result} lines within {limit:?}, expected {count}:\n{}",
                lines.len(),
                fs::read_to_string(self.root().join("audit.jsonl")).unwrap_or_default()
            );
            // poll: the line is written by a task of the daemon's that runs on its own (a
            // notes job); the audit file gives no signal. Bounded by `limit`.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn ref_in(&self, repo: &Path, name: &str) -> Option<String> {
        let out = self.git(repo, &["rev-parse", "--verify", "-q", name]);
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
