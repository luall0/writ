//! The real `writd`, on a temporary configuration, and the `writ` CLI for both sides: the
//! agent's (a session key per ticket) and the approver's (signatures through a throwaway
//! `ssh-agent`, over SSH or HTTPS).
//!
//! The daemon listens on port 0 (the OS picks free ports): the fixture reads the ports from
//! the daemon's own log as it starts, so nothing is reserved in advance and nothing polls.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, ExitStatus, Output, Stdio};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{PrivateKey, PublicKey};

use crate::agent::TestAgent;
use crate::binaries::bin;
use crate::remote::TestRemote;
use crate::telegram::{FakeTelegram, TOKEN};
use crate::{WAIT_LIMIT, stderr, write_secret};

/// Which transport `writ` uses for the approval API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approvals {
    Ssh,
    Https,
}

/// The passphrase of the sealed keystore [`Daemon::start_sealed`] makes.
pub const PASSPHRASE: &str = "an integration test passphrase";

/// A running `writd`, killed on drop.
pub struct Daemon {
    dir: TempDir,
    child: Child,
    pub agent: TestAgent,
    pub agents_port: u16,
    pub approvals_port: u16,
    pub https_port: u16,
    /// The approval URL `writ` uses: SSH or HTTPS.
    pub approval_url: String,
    pub telegram: FakeTelegram,
    /// The upstream of the repo `demo` (the policies' `ssh://git@remote.invalid/demo.git`,
    /// rewritten to it), on its own runtime.
    pub remote: TestRemote,
    /// The daemon's log lines after its listeners were announced, as they come.
    log_lines: Mutex<mpsc::Receiver<String>>,
    approvals: Approvals,
    _remote_runtime: tokio::runtime::Runtime,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The ports the daemon announced, from its log lines.
#[derive(Debug, Default)]
struct Ports {
    agents: Option<u16>,
    approvals: Option<u16>,
    https: Option<u16>,
}

impl Ports {
    fn read(&mut self, line: &str) {
        let Some(port) = line
            .split_once("127.0.0.1:")
            .and_then(|(_, rest)| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|digits| digits.parse().ok())
        else {
            return;
        };
        if line.contains("approval API (HTTPS)") {
            self.https = Some(port);
        } else if line.contains("role=Agents") {
            self.agents = Some(port);
        } else if line.contains("role=Approvals") {
            self.approvals = Some(port);
        }
    }

    fn all(&self) -> Option<(u16, u16, u16)> {
        Some((self.agents?, self.approvals?, self.https?))
    }
}

/// What [`Daemon`] prepares before `writd run`: the directory with every file the daemon
/// reads, and the services standing in for upstream and Telegram.
struct Setup {
    dir: TempDir,
    approver: PrivateKey,
    telegram: FakeTelegram,
    remote: TestRemote,
    remote_runtime: tokio::runtime::Runtime,
}

impl Setup {
    fn root(&self) -> &Path {
        self.dir.path()
    }

    /// `writd run` on the prepared configuration, its log going to `writd.err`.
    fn spawn(&self, log: &str) -> Child {
        Command::new(bin("writd"))
            .arg("run")
            .arg(self.root().join("writd.yaml"))
            .env("WRIT_LOG", log)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }
}

/// Edits the default `writd.yaml`: the edit must change it, so a default that drifted fails
/// the test instead of leaving the key unset.
pub type Edit<'a> = &'a dyn Fn(&str) -> String;

impl Daemon {
    /// Starts `writd` with `policy`, one approver key (in the test agent) and `decisions`.
    pub fn start(policy: &str, approvals: Approvals) -> Self {
        Self::launch(setup(policy, None, false), approvals, "info")
    }

    /// [`Daemon::start`] on a sealed keystore, made by `writd init` with [`PASSPHRASE`]: the
    /// daemon starts sealed ([`Daemon::unseal`] opens it).
    pub fn start_sealed(policy: &str, approvals: Approvals) -> Self {
        Self::launch(setup(policy, None, true), approvals, "info")
    }

    /// [`Daemon::start_sealed`], its HTTPS approval API's key made by `writd init` on
    /// `tls_backend` (`--tls-backend`).
    pub fn start_sealed_tls(policy: &str, approvals: Approvals, tls_backend: &str) -> Self {
        Self::launch(
            setup_tls(policy, None, true, &["--tls-backend", tls_backend]),
            approvals,
            "info",
        )
    }

    /// [`Daemon::start_sealed_with`], `writd init` given `init` (`--ca-backend <backend>`…).
    pub fn start_sealed_init(
        policy: &str,
        approvals: Approvals,
        init: &[&str],
        edit: impl Fn(&str) -> String,
    ) -> Self {
        Self::launch(
            setup_tls(policy, Some(&edit), true, init),
            approvals,
            "info",
        )
    }

    /// [`Daemon::start_sealed`] with the default `writd.yaml` edited by `edit`.
    pub fn start_sealed_with(
        policy: &str,
        approvals: Approvals,
        edit: impl Fn(&str) -> String,
    ) -> Self {
        Self::launch(setup(policy, Some(&edit), true), approvals, "info")
    }

    /// `writ unseal` with [`PASSPHRASE`] on stdin.
    pub fn unseal(&self) -> Output {
        self.run(&["unseal"], &format!("{PASSPHRASE}\n"))
    }

    /// Stops the daemon (it is started again by [`Daemon::restart`]).
    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Sends `signal` (`TERM`, `INT`, `KILL`…) to `writd run`.
    pub fn signal(&self, signal: &str) {
        let sent = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(self.child.id().to_string())
            .status()
            .unwrap();
        assert!(sent.success(), "kill -{signal}");
    }

    /// Waits until `writd run` ended (at most [`crate::WAIT_LIMIT`]): how.
    pub fn exited(&mut self) -> ExitStatus {
        let mut ended = None;
        let child = &mut self.child;
        crate::eventually("writd to end", || {
            ended = child.try_wait().unwrap();
            ended.is_some()
        });
        ended.unwrap()
    }

    /// `writd <args…>` (the configuration as given in `args`), with `stdin`.
    pub fn writd_with(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(bin("writd"))
            .args(args)
            .current_dir(self.root())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        crate::process::finish(child)
    }

    /// Stops the daemon and starts it again on the same directory (new ports, pinned again):
    /// a restart. Waits until it announced its listeners.
    pub fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut child = Command::new(bin("writd"))
            .arg("run")
            .arg(self.root().join("writd.yaml"))
            .env("WRIT_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (lines, ports) = announced_ports(&mut child, &self.root().join("writd.err"));
        let Some(ports) = ports else {
            let _ = child.kill();
            panic!("writd did not start again: {}", self.log());
        };
        self.child = child;
        self.log_lines = Mutex::new(lines);
        self.listening(ports);
    }

    /// Pins the daemon on the ports it announced, and points `writ` at them.
    fn listening(&mut self, (agents, approvals, https): (u16, u16, u16)) {
        pin(self.root(), agents, approvals, https);
        self.agents_port = agents;
        self.approvals_port = approvals;
        self.https_port = https;
        self.approval_url = approval_url(self.approvals, approvals, https);
    }

    /// [`Daemon::start`] with the default `writd.yaml` edited by `edit` (which must change
    /// it).
    pub fn start_with(policy: &str, approvals: Approvals, edit: impl Fn(&str) -> String) -> Self {
        Self::launch(setup(policy, Some(&edit), false), approvals, "info")
    }

    /// Local mode: [`Daemon::start`] with a second agents' listener on a Unix socket
    /// ([`Daemon::agents_socket`]), this OS's process chain attestor and session watcher
    /// (macOS: kqueue; Linux: pidfds, `/proc` read by the daemon itself, which runs as the
    /// test's user). The TCP listeners stay (a TCP caller gets no process chain).
    pub fn start_local(policy: &str, approvals: Approvals) -> Self {
        let local = match std::env::consts::OS {
            "linux" => "attestor: linux_process_chain\nsession_watcher: linux",
            _ => "attestor: macos_process_chain\nsession_watcher: macos",
        };
        Self::start_with(policy, approvals, move |yaml| {
            yaml.replace(
                "  agents: [{ tcp: \"127.0.0.1:0\", allow: [127.0.0.1] }]",
                "  agents: [{ tcp: \"127.0.0.1:0\", allow: [127.0.0.1] }, { unix: run/agents.sock }]",
            )
            .replace("attestor: network\nsession_watcher: none", local)
        })
    }

    /// The agents' Unix socket of [`Daemon::start_local`].
    pub fn agents_socket(&self) -> PathBuf {
        self.root().join("run/agents.sock")
    }

    /// [`Daemon::writ`] reaching the daemon on its agents' Unix socket.
    pub fn writ_local(&self, args: &[&str]) -> Command {
        let mut command = self.writ(args);
        command.env(
            "WRIT_URL",
            format!("unix:{}", self.agents_socket().display()),
        );
        command
    }

    /// [`Daemon::start_with`], with `WRIT_LOG` set to `log` (`info` otherwise).
    pub fn start_logging(
        policy: &str,
        approvals: Approvals,
        log: &str,
        edit: impl Fn(&str) -> String,
    ) -> Self {
        Self::launch(setup(policy, Some(&edit), false), approvals, log)
    }

    /// The same directory as [`Daemon::start_with`], but `writd run` must refuse to start:
    /// returns what it printed (its status is checked: 1).
    pub fn refused(policy: &str, edit: impl Fn(&str) -> String) -> String {
        let setup = setup(policy, Some(&edit), false);
        let mut child = setup.spawn("info");
        if !crate::process::ends_within(&mut child, WAIT_LIMIT) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("writd run started, it should have refused to");
        }
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        stderr(&out)
    }

    /// The same directory as [`Daemon::start`] with `policy`, but `writd run` finds `refused`
    /// (on the same test remote) as its policy file at its first start, and must refuse to
    /// start: returns what it printed (its status is checked: 1).
    pub fn refused_policy(policy: &str, refused: &str) -> String {
        let setup = setup(policy, None, false);
        fs::write(
            setup.root().join("policy.yaml"),
            setup.remote.placed(refused, &setup.remote.url("demo")),
        )
        .unwrap();
        let mut child = setup.spawn("info");
        if !crate::process::ends_within(&mut child, WAIT_LIMIT) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("writd run started, it should have refused to");
        }
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        stderr(&out)
    }

    fn launch(setup: Setup, approvals: Approvals, log: &str) -> Self {
        let root = setup.root();
        let fingerprint = writd(root, "tls-fingerprint");
        assert!(fingerprint.starts_with("SHA256:"), "{fingerprint}");

        let mut child = setup.spawn(log);
        let (lines, ports) = announced_ports(&mut child, &root.join("writd.err"));
        let Some((agents_port, approvals_port, https_port)) = ports else {
            let _ = child.kill();
            panic!(
                "writd did not start: {}",
                fs::read_to_string(root.join("writd.err")).unwrap_or_default()
            );
        };
        pin(root, agents_port, approvals_port, https_port);
        let approval_url = approval_url(approvals, approvals_port, https_port);
        let agent = TestAgent::start();
        agent.add(&setup.approver);
        let Setup {
            dir,
            telegram,
            remote,
            remote_runtime,
            ..
        } = setup;
        Self {
            dir,
            child,
            agent,
            agents_port,
            approvals_port,
            https_port,
            approval_url,
            telegram,
            remote,
            log_lines: Mutex::new(lines),
            approvals,
            _remote_runtime: remote_runtime,
        }
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    /// The `writd run` process's id (the benchmark reads its CPU time and memory).
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The daemon's log so far.
    pub fn log(&self) -> String {
        fs::read_to_string(self.root().join("writd.err")).unwrap_or_default()
    }

    /// Waits for the next log line containing `needle` (lines logged after the listeners
    /// were announced, each looked at once), at most `limit`: returns it.
    pub fn wait_for_log(&self, needle: &str, limit: Duration) -> String {
        let lines = self.log_lines.lock().unwrap();
        let deadline = Instant::now() + limit;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match lines.recv_timeout(left) {
                Ok(line) if line.contains(needle) => return line,
                Ok(_) => {}
                Err(_) => panic!(
                    "no log line with {needle:?} within {limit:?}:\n{}",
                    self.log()
                ),
            }
        }
    }

    /// A commit on `branch` of the upstream repo `demo`, made there directly (not through
    /// the daemon): upstream moving on its own. Returns its id.
    pub fn upstream_commit(&self, branch: &str, message: &str) -> String {
        let seed = self.root().join("upstream-seed");
        let git = |args: &[&str]| {
            let out = Command::new("git")
                .args([
                    "-c",
                    "user.name=Upstream",
                    "-c",
                    "user.email=up@example.com",
                ])
                .args(args)
                .current_dir(&seed)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
            String::from_utf8(out.stdout).unwrap().trim().to_owned()
        };
        if !seed.exists() {
            fs::create_dir_all(&seed).unwrap();
            git(&["init", "-q", "-b", branch]);
        }
        git(&["commit", "-q", "--allow-empty", "-m", message]);
        let upstream = self.remote.repo("demo");
        git(&[
            "push",
            "-q",
            "-f",
            upstream.to_str().unwrap(),
            &format!("HEAD:refs/heads/{branch}"),
        ]);
        git(&["rev-parse", "HEAD"])
    }

    /// A ticket submitted and signed as is: the lease's id (its session files are in
    /// [`Daemon::session`]).
    pub fn lease(&self, name: &str, ticket: &str) -> String {
        let request = self.request(name, ticket);
        let id = request.id.clone();
        let out = self.run(&["sign", &id, "--yes"], "");
        assert!(out.status.success(), "writ sign: {}", stderr(&out));
        let (status, out, err) = request.finish();
        assert_eq!(status.code(), Some(0), "{out}{err}");
        id
    }

    /// The `writ` CLI with this daemon's endpoints, keys and a private home.
    pub fn writ(&self, args: &[&str]) -> Command {
        let mut command = Command::new(bin("writ"));
        command
            .args(args)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.root().join("home"))
            .env("WRIT_HOME", self.root().join("writ"))
            .env("WRIT_KNOWN_HOSTS", self.root().join("known_hosts"))
            .env("WRIT_URL", format!("ssh://127.0.0.1:{}", self.agents_port))
            .env("WRIT_TLS_PINS", self.root().join("tls_pins"))
            .env("WRIT_APPROVAL_URL", &self.approval_url)
            .env("WRIT_APPROVAL_KEY", self.root().join("approver.pub"))
            .env("WRIT_APPROVAL_AGENT", self.agent.socket());
        command
    }

    /// Runs `writ` to the end with `stdin`.
    pub fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = self
            .writ(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        crate::process::finish(child)
    }

    /// `writ request` in the background, waiting for the decision. Returns once the ticket
    /// is submitted (the CLI's first line names it), with the process still waiting.
    pub fn request(&self, name: &str, ticket: &str) -> Request {
        self.request_through(name, ticket, Self::writ)
    }

    /// [`Daemon::request`] over the agents' Unix socket ([`Daemon::start_local`]).
    pub fn request_local(&self, name: &str, ticket: &str) -> Request {
        self.request_through(name, ticket, Self::writ_local)
    }

    fn request_through(
        &self,
        name: &str,
        ticket: &str,
        writ: fn(&Self, &[&str]) -> Command,
    ) -> Request {
        let file = self.root().join(format!("{name}.yaml"));
        fs::write(&file, ticket).unwrap();
        let mut child = writ(self, &["request", file.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut first = String::new();
        stdout.read_line(&mut first).unwrap();
        let id = first
            .strip_prefix("Ticket ")
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or_else(|| {
                let mut err = String::new();
                let _ = child.stderr.take().unwrap().read_to_string(&mut err);
                panic!("writ request didn't submit: {first:?} {err}")
            })
            .to_owned();
        Request {
            id,
            child,
            stdout,
            first,
        }
    }

    /// A lease's session files on the agent host.
    pub fn session(&self, id: &str) -> PathBuf {
        self.root().join("writ/sessions").join(id)
    }

    /// The real `ssh`, with a session's key and certificate, nothing from `~/.ssh`.
    pub fn ssh(&self, session: &Path) -> Command {
        let mut command = Command::new("ssh");
        command.args(ssh_options(&self.root().join("known_hosts"), session));
        command.args(["-p", &self.agents_port.to_string(), "git@127.0.0.1"]);
        command
    }

    /// `git ls-remote` through the gateway with a session's certificate.
    pub fn ls_remote(&self, session: &Path) -> Output {
        let ssh = format!(
            "ssh {}",
            ssh_options(&self.root().join("known_hosts"), session).join(" ")
        );
        Command::new("git")
            .args([
                "ls-remote",
                &format!("ssh://git@127.0.0.1:{}/demo.git", self.agents_port),
            ])
            .env("GIT_SSH_COMMAND", ssh)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("HOME", self.root().join("home"))
            .output()
            .unwrap()
    }

    /// A shell script running `git ls-remote` through the agents' Unix socket with a
    /// session's certificate (ssh through `nc -U`, as `writ init` wires a local endpoint):
    /// run by whichever process should be its ancestor (`/bin/sh <script>`).
    pub fn ls_remote_local_script(&self, session: &Path) -> PathBuf {
        let quote = |text: &str| format!("'{}'", text.replace('\'', "'\\''"));
        let ssh = format!(
            "ssh {} -o HostKeyAlias={} -o ProxyCommand={}",
            ssh_options(&self.root().join("known_hosts"), session).join(" "),
            crate::LOCAL_HOST_ALIAS,
            quote(&format!(
                "/usr/bin/nc -U {}",
                self.agents_socket().display()
            ))
        );
        let script = format!(
            "export GIT_SSH_COMMAND={}\nexport GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
             HOME={}\nexec git ls-remote ssh://git@{}/demo.git\n",
            quote(&ssh),
            quote(&self.root().join("home").display().to_string()),
            crate::LOCAL_HOST_ALIAS
        );
        let path = session.with_extension("ls-remote.sh");
        fs::write(&path, script).unwrap();
        path
    }

    /// `writd <command> <writd.yaml>` for a command that prints (`signing-keys`,
    /// `upstream-keys`, `host-key`): its output, trimmed.
    pub fn print(&self, command: &str) -> String {
        writd(self.root(), command)
    }

    /// The audit log so far.
    pub fn audit(&self) -> String {
        fs::read_to_string(self.root().join("s/audit.jsonl")).unwrap()
    }

    /// How many audit lines have this event and result.
    pub fn audited(&self, event: &str, result: &str) -> usize {
        crate::audit_events(&self.audit(), event, result).len()
    }
}

/// Pins the daemon's host key and TLS certificate on its ports, as `writd host-key` and
/// `writd tls-fingerprint` print them (no passphrase needed).
fn pin(root: &Path, agents: u16, approvals: u16, https: u16) {
    let host_key = writd(root, "host-key");
    let fingerprint = writd(root, "tls-fingerprint");
    fs::write(
        root.join("known_hosts"),
        format!(
            "[127.0.0.1]:{agents} {host_key}\n[127.0.0.1]:{approvals} {host_key}\n\
             {} {host_key}\n",
            crate::LOCAL_HOST_ALIAS
        ),
    )
    .unwrap();
    fs::write(
        root.join("tls_pins"),
        format!("[127.0.0.1]:{https} {fingerprint}\n"),
    )
    .unwrap();
    // `writ` refuses a pins file group or others can write: never left to the umask.
    for file in ["known_hosts", "tls_pins"] {
        private(&root.join(file));
    }
}

/// Makes `path` readable and writable by its owner only (`0600`), whatever the umask.
pub fn private(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn approval_url(approvals: Approvals, ssh: u16, https: u16) -> String {
    match approvals {
        Approvals::Ssh => format!("ssh://127.0.0.1:{ssh}"),
        Approvals::Https => format!("https://127.0.0.1:{https}"),
    }
}

/// Writes the daemon's directory: the approver and reader keys, the policy (its upstream
/// rewritten to a fresh test remote, whose `demo` is empty), the Telegram token, and
/// `writd.yaml` (edited by `edit`, which must change it); the daemon's upstream credential is
/// authorized on the remote.
fn setup(policy: &str, edit: Option<Edit<'_>>, sealed: bool) -> Setup {
    setup_tls(policy, edit, sealed, &[])
}

/// [`setup`], `writd init` given `init` (`--tls-backend <backend>`, `--ca-backend <backend>`;
/// a sealed keystore).
fn setup_tls(policy: &str, edit: Option<Edit<'_>>, sealed: bool, init_args: &[&str]) -> Setup {
    crate::tools::require();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let approver = generate(KeyKind::Ed25519).unwrap();
    let approver_public = approver.public_key().to_openssh().unwrap();
    fs::write(
        root.join("approvers"),
        format!("me@mac {approver_public}\n"),
    )
    .unwrap();
    fs::write(root.join("approver.pub"), format!("{approver_public}\n")).unwrap();
    // The repo's upstream: a test remote with an empty `demo`, its host key pinned.
    let remote_runtime = tokio::runtime::Runtime::new().unwrap();
    let placeholder = generate(KeyKind::Ed25519).unwrap();
    let remote = TestRemote::start(
        &remote_runtime,
        &root.join("remote"),
        placeholder.public_key().clone(),
    );
    let init = Command::new("git")
        .args(["init", "-q", "--bare"])
        .arg(remote.repo("demo"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap();
    assert!(init.success());
    fs::write(
        root.join("policy.yaml"),
        remote.placed(policy, &remote.url("demo")),
    )
    .unwrap();
    fs::create_dir_all(root.join("home")).unwrap();
    // A directory for local mode's sockets, as the installer makes it (nobody else writes it).
    fs::create_dir(root.join("run")).unwrap();
    fs::set_permissions(
        root.join("run"),
        std::os::unix::fs::PermissionsExt::from_mode(0o750),
    )
    .unwrap();
    write_secret(&root.join("telegram-token"), TOKEN.as_bytes());
    // The approver's reader key, made by the real `writ reader`, listed in `readers`.
    let reader = Command::new(bin("writ"))
        .args(["reader", "test-mac"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("WRIT_HOME", root.join("writ"))
        .output()
        .unwrap();
    assert!(reader.status.success(), "writ reader: {reader:?}");
    let line = String::from_utf8(reader.stdout).unwrap();
    assert!(line.starts_with("test-mac ssh-ed25519 "), "{line}");
    fs::write(root.join("readers"), line).unwrap();
    let telegram = FakeTelegram::start();
    let yaml = format!(
        "state_dir: s\npolicy: policy.yaml\napprovers: approvers\nreaders: readers\n\
         decisions: signed\nkeystore: {{ dev: s/keys }}\n\
         mirrors: {{ fresh_for: 0s }}\n\
         transports:\n  agents: [{{ tcp: \"127.0.0.1:0\", allow: [127.0.0.1] }}]\n  \
         approvals:\n    ssh: [{{ tcp: \"127.0.0.1:0\" }}]\n    \
         https: [{{ tcp: \"127.0.0.1:0\" }}]\n\
         attestor: network\nsession_watcher: none\n\
         notifiers:\n  - telegram: {{ token: {{ boot: telegram-token }}, chat_id: \"42\", \
         api_base: \"http://127.0.0.1:{}\" }}\n",
        telegram.port
    );
    let yaml = if sealed {
        yaml.replace(
            "keystore: { dev: s/keys }",
            "keystore: { sealed: { dir: s/keys, boot: s/boot } }",
        )
    } else {
        yaml
    };
    fs::write(root.join("writd.yaml"), &yaml).unwrap();
    // With init flags (a backend `writd init` makes keys on), the edit comes first: `writd
    // init` makes them with the helper the edit names.
    let edit_first = !init_args.is_empty();
    if edit_first && let Some(edit) = edit {
        let edited = edit(&yaml);
        assert_ne!(edited, yaml, "the edit left writd.yaml as it was");
        fs::write(root.join("writd.yaml"), edited).unwrap();
    }
    if sealed {
        // `writd init`, the passphrase on stdin as a script gives it.
        let mut init = Command::new(bin("writd"))
            .arg("init")
            .arg(root.join("writd.yaml"))
            .args(init_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        init.stdin
            .take()
            .unwrap()
            .write_all(format!("{PASSPHRASE}\n").as_bytes())
            .unwrap();
        let out = crate::process::finish(init);
        assert!(out.status.success(), "writd init: {}", stderr(&out));
    }
    // The daemon's upstream credential (made by its dev keystore), authorized on the remote:
    // read with the default configuration, so an edit the daemon refuses still gets here.
    let keys = writd(root, "upstream-keys");
    let line = keys.lines().next().expect("an upstream credential");
    let key: Vec<&str> = line.split(' ').skip(1).take(2).collect();
    remote.authorize(PublicKey::from_openssh(&key.join(" ")).unwrap());
    if !edit_first && let Some(edit) = edit {
        let edited = edit(&yaml);
        assert_ne!(edited, yaml, "the edit left writd.yaml as it was");
        fs::write(root.join("writd.yaml"), edited).unwrap();
    }
    Setup {
        dir,
        approver,
        telegram,
        remote,
        remote_runtime,
    }
}

/// `writd <command> <config>` (host-key, tls-fingerprint…): its output, trimmed.
fn writd(root: &Path, command: &str) -> String {
    let out = Command::new(bin("writd"))
        .arg(command)
        .arg(root.join("writd.yaml"))
        .output()
        .unwrap();
    assert!(out.status.success(), "writd {command}: {}", stderr(&out));
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// Reads the daemon's log (copying it to `log`) until it announced its three listeners, or
/// it ended, or [`WAIT_LIMIT`] passed. Keeps copying in the background afterwards, and
/// sending each line after those to the receiver returned.
fn announced_ports(
    child: &mut Child,
    log: &Path,
) -> (mpsc::Receiver<String>, Option<(u16, u16, u16)>) {
    let stderr = child.stderr.take().unwrap();
    let mut file = fs::File::create(log).unwrap();
    let (lines, announced) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { return };
            let _ = writeln!(file, "{line}");
            let _ = lines.send(line);
        }
    });
    let deadline = std::time::Instant::now() + WAIT_LIMIT;
    let mut ports = Ports::default();
    while ports.all().is_none() {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match announced.recv_timeout(left) {
            Ok(line) => ports.read(&line),
            Err(_) => return (announced, None),
        }
    }
    let all = ports.all();
    (announced, all)
}

/// The ssh options that keep a client away from the user's own SSH setup: no config, no other
/// key, no agent, only the pinned host key.
pub fn ssh_options(known_hosts: &Path, session: &Path) -> Vec<String> {
    [
        "-F",
        "/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain([
        "-o".to_owned(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "-i".to_owned(),
        session.join("key").display().to_string(),
        "-o".to_owned(),
        format!("CertificateFile={}", session.join("key-cert.pub").display()),
    ])
    .collect()
}

/// A `writ request` waiting for its decision.
pub struct Request {
    pub id: String,
    child: Child,
    stdout: BufReader<ChildStdout>,
    first: String,
}

impl Request {
    /// Waits for the CLI to end (the decision came): its status, stdout and stderr.
    pub fn finish(self) -> (ExitStatus, String, String) {
        let Self {
            child,
            mut stdout,
            first,
            ..
        } = self;
        let (done, ended) = mpsc::channel();
        std::thread::spawn(move || {
            let mut rest = String::new();
            let _ = stdout.read_to_string(&mut rest);
            let _ = done.send((rest, child.wait_with_output()));
        });
        let (rest, output) = ended
            .recv_timeout(WAIT_LIMIT)
            .expect("writ request did not end");
        let output = output.unwrap();
        (output.status, first + &rest, crate::stderr(&output))
    }
}
