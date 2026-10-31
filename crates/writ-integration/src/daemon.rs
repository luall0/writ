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
use std::sync::mpsc;

use tempfile::TempDir;
use writ_crypto::keys::{KeyKind, generate};

use crate::agent::TestAgent;
use crate::binaries::bin;
use crate::telegram::{FakeTelegram, TOKEN};
use crate::{WAIT_LIMIT, stderr, write_secret};

/// Which transport `writ` uses for the approval API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approvals {
    Ssh,
    Https,
}

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

impl Daemon {
    /// Starts `writd` with `policy`, one approver key (in the test agent) and `decisions`.
    pub fn start(policy: &str, approvals: Approvals) -> Self {
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
        fs::write(root.join("policy.yaml"), policy).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
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
        fs::write(
            root.join("writd.yaml"),
            format!(
                "state_dir: s\npolicy: policy.yaml\napprovers: approvers\nreaders: readers\n\
                 decisions: signed\nkeystore: {{ dev: s/keys }}\n\
                 transports:\n  agents: [{{ tcp: \"127.0.0.1:0\", allow: [127.0.0.1] }}]\n  \
                 approvals:\n    ssh: [{{ tcp: \"127.0.0.1:0\" }}]\n    \
                 https: [{{ tcp: \"127.0.0.1:0\" }}]\n\
                 attestor: network\nsession_watcher: none\n\
                 notifiers:\n  - telegram: {{ token_file: telegram-token, chat_id: \"42\", \
                 api_base: \"http://127.0.0.1:{}\" }}\n",
                telegram.port
            ),
        )
        .unwrap();
        // The repo the gateway serves (mirrors come in M4).
        let bare = root.join("s/repos/demo.git");
        fs::create_dir_all(&bare).unwrap();
        let init = Command::new("git")
            .args(["init", "-q", "--bare"])
            .arg(&bare)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .status()
            .unwrap();
        assert!(init.success());

        let host_key = writd(root, "host-key");
        let fingerprint = writd(root, "tls-fingerprint");
        assert!(fingerprint.starts_with("SHA256:"), "{fingerprint}");

        let mut child = Command::new(bin("writd"))
            .arg("run")
            .arg(root.join("writd.yaml"))
            .env("WRIT_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let ports = announced_ports(&mut child, &root.join("writd.err"));
        let Some((agents_port, approvals_port, https_port)) = ports else {
            let _ = child.kill();
            panic!(
                "writd did not start: {}",
                fs::read_to_string(root.join("writd.err")).unwrap_or_default()
            );
        };
        fs::write(
            root.join("known_hosts"),
            format!(
                "[127.0.0.1]:{agents_port} {host_key}\n[127.0.0.1]:{approvals_port} {host_key}\n"
            ),
        )
        .unwrap();
        fs::write(
            root.join("tls_pins"),
            format!("[127.0.0.1]:{https_port} {fingerprint}\n"),
        )
        .unwrap();
        let approval_url = match approvals {
            Approvals::Ssh => format!("ssh://127.0.0.1:{approvals_port}"),
            Approvals::Https => format!("https://127.0.0.1:{https_port}"),
        };
        let agent = TestAgent::start();
        agent.add(&approver);
        Self {
            dir,
            child,
            agent,
            agents_port,
            approvals_port,
            https_port,
            approval_url,
            telegram,
        }
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    /// The daemon's log so far.
    pub fn log(&self) -> String {
        fs::read_to_string(self.root().join("writd.err")).unwrap_or_default()
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
        let file = self.root().join(format!("{name}.yaml"));
        fs::write(&file, ticket).unwrap();
        let mut child = self
            .writ(&["request", file.to_str().unwrap()])
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

    /// The audit log so far.
    pub fn audit(&self) -> String {
        fs::read_to_string(self.root().join("s/audit.jsonl")).unwrap()
    }

    /// How many audit lines have this event and result.
    pub fn audited(&self, event: &str, result: &str) -> usize {
        crate::audit_events(&self.audit(), event, result).len()
    }
}

/// `writd <command> <config>` (host-key, tls-fingerprint): its one line of output.
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
/// it ended, or [`WAIT_LIMIT`] passed. Keeps copying in the background afterwards.
fn announced_ports(child: &mut Child, log: &Path) -> Option<(u16, u16, u16)> {
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
            Err(_) => return None,
        }
    }
    ports.all()
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
