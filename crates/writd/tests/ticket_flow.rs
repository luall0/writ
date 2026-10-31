//! M2 end to end, with the real binaries: `writd run` on a temporary configuration, the `writ`
//! CLI on both sides, approver signatures made by `ssh-keygen` through a throwaway `ssh-agent`,
//! real `ssh` and `git` with the session certificates, and a fake Telegram Bot API receiving
//! the notifications. The approval API is used over SSH in one scenario and over HTTPS (pinned
//! certificate) in the others.
//!
//! Needs the workspace binaries built (`make test` does it). Never touches the user's `~/.ssh`,
//! git configuration or ssh-agent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{LineEnding, PrivateKey};
use writ_store::looks_secret;

const WRITD: &str = env!("CARGO_BIN_EXE_writd");
const TOKEN: &str = "123456:test-token-abcdefghijklmnopqrstuvwxyz";

fn bin(name: &str) -> PathBuf {
    let path = Path::new(WRITD).with_file_name(name);
    assert!(
        path.exists(),
        "{} missing: run `cargo build --workspace --bins` first (make test does)",
        path.display()
    );
    path
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_secret(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// A fake Telegram Bot API: records the body of every `sendMessage`.
fn fake_telegram() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let sink = received.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut length = 0;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header.trim().is_empty() {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            assert!(
                request_line.contains(&format!("/bot{TOKEN}/sendMessage")),
                "{request_line}"
            );
            sink.lock().unwrap().push(String::from_utf8(body).unwrap());
            let reply = r#"{"ok":true,"result":{}}"#;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
        }
    });
    (port, received)
}

/// A throwaway `ssh-agent` holding the approval key.
struct TestAgent {
    child: Child,
    socket: PathBuf,
}

impl TestAgent {
    fn start(dir: &Path, key: &PrivateKey) -> Self {
        let socket = dir.join("agent.sock");
        let child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let agent = Self { child, socket };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !agent.socket.exists() {
            assert!(Instant::now() < deadline, "ssh-agent did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        let path = dir.join("approver-private");
        write_secret(&path, key.to_openssh(LineEnding::LF).unwrap().as_bytes());
        let status = Command::new("ssh-add")
            .arg("-q")
            .arg(&path)
            .env("SSH_AUTH_SOCK", &agent.socket)
            .status()
            .unwrap();
        assert!(status.success());
        fs::remove_file(path).unwrap();
        agent
    }
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Daemon {
    dir: tempfile::TempDir,
    child: Child,
    agent: TestAgent,
    agents_port: u16,
    https_port: u16,
    /// The approval URL `writ` uses: SSH or HTTPS.
    approval_url: String,
    telegram: Arc<Mutex<Vec<String>>>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const POLICY: &str = r#"
repos:
  demo:
    upstream: ssh://git@forge.invalid/demo.git
    upstream_credential: upstream-01
    protected_refs: ["refs/heads/main"]
templates:
  feature:
    repos: [demo]
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-01
    max_ttl: 2h
    max_signatures: 40
    max_pushes: 20
    max_ops_per_minute: 100
    max_push_size: 10MB
"#;

fn ticket(extra_text: &str, ttl: &str) -> String {
    format!(
        "scope:\n  repos: [demo]\n  operations: [fetch, commit_sign, push]\n  branches: [\"agent/oauth\"]\n\
         ticket:\n  title: \"Add OAuth login\"\n  task: Add GitHub OAuth login behind a feature flag\n\
         {extra_text}limits:\n  ttl: {ttl}\n"
    )
}

/// Which transport `writ` uses for the approval API.
#[derive(Clone, Copy)]
enum Approvals {
    Ssh,
    Https,
}

impl Daemon {
    fn start(approvals: Approvals) -> Self {
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
        fs::write(root.join("policy.yaml"), POLICY).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        write_secret(&root.join("telegram-token"), TOKEN.as_bytes());
        let (telegram_port, telegram) = fake_telegram();
        let (agents_port, approvals_port, https_port) = (free_port(), free_port(), free_port());
        fs::write(
            root.join("writd.yaml"),
            format!(
                "state_dir: s\npolicy: policy.yaml\napprovers: approvers\ndecisions: signed\n\
                 keystore: {{ dev: s/keys }}\n\
                 transports:\n  agents: [{{ tcp: \"127.0.0.1:{agents_port}\" }}]\n  \
                 approvals:\n    ssh: [{{ tcp: \"127.0.0.1:{approvals_port}\" }}]\n    \
                 https: [{{ tcp: \"127.0.0.1:{https_port}\" }}]\n\
                 attestor: network\nsession_watcher: none\n\
                 notifiers:\n  - telegram: {{ token_file: telegram-token, chat_id: \"42\", \
                 api_base: \"http://127.0.0.1:{telegram_port}\" }}\n"
            ),
        )
        .unwrap();
        // The repo the gateway serves (mirrors come in M4).
        let bare = root.join("s/repos/demo.git");
        fs::create_dir_all(&bare).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q", "--bare"])
                .arg(&bare)
                .status()
                .unwrap()
                .success()
        );

        let host_key = Command::new(WRITD)
            .arg("host-key")
            .arg(root.join("writd.yaml"))
            .output()
            .unwrap();
        assert!(
            host_key.status.success(),
            "{}",
            String::from_utf8_lossy(&host_key.stderr)
        );
        let host_key = String::from_utf8(host_key.stdout).unwrap();
        fs::write(
            root.join("known_hosts"),
            format!(
                "[127.0.0.1]:{agents_port} {host}\n[127.0.0.1]:{approvals_port} {host}\n",
                host = host_key.trim()
            ),
        )
        .unwrap();

        let fingerprint = Command::new(WRITD)
            .arg("tls-fingerprint")
            .arg(root.join("writd.yaml"))
            .output()
            .unwrap();
        assert!(
            fingerprint.status.success(),
            "{}",
            String::from_utf8_lossy(&fingerprint.stderr)
        );
        let fingerprint = String::from_utf8(fingerprint.stdout).unwrap();
        assert!(fingerprint.starts_with("SHA256:"), "{fingerprint}");
        fs::write(
            root.join("tls_pins"),
            format!("[127.0.0.1]:{https_port} {}\n", fingerprint.trim()),
        )
        .unwrap();
        let approval_url = match approvals {
            Approvals::Ssh => format!("ssh://127.0.0.1:{approvals_port}"),
            Approvals::Https => format!("https://127.0.0.1:{https_port}"),
        };

        let child = Command::new(WRITD)
            .arg("run")
            .arg(root.join("writd.yaml"))
            .stdout(fs::File::create(root.join("writd.out")).unwrap())
            .stderr(fs::File::create(root.join("writd.err")).unwrap())
            .spawn()
            .unwrap();
        let agent = TestAgent::start(root, &approver);
        let daemon = Self {
            dir,
            child,
            agent,
            agents_port,
            https_port,
            approval_url,
            telegram,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while [agents_port, approvals_port, https_port]
            .iter()
            .any(|port| std::net::TcpStream::connect(("127.0.0.1", *port)).is_err())
        {
            assert!(
                Instant::now() < deadline,
                "writd did not start: {}",
                fs::read_to_string(daemon.root().join("writd.err")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        daemon
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    /// The `writ` CLI with this daemon's endpoints, keys and a private home.
    fn writ(&self, args: &[&str]) -> Command {
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
            .env("WRIT_APPROVAL_AGENT", &self.agent.socket);
        command
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
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
        child.wait_with_output().unwrap()
    }

    /// `writ request` in the background, waiting for the decision.
    fn request(&self, name: &str, ticket: &str) -> Child {
        let file = self.root().join(format!("{name}.yaml"));
        fs::write(&file, ticket).unwrap();
        self.writ(&["request", file.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    /// The id of the only pending ticket, once there is one.
    fn pending(&self) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let out = self.run(&["ls"], "");
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            if let Some(line) = text.lines().find(|l| l.contains(" pending ")) {
                return line.split_whitespace().next().unwrap().to_owned();
            }
            assert!(
                Instant::now() < deadline,
                "no pending ticket: {text}{}",
                stderr(&out)
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The real `ssh`, with a session's key and certificate, nothing from `~/.ssh`.
    fn ssh(&self, session: &Path) -> Command {
        let mut command = Command::new("ssh");
        command
            .args([
                "-F",
                "/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentityAgent=none",
            ])
            .args([
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "LogLevel=ERROR",
            ])
            .arg("-o")
            .arg(format!(
                "UserKnownHostsFile={}",
                self.root().join("known_hosts").display()
            ))
            .args(["-o", "GlobalKnownHostsFile=/dev/null"])
            .arg("-i")
            .arg(session.join("key"))
            .arg("-o")
            .arg(format!(
                "CertificateFile={}",
                session.join("key-cert.pub").display()
            ))
            .args(["-p", &self.agents_port.to_string(), "git@127.0.0.1"]);
        command
    }

    /// `git ls-remote` through the gateway with a session's certificate.
    fn ls_remote(&self, session: &Path) -> Output {
        let ssh = format!(
            "ssh -F /dev/null -o BatchMode=yes -o IdentityAgent=none -o IdentitiesOnly=yes \
             -o StrictHostKeyChecking=yes -o LogLevel=ERROR -o UserKnownHostsFile={} \
             -o GlobalKnownHostsFile=/dev/null -i {} -o CertificateFile={}",
            self.root().join("known_hosts").display(),
            session.join("key").display(),
            session.join("key-cert.pub").display()
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

    fn session(&self, id: &str) -> PathBuf {
        self.root().join("writ/sessions").join(id)
    }

    fn audit(&self) -> String {
        fs::read_to_string(self.root().join("s/audit.jsonl")).unwrap()
    }

    fn audited(&self, event: &str, result: &str) -> usize {
        self.audit()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|e| e["event"] == event && e["result"] == result)
            .count()
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn finish(child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut child = child;
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "process did not end");
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

/// Waits for a process to exit by itself (a dropped session).
fn ends_within(child: &mut Child, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn rejected_signed_narrowed_and_refused_tickets_end_to_end() {
    let daemon = Daemon::start(Approvals::Ssh);

    // Outside every template: rejected before it reaches the approver, with the reason.
    let outside = daemon.root().join("outside.yaml");
    fs::write(&outside, ticket("", "1h").replace("agent/oauth", "main")).unwrap();
    let out = daemon.run(&["request", outside.to_str().unwrap()], "");
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("branch main is not within"),
        "{}",
        stderr(&out)
    );

    // Submitted, notified, shown, narrowed and signed through the agent.
    let request = daemon.request("first", &ticket("", "1h"));
    let id = daemon.pending();
    let deadline = Instant::now() + Duration::from_secs(10);
    while daemon.telegram.lock().unwrap().is_empty() {
        assert!(Instant::now() < deadline, "no notification");
        std::thread::sleep(Duration::from_millis(50));
    }
    let notification = daemon.telegram.lock().unwrap()[0].clone();
    assert!(
        notification.contains("Ticket waiting: Add OAuth login"),
        "{notification}"
    );
    assert!(notification.contains(&id), "{notification}");
    assert!(notification.contains(r#""chat_id":42"#), "{notification}");

    let out = daemon.run(
        &["sign", &id, "--max-signatures", "5", "--drop-op", "push"],
        "y\n",
    );
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let shown = stdout(&out);
    assert!(shown.contains("Narrowed by you"), "{shown}");
    assert!(shown.contains("│ Add OAuth login"), "{shown}");

    let out = finish(request);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("The approver narrowed the ticket"),
        "{}",
        stdout(&out)
    );
    let session = daemon.session(&id);
    let lease = fs::read_to_string(session.join("lease.json")).unwrap();
    assert!(lease.contains(r#""max_signatures":5"#), "{lease}");
    assert!(!lease.contains("\"push\""), "{lease}");
    assert_eq!(
        fs::metadata(session.join("key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::read_link(daemon.root().join("writ/sessions/current")).unwrap(),
        PathBuf::from(&id)
    );
    // The certificate works with the real ssh and git.
    let out = daemon.ls_remote(&session);
    assert!(out.status.success(), "{}", stderr(&out));

    // Refused with feedback (signed: decisions is `signed`); the agent gets it.
    let request = daemon.request("second", &ticket("", "1h"));
    let refused = daemon.pending();
    let out = daemon.run(&["refuse", &refused, "-m", "Don't touch billing"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let out = finish(request);
    assert_eq!(out.status.code(), Some(4), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("│ Don't touch billing"),
        "{}",
        stdout(&out)
    );

    // Revision 2 shows my feedback and the diff, with its escape sequences neutralized.
    let revision = ticket(&format!("  revises: {refused}\n"), "1h")
        .replace("\"Add OAuth login\"", "\"Add OAuth \\e[2J\\e[31mlogin\"");
    let request = daemon.request("third", &revision);
    let third = daemon.pending();
    let out = daemon.run(&["sign", &third], "n\n");
    assert_eq!(out.status.code(), Some(6), "{}", stderr(&out));
    let shown = stdout(&out);
    assert!(shown.contains("revision 2"), "{shown}");
    assert!(shown.contains("Feedback on revision 1"), "{shown}");
    assert!(shown.contains("│ Don't touch billing"), "{shown}");
    assert!(shown.contains("Changes since revision 1"), "{shown}");
    assert!(shown.contains("\\u{1b}[2J"), "{shown}");
    assert!(
        !shown.contains('\x1b'),
        "an escape sequence reached the terminal"
    );

    // Withdrawn: the waiting agent is told.
    let out = daemon.run(&["revoke", &third], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(finish(request).status.code(), Some(5));

    for (event, result) in [
        ("submit", "denied"),
        ("submit", "allowed"),
        ("grant", "allowed"),
        ("refuse", "done"),
        ("revoke", "done"),
        ("connect", "allowed"),
    ] {
        assert!(
            daemon.audited(event, result) >= 1,
            "{event} {result}:\n{}",
            daemon.audit()
        );
    }
    assert!(!looks_secret(&daemon.audit()), "{}", daemon.audit());
    // Clients that come and go (writ, ssh, git) leave no error in the daemon's log.
    let log = fs::read_to_string(daemon.root().join("writd.err")).unwrap();
    assert!(!log.contains("error") && !log.contains("failed"), "{log}");
}

#[test]
fn revocation_and_expiry_drop_sessions_and_refuse_the_certificate() {
    // The approval API over HTTPS this time.
    let daemon = Daemon::start(Approvals::Https);

    // Revocation: the open session is dropped, the next connection refused.
    let request = daemon.request("long", &ticket("", "1h"));
    let id = daemon.pending();
    assert!(daemon.run(&["sign", &id, "--yes"], "").status.success());
    assert!(finish(request).status.success());
    let session = daemon.session(&id);
    let mut open = daemon
        .ssh(&session)
        .arg("git-upload-pack 'demo.git'")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        !ends_within(&mut open, Duration::from_millis(500)),
        "the session should stay open"
    );
    let out = daemon.run(&["revoke", &id], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        ends_within(&mut open, Duration::from_secs(5)),
        "the open session was not dropped"
    );
    assert!(
        !daemon.ls_remote(&session).status.success(),
        "a revoked certificate got in"
    );

    // Expiry: the same, when expires_at passes.
    let request = daemon.request("short", &ticket("", "4s"));
    let short = daemon.pending();
    assert!(daemon.run(&["sign", &short, "--yes"], "").status.success());
    assert!(finish(request).status.success());
    let session = daemon.session(&short);
    let mut open = daemon
        .ssh(&session)
        .arg("git-upload-pack 'demo.git'")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        ends_within(&mut open, Duration::from_secs(10)),
        "the session outlived the lease"
    );
    assert!(
        !daemon.ls_remote(&session).status.success(),
        "an expired certificate got in"
    );

    assert!(daemon.audited("revoke", "done") >= 1, "{}", daemon.audit());
    assert!(daemon.audited("expire", "done") >= 1, "{}", daemon.audit());
    assert!(
        daemon.audited("connect", "denied") >= 1,
        "{}",
        daemon.audit()
    );
    assert!(!looks_secret(&daemon.audit()));
}

#[test]
fn https_approval_clients_check_the_pin_and_both_transports_cannot_be_disabled() {
    let daemon = Daemon::start(Approvals::Https);
    assert!(daemon.run(&["ls"], "").status.success());
    // A pin that doesn't match: refused before anything is sent.
    let other = daemon.root().join("other_pins");
    fs::write(
        &other,
        format!(
            "[127.0.0.1]:{} SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\n",
            daemon.https_port
        ),
    )
    .unwrap();
    let out = daemon.run(&["--tls-pins", other.to_str().unwrap(), "ls"], "");
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("TLS with the daemon failed"),
        "{}",
        stderr(&out)
    );
    // No pin at all: refused, saying how to pin.
    let out = daemon.run(&["--tls-pins", "/dev/null", "ls"], "");
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("writd tls-fingerprint"),
        "{}",
        stderr(&out)
    );

    // Both approval transports disabled: the daemon refuses to start.
    let config = fs::read_to_string(daemon.root().join("writd.yaml")).unwrap();
    let start = config.find("  approvals:").unwrap();
    let end = config.find("attestor:").unwrap();
    let disabled = format!(
        "{}  approvals: {{ ssh: [], https: [] }}\n{}",
        &config[..start],
        &config[end..]
    );
    fs::write(daemon.root().join("disabled.yaml"), disabled).unwrap();
    let out = Command::new(WRITD)
        .arg("run")
        .arg(daemon.root().join("disabled.yaml"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("both disabled"), "{}", stderr(&out));
}
