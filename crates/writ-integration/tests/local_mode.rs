//! Local mode on the Mac with the real daemon (M7): agents on a Unix socket, the macOS
//! process chain attestor and the kqueue session watcher plugged into an unchanged core. On
//! another OS these tests say so and pass: the Linux implementations come with M7.1.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::{audit_events, stderr, stdout};

const POLICY: &str = r#"
keys:
  agent-01:
    use: signing
    format: ssh
    algorithm: ed25519
  upstream-01:
    use: upstream
    kind: ssh
    algorithm: ed25519
upstream_hosts:
  remote.invalid:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    templates: [feature]
    protected_refs: ["refs/heads/main"]
templates:
  feature:
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

const TICKET: &str = "repos:\n  demo:\n    operations: [fetch]\n    branches: [\"agent/*\"]\n\
                      ticket:\n  title: Local mode\n  task: Fetch\nlimits:\n  ttl: 1h\n";

/// Whether this OS has local mode's implementations in this build.
fn local_mode_here() -> bool {
    let here = std::env::consts::OS == "macos";
    if !here {
        eprintln!(
            "local mode on {} comes with M7.1: nothing to run",
            std::env::consts::OS
        );
    }
    here
}

#[test]
fn a_ticket_over_the_unix_socket_carries_the_kernel_s_process_chain() {
    if !local_mode_here() {
        return;
    }
    let daemon = Daemon::start_local(POLICY, Approvals::Ssh);
    let listening = daemon.log();
    assert!(
        listening.contains(&format!(
            "listener=unix {} role=Agents",
            daemon.agents_socket().display()
        )),
        "{listening}"
    );
    let request = daemon.request_local("local", TICKET);
    let out = daemon.run(&["sign", &request.id, "--yes"], "");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let (status, out, err) = request.finish();
    assert_eq!(status.code(), Some(0), "{out}{err}");

    // The submission's caller: `writ` first, as the kernel resolved it, then its ancestors
    // up to launchd.
    let audit = daemon.audit();
    let submitted = audit_events(&audit, "submit", "allowed");
    let chain = submitted[0]["process_chain"].as_array().unwrap();
    let writ = writ_integration::binaries::bin("writ")
        .canonicalize()
        .unwrap();
    assert_eq!(chain[0], writ.to_str().unwrap(), "{chain:?}");
    assert_eq!(chain.last().unwrap(), "/sbin/launchd", "{chain:?}");
    // Over TCP, the same daemon has no chain to give.
    let request = daemon.request("tcp", TICKET);
    let out = daemon.run(&["refuse", &request.id, "-m", "Not this one"], "");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    request.finish();
    let audit = daemon.audit();
    let submitted = audit_events(&audit, "submit", "allowed");
    assert_eq!(submitted[1]["process_chain"], serde_json::Value::Null);
    assert_eq!(submitted[1]["source_addr"], "127.0.0.1");
}

/// A session's root process: a shell running the lines it is sent, one at a time, saying
/// `done <status>` after each. What it runs descends from it.
struct SessionRoot {
    child: std::process::Child,
    lines: std::sync::mpsc::Receiver<String>,
}

impl SessionRoot {
    /// The shell, with the environment `writ` gets from the fixture (the local endpoint).
    fn start(daemon: &Daemon) -> Self {
        let template = daemon.writ_local(&[]);
        let mut shell = std::process::Command::new("/bin/sh");
        shell
            .arg("-c")
            .arg("while IFS= read -r line; do eval \"$line\"; echo \"done $?\"; done")
            .env_clear()
            .envs(
                template.get_envs().filter_map(|(key, value)| {
                    value.map(|value| (key.to_owned(), value.to_owned()))
                }),
            )
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        let mut child = shell.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufRead::lines(std::io::BufReader::new(stdout)) {
                let Ok(line) = line else { return };
                let _ = send.send(line);
            }
        });
        Self { child, lines }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Sends one line to run.
    fn send(&mut self, line: &str) {
        let stdin = self.child.stdin.as_mut().unwrap();
        std::io::Write::write_all(stdin, format!("{line}\n").as_bytes()).unwrap();
        std::io::Write::flush(stdin).unwrap();
    }

    /// The next line it printed.
    fn next(&self) -> String {
        self.lines
            .recv_timeout(writ_integration::WAIT_LIMIT)
            .expect("the session's shell said nothing")
    }

    /// The lines up to the end of the command, and its status.
    fn finish(&self) -> (Vec<String>, i32) {
        let mut printed = Vec::new();
        loop {
            let line = self.next();
            if let Some(status) = line.strip_prefix("done ") {
                return (printed, status.parse().unwrap());
            }
            printed.push(line);
        }
    }

    /// Ends the shell (its stdin closed) and waits for it.
    fn end(mut self) {
        drop(self.child.stdin.take());
        self.child.wait().unwrap();
    }
}

const REQUIRED: &str = "    max_push_size: 10MB\n";

#[test]
fn a_lease_bound_to_its_session_serves_inside_it_only_and_ends_with_it() {
    if !local_mode_here() {
        return;
    }
    let policy = POLICY.replacen(
        REQUIRED,
        "    max_push_size: 10MB\n    require_session: true\n",
        1,
    );
    assert_ne!(policy, POLICY);
    let daemon = Daemon::start_local(&policy, Approvals::Ssh);
    let writ = writ_integration::binaries::bin("writ");

    // Unbound, over the socket: the template requires a session.
    let unbound = daemon.root().join("unbound.yaml");
    std::fs::write(&unbound, TICKET).unwrap();
    let out = daemon
        .writ_local(&["request", unbound.to_str().unwrap()])
        .output()
        .unwrap();
    // Rejected by policy (3), the session refusal's reason said.
    assert_eq!(out.status.code(), Some(3), "{}", stdout(&out));
    assert!(
        stderr(&out).contains(
            "repos.demo: the template feature requires a session binding (caller): start the \
             agent under `writ run`"
        ),
        "{}",
        stderr(&out)
    );

    // Bound to the session's root, submitted from inside it: completed from the kernel.
    let mut root = SessionRoot::start(&daemon);
    let bound = daemon.root().join("bound.yaml");
    std::fs::write(
        &bound,
        format!(
            "caller:\n  descends_from: {{ pid: {} }}\n{TICKET}",
            root.pid()
        ),
    )
    .unwrap();
    root.send(&format!(
        "'{}' request '{}'",
        writ.display(),
        bound.display()
    ));
    let first = root.next();
    let id = first
        .strip_prefix("Ticket ")
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("{first}"))
        .to_owned();
    // The approver sees the binding the daemon completed: the session's shell as the
    // kernel names it (macOS's /bin/sh runs on as /bin/bash), by its pid, with its signature.
    let out = daemon.run(&["sign", &id, "--yes"], "");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let shown = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        shown.contains("caller             descends from /bin/")
            && shown.contains(&format!("(pid {}, generation", root.pid()))
            && shown.contains("signed com.apple."),
        "{shown}"
    );
    let (said, status) = root.finish();
    assert_eq!(status, 0, "{said:?}");
    let session = daemon.session(&id);
    let script = daemon.ls_remote_local_script(&session);

    // Inside the session: served.
    root.send(&format!("/bin/sh '{}'", script.display()));
    let (said, status) = root.finish();
    assert_eq!(status, 0, "{said:?}");
    // Outside it (this test runs it), and over TCP: refused, the caller check's doing.
    let outside = std::process::Command::new("/bin/sh")
        .arg(&script)
        .output()
        .unwrap();
    assert_eq!(outside.status.code(), Some(128), "{}", stderr(&outside));
    let over_tcp = daemon.ls_remote(&session);
    assert_eq!(over_tcp.status.code(), Some(128), "{}", stderr(&over_tcp));
    let denied = audit_events(&daemon.audit(), "connect", "denied");
    let caller: Vec<_> = denied.iter().filter(|e| e["code"] == "caller").collect();
    assert_eq!(caller.len(), 2, "{denied:?}");
    assert!(
        caller.iter().all(|e| e["lease"] == id.as_str()),
        "{caller:?}"
    );

    // The session's root ends: the lease is revoked, and its certificate refused inside too.
    root.end();
    writ_integration::eventually("the ended session's lease to be revoked", || {
        audit_events(&daemon.audit(), "revoke", "done")
            .iter()
            .any(|e| e["lease"] == id.as_str())
    });
    let after = std::process::Command::new("/bin/sh")
        .arg(&script)
        .output()
        .unwrap();
    assert_eq!(after.status.code(), Some(128), "{}", stderr(&after));
}
