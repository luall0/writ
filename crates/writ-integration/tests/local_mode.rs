//! Local mode with the real daemon (M7 on the Mac, M7.1 on Linux): agents on a Unix socket,
//! this OS's process chain attestor and session watcher plugged into an unchanged core. On
//! Linux the daemon runs as the test's user and reads `/proc` itself (no process reader: the
//! capability and other users are the end-to-end scenario's). On another OS these tests say
//! so and pass.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use writ_integration::clone::git_ok;
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::{audit_events, stderr, stdout};

const POLICY: &str = r#"
format: 2
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
    let here = matches!(std::env::consts::OS, "macos" | "linux");
    if !here {
        eprintln!(
            "no local mode on {} in this build: nothing to run",
            std::env::consts::OS
        );
    }
    here
}

/// Whether this is the Mac (code signatures, launchd at the top of every chain).
fn on_the_mac() -> bool {
    std::env::consts::OS == "macos"
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
    // (up to launchd on the Mac; on Linux up to the first one of another user, which the
    // daemon running as the test's user can't read).
    let audit = daemon.audit();
    let submitted = audit_events(&audit, "submit", "allowed");
    let chain = submitted[0]["process_chain"].as_array().unwrap();
    let writ = writ_integration::binaries::bin("writ")
        .canonicalize()
        .unwrap();
    assert_eq!(chain[0], writ.to_str().unwrap(), "{chain:?}");
    if on_the_mac() {
        assert_eq!(chain.last().unwrap(), "/sbin/launchd", "{chain:?}");
    } else {
        let test = std::env::current_exe().unwrap();
        assert!(chain.contains(&test.to_str().unwrap().into()), "{chain:?}");
    }
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
    /// The shell, with the environment `writ` gets from the fixture (the local endpoint): not
    /// under `writ run`.
    fn start(daemon: &Daemon) -> Self {
        Self::start_as(daemon, &[])
    }

    /// The shell under `writ run`: the shell, `writ run`'s child, is the session's root.
    fn under_writ_run(daemon: &Daemon) -> Self {
        let writ = writ_integration::binaries::bin("writ");
        Self::start_as(daemon, &[writ.to_str().unwrap(), "run", "--"])
    }

    /// The shell, run by `before` (a program and its arguments) when there is one.
    fn start_as(daemon: &Daemon, before: &[&str]) -> Self {
        let template = daemon.writ_local(&[]);
        let line_loop = "while IFS= read -r line; do eval \"$line\"; echo \"done $?\"; done";
        let mut shell = match before.split_first() {
            Some((program, args)) => {
                let mut command = std::process::Command::new(program);
                command.args(args).args(["/bin/sh", "-c", line_loop]);
                command
            }
            None => {
                let mut command = std::process::Command::new("/bin/sh");
                command.args(["-c", line_loop]);
                command
            }
        };
        shell
            .env_clear()
            .envs(
                template.get_envs().filter_map(|(key, value)| {
                    value.map(|value| (key.to_owned(), value.to_owned()))
                }),
            )
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
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

    /// The pid of the process started: `writ run` when the shell runs under it.
    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The shell's own pid (`$$`): under `writ run`, the session's root.
    fn shell_pid(&mut self) -> u32 {
        self.send("echo $$");
        let (said, status) = self.finish();
        assert_eq!(status, 0, "{said:?}");
        said[0].parse().unwrap()
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

    /// Ends the shell (its stdin closed) and waits for it: how its root ended.
    fn end(mut self) -> std::process::ExitStatus {
        drop(self.child.stdin.take());
        self.child.wait().unwrap()
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

    // A binding written by hand, submitted from inside a session: only a process `writ run`
    // started can be its root (the review after M7.6, C-1). Not pid 1, nor `writ run` itself,
    // nor this test (which started `writ run`): each refused with the session code (3).
    let mut root = SessionRoot::under_writ_run(&daemon);
    let shell = root.shell_pid();
    let launcher = writ.canonicalize().unwrap();
    for pid in [1, root.pid(), std::process::id()] {
        let file = daemon.root().join(format!("refused-{pid}.yaml"));
        std::fs::write(
            &file,
            format!("caller:\n  descends_from: {{ pid: {pid} }}\n{TICKET}"),
        )
        .unwrap();
        root.send(&format!(
            "'{}' request '{}' 2>&1",
            writ.display(),
            file.display()
        ));
        let (said, status) = root.finish();
        assert_eq!(status, 3, "{pid}: {said:?}");
        let said = said.join("\n");
        // pid 1 is above what the daemon can read on Linux (another user's): not in the chain.
        let expected = if pid == 1 {
            format!("caller.descends_from.pid: {pid} is not a process ")
        } else {
            format!(
                "caller.descends_from.pid: {pid} is not a process started by `writ run` (its \
                 parent isn't {}): start the agent with `writ run -- <agent>`",
                launcher.display()
            )
        };
        assert!(said.contains(&expected), "{pid}: {said}");
    }

    // A shell this test started itself, binding to itself: not started by `writ run`.
    let mut plain = SessionRoot::start(&daemon);
    let own = plain.shell_pid();
    let file = daemon.root().join("own-shell.yaml");
    std::fs::write(
        &file,
        format!("caller:\n  descends_from: {{ pid: {own} }}\n{TICKET}"),
    )
    .unwrap();
    plain.send(&format!(
        "'{}' request '{}' 2>&1",
        writ.display(),
        file.display()
    ));
    let (said, status) = plain.finish();
    assert_eq!(status, 3, "{said:?}");
    assert!(
        said.join("\n").contains(&format!(
            "caller.descends_from.pid: {own} is not a process started by `writ run` (its parent \
             isn't {}): start the agent with `writ run -- <agent>`",
            launcher.display()
        )),
        "{said:?}"
    );
    plain.end();

    // Bound to the session's root (the shell `writ run` started), submitted from inside it:
    // completed from the kernel.
    let bound = daemon.root().join("bound.yaml");
    std::fs::write(
        &bound,
        format!("caller:\n  descends_from: {{ pid: {shell} }}\n{TICKET}"),
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
    // kernel names it (macOS's /bin/sh runs on as /bin/bash, Debian's is dash), by its pid,
    // with its signature on the Mac (Linux has none).
    let out = daemon.run(&["sign", &id, "--yes"], "");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let shown = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        shown.contains("caller             descends from \"/")
            && shown.contains(&format!("(pid {shell}, generation"))
            // "started by writ", wherever the row wraps.
            && shown.contains("started")
            && shown.contains("signed com.apple.") == on_the_mac(),
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

const WORK: &str = "repos:\n  demo:\n    operations: [fetch, commit_sign, push]\n    \
                    branches: [\"agent/*\"]\nticket:\n  title: Local work\n  task: Commit and \
                    push\nlimits:\n  ttl: 1h\n";

#[test]
fn the_agent_workflow_runs_under_writ_run_against_the_local_daemon() {
    if !local_mode_here() {
        return;
    }
    let policy = POLICY.replacen(
        REQUIRED,
        "    max_push_size: 10MB\n    require_session: true\n",
        1,
    );
    let daemon = Daemon::start_local(&policy, Approvals::Ssh);
    let writ = writ_integration::binaries::bin("writ");
    let repo = writ_integration::clone::clone(&daemon, "work");
    let ticket = daemon.root().join("work.yaml");
    std::fs::write(&ticket, WORK).unwrap();

    // The harness: a shell under `writ run`. Its ticket names no caller: `writ request`
    // binds it to the session, as the skill's workflow asks nothing more of the agent.
    let mut harness = SessionRoot::under_writ_run(&daemon);
    let shell = harness.shell_pid();
    harness.send(&format!("cd '{}'", repo.display()));
    assert_eq!(harness.finish().1, 0);
    harness.send(&format!(
        "'{}' request '{}'",
        writ.display(),
        ticket.display()
    ));
    let first = harness.next();
    let id = first
        .strip_prefix("Ticket ")
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("{first}"))
        .to_owned();
    let out = daemon.run(&["sign", &id, "--yes"], "");
    let shown = format!("{}{}", stdout(&out), stderr(&out));
    assert!(out.status.success(), "{shown}");
    // Bound to the harness `writ run` started (the shell), by its pid.
    assert!(
        shown.contains("caller             descends from")
            // Where the line wraps depends on the path's length.
            && shown.contains(&format!("(pid {shell},")),
        "{shown}"
    );
    let (said, status) = harness.finish();
    assert_eq!(status, 0, "{said:?}");

    // The M6 workflow, the endpoint the only difference: wired, a commit signed by the
    // daemon, pushed through it.
    for line in [
        format!("'{}' init demo --agents none", writ.display()),
        "echo work > f && git add f".to_owned(),
        format!("'{}' git commit -q -m work", writ.display()),
        format!(
            "'{}' git push -q origin HEAD:refs/heads/agent/local",
            writ.display()
        ),
    ] {
        harness.send(&line);
        let (said, status) = harness.finish();
        assert_eq!(status, 0, "{line}: {said:?}");
    }
    let head = git_ok(&daemon, &repo, &["rev-parse", "HEAD"]);
    let upstream = git_ok(
        &daemon,
        &daemon.remote.repo("demo"),
        &["rev-parse", "refs/heads/agent/local"],
    );
    assert_eq!(upstream.trim(), head.trim());

    // From outside the session (this test, not under writ run): refused.
    let outside = daemon
        .writ_local(&["git", "fetch", "-q", "origin"])
        .current_dir(&repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert_eq!(outside.status.code(), Some(128), "{}", stderr(&outside));
    let denied = audit_events(&daemon.audit(), "connect", "denied");
    assert!(
        denied
            .iter()
            .any(|e| e["code"] == "caller" && e["lease"] == id.as_str()),
        "{denied:?}"
    );

    // The harness quits: writ run exits with its status, and the lease is revoked.
    assert_eq!(harness.end().code(), Some(0));
    writ_integration::eventually("the session's lease to be revoked", || {
        audit_events(&daemon.audit(), "revoke", "done")
            .iter()
            .any(|e| e["lease"] == id.as_str())
    });
}

/// `session_launcher` (the review after M7.6, C-1): the `writ` whose children may be a
/// session's root, by the path the kernel names it with. Set to another program, `writ run`'s
/// harness is no session's root; a path someone else could replace stops the start, named.
#[test]
fn the_session_launcher_set_elsewhere_binds_nothing_and_a_replaceable_one_stops_the_start() {
    if !local_mode_here() {
        return;
    }
    let policy = POLICY.replacen(
        REQUIRED,
        "    max_push_size: 10MB\n    require_session: true\n",
        1,
    );
    // Another program the daemon trusts, standing for an installed writ elsewhere.
    let elsewhere = writ_integration::binaries::bin("writ-sign")
        .canonicalize()
        .unwrap();
    let daemon = Daemon::start_local_with(&policy, Approvals::Ssh, |yaml| {
        format!("{yaml}session_launcher: {}\n", elsewhere.display())
    });
    let writ = writ_integration::binaries::bin("writ");
    let ticket = daemon.root().join("work.yaml");
    std::fs::write(&ticket, TICKET).unwrap();
    let mut harness = SessionRoot::under_writ_run(&daemon);
    let shell = harness.shell_pid();
    harness.send(&format!(
        "'{}' request '{}' 2>&1",
        writ.display(),
        ticket.display()
    ));
    let (said, status) = harness.finish();
    assert_eq!(status, 3, "{said:?}");
    assert!(
        said.join("\n").contains(&format!(
            "caller.descends_from.pid: {shell} is not a process started by `writ run` (its \
             parent isn't {}): start the agent with `writ run -- <agent>`",
            elsewhere.display()
        )),
        "{said:?}"
    );
    harness.end();
    // A launcher that is no canonical path, or that others could write: the start refuses.
    let dir = tempfile::tempdir().unwrap();
    let copy = std::fs::canonicalize(dir.path()).unwrap().join("writ");
    std::fs::copy(&writ, &copy).unwrap();
    std::fs::set_permissions(&copy, std::os::unix::fs::PermissionsExt::from_mode(0o777)).unwrap();
    let said = Daemon::refused_local(&policy, |yaml| {
        format!("{yaml}session_launcher: {}\n", copy.display())
    });
    assert!(
        said.contains(&format!(
            "session_launcher {}: can be written by group or others (mode 777)",
            copy.display()
        )),
        "{said}"
    );
    let said = Daemon::refused_local(&policy, |yaml| {
        format!("{yaml}session_launcher: bin/writ\n")
    });
    assert!(
        said.contains("session_launcher bin/writ: must be an absolute path"),
        "{said}"
    );
}
