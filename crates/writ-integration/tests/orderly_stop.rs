//! The daemon's orderly stop and the state's lock (M7, the M5.6 review's L16 and L17), with
//! the real binaries: SIGTERM (launchd's, systemd's, `docker stop`'s) stops `writd run` as
//! Ctrl-C does, closing the listeners and letting an upstream push in flight finish within
//! its deadline, a git operation started meanwhile refused; `writd recover` is refused while
//! a daemon holds the state, and works once it has stopped, a crashed one's leftover included.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::Stdio;

use writ_crypto::keys::KeyKind;
use writ_integration::clone::{clone, git_ok, writ, writ_ok};
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::gateway::{GitGateway, Listen};
use writ_integration::process::finish;
use writ_integration::remote::Mode;
use writ_integration::{audit_events, eventually, stderr, stdout};

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

const TICKET: &str = "repos:\n  demo:\n    operations: [fetch, commit_sign, push]\n    \
                      branches: [\"agent/*\"]\nticket:\n  title: Stop in order\n  task: Push \
                      while the daemon stops\nlimits:\n  ttl: 1h\n";

/// The daemon with its mirrors fresh for an hour (a push right after a fetch asks upstream
/// only to push), and a granted lease.
fn started() -> Daemon {
    let daemon = Daemon::start_with(POLICY, Approvals::Ssh, |yaml| {
        yaml.replace("mirrors: { fresh_for: 0s }", "mirrors: { fresh_for: 1h }")
    });
    let request = daemon.request("agent", TICKET);
    let out = daemon.run(&["sign", &request.id, "--yes"], "");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let (status, out, err) = request.finish();
    assert_eq!(status.code(), Some(0), "{out}{err}");
    daemon
}

/// `writd recover <writd.yaml> readers <readers>`, the file in force put back: its output.
fn recover(daemon: &Daemon) -> std::process::Output {
    daemon.writd_with(&["recover", "writd.yaml", "readers", "readers"], "")
}

/// Whether something accepts connections on `port` (the agents' listener).
fn listening(port: u16) -> bool {
    std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
}

/// A commit through `writ git`, and the mirror synced by a fetch: what a push sends next.
fn committed(daemon: &Daemon, repo: &Path) -> String {
    fs::write(repo.join("f"), "x\n").unwrap();
    git_ok(daemon, repo, &["add", "f"]);
    let out = writ(daemon, repo, &["git", "commit", "-q", "-m", "f"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    writ_ok(daemon, repo, &["git", "fetch", "-q", "origin"], &[]);
    git_ok(daemon, repo, &["rev-parse", "HEAD"])
        .trim()
        .to_owned()
}

#[test]
fn sigterm_stops_in_order_and_lets_an_upstream_push_in_flight_finish() {
    let mut daemon = started();
    let repo = clone(&daemon, "work");
    writ_ok(&daemon, &repo, &["init", "demo", "--agents", "none"], &[]);
    let head = committed(&daemon, &repo);

    // The push reaches upstream, which holds it there: an upstream operation in flight.
    daemon.remote.set_mode(Mode::Held);
    let before = daemon.remote.receive_packs();
    let push = daemon
        .writ(&["git", "push", "-q", "origin", "HEAD:refs/heads/agent/x"])
        .current_dir(&repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    eventually("the upstream push to reach the remote", || {
        daemon.remote.receive_packs() > before
    });

    daemon.signal("TERM");
    let stopping = daemon.wait_for_log("stopping", writ_integration::WAIT_LIMIT);
    assert!(stopping.contains("signal=\"SIGTERM\""), "{stopping}");
    // Stopping, not stopped: the listeners closed, the state still held while it waits.
    eventually("the agents' listener to close", || {
        !listening(daemon.agents_port)
    });
    let refused = recover(&daemon);
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
    let said = stderr(&refused);
    assert!(
        said.contains(&format!("writd (pid {}) holds", daemon.pid()))
            && said.contains("s/writd.lock: stop the daemon first"),
        "{said}"
    );
    assert!(!daemon.log().contains("stopped"), "{}", daemon.log());

    // Upstream answers: the push lands there and in the mirror, then the daemon ends.
    daemon.remote.release();
    let pushed = finish(push);
    assert!(pushed.status.success(), "{}", stderr(&pushed));
    let status = daemon.exited();
    assert!(status.success(), "{status:?}: {}", daemon.log());
    let log = daemon.log();
    let (stopping_at, stopped_at) = (log.find("stopping").unwrap(), log.find("stopped").unwrap());
    assert!(stopping_at < stopped_at, "{log}");
    assert!(!log.contains("past their deadline"), "{log}");
    let upstream = git_ok(
        &daemon,
        &daemon.remote.repo("demo"),
        &["rev-parse", "refs/heads/agent/x"],
    );
    assert_eq!(upstream.trim(), head);

    // Stopped: recovery takes the state.
    let out = recover(&daemon);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn sigint_stops_the_same_way() {
    let mut daemon = started();
    daemon.signal("INT");
    let stopping = daemon.wait_for_log("stopping", writ_integration::WAIT_LIMIT);
    assert!(stopping.contains("signal=\"SIGINT\""), "{stopping}");
    let status = daemon.exited();
    assert!(status.success(), "{status:?}: {}", daemon.log());
    assert!(daemon.log().contains("stopped"), "{}", daemon.log());
    assert!(!listening(daemon.agents_port));
}

#[test]
fn recover_is_refused_while_the_daemon_runs_and_a_crashed_one_leaves_no_lock() {
    let mut daemon = started();
    let refused = recover(&daemon);
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains(&format!("writd (pid {}) holds", daemon.pid())),
        "{}",
        stderr(&refused)
    );
    // A second daemon on the same state is refused too.
    let second = daemon.writd_with(&["run", "writd.yaml"], "");
    assert_eq!(second.status.code(), Some(1), "{}", stderr(&second));
    assert!(
        stderr(&second).contains("one writd at a time on a state directory"),
        "{}",
        stderr(&second)
    );

    // Killed (a crash): the lock file stays, its lock went with the process.
    daemon.signal("KILL");
    assert_eq!(daemon.exited().signal(), Some(9));
    assert!(daemon.root().join("s/writd.lock").exists());
    let out = recover(&daemon);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn once_stopping_the_gateway_refuses_a_new_git_operation_and_logs_it() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    let work = gateway.clone("work");
    let fetched = gateway.remote.upload_packs();
    // Nothing in flight: the stop's wait ends at once, and nothing new starts after it.
    assert_eq!(gateway.runtime.block_on(gateway.gateway.stop()), 0);
    let out = gateway.git(&work, &["fetch", "origin"]);
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    let reason = "the daemon is stopping: try again once it is back";
    assert!(stderr(&out).contains(reason), "{}", stderr(&out));
    let audit = fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();
    let denied = audit_events(&audit, "command", "denied");
    assert_eq!(denied.len(), 1, "{audit}");
    assert_eq!(denied[0]["reason"], reason);
    assert_eq!(denied[0]["lease"], gateway.lease.as_str());
    assert_eq!(
        gateway.remote.upload_packs(),
        fetched,
        "nothing reached upstream"
    );
}
