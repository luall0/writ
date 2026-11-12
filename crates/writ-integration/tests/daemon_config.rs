//! The daemon's configuration (`writd.yaml`), key by key, with the real `writd`: each key set
//! to something other than the harness's default, and its effect seen from outside (a
//! client's outcome, the audit log, the daemon's log, a program it ran). The parser's own
//! tests are in `writd`; these check that what is parsed is what the daemon does.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use writ_integration::agent::TestAgent;
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::process::finish;
use writ_integration::{WAIT_LIMIT, audit_events, stderr, stdout};

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

/// A ticket that fits `feature`, with `extra` lines under `ticket:`.
fn ticket(extra: &str) -> String {
    format!(
        "repos:\n  demo:\n    operations: [fetch, commit_sign, push]\n    \
         branches: [\"agent/config\"]\nticket:\n  title: Configuration\n  \
         task: Exercise the daemon's configuration\n{extra}limits:\n  ttl: 1h\n"
    )
}

/// `writ <args…> <file>` with `text` in the file `name`.yaml: its output.
fn with_ticket(daemon: &Daemon, args: &[&str], name: &str, text: &str) -> Output {
    let file = daemon.root().join(format!("{name}.yaml"));
    fs::write(&file, text).unwrap();
    let mut args = args.to_vec();
    args.push(file.to_str().unwrap());
    daemon.run(&args, "")
}

/// `writ request --no-wait`: submitted, not waited on.
fn submit(daemon: &Daemon, name: &str) -> Output {
    with_ticket(daemon, &["request", "--no-wait"], name, &ticket(""))
}

/// `writ` run to the end with nothing on stdin, from a configured command.
fn output(mut command: Command) -> Output {
    finish(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}

/// An executable script at `path`.
fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A wrapper that appends its arguments to `log`, then runs `real` with them.
fn wrapper(path: &Path, log: &Path, real: &str) {
    script(
        path,
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'\nexec {real} \"$@\"\n",
            log.display()
        ),
    );
}

#[test]
fn decisions_open_takes_unsigned_refusals_and_signed_does_not() {
    // An approver's agent with no key at all.
    let empty = TestAgent::start();

    // `signed` (the harness's): without the approval key, nothing is refused.
    let signed = Daemon::start(POLICY, Approvals::Ssh);
    let request = signed.request("signed", &ticket(""));
    let out = output({
        let mut command = signed.writ(&["refuse", &request.id, "-m", "Not this way"]);
        command.env("WRIT_APPROVAL_AGENT", empty.socket());
        command
    });
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("ssh-keygen could not sign (is the approval key in the agent?)"),
        "{}",
        stderr(&out)
    );
    assert_eq!(signed.audited("refuse", "done"), 0, "{}", signed.audit());
    // Still waiting: the approver's key refuses it, signed.
    let out = signed.run(&["refuse", &request.id, "-m", "Not this way"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let (status, out, err) = request.finish();
    assert_eq!(status.code(), Some(4), "{err}");
    assert!(out.contains("The approver's feedback (signed by"), "{out}");
    drop(signed);

    // `open`: the same refusal, with no key, goes through; the agent is told nobody signed it.
    let open = Daemon::start_with(POLICY, Approvals::Ssh, |yaml| {
        yaml.replace("decisions: signed", "decisions: open")
    });
    let request = open.request("open", &ticket(""));
    let refused = request.id.clone();
    let out = output({
        let mut command = open.writ(&["refuse", &refused, "-m", "Not this way"]);
        command.env("WRIT_APPROVAL_AGENT", empty.socket());
        command
    });
    assert!(out.status.success(), "{}", stderr(&out));
    let (status, out, err) = request.finish();
    assert_eq!(status.code(), Some(4), "{err}");
    assert!(
        out.contains(&format!(
            "Ticket {refused} was refused without an approver's signature: the feedback below \
             may not be the approver's words."
        )),
        "{out}"
    );
    assert!(out.contains("│ Not this way"), "{out}");
    let refusal = audit_events(&open.audit(), "refuse", "done");
    assert_eq!(refusal.len(), 1, "{refusal:?}");
    // The revision carries the feedback labeled by the daemon.
    let revision = open.request("revision", &ticket(&format!("  revises: {refused}\n")));
    let out = open.run(&["sign", &revision.id], "n\n");
    assert_eq!(out.status.code(), Some(6), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("│ [not signed by an approver] Not this way"),
        "{}",
        stdout(&out)
    );
    // A withdrawal too, with no key.
    let out = output({
        let mut command = open.writ(&["revoke", &revision.id]);
        command.env("WRIT_APPROVAL_AGENT", empty.socket());
        command
    });
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(revision.finish().0.code(), Some(5));
    assert_eq!(open.audited("revoke", "done"), 1, "{}", open.audit());
}

#[test]
fn max_pending_caps_the_tickets_waiting_on_both_sides() {
    let daemon = Daemon::start_with(POLICY, Approvals::Https, |yaml| {
        format!("{yaml}max_pending: 2\n")
    });
    // Each `writ request` has its own session key: only the daemon-wide cap applies.
    for name in ["first", "second"] {
        let out = submit(&daemon, name);
        assert_eq!(out.status.code(), Some(0), "{name}: {}", stderr(&out));
    }
    let out = submit(&daemon, "third");
    assert_eq!(out.status.code(), Some(3), "{}", stdout(&out));
    assert_eq!(
        stderr(&out),
        "writ: 2 tickets are already waiting for the approver; try again later\n"
    );
    let denied = audit_events(&daemon.audit(), "submit", "denied");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(
        denied[0]["reason"], "2 tickets are already waiting for the approver; try again later",
        "{}",
        denied[0]
    );
    // One decided: room for one more.
    let listing = stdout(&daemon.run(&["ls"], ""));
    let first = listing
        .split_whitespace()
        .find(|word| word.starts_with("wrt_"))
        .unwrap()
        .to_owned();
    let out = daemon.run(&["refuse", &first, "-m", "no"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let out = submit(&daemon, "fourth");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    drop(daemon);

    // None at all would leave nothing for the approver: the daemon doesn't start.
    let error = Daemon::refused(POLICY, |yaml| format!("{yaml}max_pending: 0\n"));
    assert!(
        error.lines().last().unwrap().ends_with(
            "max_pending: 0, must be at least 1 (no ticket could ever wait for the approver)"
        ),
        "{error}"
    );
}

#[test]
fn submission_rates_per_source_and_in_all_are_the_operator_s() {
    // Every submission here comes from 127.0.0.1: one source. Per source lower than in all:
    // the source's rate refuses first.
    let per_source = Daemon::start_with(POLICY, Approvals::Https, |yaml| {
        format!("{yaml}submissions: {{ per_source: 2, in_all: 60 }}\n")
    });
    // In all lower than per source (allowed: each is bounded on its own): the rate for all
    // sources refuses first, though this source is under its own. (The test takes seconds;
    // were it to take a minute, the third would pass and the test fail, never pass by luck.)
    let in_all = Daemon::start_with(POLICY, Approvals::Https, |yaml| {
        format!("{yaml}submissions: {{ per_source: 10, in_all: 2 }}\n")
    });
    for (daemon, refusal) in [
        (
            &per_source,
            "more than 2 submissions a minute from this address",
        ),
        (&in_all, "more than 2 submissions a minute from all sources"),
    ] {
        for name in ["first", "second"] {
            let out = submit(daemon, name);
            assert_eq!(out.status.code(), Some(0), "{name}: {}", stderr(&out));
        }
        let out = submit(daemon, "third");
        assert_eq!(out.status.code(), Some(3), "{}", stdout(&out));
        assert_eq!(stderr(&out), format!("writ: {refusal}; try again later\n"));
        let denied = audit_events(&daemon.audit(), "submit", "denied");
        assert_eq!(denied.len(), 1, "{denied:?}");
        assert_eq!(denied[0]["reason"], refusal, "{}", denied[0]);
        assert_eq!(daemon.audited("submit", "allowed"), 2);
    }
}

/// `writ-sign git demo` on the gateway with a session of `lease`, its body never sent: the
/// request holds its slot until its stdin (returned) is closed.
fn held_sign_request(daemon: &Daemon, lease: &str) -> (Child, ChildStdin) {
    let mut child = daemon
        .ssh(&daemon.session(lease))
        .arg("writ-sign git demo")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    (child, stdin)
}

/// Waits for each child in its own thread; the outputs arrive on the receiver as they end,
/// with the child's index.
fn wait_all(children: Vec<Child>) -> mpsc::Receiver<(usize, Output)> {
    let (done, ended) = mpsc::channel();
    for (i, child) in children.into_iter().enumerate() {
        let done = done.clone();
        std::thread::spawn(move || {
            let _ = done.send((i, child.wait_with_output().unwrap()));
        });
    }
    ended
}

#[test]
fn sign_requests_per_lease_bounds_the_requests_held_at_once() {
    let daemon = Daemon::start_with(POLICY, Approvals::Https, |yaml| {
        format!("{yaml}sign_requests: {{ per_lease: 2 }}\n")
    });
    let lease = daemon.lease("held", &ticket(""));
    let other = daemon.lease("other", &ticket(""));
    let busy = "writ: this lease already has 2 sign requests in progress; retry shortly\n";
    // What a request that held a slot answers once its body ends, empty: it was read.
    let read = "writ: not a writ-sign/1 request (update writ-sign)\n";

    // Three at once for one lease, none sending its body: two hold a slot each, the third is
    // refused at once (whichever it is: none gives its slot back before its stdin closes).
    let (children, mut stdins): (Vec<_>, Vec<_>) =
        (0..3).map(|_| held_sign_request(&daemon, &lease)).unzip();
    let ended = wait_all(children);
    let (refused, out) = ended.recv_timeout(WAIT_LIMIT).expect("one refused");
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert_eq!(stderr(&out), busy);
    // Another lease has slots of its own: its request is read.
    let (child, stdin) = held_sign_request(&daemon, &other);
    drop(stdin);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert_eq!(stderr(&out), read);
    // The two held ones were holding a slot: closed, each is read.
    stdins.remove(refused);
    drop(stdins);
    for _ in 0..2 {
        let (_, out) = ended
            .recv_timeout(WAIT_LIMIT)
            .expect("a held request ended");
        assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
        assert_eq!(stderr(&out), read);
    }
    // Given back: two at once again, both read.
    let (children, stdins): (Vec<_>, Vec<_>) =
        (0..2).map(|_| held_sign_request(&daemon, &lease)).unzip();
    drop(stdins);
    for child in children {
        let out = finish(child);
        assert_eq!(stderr(&out), read);
    }
    // The refusal is in the audit log, with its reason.
    let denied = audit_events(&daemon.audit(), "sign", "denied");
    assert!(
        denied
            .iter()
            .any(|line| line["reason"] == busy.trim_start_matches("writ: ").trim_end()),
        "{denied:?}"
    );
}

#[test]
fn mirrors_git_and_ssh_are_the_programs_named() {
    let tools = tempfile::tempdir().unwrap();
    let (git, ssh) = (tools.path().join("git"), tools.path().join("ssh"));
    let (git_log, ssh_log) = (tools.path().join("git.log"), tools.path().join("ssh.log"));
    wrapper(&git, &git_log, "/usr/bin/git");
    wrapper(&ssh, &ssh_log, "/usr/bin/ssh");
    let named = |yaml: &str| {
        yaml.replace(
            "fresh_for: 0s }",
            &format!(
                "fresh_for: 0s, git: {}, ssh: {} }}",
                git.display(),
                ssh.display()
            ),
        )
    };
    let daemon = Daemon::start_with(POLICY, Approvals::Https, named);
    let main = daemon.upstream_commit("main", "upstream");
    let lease = daemon.lease("fetch", &ticket(""));
    // A fetch through the daemon: synced from upstream with the programs named.
    let out = daemon.ls_remote(&daemon.session(&lease));
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains(&format!("{main}\trefs/heads/main")),
        "{}",
        stdout(&out)
    );
    let git_runs = fs::read_to_string(&git_log).unwrap();
    assert!(
        git_runs.lines().any(|l| l.ends_with(" version")),
        "{git_runs}"
    );
    assert!(git_runs.lines().any(|l| l.contains("fetch")), "{git_runs}");
    let ssh_runs = fs::read_to_string(&ssh_log).unwrap();
    assert!(
        ssh_runs
            .lines()
            .any(|l| l.contains("git-upload-pack '/demo.git'")),
        "{ssh_runs}"
    );
    // A push upstream through the daemon: git and ssh named again.
    let pushes = ssh_runs.matches("git-receive-pack").count();
    assert_eq!(pushes, 0, "{ssh_runs}");
    let work = daemon.root().join("work");
    let clone = Command::new("git")
        .args(["clone", "-q"])
        .arg(format!(
            "ssh://git@127.0.0.1:{}/demo.git",
            daemon.agents_port
        ))
        .arg(&work)
        .env("GIT_SSH_COMMAND", ssh_command(&daemon, &lease))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(clone.status.success(), "{}", stderr(&clone));
    let push = Command::new("git")
        .args([
            "push",
            "-q",
            "origin",
            "origin/main:refs/heads/agent/config",
        ])
        .current_dir(&work)
        .env("GIT_SSH_COMMAND", ssh_command(&daemon, &lease))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(push.status.success(), "{}", stderr(&push));
    let ssh_runs = fs::read_to_string(&ssh_log).unwrap();
    assert!(
        ssh_runs
            .lines()
            .any(|l| l.contains("git-receive-pack '/demo.git'")),
        "{ssh_runs}"
    );
    let git_runs = fs::read_to_string(&git_log).unwrap();
    assert!(git_runs.lines().any(|l| l.contains("push")), "{git_runs}");
    let upstream = Command::new("git")
        .args(["rev-parse", "refs/heads/agent/config"])
        .current_dir(daemon.remote.repo("demo"))
        // Never the user's git config (hard rule 8).
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert_eq!(stdout(&upstream).trim(), main, "upstream has the branch");
    drop(daemon);

    // A path that is not an executable file: the daemon doesn't start.
    let plain = tools.path().join("plain");
    fs::write(&plain, "not a program\n").unwrap();
    for key in ["git", "ssh"] {
        let error = Daemon::refused(POLICY, |yaml| {
            yaml.replace(
                "fresh_for: 0s }",
                &format!("fresh_for: 0s, {key}: {} }}", plain.display()),
            )
        });
        assert!(
            error.ends_with(&format!(
                "{key} {}: not an executable file\n",
                plain.display()
            )),
            "{key}: {error}"
        );
    }
}

/// The ssh command for a lease's session, for git.
fn ssh_command(daemon: &Daemon, lease: &str) -> String {
    format!(
        "ssh {}",
        writ_integration::daemon::ssh_options(
            &daemon.root().join("known_hosts"),
            &daemon.session(lease)
        )
        .join(" ")
    )
}

#[test]
fn mirrors_sync_every_syncs_without_any_client() {
    // `WRIT_LOG` too: the daemon's own debug lines show its first sync, at start.
    let daemon = Daemon::start_logging(POLICY, Approvals::Https, "info,writd=debug", |yaml| {
        yaml.replace("fresh_for: 0s }", "fresh_for: 0s, sync_every: 10s }")
    });
    let mirror = daemon.root().join("s/repos/demo.git");
    let line = daemon.wait_for_log("mirror up to date", WAIT_LIMIT);
    assert!(line.contains("repo=demo"), "{line}");
    let main = daemon.upstream_commit("main", "upstream moved");
    // No client at all: the next round (10 s after the first) brings it.
    let line = daemon.wait_for_log("mirror synced", Duration::from_secs(10) + WAIT_LIMIT);
    assert!(line.contains("repo=demo moved=1"), "{line}");
    let synced = Command::new("git")
        .args(["rev-parse", "refs/heads/main"])
        .current_dir(&mirror)
        // Never the user's git config (hard rule 8).
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert_eq!(stdout(&synced).trim(), main);
    assert_eq!(
        daemon.audited("connect", "allowed"),
        0,
        "no client connected: {}",
        daemon.audit()
    );
}

#[test]
fn listeners_take_only_the_sources_they_allow() {
    // Every client here connects from 127.0.0.1.
    let elsewhere = Daemon::start_with(POLICY, Approvals::Ssh, |yaml| {
        yaml.replace("allow: [127.0.0.1] }]", "allow: [192.0.2.0/24] }]")
            .replace(
                "ssh: [{ tcp: \"127.0.0.1:0\" }]",
                "ssh: [{ tcp: \"127.0.0.1:0\", allow: [\"2001:db8::/32\"] }]",
            )
            .replace(
                "https: [{ tcp: \"127.0.0.1:0\" }]",
                "https: [{ tcp: \"127.0.0.1:0\", allow: [127.0.0.0/8] }]",
            )
    });
    let turned_away = "caller turned away: its address is not allowed on this listener";
    // The agents listener: a ticket can't even be submitted.
    let out = submit(&elsewhere, "agents");
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("writ: cannot connect"),
        "{}",
        stderr(&out)
    );
    let denied = audit_events(&elsewhere.audit(), "connect", "denied");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0]["reason"], turned_away, "{}", denied[0]);
    assert_eq!(denied[0]["source_addr"], "127.0.0.1", "{}", denied[0]);
    assert_eq!(elsewhere.audited("submit", "allowed"), 0);
    // The approval API over SSH: the same (the denial counted, coalesced with the first).
    let out = elsewhere.run(&["ls"], "");
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("writ: cannot connect"),
        "{}",
        stderr(&out)
    );
    // Over HTTPS, which allows 127.0.0.0/8: listed.
    let out = output({
        let mut command = elsewhere.writ(&["ls"]);
        command.env(
            "WRIT_APPROVAL_URL",
            format!("https://127.0.0.1:{}", elsewhere.https_port),
        );
        command
    });
    assert!(out.status.success(), "{}", stderr(&out));
    drop(elsewhere);

    // A list that has the source among others: taken.
    let here = Daemon::start_with(POLICY, Approvals::Ssh, |yaml| {
        yaml.replace(
            "allow: [127.0.0.1] }]",
            "allow: [192.0.2.0/24, 127.0.0.1/32] }]",
        )
        .replace(
            "ssh: [{ tcp: \"127.0.0.1:0\" }]",
            "ssh: [{ tcp: \"127.0.0.1:0\", allow: [\"2001:db8::/32\", 127.0.0.1] }]",
        )
    });
    let out = submit(&here, "agents");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let out = here.run(&["ls"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(here.audited("connect", "denied"), 0, "{}", here.audit());
}

#[test]
fn a_unix_listener_under_the_network_attestor_is_refused_at_start() {
    let agents = "agents: [{ tcp: \"127.0.0.1:0\", allow: [127.0.0.1] }]";
    let error = Daemon::refused(POLICY, |yaml| {
        yaml.replace(agents, "agents: [{ unix: run/agents.sock }]")
    });
    let last = error.lines().last().unwrap();
    assert!(
        last.ends_with(
            "writd.yaml: transports.agents[0].unix: the network attestor can't attest a Unix \
             socket's callers; local mode's attestor does (attestor: macos_process_chain or \
             linux_process_chain)"
        ),
        "{error}"
    );
}

#[test]
fn what_this_build_does_not_have_is_refused_at_start() {
    // Local mode's implementations are each OS's own (macOS: M7, Linux: M7.1): a build for
    // one refuses the other's at start, naming why. This OS's start (tests/local_mode.rs).
    let others: &[(&str, &str, &str)] = match std::env::consts::OS {
        "macos" => &[
            (
                "attestor: network",
                "attestor: linux_process_chain",
                "attestor linux_process_chain is Linux's",
            ),
            (
                "session_watcher: none",
                "session_watcher: linux",
                "session_watcher linux is Linux's",
            ),
        ],
        "linux" => &[
            (
                "attestor: network",
                "attestor: macos_process_chain",
                "attestor macos_process_chain is macOS's",
            ),
            (
                "session_watcher: none",
                "session_watcher: macos",
                "session_watcher macos is macOS's",
            ),
        ],
        _ => &[
            (
                "attestor: network",
                "attestor: macos_process_chain",
                "attestor macos_process_chain is macOS's",
            ),
            (
                "attestor: network",
                "attestor: linux_process_chain",
                "attestor linux_process_chain is Linux's",
            ),
            (
                "session_watcher: none",
                "session_watcher: macos",
                "session_watcher macos is macOS's",
            ),
            (
                "session_watcher: none",
                "session_watcher: linux",
                "session_watcher linux is Linux's",
            ),
        ],
    };
    for (from, to, why) in others {
        let error = Daemon::refused(POLICY, |yaml| yaml.replace(from, to));
        assert_eq!(
            error.lines().last().unwrap(),
            format!("writd: {why}: this build is for another OS")
        );
    }
}

/// M7: `<home>/config`, the client's settings file, gives the endpoints when no flag or
/// variable does; a flag or a variable still wins; a file that can't be trusted is refused,
/// naming its line.
#[test]
fn the_client_settings_file_gives_the_endpoints_and_flags_still_win() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let config = daemon.root().join("writ/config");
    std::fs::create_dir_all(daemon.root().join("writ")).unwrap();
    let unset = |args: &[&str]| {
        let mut command = daemon.writ(args);
        command
            .env_remove("WRIT_URL")
            .env_remove("WRIT_APPROVAL_URL");
        command.stdin(std::process::Stdio::null()).output().unwrap()
    };
    // No file, nothing set: said where the endpoint can come from.
    let out = unset(&["ls"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains(
            "no daemon to reach: set WRIT_APPROVAL_URL (or --approval-url, or approval_url in "
        ),
        "{}",
        stderr(&out)
    );
    // The file gives both.
    std::fs::write(
        &config,
        format!(
            "# Written by the installer.\nurl = ssh://127.0.0.1:{}\napproval_url = {}\n",
            daemon.agents_port, daemon.approval_url
        ),
    )
    .unwrap();
    let out = unset(&["ls"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = unset(&["policy", "demo"]);
    assert!(out.status.success(), "{}", stderr(&out));
    // A flag wins over the file (one that points nowhere).
    std::fs::write(
        &config,
        "url = ssh://127.0.0.1:1\napproval_url = ssh://127.0.0.1:1\n",
    )
    .unwrap();
    let out = unset(&["ls", "--approval-url", &daemon.approval_url]);
    assert!(out.status.success(), "{}", stderr(&out));
    // So does the variable (the fixture's own).
    let out = daemon.run(&["ls"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    // A file that can't be trusted: refused, its line named, escaped.
    std::fs::write(&config, "url = ssh://127.0.0.1:1\nhome = /tmp\x1b[2J\n").unwrap();
    let out = unset(&["ls"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out)
            .contains("writ/config: line 2: a control or hidden character (home = /tmp\\u{1b}[2J)"),
        "{}",
        stderr(&out)
    );
}
