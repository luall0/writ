//! M7.9.7: a fetch with no signature, through the gateway with the real `git` and `ssh`. A
//! repo naming an `unsigned_fetch` template is fetched under a lease granted when submitted;
//! that lease fetches and does nothing else, and is never pending, approved, amended or
//! renewed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use writ_approval::RefusalCode;
use writ_approval::testing::sign_approval;
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::lease::State;
use writ_core::ticket::Ticket;
use writ_crypto::keys::KeyKind;
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::gateway::{GitGateway, Listen, POLICY};
use writ_integration::{audit_events, stderr, stdout};

/// The gateway's policy with `demo` naming an unsigned_fetch template beside its signed one.
fn policy() -> String {
    POLICY
        .replacen("templates: [spike]", "templates: [spike, look]", 1)
        .replacen(
            "templates:\n  spike:",
            "templates:\n  look:\n    unsigned_fetch: true\n    operations: [fetch]\n    \
             max_ttl: 15m\n    max_signatures: 0\n    max_pushes: 0\n    max_ops_per_minute: 20\n    \
             max_push_size: 0\n  spike:",
            1,
        )
}

const FETCH: &str = r#"
repos:
  demo:
    template: look
    operations: [fetch]
ticket:
  title: Fetch demo
  task: Fetch before planning
limits:
  ttl: 10m
"#;

#[test]
fn an_unsigned_fetch_lease_is_granted_with_no_signature_and_only_fetches() {
    let gateway = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, &policy());
    gateway.seed_repo();
    let work = gateway.clone("work");
    let audit = || fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();

    // Submitted, active at once: no approver, nothing waiting.
    let lease = gateway.unsigned_session("look", FETCH);
    assert_eq!(gateway.service.waiting(), 0);
    let listed = gateway.service.list(false).unwrap();
    let row = listed.tickets.iter().find(|t| t.id == lease).unwrap();
    assert_eq!(row.state, State::Active);
    assert!(row.unsigned);
    // One grant line, naming its template, with no approver.
    let grants: Vec<_> = audit_events(&audit(), "grant", "allowed")
        .into_iter()
        .filter(|e| e["lease"] == lease.as_str())
        .collect();
    assert_eq!(grants.len(), 1, "{grants:?}");
    assert_eq!(
        grants[0]["reason"],
        "granted with no signature (unsigned_fetch): template look"
    );
    assert!(grants[0].get("approver").is_none(), "{grants:?}");

    // It fetches, upstream's new commit included.
    let seed = gateway.root().join("seed");
    gateway.git_ok(&seed, &["commit", "-q", "--allow-empty", "-m", "moved"]);
    let moved = gateway
        .git_ok(&seed, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    let bare = gateway.remote.repo("demo");
    gateway.git_ok(&seed, &["push", "-q", bare.to_str().unwrap(), "main"]);
    let out = gateway.git_as("look", &work, &["fetch", "-q", "origin"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        gateway.git_ok(&work, &["rev-parse", "origin/main"]).trim(),
        moved
    );
    let fetched: Vec<_> = audit_events(&audit(), "fetch", "allowed")
        .into_iter()
        .filter(|e| e["lease"] == lease.as_str())
        .collect();
    assert_eq!(fetched.len(), 1, "{fetched:?}");

    // A push under it: refused for the operation, nothing lands.
    gateway.git_ok(&work, &["commit", "-q", "--allow-empty", "-m", "x"]);
    let out = gateway.git_as(
        "look",
        &work,
        &["push", "origin", "HEAD:refs/heads/agent/x"],
    );
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("push not allowed. This lease was granted with no signature"),
        "{}",
        stderr(&out)
    );
    assert_eq!(gateway.bare_ref("refs/heads/agent/x"), None);
    let denied = audit_events(&audit(), "push", "denied");
    assert!(
        denied
            .iter()
            .any(|e| e["lease"] == lease.as_str() && e["code"] == "operation"),
        "{denied:?}"
    );

    // Never approved: it isn't pending.
    let ticket =
        Ticket::from_canonical(gateway.service.show(&lease).unwrap().canonical.as_bytes()).unwrap();
    let refused = gateway
        .service
        .approve(
            &lease,
            &sign_approval(&gateway.approver, &ticket),
            &CallerFacts::default(),
        )
        .unwrap_err();
    assert_eq!(refused.code(), Some(RefusalCode::WrongState));

    // Its amendment is refused at submission, from its own session key too.
    let key = gateway.root().join("keys/look");
    let key = writ_crypto::ssh_key::PrivateKey::read_openssh_file(&key).unwrap();
    let amendment = format!(
        "{}  amends: {lease}\n",
        FETCH.replacen("limits:\n  ttl: 10m\n", "", 1)
    );
    let refused = gateway
        .service
        .submit(
            key.public_key(),
            amendment.as_bytes(),
            &CallerFacts::default(),
        )
        .unwrap_err();
    assert!(
        refused.reason_text().contains("never amended or renewed"),
        "{}",
        refused.reason_text()
    );

    // Revoked like any lease: its fetch refused after.
    gateway.revoke(&lease);
    let out = gateway.git_as("look", &work, &["fetch", "origin"]);
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
}

/// The `writ_init` tests' policy, with `demo` naming an unsigned_fetch template too.
const DAEMON_POLICY: &str = r#"
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
    templates: [feature, look]
templates:
  look:
    unsigned_fetch: true
    operations: [fetch]
    max_ttl: 15m
    max_signatures: 0
    max_pushes: 0
    max_ops_per_minute: 20
    max_push_size: 0
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

/// `writ` as the agent runs it, in `cwd`.
fn writ_in(daemon: &Daemon, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    daemon
        .writ(args)
        .current_dir(cwd)
        .envs(env.iter().copied())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// A clone of the daemon's upstream `demo`, wired for Writ in wrapper mode with no lease.
fn wired(daemon: &Daemon) -> std::path::PathBuf {
    daemon.upstream_commit("main", "seed");
    let root = daemon.root().to_owned();
    fs::write(
        root.join("home/.gitconfig"),
        "[user]\n\tname = Operator\n\temail = me@operator.example\n[init]\n\tdefaultBranch = main\n",
    )
    .unwrap();
    let repo = root.join("repo");
    let upstream = daemon.remote.repo("demo");
    let out = Command::new("git")
        .args([
            "clone",
            "-q",
            upstream.to_str().unwrap(),
            repo.to_str().unwrap(),
        ])
        .env("HOME", root.join("home"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let out = writ_in(daemon, &repo, &["init", "demo", "--agents", "none"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    repo
}

#[test]
fn writ_git_fetch_with_no_lease_fetches_under_an_unsigned_lease_and_leaves_nothing() {
    let daemon = Daemon::start(DAEMON_POLICY, Approvals::Ssh);
    let repo = wired(&daemon);
    let sessions = daemon.root().join("writ/sessions");
    let listed = || -> Vec<String> {
        fs::read_dir(&sessions)
            .map(|d| {
                d.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    };
    let before = listed();

    // Upstream moved: `writ git fetch` with no lease gets it, under a lease no one signed.
    let moved = daemon.upstream_commit("main", "moved");
    let out = writ_in(&daemon, &repo, &["git", "fetch", "-q", "origin"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("granted with no signature (template look)"),
        "{}",
        stderr(&out)
    );
    let fetched = writ_in(&daemon, &repo, &["git", "rev-parse", "origin/main"], &[]);
    assert_eq!(stdout(&fetched).trim(), moved);
    // Granted, fetched and closed, each logged; nothing left on the host, `current` untouched.
    let grants = audit_events(&daemon.audit(), "grant", "allowed");
    assert_eq!(grants.len(), 1, "{grants:?}");
    let lease = grants[0]["lease"].as_str().unwrap().to_owned();
    assert_eq!(
        grants[0]["reason"],
        "granted with no signature (unsigned_fetch): template look"
    );
    assert!(
        audit_events(&daemon.audit(), "fetch", "allowed")
            .iter()
            .any(|e| e["lease"] == lease.as_str())
    );
    assert!(
        audit_events(&daemon.audit(), "close", "done")
            .iter()
            .any(|e| e["lease"] == lease.as_str()),
        "{}",
        daemon.audit()
    );
    assert_eq!(listed(), before);
    assert!(!sessions.join("current").exists());

    // `pull --ff-only` too: the branch moves to upstream's.
    let moved = daemon.upstream_commit("main", "moved again");
    let out = writ_in(
        &daemon,
        &repo,
        &["git", "pull", "-q", "--ff-only", "origin", "main"],
        &[],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let head = writ_in(&daemon, &repo, &["git", "rev-parse", "HEAD"], &[]);
    assert_eq!(stdout(&head).trim(), moved);
    assert_eq!(audit_events(&daemon.audit(), "grant", "allowed").len(), 2);
    assert_eq!(listed(), before);

    // git's own failure is the command's, and still closes the lease and leaves nothing.
    let out = writ_in(
        &daemon,
        &repo,
        &["git", "fetch", "origin", "refs/heads/nowhere"],
        &[],
    );
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert_eq!(listed(), before);
    assert_eq!(
        audit_events(&daemon.audit(), "close", "done").len(),
        audit_events(&daemon.audit(), "grant", "allowed").len()
    );

    // A lease named that isn't on this host: refused as before, never another identity.
    let out = writ_in(
        &daemon,
        &repo,
        &["git", "fetch", "origin"],
        &[("WRIT_SESSION", lease.as_str())],
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(&format!("WRIT_SESSION names lease {lease}")),
        "{}",
        stderr(&out)
    );
    assert_eq!(audit_events(&daemon.audit(), "grant", "allowed").len(), 3);

    // Another command than a fetch, with no lease: run as before, no lease asked.
    let out = writ_in(
        &daemon,
        &repo,
        &["git", "push", "origin", "HEAD:refs/heads/agent/x"],
        &[],
    );
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert_eq!(audit_events(&daemon.audit(), "grant", "allowed").len(), 3);
}
