//! Auto-unseal (M7.6, `unseal: auto`) with the real `writd` and `writ`: on a passphrase
//! keystore with software keys, `writ admin auto-unseal status` says each thing missing and
//! its fix, `on` is refused by the client and by the daemon; on the Mac, against the fake
//! `writ-se` (no test blob reaches the real Secure Enclave), a daemon made with everything in
//! hardware takes `on`, then opens itself at each start with no one (logged as automatic,
//! notified), and refuses to start once something is in software again, naming it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::process::{Command, Output};

use writ_integration::binaries::bin;
use writ_integration::daemon::{Approvals, Daemon, ssh_options};
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

const TICKET: &str = "repos:\n  demo:\n    operations: [fetch]\n    branches: [\"agent/x\"]\n\
                      ticket:\n  title: \"Auto\"\n  task: Auto\nlimits:\n  ttl: 30m\n";

fn ls_remote(daemon: &Daemon, lease: &str) -> Output {
    let ssh = format!(
        "ssh {}",
        ssh_options(&daemon.root().join("known_hosts"), &daemon.session(lease)).join(" ")
    );
    Command::new("git")
        .args([
            "ls-remote",
            &format!("ssh://git@127.0.0.1:{}/demo.git", daemon.agents_port),
        ])
        .env("GIT_SSH_COMMAND", ssh)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", daemon.root().join("home"))
        .output()
        .unwrap()
}

#[test]
fn auto_unseal_says_what_is_missing_and_is_refused_until_everything_is_in_hardware() {
    let daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    assert_eq!(daemon.unseal().status.code(), Some(0));
    let out = daemon.run(&["admin", "auto-unseal", "status"], "");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let said = stdout(&out);
    for line in [
        "Auto-unseal is off: after every start the daemon waits for writ unseal.",
        "Still missing:",
        "  - the keystore opens with a passphrase: make a recovery key (writ recovery new)",
        "  - the SSH CA's key is in software: writ admin ca rotate --backend se-cryptokit",
        "  - signing key agent-01 is in software: writ admin key rotate agent-01 --backend se-cryptokit",
        "  - upstream credential upstream-01 is in software: writ admin key rotate upstream-01 --backend se-cryptokit",
    ] {
        assert!(said.contains(line), "{line:?} not in:\n{said}");
    }
    // Refused by the client, nothing signed.
    let out = daemon.run(&["admin", "auto-unseal", "on", "--yes"], "");
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("auto-unseal not turned on: not everything is in hardware yet"),
        "{}",
        stderr(&out)
    );
    // And by the daemon, the policy given whole.
    let shown = daemon.run(&["admin", "show", "policy"], "");
    let file = daemon.root().join("auto.yaml");
    fs::write(&file, format!("{}\nunseal: auto\n", stdout(&shown))).unwrap();
    let out = daemon.run(
        &["admin", "apply", "policy", file.to_str().unwrap(), "--yes"],
        "",
    );
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains(
            "unseal: auto: not everything is in hardware yet: the keystore opens with a passphrase"
        ),
        "{}",
        stderr(&out)
    );
    let denied = audit_events(&daemon.audit(), "admin", "denied");
    assert!(denied.iter().any(|l| {
        l["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("unseal: auto")
    }));
    // Off while off: nothing to sign.
    let out = daemon.run(&["admin", "auto-unseal", "off", "--yes"], "");
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("Auto-unseal is off already: nothing to sign."));
}

/// On the Mac, against the fake `writ-se`.
#[test]
fn on_the_mac_a_daemon_with_everything_in_hardware_opens_itself_at_each_start() {
    if std::env::consts::OS != "macos" {
        return;
    }
    let (_, recovery) = writ_crypto::recovery::new_key();
    let policy = POLICY
        .replace(
            "    algorithm: ed25519\n  upstream-01:",
            "    algorithm: p256\n    backend: se-cryptokit\n  upstream-01:",
        )
        .replace(
            "    kind: ssh\n    algorithm: ed25519\n",
            "    kind: ssh\n    algorithm: p256\n    backend: se-cryptokit\n",
        )
        .replace(
            "repos:\n",
            &format!(
                "recipients:\n  recovery: {{ recipient: {recovery} }}\n  se-01: {{ backend: \
                 se-cryptokit }}\nrepos:\n"
            ),
        );
    let helper = bin("writ-fake-se");
    let mut daemon = Daemon::start_sealed_init(
        &policy,
        Approvals::Ssh,
        &["--ca-backend", "se-cryptokit"],
        |yaml| {
            format!(
                "{yaml}signers:\n  se_cryptokit:\n    helper: {}\n",
                helper.display()
            )
        },
    );
    let out = daemon.unseal();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let said = stdout(&daemon.run(&["admin", "auto-unseal", "status"], ""));
    assert!(
        said.contains("Everything is in hardware: the daemon can open itself"),
        "{said}"
    );
    let out = daemon.run(&["admin", "auto-unseal", "on", "--yes"], "");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stdout(&out).contains("With auto-unseal on, the daemon opens itself"));

    // A start: open with no one, logged as automatic, notified.
    daemon.restart();
    // Opened before its listeners: the restart returns after.
    assert!(
        daemon.log().contains("unsealed automatically"),
        "{}",
        daemon.log()
    );
    let unsealed = audit_events(&daemon.audit(), "unseal", "allowed");
    assert!(
        unsealed.last().unwrap()["reason"]
            .as_str()
            .unwrap_or_default()
            .starts_with("automatic: the daemon opened itself through its hardware"),
        "{unsealed:?}"
    );
    let lease = daemon.lease("auto", TICKET);
    assert_eq!(ls_remote(&daemon, &lease).status.code(), Some(0));
    let said = stdout(&daemon.run(&["admin", "auto-unseal", "status"], ""));
    assert!(said.contains("Auto-unseal is on"), "{said}");

    // Something in software again (the CA's marker says so): the start is refused, naming it.
    daemon.stop();
    fs::write(daemon.root().join("s/keys/ca.backend"), "software\n").unwrap();
    let out = Command::new(bin("writd"))
        .args(["run"])
        .arg(daemon.root().join("writd.yaml"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(
            "unseal: auto, and not everything is in hardware, so the daemon won't start on its \
             own: the SSH CA's key is in software"
        ),
        "{}",
        stderr(&out)
    );
}
