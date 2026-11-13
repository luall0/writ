//! The SSH CA behind the `Signer` (M7.6) with the real `writd`, `writ`, `git` and `ssh`: `writd
//! init --ca-backend` refuses a backend the daemon lacks; on the Mac, against the fake
//! `writ-se` (no test blob ever reaches the real Secure Enclave), the CA made on the device as
//! a P-256 key, its blob in the keystore and no private key, signing each lease's certificate,
//! which the gateway takes.

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
use writ_integration::stderr;

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
                      ticket:\n  title: \"CA\"\n  task: CA\nlimits:\n  ttl: 30m\n";

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
fn writd_init_refuses_a_ca_backend_it_lacks() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let have = if std::env::consts::OS == "macos" {
        "software, se-cryptokit"
    } else {
        "software"
    };
    let out = Command::new(bin("writd"))
        .arg("init")
        .arg(daemon.root().join("writd.yaml"))
        .args(["--ca-backend", "yubikey"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        stderr(&out).lines().last(),
        Some(
            format!(
                "writd: --ca-backend yubikey: this daemon has no such backend (it has: {have})"
            )
            .as_str()
        ),
        "{}",
        stderr(&out)
    );
}

#[test]
fn on_the_mac_writd_init_makes_the_ca_on_the_device_and_it_signs_each_certificate() {
    if std::env::consts::OS != "macos" {
        return;
    }
    let helper = bin("writ-fake-se");
    let daemon = Daemon::start_sealed_init(
        POLICY,
        Approvals::Ssh,
        &["--ca-backend", "se-cryptokit"],
        |yaml| {
            format!(
                "{yaml}signers:\n  se_cryptokit:\n    helper: {}\n",
                helper.display()
            )
        },
    );
    let keys = daemon.root().join("s/keys");
    let public = fs::read_to_string(keys.join("ca.pub")).unwrap();
    assert!(public.starts_with("ecdsa-sha2-nistp256 "), "{public}");
    let out = daemon.unseal();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    // A lease's certificate, signed by the device's CA: the gateway, which trusts only its own
    // CA, takes it.
    let request = daemon.request("ca", TICKET);
    let out = daemon.run(&["sign", &request.id, "--yes"], "");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}\n{}",
        stderr(&out),
        daemon.log()
    );
    let (status, _, err) = request.finish();
    assert_eq!(status.code(), Some(0), "{err}");
    let lease = daemon.lease("ca", TICKET);
    let out = ls_remote(&daemon, &lease);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}
