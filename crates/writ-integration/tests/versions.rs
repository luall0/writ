//! M7.9.8: the binaries say their version, every reply of the daemon names it, and `writ`
//! against a daemon of its own version says nothing about it. (A daemon of another version
//! can't be built here: the hint and the unreadable reply's words are `writ-proto`'s and
//! `writ-cli`'s unit tests, on replies naming any version.)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;
use std::process::{Command, Output, Stdio};

use writ_integration::binaries::bin;
use writ_integration::daemon::{Approvals, Daemon, ssh_options};
use writ_integration::{stderr, stdout};
use writ_proto::VERSION;

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

fn run(binary: &str, args: &[&str]) -> Output {
    Command::new(bin(binary))
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn each_binary_says_its_version_and_nothing_else() {
    for binary in ["writ", "writd", "writ-sign"] {
        let out = run(binary, &["--version"]);
        assert_eq!(out.status.code(), Some(0), "{binary}: {}", stderr(&out));
        assert_eq!(stdout(&out), format!("{binary} {VERSION}\n"), "{binary}");
        assert_eq!(stderr(&out), "", "{binary}");
    }
    // Only alone: anything after it is another call, refused as before.
    let out = run("writd", &["--version", "dev/writd.yaml"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("writd --version"), "{}", stderr(&out));
    let out = run("writ-sign", &["--version", "-Y"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with(
            "writ-sign: unsupported call: it answers -Y sign, -Y verify, \
             --status-fd=2 -bsau, --verify, --version"
        ),
        "{}",
        stderr(&out)
    );
}

#[test]
fn every_reply_names_the_daemon_s_version_and_writ_says_nothing_of_its_own() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);

    // A reply as it travels, read with plain ssh: the version first.
    let session = daemon.root().join("plain");
    fs::create_dir_all(&session).unwrap();
    let keygen = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(session.join("key"))
        .output()
        .unwrap();
    assert!(keygen.status.success(), "{}", stderr(&keygen));
    let out = Command::new("ssh")
        .args(ssh_options(&daemon.root().join("known_hosts"), &session))
        .args([
            "-p",
            &daemon.agents_port.to_string(),
            "writ@127.0.0.1",
            "writ policy demo",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stdout(&out).starts_with(&format!("{{\"version\":\"{VERSION}\",\"ok\":{{")),
        "{}",
        stdout(&out)
    );
    // An error reply too.
    let out = Command::new("ssh")
        .args(ssh_options(&daemon.root().join("known_hosts"), &session))
        .args([
            "-p",
            &daemon.agents_port.to_string(),
            "writ@127.0.0.1",
            "writ policy nowhere",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stdout(&out).starts_with(&format!("{{\"version\":\"{VERSION}\",\"error\":{{")),
        "{}",
        stdout(&out)
    );

    // The same version on both sides: `writ` says nothing of it, over the agents' listener
    // and the approval API.
    for args in [&["ls"][..], &["policy", "demo"][..]] {
        let out = daemon.run(args, "");
        assert_eq!(out.status.code(), Some(0), "{args:?}: {}", stderr(&out));
        assert!(
            !stderr(&out).contains("install the same version"),
            "{args:?}: {}",
            stderr(&out)
        );
    }
}
