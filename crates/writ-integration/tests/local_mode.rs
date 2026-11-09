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
