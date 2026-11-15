//! M7.9.6's upgrades with the real binaries: `writd run` on a state an older writd left
//! migrates it in steps after a copy of it whole, says so in its log and the audit log, and
//! serves as before; a state newer than the binary is refused at the start, nothing changed.

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

use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::{audit_events, stdout};

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
    committer_emails: [agent@example.invalid]
    signing_key: agent-01
    max_ttl: 4h
    max_signatures: 10
    max_pushes: 5
    max_ops_per_minute: 30
    max_push_size: 10MB
"#;

fn db(daemon: &Daemon) -> std::path::PathBuf {
    daemon.root().join("s/leases.db")
}

fn version(path: &Path) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap()
}

/// The state as a version 11 writd left it: version 12 only added the `migrations` table.
fn as_version_11(path: &Path) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch("DROP TABLE migrations").unwrap();
    conn.pragma_update(None, "user_version", 11).unwrap();
}

#[test]
fn a_start_on_an_older_state_migrates_it_after_a_copy_and_serves_as_before() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    assert!(daemon.unseal().status.success(), "{}", daemon.log());
    let before = stdout(&daemon.run(&["ls"], ""));
    daemon.stop();
    as_version_11(&db(&daemon));
    let backups = daemon.root().join("s/backups");
    assert!(!backups.exists());

    daemon.restart();
    // Migrated before anything read it: the copy, the log line, the audit line, the record.
    assert_eq!(version(&db(&daemon)), 12);
    let copies: Vec<_> = fs::read_dir(&backups)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(copies.len(), 1, "{copies:?}");
    assert_eq!(version(&copies[0]), 11);
    assert!(
        daemon
            .log()
            .contains("the state migrated from version 11 to 12"),
        "{}",
        daemon.log()
    );
    let lines = audit_events(&daemon.audit(), "migrate", "done");
    assert_eq!(lines.len(), 1, "{}", daemon.audit());
    assert_eq!(
        lines[0]["reason"].as_str().unwrap(),
        format!(
            "the state migrated from version 11 to 12; its copy from before: {}",
            copies[0].display()
        )
    );
    let recorded: i64 = rusqlite::Connection::open(db(&daemon))
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM migrations WHERE from_version = 11 AND to_version = 12",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(recorded, 1);

    // Serves as before, sealed then unsealed.
    assert!(daemon.unseal().status.success(), "{}", daemon.log());
    assert_eq!(stdout(&daemon.run(&["ls"], "")), before);

    // Started again: nothing to migrate, no other copy, no other line.
    daemon.restart();
    assert_eq!(fs::read_dir(&backups).unwrap().count(), 1);
    assert_eq!(audit_events(&daemon.audit(), "migrate", "done").len(), 1);
}

#[test]
fn a_state_newer_than_the_binary_is_refused_at_the_start_and_left_as_it_is() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    daemon.stop();
    rusqlite::Connection::open(db(&daemon))
        .unwrap()
        .pragma_update(None, "user_version", 13)
        .unwrap();
    let refused = daemon.restart_refused();
    assert!(
        refused
            .contains("the state is version 13, this writd reads version 12 and can't migrate it"),
        "{refused}"
    );
    assert_eq!(version(&db(&daemon)), 13);
    assert!(!daemon.root().join("s/backups").exists());
}
