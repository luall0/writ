//! M7.9.6's upgrades with the real binaries: `writd run` on a state an older writd left
//! migrates it in steps after a copy of it whole, says so in its log and the audit log, and
//! serves as before; a state newer than the binary is refused at the start, nothing changed.
//! A policy of an older format in force: the daemon starts and unseals, refuses every other
//! request with `migration_owed` until `writ migrate` signs its rewrite (or the operator's
//! text), then serves again, the leases granted before included.

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

use writ_integration::daemon::{Approvals, Daemon, PASSPHRASE};
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

const TICKET: &str = "repos:\n  demo:\n    operations: [fetch, commit_sign, push]\n    \
                      branches: [\"agent/oauth\"]\nticket:\n  title: \"Add OAuth login\"\n  \
                      task: Add GitHub OAuth login\nlimits:\n  ttl: 1h\n";

/// The policy the daemon started with (the harness points its upstream at the test remote).
fn started_with(daemon: &Daemon) -> String {
    fs::read_to_string(daemon.root().join("policy.yaml")).unwrap()
}

/// `policy` (format 2) as format 1 wrote it: no `format`, the repo's push modes said.
fn format_1(policy: &str, push_modes: &str) -> String {
    let old = policy.replacen("format: 2\n", "", 1).replacen(
        "    templates: [feature]\n",
        &format!("    templates: [feature]\n    push_modes: {push_modes}\n"),
        1,
    );
    assert!(!old.lines().any(|l| l.starts_with("format:")) && old.contains("push_modes"));
    old
}

/// Puts `text` in force with `writd recover` (the daemon stopped), then starts it again and
/// unseals it: what an older writd's policy looks like to this one.
fn in_force_as(daemon: &mut Daemon, text: &str) -> String {
    daemon.stop();
    let file = daemon.root().join("older-policy.yaml");
    fs::write(&file, text).unwrap();
    let out = daemon.writd_with(
        &["recover", "writd.yaml", "policy", file.to_str().unwrap()],
        &format!("{PASSPHRASE}\n"),
    );
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    daemon.restart();
    let unsealed = daemon.unseal();
    assert!(unsealed.status.success(), "{}", stderr(&unsealed));
    stdout(&unsealed)
}

/// What every refused request says while a migration is owed.
const OWED: &str = "writ: the policy in force is of an older format, which this writd doesn't \
                    read: every request is refused until an approver signs its migration with \
                    `writ migrate`";

#[test]
fn an_older_policy_in_force_refuses_everything_until_its_migration_is_signed() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    assert!(daemon.unseal().status.success(), "{}", daemon.log());
    let lease = daemon.lease("a", TICKET);
    let session = daemon.session(&lease);
    assert!(daemon.ls_remote(&session).status.success());

    let older = format_1(&started_with(&daemon), "[gateway, proxy]");
    let unsealed = in_force_as(&mut daemon, &older);
    // The unseal said what is owed; the daemon's log too.
    assert!(
        unsealed.contains(
            "The policy in force is format 1; this daemon reads format 2: every request is \
             refused until you sign its migration with writ migrate."
        ),
        "{unsealed}"
    );
    assert!(
        daemon
            .log()
            .contains("the policy in force is of an older format"),
        "{}",
        daemon.log()
    );

    // Every request refused, each with the same words: the approver's, the agent's, a lease's.
    let before = audit_events(&daemon.audit(), "command", "denied").len();
    for args in [
        vec!["ls"],
        vec!["admin", "show", "policy"],
        vec!["admin", "key", "list"],
        vec!["report", lease.as_str()],
        vec!["revoke", lease.as_str()],
    ] {
        let out = daemon.run(&args, "");
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", stdout(&out));
        assert!(stderr(&out).contains(OWED), "{args:?}: {}", stderr(&out));
    }
    let ticket = daemon.root().join("ticket.yaml");
    fs::write(&ticket, TICKET).unwrap();
    let ticket = ticket.to_str().unwrap().to_owned();
    let request = daemon.run(&["request", "--dry-run", &ticket], "");
    assert!(stderr(&request).contains(OWED), "{}", stderr(&request));
    // A lease's connection refused at authentication: git gets no session.
    let fetch = daemon.ls_remote(&session);
    assert_eq!(fetch.status.code(), Some(128), "a lease served while owed");
    assert!(
        stderr(&fetch).contains("Permission denied"),
        "{}",
        stderr(&fetch)
    );
    // Each refusal in the audit log, as a sealed daemon's are (coalesced per source).
    let after = audit_events(&daemon.audit(), "command", "denied");
    assert!(after.len() > before, "{}", daemon.audit());
    assert!(
        after.iter().any(|l| l["reason"]
            .as_str()
            .unwrap()
            .starts_with(&OWED["writ: ".len()..])),
        "{}",
        daemon.audit()
    );
    // Only the policy changes meanwhile: it is the migration.
    let approvers = daemon.root().join("approvers-again");
    fs::write(
        &approvers,
        fs::read_to_string(daemon.root().join("approvers")).unwrap(),
    )
    .unwrap();
    let out = daemon.run(
        &[
            "admin",
            "apply",
            "approvers",
            approvers.to_str().unwrap(),
            "--yes",
        ],
        "",
    );
    assert!(stderr(&out).contains(OWED), "{}", stderr(&out));

    // Declined: nothing changes, still owed.
    let declined = daemon.run(&["migrate"], "n\n");
    assert_eq!(declined.status.code(), Some(6), "{}", stdout(&declined));
    let shown = stdout(&declined);
    assert!(
        shown.contains(
            "The policy in force is format 1; this daemon reads format 2 and refuses every \
             request until a policy of format 2 is signed."
        ),
        "{shown}"
    );
    assert!(
        shown.contains("rewritten to format 2 by the daemon"),
        "{shown}"
    );
    // The rewrite, shown as the change it is: the format added, the push modes dropped.
    assert!(shown.contains("\n+ format: 2\n"), "{shown}");
    assert!(
        shown.contains("\n-     push_modes: [gateway, proxy]\n"),
        "{shown}"
    );
    assert!(shown.contains("Not signed."), "{shown}");
    assert!(stderr(&daemon.run(&["ls"], "")).contains(OWED));

    // Signed: format 2 in force, every request served again, the lease from before too.
    let signed = daemon.run(&["migrate", "--yes"], "");
    assert!(
        signed.status.success(),
        "{}{}",
        stdout(&signed),
        stderr(&signed)
    );
    assert!(
        stdout(&signed).contains("Applied: policy is version "),
        "{}",
        stdout(&signed)
    );
    let migrated = audit_events(&daemon.audit(), "migrate", "allowed");
    assert_eq!(migrated.len(), 1, "{}", daemon.audit());
    assert!(
        migrated[0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("policy: format 1 migrated to format 2 (version "),
        "{}",
        migrated[0]
    );
    let policy = stdout(&daemon.run(&["admin", "show", "policy"], ""));
    assert!(policy.starts_with("format: 2\n"), "{policy}");
    assert!(!policy.contains("push_modes"), "{policy}");
    assert!(daemon.run(&["ls"], "").status.success());
    let fetch = daemon.ls_remote(&session);
    assert!(
        fetch.status.success(),
        "the lease from before: {}\n{}\n{}",
        stderr(&fetch),
        daemon
            .audit()
            .lines()
            .rev()
            .take(6)
            .collect::<Vec<_>>()
            .join("\n"),
        daemon
            .log()
            .lines()
            .rev()
            .take(8)
            .collect::<Vec<_>>()
            .join("\n")
    );
    let request = daemon.run(&["request", "--dry-run", &ticket], "");
    assert!(request.status.success(), "{}", stderr(&request));
    // Nothing more to migrate, after a restart too.
    let again = daemon.run(&["migrate"], "");
    assert!(again.status.success(), "{}", stderr(&again));
    assert!(
        stdout(&again).contains("Nothing to migrate"),
        "{}",
        stdout(&again)
    );
    daemon.restart();
    assert!(daemon.unseal().status.success());
    assert!(daemon.run(&["ls"], "").status.success());
}

#[test]
fn a_policy_the_daemon_can_t_rewrite_is_migrated_with_the_operator_s_text() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    assert!(daemon.unseal().status.success(), "{}", daemon.log());
    let started = started_with(&daemon);
    in_force_as(&mut daemon, &format_1(&started, "[proxy]"));

    // No rewrite: the reason names the key, nothing is signed.
    let out = daemon.run(&["migrate", "--yes"], "");
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    let said = stdout(&out);
    assert!(
        said.contains(
            "repos.demo.push_modes: [proxy] has no gateway, so no push was accepted; format 2 has \
             no push modes, and dropping it would let gateway pushes in: write the policy you \
             want (writ migrate --file)"
        ),
        "{said}"
    );
    assert!(
        said.contains("then: writ migrate --file <policy>"),
        "{said}"
    );
    assert!(stderr(&daemon.run(&["ls"], "")).contains(OWED));

    // A format 1 text is never signed: the daemon reads format 2 only.
    let older = daemon.root().join("still-format-1.yaml");
    fs::write(&older, format_1(&started, "[gateway]")).unwrap();
    let out = daemon.run(&["migrate", "--file", older.to_str().unwrap(), "--yes"], "");
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("format: missing: a policy names its format"),
        "{}",
        stderr(&out)
    );
    assert!(stderr(&daemon.run(&["ls"], "")).contains(OWED));

    // The operator's own text, in format 2: the repo closed, as it pushed nothing before.
    let own = daemon.root().join("own.yaml");
    fs::write(
        &own,
        started.replacen("    templates: [feature]\n", "    templates: []\n", 1),
    )
    .unwrap();
    let out = daemon.run(&["migrate", "--file", own.to_str().unwrap(), "--yes"], "");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert!(
        stdout(&out).contains(&format!("replaced by {}", own.display())),
        "{}",
        stdout(&out)
    );
    assert_eq!(audit_events(&daemon.audit(), "migrate", "allowed").len(), 1);
    assert!(daemon.run(&["ls"], "").status.success());
    let policy = stdout(&daemon.run(&["admin", "show", "policy"], ""));
    assert!(policy.contains("templates: []"), "{policy}");
}

/// `writd check-upgrade writd.yaml` on the daemon's directory: (exit code, stdout, stderr).
fn check_upgrade(daemon: &Daemon, config: &str) -> (Option<i32>, String, String) {
    let out = daemon.writd_with(&["check-upgrade", config], "");
    (out.status.code(), stdout(&out), stderr(&out))
}

#[test]
fn writd_check_upgrade_says_what_the_start_will_do_and_changes_nothing() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    assert!(daemon.unseal().status.success(), "{}", daemon.log());

    // Current, the daemon running: nothing to do.
    let (code, said, _) = check_upgrade(&daemon, "writd.yaml");
    assert_eq!(code, Some(0), "{said}");
    assert_eq!(
        said,
        "writd.yaml: read as this writd reads it.\n\
         The state: version 12, this writd's: nothing to migrate.\n\
         The policy in force: format 2, this writd's: nothing to migrate.\n\
         Nothing blocks the upgrade.\n"
    );

    // An older state: its steps run on a copy, the state itself left as it was.
    daemon.stop();
    as_version_11(&db(&daemon));
    let before = fs::read(db(&daemon)).unwrap();
    let (code, said, _) = check_upgrade(&daemon, "writd.yaml");
    assert_eq!(code, Some(0), "{said}");
    assert!(
        said.contains(&format!(
            "The state: version 11; this writd migrates it to version 12 at its start, after a \
             copy of it in {} (the steps ran on a copy here).\n",
            fs::canonicalize(daemon.root())
                .unwrap()
                .join("s/backups")
                .display()
        )),
        "{said}"
    );
    assert_eq!(fs::read(db(&daemon)).unwrap(), before, "the state changed");
    assert_eq!(version(&db(&daemon)), 11);
    assert!(!daemon.root().join("s/backups").exists());
    // No copy left behind.
    let left: Vec<_> = fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("writd-check-upgrade-")
        })
        .collect();
    assert!(left.is_empty(), "{left:?}");

    // A newer state blocks it, nothing changed.
    rusqlite::Connection::open(db(&daemon))
        .unwrap()
        .pragma_update(None, "user_version", 13)
        .unwrap();
    let (code, said, err) = check_upgrade(&daemon, "writd.yaml");
    assert_eq!(code, Some(1), "{said}");
    assert!(
        said.contains(
            "Blocks the upgrade: the state (version 13): the state is version 13, this writd \
             reads version 12 and can't migrate it"
        ),
        "{said}"
    );
    assert!(
        err.contains("writd: the upgrade is blocked (1 reason): nothing was changed"),
        "{err}"
    );
    assert_eq!(version(&db(&daemon)), 13);

    // A `writd.yaml` this writd doesn't read blocks it too; no state yet: nothing to migrate.
    let yaml = fs::read_to_string(daemon.root().join("writd.yaml")).unwrap();
    fs::write(
        daemon.root().join("unknown.yaml"),
        format!("{yaml}not_a_key: 1\n"),
    )
    .unwrap();
    let (code, said, _) = check_upgrade(&daemon, "unknown.yaml");
    assert_eq!(code, Some(1), "{said}");
    assert!(
        said.starts_with("Blocks the upgrade: unknown.yaml: "),
        "{said}"
    );
    assert!(said.contains("not_a_key"), "{said}");
    let fresh = yaml.replacen("state_dir: s\n", "state_dir: fresh\n", 1);
    assert_ne!(fresh, yaml);
    fs::write(daemon.root().join("fresh.yaml"), fresh).unwrap();
    let (code, said, _) = check_upgrade(&daemon, "fresh.yaml");
    assert_eq!(code, Some(0), "{said}");
    assert!(
        said.contains("The state: none yet (no writd ran here): nothing to migrate.\n"),
        "{said}"
    );
}

#[test]
fn writd_check_upgrade_says_which_policy_migration_waits() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    assert!(daemon.unseal().status.success(), "{}", daemon.log());
    let started = started_with(&daemon);
    in_force_as(&mut daemon, &format_1(&started, "[gateway]"));
    let (code, said, _) = check_upgrade(&daemon, "writd.yaml");
    assert_eq!(code, Some(0), "{said}");
    assert!(
        said.contains(
            "The policy in force: format 1; this writd reads format 2. After the start, every \
             request is refused until an approver signs its migration: writ migrate.\n  The \
             daemon's rewrite is ready: writ migrate shows it, then signs it.\n"
        ),
        "{said}"
    );
    in_force_as(&mut daemon, &format_1(&started, "[proxy]"));
    let (code, said, _) = check_upgrade(&daemon, "writd.yaml");
    assert_eq!(code, Some(0), "not a block: {said}");
    assert!(
        said.contains(
            "  The daemon can't rewrite it: write the policy you want, then writ migrate --file \
             <policy>. Why:\n    repos.demo.push_modes: [proxy] has no gateway"
        ),
        "{said}"
    );
}
