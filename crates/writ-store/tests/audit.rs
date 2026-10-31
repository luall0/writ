//! The audit log: one JSON line per event, only ever appended, never a secret.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use writ_core::caller::{CallerFacts, ProcessRef};
use writ_core::names::{KeyFingerprint, TicketId};
use writ_core::policy::{Denial, DenyCode};
use writ_core::units::Timestamp;
use writ_store::{AuditEvent, AuditLog, EventKind, Outcome, looks_secret};

fn t(offset: i64) -> Timestamp {
    Timestamp::from_unix(1_793_455_331 + offset).unwrap()
}

fn lease_id() -> TicketId {
    TicketId::from_parts(1_793_455_331_000, [1; 10])
}

fn fp(c: char) -> KeyFingerprint {
    format!("SHA256:{}", c.to_string().repeat(43))
        .parse()
        .unwrap()
}

/// Every kind of event a lease goes through, with every field the daemon fills.
fn lifecycle() -> Vec<AuditEvent> {
    let lease = lease_id();
    let repo = "omega-code".parse().unwrap();
    let commit = "9e1c2f0000000000000000000000000000000000".parse().unwrap();
    let local = CallerFacts {
        source_addr: None,
        process_chain: Some(vec![
            ProcessRef {
                pid: 5003,
                generation: 1,
                executable: PathBuf::from("/usr/local/bin/writ-sign"),
                code_identity: None,
            },
            ProcessRef {
                pid: 4242,
                generation: 118,
                executable: PathBuf::from("/Applications/Omega Code.app/Contents/MacOS/omega"),
                code_identity: None,
            },
        ]),
    };
    let remote = CallerFacts {
        source_addr: Some("192.0.2.7".parse().unwrap()),
        process_chain: None,
    };
    let denial = Denial {
        code: DenyCode::Ref,
        reason: format!("outside ticket {lease}: branch main not allowed"),
        hint: Some(format!(
            "If needed, submit an amendment (ticket.amends: {lease})"
        )),
    };
    vec![
        AuditEvent::new(t(0), EventKind::Submit, Outcome::Allowed)
            .ticket(&lease)
            .caller(&remote),
        AuditEvent::new(t(1), EventKind::Submit, Outcome::Denied)
            .reason("the ticket fits no template"),
        AuditEvent::new(t(60), EventKind::Grant, Outcome::Allowed)
            .lease(&lease)
            .cert(1842)
            .approver(&fp('A')),
        AuditEvent::new(t(61), EventKind::Grant, Outcome::Denied)
            .lease(&lease)
            .reason("signature by a key not in approvers"),
        AuditEvent::new(t(90), EventKind::Sign, Outcome::Allowed)
            .lease(&lease)
            .cert(1842)
            .repo(&repo)
            .commit(&commit)
            .committer("user+agent@example.org")
            .warnings(["files outside expected_paths: src/billing/x.rs".to_owned()])
            .caller(&local),
        AuditEvent::new(t(95), EventKind::Push, Outcome::Denied)
            .lease(&lease)
            .cert(1842)
            .repo(&repo)
            .refs(["refs/heads/main".to_owned()])
            .denial(&denial)
            .caller(&remote),
        AuditEvent::new(t(96), EventKind::Fetch, Outcome::Allowed)
            .lease(&lease)
            .repo(&repo),
        AuditEvent::new(t(100), EventKind::Refuse, Outcome::Done)
            .ticket(&lease)
            .reason("Don't touch billing"),
        AuditEvent::new(t(200), EventKind::Amend, Outcome::Allowed)
            .lease(&lease)
            .ticket(&lease)
            .approver(&fp('A')),
        AuditEvent::new(t(300), EventKind::Revoke, Outcome::Done)
            .lease(&lease)
            .reason("revoked by the approver"),
        AuditEvent::new(t(301), EventKind::Expire, Outcome::Done).lease(&lease),
        AuditEvent::new(t(302), EventKind::Exhaust, Outcome::Done).lease(&lease),
        AuditEvent::new(t(303), EventKind::Close, Outcome::Done).lease(&lease),
        AuditEvent::new(t(400), EventKind::Admin, Outcome::Denied)
            .approver(&fp('B'))
            .reason("unsigned admin change"),
        AuditEvent::new(t(500), EventKind::Seal, Outcome::Done),
        AuditEvent::new(t(501), EventKind::Unseal, Outcome::Denied)
            .reason("wrong keystore passphrase"),
    ]
}

#[test]
fn one_json_line_per_event() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&path).unwrap();
    for event in lifecycle() {
        log.append(&event).unwrap();
    }
    let text = fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), lifecycle().len());
    assert!(text.ends_with('\n'));
    for line in &lines {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(
            value["time"].is_string() && value["event"].is_string() && value["result"].is_string()
        );
    }
    assert_eq!(
        lines[4],
        format!(
            r#"{{"time":"2026-10-31T14:03:41Z","event":"sign","result":"allowed","lease":"{id}","cert":1842,"repo":"omega-code","commit":"9e1c2f0000000000000000000000000000000000","committer":"user+agent@example.org","warnings":["files outside expected_paths: src/billing/x.rs"],"process_chain":["/usr/local/bin/writ-sign","/Applications/Omega Code.app/Contents/MacOS/omega"]}}"#,
            id = lease_id()
        )
    );
    let denied: serde_json::Value = serde_json::from_str(lines[5]).unwrap();
    assert_eq!(denied["code"], "ref");
    assert_eq!(denied["source_addr"], "192.0.2.7");
    assert!(
        denied["reason"]
            .as_str()
            .unwrap()
            .contains("submit an amendment")
    );
}

#[test]
fn the_log_only_grows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let events = lifecycle();
    let mut log = AuditLog::open(&path).unwrap();
    log.append(&events[0]).unwrap();
    log.append(&events[1]).unwrap();
    drop(log);
    let before = fs::read(&path).unwrap();

    let mut log = AuditLog::open(&path).unwrap();
    log.append(&events[2]).unwrap();
    drop(log);
    let after = fs::read(&path).unwrap();
    assert!(after.starts_with(&before), "earlier lines changed");
    assert_eq!(String::from_utf8(after).unwrap().lines().count(), 3);
}

#[test]
fn a_cut_line_is_kept_and_the_next_event_starts_a_new_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&path).unwrap();
    log.append(&lifecycle()[0]).unwrap();
    drop(log);
    // A crash in the middle of a line.
    let mut torn = fs::read(&path).unwrap();
    torn.extend_from_slice(br#"{"time":"2026-10-31T14:0"#);
    fs::write(&path, &torn).unwrap();

    let mut log = AuditLog::open(&path).unwrap();
    log.append(&lifecycle()[2]).unwrap();
    let after = fs::read(&path).unwrap();
    assert!(after.starts_with(&torn), "the cut line was rewritten");
    let text = String::from_utf8(after).unwrap();
    let last = text.lines().last().unwrap();
    assert!(
        serde_json::from_str::<serde_json::Value>(last).is_ok(),
        "{last}"
    );
}

#[test]
fn the_log_holds_no_secret() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&path).unwrap();
    for event in lifecycle() {
        log.append(&event).unwrap();
    }
    let text = fs::read_to_string(&path).unwrap();
    for line in text.lines() {
        assert!(!looks_secret(line), "{line}");
    }
    // The approval's signature is never there, only the approver's fingerprint.
    assert!(!text.contains("SSH SIGNATURE"));
    assert!(text.contains(fp('A').as_str()));
}

#[test]
fn the_scan_finds_what_it_looks_for() {
    for secret in [
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN SSH SIGNATURE-----",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI",
        "AGE-SECRET-KEY-1QQQ",
        "token ghp_abcdef",
    ] {
        assert!(looks_secret(secret), "{secret}");
    }
    assert!(!looks_secret(
        "outside ticket wrt_01: branch main not allowed"
    ));
}

#[test]
fn the_log_and_the_database_are_private_from_creation() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.jsonl");
    AuditLog::open(&audit).unwrap();
    let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&audit), 0o600);
    let db = dir.path().join("leases.db");
    writ_store::Store::open(&db).unwrap();
    assert_eq!(mode(&db), 0o600);
}

#[test]
fn a_write_cut_short_never_glues_the_next_line_to_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let (mut log, breaker) = AuditLog::open_breakable(&path).unwrap();
    let events = lifecycle();
    log.append(&events[0]).unwrap();
    breaker.set_cut_short(true);
    assert!(log.append(&events[1]).is_err());
    breaker.set_cut_short(false);
    log.append(&events[2]).unwrap();
    let text = fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    // The first and the last are whole events; the middle one is the fragment, alone.
    for line in [lines[0], lines[2]] {
        assert!(
            serde_json::from_str::<serde_json::Value>(line).is_ok(),
            "{line}"
        );
    }
    assert!(serde_json::from_str::<serde_json::Value>(lines[1]).is_err());
}

#[test]
fn characters_a_terminal_acts_on_are_escaped_in_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&path).unwrap();
    let hostile = "refs/heads/x\u{9b}31m\u{202e}\u{200b}\u{e0041}é";
    log.append(
        &AuditEvent::new(t(0), EventKind::Push, Outcome::Denied)
            .refs([hostile.to_owned()])
            .reason(hostile),
    )
    .unwrap();
    let text = fs::read_to_string(&path).unwrap();
    for c in text.trim_end().chars() {
        assert!(
            !writ_core::text::is_hidden_char(c),
            "{c:?} reached the file"
        );
    }
    assert!(
        text.contains("\\u009b") && text.contains("\\u202e") && text.contains("\\udb40\\udc41")
    );
    assert!(text.contains('é'), "visible characters stay as they are");
    // Still the same text once read back.
    let event: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
    assert_eq!(event["reason"], hostile);
    assert_eq!(event["refs"][0], hostile);
}
