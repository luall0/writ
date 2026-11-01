//! The lease store and ledger: state across a reopen, compare-and-set transitions, atomic
//! counters, strict decoding of what is stored.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::path::Path;
use std::sync::Arc;
use std::thread;

use writ_core::canonical::Canonical;
use writ_core::config::PolicyConfig;
use writ_core::fit::{self, Submission};
use writ_core::lease::{
    self, APPROVAL_NAMESPACE, Approval, Lease, LifecycleError, State, TicketRecord,
};
use writ_core::names::{CommitId, KeyFingerprint, TicketId};
use writ_core::policy::RATE_WINDOW_SECONDS;
use writ_core::ticket::{Ticket, TicketRequest};
use writ_core::units::Timestamp;
use writ_store::{Counter, LedgerEntry, OPS_KEPT_PAST_WINDOW_SECONDS, Store, StoreError};

/// Stand-ins: the store keeps these as text and never parses them.
const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIStandInSessionKey";
const CERT: &str = "ssh-ed25519-cert-v01@openssh.com AAAAStandInCertificate";

const POLICY: &str = include_str!("../../writ-core/tests/fixtures/policy.yaml");

const REQUEST: &str = r#"
template: feature-branch
scope:
  repos: [omega-code]
  operations: [fetch, commit_sign, push]
  branches: ["agent/oauth-*"]
ticket:
  title: Add OAuth login
  task: Add GitHub OAuth login behind a feature flag
limits:
  ttl: 2h
  max_signatures: 3
  max_pushes: 2
  max_ops_per_minute: 5
"#;

fn config() -> PolicyConfig {
    PolicyConfig::from_yaml(POLICY).unwrap()
}

fn t(offset: i64) -> Timestamp {
    Timestamp::from_unix(1_793_455_331 + offset).unwrap()
}

fn fp(c: char) -> KeyFingerprint {
    format!("SHA256:{}", c.to_string().repeat(43))
        .parse()
        .unwrap()
}

fn id(n: u64) -> TicketId {
    TicketId::from_parts(1_793_455_331_000 + n, [n as u8; 10])
}

fn commit(n: u64) -> CommitId {
    format!("{n:040x}").parse().unwrap()
}

fn approval() -> Approval {
    Approval {
        approver: fp('A'),
        namespace: APPROVAL_NAMESPACE.to_owned(),
        sshsig: "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----".to_owned(),
    }
}

fn ticket(n: u64, yaml: &str, amends: Option<&Lease>) -> Ticket {
    let submission = Submission {
        id: id(n),
        now: t(0),
        session_key: fp('S'),
        amends,
        revises: None,
    };
    fit::submit(
        &config(),
        &TicketRequest::from_yaml(yaml).unwrap(),
        &submission,
    )
    .unwrap()
}

/// Submits and activates ticket `n` in the store, with certificate serial `n`.
fn active_lease(store: &Store, n: u64) -> Lease {
    let ticket = ticket(n, REQUEST, None);
    store.insert_pending(&ticket, KEY, t(0)).unwrap();
    let record = store.ticket(&ticket.id).unwrap().unwrap();
    let lease = lease::activate(&config(), &record, ticket, approval(), n, t(10)).unwrap();
    store.activate(&lease, CERT, t(10)).unwrap();
    lease
}

fn entry(commit_n: u64, lease: &TicketId, repo: &str) -> LedgerEntry {
    LedgerEntry {
        commit: commit(commit_n),
        lease: lease.clone(),
        repo: repo.parse().unwrap(),
        key: "agent-ed25519-01".parse().unwrap(),
        signed_at: t(20 + commit_n as i64),
    }
}

#[test]
fn leases_and_ledger_survive_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("writ.db");
    let (lease, pending, refused) = {
        let store = Store::open(&path).unwrap();
        let lease = active_lease(&store, 1);
        assert!(
            store
                .consume(&lease.id, Counter::Signature, 3, t(30))
                .unwrap()
        );
        assert!(store.consume(&lease.id, Counter::Push, 2, t(31)).unwrap());
        store
            .ledger_append(&entry(1, &lease.id, "omega-code"))
            .unwrap();
        store
            .ledger_append(&entry(2, &lease.id, "omega-code"))
            .unwrap();
        let pending = ticket(2, REQUEST, None);
        store.insert_pending(&pending, KEY, t(0)).unwrap();
        let refused = ticket(3, REQUEST, None);
        store.insert_pending(&refused, KEY, t(0)).unwrap();
        store
            .refuse(&refused.id, "split it", Some(&fp('A')), t(5))
            .unwrap();
        let open = ticket(4, REQUEST, None);
        store.insert_pending(&open, KEY, t(0)).unwrap();
        store.refuse(&open.id, "anyone", None, t(5)).unwrap();
        (lease, pending, refused)
    };
    let store = Store::open(&path).unwrap();
    assert_eq!(store.lease(&lease.id).unwrap().unwrap(), lease);
    assert_eq!(store.leases(State::Active).unwrap(), vec![lease.clone()]);
    let usage = store.usage(&lease.id, t(40)).unwrap();
    assert_eq!(
        (usage.signatures, usage.pushes, usage.ops_last_minute),
        (1, 1, 2)
    );
    let entries = store.ledger_for_lease(&lease.id).unwrap();
    assert_eq!(
        entries,
        vec![
            entry(1, &lease.id, "omega-code"),
            entry(2, &lease.id, "omega-code")
        ]
    );
    assert_eq!(
        store.ledger_entries(&commit(2)).unwrap(),
        vec![entry(2, &lease.id, "omega-code")]
    );
    assert_eq!(
        store.ticket(&pending.id).unwrap().unwrap(),
        TicketRecord::pending(pending.clone())
    );
    let refused = store.ticket(&refused.id).unwrap().unwrap();
    assert_eq!(
        (refused.state, refused.feedback.as_deref()),
        (State::Refused, Some("split it"))
    );
    assert_eq!(refused.feedback_by, Some(fp('A')), "who signed the refusal");
    let open = store.ticket(&id(4)).unwrap().unwrap();
    assert_eq!(open.feedback_by, None, "a refusal nobody signed");
    assert_eq!(store.tickets(State::Pending).unwrap().len(), 1);
    assert!(
        store.lease(&pending.id).unwrap().is_none(),
        "a pending ticket is not a lease"
    );
}

#[test]
fn a_narrowed_lease_is_stored_as_signed() {
    let store = Store::open_in_memory().unwrap();
    let submitted = ticket(1, REQUEST, None);
    store.insert_pending(&submitted, KEY, t(0)).unwrap();
    let mut signed = submitted.clone();
    signed.limits.max_signatures = 1;
    let record = store.ticket(&submitted.id).unwrap().unwrap();
    let lease = lease::activate(&config(), &record, signed.clone(), approval(), 1, t(5)).unwrap();
    store.activate(&lease, CERT, t(5)).unwrap();
    assert_eq!(store.lease(&submitted.id).unwrap().unwrap().ticket, signed);
}

#[test]
fn transitions_are_compare_and_set() {
    let store = Store::open_in_memory().unwrap();
    let lease = active_lease(&store, 1);
    // Activating twice: the second sees it is no longer pending.
    assert!(matches!(
        store.activate(&lease, CERT, t(11)),
        Err(StoreError::Conflict { .. })
    ));
    // A transition from the wrong state.
    assert!(matches!(
        store.transition(&lease.id, State::Pending, State::Expired, t(12)),
        Err(StoreError::Conflict { .. })
    ));
    // A transition the lifecycle forbids, whatever the stored state.
    assert!(matches!(
        store.transition(&lease.id, State::Active, State::Pending, t(12)),
        Err(StoreError::Lifecycle(LifecycleError::Transition { .. }))
    ));
    // Activation only through activate().
    assert!(matches!(
        store.transition(&lease.id, State::Pending, State::Active, t(12)),
        Err(StoreError::Lifecycle(LifecycleError::Transition {
            from: State::Pending,
            to: State::Active
        }))
    ));
    store
        .transition(&lease.id, State::Active, State::Revoked, t(13))
        .unwrap();
    assert_eq!(
        store.lease(&lease.id).unwrap().unwrap().state,
        State::Revoked
    );
    assert!(matches!(
        store.transition(&lease.id, State::Revoked, State::Active, t(14)),
        Err(StoreError::Lifecycle(LifecycleError::Transition {
            from: State::Revoked,
            to: State::Active
        }))
    ));
    assert!(matches!(
        store.transition(&id(9), State::Active, State::Revoked, t(14)),
        Err(StoreError::NotFound(_))
    ));
    // Refusing a lease, or twice.
    assert!(matches!(
        store.refuse(&lease.id, "no", None, t(15)),
        Err(StoreError::Conflict {
            expected: State::Pending,
            ..
        })
    ));
    // The same id twice.
    let again = ticket(1, REQUEST, None);
    assert!(matches!(
        store.insert_pending(&again, KEY, t(16)),
        Err(StoreError::Duplicate(_))
    ));
}

#[test]
fn counters_never_go_over_the_limit() {
    let store = Store::open_in_memory().unwrap();
    let lease = active_lease(&store, 1);
    for i in 0..3 {
        assert!(
            store
                .consume(&lease.id, Counter::Signature, 3, t(30 + i))
                .unwrap()
        );
    }
    assert!(
        !store
            .consume(&lease.id, Counter::Signature, 3, t(40))
            .unwrap()
    );
    assert_eq!(store.usage(&lease.id, t(40)).unwrap().signatures, 3);
    // A refused take records no operation.
    assert_eq!(store.usage(&lease.id, t(40)).unwrap().ops_last_minute, 3);
    // Fetches only count for the rate.
    assert!(store.consume(&lease.id, Counter::Fetch, 0, t(41)).unwrap());
    let usage = store.usage(&lease.id, t(41)).unwrap();
    assert_eq!(
        (usage.signatures, usage.pushes, usage.ops_last_minute),
        (3, 0, 4)
    );
    // The rate window slides.
    assert_eq!(
        store.usage(&lease.id, t(30 + 60)).unwrap().ops_last_minute,
        3
    );
    assert_eq!(
        store.usage(&lease.id, t(31 + 60)).unwrap().ops_last_minute,
        2
    );
    assert_eq!(store.usage(&lease.id, t(200)).unwrap().ops_last_minute, 0);
    // Nothing is taken from a lease that isn't active.
    store
        .transition(&lease.id, State::Active, State::Expired, t(50))
        .unwrap();
    assert!(!store.consume(&lease.id, Counter::Push, 2, t(51)).unwrap());
    assert!(!store.consume(&lease.id, Counter::Fetch, 0, t(51)).unwrap());
    // Nor from a pending ticket.
    let pending = ticket(2, REQUEST, None);
    store.insert_pending(&pending, KEY, t(0)).unwrap();
    assert!(
        !store
            .consume(&pending.id, Counter::Fetch, 0, t(52))
            .unwrap()
    );
}

#[test]
fn old_operations_are_pruned_and_the_window_still_counts() {
    let store = Store::open_in_memory().unwrap();
    let lease = active_lease(&store, 1);
    for offset in [30, 31, 90] {
        assert!(
            store
                .consume(&lease.id, Counter::Fetch, 0, t(offset))
                .unwrap()
        );
    }
    // Kept until the window ending now is past them by the margin, then deleted.
    let kept = RATE_WINDOW_SECONDS + OPS_KEPT_PAST_WINDOW_SECONDS;
    assert_eq!(store.prune_ops(t(30 + kept - 1)).unwrap(), 0);
    assert_eq!(store.ops_rows().unwrap(), 3);
    assert_eq!(store.prune_ops(t(30 + kept)).unwrap(), 1);
    assert_eq!(store.prune_ops(t(31 + kept)).unwrap(), 1);
    assert_eq!(store.ops_rows().unwrap(), 1);
    // Pruning never touches what a window counts, even with the clock set back by the margin.
    assert_eq!(store.usage(&lease.id, t(120)).unwrap().ops_last_minute, 1);
    assert_eq!(store.prune_ops(t(90)).unwrap(), 0);
    assert_eq!(store.usage(&lease.id, t(120)).unwrap().ops_last_minute, 1);
}

#[test]
fn concurrent_takes_never_overshoot() {
    let dir = tempfile::tempdir().unwrap();
    let path = Arc::new(dir.path().join("writ.db"));
    let lease = active_lease(&Store::open(&path).unwrap(), 1);
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let path = Arc::clone(&path);
            let id = lease.id.clone();
            thread::spawn(move || {
                let store = open_retrying(&path);
                let mut taken = 0;
                for i in 0..20 {
                    loop {
                        match store.consume(&id, Counter::Push, 25, t(100 + i)) {
                            Ok(true) => {
                                taken += 1;
                                break;
                            }
                            Ok(false) => break,
                            Err(StoreError::Sqlite(_)) => continue, // busy: retry
                            Err(e) => panic!("{e}"),
                        }
                    }
                }
                taken
            })
        })
        .collect();
    let total: u32 = workers.into_iter().map(|w| w.join().unwrap()).sum();
    assert_eq!(total, 25);
    assert_eq!(
        Store::open(&path)
            .unwrap()
            .usage(&lease.id, t(200))
            .unwrap()
            .pushes,
        25
    );
}

fn open_retrying(path: &Path) -> Store {
    loop {
        if let Ok(store) = Store::open(path) {
            return store;
        }
    }
}

#[test]
fn an_amendment_replaces_the_terms_in_force() {
    let store = Store::open_in_memory().unwrap();
    let lease = active_lease(&store, 1);
    assert!(
        store
            .consume(&lease.id, Counter::Signature, 3, t(30))
            .unwrap()
    );
    let amended_yaml = REQUEST
        .replace("[omega-code]", "[omega-code, homelab-scripts]")
        .replace("  task:", &format!("  amends: {}\n  task:", lease.id));
    let amendment = ticket(2, &amended_yaml, Some(&lease));
    store.insert_pending(&amendment, KEY, t(40)).unwrap();
    let record = store.ticket(&amendment.id).unwrap().unwrap();
    let (updated, applied) = lease::apply_amendment(
        &config(),
        &lease,
        &record,
        amendment.clone(),
        approval(),
        t(50),
    )
    .unwrap();
    store.apply_amendment(&updated, &applied, t(50)).unwrap();

    let loaded = store.lease(&lease.id).unwrap().unwrap();
    assert_eq!(loaded, updated);
    assert_eq!(loaded.ticket.id, amendment.id);
    assert_eq!(
        store.ticket(&amendment.id).unwrap().unwrap().state,
        State::Applied
    );
    // Usage carries over.
    assert_eq!(store.usage(&lease.id, t(51)).unwrap().signatures, 1);
    // The amendment's id is not a lease of its own.
    assert!(store.lease(&amendment.id).unwrap().is_none());
    // Applying again: the amendment is no longer pending, nothing changes.
    assert!(matches!(
        store.apply_amendment(&updated, &applied, t(60)),
        Err(StoreError::Conflict {
            expected: State::Pending,
            ..
        })
    ));
    assert_eq!(store.lease(&lease.id).unwrap().unwrap(), updated);
}

#[test]
fn an_amendment_of_an_ended_lease_changes_nothing() {
    let store = Store::open_in_memory().unwrap();
    let lease = active_lease(&store, 1);
    let amended_yaml = REQUEST.replace("  task:", &format!("  amends: {}\n  task:", lease.id));
    let amendment = ticket(2, &amended_yaml, Some(&lease));
    store.insert_pending(&amendment, KEY, t(40)).unwrap();
    let record = store.ticket(&amendment.id).unwrap().unwrap();
    let (updated, applied) = lease::apply_amendment(
        &config(),
        &lease,
        &record,
        amendment.clone(),
        approval(),
        t(50),
    )
    .unwrap();
    // Revoked between the decision and the write.
    store
        .transition(&lease.id, State::Active, State::Revoked, t(55))
        .unwrap();
    assert!(matches!(
        store.apply_amendment(&updated, &applied, t(56)),
        Err(StoreError::Conflict {
            expected: State::Active,
            ..
        })
    ));
    // Both or neither: the amendment is still pending, the lease keeps its terms.
    assert_eq!(
        store.ticket(&amendment.id).unwrap().unwrap().state,
        State::Pending
    );
    assert_eq!(
        store.lease(&lease.id).unwrap().unwrap().ticket,
        lease.ticket
    );
}

#[test]
fn the_ledger_keeps_the_first_entry() {
    let store = Store::open_in_memory().unwrap();
    let a = active_lease(&store, 1);
    let b = active_lease(&store, 2);
    store.ledger_append(&entry(7, &a.id, "omega-code")).unwrap();
    let mut later = entry(7, &a.id, "omega-code");
    later.signed_at = t(999);
    store.ledger_append(&later).unwrap();
    store.ledger_append(&entry(7, &b.id, "omega-code")).unwrap();
    let entries = store.ledger_entries(&commit(7)).unwrap();
    assert_eq!(
        entries,
        vec![entry(7, &a.id, "omega-code"), entry(7, &b.id, "omega-code")]
    );
    assert!(store.ledger_entries(&commit(8)).unwrap().is_empty());
    // An entry for a lease that doesn't exist is refused.
    assert!(matches!(
        store.ledger_append(&entry(9, &id(42), "omega-code")),
        Err(StoreError::Sqlite(_))
    ));
    assert!(store.ledger_entries(&commit(9)).unwrap().is_empty());
}

#[test]
fn tampered_records_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("writ.db");
    let lease = active_lease(&Store::open(&path).unwrap(), 1);
    let raw = rusqlite::Connection::open(&path).unwrap();
    let tamper = |sql: &str| raw.execute(sql, []).unwrap();
    let store = Store::open(&path).unwrap();

    // Widening the stored ticket by hand: its JSON is no longer canonical.
    let original: Vec<u8> = raw
        .query_row("SELECT canonical FROM tickets", [], |r| r.get(0))
        .unwrap();
    let widened = String::from_utf8(original.clone())
        .unwrap()
        .replace("\"max_signatures\":3", "\"max_signatures\": 300");
    raw.execute("UPDATE tickets SET canonical = ?1", [widened.as_bytes()])
        .unwrap();
    assert!(matches!(
        store.lease(&lease.id),
        Err(StoreError::Corrupt { .. })
    ));
    assert!(matches!(
        store.leases(State::Active),
        Err(StoreError::Corrupt { .. })
    ));
    raw.execute("UPDATE tickets SET canonical = ?1", [&original])
        .unwrap();
    assert!(store.lease(&lease.id).unwrap().is_some());

    tamper("UPDATE tickets SET state = 'superuser'");
    assert!(matches!(
        store.lease(&lease.id),
        Err(StoreError::Corrupt { .. })
    ));
    tamper("UPDATE tickets SET state = 'active', namespace = 'git'");
    assert!(matches!(
        store.lease(&lease.id),
        Err(StoreError::Corrupt { .. })
    ));
    tamper("UPDATE tickets SET namespace = 'writ-approval', sshsig = NULL");
    assert!(matches!(
        store.lease(&lease.id),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn a_newer_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("writ.db");
    drop(Store::open(&path).unwrap());
    rusqlite::Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 4)
        .unwrap();
    assert!(matches!(
        Store::open(&path),
        Err(StoreError::SchemaTooNew(4))
    ));
}

#[test]
fn keeps_the_session_key_and_the_certificate() {
    let store = Store::open_in_memory().unwrap();
    let lease = active_lease(&store, 1);
    assert_eq!(
        store.session_pubkey(&lease.id).unwrap().as_deref(),
        Some(KEY)
    );
    assert_eq!(store.certificate(&lease.id).unwrap().as_deref(), Some(CERT));
    assert_eq!(store.session_pubkey(&id(99)).unwrap(), None);
    assert_eq!(store.count(State::Active).unwrap(), 1);
    assert_eq!(store.count(State::Pending).unwrap(), 0);
    assert_eq!(store.recent_tickets(10).unwrap().len(), 1);
}

#[test]
fn a_listing_holds_the_most_recent_tickets_only() {
    let store = Store::open_in_memory().unwrap();
    for n in 1..=5 {
        active_lease(&store, n);
    }
    let ids = |limit| -> Vec<TicketId> {
        store
            .recent_tickets(limit)
            .unwrap()
            .into_iter()
            .map(|r| r.ticket.id)
            .collect()
    };
    assert_eq!(ids(3), [id(3), id(4), id(5)], "the newest, oldest first");
    assert_eq!(ids(5), [id(1), id(2), id(3), id(4), id(5)]);
    assert_eq!(ids(6).len(), 5);
    assert!(ids(0).is_empty());
}

#[test]
fn a_version_1_database_is_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("writ.db");
    {
        // The M1 schema, with one pending ticket.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE tickets (id TEXT PRIMARY KEY, canonical BLOB NOT NULL, state TEXT NOT NULL,
                 lease_id TEXT NOT NULL, feedback TEXT, approver TEXT, namespace TEXT, sshsig TEXT,
                 cert_serial INTEGER UNIQUE, current_ticket TEXT REFERENCES tickets(id),
                 signatures INTEGER NOT NULL DEFAULT 0, pushes INTEGER NOT NULL DEFAULT 0,
                 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL) STRICT;
             CREATE TABLE ops (lease_id TEXT NOT NULL, at INTEGER NOT NULL) STRICT;
             CREATE TABLE ledger (commit_id TEXT NOT NULL, lease_id TEXT NOT NULL, repo TEXT NOT NULL,
                 key_id TEXT NOT NULL, signed_at INTEGER NOT NULL,
                 PRIMARY KEY (commit_id, lease_id, repo)) STRICT;
             PRAGMA user_version = 1;",
        )
        .unwrap();
        let pending = ticket(1, REQUEST, None);
        conn.execute(
            "INSERT INTO tickets (id, canonical, state, lease_id, created_at, updated_at)
             VALUES (?1, ?2, 'pending', ?1, 0, 0)",
            rusqlite::params![pending.id.as_str(), pending.canonical_bytes().unwrap()],
        )
        .unwrap();
    }
    let store = Store::open(&path).unwrap();
    let pending = store.tickets(State::Pending).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(store.session_pubkey(&pending[0].ticket.id).unwrap(), None);
    assert_eq!(pending[0].feedback_by, None);
    let version: i64 = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 3);
}
