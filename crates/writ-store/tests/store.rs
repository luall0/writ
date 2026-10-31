//! The lease store and ledger: state across a reopen, compare-and-set transitions, atomic
//! counters, strict decoding of what is stored.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::Arc;
use std::thread;

use writ_core::config::PolicyConfig;
use writ_core::fit::{self, Submission};
use writ_core::lease::{
    self, APPROVAL_NAMESPACE, Approval, Lease, LifecycleError, State, TicketRecord,
};
use writ_core::names::{CommitId, KeyFingerprint, TicketId};
use writ_core::ticket::{Ticket, TicketRequest};
use writ_core::units::Timestamp;
use writ_store::{Counter, LedgerEntry, Store, StoreError};

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
    store.insert_pending(&ticket, t(0)).unwrap();
    let record = store.ticket(&ticket.id).unwrap().unwrap();
    let lease = lease::activate(&config(), &record, ticket, approval(), n, t(10)).unwrap();
    store.activate(&lease, t(10)).unwrap();
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
        store.insert_pending(&pending, t(0)).unwrap();
        let refused = ticket(3, REQUEST, None);
        store.insert_pending(&refused, t(0)).unwrap();
        store.refuse(&refused.id, "split it", t(5)).unwrap();
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
    store.insert_pending(&submitted, t(0)).unwrap();
    let mut signed = submitted.clone();
    signed.limits.max_signatures = 1;
    let record = store.ticket(&submitted.id).unwrap().unwrap();
    let lease = lease::activate(&config(), &record, signed.clone(), approval(), 1, t(5)).unwrap();
    store.activate(&lease, t(5)).unwrap();
    assert_eq!(store.lease(&submitted.id).unwrap().unwrap().ticket, signed);
}

#[test]
fn transitions_are_compare_and_set() {
    let store = Store::open_in_memory().unwrap();
    let lease = active_lease(&store, 1);
    // Activating twice: the second sees it is no longer pending.
    assert!(matches!(
        store.activate(&lease, t(11)),
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
    assert!(
        store
            .transition(&lease.id, State::Pending, State::Active, t(12))
            .is_err()
    );
    store
        .transition(&lease.id, State::Active, State::Revoked, t(13))
        .unwrap();
    assert_eq!(
        store.lease(&lease.id).unwrap().unwrap().state,
        State::Revoked
    );
    assert!(
        store
            .transition(&lease.id, State::Revoked, State::Active, t(14))
            .is_err()
    );
    assert!(matches!(
        store.transition(&id(9), State::Active, State::Revoked, t(14)),
        Err(StoreError::NotFound(_))
    ));
    // Refusing a lease, or twice.
    assert!(store.refuse(&lease.id, "no", t(15)).is_err());
    // The same id twice.
    let again = ticket(1, REQUEST, None);
    assert!(matches!(
        store.insert_pending(&again, t(16)),
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
    store.insert_pending(&pending, t(0)).unwrap();
    assert!(
        !store
            .consume(&pending.id, Counter::Fetch, 0, t(52))
            .unwrap()
    );
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
    store.insert_pending(&amendment, t(40)).unwrap();
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
    assert!(store.apply_amendment(&updated, &applied, t(60)).is_err());
    assert_eq!(store.lease(&lease.id).unwrap().unwrap(), updated);
}

#[test]
fn an_amendment_of_an_ended_lease_changes_nothing() {
    let store = Store::open_in_memory().unwrap();
    let lease = active_lease(&store, 1);
    let amended_yaml = REQUEST.replace("  task:", &format!("  amends: {}\n  task:", lease.id));
    let amendment = ticket(2, &amended_yaml, Some(&lease));
    store.insert_pending(&amendment, t(40)).unwrap();
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
    assert!(store.apply_amendment(&updated, &applied, t(56)).is_err());
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
    assert!(
        store
            .ledger_append(&entry(9, &id(42), "omega-code"))
            .is_err()
    );
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
    assert!(store.leases(State::Active).is_err());
    raw.execute("UPDATE tickets SET canonical = ?1", [&original])
        .unwrap();
    assert!(store.lease(&lease.id).unwrap().is_some());

    tamper("UPDATE tickets SET state = 'superuser'");
    assert!(store.lease(&lease.id).is_err());
    tamper("UPDATE tickets SET state = 'active', namespace = 'git'");
    assert!(store.lease(&lease.id).is_err());
    tamper("UPDATE tickets SET namespace = 'writ-approval', sshsig = NULL");
    assert!(store.lease(&lease.id).is_err());
}

#[test]
fn a_newer_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("writ.db");
    drop(Store::open(&path).unwrap());
    rusqlite::Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 2)
        .unwrap();
    assert!(matches!(
        Store::open(&path),
        Err(StoreError::SchemaTooNew(2))
    ));
}
