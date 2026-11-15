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

use writ_core::config::PolicyConfig;
use writ_core::fit::{self, Submission};
use writ_core::lease::{
    self, APPROVAL_NAMESPACE, Approval, Lease, LifecycleError, RepoUsage, State, TicketRecord,
};
use writ_core::names::{CommitId, KeyFingerprint, KeyId, RepoName, TicketId};
use writ_core::net::Source;
use writ_core::policy::RATE_WINDOW_SECONDS;
use writ_core::ticket::{Ticket, TicketRequest};
use writ_core::units::Timestamp;
use writ_store::{
    Counter, LedgerEntry, OPS_KEPT_PAST_WINDOW_SECONDS, PendingNote, STATE_VERSION, Store,
    StoreError,
};

/// Stand-ins: the store keeps these as text and never parses them.
const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIStandInSessionKey";
const CERT: &str = "ssh-ed25519-cert-v01@openssh.com AAAAStandInCertificate";
const SOURCE: Source = Source::Local;

const POLICY: &str = include_str!("../../writ-core/tests/fixtures/policy.yaml");

const REQUEST: &str = r#"
repos:
  omega-code:
    template: feature-branch
    operations: [fetch, commit_sign, push]
    branches: ["agent/oauth-*"]
    limits:
      max_signatures: 3
      max_pushes: 2
ticket:
  title: Add OAuth login
  task: Add GitHub OAuth login behind a feature flag
limits:
  ttl: 2h
  max_ops_per_minute: 5
"#;

/// The repository [`REQUEST`] names.
fn omega() -> RepoName {
    "omega-code".parse().unwrap()
}

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
        renews: None,
        revises: None,
        min_ttl: fit::DEFAULT_MIN_TTL,
        chain: None,
        launcher: None,
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
    store.insert_pending(&ticket, KEY, SOURCE, t(0)).unwrap();
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
        paths_digest: commit_n
            .is_multiple_of(2)
            .then(|| format!("digest-{commit_n}")),
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
                .consume(&lease.id, &omega(), Counter::Signature, 3, t(30))
                .unwrap()
        );
        assert!(
            store
                .consume(&lease.id, &omega(), Counter::Push, 2, t(31))
                .unwrap()
        );
        store
            .ledger_append(&entry(1, &lease.id, "omega-code"))
            .unwrap();
        store
            .ledger_append(&entry(2, &lease.id, "omega-code"))
            .unwrap();
        let pending = ticket(2, REQUEST, None);
        store.insert_pending(&pending, KEY, SOURCE, t(0)).unwrap();
        let refused = ticket(3, REQUEST, None);
        store.insert_pending(&refused, KEY, SOURCE, t(0)).unwrap();
        store
            .refuse(&refused.id, "split it", Some(&fp('A')), t(5))
            .unwrap();
        let open = ticket(4, REQUEST, None);
        store.insert_pending(&open, KEY, SOURCE, t(0)).unwrap();
        store.refuse(&open.id, "anyone", None, t(5)).unwrap();
        (lease, pending, refused)
    };
    let store = Store::open(&path).unwrap();
    assert_eq!(store.lease(&lease.id).unwrap().unwrap(), lease);
    assert_eq!(store.leases(State::Active).unwrap(), vec![lease.clone()]);
    let usage = store.usage(&lease.id, t(40)).unwrap();
    assert_eq!(
        (
            usage.of(&omega()).signatures,
            usage.of(&omega()).pushes,
            usage.ops_last_minute
        ),
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
        TicketRecord {
            source: Some(SOURCE),
            ..TicketRecord::pending(pending.clone())
        }
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
    store.insert_pending(&submitted, KEY, SOURCE, t(0)).unwrap();
    let mut signed = submitted.clone();
    signed
        .repos
        .get_mut(&omega())
        .unwrap()
        .limits
        .max_signatures = 1;
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
        store.insert_pending(&again, KEY, SOURCE, t(16)),
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
                .consume(&lease.id, &omega(), Counter::Signature, 3, t(30 + i))
                .unwrap()
        );
    }
    assert!(
        !store
            .consume(&lease.id, &omega(), Counter::Signature, 3, t(40))
            .unwrap()
    );
    assert_eq!(
        store
            .usage(&lease.id, t(40))
            .unwrap()
            .of(&omega())
            .signatures,
        3
    );
    // A refused take records no operation.
    assert_eq!(store.usage(&lease.id, t(40)).unwrap().ops_last_minute, 3);
    // Fetches only count for the rate.
    assert!(
        store
            .consume(&lease.id, &omega(), Counter::Fetch, 0, t(41))
            .unwrap()
    );
    let usage = store.usage(&lease.id, t(41)).unwrap();
    assert_eq!(
        (
            usage.of(&omega()).signatures,
            usage.of(&omega()).pushes,
            usage.ops_last_minute
        ),
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
    assert!(
        !store
            .consume(&lease.id, &omega(), Counter::Push, 2, t(51))
            .unwrap()
    );
    assert!(
        !store
            .consume(&lease.id, &omega(), Counter::Fetch, 0, t(51))
            .unwrap()
    );
    // Nor from a pending ticket.
    let pending = ticket(2, REQUEST, None);
    store.insert_pending(&pending, KEY, SOURCE, t(0)).unwrap();
    assert!(
        !store
            .consume(&pending.id, &omega(), Counter::Fetch, 0, t(52))
            .unwrap()
    );
}

/// Signatures and pushes are counted per repository (each against its own limit); the rate
/// counts every repository together. Each limit on both sides.
#[test]
fn counters_are_per_repository() {
    let store = Store::open_in_memory().unwrap();
    let lease = active_lease(&store, 1);
    let homelab: RepoName = "homelab-scripts".parse().unwrap();
    for i in 0..2 {
        assert!(
            store
                .consume(&lease.id, &omega(), Counter::Push, 2, t(30 + i))
                .unwrap()
        );
    }
    // omega-code's pushes used up: one more there is refused, homelab-scripts' still counts
    // from zero up to its own limit.
    assert!(
        !store
            .consume(&lease.id, &omega(), Counter::Push, 2, t(32))
            .unwrap()
    );
    assert!(
        store
            .consume(&lease.id, &homelab, Counter::Push, 1, t(33))
            .unwrap()
    );
    assert!(
        !store
            .consume(&lease.id, &homelab, Counter::Push, 1, t(34))
            .unwrap()
    );
    assert!(
        store
            .consume(&lease.id, &homelab, Counter::Signature, 1, t(35))
            .unwrap()
    );
    let usage = store.usage(&lease.id, t(40)).unwrap();
    assert_eq!(
        usage.repos,
        [
            (
                homelab.clone(),
                RepoUsage {
                    signatures: 1,
                    pushes: 1
                }
            ),
            (
                omega(),
                RepoUsage {
                    signatures: 0,
                    pushes: 2
                }
            ),
        ]
        .into()
    );
    // One rate for the lease: the four operations allowed, in both repositories (the two
    // refused ones not counted).
    assert_eq!(usage.ops_last_minute, 4);
}

#[test]
fn old_operations_are_pruned_and_the_window_still_counts() {
    let store = Store::open_in_memory().unwrap();
    let lease = active_lease(&store, 1);
    for offset in [30, 31, 90] {
        assert!(
            store
                .consume(&lease.id, &omega(), Counter::Fetch, 0, t(offset))
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
                        match store.consume(&id, &omega(), Counter::Push, 25, t(100 + i)) {
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
            .of(&omega())
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
            .consume(&lease.id, &omega(), Counter::Signature, 3, t(30))
            .unwrap()
    );
    let amended_yaml = REQUEST
        .replace(
            "repos:\n",
            "repos:\n  homelab-scripts:\n    template: feature-branch\n    operations: [fetch]\n",
        )
        .replace("  task:", &format!("  amends: {}\n  task:", lease.id));
    let amendment = ticket(2, &amended_yaml, Some(&lease));
    store
        .insert_pending(&amendment, KEY, SOURCE, t(40))
        .unwrap();
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
    assert_eq!(
        store
            .usage(&lease.id, t(51))
            .unwrap()
            .of(&omega())
            .signatures,
        1
    );
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
    store
        .insert_pending(&amendment, KEY, SOURCE, t(40))
        .unwrap();
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

fn credential(name: &str) -> KeyId {
    name.parse().unwrap()
}

fn note(commit_n: u64, lease: &TicketId, key: &str) -> PendingNote {
    PendingNote {
        commit: commit(commit_n),
        lease: lease.clone(),
        credential: credential(key),
    }
}

#[test]
fn a_pushed_commit_waits_for_its_note_until_written() {
    let store = Store::open_in_memory().unwrap();
    let a = active_lease(&store, 1);
    let b = active_lease(&store, 2);
    let (omega, other) = ("omega-code".parse().unwrap(), "other".parse().unwrap());
    for n in [1, 2, 3] {
        store.ledger_append(&entry(n, &a.id, "omega-code")).unwrap();
    }
    store.ledger_append(&entry(4, &b.id, "omega-code")).unwrap();
    store.ledger_append(&entry(5, &a.id, "other")).unwrap();
    let up = credential("upstream-01");

    // Only the ledger's entries for this lease and repo: commit 4 is b's, 5 another repo's,
    // 9 nobody's.
    store
        .notes_add_pending(
            std::slice::from_ref(&a.id),
            &omega,
            &[commit(1), commit(2), commit(4), commit(5), commit(9)],
            &up,
        )
        .unwrap();
    assert_eq!(
        store.notes_pending(&omega, 10).unwrap(),
        [note(1, &a.id, "upstream-01"), note(2, &a.id, "upstream-01")]
    );
    assert!(store.notes_pending(&other, 10).unwrap().is_empty());

    // Another lease's push adds its own; oldest signature first, at most `limit`.
    store
        .notes_add_pending(std::slice::from_ref(&b.id), &omega, &[commit(4)], &up)
        .unwrap();
    store
        .notes_add_pending(std::slice::from_ref(&a.id), &omega, &[commit(3)], &up)
        .unwrap();
    assert_eq!(
        store.notes_pending(&omega, 2).unwrap(),
        [note(1, &a.id, "upstream-01"), note(2, &a.id, "upstream-01")]
    );
    assert_eq!(store.notes_pending(&omega, 4).unwrap().len(), 4);
    assert!(store.notes_pending(&omega, 0).unwrap().is_empty());

    // Written: no longer waiting, and pushed again (another branch) it stays written.
    store
        .notes_written(
            &omega,
            &[note(1, &a.id, "upstream-01"), note(4, &b.id, "upstream-01")],
        )
        .unwrap();
    assert_eq!(
        store.notes_pending(&omega, 10).unwrap(),
        [note(2, &a.id, "upstream-01"), note(3, &a.id, "upstream-01")]
    );
    store
        .notes_add_pending(std::slice::from_ref(&a.id), &omega, &[commit(1)], &up)
        .unwrap();
    assert_eq!(store.notes_pending(&omega, 10).unwrap().len(), 2);

    // Still waiting, pushed again by another credential: that one pushes its note.
    store
        .notes_add_pending(
            std::slice::from_ref(&a.id),
            &omega,
            &[commit(2)],
            &credential("upstream-02"),
        )
        .unwrap();
    assert_eq!(
        store.notes_pending(&omega, 1).unwrap(),
        [note(2, &a.id, "upstream-02")]
    );

    // Marking written only touches that repo's pending notes of that lease.
    store
        .notes_written(&other, &[note(2, &a.id, "upstream-02")])
        .unwrap();
    store
        .notes_written(&omega, &[note(3, &b.id, "upstream-01")])
        .unwrap();
    assert_eq!(store.notes_pending(&omega, 10).unwrap().len(), 2);
}

#[test]
fn commits_with_no_note_state_are_listed_newest_first() {
    let store = Store::open_in_memory().unwrap();
    let a = active_lease(&store, 1);
    let b = active_lease(&store, 2);
    let (omega, other) = ("omega-code".parse().unwrap(), "other".parse().unwrap());
    for n in [1, 2, 3] {
        store.ledger_append(&entry(n, &a.id, "omega-code")).unwrap();
    }
    store.ledger_append(&entry(4, &b.id, "omega-code")).unwrap();
    store.ledger_append(&entry(5, &a.id, "other")).unwrap();
    let up = credential("upstream-01");
    // 2 waits, 3 is written: neither is unrecorded.
    store
        .notes_add_pending(
            std::slice::from_ref(&a.id),
            &omega,
            &[commit(2), commit(3)],
            &up,
        )
        .unwrap();
    store
        .notes_written(&omega, &[note(3, &a.id, "upstream-01")])
        .unwrap();
    assert_eq!(
        store.notes_unrecorded(&omega, 10).unwrap(),
        [(commit(4), b.id.clone()), (commit(1), a.id.clone())]
    );
    assert_eq!(
        store.notes_unrecorded(&omega, 1).unwrap(),
        [(commit(4), b.id.clone())]
    );
    assert!(store.notes_unrecorded(&omega, 0).unwrap().is_empty());
    assert_eq!(
        store.notes_unrecorded(&other, 10).unwrap(),
        [(commit(5), a.id.clone())]
    );
}

#[test]
fn a_pending_note_without_its_credential_is_refused_as_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("writ.db");
    let store = Store::open(&path).unwrap();
    let a = active_lease(&store, 1);
    store.ledger_append(&entry(1, &a.id, "omega-code")).unwrap();
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute("UPDATE ledger SET note = 'pending'", [])
        .unwrap();
    let repo = "omega-code".parse().unwrap();
    assert!(matches!(
        store.notes_pending(&repo, 10),
        Err(StoreError::Corrupt { .. })
    ));
    // A state the schema doesn't know is refused when written.
    let other = rusqlite::Connection::open(&path)
        .unwrap()
        .execute("UPDATE ledger SET note = 'sent'", []);
    match other {
        Err(rusqlite::Error::SqliteFailure(e, Some(message))) => {
            assert_eq!(e.code, rusqlite::ErrorCode::ConstraintViolation);
            assert!(message.contains("CHECK constraint failed"), "{message}");
        }
        other => panic!("expected the CHECK constraint, got {other:?}"),
    }
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

/// The schema of version 11, frozen: what the step to 12 starts from.
const SCHEMA_V11: &str = include_str!("schemas/v11.sql");

/// The tables of version 11, all of them.
const TABLES_V11: [&str; 8] = [
    "formats",
    "tickets",
    "usage",
    "ops",
    "ledger",
    "authority",
    "authority_head",
    "token_versions",
];

/// A state with rows in every table, written through the store's own calls: an active lease
/// with its counters and recent operations, a pending ticket, a refused one, ledger entries
/// (one with a note pending), the authority versions and their head, a token's count.
fn filled(path: &Path) -> (Lease, TicketId, TicketId) {
    let store = Store::open(path).unwrap();
    let lease = active_lease(&store, 1);
    assert!(
        store
            .consume(&lease.id, &omega(), Counter::Signature, 3, t(20))
            .unwrap()
    );
    assert!(
        store
            .consume(&lease.id, &omega(), Counter::Push, 2, t(21))
            .unwrap()
    );
    let pending = ticket(2, REQUEST, None);
    store.insert_pending(&pending, KEY, SOURCE, t(30)).unwrap();
    let refused = ticket(3, REQUEST, None);
    store.insert_pending(&refused, KEY, SOURCE, t(31)).unwrap();
    store.refuse(&refused.id, "anyone", None, t(32)).unwrap();
    for n in 1..=3 {
        store
            .ledger_append(&entry(n, &lease.id, "omega-code"))
            .unwrap();
    }
    store
        .notes_add_pending(
            std::slice::from_ref(&lease.id),
            &omega(),
            &[commit(1)],
            &"upstream".parse().unwrap(),
        )
        .unwrap();
    let version = |target, text: &str| writ_store::AuthorityVersion {
        target,
        version: 1,
        text: text.to_owned(),
        digest: writ_core::authority::TextDigest::of(text),
        how: writ_store::AuthorityHow::Init,
        document: None,
        signature: None,
        approver: None,
        applied_at: t(1),
    };
    use writ_core::authority::AdminTarget;
    store
        .record_authority(
            &[
                version(AdminTarget::Policy, POLICY),
                version(AdminTarget::Approvers, "me ssh-ed25519 A\n"),
                version(AdminTarget::Readers, "mac ssh-ed25519 B\n"),
            ],
            &writ_store::AuthorityHead {
                versions: AdminTarget::ALL.into_iter().map(|t| (t, 1)).collect(),
                mac: "mac".to_owned(),
            },
        )
        .unwrap();
    let token = "upstream".parse().unwrap();
    assert_eq!(store.bump_token_version(&token, 0).unwrap(), 1);
    (lease, pending.id, refused.id)
}

/// The rows of the state at `from` copied into a new database at `to` written by version
/// 11's frozen schema: a state as a version 11 writd left it.
fn as_version_11(from: &Path, to: &Path) {
    let conn = rusqlite::Connection::open(to).unwrap();
    conn.execute_batch(SCHEMA_V11).unwrap();
    conn.execute("ATTACH DATABASE ?1 AS v12", [from.to_str().unwrap()])
        .unwrap();
    for table in TABLES_V11 {
        conn.execute(
            &format!("INSERT INTO main.{table} SELECT * FROM v12.{table}"),
            [],
        )
        .unwrap();
    }
    conn.execute("DETACH DATABASE v12", []).unwrap();
    conn.pragma_update(None, "user_version", 11).unwrap();
}

fn rows(path: &Path, table: &str) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

fn has_table(path: &Path, table: &str) -> bool {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
        == 1
}

#[test]
fn a_version_11_state_migrates_to_12_after_a_copy_with_every_row_kept() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.db");
    let (lease, pending, refused) = filled(&current);
    let old = dir.path().join("leases.db");
    as_version_11(&current, &old);
    let backups = dir.path().join("backups");

    // Opened without migrating: refused, with the way to migrate it; nothing changed.
    assert!(matches!(
        Store::open(&old),
        Err(StoreError::Older {
            found: 11,
            expected: 12
        })
    ));
    assert_eq!(Store::version_at(&old).unwrap(), 11);
    assert!(!backups.exists());

    let (store, migrated) = Store::open_migrating(&old, &backups, t(1000)).unwrap();
    let migrated = migrated.unwrap();
    assert_eq!((migrated.from, migrated.to), (11, 12));
    assert_eq!(
        migrated.backup,
        backups.join(format!("state-v11-{}.db", t(1000).unix()))
    );
    // The copy: a version 11 database with the same rows, private, in a private directory.
    assert_eq!(Store::version_at(&migrated.backup).unwrap(), 11);
    for table in TABLES_V11 {
        assert_eq!(
            rows(&migrated.backup, table),
            rows(&current, table),
            "{table}"
        );
    }
    assert!(!has_table(&migrated.backup, "migrations"));
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&migrated.backup), 0o600);
    assert_eq!(mode(&backups), 0o700);

    // Every row read back as the version 12 store reads its own.
    let reference = Store::open(&current).unwrap();
    assert_eq!(
        store.lease(&lease.id).unwrap(),
        reference.lease(&lease.id).unwrap()
    );
    for id in [&lease.id, &pending, &refused] {
        assert_eq!(store.ticket(id).unwrap(), reference.ticket(id).unwrap());
        assert_eq!(
            store.session_pubkey(id).unwrap(),
            reference.session_pubkey(id).unwrap()
        );
    }
    assert_eq!(
        store.usage(&lease.id, t(40)).unwrap(),
        reference.usage(&lease.id, t(40)).unwrap()
    );
    assert_eq!(
        store.ledger_for_lease(&lease.id).unwrap(),
        reference.ledger_for_lease(&lease.id).unwrap()
    );
    assert_eq!(
        store.notes_pending(&omega(), 10).unwrap(),
        reference.notes_pending(&omega(), 10).unwrap()
    );
    assert_eq!(
        store.authority_in_force().unwrap(),
        reference.authority_in_force().unwrap()
    );
    let token = "upstream".parse().unwrap();
    assert_eq!(store.token_version(&token).unwrap(), 1);
    assert_eq!(store.ops_rows().unwrap(), reference.ops_rows().unwrap());
    // The migration recorded in the state.
    assert_eq!(store.migrations().unwrap(), vec![migrated.clone()]);
    drop(store);

    // Opened again: at its version, nothing done, no other copy.
    let (store, again) = Store::open_migrating(&old, &backups, t(2000)).unwrap();
    assert_eq!(again, None);
    assert_eq!(std::fs::read_dir(&backups).unwrap().count(), 1);
    drop(store);
    assert_eq!(
        Store::open(&old).unwrap().migrations().unwrap(),
        vec![migrated]
    );
}

#[test]
fn a_step_that_fails_is_rolled_back_and_the_copy_kept() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.db");
    filled(&current);
    let old = dir.path().join("leases.db");
    as_version_11(&current, &old);
    let backups = dir.path().join("backups");

    let failed = Store::open_migrating_failing(&old, &backups, t(1000), 12);
    assert!(
        matches!(
            &failed,
            Err(StoreError::Migration {
                from: 11,
                to: 12,
                ..
            })
        ),
        "{:?}",
        failed.err()
    );
    // Rolled back: still version 11, without the step's table; the copy there, whole.
    assert_eq!(Store::version_at(&old).unwrap(), 11);
    assert!(!has_table(&old, "migrations"));
    let copy = backups.join(format!("state-v11-{}.db", t(1000).unix()));
    assert_eq!(Store::version_at(&copy).unwrap(), 11);
    for table in TABLES_V11 {
        assert_eq!(rows(&copy, table), rows(&old, table), "{table}");
    }

    // Tried again in the same second: a second copy beside the first, never written over.
    let (store, migrated) = Store::open_migrating(&old, &backups, t(1000)).unwrap();
    let migrated = migrated.unwrap();
    assert_eq!(
        migrated.backup,
        backups.join(format!("state-v11-{}-1.db", t(1000).unix()))
    );
    assert_eq!(Store::version_at(&copy).unwrap(), 11);
    assert_eq!(store.migrations().unwrap(), vec![migrated]);
}

#[test]
fn a_state_no_step_migrates_is_refused_and_never_written_over() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("writ.db");
    let backups = dir.path().join("backups");
    drop(Store::open(&path).unwrap());
    let set = |version: i64| {
        rusqlite::Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", version)
            .unwrap();
    };
    // Newer than this writd (no downgrade), older than the first step, or a database with
    // tables and no version: refused by both opens, nothing copied, nothing changed.
    for version in [STATE_VERSION + 1, writ_store::FIRST_MIGRATABLE - 1, 0] {
        set(version);
        assert!(
            matches!(
                Store::open(&path),
                Err(StoreError::OtherVersion { found, expected: STATE_VERSION }) if found == version
            ),
            "version {version}"
        );
        assert!(
            matches!(
                Store::open_migrating(&path, &backups, t(0)),
                Err(StoreError::OtherVersion { found, expected: STATE_VERSION }) if found == version
            ),
            "version {version}"
        );
        assert_eq!(Store::version_at(&path).unwrap(), version);
        assert!(!backups.exists(), "version {version}");
    }
    // Its version back: read again (the refusals above changed nothing).
    set(STATE_VERSION);
    let store = Store::open(&path).unwrap();
    assert_eq!(store.count(State::Pending).unwrap(), 0);
    assert_eq!(store.migrations().unwrap(), vec![]);
    drop(store);
    // A state that holds tickets of another format is refused too.
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute("UPDATE formats SET ticket_kind = 'writ-ticket/2'", [])
        .unwrap();
    assert!(matches!(
        Store::open(&path),
        Err(StoreError::OtherTicketFormat { found, expected: "writ-ticket/3" }) if found == "writ-ticket/2"
    ));
}

#[test]
fn a_new_state_is_written_whole_at_the_version_with_no_migration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("writ.db");
    let backups = dir.path().join("backups");
    let (store, migrated) = Store::open_migrating(&path, &backups, t(0)).unwrap();
    assert_eq!(migrated, None);
    assert_eq!(store.migrations().unwrap(), vec![]);
    assert!(!backups.exists());
    drop(store);
    assert_eq!(Store::version_at(&path).unwrap(), STATE_VERSION);
}

#[test]
fn a_copy_of_the_state_is_whole_private_and_never_written_over() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("writ.db");
    filled(&path);
    let copy = dir.path().join("copy.db");
    Store::copy_state(&path, &copy).unwrap();
    assert_eq!(
        std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
        0o600
    );
    for table in TABLES_V11 {
        assert_eq!(rows(&copy, table), rows(&path, table), "{table}");
    }
    assert!(matches!(
        Store::copy_state(&path, &copy),
        Err(StoreError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists
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

/// A renewal of `renewed` (its lease ended, `from`), submitted and granted as ticket `n`.
fn renew(store: &Store, renewed: &Lease, from: State, n: u64) -> Lease {
    let yaml = REQUEST.replace(
        "  title: Add OAuth login\n",
        &format!("  title: Add OAuth login\n  renews: {}\n", renewed.id),
    );
    let submission = Submission {
        id: id(n),
        now: t(0),
        session_key: fp('S'),
        amends: None,
        renews: Some(lease::Renewed {
            lease: renewed,
            renewals: 0,
            grace: fit::DEFAULT_RENEW_GRACE,
        }),
        revises: None,
        min_ttl: fit::DEFAULT_MIN_TTL,
        chain: None,
        launcher: None,
    };
    let ticket = fit::submit(
        &config(),
        &TicketRequest::from_yaml(&yaml).unwrap(),
        &submission,
    )
    .unwrap();
    store.insert_pending(&ticket, KEY, SOURCE, t(0)).unwrap();
    let record = store.ticket(&ticket.id).unwrap().unwrap();
    let mut ended = renewed.clone();
    ended.state = from;
    let new = lease::activate_renewal(
        &config(),
        &record,
        ticket,
        approval(),
        n,
        lease::Renewed {
            lease: &ended,
            renewals: 0,
            grace: fit::DEFAULT_RENEW_GRACE,
        },
        t(20),
    )
    .unwrap();
    store
        .activate_renewal(&new, CERT, &renewed.id, from, t(20))
        .unwrap();
    new
}

#[test]
fn a_renewal_ends_its_lease_and_the_chain_is_followed_back() {
    let store = Store::open_in_memory().unwrap();
    let first = active_lease(&store, 1);
    let second = renew(&store, &first, State::Active, 2);
    store
        .transition(&second.id, State::Active, State::Expired, t(30))
        .unwrap();
    let third = renew(&store, &second, State::Expired, 3);
    assert_eq!(
        store.lease(&first.id).unwrap().unwrap().state,
        State::Renewed
    );
    assert_eq!(
        store.lease(&second.id).unwrap().unwrap().state,
        State::Renewed
    );
    assert_eq!(
        store.lease(&third.id).unwrap().unwrap().state,
        State::Active
    );
    assert_eq!(
        store.predecessors(&third.id).unwrap(),
        [second.id.clone(), first.id.clone()]
    );
    assert_eq!(
        store.predecessors(&second.id).unwrap(),
        vec![first.id.clone()]
    );
    assert!(store.predecessors(&first.id).unwrap().is_empty());
    // A lease is recorded as the renewal of the lease it names only (a renewed lease ending
    // again is refused by its state: the next test).
    let again = store.activate_renewal(&third, CERT, &first.id, State::Active, t(40));
    assert!(
        matches!(again, Err(StoreError::Corrupt { .. })),
        "{again:?}"
    );
    assert_eq!(
        store.lease(&third.id).unwrap().unwrap().state,
        State::Active
    );
}

#[test]
fn a_renewal_that_cannot_end_its_lease_grants_nothing() {
    let store = Store::open_in_memory().unwrap();
    let first = active_lease(&store, 1);
    store
        .transition(&first.id, State::Active, State::Revoked, t(15))
        .unwrap();
    // Built as if the lease were still active: the store finds it revoked and records neither.
    let yaml = REQUEST.replace(
        "  title: Add OAuth login\n",
        &format!("  title: Add OAuth login\n  renews: {}\n", first.id),
    );
    let mut active = first.clone();
    active.state = State::Active;
    let submission = Submission {
        id: id(2),
        now: t(0),
        session_key: fp('S'),
        amends: None,
        renews: Some(lease::Renewed {
            lease: &active,
            renewals: 0,
            grace: fit::DEFAULT_RENEW_GRACE,
        }),
        revises: None,
        min_ttl: fit::DEFAULT_MIN_TTL,
        chain: None,
        launcher: None,
    };
    let ticket = fit::submit(
        &config(),
        &TicketRequest::from_yaml(&yaml).unwrap(),
        &submission,
    )
    .unwrap();
    store.insert_pending(&ticket, KEY, SOURCE, t(0)).unwrap();
    let record = store.ticket(&ticket.id).unwrap().unwrap();
    let new = lease::activate_renewal(
        &config(),
        &record,
        ticket,
        approval(),
        2,
        lease::Renewed {
            lease: &active,
            renewals: 0,
            grace: fit::DEFAULT_RENEW_GRACE,
        },
        t(20),
    )
    .unwrap();
    assert!(matches!(
        store.activate_renewal(&new, CERT, &first.id, State::Active, t(20)),
        Err(StoreError::Conflict {
            expected: State::Active,
            ..
        })
    ));
    assert_eq!(
        store.ticket(&new.id).unwrap().unwrap().state,
        State::Pending,
        "not granted"
    );
    assert_eq!(
        store.lease(&first.id).unwrap().unwrap().state,
        State::Revoked
    );
}

#[test]
fn the_source_is_kept_and_active_leases_are_found_by_it() {
    let store = Store::open_in_memory().unwrap();
    let here: Source = "192.0.2.7".parse().unwrap();
    let there: Source = "2001:db8::/64".parse().unwrap();
    let submit = |n: u64, source: Source| {
        let ticket = ticket(n, REQUEST, None);
        store.insert_pending(&ticket, KEY, source, t(0)).unwrap();
        let record = store.ticket(&ticket.id).unwrap().unwrap();
        assert_eq!(record.source, Some(source));
        let lease = lease::activate(&config(), &record, ticket, approval(), n, t(10)).unwrap();
        store.activate(&lease, CERT, t(10)).unwrap();
        lease
    };
    let a = submit(1, here);
    let b = submit(2, here);
    let c = submit(3, there);
    let ids = |source| -> Vec<TicketId> {
        store
            .active_from(source)
            .unwrap()
            .into_iter()
            .map(|l| l.id)
            .collect()
    };
    assert_eq!(ids(here), [a.id.clone(), b.id.clone()]);
    assert_eq!(ids(there), vec![c.id]);
    assert!(ids(Source::Local).is_empty());
    // An ended lease isn't active any more.
    store
        .transition(&b.id, State::Active, State::Expired, t(30))
        .unwrap();
    assert_eq!(ids(here), [a.id]);
}

#[test]
fn closing_ends_an_active_lease_and_keeps_an_ended_one_s_end() {
    let store = Store::open_in_memory().unwrap();
    let a = active_lease(&store, 1);
    store
        .close(&a.id, State::Active, "done: login works", t(100))
        .unwrap();
    assert_eq!(store.lease(&a.id).unwrap().unwrap().state, State::Closed);
    assert_eq!(
        store.summary(&a.id).unwrap().as_deref(),
        Some("done: login works")
    );
    assert_eq!(store.times(&a.id).unwrap().updated_at, t(100));
    // Expired at 50, closed at 200: its state and end stay.
    let b = active_lease(&store, 2);
    store
        .transition(&b.id, State::Active, State::Expired, t(50))
        .unwrap();
    store
        .close(&b.id, State::Expired, "ran out", t(200))
        .unwrap();
    assert_eq!(store.lease(&b.id).unwrap().unwrap().state, State::Expired);
    assert_eq!(
        store.times(&b.id).unwrap(),
        writ_store::LeaseTimes {
            created_at: t(0),
            updated_at: t(50)
        }
    );
    // Compared and set on the state it is in; a pending ticket is no lease.
    assert!(matches!(
        store.close(&a.id, State::Active, "again", t(300)),
        Err(StoreError::Conflict { .. })
    ));
    let pending = ticket(3, REQUEST, None);
    store.insert_pending(&pending, KEY, SOURCE, t(0)).unwrap();
    assert!(matches!(
        store.close(&pending.id, State::Pending, "x", t(300)),
        Err(StoreError::Lifecycle(_))
    ));
}

/// The review after M7.6 (A-6): each credential's count of token changes only grows, one at a
/// time from the count in force, and outlives everything else of the id: a reopened store
/// keeps it, and nothing deletes it.
#[test]
fn a_token_s_change_count_only_grows_and_survives_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("writ.db");
    let id: KeyId = "Token-01".parse().unwrap();
    let store = Store::open(&path).unwrap();
    assert_eq!(store.token_version(&id).unwrap(), 0, "never given one");
    assert_eq!(store.bump_token_version(&id, 0).unwrap(), 1);
    // From another count than the one in force, on both sides: refused, nothing counted.
    for stale in [0, 2] {
        assert!(
            matches!(
                store.bump_token_version(&id, stale),
                Err(StoreError::TokenVersion { expected, found: 1, .. }) if expected == stale
            ),
            "from {stale}"
        );
    }
    assert_eq!(store.token_version(&id).unwrap(), 1);
    assert_eq!(store.bump_token_version(&id, 1).unwrap(), 2);
    // Another spelling of the same file's name is the same count; another id its own.
    let folded: KeyId = "token-01".parse().unwrap();
    assert_eq!(store.token_version(&folded).unwrap(), 2);
    let other: KeyId = "token-02".parse().unwrap();
    assert_eq!(store.token_version(&other).unwrap(), 0);
    drop(store);
    let store = Store::open(&path).unwrap();
    assert_eq!(store.token_version(&id).unwrap(), 2, "kept across a reopen");
    drop(store);
    // A count of 0 (which would read as "never given one") can't be written, even by hand.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let refused = conn.execute("UPDATE token_versions SET version = 0", []);
    assert!(
        matches!(refused, Err(rusqlite::Error::SqliteFailure(..))),
        "the schema refuses it: {refused:?}"
    );
}
