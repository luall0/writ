//! Property test of `Service::sign`'s three phases (proptest): whatever the interleaving of
//! concurrent requests' phases, with the clock moving and a revocation coming at any point,
//! a lease never gets more signatures than `max_signatures`, never more in a minute than
//! `max_ops_per_minute`, and none after its revocation; a signature is discarded only for a
//! reason (a revocation meanwhile); every signature handed out has its `sign` line and its
//! ledger entry.
//!
//! Deterministic: each request runs on its own thread, but the test drives it a phase at a
//! time. A request is started and the test waits until it is either answered (denied in its
//! first phase) or held at the signer's gate; a held one is released by the test and waited
//! for. Nothing runs on its own between two steps.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use proptest::prelude::*;
use writ_approval::testing::{START, TestService, TestServiceBuilder};
use writ_approval::{SignObject, SignedCommit, Signing};
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::lease::State;
use writ_core::names::TicketId;
use writ_core::policy::{CertIdentity, Denial, DenyCode};
use writ_core::ticket::Ticket;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{Certificate, HashAlg};
use writ_git::Commit;
use writ_platform::testing::FakeClock;
use writ_proto::Decision;
use writ_store::Store;

const POLICY: &str = include_str!("../../writ-core/tests/fixtures/policy.yaml");

/// Every failure proptest ever found, replayed first by every run.
const REGRESSIONS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/sign_phases.proptest-regressions"
);

/// The seed of the fixed pass: every run of `cargo test` checks the same inputs.
const FIXED_SEED: u64 = 0x5752_4954_0035_0001;

/// How long the test waits for a request to reach the gate or be answered: a bound on a
/// hang, never a pause.
const PATIENCE: Duration = Duration::from_secs(60);

/// One step of a schedule.
#[derive(Debug, Clone)]
enum Step {
    /// A new request: its first phase runs, then it is answered or held at the gate.
    Start,
    /// The held request at this position (modulo how many are held) signs, and its last
    /// phase runs.
    Release(usize),
    /// The clock moves on, in seconds.
    Advance(u64),
    /// The approver revokes the lease (once; later ones do nothing; a lease already used up
    /// stays so).
    Revoke,
}

fn arb_step() -> impl Strategy<Value = Step> {
    prop_oneof![
        4 => Just(Step::Start),
        4 => any::<usize>().prop_map(Step::Release),
        2 => (0u64..=90).prop_map(Step::Advance),
        1 => Just(Step::Revoke),
    ]
}

/// What the test sees of the service.
enum Event {
    /// A signature reached the gate (its call number).
    Entered(u64),
    /// A request was answered.
    Done(usize, Result<SignedCommit, Denial>),
}

/// One request, as the test drove it.
struct Request {
    /// When its first phase ran (the slot's time), in Unix seconds.
    started: u64,
    /// Whether the lease was revoked when its last phase ran (or when it was answered).
    revoked_before_answer: bool,
    result: Option<Result<SignedCommit, Denial>>,
}

/// A commit for the lease's repo (`homelab-scripts`: no trailer needed; its paths unknown,
/// which `paths_check: warn` lets through with a warning).
fn commit(n: usize) -> Commit {
    Commit::parse(
        format!(
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A <user+agent@example.org> {n} +0000\n\
             committer A <user+agent@example.org> {n} +0000\n\nchange {n}\n"
        )
        .into_bytes(),
    )
    .unwrap()
}

/// An active lease for `yaml`: its id and the certificate's identity.
fn lease(test: &TestService, yaml: &str) -> (TicketId, CertIdentity) {
    let key = generate(KeyKind::Ed25519).unwrap();
    let submitted = test
        .service
        .submit(key.public_key(), yaml.as_bytes(), &CallerFacts::default())
        .unwrap();
    let ticket = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
    test.service
        .approve(&ticket.id, &test.approval(&ticket), &CallerFacts::default())
        .unwrap();
    let decision = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(test.service.wait(&ticket.id, key.public_key()))
        .unwrap();
    let Decision::Active { certificate, .. } = decision else {
        panic!("expected an active lease, got {decision:?}");
    };
    let cert = Certificate::from_openssh(&certificate).unwrap();
    let identity = CertIdentity {
        key_id: cert.key_id().to_owned(),
        serial: cert.serial(),
        session_key: cert
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
            .parse()
            .unwrap(),
    };
    (ticket.id, identity)
}

/// The next event, or a failure if none comes in time.
fn next(events: &Receiver<Event>) -> Event {
    events
        .recv_timeout(PATIENCE)
        .expect("a request neither reached the gate nor was answered")
}

/// Runs `schedule` against a lease with these limits, and returns what each request got.
fn run(max_signatures: u32, rate: u32, fetch: bool, schedule: &[Step]) -> Outcome {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock::at_unix(START));
    let test = TestServiceBuilder::new(POLICY)
        .clock(clock.clone())
        .build(dir.path());
    let operations = if fetch {
        "[fetch, commit_sign]"
    } else {
        "[commit_sign]"
    };
    let yaml = format!(
        "template: feature-branch\nscope:\n  repos: [homelab-scripts]\n  operations: {operations}\n  \
         branches: [\"agent/x\"]\nticket:\n  title: T\n  task: T\n  expected_paths: [\"src/**\"]\n\
         limits:\n  max_signatures: {max_signatures}\n  max_ops_per_minute: {rate}\n"
    );
    let (lease_id, cert) = lease(&test, &yaml);

    let (tx, events): (Sender<Event>, Receiver<Event>) = channel();
    let entered = Mutex::new(tx.clone());
    test.signer.on_enter(Box::new(move |call| {
        entered.lock().unwrap().send(Event::Entered(call)).unwrap();
    }));
    let mut requests: Vec<Request> = Vec::new();
    let mut revoked = false;
    let closed = test.signer.close();
    std::thread::scope(|scope| {
        // Held requests: (call number at the gate, request index).
        let mut held: Vec<(u64, usize)> = Vec::new();
        let answer = |requests: &mut Vec<Request>, revoked: bool, index: usize, result| {
            let request: &mut Request = &mut requests[index];
            request.revoked_before_answer = revoked;
            request.result = Some(result);
        };
        for step in schedule {
            match step {
                Step::Start => {
                    let index = requests.len();
                    requests.push(Request {
                        started: test.service.now_unix(),
                        revoked_before_answer: false,
                        result: None,
                    });
                    let (tx, test, cert) = (tx.clone(), &test, &cert);
                    scope.spawn(move || {
                        let signing = Signing {
                            cert: cert.clone(),
                            caller: CallerFacts::default(),
                            repo: "homelab-scripts".parse().unwrap(),
                            format: writ_crypto::algorithm::SignatureFormat::Ssh,
                            object: SignObject::Commit {
                                commit: commit(index),
                                touched_paths: None,
                            },
                        };
                        tx.send(Event::Done(index, test.service.sign(&signing)))
                            .unwrap();
                    });
                    match next(&events) {
                        Event::Entered(call) => held.push((call, index)),
                        Event::Done(i, result) => answer(&mut requests, revoked, i, result),
                    }
                }
                Step::Release(at) if !held.is_empty() => {
                    let (call, _) = held.remove(at % held.len());
                    test.signer.release(call);
                    match next(&events) {
                        Event::Done(i, result) => answer(&mut requests, revoked, i, result),
                        Event::Entered(_) => panic!("a released request reached the gate again"),
                    }
                }
                Step::Release(_) => {}
                Step::Advance(seconds) => clock.advance(*seconds),
                Step::Revoke if !revoked => {
                    let revocation = test.revocation(&lease_id);
                    match test
                        .service
                        .revoke(&lease_id, &revocation, &CallerFacts::default())
                    {
                        Ok(_) => revoked = true,
                        // Only a lease that already ended (used up) can't be revoked.
                        Err(e) => assert_eq!(
                            test.service.show(&lease_id).unwrap().state,
                            State::Exhausted,
                            "{e}"
                        ),
                    }
                }
                Step::Revoke => {}
            }
        }
        // The rest sign, in the order they came.
        drop(closed);
        for _ in 0..held.len() {
            match next(&events) {
                Event::Done(i, result) => answer(&mut requests, revoked, i, result),
                Event::Entered(_) => panic!("a request reached an open gate"),
            }
        }
    });
    let store = Store::open(&dir.path().join("leases.db")).unwrap();
    Outcome {
        requests,
        ledger: store.ledger_for_lease(&lease_id).unwrap().len(),
        allowed_lines: test.events("sign", "allowed").len(),
        state: test.service.show(&lease_id).unwrap().state,
        revoked,
    }
}

struct Outcome {
    requests: Vec<Request>,
    /// Whether the approver's revocation went through.
    revoked: bool,
    ledger: usize,
    allowed_lines: usize,
    state: State,
}

/// The seed: [`FIXED_SEED`], or `WRIT_PROPTEST_SEED` (`random` for a new one, or a number to
/// replay a run), printed so any failing run can be replayed.
fn seed() -> u64 {
    static SEED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SEED.get_or_init(|| {
        let seed = match std::env::var("WRIT_PROPTEST_SEED").ok().as_deref() {
            None | Some("") => FIXED_SEED,
            Some("random") => {
                use std::hash::{BuildHasher, Hasher};
                let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
                hasher.write_u128(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos(),
                );
                hasher.finish()
            }
            Some(number) => number
                .parse()
                .expect("WRIT_PROPTEST_SEED is `random` or a number"),
        };
        eprintln!("proptest seed: {seed} (replay with WRIT_PROPTEST_SEED={seed})");
        seed
    })
}

fn proptest_config() -> ProptestConfig {
    ProptestConfig {
        cases: 256,
        rng_algorithm: proptest::test_runner::RngAlgorithm::ChaCha,
        rng_seed: proptest::test_runner::RngSeed::Fixed(seed()),
        failure_persistence: Some(Box::new(
            proptest::test_runner::FileFailurePersistence::Direct(REGRESSIONS),
        )),
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn count_and_rate_hold_whatever_the_phases_interleaving(
        max_signatures in 1u32..=4,
        rate in 1u32..=3,
        fetch in any::<bool>(),
        schedule in prop::collection::vec(arb_step(), 1..32),
    ) {
        let outcome = run(max_signatures, rate, fetch, &schedule);
        let signed: Vec<&Request> = outcome
            .requests
            .iter()
            .filter(|r| matches!(r.result, Some(Ok(_))))
            .collect();

        // Count: never more than max_signatures.
        prop_assert!(signed.len() <= max_signatures as usize, "{} signed", signed.len());
        // Rate: never more than `rate` slots in any minute (the store's window: (t-60, t]).
        for request in &signed {
            let in_window = signed
                .iter()
                .filter(|r| r.started > request.started.saturating_sub(60) && r.started <= request.started)
                .count();
            prop_assert!(in_window <= rate as usize, "{in_window} in the minute up to {}", request.started);
        }
        // Revocation: nothing handed out once the lease was revoked.
        prop_assert!(signed.iter().all(|r| !r.revoked_before_answer));
        // And nothing discarded without a reason: a signature refused in its last phase was
        // revoked meanwhile (the schedule never reaches the lease's expiry), never refused
        // because its own slot made the lease look used up.
        for request in &outcome.requests {
            if let Some(Err(denial)) = &request.result
                && denial.reason.contains("while the commit was being signed")
            {
                prop_assert!(request.revoked_before_answer, "discarded: {denial}");
            }
        }
        // Every signature handed out is logged and in the ledger, and nothing else is.
        prop_assert_eq!(outcome.ledger, signed.len());
        prop_assert_eq!(outcome.allowed_lines, signed.len());
        // Every request was answered, each denial with a code of these.
        for request in &outcome.requests {
            match &request.result {
                Some(Ok(_)) => {}
                Some(Err(denial)) => prop_assert!(
                    matches!(
                        denial.code,
                        DenyCode::Limit | DenyCode::Rate | DenyCode::Exhausted | DenyCode::NotActive
                    ),
                    "unexpected denial: {denial}"
                ),
                None => prop_assert!(false, "a request was never answered"),
            }
        }
        // The lease ended as it should: revoked, used up (no `fetch` and every slot taken),
        // or still active.
        let used_up = !fetch && slots_taken(&outcome) == max_signatures as usize;
        let expected = if outcome.revoked {
            State::Revoked
        } else if used_up {
            State::Exhausted
        } else {
            State::Active
        };
        prop_assert_eq!(outcome.state, expected);
    }
}

/// Slots taken: every request that got past its first phase (signed, or refused in its last
/// one, which says "while the commit was being signed").
fn slots_taken(outcome: &Outcome) -> usize {
    outcome
        .requests
        .iter()
        .filter(|r| match &r.result {
            Some(Ok(_)) => true,
            Some(Err(denial)) => denial.reason.contains("while the commit was being signed"),
            None => false,
        })
        .count()
}
