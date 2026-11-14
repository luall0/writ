//! The approver's watch (M7.8): the tickets waiting for a signature, answered as soon as they
//! aren't the ones the caller's cursor names, or at [`WATCH_LIMIT`] with the same ones. Run
//! under tokio's paused time: every wait is the runtime's virtual clock, never the wall's.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::time::Duration;

use writ_approval::WATCH_LIMIT;
use writ_approval::testing::{START, TestService, TestServiceBuilder};
use writ_core::authority::TextDigest;
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::lease::State;
use writ_core::ticket::Ticket;
use writ_crypto::keys::{KeyKind, generate};
use writ_platform::testing::FakeClock;
use writ_proto::Watched;

const POLICY: &str = include_str!("../../writ-core/tests/fixtures/policy.yaml");

fn feature(branch: &str, ttl: &str) -> String {
    format!(
        r#"
limits:
  ttl: {ttl}
repos:
  omega-code:
    template: feature-branch
    operations: [fetch, commit_sign, push]
    branches: ["{branch}"]
ticket:
  title: Add OAuth login
  task: Add GitHub OAuth login behind a feature flag
"#
    )
}

struct Harness {
    _dir: tempfile::TempDir,
    test: TestService,
    clock: Arc<FakeClock>,
}

impl std::ops::Deref for Harness {
    type Target = TestService;
    fn deref(&self) -> &TestService {
        &self.test
    }
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(FakeClock::at_unix(START));
        let test = TestServiceBuilder::new(POLICY)
            .clock(clock.clone())
            .build(dir.path());
        Self {
            _dir: dir,
            test,
            clock,
        }
    }

    fn submit(&self, branch: &str) -> Ticket {
        let key = generate(KeyKind::Ed25519).unwrap();
        let caller = CallerFacts {
            source_addr: Some("10.0.0.1".parse().unwrap()),
            process_chain: None,
        };
        let submitted = self
            .service
            .submit(key.public_key(), feature(branch, "2h").as_bytes(), &caller)
            .unwrap();
        Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap()
    }
}

fn paused() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap()
}

fn ids(watched: &Watched) -> Vec<String> {
    watched.tickets.iter().map(|t| t.id.to_string()).collect()
}

#[test]
fn without_a_cursor_the_waiting_tickets_come_at_once_in_order() {
    let h = Harness::new();
    paused().block_on(async {
        let empty = h.service.watch(None).await.unwrap();
        assert!(empty.tickets.is_empty());
        assert_eq!(empty.cursor, TextDigest::of(""));
        let (a, b) = (h.submit("agent/a-*"), h.submit("agent/b-*"));
        let started = tokio::time::Instant::now();
        let both = h.service.watch(None).await.unwrap();
        assert_eq!(started.elapsed(), Duration::ZERO);
        // In id order (two ids of one millisecond order by their random part).
        let mut expected = [a.id.to_string(), b.id.to_string()];
        expected.sort();
        assert_eq!(ids(&both), expected);
        assert!(both.tickets.iter().all(|t| t.state == State::Pending));
        assert_eq!(both.cursor, TextDigest::of(&expected.join("\n")));
        // A cursor naming other tickets (a stale one, one of another daemon): at once too.
        let other = TextDigest::of("wrt_other");
        let again = h.service.watch(Some(&other)).await.unwrap();
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(again, both);
    });
}

#[test]
fn with_the_current_cursor_it_waits_for_the_limit_and_no_longer() {
    let h = Harness::new();
    let ticket = h.submit("agent/a-*");
    paused().block_on(async {
        let now = h.service.watch(None).await.unwrap();
        let started = tokio::time::Instant::now();
        // One second short of the limit: still waiting.
        let early = tokio::time::timeout(
            WATCH_LIMIT - Duration::from_secs(1),
            h.service.watch(Some(&now.cursor)),
        )
        .await;
        // any error: a timeout's only error is that it elapsed.
        assert!(early.is_err(), "answered before the limit: {early:?}");
        // At the limit: the same tickets, the same cursor.
        let started_again = tokio::time::Instant::now();
        let same = h.service.watch(Some(&now.cursor)).await.unwrap();
        assert_eq!(started_again.elapsed(), WATCH_LIMIT);
        assert_eq!(same, now);
        assert_eq!(ids(&same), [ticket.id.to_string()]);
        assert!(started.elapsed() < WATCH_LIMIT * 2);
    });
}

#[test]
fn a_submission_while_it_waits_answers_at_once_with_the_new_ticket() {
    let h = Harness::new();
    let first = h.submit("agent/a-*");
    paused().block_on(async {
        let now = h.service.watch(None).await.unwrap();
        let started = tokio::time::Instant::now();
        let (watched, second) = tokio::join!(h.service.watch(Some(&now.cursor)), async {
            // poll: nothing; paused virtual time, which the runtime moves only once the watch
            // is parked on its change or its recheck: the submission comes at exactly 45 s.
            tokio::time::sleep(Duration::from_secs(45)).await;
            h.submit("agent/b-*")
        });
        let watched = watched.unwrap();
        // Woken by the submission, not by the limit.
        assert_eq!(started.elapsed(), Duration::from_secs(45));
        let mut expected = [first.id.to_string(), second.id.to_string()];
        expected.sort();
        assert_eq!(ids(&watched), expected);
        assert_ne!(watched.cursor, now.cursor);
    });
}

#[test]
fn a_ticket_leaving_the_queue_answers_without_it() {
    let h = Harness::new();
    let (signed, refused, withdrawn, kept) = (
        h.submit("agent/a-*"),
        h.submit("agent/b-*"),
        h.submit("agent/c-*"),
        h.submit("agent/d-*"),
    );
    paused().block_on(async {
        let mut now = h.service.watch(None).await.unwrap();
        assert_eq!(now.tickets.len(), 4);
        let leave: [&dyn Fn(); 3] = [
            &|| {
                let ack = h
                    .service
                    .approve(&signed.id, &h.approval(&signed), &CallerFacts::default())
                    .unwrap();
                assert_eq!(ack.state, State::Active);
            },
            &|| {
                h.service
                    .refuse(
                        &refused.id,
                        &h.refusal(&refused.id, "too broad"),
                        &CallerFacts::default(),
                    )
                    .unwrap();
            },
            &|| {
                h.service
                    .revoke(
                        &withdrawn.id,
                        &h.revocation(&withdrawn.id),
                        &CallerFacts::default(),
                    )
                    .unwrap();
            },
        ];
        for (gone, act) in [&signed, &refused, &withdrawn].into_iter().zip(leave) {
            let started = tokio::time::Instant::now();
            let (watched, ()) = tokio::join!(h.service.watch(Some(&now.cursor)), async {
                // poll: nothing; paused virtual time, moved only once the watch is parked.
                tokio::time::sleep(Duration::from_secs(10)).await;
                act();
            });
            let watched = watched.unwrap();
            assert_eq!(started.elapsed(), Duration::from_secs(10));
            assert!(!ids(&watched).contains(&gone.id.to_string()), "{watched:?}");
            assert_ne!(watched.cursor, now.cursor);
            now = watched;
        }
        assert_eq!(ids(&now), [kept.id.to_string()]);
    });
}

#[test]
fn a_ticket_that_expires_while_it_waits_is_swept_out_of_the_reply() {
    let h = Harness::new();
    let ticket = h.submit("agent/a-*");
    paused().block_on(async {
        let now = h.service.watch(None).await.unwrap();
        assert_eq!(ids(&now), [ticket.id.to_string()]);
        // Past the ticket's expiry on the service's clock; the store still lists it until a
        // sweep, which the watch runs at its recheck.
        h.clock.advance(3 * 3600);
        let started = tokio::time::Instant::now();
        let watched = h.service.watch(Some(&now.cursor)).await.unwrap();
        assert!(started.elapsed() < WATCH_LIMIT, "{:?}", started.elapsed());
        assert!(watched.tickets.is_empty(), "{watched:?}");
        assert_eq!(watched.cursor, TextDigest::of(""));
    });
    assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Expired);
}
