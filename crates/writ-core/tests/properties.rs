//! Property tests of the policy (proptest):
//! - a narrowed ticket never grants anything the submitted one did not;
//! - no ticket outside every template is ever accepted: whatever a submitted ticket allows,
//!   its template's largest ticket allows too;
//! - a certificate matching two leases is denied;
//! - counters and the rate never exceed the lease's limits.
//!
//! "Grants" is checked semantically: random sign, push and fetch requests, with random usage,
//! time and caller facts, through the real decisions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::*;
use proptest::prelude::*;
use proptest::sample::{select, subsequence};
use proptest::strategy::ValueTree;
use writ_core::caller::{CallerConstraint, CallerFacts, ProcessMatch, ProcessRef};
use writ_core::config::{PolicyConfig, PushMode};
use writ_core::fit;
use writ_core::lease::{self, Lease, State, TicketRecord, Usage};
use writ_core::narrow;
use writ_core::policy::{
    self, CertIdentity, Context, DenyCode, FetchRequest, LedgerRef, ObjectKind, PushRequest,
    PushedCommit, RefUpdate, SignRequest,
};
use writ_core::ticket::Operation;
use writ_core::ticket::{
    Limits, OnViolation, RequestLimits, RequestScope, RequestText, Ticket, TicketRequest,
};
use writ_core::units::{ByteSize, Duration, Timestamp};

const REPOS: [&str; 4] = ["omega-code", "homelab-scripts", "dotfiles", "nope"];
const OPS: [Operation; 3] = [Operation::Fetch, Operation::CommitSign, Operation::Push];
const BRANCHES: [&str; 8] = [
    "agent/*",
    "agent/fix-*",
    "agent/oauth-*",
    "agent/oauth-login",
    "agent/fix-1",
    "main",
    "*",
    "feature/*",
];
const EMAILS: [&str; 3] = [AGENT_EMAIL, "user+fix@example.org", "user@example.org"];
const PATHS: [&str; 3] = ["src/auth/**", "tests/auth/**", "src/**"];
const TOUCHED: [&str; 4] = [
    "src/auth/a.rs",
    "tests/auth/b.rs",
    "src/billing/x.rs",
    "README.md",
];
const REFS: [&str; 7] = [
    "refs/heads/agent/oauth-login",
    "refs/heads/agent/fix-1",
    "refs/heads/agent/x",
    "refs/heads/main",
    "refs/heads/feature/x",
    "refs/tags/v1",
    "refs/notes/writ",
];
const TTLS: [u64; 6] = [600, 1800, 3600, 7200, 14_400, 30_000];
const OMEGA: &str = "/Applications/Omega Code.app/Contents/MacOS/omega";

/// The test policy with a wider feature-branch (force push allowed, two emails, paths
/// denied), so that only the narrowing check can refuse those widenings.
fn config() -> PolicyConfig {
    let policy = POLICY.replacen(
        "    committer_emails: [\"user+agent@example.org\"]\n    signing_key: agent-ed25519-01\n    max_ttl: 4h",
        "    force_push: true\n    committer_emails: [\"user+agent@example.org\", \"user+fix@example.org\"]\n    signing_key: agent-ed25519-01\n    max_ttl: 4h",
        1,
    )
    .replacen("    paths_check: warn\n", "    paths_check: deny\n", 1);
    let config = PolicyConfig::from_yaml(&policy).unwrap();
    assert!(
        config
            .template(&"feature-branch".parse().unwrap())
            .unwrap()
            .force_push
    );
    config
}

/// Submits with the property policy.
fn submitted(yaml: &str) -> Ticket {
    fit::submit(&config(), &common::request(yaml), &submission(1)).unwrap()
}

fn parse_all<T: std::str::FromStr>(items: Vec<&str>) -> Vec<T>
where
    T::Err: std::fmt::Debug,
{
    items.into_iter().map(|s| s.parse().unwrap()).collect()
}

fn omega_constraint() -> CallerConstraint {
    CallerConstraint {
        descends_from: ProcessMatch {
            executable: OMEGA.to_owned(),
            pid: 4242,
            generation: 118,
            code_identity: None,
        },
    }
}

/// Picks from `inside` most of the time, from `everything` otherwise.
fn mostly<T: Clone + std::fmt::Debug + 'static>(
    inside: Vec<T>,
    everything: Vec<T>,
) -> impl Strategy<Value = Vec<T>> {
    let inside = if inside.is_empty() {
        everything.clone()
    } else {
        inside
    };
    let max_in = inside.len().min(2);
    let max_all = everything.len().min(3);
    prop_oneof![
        6 => subsequence(inside, 0..=max_in),
        1 => subsequence(everything, 0..=max_all),
    ]
}

fn up_to(cap: u64, beyond: u64) -> impl Strategy<Value = Option<u64>> {
    prop_oneof![
        2 => Just(None),
        6 => (0..=cap).prop_map(Some),
        1 => (0..=beyond).prop_map(Some),
    ]
}

/// A ticket request, biased toward one template's values so that many fit.
fn arb_request() -> impl Strategy<Value = TicketRequest> {
    let config = config();
    let names: Vec<String> = config.templates().keys().map(|n| n.to_string()).collect();
    (select(names), any::<bool>()).prop_flat_map(move |(name, named)| {
        let template = config.template(&name.parse().unwrap()).unwrap().clone();
        let branches_inside: Vec<&str> = BRANCHES
            .iter()
            .copied()
            .filter(|b| template.branches.iter().any(|t| t.covers(&b.parse().unwrap())))
            .collect();
        let repos_inside: Vec<String> = template.repos.iter().map(|r| r.to_string()).collect();
        let emails_inside: Vec<String> =
            template.committer_emails.iter().map(|e| e.to_string()).collect();
        let scope = (
            mostly(repos_inside, REPOS.iter().map(|r| r.to_string()).collect()),
            mostly(template.operations.iter().copied().collect(), OPS.to_vec()),
            mostly(branches_inside, BRANCHES.to_vec()),
            prop::bool::weighted(0.1),
            mostly(emails_inside, EMAILS.iter().map(|e| e.to_string()).collect()),
        );
        let ttls: Vec<u64> = TTLS.iter().copied().filter(|t| *t <= template.max_ttl.seconds()).collect();
        let limits = (
            prop_oneof![2 => Just(None), 6 => select(ttls).prop_map(Some), 1 => select(TTLS.to_vec()).prop_map(Some)],
            up_to(template.max_signatures.into(), 60),
            up_to(template.max_pushes.into(), 40),
            up_to(template.max_ops_per_minute.into(), 25),
            up_to(template.max_push_size.bytes(), 60_000_000),
        );
        (
            Just(named.then(|| name.clone())),
            scope,
            limits,
            subsequence(PATHS.to_vec(), 0..=2),
            prop::bool::weighted(0.25),
            any::<bool>(),
        )
    })
    .prop_map(|(template, scope, limits, paths, bound, strict)| TicketRequest {
        template: template.map(|t| t.parse().unwrap()),
        origin_hint: None,
        caller: bound.then(omega_constraint),
        scope: RequestScope {
            repos: scope.0.iter().map(|r| r.parse().unwrap()).collect(),
            operations: if scope.1.is_empty() { vec![Operation::Fetch] } else { scope.1 },
            branches: parse_all(scope.2),
            force_push: scope.3,
            committer_emails: scope.4.iter().map(|e| e.parse().unwrap()).collect(),
        },
        ticket: RequestText {
            title: "A task".to_owned(),
            task: "Do it".to_owned(),
            plan: vec!["Step".to_owned()],
            expected_paths: parse_all(paths),
            amends: None,
            revises: None,
        },
        limits: RequestLimits {
            ttl: limits.0.map(Duration::from_seconds),
            max_signatures: limits.1.map(|v| v as u32),
            max_pushes: limits.2.map(|v| v as u32),
            max_ops_per_minute: limits.3.map(|v| v as u32),
            max_push_size: limits.4.map(ByteSize::from_bytes),
        },
        on_violation: if strict { OnViolation::RevokeLease } else { OnViolation::DenyAndNotify },
    })
}

/// A request that fits a template, completed into a ticket.
fn arb_ticket() -> impl Strategy<Value = Ticket> {
    arb_request().prop_filter_map("fits no template", |request| {
        fit::submit(&config(), &request, &submission(1)).ok()
    })
}

/// A ticket the approver might sign instead: one or two parts changed, with values near the
/// template's range. Many are wider than submitted; the narrowing check must refuse those.
fn arb_signed(submitted: Ticket) -> impl Strategy<Value = Ticket> {
    let config = config();
    let template = config.template(&submitted.template).unwrap().clone();
    let repos: Vec<String> = template.repos.iter().map(|r| r.to_string()).collect();
    let emails: Vec<String> = template
        .committer_emails
        .iter()
        .map(|e| e.to_string())
        .collect();
    let values = (
        mostly(repos, REPOS.iter().map(|r| r.to_string()).collect()),
        subsequence(OPS.to_vec(), 0..=3),
        subsequence(BRANCHES.to_vec(), 0..=2),
        mostly(emails, EMAILS.iter().map(|e| e.to_string()).collect()),
        subsequence(PATHS.to_vec(), 0..=2),
        -3600i64..3600,
        (
            0..=template.max_signatures + 1,
            0..=template.max_pushes + 1,
            1..=template.max_ops_per_minute + 1,
        ),
        0..=template.max_push_size.bytes() + 1,
    );
    (subsequence((0usize..13).collect::<Vec<_>>(), 1..=2), values).prop_map(move |(fields, v)| {
        let mut t = submitted.clone();
        for field in fields {
            match field {
                0 => t.scope.repos = v.0.iter().map(|r| r.parse().unwrap()).collect(),
                1 => t.scope.operations = v.1.iter().copied().collect(),
                2 => t.scope.branches = parse_all(v.2.clone()).into_iter().collect(),
                3 => t.scope.force_push = !t.scope.force_push,
                4 => t.scope.committer_emails = v.3.iter().map(|e| e.parse().unwrap()).collect(),
                5 => t.text.expected_paths = parse_all(v.4.clone()).into_iter().collect(),
                6 => {
                    t.limits.expires_at =
                        Timestamp::from_unix(t.limits.expires_at.unix() + v.5).unwrap()
                }
                7 => t.limits.max_signatures = v.6.0,
                8 => t.limits.max_pushes = v.6.1,
                9 => t.limits.max_ops_per_minute = v.6.2,
                10 => t.limits.max_push_size = ByteSize::from_bytes(v.7),
                11 => {
                    t.subject.caller = match t.subject.caller {
                        Some(_) => None,
                        None => Some(omega_constraint()),
                    }
                }
                _ => {
                    t.on_violation = match t.on_violation {
                        OnViolation::DenyAndNotify => OnViolation::RevokeLease,
                        OnViolation::RevokeLease => OnViolation::DenyAndNotify,
                    }
                }
            }
        }
        t
    })
}

#[derive(Debug, Clone)]
enum Op {
    Sign(SignRequest),
    Push(PushRequest),
    Fetch(FetchRequest),
}

#[derive(Debug, Clone)]
struct Facts {
    op: Op,
    usage: Usage,
    now: Timestamp,
    caller: CallerFacts,
}

fn arb_op() -> impl Strategy<Value = Op> {
    let lease_ids = vec![ticket_id(1).to_string(), ticket_id(99).to_string()];
    let sign = (
        select(REPOS.to_vec()),
        select(vec![
            ObjectKind::Commit,
            ObjectKind::Commit,
            ObjectKind::Tag,
        ]),
        select(EMAILS.to_vec()),
        subsequence(lease_ids.clone(), 0..=2),
        prop::option::of(subsequence(TOUCHED.to_vec(), 0..=3)),
    )
        .prop_map(|(repo_name, object, email, trailers, touched)| {
            Op::Sign(SignRequest {
                repo: repo(repo_name),
                object,
                committer_email: email.to_owned(),
                writ_trailers: trailers,
                touched_paths: touched.map(|t| t.into_iter().map(str::to_owned).collect()),
            })
        });
    let update = (
        select(REFS.to_vec()),
        prop::option::of(1u64..4),
        prop::option::of(1u64..4),
        any::<bool>(),
    )
        .prop_map(|(name, old, new, fast_forward)| RefUpdate {
            name: name.to_owned(),
            old: old.map(commit),
            new: new.map(commit),
            fast_forward,
        });
    let pushed = (
        1u64..6,
        prop::collection::vec((select(lease_ids), select(REPOS.to_vec())), 0..=2),
    )
        .prop_map(|(n, under)| PushedCommit {
            id: commit(n),
            signed_under: under
                .into_iter()
                .map(|(lease, r)| LedgerRef {
                    lease: lease.parse().unwrap(),
                    repo: repo(r),
                })
                .collect(),
        });
    let push = (
        select(REPOS.to_vec()),
        select(vec![
            PushMode::Gateway,
            PushMode::Gateway,
            PushMode::Proxy,
            PushMode::DirectSsh,
        ]),
        prop::collection::vec(update, 0..=2),
        prop::collection::vec(pushed, 0..=3),
        0u64..60_000_000,
    )
        .prop_map(|(repo_name, mode, updates, commits, pack_size)| {
            Op::Push(PushRequest {
                repo: repo(repo_name),
                mode,
                updates,
                commits,
                pack_size,
            })
        });
    let fetch = select(REPOS.to_vec()).prop_map(|r| Op::Fetch(FetchRequest { repo: repo(r) }));
    prop_oneof![sign, push, fetch]
}

fn arb_facts() -> impl Strategy<Value = Facts> {
    let process = |pid, generation, exe: &str| ProcessRef {
        pid,
        generation,
        executable: PathBuf::from(exe),
        code_identity: None,
    };
    let chains = vec![
        None,
        Some(vec![]),
        Some(vec![
            process(5000, 1, "/usr/bin/git"),
            process(4242, 118, OMEGA),
        ]),
        Some(vec![
            process(5000, 1, "/usr/bin/git"),
            process(4242, 119, OMEGA),
        ]),
    ];
    (
        arb_op(),
        (0u32..5, 0u32..4, 0u32..6),
        -100i64..6 * 3600,
        select(chains),
    )
        .prop_map(|(op, (signatures, pushes, ops), offset, chain)| Facts {
            op,
            usage: Usage {
                signatures,
                pushes,
                ops_last_minute: ops,
            },
            now: later(offset),
            caller: CallerFacts {
                source_addr: None,
                process_chain: chain,
            },
        })
}

/// Requests aimed at the boundary between two tickets: built from their own repos, branches,
/// emails, paths and limits, so most pass every check but the one that differs.
fn arb_probe(a: &Ticket, b: &Ticket) -> impl Strategy<Value = Facts> + use<> {
    let mut repos: Vec<String> = a
        .scope
        .repos
        .iter()
        .chain(&b.scope.repos)
        .map(|r| r.to_string())
        .collect();
    repos.push("nope".to_owned());
    let mut refs: Vec<String> = a
        .scope
        .branches
        .iter()
        .chain(&b.scope.branches)
        .map(|p| {
            let text = p.to_string();
            match text.strip_suffix('*') {
                Some(prefix) => format!("refs/heads/{prefix}x"),
                None => format!("refs/heads/{text}"),
            }
        })
        .collect();
    refs.push("refs/heads/main".to_owned());
    let mut emails: Vec<String> = a
        .scope
        .committer_emails
        .iter()
        .chain(&b.scope.committer_emails)
        .chain(&b.scope.committer_emails)
        .map(|e| e.to_string())
        .collect();
    emails.push("user@example.org".to_owned());
    // A file inside each expected path of either ticket, and one outside them all.
    let mut touched: Vec<String> = a
        .text
        .expected_paths
        .iter()
        .chain(&b.text.expected_paths)
        .map(|p| p.as_str().replace("**", "deep/x.rs").replace('*', "x"))
        .collect();
    let max_inside = touched.len().min(2);
    let inside = touched.clone();
    touched.push("README.md".to_owned());
    let max_touched = touched.len().min(2);
    let touched_paths = prop_oneof![
        1 => Just(None),
        4 => subsequence(inside, 0..=max_inside).prop_map(Some),
        2 => subsequence(touched, 0..=max_touched).prop_map(Some),
    ];
    let id = a.id.clone();
    let max_sig = a.limits.max_signatures.max(b.limits.max_signatures);
    let max_push = a.limits.max_pushes.max(b.limits.max_pushes);
    let max_rate = a.limits.max_ops_per_minute.max(b.limits.max_ops_per_minute);
    let sizes = vec![
        a.limits.max_push_size.bytes(),
        b.limits.max_push_size.bytes(),
        a.limits.max_push_size.bytes() + 1,
        b.limits.max_push_size.bytes() + 1,
        0,
    ];
    let span = a
        .created_at
        .seconds_until(a.limits.expires_at.max(b.limits.expires_at))
        + 10;
    let created = a.created_at;
    let chains = vec![
        None,
        Some(vec![ProcessRef {
            pid: 4242,
            generation: 118,
            executable: PathBuf::from(OMEGA),
            code_identity: None,
        }]),
    ];
    (
        select(vec![0u8, 0, 1, 2]),
        select(repos),
        select(refs),
        (any::<bool>(), any::<bool>(), any::<bool>()),
        select(emails),
        touched_paths,
        select(sizes),
        select(vec![PushMode::Gateway, PushMode::Proxy]),
        (0..=max_sig, 0..=max_push, 0..=max_rate),
        0..span,
        select(chains),
    )
        .prop_map(
            move |(
                kind,
                repo_name,
                ref_name,
                (create, delete, ff),
                email,
                touched,
                size,
                mode,
                usage,
                offset,
                chain,
            )| {
                let repo_name = repo(&repo_name);
                let op = match kind {
                    0 => Op::Sign(SignRequest {
                        repo: repo_name,
                        object: ObjectKind::Commit,
                        committer_email: email,
                        writ_trailers: vec![id.to_string()],
                        touched_paths: touched,
                    }),
                    1 => Op::Push(PushRequest {
                        repo: repo_name.clone(),
                        mode,
                        updates: vec![RefUpdate {
                            name: ref_name,
                            old: (!create).then(|| commit(1)),
                            new: (!delete).then(|| commit(2)),
                            fast_forward: ff,
                        }],
                        commits: vec![PushedCommit {
                            id: commit(2),
                            signed_under: vec![LedgerRef {
                                lease: id.clone(),
                                repo: repo_name,
                            }],
                        }],
                        pack_size: size,
                    }),
                    _ => Op::Fetch(FetchRequest { repo: repo_name }),
                };
                Facts {
                    op,
                    usage: Usage {
                        signatures: usage.0,
                        pushes: usage.1,
                        ops_last_minute: usage.2,
                    },
                    now: Timestamp::from_unix(created.unix() + offset).unwrap(),
                    caller: CallerFacts {
                        source_addr: None,
                        process_chain: chain,
                    },
                }
            },
        )
}

fn allows(config: &PolicyConfig, lease: &Lease, facts: &Facts) -> bool {
    let ctx = Context {
        config,
        lease,
        usage: &facts.usage,
        caller: &facts.caller,
        now: facts.now,
    };
    match &facts.op {
        Op::Sign(r) => policy::decide_sign(&ctx, r).is_ok(),
        Op::Push(r) => policy::decide_push(&ctx, r).is_ok(),
        Op::Fetch(r) => policy::decide_fetch(&ctx, r).is_ok(),
    }
}

/// A lease with the ticket's terms, without going through activation.
fn as_lease(ticket: Ticket) -> Lease {
    Lease {
        id: ticket.id.clone(),
        ticket,
        approval: approval(),
        state: State::Active,
        cert_serial: 7,
    }
}

fn proptest_config() -> ProptestConfig {
    ProptestConfig {
        cases: 1024,
        max_global_rejects: 1_000_000,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn a_narrowed_ticket_never_grants_more(
        (submitted, signed, probes) in arb_ticket()
            .prop_flat_map(|t| (Just(t.clone()), arb_signed(t)))
            .prop_flat_map(|(a, b)| {
                let probes = prop::collection::vec(arb_probe(&a, &b), 24);
                (Just(a), Just(b), probes)
            }),
        random in prop::collection::vec(arb_facts(), 8),
    ) {
        let requests: Vec<Facts> = probes.into_iter().chain(random).collect();
        let config = config();
        if narrow::check(&submitted, &signed).is_err() {
            // Refused: and the daemon would not activate it either.
            let record = TicketRecord::pending(submitted.clone());
            prop_assert!(lease::activate(&config, &record, signed, approval(), 7, later(1)).is_err());
            return Ok(());
        }
        let record = TicketRecord::pending(submitted.clone());
        let Ok(signed_lease) = lease::activate(&config, &record, signed, approval(), 7, later(1)) else {
            return Ok(());
        };
        let submitted_lease = as_lease(submitted);
        for facts in &requests {
            if allows(&config, &signed_lease, facts) {
                prop_assert!(
                    allows(&config, &submitted_lease, facts),
                    "the narrowed lease allows {facts:?}, the submitted one doesn't"
                );
            }
        }
    }

    #[test]
    fn no_ticket_outside_every_template_is_accepted(
        request in arb_request(),
        requests in prop::collection::vec(arb_facts(), 16),
    ) {
        let config = config();
        let Ok(ticket) = fit::submit(&config, &request, &submission(1)) else {
            return Ok(());
        };
        prop_assert!(fit::fits(&config, &ticket).is_ok());
        if let Some(named) = &request.template {
            prop_assert_eq!(&ticket.template, named);
        }
        // The largest ticket the template accepts with the same identity, text and operations
        // (operations beyond the template are the next property's job). With push, only the
        // repos the template can push to.
        let template = config.template(&ticket.template).unwrap();
        let mut largest = ticket.clone();
        let pushes = ticket.allows(Operation::Push);
        largest.scope.repos = template
            .repos
            .iter()
            .filter(|r| !pushes || !fit::push_modes(&config.repo(r).unwrap().push_modes, template).is_empty())
            .cloned()
            .collect();
        largest.scope.branches = template.branches.clone();
        largest.scope.force_push = template.force_push;
        largest.scope.committer_emails = template.committer_emails.clone();
        largest.scope.signing_key = template.signing_key.clone();
        largest.limits = Limits {
            expires_at: ticket.created_at.checked_add(template.max_ttl).unwrap(),
            max_signatures: template.max_signatures,
            max_pushes: template.max_pushes,
            max_ops_per_minute: template.max_ops_per_minute,
            max_push_size: template.max_push_size,
        };
        prop_assert!(fit::fits(&config, &largest).is_ok(), "{:?}", fit::fits(&config, &largest));
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let probes: Vec<Facts> = (0..24)
            .map(|_| arb_probe(&ticket, &largest).new_tree(&mut runner).unwrap().current())
            .collect();
        let (ticket_lease, largest_lease) = (as_lease(ticket), as_lease(largest));
        for facts in requests.iter().chain(&probes) {
            if allows(&config, &ticket_lease, facts) {
                prop_assert!(
                    allows(&config, &largest_lease, facts),
                    "the ticket allows {facts:?}, its template doesn't"
                );
            }
        }
    }

    #[test]
    fn a_ticket_beyond_its_template_never_fits(
        ticket in arb_ticket(),
        widen in 0usize..8,
    ) {
        let config = config();
        let template = config.template(&ticket.template).unwrap().clone();
        let mut wide = ticket.clone();
        match widen {
            0 => { wide.scope.repos.insert(repo("nope")); }
            1 => { wide.scope.operations = OPS.into_iter().collect(); }
            2 => { wide.scope.branches.insert("main".parse().unwrap()); }
            3 => wide.scope.force_push = true,
            4 => { wide.scope.committer_emails.insert("user@example.org".parse().unwrap()); }
            5 => wide.limits.max_signatures = template.max_signatures + 1,
            6 => wide.limits.expires_at = wide.created_at.checked_add(Duration::from_seconds(template.max_ttl.seconds() + 1)).unwrap(),
            _ => wide.limits.max_push_size = ByteSize::from_bytes(template.max_push_size.bytes() + 1),
        }
        let beyond = match widen {
            1 => !template.operations.is_superset(&wide.scope.operations),
            2 => !template.branches.iter().any(|b| b.covers(&"main".parse().unwrap())),
            3 => !template.force_push,
            _ => true,
        };
        if beyond {
            prop_assert!(fit::fits(&config, &wide).is_err());
        }
    }

    #[test]
    fn ambiguity_denies(
        pool in prop::collection::vec((1u64..4, 7u64..9, select(vec!['S', 'T']), select(State::ALL.to_vec())), 0..6),
        cert in (1u64..4, 7u64..9, select(vec!['S', 'T'])),
        duplicate in any::<prop::sample::Index>(),
    ) {
        let base = lease();
        let make = |(id, serial, key): (u64, u64, char)| {
            let mut lease = base.clone();
            lease.id = ticket_id(id);
            lease.cert_serial = serial;
            lease.ticket.subject.session_key = fp(key);
            lease
        };
        let mut leases: Vec<Lease> = pool
            .iter()
            .map(|&(id, serial, key, state)| Lease { state, ..make((id, serial, key)) })
            .collect();
        let cert_identity = CertIdentity {
            key_id: ticket_id(cert.0).to_string(),
            serial: cert.1,
            session_key: fp(cert.2),
        };
        let matching = leases
            .iter()
            .filter(|l| l.id.as_str() == cert_identity.key_id && l.cert_serial == cert.1 && l.ticket.subject.session_key == fp(cert.2))
            .count();
        let result = policy::resolve_lease(&leases, &cert_identity);
        match matching {
            0 => prop_assert_eq!(result.unwrap_err().code, DenyCode::NoLease),
            1 => prop_assert!(result.is_ok()),
            _ => prop_assert_eq!(result.unwrap_err().code, DenyCode::AmbiguousLease),
        }
        // Duplicating the matching lease, in any state, always denies.
        leases.push(make(cert));
        let copy = leases[duplicate.index(leases.len())].clone();
        leases.push(copy);
        let twice = leases
            .iter()
            .filter(|l| l.id.as_str() == cert_identity.key_id && l.cert_serial == cert.1 && l.ticket.subject.session_key == fp(cert.2))
            .count();
        prop_assert!(twice >= 2 || policy::resolve_lease(&leases, &cert_identity).is_ok());
        if twice >= 2 {
            prop_assert_eq!(policy::resolve_lease(&leases, &cert_identity).unwrap_err().code, DenyCode::AmbiguousLease);
        }
    }

    #[test]
    fn counters_never_exceed_limits(
        limits in (0u32..6, 0u32..6, 1u32..6),
        steps in prop::collection::vec((0u8..3, 0i64..40), 1..80),
    ) {
        let config = config();
        let mut ticket = submitted(REQUEST);
        ticket.limits.max_signatures = limits.0;
        ticket.limits.max_pushes = limits.1;
        ticket.limits.max_ops_per_minute = limits.2;
        let lease = as_lease(ticket);
        let mut usage = Usage::default();
        let mut history: Vec<Timestamp> = Vec::new();
        let mut now = later(1);
        for (kind, wait) in steps {
            now = Timestamp::from_unix(now.unix() + wait).unwrap();
            let window_start = now.unix() - policy::RATE_WINDOW_SECONDS;
            usage.ops_last_minute = history.iter().filter(|t| t.unix() > window_start).count() as u32;
            let caller = CallerFacts::default();
            let ctx = Context { config: &config, lease: &lease, usage: &usage, caller: &caller, now };
            let allowed = match kind {
                0 => policy::decide_sign(&ctx, &sign_request(&lease)).is_ok(),
                1 => policy::decide_push(&ctx, &push_request(&lease)).is_ok(),
                _ => policy::decide_fetch(&ctx, &fetch_request()).is_ok(),
            };
            if allowed {
                prop_assert!(now < lease.ticket.limits.expires_at);
                match kind {
                    0 => usage.signatures += 1,
                    1 => usage.pushes += 1,
                    _ => {}
                }
                history.push(now);
            }
            prop_assert!(usage.signatures <= limits.0);
            prop_assert!(usage.pushes <= limits.1);
            let in_window = history.iter().filter(|t| t.unix() > window_start).count() as u32;
            prop_assert!(in_window <= limits.2);
        }
    }
}

#[test]
fn the_generators_reach_both_outcomes() {
    // Guard against vacuous properties: some random requests fit, some don't, and some
    // narrowed tickets are accepted.
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    let config = config();
    let (mut fit_count, mut rejected) = (0, 0);
    for _ in 0..2000 {
        let request = arb_request().new_tree(&mut runner).unwrap().current();
        match fit::submit(&config, &request, &submission(1)) {
            Ok(_) => fit_count += 1,
            Err(_) => rejected += 1,
        }
    }
    assert!(
        fit_count > 50 && rejected > 50,
        "fit {fit_count}, rejected {rejected}"
    );

    let mut narrowed = 0;
    for _ in 0..500 {
        let submitted = arb_ticket().new_tree(&mut runner).unwrap().current();
        let signed = arb_signed(submitted.clone())
            .new_tree(&mut runner)
            .unwrap()
            .current();
        if narrow::check(&submitted, &signed).is_ok() && signed != submitted {
            narrowed += 1;
        }
    }
    assert!(narrowed > 10, "only {narrowed} strict narrowings generated");

    let mut allowed = 0;
    let lease = lease();
    for _ in 0..2000 {
        let facts = arb_facts().new_tree(&mut runner).unwrap().current();
        if allows(&config, &lease, &facts) {
            allowed += 1;
        }
    }
    assert!(allowed > 20, "only {allowed} random requests allowed");
}
