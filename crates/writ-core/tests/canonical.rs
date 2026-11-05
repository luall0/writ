//! The canonical encoding of a ticket: the bytes an approval signs. Pinned by fixtures in
//! tests/fixtures/; any field change changes the bytes; only canonical bytes decode.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

mod common;

use std::collections::BTreeSet;

use common::*;
use writ_core::caller::{CallerConstraint, CodeIdentity, ProcessMatch};
use writ_core::canonical::Canonical;
use writ_core::ticket::Operation;
use writ_core::ticket::{Estimate, OnViolation, Ticket};
use writ_core::units::{ByteSize, Duration};

const FULL: &[u8] = include_bytes!("fixtures/ticket-full.json");
const MINIMAL: &[u8] = include_bytes!("fixtures/ticket-minimal.json");

/// Every field set, including the optional ones.
fn full() -> Ticket {
    let mut ticket = submitted(REQUEST);
    ticket.subject.origin_hint = Some("macbook-user".to_owned());
    ticket.subject.caller = Some(CallerConstraint {
        descends_from: ProcessMatch {
            executable: "/Applications/Omega Code.app/Contents/MacOS/omega".to_owned(),
            pid: 4242,
            generation: 118,
            code_identity: Some(CodeIdentity {
                signing_id: "com.omega.code".to_owned(),
                team_id: Some("TEAM123456".to_owned()),
            }),
        },
    });
    ticket.text.title = "Add OAuth login \"v2\" — é\u{1b}[2J".to_owned();
    ticket.common.committer_name = Some("Writ agent — Zoë".parse().unwrap());
    ticket.text.estimate = Some(Estimate {
        coding: Some(Duration::from_seconds(45 * 60)),
        checks: None,
        ci: Some(Duration::from_seconds(90 * 60)),
    });
    ticket.text.amends = Some(ticket_id(10));
    ticket.text.renews = Some(ticket_id(13));
    ticket.text.revises = Some(ticket_id(11));
    ticket.text.revision = 2;
    ticket.text.previous_feedback = Some("Don't touch billing".to_owned());
    ticket.on_violation = OnViolation::RevokeLease;
    ticket
}

/// A fetch-only ticket with nothing optional.
fn minimal() -> Ticket {
    submitted(
        r#"
repos:
  omega-code:
    template: read-only
    operations: [fetch]
    limits:
      max_signatures: 0
      max_pushes: 0
      max_push_size: 0
ticket:
  title: Read the code
  task: Look around
"#,
    )
}

#[test]
fn fixtures_are_stable() {
    // Regenerate by hand only when the format changes on purpose (and bump `Ticket::KIND`).
    if std::env::var_os("WRIT_WRITE_FIXTURES").is_some() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        std::fs::write(
            format!("{dir}/ticket-full.json"),
            full().canonical_bytes().unwrap(),
        )
        .unwrap();
        std::fs::write(
            format!("{dir}/ticket-minimal.json"),
            minimal().canonical_bytes().unwrap(),
        )
        .unwrap();
    }
    assert_eq!(full().canonical_bytes().unwrap(), FULL);
    assert_eq!(minimal().canonical_bytes().unwrap(), MINIMAL);
    // Twice in a run, and through a decode.
    assert_eq!(
        full().canonical_bytes().unwrap(),
        full().canonical_bytes().unwrap()
    );
    assert_eq!(Ticket::from_canonical(FULL).unwrap(), full());
    assert_eq!(Ticket::from_canonical(MINIMAL).unwrap(), minimal());
}

#[test]
fn the_format_starts_with_its_kind() {
    assert!(FULL.starts_with(br#"{"kind":"writ-ticket/3","id":"wrt_"#));
    assert_eq!(
        Ticket::KIND,
        "writ-ticket/3",
        "KIND is the serde name of the marker"
    );
}

#[test]
fn every_field_change_changes_the_bytes() {
    type Change = fn(&mut Ticket);
    let changes: Vec<(&str, Change)> = vec![
        ("id", |t| t.id = ticket_id(50)),
        ("created_at", |t| t.created_at = later(1)),
        ("template", |t| {
            omega(t).template = "quick-fix".parse().unwrap()
        }),
        ("subject.session_key", |t| t.subject.session_key = fp('T')),
        ("subject.origin_hint", |t| {
            t.subject.origin_hint = Some("macbook-userz".to_owned())
        }),
        ("subject.origin_hint removed", |t| {
            t.subject.origin_hint = None
        }),
        ("caller removed", |t| t.subject.caller = None),
        ("caller executable", |t| {
            if let Some(c) = &mut t.subject.caller {
                c.descends_from.executable.push('2');
            }
        }),
        ("caller pid", |t| {
            if let Some(c) = &mut t.subject.caller {
                c.descends_from.pid += 1;
            }
        }),
        ("caller generation", |t| {
            if let Some(c) = &mut t.subject.caller {
                c.descends_from.generation += 1;
            }
        }),
        ("caller signing_id", |t| {
            if let Some(CallerConstraint {
                descends_from:
                    ProcessMatch {
                        code_identity: Some(i),
                        ..
                    },
            }) = &mut t.subject.caller
            {
                i.signing_id.push('x');
            }
        }),
        ("caller team_id", |t| {
            if let Some(CallerConstraint {
                descends_from:
                    ProcessMatch {
                        code_identity: Some(i),
                        ..
                    },
            }) = &mut t.subject.caller
            {
                i.team_id = None;
            }
        }),
        ("repos", |t| {
            let terms = om(t).clone();
            t.repos.insert(repo("homelab-scripts"), terms);
        }),
        ("scope.operations", |t| {
            omega(t).operations.remove(&Operation::Push);
        }),
        ("scope.branches", |t| {
            omega(t).branches = BTreeSet::from(["agent/oauth-x".parse().unwrap()]);
        }),
        ("scope.force_push", |t| omega(t).force_push = true),
        ("scope.committer_emails", |t| {
            t.common
                .committer_emails
                .insert("x@example.org".parse().unwrap());
        }),
        ("common.committer_name", |t| {
            t.common.committer_name = Some("Writ agent — Zoe".parse().unwrap())
        }),
        ("common.committer_name removed", |t| {
            t.common.committer_name = None
        }),
        ("common.signing_key", |t| {
            t.common.signing_key = Some("agent-ed25519-02".parse().unwrap())
        }),
        ("ticket.title", |t| t.text.title.push(' ')),
        ("ticket.task", |t| t.text.task.push('.')),
        ("ticket.plan step", |t| t.text.plan[0].push('!')),
        ("ticket.plan order", |t| t.text.plan.swap(0, 1)),
        ("ticket.expected_paths", |t| {
            omega(t).expected_paths.insert("docs/**".parse().unwrap());
        }),
        ("ticket.estimate", |t| t.text.estimate = None),
        ("ticket.estimate.checks", |t| {
            if let Some(e) = &mut t.text.estimate {
                e.checks = Some(Duration::from_seconds(60));
            }
        }),
        ("ticket.amends", |t| t.text.amends = None),
        ("ticket.renews", |t| t.text.renews = None),
        ("ticket.revises", |t| t.text.revises = Some(ticket_id(12))),
        ("ticket.revision", |t| t.text.revision = 3),
        ("ticket.previous_feedback", |t| {
            t.text.previous_feedback = None
        }),
        ("limits.expires_at", |t| t.limits.expires_at = later(100)),
        ("limits.max_signatures", |t| {
            omega(t).limits.max_signatures += 1
        }),
        ("limits.max_pushes", |t| omega(t).limits.max_pushes += 1),
        ("limits.max_ops_per_minute", |t| {
            t.limits.max_ops_per_minute += 1
        }),
        ("limits.max_push_size", |t| {
            omega(t).limits.max_push_size = ByteSize::from_bytes(1)
        }),
        ("on_violation", |t| {
            t.on_violation = OnViolation::DenyAndNotify
        }),
    ];
    let mut seen = BTreeSet::from([FULL.to_vec()]);
    for (name, change) in changes {
        let mut ticket = full();
        change(&mut ticket);
        let bytes = ticket.canonical_bytes().unwrap();
        assert!(
            seen.insert(bytes),
            "changing {name} did not produce new bytes"
        );
    }
}

#[test]
fn set_order_in_the_request_does_not_matter() {
    let a = submitted(REQUEST);
    let b = submitted(&REQUEST.replace(
        r#"["src/auth/**", "tests/auth/**"]"#,
        r#"["tests/auth/**", "src/auth/**", "src/auth/**"]"#,
    ));
    assert_eq!(a.canonical_bytes().unwrap(), b.canonical_bytes().unwrap());
}

#[test]
fn only_canonical_bytes_decode() {
    let text = std::str::from_utf8(FULL).unwrap();
    let variants: Vec<(&str, String)> = vec![
        ("trailing newline", format!("{text}\n")),
        ("leading space", format!(" {text}")),
        (
            "space after a colon",
            text.replacen(r#""kind":"#, r#""kind": "#, 1),
        ),
        (
            "keys reordered",
            text.replacen(r#"{"kind":"writ-ticket/3","#, "{", 1)
                .replacen(
                    r#""on_violation""#,
                    r#""kind":"writ-ticket/3","on_violation""#,
                    1,
                ),
        ),
        (
            "unsorted set",
            text.replacen(
                r#"["src/auth/**","tests/auth/**"]"#,
                r#"["tests/auth/**","src/auth/**"]"#,
                1,
            ),
        ),
        (
            "duplicate set entry",
            text.replacen(
                r#"["src/auth/**","tests/auth/**"]"#,
                r#"["src/auth/**","src/auth/**","tests/auth/**"]"#,
                1,
            ),
        ),
        (
            "unknown field",
            text.replacen(r#""on_violation""#, r#""extra":1,"on_violation""#, 1),
        ),
        (
            "missing field",
            text.replacen(r#""force_push":false,"#, "", 1),
        ),
        (
            "other kind",
            text.replacen("writ-ticket/3", "writ-ticket/2", 1),
        ),
        (
            "size as text",
            text.replacen(r#""max_push_size":1000000"#, r#""max_push_size":"1MB""#, 1),
        ),
        (
            "timestamp with offset",
            text.replacen("T14:02:11Z", "T15:02:11+01:00", 1),
        ),
        (
            "escaped slash",
            text.replacen("/Applications", "\\/Applications", 1),
        ),
        ("unicode escape", text.replacen("é", "\\u00e9", 1)),
    ];
    for (name, bytes) in variants {
        assert_ne!(bytes.as_bytes(), FULL, "{name}: variant is identical");
        // Refused as not the canonical form, or as no ticket at all: never decoded. Either
        // variant of the error is the refusal (its text says which byte).
        assert!(
            matches!(
                Ticket::from_canonical(bytes.as_bytes()),
                Err(writ_core::canonical::CanonicalError::NotCanonical {
                    kind: "writ-ticket/3"
                } | writ_core::canonical::CanonicalError::Decode {
                    kind: "writ-ticket/3",
                    ..
                })
            ),
            "{name} decoded"
        );
    }
}

/// The orders and escapes lease-model.md specifies for an independent client (the review after
/// M5.5, D3): sets by their own order, not always by text; only C0 escaped.
#[test]
fn the_documented_orders_and_escapes_are_the_encoded_ones() {
    let mut t = full();
    omega(&mut t).operations = [Operation::Push, Operation::Fetch, Operation::CommitSign].into();
    omega(&mut t).branches = ["agent/*", "main", "a/*", "zeta"]
        .iter()
        .map(|b| b.parse().unwrap())
        .collect();
    let terms = om(&t).clone();
    t.repos = ["omega-code", "Omega", "alpha"]
        .iter()
        .map(|r| (r.parse().unwrap(), terms.clone()))
        .collect();
    t.text.title = "q\"b\\s\u{8}\t\n\u{c}\r\u{1}\u{1f} \u{7f}\u{85}é".to_owned();
    let text = String::from_utf8(t.canonical_bytes().unwrap()).unwrap();
    assert!(
        text.contains(r#""operations":["fetch","commit_sign","push"]"#),
        "{text}"
    );
    assert!(
        text.contains(r#""branches":["main","zeta","a/*","agent/*"]"#),
        "{text}"
    );
    assert!(
        text.contains(r#""repos":{"Omega":{"#)
            && text.contains(r#"},"alpha":{"#)
            && text.contains(r#"},"omega-code":{"#),
        "{text}"
    );
    assert!(
        text.contains("\"title\":\"q\\\"b\\\\s\\b\\t\\n\\f\\r\\u0001\\u001f \u{7f}\u{85}é\""),
        "{text}"
    );
    // And it decodes back to itself.
    assert_eq!(Ticket::from_canonical(text.as_bytes()).unwrap(), t);
}
