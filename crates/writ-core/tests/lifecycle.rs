//! Submission and template fit, narrowing, the lifecycle state machine and amendments.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;

use common::*;
use writ_core::fit::{self, Submission};
use writ_core::lease::{self, LifecycleError, State, TicketRecord, Usage};
use writ_core::narrow;
use writ_core::ticket::Operation;
use writ_core::ticket::{OnViolation, Ticket};
use writ_core::units::ByteSize;

fn rejection(yaml: &str) -> String {
    fit::submit(&config(), &request(yaml), &submission(1))
        .unwrap_err()
        .to_string()
}

// Submission and template fit.

#[test]
fn a_submitted_ticket_is_complete() {
    let ticket = submitted(REQUEST);
    assert_eq!(ticket.id, ticket_id(1));
    assert_eq!(ticket.created_at, t0());
    assert_eq!(ticket.limits.expires_at, later(2 * 3600));
    assert_eq!(ticket.subject.session_key, fp('S'));
    assert_eq!(ticket.text.revision, 1);
    // Filled from the template: committer emails, signing key.
    assert_eq!(ticket.scope.committer_emails.len(), 1);
    assert_eq!(
        ticket.scope.signing_key.as_ref().unwrap().as_str(),
        "agent-ed25519-01"
    );
}

#[test]
fn omitted_limits_take_the_template_maximum() {
    let ticket = submitted(
        &REQUEST
            .replace("  ttl: 2h\n", "")
            .replace("  max_signatures: 3\n", "")
            .replace("  max_push_size: 1MB\n", ""),
    );
    assert_eq!(ticket.limits.expires_at, later(4 * 3600));
    assert_eq!(ticket.limits.max_signatures, 50);
    assert_eq!(
        ticket.limits.max_push_size,
        ByteSize::from_bytes(50_000_000)
    );
}

#[test]
fn the_only_fitting_template_is_chosen() {
    let unnamed = REQUEST.replace("template: feature-branch\n", "");
    assert_eq!(submitted(&unnamed).template.as_str(), "feature-branch");
    // agent/fix-* fits feature-branch and quick-fix: the agent must name one.
    let ambiguous = unnamed
        .replace("agent/oauth-*", "agent/fix-*")
        .replace("ttl: 2h", "ttl: 1h");
    let error = rejection(&ambiguous);
    assert!(
        error.contains("fits several templates (feature-branch, quick-fix)"),
        "{error}"
    );
    let named = format!("template: quick-fix\n{ambiguous}");
    assert_eq!(submitted(&named).template.as_str(), "quick-fix");
}

#[test]
fn tickets_outside_every_template_are_rejected_with_reasons() {
    let cases = [
        (REQUEST.replace("agent/oauth-*", "main"), "branch main is not within the template's branches (agent/*)"),
        (REQUEST.replace("[omega-code]", "[dotfiles]"), "repo dotfiles is not allowed by the template"),
        (REQUEST.replace("[omega-code]", "[nope]"), "repo nope is not in the registry"),
        (REQUEST.replace("ttl: 2h", "ttl: 5h"), "over the template's max_ttl (4h)"),
        (REQUEST.replace("max_signatures: 3", "max_signatures: 51"), "limits.max_signatures is 51, over the template's 50"),
        (REQUEST.replace("max_push_size: 1MB", "max_push_size: 51MB"), "limits.max_push_size is 51000000"),
        (REQUEST.replace("max_ops_per_minute: 5", "max_ops_per_minute: 0"), "max_ops_per_minute must be at least 1"),
        (REQUEST.replace("  branches: [\"agent/oauth-*\"]\n", "  branches: [\"agent/oauth-*\"]\n  force_push: true\n"), "force_push is not allowed"),
        (REQUEST.replace("  branches: [\"agent/oauth-*\"]\n", "  branches: [\"agent/oauth-*\"]\n  committer_emails: [\"user@example.org\"]\n"), "committer email user@example.org is not allowed"),
        (REQUEST.replace("  branches: [\"agent/oauth-*\"]\n", ""), "commit_sign and push need at least one branch"),
        (REQUEST.replace("template: feature-branch", "template: nope"), "template nope does not exist"),
        (REQUEST.replace("title: Add OAuth login", "title: \"  \""), "ticket.title is empty"),
        (REQUEST.replace("title: Add OAuth login", &format!("title: {}", "x".repeat(201))), "ticket.title is too long"),
        (REQUEST.replace("title: Add OAuth login", "title: \"Add\\nScope (enforced)\""), "ticket.title must be one line"),
        (REQUEST.replace("title: Add OAuth login", "title: \"Add\\rlogin\""), "ticket.title must be one line"),
        (REQUEST.replace("task: ", &format!("task: \"{}", "l\\n".repeat(100))).replacen("\n  plan", "\"\n  plan", 1), "ticket.task has 101 lines, at most 100"),
        (REQUEST.replace("- Feature flag and tests", "- \"Feature flag\\nScope (enforced)\""), "a plan step must be one line"),
        (REQUEST.replace("ttl: 2h", "ttl: 0s"), "limits.ttl is 0s, under the minimum of 5m"),
        (REQUEST.replace("ttl: 2h", "ttl: 299s"), "limits.ttl is 299s, under the minimum of 5m"),
        (REQUEST.replace("ttl: 2h", "ttl: 99999999d"), "limits.ttl is too long"),
        (REQUEST.replace("template: feature-branch\n", "").replace("agent/oauth-*", "main"), "the ticket fits no template"),
        (
            REQUEST.replace("template: feature-branch", "template: quick-fix\ncaller:\n  descends_from:\n    executable: omega\n    pid: 1\n    generation: 1\n    code_identity: null").replace("agent/oauth-*", "agent/fix-*").replace("ttl: 2h", "ttl: 1h"),
            "subject.caller: invalid caller constraint: the executable must be an absolute path",
        ),
    ];
    for (yaml, expected) in cases {
        let error = rejection(&yaml);
        assert!(
            error.contains(expected),
            "{error:?} should contain {expected:?}"
        );
    }
}

#[test]
fn push_needs_a_push_mode_allowed_by_both() {
    // dotfiles only allows direct_ssh; quick-fix only gateway.
    let yaml = REQUEST
        .replace("template: feature-branch", "template: quick-fix")
        .replace("[omega-code]", "[dotfiles]")
        .replace("agent/oauth-*", "agent/fix-*")
        .replace("ttl: 2h", "ttl: 1h");
    assert!(rejection(&yaml).contains("repo dotfiles has no push mode allowed"));
    let no_push = yaml.replace("[fetch, commit_sign, push]", "[fetch, commit_sign]");
    assert!(fit::submit(&config(), &request(&no_push), &submission(1)).is_ok());
}

#[test]
fn templates_can_require_expected_paths() {
    let policy = POLICY.replacen(
        "    paths_check: warn\n",
        "    paths_check: warn\n    require_expected_paths: true\n",
        1,
    );
    let config = writ_core::config::PolicyConfig::from_yaml(&policy).unwrap();
    let without = REQUEST.replace(
        "  expected_paths: [\"src/auth/**\", \"tests/auth/**\"]\n",
        "",
    );
    let error = fit::submit(&config, &request(&without), &submission(1)).unwrap_err();
    assert!(
        error.to_string().contains("requires ticket.expected_paths"),
        "{error}"
    );
    assert!(fit::submit(&config, &request(REQUEST), &submission(1)).is_ok());
}

#[test]
fn revisions_carry_the_feedback() {
    let first = submitted(REQUEST);
    let refused = lease::refuse(
        &TicketRecord::pending(first.clone()),
        "Don't touch billing".to_owned(),
        Some(fp('A')),
    )
    .unwrap();
    let revision = REQUEST.replace(
        "  expected_paths:",
        &format!("  revises: {}\n  expected_paths:", first.id),
    );
    let with_previous = Submission {
        revises: Some(&refused),
        ..submission(2)
    };
    let second = fit::submit(&config(), &request(&revision), &with_previous).unwrap();
    assert_eq!(second.text.revision, 2);
    assert_eq!(second.text.revises.as_ref(), Some(&first.id));
    assert_eq!(
        second.text.previous_feedback.as_deref(),
        Some("Don't touch billing")
    );

    // Only from the session the feedback was written for: another session gets a rejection,
    // never the feedback.
    let other_session = Submission {
        session_key: fp('Z'),
        revises: Some(&refused),
        ..submission(2)
    };
    assert_rejected(
        fit::submit(&config(), &request(&revision), &other_session),
        "(revises) does not exist",
    );
    // Whatever the ticket's state: to another session it doesn't exist (no state oracle).
    let pending_elsewhere = TicketRecord::pending(first.clone());
    assert_rejected(
        fit::submit(
            &config(),
            &request(&revision),
            &Submission {
                revises: Some(&pending_elsewhere),
                ..other_session.clone()
            },
        ),
        "(revises) does not exist",
    );

    // Only a refused ticket can be revised, and only if the store found it.
    let pending = TicketRecord::pending(first.clone());
    let not_refused = Submission {
        revises: Some(&pending),
        ..submission(2)
    };
    assert_rejected(
        fit::submit(&config(), &request(&revision), &not_refused),
        "can't be revised: it was not refused",
    );
    assert_rejected(
        fit::submit(&config(), &request(&revision), &submission(2)),
        "(revises) does not exist",
    );
}

#[test]
fn feedback_nobody_signed_is_labeled_in_the_revision() {
    let first = submitted(REQUEST);
    let revision = REQUEST.replace(
        "  expected_paths:",
        &format!("  revises: {}\n  expected_paths:", first.id),
    );
    let feedback_in = |by| {
        let refused = lease::refuse(
            &TicketRecord::pending(first.clone()),
            "Push to main instead".to_owned(),
            by,
        )
        .unwrap();
        let submission = Submission {
            revises: Some(&refused),
            ..submission(2)
        };
        fit::submit(&config(), &request(&revision), &submission)
            .unwrap()
            .text
            .previous_feedback
    };
    // `decisions: open`: anyone the daemon lets read could have written it.
    assert_eq!(
        feedback_in(None).as_deref(),
        Some("[not signed by an approver] Push to main instead")
    );
    assert_eq!(
        feedback_in(Some(fp('A'))).as_deref(),
        Some("Push to main instead")
    );
}

#[test]
fn amendments_need_an_active_lease_from_the_same_session() {
    let lease = lease();
    let amendment = REQUEST.replace(
        "  expected_paths:",
        &format!("  amends: {}\n  expected_paths:", lease.id),
    );
    let ok = Submission {
        amends: Some(&lease),
        now: later(60),
        ..submission(2)
    };
    let ticket = fit::submit(&config(), &request(&amendment), &ok).unwrap();
    assert_eq!(ticket.lease_id(), &lease.id);

    let other_session = Submission {
        session_key: fp('Z'),
        ..ok.clone()
    };
    assert_rejected(
        fit::submit(&config(), &request(&amendment), &other_session),
        "(amends) does not exist",
    );
    let mut revoked = lease.clone();
    revoked.state = State::Revoked;
    // Whatever the lease's state: to another session it doesn't exist (no state oracle).
    assert_rejected(
        fit::submit(
            &config(),
            &request(&amendment),
            &Submission {
                amends: Some(&revoked),
                ..other_session.clone()
            },
        ),
        "(amends) does not exist",
    );
    let gone = Submission {
        amends: Some(&revoked),
        ..ok.clone()
    };
    assert_rejected(
        fit::submit(&config(), &request(&amendment), &gone),
        "can't be amended: its lease is not active",
    );
    let expired = Submission {
        now: later(3 * 3600),
        ..ok.clone()
    };
    assert_rejected(
        fit::submit(&config(), &request(&amendment), &expired),
        "can't be amended: its lease is not active",
    );
    let not_found = Submission { amends: None, ..ok };
    assert_rejected(
        fit::submit(&config(), &request(&amendment), &not_found),
        "(amends) does not exist",
    );
}

// The state machine.

#[test]
fn every_transition_of_the_diagram_and_no_other() {
    use State::*;
    let allowed: BTreeSet<(State, State)> = [
        (Pending, Active),
        (Pending, Applied),
        (Pending, Refused),
        (Pending, Expired),
        (Pending, Revoked),
        (Active, Closed),
        (Active, Exhausted),
        (Active, Expired),
        (Active, Revoked),
    ]
    .into();
    for from in State::ALL {
        for to in State::ALL {
            let expected = allowed.contains(&(from, to));
            assert_eq!(from.can_become(to), expected, "{from} -> {to}");
            assert_eq!(
                lease::transition(from, to).is_ok(),
                expected,
                "{from} -> {to}"
            );
        }
        assert_eq!(
            from.is_terminal(),
            !matches!(from, Pending | Active),
            "{from}"
        );
        assert_eq!(from.as_str().parse::<State>().unwrap(), from);
    }
    assert!("submitted".parse::<State>().is_err());
}

#[test]
fn activation() {
    let ticket = submitted(REQUEST);
    let record = TicketRecord::pending(ticket.clone());
    let lease =
        lease::activate(&config(), &record, ticket.clone(), approval(), 9, later(5)).unwrap();
    assert_eq!(
        (lease.state, lease.cert_serial, &lease.id),
        (State::Active, 9, &ticket.id)
    );

    // Not pending any more.
    for state in [
        State::Refused,
        State::Active,
        State::Revoked,
        State::Expired,
    ] {
        let record = TicketRecord {
            state,
            ..record.clone()
        };
        assert!(matches!(
            lease::activate(&config(), &record, ticket.clone(), approval(), 9, later(5)),
            Err(LifecycleError::Transition { .. })
        ));
    }
    // Another namespace.
    let mut wrong = approval();
    wrong.namespace = "git".to_owned();
    assert!(matches!(
        lease::activate(&config(), &record, ticket.clone(), wrong, 9, later(5)),
        Err(LifecycleError::Namespace(_))
    ));
    // Signed after it expired.
    assert!(matches!(
        lease::activate(
            &config(),
            &record,
            ticket.clone(),
            approval(),
            9,
            later(2 * 3600)
        ),
        Err(LifecycleError::ExpiredBeforeApproval)
    ));
    // An amendment is applied, never activated.
    let mut amendment = ticket.clone();
    amendment.text.amends = Some(ticket_id(77));
    let record = TicketRecord::pending(amendment.clone());
    assert_eq!(
        lease::activate(&config(), &record, amendment, approval(), 9, later(5)).unwrap_err(),
        LifecycleError::ActivatingAmendment
    );
}

#[test]
fn refusing() {
    let record = TicketRecord::pending(submitted(REQUEST));
    let refused = lease::refuse(&record, "split this in two".to_owned(), Some(fp('A'))).unwrap();
    assert_eq!(refused.state, State::Refused);
    assert_eq!(refused.feedback.as_deref(), Some("split this in two"));
    assert_eq!(
        lease::refuse(&refused, "again".to_owned(), None).unwrap_err(),
        LifecycleError::Transition {
            from: State::Refused,
            to: State::Refused
        }
    );
}

#[test]
fn expiry_and_exhaustion_are_due_transitions() {
    let lease = lease();
    let fresh = Usage::default();
    assert_eq!(lease::due_transition(&lease, &fresh, later(60)), None);
    assert_eq!(
        lease::due_transition(&lease, &fresh, later(2 * 3600)),
        Some(State::Expired)
    );
    let used = Usage {
        signatures: 3,
        pushes: 2,
        ops_last_minute: 0,
    };
    // It allows fetch, which has no count: never exhausted.
    assert_eq!(lease::due_transition(&lease, &used, later(60)), None);
    let no_fetch = lease_of(submitted(
        &REQUEST.replace("[fetch, commit_sign, push]", "[commit_sign, push]"),
    ));
    assert_eq!(
        lease::due_transition(&no_fetch, &used, later(60)),
        Some(State::Exhausted)
    );
    let signatures_only = Usage {
        signatures: 3,
        ..fresh
    };
    assert_eq!(
        lease::due_transition(&no_fetch, &signatures_only, later(60)),
        None
    );
    // Expiry wins.
    assert_eq!(
        lease::due_transition(&no_fetch, &used, later(2 * 3600)),
        Some(State::Expired)
    );
    // Only active leases move.
    let mut closed = lease.clone();
    closed.state = State::Closed;
    assert_eq!(lease::due_transition(&closed, &used, later(9 * 3600)), None);
    // A pending ticket expires too.
    let record = TicketRecord::pending(submitted(REQUEST));
    assert_eq!(lease::pending_due(&record, later(60)), None);
    assert_eq!(
        lease::pending_due(&record, later(2 * 3600)),
        Some(State::Expired)
    );
}

// Narrowing.

#[test]
fn narrowing_accepts_only_narrower_tickets() {
    type Change = fn(&mut Ticket);
    let narrower: Vec<(&str, Change)> = vec![
        ("unchanged", |_| {}),
        ("shorter ttl", |t| t.limits.expires_at = later(3600)),
        ("fewer operations", |t| {
            t.scope.operations.remove(&Operation::Push);
        }),
        ("no commit_sign", |t| {
            t.scope.operations.remove(&Operation::CommitSign);
        }),
        ("exact branch within the pattern", |t| {
            t.scope.branches = BTreeSet::from(["agent/oauth-login".parse().unwrap()]);
        }),
        ("lower limits", |t| {
            t.limits.max_signatures = 1;
            t.limits.max_pushes = 0;
            t.limits.max_ops_per_minute = 1;
            t.limits.max_push_size = ByteSize::from_bytes(1);
        }),
        ("fewer expected paths", |t| {
            t.text
                .expected_paths
                .remove(&"tests/auth/**".parse().unwrap());
        }),
        ("stricter on_violation", |t| {
            t.on_violation = OnViolation::RevokeLease
        }),
        ("no committer emails", |t| t.scope.committer_emails.clear()),
    ];
    let submitted = submitted(REQUEST);
    for (name, change) in narrower {
        let mut signed = submitted.clone();
        change(&mut signed);
        assert!(
            narrow::check(&submitted, &signed).is_ok(),
            "{name} should be accepted"
        );
    }

    let wider: Vec<(&str, Change)> = vec![
        ("longer ttl", |t| t.limits.expires_at = later(3 * 3600)),
        ("another repo", |t| {
            t.scope.repos.insert(repo("homelab-scripts"));
        }),
        ("wider branch pattern", |t| {
            t.scope.branches = BTreeSet::from(["agent/*".parse().unwrap()]);
        }),
        ("another branch", |t| {
            t.scope.branches.insert("agent/other".parse().unwrap());
        }),
        ("force push", |t| t.scope.force_push = true),
        ("another email", |t| {
            t.scope
                .committer_emails
                .insert("user+fix@example.org".parse().unwrap());
        }),
        ("more signatures", |t| t.limits.max_signatures += 1),
        ("more pushes", |t| t.limits.max_pushes += 1),
        ("faster rate", |t| t.limits.max_ops_per_minute += 1),
        ("bigger pushes", |t| {
            t.limits.max_push_size = ByteSize::from_bytes(2_000_000)
        }),
        ("expected paths emptied", |t| t.text.expected_paths.clear()),
        ("expected path added", |t| {
            t.text.expected_paths.insert("src/**".parse().unwrap());
        }),
        ("another session key", |t| t.subject.session_key = fp('Q')),
        ("origin hint changed", |t| {
            t.subject.origin_hint = Some("x".to_owned())
        }),
        ("other template", |t| {
            t.template = "quick-fix".parse().unwrap()
        }),
        ("other id", |t| t.id = ticket_id(2)),
        ("other text", |t| t.text.title = "Something else".to_owned()),
        ("other plan", |t| t.text.plan.push("And billing".to_owned())),
        ("other signing key", |t| t.scope.signing_key = None),
        ("now amends", |t| t.text.amends = Some(ticket_id(3))),
        ("earlier creation", |t| t.created_at = later(-60)),
    ];
    for (name, change) in wider {
        let mut signed = submitted.clone();
        change(&mut signed);
        assert!(
            narrow::check(&submitted, &signed).is_err(),
            "{name} should be refused"
        );
    }
}

#[test]
fn narrowing_from_no_expected_paths_may_add_some() {
    let without = submitted(&REQUEST.replace(
        "  expected_paths: [\"src/auth/**\", \"tests/auth/**\"]\n",
        "",
    ));
    let mut signed = without.clone();
    signed.text.expected_paths.insert("src/**".parse().unwrap());
    assert!(narrow::check(&without, &signed).is_ok());
}

#[test]
fn a_narrowed_ticket_becomes_the_lease() {
    let submitted = submitted(REQUEST);
    let mut signed = submitted.clone();
    signed.limits.expires_at = later(1800);
    signed.scope.operations.remove(&Operation::Push);
    let record = TicketRecord::pending(submitted);
    let lease =
        lease::activate(&config(), &record, signed.clone(), approval(), 1, later(5)).unwrap();
    assert_eq!(lease.ticket, signed);

    let mut widened = signed.clone();
    widened.limits.max_signatures = 40;
    assert!(matches!(
        lease::activate(&config(), &record, widened, approval(), 1, later(5)),
        Err(LifecycleError::Narrowing(_))
    ));
}

// Amendments.

#[test]
fn an_applied_amendment_replaces_the_scope() {
    let lease = lease();
    let amendment_yaml = REQUEST
        .replace("[omega-code]", "[omega-code, homelab-scripts]")
        .replace(
            "  expected_paths:",
            &format!("  amends: {}\n  expected_paths:", lease.id),
        );
    let with_lease = Submission {
        amends: Some(&lease),
        now: later(600),
        ..submission(2)
    };
    let amendment = fit::submit(&config(), &request(&amendment_yaml), &with_lease).unwrap();
    let record = TicketRecord::pending(amendment.clone());

    let (updated, applied) = lease::apply_amendment(
        &config(),
        &lease,
        &record,
        amendment.clone(),
        approval(),
        later(700),
    )
    .unwrap();
    assert_eq!(updated.id, lease.id, "the lease keeps its id");
    assert_eq!(updated.cert_serial, lease.cert_serial);
    assert_eq!(updated.ticket, amendment);
    assert!(
        updated
            .ticket
            .scope
            .repos
            .contains(&repo("homelab-scripts"))
    );
    assert_eq!(applied.state, State::Applied);

    // Not for another lease, nor an ended one, nor with another session key.
    let other = lease_of(fit::submit(&config(), &request(REQUEST), &submission(3)).unwrap());
    assert!(matches!(
        lease::apply_amendment(
            &config(),
            &other,
            &record,
            amendment.clone(),
            approval(),
            later(700)
        ),
        Err(LifecycleError::AmendsAnotherLease { .. })
    ));
    let mut revoked = lease.clone();
    revoked.state = State::Revoked;
    assert!(matches!(
        lease::apply_amendment(
            &config(),
            &revoked,
            &record,
            amendment.clone(),
            approval(),
            later(700)
        ),
        Err(LifecycleError::LeaseNotActive(_))
    ));
    assert!(matches!(
        lease::apply_amendment(
            &config(),
            &lease,
            &record,
            amendment.clone(),
            approval(),
            later(2 * 3600)
        ),
        Err(LifecycleError::LeaseNotActive(_))
    ));
    let mut other_key = amendment.clone();
    other_key.subject.session_key = fp('K');
    assert!(matches!(
        lease::apply_amendment(
            &config(),
            &lease,
            &record,
            other_key,
            approval(),
            later(700)
        ),
        Err(LifecycleError::SessionKeyChanged)
    ));
    // The process the lease is bound to (watched to revoke it) can't be added, dropped or
    // moved by an amendment, even with the same session key.
    let process = |pid| writ_core::caller::CallerConstraint {
        descends_from: writ_core::caller::ProcessMatch {
            executable: "/usr/bin/agent".to_owned(),
            pid,
            generation: 1,
            code_identity: None,
        },
    };
    let mut bound_lease = lease.clone();
    bound_lease.ticket.subject.caller = Some(process(10));
    let mut same = amendment.clone();
    same.subject.caller = Some(process(10));
    let mut bound_record = record.clone();
    bound_record.ticket.subject.caller = Some(process(10));
    let mut moved = same.clone();
    moved.subject.caller = Some(process(11));
    for (lease, signed) in [
        (&lease, same.clone()),            // added
        (&bound_lease, amendment.clone()), // dropped
        (&bound_lease, moved),             // moved to another process
    ] {
        assert!(matches!(
            lease::apply_amendment(&config(), lease, &record, signed, approval(), later(700)),
            Err(LifecycleError::SubjectChanged)
        ));
    }
    // The same binding is applied: the refusals above are the subject check's doing.
    let (updated, _) = lease::apply_amendment(
        &config(),
        &bound_lease,
        &bound_record,
        same,
        approval(),
        later(700),
    )
    .unwrap();
    assert_eq!(updated.ticket.subject.caller, Some(process(10)));
    // Applied once.
    assert!(matches!(
        lease::apply_amendment(
            &config(),
            &lease,
            &applied,
            amendment,
            approval(),
            later(700)
        ),
        Err(LifecycleError::Transition {
            from: State::Applied,
            to: State::Applied
        })
    ));
}

/// A submission rejected with a reason containing `expected`.
fn assert_rejected(result: Result<writ_core::ticket::Ticket, fit::Rejection>, expected: &str) {
    match result {
        Ok(ticket) => panic!("accepted: {}", ticket.id),
        Err(rejection) => assert!(
            rejection.reasons.iter().any(|r| r.contains(expected)),
            "{expected:?} not in {:?}",
            rejection.reasons
        ),
    }
}

#[test]
fn a_task_at_the_line_limit_is_accepted() {
    // 99 newlines: 100 lines, the limit (101 is refused above).
    let yaml = REQUEST
        .replace("task: ", &format!("task: \"{}", "l\\n".repeat(99)))
        .replacen("\n  plan", "\"\n  plan", 1);
    let ticket = fit::submit(&config(), &request(&yaml), &submission(1)).unwrap();
    assert_eq!(ticket.text.task.split('\n').count(), fit::MAX_TASK_LINES);
}

#[test]
fn the_shortest_ticket_lasts_the_minimum_ttl() {
    // One second under is refused (above); exactly the minimum is accepted.
    let ticket = fit::submit(
        &config(),
        &request(&REQUEST.replace("ttl: 2h", "ttl: 300s")),
        &submission(1),
    )
    .unwrap();
    assert_eq!(
        ticket.created_at.seconds_until(ticket.limits.expires_at),
        i64::try_from(fit::MIN_TTL.seconds()).unwrap()
    );
}

#[test]
fn feedback_is_bounded_in_the_core() {
    let record = TicketRecord::pending(submitted(REQUEST));
    let max = writ_core::signed::MAX_FEEDBACK_CHARS;
    assert!(
        lease::refuse(&record, "é".repeat(max), None).is_ok(),
        "at the limit"
    );
    assert!(matches!(
        lease::refuse(&record, "é".repeat(max + 1), None),
        Err(LifecycleError::FeedbackTooLong)
    ));
    for blank in ["", "  \n\t"] {
        assert!(matches!(
            lease::refuse(&record, blank.to_owned(), None),
            Err(LifecycleError::FeedbackEmpty)
        ));
    }
}
