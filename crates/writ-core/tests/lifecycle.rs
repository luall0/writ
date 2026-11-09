//! Submission and template fit, narrowing, the lifecycle state machine and amendments.

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
use writ_core::fit::{self, Submission};
use writ_core::lease::{self, LifecycleError, State, TicketRecord, Usage};
use writ_core::narrow;
use writ_core::ticket::Operation;
use writ_core::ticket::{OnViolation, Ticket};
use writ_core::units::{ByteSize, Duration};

fn rejection(yaml: &str) -> String {
    fit::submit(&config(), &request(yaml), &submission(1))
        .unwrap_err()
        .to_string()
}

// Submission and template fit.

/// A submission whose kernel chain is `chain`.
fn from_chain(chain: &[writ_core::caller::ProcessRef]) -> Result<Ticket, fit::Rejection> {
    let yaml = format!("caller:\n  descends_from: {{ pid: 42 }}\n{REQUEST}");
    let submission = fit::Submission {
        chain: Some(chain),
        ..submission(1)
    };
    fit::submit(&config(), &request(&yaml), &submission)
}

#[test]
fn a_binding_takes_the_kernel_s_process_within_the_bounds() {
    use std::os::unix::ffi::OsStrExt as _;
    use writ_core::caller::{CodeIdentity, MAX_EXECUTABLE_BYTES, ProcessRef};
    let process = |executable: std::path::PathBuf| ProcessRef {
        pid: 42,
        generation: 9,
        executable,
        code_identity: Some(CodeIdentity {
            signing_id: "dev.writ.writ".to_owned(),
            team_id: None,
        }),
    };
    let at = format!("/{}", "a".repeat(MAX_EXECUTABLE_BYTES - 1));
    let ticket = from_chain(&[process(at.clone().into())]).unwrap();
    let bound = ticket.subject.caller.unwrap().descends_from;
    assert_eq!((bound.executable, bound.pid, bound.generation), (at, 42, 9));
    assert_eq!(bound.code_identity.unwrap().signing_id, "dev.writ.writ");
    let past = format!("/{}", "a".repeat(MAX_EXECUTABLE_BYTES));
    let not_utf8 = std::ffi::OsStr::from_bytes(b"/opt/\xff/writ");
    for (executable, expected) in [
        (
            past.into(),
            "caller.descends_from.pid: 42: invalid caller constraint: the executable path is \
             too long",
        ),
        (
            std::path::PathBuf::from(not_utf8),
            "caller.descends_from.pid: 42: its executable's path is not UTF-8",
        ),
    ] {
        let rejection = from_chain(&[process(executable)]).unwrap_err();
        assert!(rejection.session);
        assert_eq!(rejection.reasons, [expected.to_owned()]);
    }
}

#[test]
fn a_submitted_ticket_is_complete() {
    let ticket = submitted(REQUEST);
    assert_eq!(ticket.id, ticket_id(1));
    assert_eq!(ticket.created_at, t0());
    assert_eq!(ticket.limits.expires_at, later(2 * 3600));
    assert_eq!(ticket.subject.session_key, fp('S'));
    assert_eq!(ticket.text.revision, 1);
    // Filled from the template: committer emails, signing key.
    assert_eq!(ticket.common.committer_emails.len(), 1);
    assert_eq!(
        ticket.common.signing_key.as_ref().unwrap().as_str(),
        "agent-ed25519-01"
    );
}

#[test]
fn omitted_limits_take_the_template_maximum() {
    let ticket = submitted(
        &REQUEST
            .replace("  ttl: 2h\n", "")
            .replace("      max_signatures: 3\n", "")
            .replace("      max_push_size: 1MB\n", ""),
    );
    assert_eq!(ticket.limits.expires_at, later(4 * 3600));
    assert_eq!(om(&ticket).limits.max_signatures, 50);
    assert_eq!(
        om(&ticket).limits.max_push_size,
        ByteSize::from_bytes(50_000_000)
    );
}

#[test]
fn the_only_fitting_template_is_chosen() {
    let unnamed = REQUEST.replace("    template: feature-branch\n", "");
    assert_eq!(om(&submitted(&unnamed)).template.as_str(), "feature-branch");
    // agent/fix-* fits feature-branch and quick-fix: the agent must name one.
    let ambiguous = unnamed
        .replace("agent/oauth-*", "agent/fix-*")
        .replace("ttl: 2h", "ttl: 1h");
    let error = rejection(&ambiguous);
    assert!(
        error.contains("fits several templates (feature-branch, quick-fix)"),
        "{error}"
    );
    let named = ambiguous.replace(
        "  omega-code:\n",
        "  omega-code:\n    template: quick-fix\n",
    );
    assert_eq!(om(&submitted(&named)).template.as_str(), "quick-fix");
}

/// Without commit_sign the committer emails are unused, yet the approver reads them: each one
/// must still be an email one of the lease's templates allows.
#[test]
fn committer_emails_without_signing_stay_within_the_templates() {
    let fetch_only = REQUEST.replace("[fetch, commit_sign, push]", "[fetch]");
    let with = |email: &str| format!("common:\n  committer_emails: [\"{email}\"]\n{fetch_only}");
    let ticket = submitted(&with("user+agent@example.org"));
    assert_eq!(
        ticket.common.committer_emails,
        ["user+agent@example.org".parse().unwrap()].into()
    );
    let error = rejection(&with("user@example.org"));
    assert!(
        error.contains(
            "common.committer_emails: user@example.org is not allowed by any of the templates"
        ),
        "{error}"
    );
}

#[test]
fn tickets_outside_every_template_are_rejected_with_reasons() {
    let cases = [
        (
            REQUEST.replace("agent/oauth-*", "main"),
            "branch main is not within the template's branches (agent/*)",
        ),
        (
            REQUEST.replace("  omega-code:\n", "  dotfiles:\n"),
            "repo dotfiles does not allow the template",
        ),
        (
            REQUEST.replace("  omega-code:\n", "  nope:\n"),
            "repo nope is not in the registry",
        ),
        (
            REQUEST.replace("ttl: 2h", "ttl: 5h"),
            "over the template feature-branch's max_ttl (4h)",
        ),
        (
            REQUEST.replace("max_signatures: 3", "max_signatures: 51"),
            "repos.omega-code.limits.max_signatures is 51, over the template's 50",
        ),
        (
            REQUEST.replace("max_push_size: 1MB", "max_push_size: 51MB"),
            "limits.max_push_size is 51000000",
        ),
        (
            REQUEST.replace("max_ops_per_minute: 5", "max_ops_per_minute: 0"),
            "max_ops_per_minute must be at least 1",
        ),
        (
            REQUEST.replace("max_push_size: 1MB", "max_push_size: 0"),
            "repos.omega-code.limits.max_push_size must be at least 1 byte",
        ),
        (
            REQUEST.replace(
                "    branches: [\"agent/oauth-*\"]\n",
                "    branches: [\"agent/oauth-*\"]\n    force_push: true\n",
            ),
            "force_push is not allowed",
        ),
        (
            format!("common:\n  committer_emails: [\"user@example.org\"]\n{REQUEST}"),
            "committer email user@example.org is not allowed",
        ),
        (
            REQUEST.replace("    branches: [\"agent/oauth-*\"]\n", ""),
            "repos.omega-code: commit_sign and push need at least one branch",
        ),
        (
            REQUEST.replace("template: feature-branch", "template: nope"),
            "template nope does not exist",
        ),
        (
            REQUEST.replace("title: Add OAuth login", "title: \"  \""),
            "ticket.title is empty",
        ),
        (
            REQUEST.replace(
                "title: Add OAuth login",
                &format!("title: {}", "x".repeat(201)),
            ),
            "ticket.title is too long",
        ),
        (
            REQUEST.replace(
                "title: Add OAuth login",
                "title: \"Add\\nScope (enforced)\"",
            ),
            "ticket.title must be one line",
        ),
        (
            REQUEST.replace("title: Add OAuth login", "title: \"Add\\rlogin\""),
            "ticket.title must be one line",
        ),
        (
            REQUEST
                .replace("task: ", &format!("task: \"{}", "l\\n".repeat(100)))
                .replacen("\n  plan", "\"\n  plan", 1),
            "ticket.task has 101 lines, at most 100",
        ),
        (
            REQUEST.replace(
                "- Feature flag and tests",
                "- \"Feature flag\\nScope (enforced)\"",
            ),
            "a plan step must be one line",
        ),
        (
            REQUEST.replace("ttl: 2h", "ttl: 0s"),
            "limits.ttl is 0s, under the minimum of 5m",
        ),
        (
            REQUEST.replace("ttl: 2h", "ttl: 299s"),
            "limits.ttl is 299s, under the minimum of 5m",
        ),
        (
            REQUEST.replace("ttl: 2h", "ttl: 99999999d"),
            "limits.ttl is too long",
        ),
        (
            REQUEST
                .replace("    template: feature-branch\n", "")
                .replace("agent/oauth-*", "main"),
            "repos.omega-code fits no template",
        ),
        (
            format!("caller:\n  descends_from: {{ pid: 1 }}\n{REQUEST}"),
            "caller.descends_from.pid: a session binding needs local mode",
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

/// The bounds the review after M5.5 added (S8, L20), each on both sides: the bytes of every
/// `expected_paths` pattern together (what each commit's paths are matched against), and the
/// number of branches (what the approver reads).
#[test]
fn expected_paths_and_branches_are_bounded_on_both_sides() {
    use writ_core::fit::{MAX_BRANCHES, MAX_EXPECTED_PATHS_BYTES};
    // 16 patterns of 1,024 bytes: exactly the bound; then a 17th of one byte.
    let paths = |extra: bool| {
        let mut all: Vec<String> = (0..16)
            .map(|i| format!("d{i:02}/{}", "x".repeat(1020)))
            .collect();
        if extra {
            all.push("z".to_owned());
        }
        let total: usize = all.iter().map(String::len).sum();
        let list = all
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(", ");
        (
            total,
            REQUEST.replace(
                r#"expected_paths: ["src/auth/**", "tests/auth/**"]"#,
                &format!("expected_paths: [{list}]"),
            ),
        )
    };
    let (total, at) = paths(false);
    assert_eq!(total, MAX_EXPECTED_PATHS_BYTES);
    assert!(fit::submit(&config(), &request(&at), &submission(1)).is_ok());
    let (total, over) = paths(true);
    assert_eq!(total, MAX_EXPECTED_PATHS_BYTES + 1);
    let error = rejection(&over);
    assert!(
        error.contains(&format!(
            "expected_paths (bytes in all, every repository) is too long ({}, at most {MAX_EXPECTED_PATHS_BYTES})",
            MAX_EXPECTED_PATHS_BYTES + 1
        )),
        "{error}"
    );
    // Branches: 50 within the template's `agent/*`, then 51.
    let branches = |n: usize| {
        let list = (0..n)
            .map(|i| format!("\"agent/oauth-{i}\""))
            .collect::<Vec<_>>()
            .join(", ");
        REQUEST.replace(
            r#"branches: ["agent/oauth-*"]"#,
            &format!("branches: [{list}]"),
        )
    };
    assert!(fit::submit(&config(), &request(&branches(MAX_BRANCHES)), &submission(1)).is_ok());
    let error = rejection(&branches(MAX_BRANCHES + 1));
    assert!(
        error.contains(&format!(
            "repos.omega-code.branches is too long ({}, at most {MAX_BRANCHES})",
            MAX_BRANCHES + 1
        )),
        "{error}"
    );
}

#[test]
fn push_needs_a_push_mode_allowed_by_both() {
    // dotfiles only allows direct_ssh; quick-fix only gateway.
    let yaml = REQUEST
        .replace("template: feature-branch", "template: quick-fix")
        .replace("  omega-code:\n", "  dotfiles:\n")
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
        "    expected_paths: [\"src/auth/**\", \"tests/auth/**\"]\n",
        "",
    );
    let error = fit::submit(&config, &request(&without), &submission(1)).unwrap_err();
    assert!(
        error.to_string().contains("requires expected_paths"),
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
    let revision = REQUEST.replace("ticket:\n", &format!("ticket:\n  revises: {}\n", first.id));
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
    let revision = REQUEST.replace("ticket:\n", &format!("ticket:\n  revises: {}\n", first.id));
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
    let amendment = REQUEST.replace("ticket:\n", &format!("ticket:\n  amends: {}\n", lease.id));
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
        (Active, Renewed),
        (Expired, Renewed),
        (Exhausted, Renewed),
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
    assert!(matches!(
        "submitted".parse::<State>(),
        Err(LifecycleError::UnknownState(s)) if s == "submitted"
    ));
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
    let used = usage_in(3, 2, 0);
    // It allows fetch, which has no count: never exhausted.
    assert_eq!(lease::due_transition(&lease, &used, later(60)), None);
    let no_fetch = lease_of(submitted(
        &REQUEST.replace("[fetch, commit_sign, push]", "[commit_sign, push]"),
    ));
    assert_eq!(
        lease::due_transition(&no_fetch, &used, later(60)),
        Some(State::Exhausted)
    );
    let signatures_only = usage_in(3, 0, 0);
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
            omega(t).operations.remove(&Operation::Push);
        }),
        ("no commit_sign", |t| {
            omega(t).operations.remove(&Operation::CommitSign);
        }),
        ("exact branch within the pattern", |t| {
            omega(t).branches = BTreeSet::from(["agent/oauth-login".parse().unwrap()]);
        }),
        ("lower limits", |t| {
            omega(t).limits.max_signatures = 1;
            omega(t).limits.max_pushes = 0;
            t.limits.max_ops_per_minute = 1;
            omega(t).limits.max_push_size = ByteSize::from_bytes(1);
        }),
        ("fewer expected paths", |t| {
            omega(t)
                .expected_paths
                .remove(&"tests/auth/**".parse().unwrap());
        }),
        ("stricter on_violation", |t| {
            t.on_violation = OnViolation::RevokeLease
        }),
        ("no committer emails", |t| t.common.committer_emails.clear()),
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
            let terms = om(t).clone();
            t.repos.insert(repo("homelab-scripts"), terms);
        }),
        ("wider branch pattern", |t| {
            omega(t).branches = BTreeSet::from(["agent/*".parse().unwrap()]);
        }),
        ("another branch", |t| {
            omega(t).branches.insert("agent/other".parse().unwrap());
        }),
        ("force push", |t| omega(t).force_push = true),
        ("another email", |t| {
            t.common
                .committer_emails
                .insert("user+fix@example.org".parse().unwrap());
        }),
        ("more signatures", |t| omega(t).limits.max_signatures += 1),
        ("more pushes", |t| omega(t).limits.max_pushes += 1),
        ("faster rate", |t| t.limits.max_ops_per_minute += 1),
        ("bigger pushes", |t| {
            omega(t).limits.max_push_size = ByteSize::from_bytes(2_000_000)
        }),
        ("expected paths emptied", |t| {
            omega(t).expected_paths.clear()
        }),
        ("expected path added", |t| {
            omega(t).expected_paths.insert("src/**".parse().unwrap());
        }),
        ("another session key", |t| t.subject.session_key = fp('Q')),
        ("origin hint changed", |t| {
            t.subject.origin_hint = Some("x".to_owned())
        }),
        ("other template", |t| {
            omega(t).template = "quick-fix".parse().unwrap()
        }),
        ("other id", |t| t.id = ticket_id(2)),
        ("other text", |t| t.text.title = "Something else".to_owned()),
        ("other plan", |t| t.text.plan.push("And billing".to_owned())),
        ("other signing key", |t| t.common.signing_key = None),
        ("now amends", |t| t.text.amends = Some(ticket_id(3))),
        ("earlier creation", |t| t.created_at = later(-60)),
    ];
    for (name, change) in wider {
        let mut signed = submitted.clone();
        change(&mut signed);
        // Refused for exactly this change (the review after M5.5: any refusal passed).
        let reasons = narrow::check(&submitted, &signed).unwrap_err().reasons;
        let expected = match name {
            "longer ttl" => "limits.expires_at raised",
            "another repo" => "repos adds homelab-scripts",
            "wider branch pattern" => "repos.omega-code.branches adds agent/*",
            "another branch" => "repos.omega-code.branches adds agent/other",
            "force push" => "repos.omega-code.force_push turned on",
            "another email" => "common.committer_emails adds user+fix@example.org",
            "more signatures" => "repos.omega-code.limits.max_signatures raised",
            "more pushes" => "repos.omega-code.limits.max_pushes raised",
            "faster rate" => "limits.max_ops_per_minute raised",
            "bigger pushes" => "repos.omega-code.limits.max_push_size raised",
            "expected paths emptied" => {
                "repos.omega-code.expected_paths emptied (turns the path check off)"
            }
            "expected path added" => "repos.omega-code.expected_paths adds src/**",
            "another session key" | "origin hint changed" => "subject changed",
            "other template" => "repos.omega-code.template changed",
            "other id" => "id changed",
            "other text" => "ticket.title changed",
            "other plan" => "ticket.plan changed",
            "other signing key" => "common.signing_key changed",
            "now amends" => "ticket.amends changed",
            "earlier creation" => "created_at changed",
            other => panic!("no reason written for {other}"),
        };
        assert_eq!(reasons, [expected], "{name}");
    }
}

#[test]
fn narrowing_from_no_expected_paths_may_add_some() {
    let without = submitted(&REQUEST.replace(
        "    expected_paths: [\"src/auth/**\", \"tests/auth/**\"]\n",
        "",
    ));
    let mut signed = without.clone();
    omega(&mut signed)
        .expected_paths
        .insert("src/**".parse().unwrap());
    assert!(narrow::check(&without, &signed).is_ok());
}

#[test]
fn a_narrowed_ticket_becomes_the_lease() {
    let submitted = submitted(REQUEST);
    let mut signed = submitted.clone();
    signed.limits.expires_at = later(1800);
    omega(&mut signed).operations.remove(&Operation::Push);
    let record = TicketRecord::pending(submitted);
    let lease =
        lease::activate(&config(), &record, signed.clone(), approval(), 1, later(5)).unwrap();
    assert_eq!(lease.ticket, signed);

    let mut widened = signed.clone();
    omega(&mut widened).limits.max_signatures = 40;
    assert!(matches!(
        lease::activate(&config(), &record, widened, approval(), 1, later(5)),
        Err(LifecycleError::Narrowing(_))
    ));
}

// Amendments.

#[test]
fn an_applied_amendment_replaces_the_scope() {
    let lease = lease();
    let amendment_yaml = with_repos(REQUEST, &["omega-code", "homelab-scripts"])
        .replace("ticket:\n", &format!("ticket:\n  amends: {}\n", lease.id));
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
    assert!(updated.ticket.repos.contains_key(&repo("homelab-scripts")));
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
        i64::try_from(fit::DEFAULT_MIN_TTL.seconds()).unwrap()
    );
}

#[test]
fn the_minimum_ttl_is_the_daemon_s_on_both_sides() {
    // `writd.yaml`'s `min_ttl` at 30 s: one second under refused, naming it; exactly it accepted.
    let at = |ttl: &str| {
        let mut submission = submission(1);
        submission.min_ttl = Duration::from_seconds(30);
        fit::submit(
            &config(),
            &request(&REQUEST.replace("ttl: 2h", &format!("ttl: {ttl}"))),
            &submission,
        )
    };
    let refused = at("29s").unwrap_err();
    assert_eq!(
        refused.reasons,
        ["limits.ttl is 29s, under the minimum of 30s"],
        "{refused}"
    );
    let ticket = at("30s").unwrap();
    assert_eq!(
        ticket.created_at.seconds_until(ticket.limits.expires_at),
        30
    );
}

#[test]
fn a_template_s_max_ttl_is_at_least_the_daemon_s_minimum() {
    // A template of 1 minute: under the default minimum (5 minutes), refused naming the
    // field; accepted by a daemon whose minimum is 1 minute, refused by one at 61 seconds.
    let policy = writ_core::config::PolicyConfig::from_yaml;
    let text = common::POLICY.replace("max_ttl: 4h", "max_ttl: 1m");
    assert_ne!(
        text,
        common::POLICY,
        "the fixture's template has `max_ttl: 4h`"
    );
    let refused = policy(&text).unwrap_err().to_string();
    assert!(
        refused.contains("max_ttl") && refused.contains("must be at least 5m"),
        "{refused}"
    );
    let with = |seconds| {
        writ_core::config::PolicyConfig::from_yaml_with_min_ttl(
            &text,
            Duration::from_seconds(seconds),
        )
    };
    assert!(with(60).is_ok());
    let refused = with(61).unwrap_err().to_string();
    assert!(refused.contains("must be at least 61s"), "{refused}");
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

/// The review after M5.5 (L21): with no template named, a template the request can't be built
/// against (here: its `max_ttl`, the default TTL, runs past the end of time) was the end of the
/// search, and the request was rejected though another template fits it.
#[test]
fn a_template_the_request_cannot_be_built_against_does_not_hide_one_it_fits() {
    let policy = POLICY.replacen("    max_ttl: 4h\n", "    max_ttl: 99999999d\n", 1);
    assert_ne!(policy, POLICY, "the fixture changed");
    let config = writ_core::config::PolicyConfig::from_yaml(&policy).unwrap();
    // No TTL: feature-branch's default overflows. The lease's TTL comes from the templates
    // each repository fits (the strictest), so named, it is said; quick-fix named, it fits.
    let yaml = REQUEST
        .replace("agent/oauth-*", "agent/fix-*")
        .replace("  ttl: 2h\n", "");
    let error = fit::submit(&config, &request(&yaml), &submission(1)).unwrap_err();
    assert_eq!(error.reasons, ["limits.ttl is too long"], "{error}");
    let quick = yaml.replace("template: feature-branch", "template: quick-fix");
    let ticket = fit::submit(&config, &request(&quick), &submission(1)).unwrap();
    assert_eq!(om(&ticket).template.as_str(), "quick-fix");
    // Unnamed, both allow the repository and fit its terms: the agent must name one.
    let unnamed = yaml.replace("    template: feature-branch\n", "");
    let error = fit::submit(&config, &request(&unnamed), &submission(1)).unwrap_err();
    assert_eq!(
        error.reasons,
        [
            "repos.omega-code fits several templates (feature-branch, quick-fix): name one in \
          repos.omega-code.template"
        ]
    );
}

/// The review after M5.5 (S7): the gateway handed git the lease's `max_push_size`, though the
/// policy decides on the smaller of the lease's and the template's (one a signed change may
/// have lowered since); and 0, which git reads as no limit, was a valid limit.
#[test]
fn the_push_size_git_gets_is_the_smaller_of_the_lease_s_and_the_template_s() {
    let ticket = submitted(REQUEST);
    let config = config();
    let template = config.template(&om(&ticket).template).unwrap();
    // The lease asks 1MB, the template allows 50MB: the lease's.
    assert_eq!(
        writ_core::policy::max_push_size(om(&ticket), template),
        1_000_000
    );
    // The template lowered to 1 byte under it: the template's.
    let lowered = POLICY.replacen("max_push_size: 50MB", "max_push_size: 1", 1);
    let config = writ_core::config::PolicyConfig::from_yaml(&lowered).unwrap();
    let template = config.template(&om(&ticket).template).unwrap();
    assert_eq!(writ_core::policy::max_push_size(om(&ticket), template), 1);
    // A byte, the least a limit can be: taken (never 0).
    let one = REQUEST.replace("max_push_size: 1MB", "max_push_size: 1");
    let t = fit::submit(&self::config(), &request(&one), &submission(1)).unwrap();
    assert_eq!(om(&t).limits.max_push_size.bytes(), 1);
}

// Renewals.

/// [`REQUEST`] as a renewal of `lease`: no template named, an hour more, the emails and paths
/// left out (the lease's).
fn renewal_yaml(lease: &writ_core::lease::Lease) -> String {
    REQUEST
        .replace("    template: feature-branch\n", "")
        .replace("  ttl: 2h\n", "  ttl: 1h\n")
        .replace(
            "    expected_paths: [\"src/auth/**\", \"tests/auth/**\"]\n",
            "",
        )
        .replace("ticket:\n", &format!("ticket:\n  renews: {}\n", lease.id))
}

fn renewing<'a>(
    lease: &'a writ_core::lease::Lease,
    renewals: u32,
    grace: u64,
    at: i64,
) -> Submission<'a> {
    Submission {
        renews: Some(lease::Renewed {
            lease,
            renewals,
            grace: Duration::from_seconds(grace),
        }),
        now: later(at),
        ..submission(5)
    }
}

/// The lease of [`REQUEST`] (it ends at `later(7200)`), in `state`.
fn lease_in(state: State) -> writ_core::lease::Lease {
    let mut lease = lease();
    lease.state = state;
    lease
}

#[test]
fn a_renewal_continues_its_lease_under_a_new_one() {
    let lease = lease_in(State::Expired);
    let renewal = fit::submit(
        &config(),
        &request(&renewal_yaml(&lease)),
        &renewing(&lease, 0, 86_400, 7_260),
    )
    .unwrap();
    // The lease's template, emails and paths; its own time and id.
    assert_eq!(om(&renewal).template, om(&lease.ticket).template);
    assert_eq!(
        renewal.common.committer_emails,
        lease.ticket.common.committer_emails
    );
    assert_eq!(
        om(&renewal).expected_paths,
        om(&lease.ticket).expected_paths
    );
    assert_eq!(renewal.text.renews.as_ref(), Some(&lease.id));
    assert_eq!(renewal.limits.expires_at, later(7_260 + 3_600));
    assert_eq!(renewal.lease_id(), &renewal.id, "a lease of its own");

    let record = TicketRecord::pending(renewal.clone());
    let renewed = lease::Renewed {
        lease: &lease,
        renewals: 0,
        grace: Duration::from_seconds(86_400),
    };
    let new = lease::activate_renewal(
        &config(),
        &record,
        renewal.clone(),
        approval(),
        9,
        renewed,
        later(7_300),
    )
    .unwrap();
    assert_eq!(new.id, renewal.id);
    assert_eq!(new.state, State::Active);
    assert_eq!(new.cert_serial, 9);
    // A renewal is never activated as a plain ticket.
    assert_eq!(
        lease::activate(&config(), &record, renewal, approval(), 9, later(7_300)),
        Err(LifecycleError::RenewalWithoutLease)
    );
}

#[test]
fn renew_grace_holds_on_both_sides() {
    let lease = lease_in(State::Expired);
    let yaml = renewal_yaml(&lease);
    let end = 7_200;
    // One second before the grace is over: taken; at it: refused, naming it.
    assert!(
        fit::submit(
            &config(),
            &request(&yaml),
            &renewing(&lease, 0, 600, end + 599)
        )
        .is_ok()
    );
    let refused = fit::submit(
        &config(),
        &request(&yaml),
        &renewing(&lease, 0, 600, end + 600),
    )
    .unwrap_err();
    assert_eq!(
        refused.reasons,
        [format!(
            "lease {} can't be renewed: it ended at 2026-10-31T16:02:11Z, more than renew_grace (10m) ago",
            lease.id
        )]
    );
    // With no grace, a lease still in force is renewable, one past its end isn't.
    let active = lease_in(State::Active);
    assert!(
        fit::submit(
            &config(),
            &request(&yaml),
            &renewing(&active, 0, 0, end - 1)
        )
        .is_ok()
    );
    assert_rejected(
        fit::submit(&config(), &request(&yaml), &renewing(&active, 0, 0, end)),
        "more than renew_grace (0s) ago",
    );
    // A used-up lease is renewable too.
    let exhausted = lease_in(State::Exhausted);
    assert!(fit::submit(&config(), &request(&yaml), &renewing(&exhausted, 0, 0, 600)).is_ok());
}

#[test]
fn only_an_active_expired_or_used_up_lease_of_the_same_session_is_renewed() {
    for (state, why) in [
        (State::Revoked, "it is revoked"),
        (State::Closed, "it is closed"),
        (State::Renewed, "it was renewed already"),
    ] {
        let lease = lease_in(state);
        assert_rejected(
            fit::submit(
                &config(),
                &request(&renewal_yaml(&lease)),
                &renewing(&lease, 0, 86_400, 600),
            ),
            &format!("lease {} can't be renewed: {why}", lease.id),
        );
    }
    let lease = lease_in(State::Active);
    // Another session: the lease doesn't exist.
    let mut elsewhere = renewing(&lease, 0, 86_400, 600);
    elsewhere.session_key = fp('K');
    assert_rejected(
        fit::submit(&config(), &request(&renewal_yaml(&lease)), &elsewhere),
        &format!("ticket {} (renews) does not exist", lease.id),
    );
    // Not both an amendment and a renewal.
    let both =
        renewal_yaml(&lease).replace("  renews:", &format!("  amends: {}\n  renews:", lease.id));
    let mut with_both = renewing(&lease, 0, 86_400, 600);
    with_both.amends = Some(&lease);
    assert_rejected(
        fit::submit(&config(), &request(&both), &with_both),
        "a ticket can't both amend and renew a lease",
    );
    // Another template.
    let other = renewal_yaml(&lease).replace(
        "  omega-code:\n",
        "  omega-code:\n    template: quick-fix\n",
    );
    assert_rejected(
        fit::submit(
            &config(),
            &request(&other),
            &renewing(&lease, 0, 86_400, 600),
        ),
        "repos.omega-code: a renewal keeps its lease's template (feature-branch), not quick-fix",
    );
}

#[test]
fn a_renewal_stays_within_its_lease() {
    let lease = lease_in(State::Active);
    let yaml = renewal_yaml(&lease);
    let wider = [
        (
            with_repos(&yaml, &["omega-code", "homelab-scripts"]),
            "repos adds homelab-scripts",
        ),
        (
            yaml.replace("agent/oauth-*", "agent/*"),
            "repos.omega-code.branches adds agent/*",
        ),
        (
            yaml.replace(
                "    branches: [\"agent/oauth-*\"]\n",
                "    branches: [\"agent/oauth-*\"]\n    expected_paths: [\"src/auth/**\", \"docs/**\"]\n",
            ),
            "repos.omega-code.expected_paths adds docs/**",
        ),
    ];
    for (yaml, expected) in wider {
        let result = fit::submit(
            &config(),
            &request(&yaml),
            &renewing(&lease, 0, 86_400, 600),
        );
        assert_rejected(
            result,
            &format!("wider than lease {}: {expected}", lease.id),
        );
    }
    // An email the template allows and the lease doesn't have.
    let mut fewer = lease.clone();
    fewer.ticket.common.committer_emails.clear();
    fewer
        .ticket
        .common
        .committer_emails
        .insert("user+other@example.org".parse().unwrap());
    assert_rejected(
        fit::submit(
            &config(),
            &request(&format!(
                "common:\n  committer_emails: [\"user+agent@example.org\"]\n{yaml}"
            )),
            &renewing(&fewer, 0, 86_400, 600),
        ),
        "common.committer_emails adds user+agent@example.org",
    );
    // Less strict on violations, and an operation the lease didn't have.
    let mut strict = lease.clone();
    strict.ticket.on_violation = OnViolation::RevokeLease;
    omega(&mut strict.ticket)
        .operations
        .remove(&Operation::Fetch);
    let result = fit::submit(
        &config(),
        &request(&yaml),
        &renewing(&strict, 0, 86_400, 600),
    );
    assert_rejected(result.clone(), "on_violation made less strict");
    assert_rejected(result, "repos.omega-code.operations adds fetch");
    // Narrower is fine.
    let narrower = yaml.replace("agent/oauth-*", "agent/oauth-login");
    assert!(
        fit::submit(
            &config(),
            &request(&narrower),
            &renewing(&lease, 0, 86_400, 600)
        )
        .is_ok()
    );
}

#[test]
fn max_renewals_holds_on_both_sides() {
    let policy = POLICY.replacen(
        "    paths_check: warn\n",
        "    paths_check: warn\n    max_renewals: 2\n",
        1,
    );
    assert_ne!(policy, POLICY, "the fixture changed");
    let config = writ_core::config::PolicyConfig::from_yaml(&policy).unwrap();
    let lease = lease_in(State::Active);
    let yaml = renewal_yaml(&lease);
    // The lease is the chain's first renewal: a second is allowed, a third isn't.
    assert!(fit::submit(&config, &request(&yaml), &renewing(&lease, 1, 86_400, 600)).is_ok());
    assert_rejected(
        fit::submit(&config, &request(&yaml), &renewing(&lease, 2, 86_400, 600)),
        "template feature-branch allows 2 renewals of a lease",
    );
    // No limit without the key.
    assert!(
        fit::submit(
            &self::config(),
            &request(&yaml),
            &renewing(&lease, 1_000, 86_400, 600)
        )
        .is_ok()
    );
}

#[test]
fn a_renewal_is_checked_again_when_it_is_signed() {
    let lease = lease_in(State::Expired);
    let renewal = fit::submit(
        &config(),
        &request(&renewal_yaml(&lease)),
        &renewing(&lease, 0, 600, 7_300),
    )
    .unwrap();
    let record = TicketRecord::pending(renewal.clone());
    let at = |lease: &writ_core::lease::Lease, now: i64| {
        lease::activate_renewal(
            &config(),
            &record,
            renewal.clone(),
            approval(),
            9,
            lease::Renewed {
                lease,
                renewals: 0,
                grace: Duration::from_seconds(600),
            },
            later(now),
        )
    };
    assert!(at(&lease, 7_799).is_ok());
    // Signed once the grace is over.
    assert!(
        matches!(at(&lease, 7_800), Err(LifecycleError::Renewal(reasons)) if reasons[0].contains("more than renew_grace"))
    );
    // The lease was renewed (or revoked) meanwhile.
    assert_eq!(
        at(&lease_in(State::Renewed), 7_300),
        Err(LifecycleError::Transition {
            from: State::Renewed,
            to: State::Renewed
        })
    );
    // The lease's terms narrowed meanwhile (an amendment): the renewal is now wider.
    let mut amended = lease.clone();
    omega(&mut amended.ticket).branches = BTreeSet::from(["agent/oauth-login".parse().unwrap()]);
    assert!(
        matches!(at(&amended, 7_300), Err(LifecycleError::Renewal(reasons)) if reasons.iter().any(|r| r.contains("repos.omega-code.branches adds agent/oauth-*")))
    );
    // Another lease.
    let other = lease_of(fit::submit(&config(), &request(REQUEST), &submission(3)).unwrap());
    assert!(matches!(
        at(&other, 7_300),
        Err(LifecycleError::RenewsAnotherLease { .. })
    ));
}

#[test]
fn an_amendment_ends_with_its_lease() {
    let lease = lease();
    // Asked for 4h, ten minutes in: capped at the lease's end.
    let yaml = REQUEST
        .replace("ttl: 2h", "ttl: 4h")
        .replace("ticket:\n", &format!("ticket:\n  amends: {}\n", lease.id));
    let with_lease = Submission {
        amends: Some(&lease),
        now: later(600),
        ..submission(2)
    };
    let amendment = fit::submit(&config(), &request(&yaml), &with_lease).unwrap();
    assert_eq!(amendment.limits.expires_at, lease.ticket.limits.expires_at);
    // One that would end later (built by hand: the daemon never makes one) is refused.
    let mut longer = amendment.clone();
    longer.limits.expires_at = lease.ticket.limits.expires_at.saturating_sub_seconds(-1);
    let record = TicketRecord::pending(longer.clone());
    assert_eq!(
        lease::apply_amendment(&config(), &lease, &record, longer, approval(), later(700)),
        Err(LifecycleError::AmendmentOutlivesLease {
            amendment: later(7_201),
            lease: later(7_200),
        })
    );
    // At the lease's end exactly: applied.
    let record = TicketRecord::pending(amendment.clone());
    assert!(
        lease::apply_amendment(
            &config(),
            &lease,
            &record,
            amendment,
            approval(),
            later(700)
        )
        .is_ok()
    );
}

#[test]
fn the_estimate_is_shown_never_checked_and_bounded() {
    let with = |coding: &str| {
        REQUEST.replace(
            "ticket:\n",
            &format!("ticket:\n  estimate:\n    coding: {coding}\n    ci: 20m\n"),
        )
    };
    let ticket = fit::submit(&config(), &request(&with("30d")), &submission(1)).unwrap();
    let estimate = ticket.text.estimate.unwrap();
    assert_eq!(estimate.coding, Some(Duration::from_seconds(30 * 86_400)));
    assert_eq!(estimate.checks, None);
    assert_eq!(
        estimate.total(),
        Some(Duration::from_seconds(30 * 86_400 + 1_200))
    );
    assert_rejected(
        fit::submit(&config(), &request(&with("2592001s")), &submission(1)),
        "ticket.estimate.coding is over 30d",
    );
    assert_eq!(writ_core::ticket::Estimate::default().total(), None);
}

#[test]
fn a_ticket_file_is_checked_without_the_daemon_as_the_daemon_would() {
    // Clean: nothing to say (fitting a template is the daemon's to check).
    assert!(fit::check_request(&request(REQUEST)).is_empty());
    let cases = [
        (REQUEST.replace("title: Add OAuth login", "title: \"  \""), "ticket.title is empty"),
        (REQUEST.replace("title: Add OAuth login", &format!("title: {}", "x".repeat(201))), "ticket.title is too long (201, at most 200)"),
        (REQUEST.replace("    branches: [\"agent/oauth-*\"]\n", ""), "repos.omega-code: commit_sign and push need at least one branch"),
        (REQUEST.replace("ttl: 2h", "ttl: 9s"), "limits.ttl is 9s, under 10s, the least any daemon takes"),
        (REQUEST.replace("max_ops_per_minute: 5", "max_ops_per_minute: 0"), "limits.max_ops_per_minute must be at least 1"),
        (REQUEST.replace("max_push_size: 1MB", "max_push_size: 0"), "repos.omega-code.limits.max_push_size must be at least 1 byte"),
        (
            REQUEST.replace("ticket:\n", "ticket:\n  estimate: { ci: 31d }\n"),
            "ticket.estimate.ci is over 30d",
        ),
        (
            REQUEST.replace("ticket:\n", "ticket:\n  amends: wrt_01JD8X0000000000000000000A\n  renews: wrt_01JD8X0000000000000000000A\n"),
            "a ticket can't both amend and renew a lease",
        ),
    ];
    for (yaml, expected) in cases {
        let reasons = fit::check_request(&request(&yaml));
        assert!(
            reasons.iter().any(|r| r == expected),
            "{expected:?} not in {reasons:?}"
        );
        // The daemon refuses it too (the TTL against its own min_ttl, said its way).
        let daemon = match expected {
            e if e.starts_with("limits.ttl") => "under the minimum of 5m",
            // The daemon looks the links up first: unknown here.
            e if e.contains("amend and renew") => "(amends) does not exist",
            e => e,
        };
        let rejected = fit::submit(&config(), &request(&yaml), &submission(1));
        assert!(
            rejected
                .as_ref()
                .is_err_and(|r| r.to_string().contains(daemon)),
            "the daemon on {expected:?}: {rejected:?}"
        );
    }
    // At the bounds: clean.
    let at = REQUEST
        .replace(
            "title: Add OAuth login",
            &format!("title: {}", "x".repeat(200)),
        )
        .replace("ttl: 2h", "ttl: 10s");
    assert!(fit::check_request(&request(&at)).is_empty());
}
