//! Scenario 15, the notes reconcile (asked by the user): `writd` brings a notes repo's notes
//! up to date at start, from its ledger, for commits upstream has whose note was never
//! recorded. The way an operator meets it: switching a repo that already has pushed commits
//! to `ticket_link: notes` (a backfill), which is also the state a daemon stopped between
//! upstream taking a push and recording its notes leaves.
//!
//! An agent pushes two commits to `backfill` while the repo doesn't ask for notes, and signs
//! a third it never pushes. The approver switches the repo to `ticket_link: notes` (a signed
//! admin change: `writ admin apply policy`, the daemon's `policy.yaml` written back) and the
//! operator restarts the daemon: the reconcile after the mirror's first sync writes both
//! pushed commits' notes on Forgejo, and none for the commit upstream doesn't have. Then the
//! policy is put back the same way and the daemon restarted, as it was.

use std::time::Duration;

use writ_e2e::Stack;
use writ_e2e::agent::expect;
use writ_e2e::docker::eventually;
use writ_e2e::setup::{unseal, wait_started};

use crate::wired;

const REPO: &str = "backfill";
/// The registry's line for the repo, as the operator setup wrote it, and with notes.
const WITHOUT: &str = "upstream_credential: upstream-backfill, protected_refs";
const WITH: &str = "upstream_credential: upstream-backfill, ticket_link: notes, protected_refs";

/// The policy in force with `from` replaced by `to`, applied by the approver (a signed admin
/// change, at once), then written back to the daemon's `policy.yaml`.
fn change_policy(stack: &Stack, from: &str, to: &str) {
    let approver = &stack.approver;
    approver.ok("writ admin show policy > notes-policy.yaml");
    approver.ok(&format!("sed -i 's/{from}/{to}/' notes-policy.yaml"));
    expect(
        &approver.run("writ admin apply policy notes-policy.yaml --yes"),
        0,
        "writ admin apply policy",
    );
    assert!(stack.operator.read("policy.yaml").contains(to));
}

/// Restarts the `writd` container (the `n`th start since the stack came up) and waits for it.
fn restart(stack: &Stack) {
    let starts = stack
        .operator
        .read("writd.log")
        .lines()
        .filter(|l| l.contains("role=Agents"))
        .count();
    stack.operator.container.lifecycle("restart");
    wait_started(&stack.operator, starts + 1);
    // It starts sealed: the approver unseals it, as after every start.
    unseal(&stack.approver);
}

#[test]
#[ignore = "end to end: make e2e"]
fn switching_a_repo_to_notes_and_restarting_notes_what_was_pushed_before() {
    let stack = Stack::exclusive();
    let agent = stack.agent("backfill");
    let (lease, w) = wired(&stack, &agent, REPO);
    agent.ok_in(&w, "git checkout -q -b agent/backfill");
    let first = agent.commit(&w, &lease, "a.txt", "one");
    let second = agent.commit(&w, &lease, "b.txt", "two");
    expect(
        &agent.in_dir(&w, "writ git push -q origin HEAD"),
        0,
        "the push before the switch",
    );
    // Signed, never pushed: upstream doesn't have it.
    let unpushed = agent.commit(&w, &lease, "c.txt", "three");
    assert_eq!(stack.forgejo.note(REPO, &first), None);
    assert_eq!(stack.forgejo.note(REPO, &second), None);
    assert!(stack.audited(&lease, "notes", "allowed").is_empty());

    // The approver asks for notes, and the operator restarts the daemon.
    let policy = stack.operator.read("policy.yaml");
    assert!(policy.contains(WITHOUT), "{policy}");
    change_policy(&stack, WITHOUT, WITH);
    restart(&stack);

    // At start, after the mirror's first sync: the notes of what upstream has.
    eventually("the backfilled notes", Duration::from_secs(120), || {
        stack.forgejo.note(REPO, &second).is_some() && stack.forgejo.note(REPO, &first).is_some()
    });
    let note = format!("Writ: {lease}\n");
    assert_eq!(stack.forgejo.note(REPO, &first), Some(note.clone()));
    assert_eq!(stack.forgejo.note(REPO, &second), Some(note.clone()));
    assert_eq!(stack.forgejo.note(REPO, &unpushed), None);
    // Shown on the commit's page.
    let page = stack.forgejo.commit_page(REPO, &first);
    assert!(
        page.contains(&format!("Writ: {lease}")),
        "the note on the page"
    );
    // One allowed line for the lease, both notes counted; the daemon says what it found.
    let lines = stack.audited(&lease, "notes", "allowed");
    let counted: u64 = lines.iter().map(|l| l["count"].as_u64().unwrap()).sum();
    assert_eq!(counted, 2, "{lines:?}");
    assert_eq!(lines[0]["refs"][0], "refs/notes/commits");
    let log = stack.operator.read("writd.log");
    assert!(
        log.lines().any(|l| l.contains("notes found missing")
            && l.contains(&lease)
            && l.contains("notes=2")),
        "{log}"
    );
    // The mirror's notes ref is Forgejo's.
    assert_eq!(
        stack.mirror_ref(REPO, "refs/notes/commits"),
        stack.forgejo.git_ref(REPO, "refs/notes/commits")
    );
    // The commit never pushed gets its note once pushed, by its push's own job.
    expect(
        &agent.in_dir(&w, "writ git push -q origin HEAD"),
        0,
        "the push after the switch",
    );
    eventually("the pushed commit's note", Duration::from_secs(60), || {
        stack.forgejo.note(REPO, &unpushed).is_some()
    });
    assert_eq!(stack.forgejo.note(REPO, &unpushed), Some(note));
    assert!(stack.audited(&lease, "notes", "denied").is_empty());

    // As it was: the repo without notes, the daemon restarted.
    change_policy(&stack, WITH, WITHOUT);
    restart(&stack);
    assert!(stack.operator.read("policy.yaml").contains(WITHOUT));
}
