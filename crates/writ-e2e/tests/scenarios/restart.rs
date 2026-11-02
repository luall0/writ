//! Scenario 10, restart: the `writd` container restarted (the daemon starts again from its
//! entrypoint, the same way, on the same relative path) keeps its leases, its mirrors and its
//! ledger: a commit signed before the restart is pushed after it.

use writ_e2e::Stack;
use writ_e2e::agent::expect;
use writ_e2e::setup::wait_started;

use crate::wired;

#[test]
#[ignore = "end to end: make e2e"]
fn a_restarted_daemon_keeps_leases_mirrors_and_ledger() {
    let stack = Stack::exclusive();
    let agent = stack.agent("restart");
    let (lease, w) = wired(&stack, &agent, "restart");
    agent.ok_in(&w, "git checkout -q -b agent/restart");
    let first = agent.commit(&w, &lease, "a.txt", "before");
    expect(
        &agent.in_dir(&w, "writ git push -q origin HEAD"),
        0,
        "the push before",
    );
    // Signed before the restart, pushed after it.
    let second = agent.commit(&w, &lease, "b.txt", "signed before");

    let starts = stack
        .operator
        .read("writd.log")
        .lines()
        .filter(|l| l.contains("role=Agents"))
        .count();
    stack.operator.container.lifecycle("restart");
    wait_started(&stack.operator, starts + 1);

    // The lease, still active; the mirror, still holding the first push.
    let active = stack.approver.ok("writ ls");
    assert!(
        active
            .lines()
            .any(|l| l.starts_with(&lease) && l.contains("active")),
        "{active}"
    );
    assert_eq!(
        stack
            .mirror_ref("restart", "refs/heads/agent/restart")
            .as_deref(),
        Some(first.as_str())
    );
    // The ledger: the commit signed before goes through after.
    expect(
        &agent.in_dir(&w, "writ git push -q origin HEAD"),
        0,
        "the push after",
    );
    assert_eq!(
        stack.forgejo.branch("restart", "agent/restart").as_deref(),
        Some(second.as_str())
    );
    assert_eq!(
        stack
            .mirror_ref("restart", "refs/heads/agent/restart")
            .as_deref(),
        Some(second.as_str())
    );
    assert_eq!(stack.audited(&lease, "sign", "allowed").len(), 2);
    assert_eq!(stack.audited(&lease, "push", "allowed").len(), 2);
    // And it still signs.
    let third = agent.commit(&w, &lease, "c.txt", "after");
    expect(
        &agent.in_dir(&w, "writ git push -q origin HEAD"),
        0,
        "a commit signed after",
    );
    assert_eq!(
        stack.forgejo.branch("restart", "agent/restart").as_deref(),
        Some(third.as_str())
    );
}
