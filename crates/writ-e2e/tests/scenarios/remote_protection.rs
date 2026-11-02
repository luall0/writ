//! Scenario 7, the remote's own branch protection: a branch the lease allows but Forgejo
//! protects. The daemon pushes upstream before its mirror moves, so Forgejo's refusal
//! reaches the agent with Forgejo's reason, is logged, and leaves the mirror as it was.

use writ_e2e::Stack;
use writ_e2e::agent::expect;
use writ_e2e::stderr;

use crate::wired;

#[test]
#[ignore = "end to end: make e2e"]
fn forgejo_s_branch_protection_refuses_and_its_reason_reaches_the_agent() {
    let stack = Stack::shared();
    stack.forgejo.protect("protection", "agent/locked");
    let agent = stack.agent("protection");
    let (lease, w) = wired(&stack, &agent, "protection");
    let commit = agent.commit(&w, &lease, "notes.txt", "locked");

    let out = agent.in_dir(&w, "writ git push origin HEAD:refs/heads/agent/locked");
    expect(&out, 1, "a push Forgejo refuses");
    let err = stderr(&out);
    assert!(
        err.contains("writ: repo protection: upstream refused the push"),
        "{err}"
    );
    assert!(err.contains("protected"), "Forgejo's reason: {err}");
    assert_eq!(stack.forgejo.branch("protection", "agent/locked"), None);
    assert_eq!(
        stack.mirror_ref("protection", "refs/heads/agent/locked"),
        None
    );
    let denied = stack.audited(&lease, "push", "denied");
    let reason = denied.last().unwrap()["reason"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(reason.contains("upstream refused the push"), "{reason}");

    // The same commit to a branch Forgejo leaves open: through.
    expect(
        &agent.in_dir(&w, "writ git push -q origin HEAD:refs/heads/agent/open"),
        0,
        "the open branch",
    );
    assert_eq!(
        stack.forgejo.branch("protection", "agent/open").as_deref(),
        Some(commit.as_str())
    );
}
