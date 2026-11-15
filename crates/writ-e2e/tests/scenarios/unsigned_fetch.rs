//! Scenario 28, a fetch with no signature (M7.9.7): an agent in a clone wired with no lease
//! runs `writ git fetch` and `writ git pull --ff-only` before writing its ticket, and gets
//! Forgejo's new commits under leases the daemon granted with no approver (the repo names
//! the `prefetch` template), each granted, fetched and closed in the audit log, nothing left
//! on the agent's host; `writ policy` says the template asks no signature; the same agent's
//! signed lease then works as before.

use writ_e2e::Stack;
use writ_e2e::agent::{expect, ticket};

/// The lease a fetch with no lease ran under, as `writ git` names it on stderr.
fn unsigned_lease(said: &str) -> String {
    let (_, rest) = said
        .split_once("fetching under lease ")
        .unwrap_or_else(|| panic!("no lease named in: {said}"));
    rest.split(',').next().unwrap().trim().to_owned()
}

#[test]
#[ignore = "end to end: make e2e"]
fn an_agent_fetches_before_its_ticket_with_no_signature_and_leaves_nothing() {
    let stack = Stack::shared();
    let agent = stack.agent("prefetch");
    agent.clone_from_forgejo(&stack, "planning", "work");
    agent.ok_in("work", "writ init planning --agents none");

    // What the repo allows: the unsigned template, said to ask no signature.
    let policy = agent.ok_in("work", "writ policy");
    assert!(policy.contains("Template prefetch:\n"), "{policy}");
    assert!(
        policy.contains("signature           none: granted when submitted, fetch only"),
        "{policy}"
    );

    // Upstream moved; the agent fetches with no lease and gets it.
    let moved = stack
        .forgejo
        .commit_file("planning", "main", "notes.txt", "moved\n");
    let out = agent.in_dir("work", "writ git fetch -q origin");
    let (_, said) = expect(&out, 0, "writ git fetch with no lease");
    assert!(
        said.contains("granted with no signature (template prefetch)"),
        "{said}"
    );
    let lease = unsigned_lease(&said);
    assert_eq!(
        agent.ok_in("work", "git rev-parse origin/main").trim(),
        moved
    );
    let grants = stack.audited(&lease, "grant", "allowed");
    assert_eq!(grants.len(), 1, "{grants:?}");
    assert_eq!(
        grants[0]["reason"],
        "granted with no signature (unsigned_fetch): template prefetch"
    );
    assert!(grants[0].get("approver").is_none(), "{grants:?}");
    assert_eq!(stack.audited(&lease, "fetch", "allowed").len(), 1);
    assert_eq!(stack.audited(&lease, "close", "done").len(), 1);
    // Nothing on the agent's host: no session, no `current`.
    assert_eq!(
        agent
            .ok_in("work", "ls -A \"$WRIT_HOME/sessions\" 2>/dev/null | wc -l")
            .trim(),
        "0"
    );
    assert_eq!(
        stack.mirror_ref("planning", "refs/heads/main").as_deref(),
        Some(moved.as_str())
    );

    // pull --ff-only: the branch moves to Forgejo's, under a lease of its own.
    let again = stack
        .forgejo
        .commit_file("planning", "main", "notes.txt", "moved again\n");
    let out = agent.in_dir("work", "writ git pull -q --ff-only origin main");
    let (_, said) = expect(&out, 0, "writ git pull with no lease");
    let pulled = unsigned_lease(&said);
    assert_ne!(pulled, lease);
    assert_eq!(agent.ok_in("work", "git rev-parse HEAD").trim(), again);
    assert_eq!(stack.audited(&pulled, "close", "done").len(), 1);

    // Then the ticket, signed: the agent's lease works as any.
    let signed = agent.lease(&stack, &ticket(&["planning"], &["agent/*"], "1h", ""));
    agent.ok_in("work", "git checkout -q -b agent/plan");
    let commit = agent.commit("work", &signed, "plan.txt", "the plan");
    expect(
        &agent.in_dir(
            "work",
            &format!("WRIT_SESSION={signed} writ git push -q origin HEAD"),
        ),
        0,
        "the signed lease's push",
    );
    assert_eq!(
        stack.forgejo.branch("planning", "agent/plan").as_deref(),
        Some(commit.as_str())
    );
}
