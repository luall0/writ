//! Scenario 6, upstream moved with a conflict: someone edits the agent's own file on its
//! branch on Forgejo; the agent's push is refused with the remote's reason, nothing of it in
//! the mirror; then fetch, a rebase that conflicts, the conflict resolved and the commit
//! signed again by `writ git rebase --continue`, and pushed. (The clean rebase is the manual
//! check's step 6, in `wrapper_mode`.)

use writ_e2e::Stack;
use writ_e2e::agent::expect;
use writ_e2e::stderr;

use crate::wired;

#[test]
#[ignore = "end to end: make e2e"]
fn a_conflicting_upstream_change_is_fetched_resolved_signed_again_and_pushed() {
    let stack = Stack::shared();
    let agent = stack.agent("moved");
    let (lease, w) = wired(&stack, &agent, "moved");
    agent.ok_in(&w, "git checkout -q -b agent/moved");
    agent.commit(&w, &lease, "notes.txt", "mine");
    expect(
        &agent.in_dir(&w, "writ git push -q origin HEAD"),
        0,
        "the first push",
    );

    // Upstream edits the same file on the branch.
    let theirs = stack
        .forgejo
        .commit_file("moved", "agent/moved", "notes.txt", "theirs\n");
    let mine = agent.commit(&w, &lease, "notes.txt", "mine, again");
    let out = agent.in_dir(&w, "writ git push origin HEAD");
    // git refuses it itself: the daemon synced from Forgejo before showing the refs, so git
    // sees its push isn't a fast-forward and sends nothing.
    expect(&out, 1, "a push behind upstream");
    assert!(stderr(&out).contains("rejected"), "{}", stderr(&out));
    assert_eq!(
        stack.forgejo.branch("moved", "agent/moved").as_deref(),
        Some(theirs.as_str())
    );
    assert!(
        !stack.mirror_has("moved", &mine),
        "a refused commit reached the mirror"
    );

    // Fetch through the daemon; the rebase conflicts; resolved, it is signed again.
    agent.ok_in(&w, "writ git fetch -q origin");
    let out = agent.in_dir(&w, "writ git rebase origin/agent/moved");
    expect(&out, 1, "the conflicting rebase");
    agent.ok_in(
        &w,
        "printf 'theirs\\nmine, again\\n' > notes.txt && writ git add notes.txt && \
         GIT_EDITOR=true writ git rebase --continue",
    );
    let resolved = agent.ok_in(&w, "git rev-parse HEAD").trim().to_owned();
    assert_eq!(agent.ok_in(&w, "git rev-parse HEAD~1").trim(), theirs);
    expect(
        &agent.in_dir(&w, "writ git push -q origin HEAD"),
        0,
        "the resolved push",
    );
    assert_eq!(
        stack.forgejo.branch("moved", "agent/moved").as_deref(),
        Some(resolved.as_str())
    );
    assert_eq!(
        stack
            .mirror_ref("moved", "refs/heads/agent/moved")
            .as_deref(),
        Some(resolved.as_str())
    );
    // Signed three times (mine, mine again, the resolution); two pushes went through.
    assert_eq!(stack.audited(&lease, "sign", "allowed").len(), 3);
    assert_eq!(stack.audited(&lease, "push", "allowed").len(), 2);
    // The refused push never reached the daemon's checks: git refused it itself, the daemon
    // having synced from Forgejo before it showed the refs.
    assert!(stack.audited(&lease, "push", "denied").is_empty());
}
