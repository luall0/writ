//! Scenario 5, every push denial: a protected ref, a branch outside the lease, a force push,
//! a deletion, an unsigned commit, a signed commit on an unsigned parent, another lease's
//! commit, a pack over `max_push_size`, a tree with a mode git doesn't write (refused to sign,
//! then by the mirror's `fsck`), a ref differing only in case, and a fetch under a
//! lease without `fetch`. Each refused with what the agent reads and its audit code, Forgejo
//! and the mirror unchanged, with the allowed push beside them.

use writ_e2e::Stack;
use writ_e2e::agent::{expect, ticket, ticket_with};
use writ_e2e::stderr;

use crate::assert_push_refused;

#[test]
#[ignore = "end to end: make e2e"]
fn every_push_denial_leaves_forgejo_and_the_mirror_unchanged() {
    let stack = Stack::shared();
    let agent = stack.agent("denials");
    let lease = agent.lease(
        &stack,
        &ticket_with(
            &["denials"],
            &["agent/*"],
            "1h",
            "    limits:\n      max_push_size: 1MB\n",
            "",
        ),
    );
    agent.clone_from_forgejo(&stack, "denials", "work");
    agent.ok_in("work", "writ init denials --agents none");
    let w = "work";
    let main = stack.forgejo.branch("denials", "main").unwrap();
    let push = |refspec: &str| agent.in_dir(w, &format!("writ git push origin {refspec}"));
    let unchanged = |branch: &str, expected: Option<&str>| {
        assert_eq!(
            stack.forgejo.branch("denials", branch).as_deref(),
            expected,
            "Forgejo {branch}"
        );
        assert_eq!(
            stack
                .mirror_ref("denials", &format!("refs/heads/{branch}"))
                .as_deref(),
            expected,
            "mirror {branch}"
        );
    };

    // The allowed push: the baseline.
    let base = agent.commit(w, &lease, "a.txt", "a");
    expect(&push("HEAD:refs/heads/agent/base"), 0, "the allowed push");
    unchanged("agent/base", Some(&base));

    // A protected ref, a branch outside the lease.
    assert_push_refused(
        &stack,
        &lease,
        &push("HEAD:refs/heads/main"),
        "refs/heads/main is protected",
        "protected_ref",
    );
    assert_push_refused(
        &stack,
        &lease,
        &push("HEAD:refs/heads/feature/x"),
        "branch feature/x not allowed",
        "ref",
    );
    unchanged("main", Some(&main));
    unchanged("feature/x", None);

    // A force push (another history for the branch), a deletion.
    agent.ok_in(w, "git reset -q --hard HEAD~1");
    agent.commit(w, &lease, "b.txt", "b");
    assert_push_refused(
        &stack,
        &lease,
        &push("+HEAD:refs/heads/agent/base"),
        "force push to refs/heads/agent/base not allowed",
        "force_push",
    );
    assert_push_refused(
        &stack,
        &lease,
        &push(":refs/heads/agent/base"),
        "deleting refs/heads/agent/base needs force_push",
        "force_push",
    );
    unchanged("agent/base", Some(&base));

    // An unsigned commit, then a signed one on top of it.
    agent.ok_in(w, &format!("git reset -q --hard {base}"));
    agent.ok_in(w, "git commit -q --allow-empty --no-gpg-sign -m Unsigned");
    let unsigned = agent.ok_in(w, "git rev-parse HEAD").trim().to_owned();
    assert_push_refused(
        &stack,
        &lease,
        &push("HEAD:refs/heads/agent/unsigned"),
        &format!(
            "commit {unsigned} was not signed under this lease (or a lease it renews) for repo denials"
        ),
        "unsigned",
    );
    let on_top = agent.commit(w, &lease, "c.txt", "c");
    assert_push_refused(
        &stack,
        &lease,
        &push("HEAD:refs/heads/agent/unsigned"),
        &format!("commit {unsigned} was not signed under this lease"),
        "unsigned",
    );
    unchanged("agent/unsigned", None);
    assert!(
        !stack.mirror_has("denials", &on_top),
        "a refused commit reached the mirror"
    );

    // Another lease's commit: signed under it, pushed under this one. The other lease may
    // push it itself.
    let other = stack.agent("denials-other");
    let theirs_lease = other.lease(&stack, &ticket(&["denials"], &["agent/*"], "1h", ""));
    other.clone_from_forgejo(&stack, "denials", "work");
    other.ok_in("work", "writ init denials --agents none");
    let theirs = other.commit("work", &theirs_lease, "d.txt", "d");
    agent.ok_in(
        w,
        &format!(
            "git fetch -q {}/work HEAD && git reset -q --hard {theirs}",
            other.dir
        ),
    );
    assert_push_refused(
        &stack,
        &lease,
        &push("HEAD:refs/heads/agent/theirs"),
        &format!("commit {theirs} was not signed under this lease"),
        "unsigned",
    );
    unchanged("agent/theirs", None);
    expect(
        &other.in_dir(
            "work",
            "writ git push -q origin HEAD:refs/heads/agent/theirs",
        ),
        0,
        "their own push",
    );
    unchanged("agent/theirs", Some(&theirs));

    // A pack over max_push_size (1 MB): git refuses it before the hook; still logged.
    agent.ok_in(w, &format!("git reset -q --hard {base}"));
    agent.ok_in(w, "head -c 2000000 /dev/urandom > big.bin");
    agent.ok_in(
        w,
        &format!("writ git add big.bin && writ git commit -q -m Big --trailer 'Writ: {lease}'"),
    );
    let out = push("HEAD:refs/heads/agent/big");
    expect(&out, 1, "a pack over max_push_size");
    assert!(
        stderr(&out).contains("pack exceeds maximum allowed size"),
        "{}",
        stderr(&out)
    );
    let denied = stack.audited(&lease, "push", "denied");
    assert!(
        denied.last().unwrap()["reason"]
            .as_str()
            .unwrap()
            .starts_with("the push ended before its checks"),
        "{denied:?}"
    );
    unchanged("agent/big", None);

    // A directory with a mode git reads as one but never writes (`40755`): read as a file,
    // `.github/evil.yml` would pass as `.github`. Signing it is refused whatever paths_check
    // says; pushed unsigned, the mirror's fsck refuses it before the hook (`badFilemode`).
    agent.ok_in(w, &format!("git reset -q --hard {base}"));
    let inner = agent.ok_in(
        w,
        "printf '100644 blob %s\\tevil.yml\\n' \"$(git hash-object -w a.txt)\" | git mktree",
    );
    let tree = agent.ok_in(
        w,
        &format!(
            "{{ git ls-tree HEAD; printf '40755 tree %s\\t.github\\n' {}; }} | git mktree",
            inner.trim()
        ),
    );
    let tree = tree.trim();
    let out = agent.in_dir(
        w,
        &format!("writ git commit-tree -S {tree} -p HEAD -m Mode -m 'Writ: {lease}'"),
    );
    expect(&out, 1, "signing a tree with a non-standard mode");
    let reason = "cannot sign: a tree entry has a non-standard mode (git writes only 100644, \
                  100755, 120000, 40000 and 160000)";
    assert!(stderr(&out).contains(reason), "{}", stderr(&out));
    let denied = stack.audited(&lease, "sign", "denied");
    assert_eq!(denied.last().unwrap()["reason"], reason, "{denied:?}");
    let unsigned_mode = agent.ok_in(w, &format!("git commit-tree {tree} -p HEAD -m Mode"));
    let out = push(&format!("{}:refs/heads/agent/mode", unsigned_mode.trim()));
    expect(&out, 1, "a tree with a non-standard mode");
    assert!(stderr(&out).contains("badFilemode"), "{}", stderr(&out));
    let denied = stack.audited(&lease, "push", "denied");
    assert!(
        denied.last().unwrap()["reason"]
            .as_str()
            .unwrap()
            .starts_with("the push ended before its checks"),
        "{denied:?}"
    );
    unchanged("agent/mode", None);
    assert!(
        !stack.mirror_has("denials", unsigned_mode.trim()),
        "a refused commit reached the mirror"
    );

    // A ref that differs only in case from one the repository has.
    agent.ok_in(w, &format!("git reset -q --hard {base}"));
    agent.commit(w, &lease, "e.txt", "e");
    assert_push_refused(
        &stack,
        &lease,
        &push("HEAD:refs/heads/agent/Base"),
        "refs/heads/agent/Base differs only in case from a ref the repo has",
        "invalid",
    );
    unchanged("agent/Base", None);

    // A fetch under a lease without `fetch`.
    let no_fetch = stack.agent("denials-no-fetch");
    let no_fetch_lease = no_fetch.lease(
        &stack,
        &ticket(&["denials"], &["agent/*"], "1h", "").replace(
            "operations: [fetch, commit_sign, push]",
            "operations: [commit_sign, push]",
        ),
    );
    no_fetch.clone_from_forgejo(&stack, "denials", "work");
    no_fetch.ok_in("work", "writ init denials --agents none");
    let out = no_fetch.in_dir("work", "writ git fetch origin");
    expect(&out, 128, "a fetch without fetch");
    assert!(
        stderr(&out).contains("fetch not allowed"),
        "{}",
        stderr(&out)
    );
    let denied = stack.audited(&no_fetch_lease, "fetch", "denied");
    assert_eq!(denied.last().unwrap()["code"], "operation", "{denied:?}");

    // After all of it: Forgejo's branches are the allowed ones only.
    unchanged("main", Some(&main));
    unchanged("agent/base", Some(&base));
    assert_eq!(stack.audited(&lease, "push", "allowed").len(), 1);
}
