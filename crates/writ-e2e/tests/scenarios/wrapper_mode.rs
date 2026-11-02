//! Scenario 3, wrapper mode: the operator's own clone from Forgejo, wired with `writ init`,
//! the agent's signed commits pushed through the daemon with `writ git` (and a program run
//! with `writ exec`), verified through `writ-sign`; upstream moving under the agent (the clean
//! rebase); the refused pushes; and the operator's plain git in the same clone untouched.
//!
//! The agent's commands are the GitHub manual check's, steps 5 to 7, exactly as written there
//! (docs/guides/manual-checks.md#a-throwaway-github-repo-m4; `doc_step`, checked by
//! `tool/check-e2e.py`), against Forgejo; the repo is `demo`, as in the development policy.

use writ_e2e::Stack;
use writ_e2e::agent::expect;
use writ_e2e::setup::{doc_step, doc_step_fails};
use writ_e2e::stderr;

use crate::assert_push_refused;

#[test]
#[ignore = "end to end: make e2e"]
fn an_agent_works_through_writ_git_beside_the_operator_s_own_git() {
    let stack = Stack::shared();
    let agent = stack.agent("wrapper");
    let lease = agent.lease(
        &stack,
        &writ_e2e::agent::ticket(&["demo"], &["agent/*"], "1h", ""),
    );
    agent.clone_from_forgejo(&stack, "demo", "work");
    let work = agent
        .host
        .with(&format!("{}/work", agent.dir), Some("../client.env"));
    let fill = [("<lease id>", lease.as_str())];
    let main = stack.forgejo.branch("demo", "main").unwrap();

    // Step 5: wired, fetched through the daemon, a signed commit pushed.
    let out = doc_step(&work, "writ init demo", &[]);
    assert!(out.contains("`writ git push origin`"), "{out}");
    doc_step(&work, "writ git fetch origin", &[]);
    doc_step(
        &work,
        "git checkout -q -b agent/manual-check origin/main",
        &[],
    );
    doc_step(&work, "echo hi > notes.txt && writ git add notes.txt", &[]);
    doc_step(
        &work,
        "writ git commit -m \"Manual check\" --trailer \"Writ: <lease id>\"",
        &fill,
    );
    doc_step(
        &work,
        "writ git push origin HEAD:refs/heads/agent/manual-check",
        &[],
    );
    let first = work.ok("git rev-parse HEAD").trim().to_owned();
    assert_eq!(
        stack
            .forgejo
            .branch("demo", "agent/manual-check")
            .as_deref(),
        Some(first.as_str())
    );
    assert_eq!(
        stack
            .mirror_ref("demo", "refs/heads/agent/manual-check")
            .as_deref(),
        Some(first.as_str())
    );
    assert_eq!(stack.audited(&lease, "push", "allowed").len(), 1);
    assert_eq!(stack.audited(&lease, "sign", "allowed").len(), 1);
    assert!(!stack.audited(&lease, "fetch", "allowed").is_empty());

    // The commit verifies with the lease's key, through writ-sign (which hands verification
    // to ssh-keygen); by the agent's email.
    work.ok(
        "echo \"agent@writ.invalid $(cat ../.writ/sessions/current/signing_key.pub)\" > ../allowed",
    );
    let out = work.run("writ git -c gpg.ssh.allowedSignersFile=../allowed verify-commit HEAD");
    let (_, err) = expect(&out, 0, "writ git verify-commit");
    assert!(
        err.contains("Good \"git\" signature for agent@writ.invalid"),
        "{err}"
    );
    let shown = work.ok("writ git -c gpg.ssh.allowedSignersFile=../allowed log -1 --format='%G?|%ce|%(trailers:key=Writ,valueonly)'");
    assert_eq!(shown.trim(), format!("G|agent@writ.invalid|{lease}"));

    // A program that runs git, with the wiring: its commit signed too.
    work.ok(&format!(
        "writ exec -- sh -c 'echo exec > exec.txt && git add exec.txt && \
         git commit -q -m Exec --trailer \"Writ: {lease}\"'"
    ));
    let shown = work.ok("writ git -c gpg.ssh.allowedSignersFile=../allowed log -1 --format=%G?");
    assert_eq!(shown.trim(), "G");
    expect(
        &work.run("writ git push -q origin HEAD:refs/heads/agent/manual-check"),
        0,
        "the exec commit",
    );
    let exec = work.ok("git rev-parse HEAD").trim().to_owned();
    assert_eq!(
        stack
            .forgejo
            .branch("demo", "agent/manual-check")
            .as_deref(),
        Some(exec.as_str())
    );

    // Step 6: upstream moves (someone commits another file on the branch on Forgejo); the
    // push is refused, then fetch, rebase (signed again), push.
    let theirs = stack
        .forgejo
        .commit_file("demo", "agent/manual-check", "theirs.txt", "theirs");
    doc_step(
        &work,
        "echo more >> notes.txt && writ git commit -qam \"Second\" --trailer \"Writ: <lease id>\"",
        &fill,
    );
    let second = work.ok("git rev-parse HEAD").trim().to_owned();
    let out = doc_step_fails(
        &work,
        "writ git push origin HEAD:refs/heads/agent/manual-check",
        &[],
        1,
    );
    assert!(stderr(&out).contains("rejected"), "{}", stderr(&out));
    assert_eq!(
        stack
            .forgejo
            .branch("demo", "agent/manual-check")
            .as_deref(),
        Some(theirs.as_str())
    );
    assert!(
        !stack.mirror_has("demo", &second),
        "a refused commit reached the mirror"
    );
    doc_step(
        &work,
        "writ git fetch origin && writ git rebase origin/agent/manual-check",
        &[],
    );
    doc_step(
        &work,
        "writ git push origin HEAD:refs/heads/agent/manual-check",
        &[],
    );
    let rebased = work.ok("git rev-parse HEAD").trim().to_owned();
    assert_eq!(work.ok("git rev-parse HEAD~1").trim(), theirs);
    assert_eq!(
        stack
            .forgejo
            .branch("demo", "agent/manual-check")
            .as_deref(),
        Some(rebased.as_str())
    );
    assert_eq!(
        stack
            .mirror_ref("demo", "refs/heads/agent/manual-check")
            .as_deref(),
        Some(rebased.as_str())
    );

    // Step 7: the refused pushes; nothing moves on Forgejo.
    let out = doc_step_fails(&work, "writ git push origin HEAD:refs/heads/main", &[], 1);
    assert_push_refused(
        &stack,
        &lease,
        &out,
        "refs/heads/main is protected",
        "protected_ref",
    );
    doc_step(
        &work,
        "git commit -q --allow-empty --no-gpg-sign -m \"Unsigned\"",
        &[],
    );
    let unsigned = work.ok("git rev-parse HEAD").trim().to_owned();
    let out = doc_step_fails(
        &work,
        "writ git push origin HEAD:refs/heads/agent/manual-check",
        &[],
        1,
    );
    assert_push_refused(
        &stack,
        &lease,
        &out,
        &format!("commit {unsigned} was not signed under this lease"),
        "unsigned",
    );
    assert_eq!(
        stack.forgejo.branch("demo", "main").as_deref(),
        Some(main.as_str())
    );
    assert_eq!(
        stack
            .forgejo
            .branch("demo", "agent/manual-check")
            .as_deref(),
        Some(rebased.as_str())
    );

    // The operator's plain git, in the same clone: its own remote (Forgejo), its own email,
    // no signature, and nothing of Writ in the repository's config.
    let config = work.ok("git config --local --list");
    for key in config.lines().filter_map(|l| l.split('=').next()) {
        assert!(
            ![
                "writ.",
                "remote.writ.",
                "gpg.",
                "url.",
                "user.",
                "commit.",
                "core.sshcommand"
            ]
            .iter()
            .any(|prefix| key.starts_with(prefix)),
            "{key} in the repository's config:\n{config}"
        );
    }
    assert!(
        config.contains("remote.origin.url=http://writ:"),
        "{config}"
    );
    work.ok("git checkout -q -b operator-work origin/main && echo mine > mine.txt && git add mine.txt && git commit -q -m Mine");
    let shown = work.ok("git log -1 --format='%G?|%ce'");
    assert_eq!(shown.trim(), "N|operator@writ.invalid");
    let mine = work.ok("git rev-parse HEAD").trim().to_owned();
    work.ok("git push -q origin HEAD:refs/heads/operator-work");
    assert_eq!(
        stack.forgejo.branch("demo", "operator-work").as_deref(),
        Some(mine.as_str())
    );
    assert!(
        !stack
            .audit()
            .iter()
            .any(|e| e["refs"].to_string().contains("operator-work")),
        "the operator's push went through the daemon"
    );
}
