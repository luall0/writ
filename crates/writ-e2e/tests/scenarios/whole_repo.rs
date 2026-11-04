//! Scenario 4, whole-repo mode: a clone dedicated to an agent, wired with `writ init
//! --whole-repo` (the email and the daemon's URL given as flags), where plain `git` is the
//! agent's (signed by the daemon, `origin` through it); a second wiring refused; and `writ
//! init --undo` taking the repository's config back exactly.

use writ_e2e::Stack;
use writ_e2e::agent::{expect, ticket};
use writ_e2e::setup::AGENTS_URL;
use writ_e2e::stderr;

#[test]
#[ignore = "end to end: make e2e"]
fn a_dedicated_clone_is_wired_whole_and_undone_exactly() {
    let stack = Stack::shared();
    let agent = stack.agent("whole");
    let lease = agent.lease(&stack, &ticket(&["whole"], &["agent/*"], "1h", ""));
    agent.clone_from_forgejo(&stack, "whole", "work");
    let before = agent.ok_in("work", "git config --local --list");

    // Wired whole, with the settings as flags (no WRIT_URL in the environment).
    let out = agent.in_dir(
        "work",
        &format!("env -u WRIT_URL writ init whole --whole-repo --email agent@writ.invalid --url {AGENTS_URL} --agents none"),
    );
    let (out, _) = expect(&out, 0, "writ init --whole-repo");
    assert!(
        out.contains("Committer email: agent@writ.invalid (--email; the lease must allow it)."),
        "{out}"
    );
    let config = agent.ok_in("work", "git config --local --list");
    for setting in [
        "gpg.format=ssh",
        "commit.gpgsign=true",
        "user.email=agent@writ.invalid",
        "writ.repo=whole",
        "remote.writ.url=ssh://git@writd:2222/whole.git",
        "url.ssh://git@writd:2222/whole.git.insteadof=http://writ:",
    ] {
        assert!(config.contains(setting), "{setting} not in:\n{config}");
    }

    // A second wiring: refused, the first one stays.
    let out = agent.in_dir("work", "writ init whole");
    let (_, err) = expect(&out, 1, "a repo already wired");
    assert!(err.contains("already"), "{err}");

    // Plain git is the agent's: signed by the daemon, pushed through it.
    let commit = agent.ok_in(
        "work",
        &format!(
            "git checkout -q -b agent/whole && echo whole > whole.txt && git add whole.txt && \
             git commit -q -m Whole --trailer 'Writ: {lease}' && git rev-parse HEAD"
        ),
    );
    let commit = commit.trim();
    agent.ok_in("work", "git push -q origin HEAD");
    assert_eq!(
        stack.forgejo.branch("whole", "agent/whole").as_deref(),
        Some(commit)
    );
    assert_eq!(
        stack
            .mirror_ref("whole", "refs/heads/agent/whole")
            .as_deref(),
        Some(commit)
    );
    assert_eq!(stack.audited(&lease, "sign", "allowed").len(), 1);
    assert_eq!(stack.audited(&lease, "push", "allowed").len(), 1);
    // And it is checked: main is protected.
    let out = agent.in_dir("work", "git push origin HEAD:refs/heads/main");
    expect(&out, 1, "plain git to a protected ref");
    assert!(
        stderr(&out).contains("refs/heads/main is protected"),
        "{}",
        stderr(&out)
    );

    // Undone: the repository's config exactly as before.
    expect(
        &agent.in_dir("work", "writ init --undo"),
        0,
        "writ init --undo",
    );
    assert_eq!(agent.ok_in("work", "git config --local --list"), before);
}
