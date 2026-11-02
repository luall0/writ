//! Scenario 13, an HTTPS upstream (M4.5): the `https` repository, reached through Forgejo's
//! HTTPS front with a token the operator pasted into the keystore (its certificate trusted
//! through `mirrors.ca_certs`). The agent fetches, commits and pushes through the daemon as
//! with any repository; the branch lands on Forgejo and in the mirror; the registry's
//! protected ref is still refused; and the token is in its keystore file alone: not in the
//! daemon's log, its mirrors or their configuration, the audit log, or anything on the
//! agent's side. git ran the daemon's credential helper (`writd upstream-credential`) for it.

use writ_e2e::Stack;
use writ_e2e::agent::expect;
use writ_e2e::setup::{HTTPS_CREDENTIAL, HTTPS_REPO};
use writ_e2e::stdout;

use crate::{assert_push_refused, wired};

#[test]
#[ignore = "end to end: make e2e"]
fn a_repo_behind_https_is_fetched_and_pushed_with_a_token_nobody_else_sees() {
    let stack = Stack::shared();
    let agent = stack.agent("https");
    let (lease, w) = wired(&stack, &agent, HTTPS_REPO);
    let main = stack.forgejo.branch(HTTPS_REPO, "main").unwrap();

    // A fetch through the daemon: the mirror synced from Forgejo over HTTPS.
    agent.ok_in(&w, "writ git fetch -q origin");
    assert_eq!(
        stack.mirror_ref(HTTPS_REPO, "refs/heads/main").as_deref(),
        Some(main.as_str())
    );
    // A signed commit, pushed: on Forgejo and in the mirror.
    agent.ok_in(&w, "git checkout -q -b agent/https");
    let commit = agent.commit(&w, &lease, "notes.txt", "over https");
    expect(
        &agent.in_dir(&w, "writ git push origin HEAD"),
        0,
        "the push over HTTPS",
    );
    assert_eq!(
        stack.forgejo.branch(HTTPS_REPO, "agent/https").as_deref(),
        Some(commit.as_str())
    );
    assert_eq!(
        stack
            .mirror_ref(HTTPS_REPO, "refs/heads/agent/https")
            .as_deref(),
        Some(commit.as_str())
    );
    assert_eq!(stack.audited(&lease, "push", "allowed").len(), 1);
    // The registry's protection holds whatever the transport: main refused, Forgejo unchanged.
    let out = agent.in_dir(&w, "writ git push origin HEAD:refs/heads/main");
    assert_push_refused(
        &stack,
        &lease,
        &out,
        "refs/heads/main is protected",
        "protected_ref",
    );
    assert_eq!(
        stack.forgejo.branch(HTTPS_REPO, "main").as_deref(),
        Some(main.as_str())
    );

    // The token: in its file, readable by the daemon's user alone, and nowhere else.
    let file = format!("data/keys/tokens/{HTTPS_CREDENTIAL}");
    assert_eq!(
        stack.operator.ok(&format!("stat -c %a {file}")).trim(),
        "600"
    );
    let token = stack.operator.read(&file).trim().to_owned();
    assert_eq!(token.len(), 40, "a Forgejo token");
    let grep = format!("grep -rlF -e '{token}' . --exclude-dir=tokens");
    let found = stack.operator.run(&grep);
    assert_eq!(
        found.status.code(),
        Some(1),
        "the token outside its file, on the daemon's host: {}",
        stdout(&found)
    );
    let found = agent.run(&grep);
    assert_eq!(
        found.status.code(),
        Some(1),
        "the token on the agent's side: {}",
        stdout(&found)
    );
    let audit = stack.operator.read("data/audit.jsonl");
    assert!(!audit.contains(&token));
}
