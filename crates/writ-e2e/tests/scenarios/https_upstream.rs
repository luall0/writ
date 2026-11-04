//! Scenario 13, an HTTPS upstream (M4.5): the `https` repository, reached through Forgejo's
//! HTTPS front with a token the approver added with `writ admin token` (its certificate trusted
//! through `mirrors.ca_certs`). The agent fetches, commits and pushes through the daemon as
//! with any repository; the branch lands on Forgejo and in the mirror; the registry's
//! protected ref is still refused; and the token is sealed in its keystore file, in clear
//! nowhere: not in the daemon's files, log, mirrors or their configuration, the audit log, or
//! anything on the agent's side. git ran the daemon's credential helper (`writd upstream-credential`) for it.
//!
//! And `mirrors.ca_certs` is the only trust: the `https-system` repository, the same Forgejo
//! repository behind a second front whose certificate the daemon container's system store
//! trusts (plain git there reaches it), is refused, its certificate not verifying.

use writ_e2e::Stack;
use writ_e2e::agent::{expect, ticket};
use writ_e2e::setup::{HTTPS_CREDENTIAL, HTTPS_REPO, SYSTEM_FRONT, SYSTEM_REPO};
use writ_e2e::{stderr, stdout};

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

    // The token: sealed in its file (the approver added it with `writ admin token`), readable
    // by the daemon's user alone, and in clear nowhere on the daemon's host.
    let file = format!("data/keys/tokens/{HTTPS_CREDENTIAL}.age");
    assert_eq!(
        stack.operator.ok(&format!("stat -c %a {file}")).trim(),
        "600"
    );
    assert_eq!(
        stack.operator.ok(&format!("grep -c '^-> X25519 ' {file}")),
        "1\n"
    );
    let token = stack.report.https_token.clone();
    assert_eq!(token.len(), 40, "a Forgejo token");
    let grep = format!("grep -rlF -e '{token}' .");
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

#[test]
#[ignore = "end to end: make e2e"]
fn a_certificate_the_system_trusts_is_refused_when_the_operator_named_their_cas() {
    let stack = Stack::shared();

    // The system trusts the second front (the setup put its certificate in the daemon
    // container's store): plain git, as the daemon's user, reaches the repository there.
    let plain = stack.operator.run(&format!(
        "GIT_TERMINAL_PROMPT=0 git -c credential.helper= ls-remote \
         https://{SYSTEM_FRONT}:3443/writ/{HTTPS_REPO}.git HEAD"
    ));
    expect(&plain, 0, "plain git through the system's CAs");

    // The daemon trusts only `mirrors.ca_certs`, which names the other front: refused, with
    // the reason, and nothing in the mirror.
    let agent = stack.agent("https-system");
    let lease = agent.lease(&stack, &ticket(&[SYSTEM_REPO], &["agent/*"], "1h", ""));
    agent.clone_from_forgejo(&stack, HTTPS_REPO, "work");
    agent.ok_in("work", &format!("writ init {SYSTEM_REPO} --agents none"));
    let out = agent.in_dir("work", "writ git fetch origin");
    expect(
        &out,
        128,
        "a fetch through a certificate only the system trusts",
    );
    let refusal = "upstream's certificate does not verify";
    assert!(stderr(&out).contains(refusal), "{}", stderr(&out));
    let denied = stack.audited(&lease, "fetch", "denied");
    let reason = denied.last().expect("a fetch denied line")["reason"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(reason.contains(refusal), "{reason}");
    assert_eq!(stack.mirror_ref(SYSTEM_REPO, "refs/heads/main"), None);
}
