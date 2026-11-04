//! Scenario 8, signature verification on the account: commits pushed through Writ are
//! unverified on Forgejo until the lease's signing key (`writd signing-keys`) is registered on
//! the account **and** proven (Forgejo's challenge, signed through `writ prove-key`, an
//! approval); then verified, the committer email being the account's. The proof is answered
//! `n` once on a terminal (nothing signed), then `y`, and once more with `--yes` over SSH:
//! Ed25519 signs the same message the same way, so both signatures are the same bytes. A
//! commit authored as someone else is refused at signing (`author`).

use writ_e2e::Stack;
use writ_e2e::agent::{expect, ticket};
use writ_e2e::setup::{APPROVALS_SSH, split_key_line};

/// The armored signature in what a terminal showed (`script` merges the streams and ends
/// lines with `\r\n`).
fn armored(screen: &str) -> String {
    let screen = screen.replace("\r\n", "\n");
    let start = screen
        .find("-----BEGIN SSH SIGNATURE-----")
        .expect("a signature on screen");
    let end = screen.find("-----END SSH SIGNATURE-----").expect("its end")
        + "-----END SSH SIGNATURE-----".len();
    format!("{}\n", &screen[start..end])
}

#[test]
#[ignore = "end to end: make e2e"]
fn commits_are_verified_once_the_signing_key_is_registered_and_proven() {
    let stack = Stack::shared();
    let agent = stack.agent("verified");
    let lease = agent.lease(
        &stack,
        &ticket(&["verified"], &["agent/*"], "1h", "")
            .replace("template: feature", "template: verified"),
    );
    agent.clone_from_forgejo(&stack, "verified", "work");
    agent.ok_in("work", "writ init verified");
    agent.ok_in("work", "git checkout -q -b agent/verified");
    let push = |file: &str| {
        let commit = agent.commit("work", &lease, file, file);
        expect(
            &agent.in_dir("work", "writ git push -q origin HEAD"),
            0,
            "a push",
        );
        assert_eq!(
            stack
                .forgejo
                .branch("verified", "agent/verified")
                .as_deref(),
            Some(commit.as_str())
        );
        commit
    };

    // No key on the account: unverified.
    let first = push("one.txt");
    let (verified, why) = stack.forgejo.verification("verified", &first);
    assert!(!verified, "{why}");

    // The lease's key registered on the account, not proven: still unverified.
    let line = stack
        .report
        .signing_keys
        .iter()
        .find(|l| l.starts_with("agent-e2e-verify "))
        .unwrap();
    let (key, templates) = split_key_line(line, "templates");
    assert_eq!(templates, ["verified"]);
    assert_eq!(key, agent.session_file(&lease, "signing_key.pub").trim());
    let fingerprint = stack.forgejo.add_account_key(&key);
    let second = push("two.txt");
    let (verified, why) = stack.forgejo.verification("verified", &second);
    assert!(!verified, "registered but not proven: {why}");

    // Never in git's namespace (the parser refuses it, nothing is signed).
    let out = stack.approver.run_with(
        "writ prove-key agent-e2e-verify --namespace git --yes",
        b"x",
    );
    let (_, err) = expect(&out, 2, "a proof in git's namespace");
    assert!(err.contains("invalid proof namespace"), "{err}");

    // On a terminal, answered no: nothing signed, nothing sent.
    let on_terminal = |token: &str| {
        format!(
            "script -qec \"printf %s {token} | writ prove-key agent-e2e-verify --namespace gitea\" /dev/null"
        )
    };
    let out = stack
        .approver
        .run_with(&on_terminal("not-the-token"), b"n\n");
    let (screen, _) = expect(&out, 6, "a proof answered no");
    assert!(
        // On a terminal (`script`): rows end with `\r\n`, so no newline is matched.
        screen
            .lines()
            .any(|l| l.trim_end() == "  key        agent-e2e-verify")
            && screen.contains("Sign this proof? [y/N]"),
        "{screen}"
    );
    assert!(screen.contains("Nothing signed."), "{screen}");

    // Proven: Forgejo's challenge, signed on a terminal (yes), and with --yes over SSH.
    let mut by_flag = String::new();
    let token = stack.forgejo.prove_key(&fingerprint, |token| {
        let out = stack.approver.run_with(&on_terminal(token), b"y\n");
        let (screen, _) = expect(&out, 0, "the proof, signed on a terminal");
        assert!(screen.contains(&format!("│ {token}")), "{screen}");
        assert!(screen.contains("namespace  gitea"), "{screen}");
        let signature = armored(&screen);
        let out = stack.approver.run_with(
            &format!("WRIT_APPROVAL_URL={APPROVALS_SSH} writ prove-key agent-e2e-verify --namespace gitea --yes"),
            token.as_bytes(),
        );
        let (flag, err) = expect(&out, 0, "the proof with --yes");
        assert!(err.contains("Signed by agent-e2e-verify (SHA256:"), "{err}");
        by_flag = flag;
        signature
    });
    assert_eq!(armored(&by_flag), by_flag, "only the signature on stdout");
    assert_eq!(armored(&by_flag), {
        let out = stack.approver.run_with(&on_terminal(&token), b"y\n");
        armored(&expect(&out, 0, "the same proof again").0)
    });

    // Verified now, by the account.
    let third = push("three.txt");
    let (verified, why) = stack.forgejo.verification("verified", &third);
    assert!(verified, "{why}");
    assert_eq!(why["signer"]["email"], "agent@writ.invalid", "{why}");

    // A commit authored as someone else (the operator's own identity), with the agent as its
    // committer: refused at signing, with its code, so Forgejo never shows a verified commit
    // under another person's name.
    let out = agent.in_dir(
        "work",
        &format!(
            "printf 'x\\n' > four.txt && writ git add four.txt && writ git commit -q \
             --author 'Operator <operator@writ.invalid>' -m 'Change four.txt' \
             --trailer 'Writ: {lease}'"
        ),
    );
    let (_, err) = expect(&out, 128, "a commit authored as someone else");
    assert!(
        err.contains("author email \"operator@writ.invalid\" not allowed"),
        "{err}"
    );
    let denied = stack
        .audit()
        .into_iter()
        .rfind(|e| e["event"] == "sign" && e["result"] == "denied")
        .unwrap();
    assert_eq!(denied["code"], "author", "{denied}");
    agent.ok_in("work", "git reset -q --hard");

    // Each proof logged: the key, the namespace, the challenge's digest, never the challenge.
    let digest = agent
        .ok(&format!("printf %s {token} | sha256sum"))
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let proofs: Vec<_> = stack
        .audit()
        .into_iter()
        .filter(|e| {
            e["event"] == "prove" && e["result"] == "allowed" && e["key"] == "agent-e2e-verify"
        })
        .collect();
    assert_eq!(proofs.len(), 3, "{proofs:?}");
    assert!(
        proofs
            .iter()
            .all(|p| p["namespace"] == "gitea" && p["message_sha256"] == digest)
    );
    assert!(!stack.operator.read("data/audit.jsonl").contains(&token));
}
