//! Scenario 18, OpenPGP commits (M5.5): a template signs with a key `writd.yaml` declares
//! `format: openpgp`, certified for the account's email by the policy. The agent's lease
//! carries the key's certificate (`signing_key.asc`), the same the operator's `writd
//! signing-keys` prints; `writ init` wires git for gpg (`gpg.format = openpgp`, `writ-sign` as
//! `gpg.openpgp.program`, the key's fingerprint as `user.signingkey`); commits sign with a
//! hostile GnuPG home and agent in the environment, never used. On Forgejo the commits are
//! unverified until the key is added to the account with its proof: Forgejo's GPG challenge
//! (`/user/gpg_key_token`) signed in OpenPGP through `writ prove-key` (an approval); then
//! verified, the signer the account. The agent verifies them itself through `writ-sign
//! --verify`, handed to the real gpg (`WRIT_GPG`). A sign request in SSH under this lease is
//! denied (`signature_format`), logged, nothing signed.

use writ_e2e::Stack;
use writ_e2e::agent::{expect, ticket};
use writ_e2e::forgejo::EMAIL;

#[test]
#[ignore = "end to end: make e2e"]
fn an_openpgp_key_is_proven_on_forgejo_and_its_commits_show_verified() {
    let stack = Stack::shared();
    let agent = stack.agent("openpgp");
    let lease = agent.lease(
        &stack,
        &ticket(&["openpgp"], &["agent/*"], "1h", "")
            .replace("template: feature", "template: openpgp"),
    );
    // The lease's certificate is the one the operator registers.
    let certificate = agent.session_file(&lease, "signing_key.asc");
    assert!(
        certificate.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"),
        "{certificate}"
    );
    let line = stack
        .report
        .signing_keys
        .iter()
        .find(|l| l.starts_with("agent-e2e-pgp "))
        .unwrap();
    let fingerprint = line.split(' ').nth(2).unwrap().to_owned();
    assert_eq!(fingerprint.len(), 40, "{line}");
    let printed = stack.operator.ok("writd signing-keys writd.yaml");
    assert!(printed.contains(certificate.trim()), "{printed}");

    // Wired for gpg.
    agent.clone_from_forgejo(&stack, "openpgp", "work");
    agent.ok_in("work", "writ init openpgp");
    agent.ok_in("work", "git checkout -q -b agent/openpgp");
    assert_eq!(
        agent.ok_in("work", "writ git config gpg.format").trim(),
        "openpgp"
    );
    assert_eq!(
        agent
            .ok_in("work", "writ git config user.signingkey")
            .trim(),
        fingerprint
    );

    // Signed with a hostile GnuPG home and agent socket in the environment (a home nobody
    // may read, a socket that is a plain file): writ-sign never runs gpg to sign.
    agent.ok(
        "mkdir -p hostile-gnupg && printf 'not a socket\\n' > hostile-gnupg/S.gpg-agent && \
         chmod 000 hostile-gnupg",
    );
    let push = |file: &str| {
        let commit = agent
            .ok_in(
                "work",
                &format!(
                    "printf '%s\\n' {file} > {file} && writ git add {file} && \
                     GNUPGHOME=$(cd .. && pwd)/hostile-gnupg \
                     GPG_AGENT_INFO=$(cd .. && pwd)/hostile-gnupg/S.gpg-agent \
                     writ git commit -q -m 'Change {file}' --trailer 'Writ: {lease}' && \
                     git rev-parse HEAD"
                ),
            )
            .trim()
            .to_owned();
        expect(
            &agent.in_dir("work", "writ git push -q origin HEAD"),
            0,
            "a push",
        );
        assert_eq!(
            stack.forgejo.branch("openpgp", "agent/openpgp").as_deref(),
            Some(commit.as_str())
        );
        commit
    };
    let first = push("one.txt");
    agent.ok("chmod 700 hostile-gnupg");
    assert_eq!(
        agent.ok("ls hostile-gnupg"),
        "S.gpg-agent\n",
        "nothing written there"
    );
    assert!(
        agent
            .ok_in("work", "git cat-file commit HEAD")
            .contains("gpgsig -----BEGIN PGP SIGNATURE-----"),
    );

    // The agent verifies it: the certificate imported in a home of its own, writ-sign handing
    // --verify to the real gpg.
    agent.ok("mkdir -p verify-gnupg && chmod 700 verify-gnupg && \
         gpg --batch --homedir verify-gnupg --import .writ/sessions/current/signing_key.asc");
    let out = agent.in_dir(
        "work",
        "GNUPGHOME=$(cd .. && pwd)/verify-gnupg WRIT_GPG=/usr/bin/gpg writ git verify-commit HEAD",
    );
    let (_, said) = expect(&out, 0, "verify-commit through writ-sign");
    assert!(
        said.contains("Good signature from \"Writ agent <agent@writ.invalid>\""),
        "{said}"
    );

    // Not on the account yet: unverified.
    let (verified, why) = stack.forgejo.verification("openpgp", &first);
    assert!(!verified, "{why}");

    // Proven: Forgejo's challenge signed in OpenPGP through `writ prove-key` (an approval),
    // then the key added to the account with it.
    let token = stack.forgejo.gpg_key_token();
    let out = stack.approver.run_with(
        "writ prove-key agent-e2e-pgp --namespace gitea --yes",
        token.as_bytes(),
    );
    let (signature, said) = expect(&out, 0, "the OpenPGP proof");
    assert!(said.contains("Signed by agent-e2e-pgp (SHA256:"), "{said}");
    assert!(said.contains("in OpenPGP"), "{said}");
    assert!(
        signature.starts_with("-----BEGIN PGP SIGNATURE-----\n"),
        "{signature}"
    );
    let (status, key) = stack.forgejo.add_gpg_key(&certificate, &signature);
    assert_eq!(status, 201, "{key}");
    assert_eq!(key["verified"], true, "{key}");
    assert!(
        key["emails"]
            .as_array()
            .is_some_and(|emails| emails.iter().any(|e| e["email"] == EMAIL)),
        "{key}"
    );
    assert!(
        fingerprint.ends_with(key["key_id"].as_str().unwrap()),
        "{key}"
    );

    // Verified now, signed by the account's key.
    let second = push("two.txt");
    let (verified, why) = stack.forgejo.verification("openpgp", &second);
    assert!(verified, "{why}");
    assert_eq!(why["signer"]["email"], EMAIL, "{why}");

    // An SSH signature asked under this lease: denied, logged, nothing signed.
    let before = agent.ok_in("work", "git rev-parse HEAD");
    let out = agent.in_dir(
        "work",
        &format!(
            "writ git -c gpg.format=ssh -c gpg.ssh.program=$(command -v writ-sign) commit -q \
             --allow-empty -m 'ssh' --trailer 'Writ: {lease}'"
        ),
    );
    let (_, err) = expect(&out, 128, "an SSH signature under an OpenPGP lease");
    assert!(
        err.contains("signs in openpgp, and git asked for ssh"),
        "{err}"
    );
    assert_eq!(agent.ok_in("work", "git rev-parse HEAD"), before);
    assert!(
        stack.audit().iter().any(|e| e["event"] == "sign"
            && e["result"] == "denied"
            && e["code"] == "signature_format"
            && e["lease"] == lease.as_str()),
        "the denial is logged"
    );
    // The proof logged, never the challenge.
    assert!(
        stack.audit().iter().any(|e| e["event"] == "prove"
            && e["result"] == "allowed"
            && e["key"] == "agent-e2e-pgp")
    );
    assert!(!stack.operator.read("data/audit.jsonl").contains(&token));
}
