//! Scenario 23, managing the daemon from the approver's machine (M6.2,
//! docs/backlog/daemon-management-from-the-cli.md): `writ admin repo|template|key|host`,
//! with the reader key only for the reads. Every entry of the policy in force listed and shown
//! as the policy writes it; each key's public half as the daemon's signers hold it (the same
//! the operator registered from `writd upstream-keys` and `writd signing-keys`), a token's
//! only as added or not, never its value; Forgejo's pin with the fingerprint the setup
//! compared with the one Forgejo publishes.

use writ_e2e::Stack;
use writ_e2e::agent::expect;
use writ_e2e::setup::HTTPS_CREDENTIAL;

#[test]
#[ignore = "end to end: make e2e"]
fn the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine() {
    let stack = Stack::shared();
    let approver = &stack.approver;
    let report = &stack.report;

    // Repos: one line each, the closed ones said; one shown as the policy writes it.
    let repos = approver.ok("writ admin repo list");
    assert!(
        repos.lines().any(|l| l
            == "setup  ssh://git@forgejo/writ/setup.git  credential upstream-setup  templates \
                feature"),
        "{repos}"
    );
    assert!(
        repos
            .lines()
            .any(|l| l.starts_with("pr-api  ") && l.ends_with("templates feature, pr-backend")),
        "{repos}"
    );
    let setup = approver.ok("writ admin repo show setup");
    assert!(
        setup.starts_with(
            "setup:\n  upstream: \"ssh://git@forgejo/writ/setup.git\"\n  upstream_credential: \
             upstream-setup\n  templates: [feature]\n  protected_refs: [refs/heads/main, \
             refs/tags/*]\n"
        ),
        "{setup}"
    );
    assert!(setup.contains("\nhost pin: forgejo\n"), "{setup}");
    assert!(
        setup.contains("\ncredential: upstream-setup (upstream ssh ed25519)\n"),
        "{setup}"
    );
    let missing = approver.run("writ admin repo show nowhere");
    let (_, why) = expect(&missing, 1, "a repo not in the policy");
    assert!(
        why.contains("no repo nowhere in the policy in force (writ admin repo list)"),
        "{why}"
    );

    // Templates: what each allows, and the repos that name it.
    let templates = approver.ok("writ admin template list");
    assert!(
        templates
            .lines()
            .any(|l| l == "pr-frontend  fetch, commit_sign, push  max_ttl 1h  repos pr-web"),
        "{templates}"
    );
    let frontend = approver.ok("writ admin template show pr-frontend");
    assert!(
        frontend.starts_with("pr-frontend:\n  operations: [fetch, commit_sign, push]\n"),
        "{frontend}"
    );
    assert!(frontend.contains("  paths_check: deny\n"), "{frontend}");
    assert!(frontend.ends_with("repos: pr-web\n"), "{frontend}");

    // Keys: every one the policy declares, its public half from the daemon's signers.
    let keys = approver.ok("writ admin key list");
    for line in &report.upstream_keys {
        // `<id> <type> <base64> (repos: …)`, as `writd upstream-keys` printed it.
        let id = line.split(' ').next().unwrap();
        let public = line
            .split(' ')
            .skip(1)
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            keys.lines()
                .any(|l| l.starts_with(&format!("{id}  upstream ssh ed25519  SHA256:"))),
            "{id}: {keys}"
        );
        // `--public`: the same public half the operator registered as a deploy key.
        let printed = approver.ok(&format!("writ admin key show {id} --public"));
        assert_eq!(printed.trim(), public, "{id}");
    }
    assert!(
        keys.lines().any(|l| l
            == format!("{HTTPS_CREDENTIAL}  upstream token for forgejo-https  added  repos https")),
        "{keys}"
    );
    // A token: whether it was added, never its value, and no public half to print.
    let token = approver.ok(&format!("writ admin key show {HTTPS_CREDENTIAL}"));
    assert!(token.contains("\ntoken: added\n"), "{token}");
    assert!(!token.contains(&report.https_token), "the token itself");
    assert!(!keys.contains(&report.https_token), "the token itself");
    let (_, why) = expect(
        &approver.run(&format!("writ admin key show {HTTPS_CREDENTIAL} --public")),
        1,
        "a token's public half",
    );
    assert!(why.contains("is a token: it has no public half"), "{why}");
    // An OpenPGP key: its fingerprint and certificate, the one `writd signing-keys` printed.
    let pgp = approver.ok("writ admin key show agent-e2e-pgp");
    assert!(
        pgp.starts_with("agent-e2e-pgp:\n  use: signing\n  format: openpgp\n"),
        "{pgp}"
    );
    assert!(pgp.contains("\nused by: templates openpgp\n"), "{pgp}");
    let pgp_line = report
        .signing_keys
        .iter()
        .find(|l| l.starts_with("agent-e2e-pgp openpgp "))
        .unwrap();
    let fingerprint = pgp_line.split(' ').nth(2).unwrap();
    assert!(
        pgp.contains(&format!("\nOpenPGP fingerprint: {fingerprint}\n")),
        "{pgp}"
    );
    let certificate = approver.ok("writ admin key show agent-e2e-pgp --public");
    assert!(
        certificate.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"),
        "{certificate}"
    );

    // Hosts: Forgejo's pin, with the fingerprint the setup compared with Forgejo's.
    let hosts = approver.ok("writ admin host list");
    assert!(
        hosts
            .lines()
            .any(|l| l.starts_with("forgejo  1 key  repos ")),
        "{hosts}"
    );
    let forgejo = approver.ok("writ admin host show forgejo");
    let compared = report
        .upstream_fingerprint
        .split(' ')
        .nth(1)
        .expect("ssh-keygen -lf printed a fingerprint");
    assert!(
        forgejo.contains(&format!("\nfingerprint: ssh-ed25519 {compared}\n")),
        "{forgejo}: {}",
        report.upstream_fingerprint
    );
    assert!(forgejo.contains(&report.published_upstream), "{forgejo}");

    // The reads go through the approval API's own URL flag as well as its variable.
    let url = approver.ok("printf %s \"$WRIT_APPROVAL_URL\"");
    for noun in ["repo", "template", "key", "host"] {
        let listed = approver.ok(&format!("writ admin {noun} list --approval-url {url}"));
        assert!(!listed.is_empty(), "{noun}");
    }
    for (noun, name) in [
        ("repo", "setup"),
        ("template", "feature"),
        ("key", "agent-e2e"),
        ("host", "forgejo"),
    ] {
        let shown = approver.ok(&format!(
            "writ admin {noun} show {name} --approval-url {url}"
        ));
        assert!(shown.starts_with(&format!("{name}:\n")), "{noun}: {shown}");
    }
}
