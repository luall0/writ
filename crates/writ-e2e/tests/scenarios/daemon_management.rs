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

/// The approval flags, given explicitly (each command's `--approval-url`, `--key`, `--agent`),
/// and `--yes`.
const FLAGS: &str = "--yes --approval-url \"$WRIT_APPROVAL_URL\" --key \
                     \"$HOME/.writ/approver.pub\" --agent \"$WRIT_APPROVAL_AGENT\"";

/// The version of the policy in force.
fn version(approver: &writ_e2e::docker::Host) -> String {
    let out = approver.run("writ admin show policy >/dev/null");
    writ_e2e::stderr(&out)
        .split_whitespace()
        .nth(2)
        .unwrap_or_default()
        .to_owned()
}

#[test]
#[ignore = "end to end: make e2e"]
fn the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine() {
    // It changes the policy every scenario runs under: alone, and put back at the end as it
    // was (the text other scenarios edit by hand).
    let stack = Stack::exclusive();
    let approver = &stack.approver;
    approver.ok("writ admin show policy > policy-before.yaml");

    // set: only the fields named, in every syntax, one signed change each.
    let said = approver.ok(&format!(
        "writ admin template set managed max_ttl=2h max_renewals=2 {FLAGS}"
    ));
    // The setup's own `writ admin` changes wrote the policy in Writ's layout already (the
    // first change's note is field_edits' integration test).
    assert!(!said.contains("isn't in Writ's layout"), "{said}");
    assert!(said.contains("\n+     max_ttl: 2h\n"), "{said}");
    let shown = approver.ok("writ admin template show managed");
    assert!(
        shown.contains("  max_ttl: 2h\n  max_signatures: 0\n"),
        "{shown}"
    );
    assert!(shown.contains("  max_renewals: 2\n"), "{shown}");
    let said = approver.ok(&format!(
        "writ admin template set managed max_renewals! {FLAGS}"
    ));
    assert!(said.contains("\n-     max_renewals: 2\n"), "{said}");
    approver.ok(&format!(
        "writ admin key set managed-signing hash=sha256 {FLAGS}"
    ));
    assert!(
        approver
            .ok("writ admin key show managed-signing")
            .contains("  hash: sha256\n")
    );
    approver.ok("rm -f extra && ssh-keygen -q -t ed25519 -N '' -C '' -f extra");
    let extra = approver.ok("cut -d' ' -f1,2 extra.pub");
    approver.ok(&format!(
        "writ admin host set managed.invalid \"keys+={}\" {FLAGS}",
        extra.trim()
    ));
    let host = approver.ok("writ admin host show managed.invalid");
    assert_eq!(
        host.matches("\nfingerprint: ssh-ed25519 SHA256:").count(),
        2,
        "{host}"
    );
    approver.ok(&format!(
        "writ admin repo set setup protected_refs+=refs/heads/release protected_refs-=refs/tags/* {FLAGS}"
    ));
    assert!(
        approver
            .ok("writ admin repo show setup")
            .contains("  protected_refs: [refs/heads/main, refs/heads/release]\n")
    );
    // Refused with the reason, naming the field; nothing changed.
    let before = version(approver);
    for (command, why) in [
        (
            "writ admin template set managed operations+=commit_sign",
            "templates.managed.branches: required with commit_sign or push",
        ),
        (
            "writ admin key set managed-signing format=openpgp",
            "keys.managed-signing.format: can't change: it is what the key is",
        ),
        (
            "writ admin repo set setup max_ttl=1h",
            "repo has no field \"max_ttl\"",
        ),
    ] {
        let (_, err) = expect(&approver.run(&format!("{command} {FLAGS}")), 1, command);
        assert!(err.contains(why), "{command}: {err}");
    }
    assert_eq!(version(approver), before);

    // remove: refused while something uses it, naming what.
    let (_, err) = expect(
        &approver.run(&format!("writ admin template remove feature {FLAGS}")),
        1,
        "a template repos name",
    );
    assert!(
        err.contains("template feature is in use by repos "),
        "{err}"
    );
    // A key: its id typed again on a terminal; a mistyped one sends nothing.
    let mistyped = approver.run_with(
        "script -qec \"writ admin key remove managed-signin\" /dev/null",
        b"managed-signing\n",
    );
    assert!(
        writ_e2e::stdout(&mistyped).contains("no key managed-signin in the policy in force"),
        "{}",
        writ_e2e::stdout(&mistyped)
    );
    let mistyped = approver.run_with(
        "script -qec \"writ admin key remove managed-signing\" /dev/null",
        b"managed-signin\n",
    );
    assert!(
        writ_e2e::stdout(&mistyped).contains("Not signed: that is not managed-signing."),
        "{}",
        writ_e2e::stdout(&mistyped)
    );
    assert_eq!(version(approver), before, "nothing sent");
    assert_eq!(
        stack
            .operator
            .run("test -e data/keys/signing/managed-signing.age")
            .status
            .code(),
        Some(0)
    );
    let public = stack
        .operator
        .ok("cat data/keys/signing/managed-signing.pub");
    let said = approver.ok(&format!("writ admin key remove managed-signing {FLAGS}"));
    assert!(
        said.contains("Deleted signing ssh ed25519 managed-signing (SHA256:")
            && said.trim_end().ends_with(public.trim()),
        "{said}"
    );
    assert_eq!(
        stack
            .operator
            .run("test -e data/keys/signing/managed-signing.age || test -e data/keys/signing/managed-signing.pub")
            .status
            .code(),
        Some(1),
        "the key's files are deleted"
    );
    let audit = stack
        .operator
        .ok("grep '\"event\":\"admin\"' data/audit.jsonl | tail -n 1");
    assert!(
        audit.contains("removed signing ssh ed25519 managed-signing (SHA256:"),
        "{audit}"
    );
    // A template, a host, a repo nothing else needs.
    approver.ok(&format!("writ admin template remove managed {FLAGS}"));
    approver.ok(&format!("writ admin host remove managed.invalid {FLAGS}"));
    let said = approver.ok(&format!("writ admin repo remove setup {FLAGS}"));
    assert!(said.contains("Applied: policy is version "), "{said}");
    let repos = approver.ok("writ admin repo list");
    assert!(!repos.lines().any(|l| l.starts_with("setup  ")), "{repos}");

    // Put back as it was: the text other scenarios edit (the removed key made again, new).
    let said = approver.ok("writ admin apply policy policy-before.yaml --yes");
    assert!(
        said.contains("New signing key managed-signing (register it on the remote): "),
        "{said}"
    );
    assert_eq!(
        approver.ok("writ admin show policy"),
        approver.ok("cat policy-before.yaml")
    );
}

/// `command` on a terminal (`script`), `answers` typed one per line: what it showed (the
/// streams merged, rows ending in `\r\n`).
fn on_terminal(approver: &writ_e2e::docker::Host, command: &str, answers: &[&str]) -> String {
    let typed: String = answers.iter().map(|a| format!("{a}\n")).collect();
    let out = approver.run_with(
        &format!("script -qec '{command}' /dev/null"),
        typed.as_bytes(),
    );
    writ_e2e::stdout(&out)
}

#[test]
#[ignore = "end to end: make e2e"]
fn entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal() {
    // It changes the policy every scenario runs under: alone, and put back at the end.
    let stack = Stack::exclusive();
    let approver = &stack.approver;
    approver.ok("writ admin show policy > guided-before.yaml");
    let url = "--approval-url \"$WRIT_APPROVAL_URL\" --key \"$HOME/.writ/approver.pub\" --agent \"$WRIT_APPROVAL_AGENT\"";

    // A template from another one's values: each field asked, Enter keeping it, the fields a
    // fetch-only template doesn't take never asked.
    let shown = on_terminal(
        approver,
        &format!("writ admin template add guided --from managed {url}"),
        &["", "3h", "", "", "", "", "", "", "y"],
    );
    assert!(shown.contains("max_ttl (the longest lease"), "{shown}");
    assert!(
        !shown.contains("branches ("),
        "a fetch-only template asks no branches: {shown}"
    );
    assert!(shown.contains("Applied: policy is version "), "{shown}");
    let guided = approver.ok("writ admin template show guided");
    assert!(
        guided.contains("  operations: [fetch]\n  max_ttl: 3h\n"),
        "{guided}"
    );
    // A token: its use and kind asked first, then only its host.
    let shown = on_terminal(
        approver,
        &format!("writ admin key add guided-token {url}"),
        &["upstream", "token", "forgejo-https", "y"],
    );
    assert!(
        !shown.contains("algorithm ("),
        "a token has no algorithm: {shown}"
    );
    assert!(
        shown.contains("Next: add the token for forgejo-https from forgejo-https: writ admin token guided-token"),
        "{shown}"
    );
    assert!(approver.ok("writ admin key list").contains(
        "guided-token  upstream token for forgejo-https  not added yet (writ admin token)  unused"
    ));
    // A repo with a new credential, declared in the same change (RSA: some remotes take only
    // RSA keys); then edited, each field kept but those changed.
    let shown = on_terminal(
        approver,
        &format!("writ admin repo add guided-repo {url}"),
        &[
            "ssh://git@forgejo/writ/guided.git",
            "new",
            "",
            "rsa3072",
            "managed",
            "",
            "",
            "",
            "",
            "y",
            "",
        ],
    );
    assert!(
        shown.contains(
            "New upstream credential guided-repo-upstream (register it on the remote): ssh-rsa "
        ),
        "{shown}"
    );
    // Enter once it is registered: it isn't, so the check fails at reading.
    assert!(shown.contains("  read: failed: "), "{shown}");
    assert!(
        shown.contains("as a deploy key with write access"),
        "{shown}"
    );
    let shown = on_terminal(
        approver,
        &format!("writ admin repo edit guided-repo {url}"),
        &["", "", "managed,guided", "refs/heads/main", "", "", "", "y"],
    );
    assert!(
        shown.contains(
            "with repo guided-repo edited: templates=managed,guided protected_refs=refs/heads/main"
        ),
        "{shown}"
    );
    let repo = approver.ok("writ admin repo show guided-repo");
    assert!(
        repo.contains("  templates: [guided, managed]\n  protected_refs: [refs/heads/main]\n"),
        "{repo}"
    );
    // A key's and a template's edit: only what isn't the key itself is asked.
    let shown = on_terminal(
        approver,
        &format!("writ admin key edit managed-signing {url}"),
        &["sha512", "y"],
    );
    assert!(!shown.contains("algorithm ("), "{shown}");
    assert!(
        approver
            .ok("writ admin key show managed-signing")
            .contains("  hash: sha512\n")
    );
    let shown = on_terminal(
        approver,
        &format!("writ admin template edit guided {url}"),
        &["", "", "", "", "7", "", "", "", "y"],
    );
    assert!(shown.contains("max_ops_per_minute=7"), "{shown}");
    // A host: given whole without a terminal (scanning one is `host add` with no keys), and
    // an edit that changes nothing sends nothing.
    approver.ok("rm -f guided && ssh-keygen -q -t ed25519 -N '' -C '' -f guided");
    let key = approver.ok("cut -d' ' -f1,2 guided.pub");
    approver.ok(&format!(
        "writ admin host add guided.invalid \"keys={}\" --yes {url}",
        key.trim()
    ));
    let shown = on_terminal(
        approver,
        &format!("writ admin host edit guided.invalid {url}"),
        &[""],
    );
    assert!(shown.contains("Nothing changed."), "{shown}");

    // rotate on a terminal: the new key, Enter once it is registered, the switch, then the old
    // key removed (its id typed again).
    let shown = on_terminal(
        approver,
        &format!("writ admin key rotate guided-repo-upstream {url}"),
        &["y", "", "y", "y", "guided-repo-upstream", "y"],
    );
    assert!(
        shown.contains(
            "New upstream credential guided-repo-upstream-2 (register it on the remote): ssh-rsa "
        ),
        "{shown}"
    );
    assert!(
        shown.contains("Deleted upstream ssh rsa3072 guided-repo-upstream (SHA256:"),
        "{shown}"
    );
    let keys = approver.ok("writ admin key list");
    assert!(!keys.contains("guided-repo-upstream  "), "{keys}");
    assert!(
        keys.contains("guided-repo-upstream-2  upstream ssh rsa3072  SHA256:"),
        "{keys}"
    );
    assert!(keys.contains("repos guided-repo"), "{keys}");
    // Named, without a terminal: --yes answers the question between the two changes.
    let said = approver.ok(&format!(
        "writ admin key rotate guided-token --name guided-token-next --yes {url}"
    ));
    assert!(
        said.contains("guided-token stays declared, unused"),
        "{said}"
    );
    // add and edit with --yes given (the diff still shown, no question).
    let said = approver.ok(&format!(
        "writ admin template add guided-yes --from guided --yes {url}"
    ));
    assert!(said.contains("with template guided-yes added"), "{said}");
    let said = approver.ok(&format!(
        "writ admin key add guided-signing use=signing format=ssh algorithm=p256 --yes {url}"
    ));
    assert!(
        said.contains(
            "New signing key guided-signing (register it on the remote): ecdsa-sha2-nistp256 "
        ),
        "{said}"
    );
    let said = approver.ok(&format!(
        "writ admin repo add guided-other upstream=ssh://git@forgejo/writ/guided-other.git upstream_credential=guided-repo-upstream-2 templates= --yes {url}"
    ));
    assert!(said.contains("with repo guided-other added"), "{said}");
    for (noun, name, answers) in [
        ("repo", "guided-other", vec!["", "", "", "", "", "", ""]),
        ("template", "guided-yes", vec!["", "", "", "", "", "", ""]),
        ("key", "guided-signing", vec!["sha256"]),
        ("host", "guided.invalid", vec![""]),
    ] {
        let shown = on_terminal(
            approver,
            &format!("writ admin {noun} edit {name} --yes {url}"),
            &answers,
        );
        assert!(
            !shown.contains("Sign this change?"),
            "{noun}: --yes asks no question: {shown}"
        );
    }

    // Put back as it was (the keys removed or rotated made again, new).
    approver.ok("writ admin apply policy guided-before.yaml --yes");
    assert_eq!(
        approver.ok("writ admin show policy"),
        approver.ok("cat guided-before.yaml")
    );
}

#[test]
#[ignore = "end to end: make e2e"]
fn a_host_is_scanned_from_the_daemon_rescanned_and_a_repo_checked_against_forgejo() {
    // It changes the policy every scenario runs under: alone, and put back at the end.
    let stack = Stack::exclusive();
    let approver = &stack.approver;
    approver.ok("writ admin show policy > scan-before.yaml");
    let url = "--approval-url \"$WRIT_APPROVAL_URL\" --key \"$HOME/.writ/approver.pub\" --agent \"$WRIT_APPROVAL_AGENT\"";
    // Forgejo's key, as the setup compared it with the one Forgejo publishes.
    let compared = stack
        .report
        .upstream_fingerprint
        .split(' ')
        .nth(1)
        .expect("ssh-keygen -lf printed a fingerprint")
        .to_owned();

    // Without a terminal, a scan isn't offered: the keys are given.
    let refused = approver.run(&format!("writ admin host add forgejo-scan --yes {url}"));
    let (_, why) = expect(&refused, 1, "a scan without a terminal");
    assert!(
        why.contains("host add scans the host on a terminal, where you compare its keys"),
        "{why}"
    );
    // On a terminal: the daemon scans Forgejo under another name on the approver's
    // signature; its key is the one compared at setup; pinned once confirmed.
    let shown = on_terminal(
        approver,
        &format!("writ admin host add forgejo-scan {url}"),
        &["y", "y"],
    );
    assert!(
        shown.contains("Scanning forgejo-scan:22 from the daemon"),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("  ssh-ed25519 {compared}\r\n")),
        "{shown}"
    );
    assert!(shown.contains("Applied: policy is version "), "{shown}");
    let host = approver.ok("writ admin host show forgejo-scan");
    assert!(
        host.contains(&format!("\nfingerprint: ssh-ed25519 {compared}\n")),
        "{host}"
    );
    // Rescanned: the key is the one pinned, nothing to change.
    let shown = on_terminal(
        approver,
        &format!("writ admin host rescan forgejo-scan --yes {url}"),
        &["y"],
    );
    assert!(
        shown.contains(&format!("  ssh-ed25519 {compared}  (pinned)\r\n")),
        "{shown}"
    );
    assert!(
        shown.contains("The pin already holds these keys: nothing changed."),
        "{shown}"
    );
    // A pin gone stale (another key): the rescan shows Forgejo's as new, replaces it.
    approver.ok("rm -f stale && ssh-keygen -q -t ed25519 -N '' -C '' -f stale");
    let stale = approver.ok("cut -d' ' -f1,2 stale.pub");
    approver.ok(&format!(
        "writ admin host set forgejo-scan \"keys={}\" --yes {url}",
        stale.trim()
    ));
    let shown = on_terminal(
        approver,
        &format!("writ admin host rescan forgejo-scan {url}"),
        &["y", "y"],
    );
    assert!(
        shown.contains(&format!(
            "  ssh-ed25519 {compared}  (new: not in the pin)\r\n"
        )),
        "{shown}"
    );
    assert!(
        shown.contains("with host forgejo-scan rescanned"),
        "{shown}"
    );
    assert!(
        approver
            .ok("writ admin host show forgejo-scan")
            .contains(&format!("\nfingerprint: ssh-ed25519 {compared}\n"))
    );
    // The daemon logged each scan, with what it read and who signed for it.
    let scans: Vec<_> = stack
        .audit()
        .into_iter()
        .filter(|e| {
            e["event"] == "scan"
                && e["result"] == "allowed"
                && e["reason"]
                    .as_str()
                    .is_some_and(|r| r.starts_with("forgejo-scan:22: "))
        })
        .collect();
    assert_eq!(scans.len(), 3, "{scans:?}");
    assert!(
        scans.iter().all(|e| e["reason"]
            .as_str()
            .is_some_and(|r| r.starts_with("forgejo-scan:22: ") && r.contains(&compared))
            && e["approver"]
                .as_str()
                .is_some_and(|a| a.starts_with("SHA256:"))),
        "{scans:?}"
    );

    // The check, without a terminal: setup's credential reads, syncs and writes (nothing
    // pushed), through --approval-url too.
    let checked = approver.ok("writ admin repo check setup");
    assert!(
        checked.contains("  read: ok: upstream answers with its credential"),
        "{checked}"
    );
    assert!(checked.contains("  sync: ok: "), "{checked}");
    assert!(
        checked.contains("  write: ok: upstream takes pushes with its credential (nothing pushed)"),
        "{checked}"
    );
    assert!(checked.contains("setup is ready"), "{checked}");
    approver.ok("writ admin repo check setup --approval-url \"$WRIT_APPROVAL_URL\"");
    let missing = approver.run("writ admin repo check nowhere");
    let (_, why) = expect(&missing, 1, "a repo not in the registry");
    assert!(why.contains("repo nowhere is not in the registry"), "{why}");

    // A repo added step by step on a host with no pin: scanned in the same change, then
    // checked once Enter says its credential is registered (setup's, which is).
    let shown = on_terminal(
        approver,
        &format!("writ admin repo add scanned {url}"),
        &[
            "ssh://git@forgejo-new/writ/setup.git",
            "y",
            "upstream-setup",
            "managed",
            "",
            "",
            "",
            "",
            "y",
            "",
        ],
    );
    assert!(
        shown.contains("Its host forgejo-new has no pin: it is scanned now."),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("  ssh-ed25519 {compared}\r\n")),
        "{shown}"
    );
    assert!(shown.contains("scanned is ready"), "{shown}");
    // Pinned with every key Forgejo offers.
    let hosts = approver.ok("writ admin host list");
    assert!(
        hosts
            .lines()
            .any(|l| l.starts_with("forgejo-new  ") && l.ends_with("  repos scanned")),
        "{hosts}"
    );

    // Put back as it was.
    approver.ok("writ admin apply policy scan-before.yaml --yes");
    assert_eq!(
        approver.ok("writ admin show policy"),
        approver.ok("cat scan-before.yaml")
    );
}
