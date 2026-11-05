//! Scenario 1, the operator setup from nothing (docs/operators/setup.md):
//! the setup runs once per stack, with the guide's own commands ([`writ_e2e::setup`]); this
//! checks what it saw and that the daemon it started checks every push. Since M5 the daemon
//! runs on a sealed keystore: `writd init` (the approvers and readers listed first), the
//! commands that print a key with no passphrase (before the daemon starts), `writ unseal`,
//! and the HTTPS repo's token through `writ admin token`. A daemon started on a relative
//! configuration path running pushes with no hook (M4's GitHub check, fixed in fd57274) fails
//! here: the protected ref below would go through.

use writ_e2e::Stack;
use writ_e2e::agent::expect;

use crate::{assert_push_refused, wired};

/// The registry's repositories (e2e/config/policy.yaml).
const REPOS: &[&str] = &[
    "setup",
    "lifecycle",
    "narrowing",
    "demo",
    "whole",
    "denials",
    "moved",
    "protection",
    "protocols",
    "openpgp",
    "verified",
    "inflight",
    "restart",
    "hostile",
    "busy",
    "notes",
    "backfill",
    "sessions",
    "ws-api",
    "ws-web",
    "pr-api",
    "pr-web",
];

#[test]
#[ignore = "end to end: make e2e"]
fn the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says() {
    let stack = Stack::shared();
    let report = &stack.report;

    // `writd init` made the keystore and printed what to register; the commands that print a
    // key ran after it, before the daemon started: no passphrase.
    assert!(
        report.init_printed.starts_with("keystore made: /"),
        "{}",
        report.init_printed
    );
    assert!(
        report.init_printed.contains("recipient: age1"),
        "{}",
        report.init_printed
    );
    let ran: Vec<&str> = report.printed.iter().map(|(c, _)| c.as_str()).collect();
    assert_eq!(
        ran,
        [
            "writd upstream-keys writd.yaml",
            "writd signing-keys writd.yaml",
            "writd host-key writd.yaml",
            "writd tls-fingerprint writd.yaml",
        ]
    );
    // One upstream credential per repo, each a deploy key on its repository only.
    assert_eq!(
        report.upstream_keys.len(),
        REPOS.len(),
        "{:?}",
        report.upstream_keys
    );
    for repo in REPOS {
        let line = report
            .upstream_keys
            .iter()
            .find(|l| l.starts_with(&format!("upstream-{repo} ssh-ed25519 ")))
            .unwrap_or_else(|| panic!("no credential for {repo}: {:?}", report.upstream_keys));
        assert!(line.ends_with(&format!(" (repos: {repo})")), "{line}");
        assert_eq!(stack.forgejo.deploy_keys(repo).len(), 1, "{repo}");
    }
    // Every declared signing key, with the templates that name it (scenario 23's named by
    // none).
    assert_eq!(report.signing_keys.len(), 4, "{:?}", report.signing_keys);
    assert!(report.signing_keys[0].starts_with("agent-e2e ssh-ed25519 "));
    assert!(
        report.signing_keys[0].ends_with(" (templates: feature, pr-backend, pr-frontend)"),
        "{:?}",
        report.signing_keys
    );
    // The OpenPGP key: its fingerprint and algorithm (its certificate on the lines after).
    assert!(report.signing_keys[1].starts_with("agent-e2e-pgp openpgp "));
    assert!(report.signing_keys[1].ends_with(" (ed25519) (templates: openpgp)"));
    assert!(report.signing_keys[2].starts_with("agent-e2e-verify ssh-ed25519 "));
    assert!(report.signing_keys[2].ends_with(" (templates: verified)"));
    assert!(report.signing_keys[3].starts_with("managed-signing ssh-ed25519 "));
    assert!(report.signing_keys[3].ends_with(" (templates: )"));
    assert!(
        report.host_key.starts_with("ssh-ed25519 "),
        "{}",
        report.host_key
    );
    assert!(
        report.tls_fingerprint.starts_with("SHA256:"),
        "{}",
        report.tls_fingerprint
    );
    // Forgejo's host key pinned as it publishes it, and its fingerprint shown to compare.
    assert_eq!(
        report.pinned_upstream,
        format!("forgejo {}", report.published_upstream)
    );
    assert!(
        report.upstream_fingerprint.contains("forgejo"),
        "{}",
        report.upstream_fingerprint
    );
    assert!(
        report.upstream_fingerprint.contains("(ED25519)"),
        "{}",
        report.upstream_fingerprint
    );
    assert!(report.reader_line.starts_with("e2e-approver ssh-ed25519 "));

    // The daemon runs as started: from its directory, on the relative path.
    assert_eq!(report.config_path, "writd.yaml");
    let processes = stack
        .operator
        .ok("for p in /proc/[0-9]*; do tr '\\0' ' ' < $p/cmdline 2>/dev/null; echo; done");
    assert!(
        processes
            .lines()
            .any(|l| l.trim_end() == "writd run writd.yaml"),
        "{processes}"
    );
    // Its log names the approver and the reader the operator listed.
    let approval_key = stack.approver.ok("ssh-keygen -lf .writ/approver.pub");
    let fingerprint = approval_key.split_whitespace().nth(1).unwrap();
    let log = stack.operator.read("writd.log");
    assert!(log.contains(&format!("fingerprint={fingerprint}")), "{log}");
    assert!(log.contains("name=e2e-approver"), "{log}");
    // The pre-receive hook the daemon gives git (`-c core.hooksPath=<state>/run/hooks`, an
    // absolute path), in place and executable. Whether git finds it is what the refused push
    // below proves: with a relative path (fd57274's bug) the push to main went through.
    stack.operator.ok("test -x data/run/hooks/pre-receive");
    for repo in REPOS {
        stack.operator.ok(&format!("test -d data/repos/{repo}.git"));
    }

    // And the daemon it started checks pushes: the protected branch refused, nothing on
    // Forgejo; an allowed branch lands there and in the mirror.
    let agent = stack.agent("operator-setup");
    let (lease, work) = wired(&stack, &agent, "setup");
    let main = stack.forgejo.branch("setup", "main").unwrap();
    let commit = agent.commit(&work, &lease, "notes.txt", "set up");
    let out = agent.in_dir(&work, "writ git push origin HEAD:refs/heads/main");
    assert_push_refused(
        &stack,
        &lease,
        &out,
        "refs/heads/main is protected",
        "protected_ref",
    );
    assert_eq!(
        stack.forgejo.branch("setup", "main").as_deref(),
        Some(main.as_str())
    );
    let out = agent.in_dir(&work, "writ git push origin HEAD:refs/heads/agent/setup");
    expect(&out, 0, "the allowed push");
    assert_eq!(
        stack.forgejo.branch("setup", "agent/setup").as_deref(),
        Some(commit.as_str())
    );
    assert_eq!(
        stack
            .mirror_ref("setup", "refs/heads/agent/setup")
            .as_deref(),
        Some(commit.as_str())
    );
    assert_eq!(stack.audited(&lease, "push", "allowed").len(), 1);

    // The repo the setup added from the approver's machine with `writ admin` only (no host
    // file, no restart, no unseal): its host scanned by the daemon (the key Forgejo
    // publishes), its own template and upstream key, its check passing once the key was
    // registered on Forgejo.
    let compared = report.upstream_fingerprint.split(' ').nth(1).unwrap();
    assert!(
        report
            .added_host
            .contains(&format!("  ssh-ed25519 {compared}\r\n")),
        "{}",
        report.added_host
    );
    for step in [
        "  read: ok: upstream answers with its credential, 1 ref\n",
        "  sync: ok: the mirror synced, 1 ref moved, in its object format (sha1)\n",
        "  write: ok: upstream takes pushes with its credential (nothing pushed)\n",
        "added is ready: read and write access proven, its mirror synced.\n",
    ] {
        assert!(
            report.added_check.contains(step),
            "{step:?}: {}",
            report.added_check
        );
    }
    stack.operator.ok("test -d data/repos/added.git");
    // Its template, key and host are what the changes said, and nothing else names them.
    let shown = stack.approver.ok("writ admin repo show added");
    assert!(
        shown.starts_with(
            "added:\n  upstream: \"ssh://git@forgejo-added/writ/added.git\"\n  \
             upstream_credential: upstream-added\n  templates: [added]\n"
        ),
        "{shown}"
    );
    assert!(shown.contains("\nhost pin: forgejo-added\n"), "{shown}");
    let audit = stack.audit();
    assert!(
        audit
            .iter()
            .any(|e| e["event"] == "check" && e["result"] == "allowed" && e["repo"] == "added"),
        "no allowed check of added"
    );
}
