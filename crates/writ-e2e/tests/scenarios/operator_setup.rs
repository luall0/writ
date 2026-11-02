//! Scenario 1, the operator setup from nothing (docs/operators/setup.md):
//! the setup runs once per stack, with the guide's own commands ([`writ_e2e::setup`]); this
//! checks what it saw and that the daemon it started checks every push. The two bugs M4's
//! GitHub check found fail here: a command that prints a key needing the approvers file
//! (fixed in 5658e4e: the setup runs them before any approver exists), and a daemon started on
//! a relative configuration path running pushes with no hook (fixed in fd57274: the protected
//! ref below would go through).

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
    "verified",
    "inflight",
    "restart",
    "hostile",
    "busy",
    "notes",
    "backfill",
];

#[test]
#[ignore = "end to end: make e2e"]
fn the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says() {
    let stack = Stack::shared();
    let report = &stack.report;

    // The commands that print a key ran before any approvers or readers file existed.
    let ran: Vec<&str> = report
        .before_approvers
        .iter()
        .map(|(c, _)| c.as_str())
        .collect();
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
    // One signing key per template key id, with the templates that name it.
    assert_eq!(report.signing_keys.len(), 2, "{:?}", report.signing_keys);
    assert!(report.signing_keys[0].starts_with("agent-e2e ssh-ed25519 "));
    assert!(report.signing_keys[0].ends_with(" (templates: feature)"));
    assert!(report.signing_keys[1].starts_with("agent-e2e-verify ssh-ed25519 "));
    assert!(report.signing_keys[1].ends_with(" (templates: verified)"));
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
}
