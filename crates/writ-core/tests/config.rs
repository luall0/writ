//! Loading the registry and templates: valid documents parse, every error names its field.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

mod common;

use common::*;
use writ_core::config::{PathsCheck, PolicyConfig, PushMode, TicketLink};
use writ_core::ticket::Operation;
use writ_core::ticket::TicketRequest;

const UPSTREAM: &str = "ssh://git@github.com/user/omega-code.git";

#[test]
fn the_test_policy_parses_with_defaults() {
    let config = config();
    let omega = config.repo(&repo("omega-code")).unwrap();
    assert_eq!(omega.protected_refs.len(), 2);
    assert_eq!(omega.ticket_link, TicketLink::Trailer);
    let dotfiles = config.repo(&repo("dotfiles")).unwrap();
    assert!(dotfiles.direct_ssh.is_some());
    let quick = config.template(&"quick-fix".parse().unwrap()).unwrap();
    assert_eq!(quick.paths_check, PathsCheck::Deny);
    // Defaults: push modes gateway only, no force push, expected paths not required.
    assert_eq!(
        quick.push_modes.iter().copied().collect::<Vec<_>>(),
        vec![PushMode::Gateway]
    );
    assert!(!quick.force_push && !quick.require_expected_paths);
    let read_only = config.template(&"read-only".parse().unwrap()).unwrap();
    assert_eq!(
        read_only.operations.iter().copied().collect::<Vec<_>>(),
        vec![Operation::Fetch]
    );
    assert_eq!(read_only.paths_check, PathsCheck::Warn);
}

/// Each edit of the test policy, and the start of the error it must give.
/// The policy with one more repo named `name`, a copy of `homelab-scripts`.
fn with_extra_repo(name: &str) -> String {
    POLICY.replacen(
        "  dotfiles:\n",
        &format!(
            "  {name}:\n    upstream: ssh://git@forgejo.home/user/other.git\n    \
             upstream_credential: upstream-forgejo-01\n  dotfiles:\n"
        ),
        1,
    )
}

#[test]
fn repo_names_are_unique_ignoring_case() {
    // Allowed: a different name (the check's control).
    let config = PolicyConfig::from_yaml(&with_extra_repo("homelab-scripts-2")).unwrap();
    assert!(config.repo(&repo("homelab-scripts-2")).is_some());
    // Refused: the same name in another case. The error names the second of the two in the
    // registry's (byte) order.
    for name in [
        "Homelab-Scripts",
        "HOMELAB-SCRIPTS",
        "homelab-Scripts",
        "homelab-scriptS",
    ] {
        let error = PolicyConfig::from_yaml(&with_extra_repo(name)).unwrap_err();
        let second = name.max("homelab-scripts");
        assert_eq!(error.path, format!("repos.{second}"), "{name}");
        assert!(error.message.contains("same name ignoring case"), "{error}");
    }
}

#[test]
fn errors_name_the_field() {
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "bad duration",
            POLICY.replacen("max_ttl: 4h", "max_ttl: 4 hours", 1),
            "templates.feature-branch.max_ttl: ",
        ),
        (
            "bad size",
            POLICY.replacen("max_push_size: 50MB", "max_push_size: 50 megs", 1),
            "templates.feature-branch.max_push_size: ",
        ),
        (
            "negative count",
            POLICY.replacen("max_signatures: 50", "max_signatures: -1", 1),
            "templates.feature-branch.max_signatures: ",
        ),
        (
            "missing limit",
            POLICY.replacen("    max_pushes: 30\n", "", 1),
            "templates.feature-branch: ",
        ),
        (
            "unknown field",
            POLICY.replacen("    max_ttl: 4h\n", "    max_ttl: 4h\n    max_tll: 4h\n", 1),
            "templates.feature-branch.max_tll: ",
        ),
        (
            "unknown operation",
            POLICY.replacen(
                "operations: [fetch, commit_sign, push]",
                "operations: [fetch, sign]",
                1,
            ),
            "templates.feature-branch.operations[1]: ",
        ),
        (
            "bad branch pattern",
            POLICY.replacen(r#"branches: ["agent/*"]"#, r#"branches: ["agent/*/x"]"#, 1),
            "templates.feature-branch.branches[0]: ",
        ),
        (
            "bad protected ref",
            POLICY.replacen(r#""refs/tags/*""#, r#""tags/*""#, 1),
            "repos.omega-code.protected_refs[1]: ",
        ),
        (
            "bad repo name",
            POLICY.replacen("  omega-code:\n", "  ../omega:\n", 1),
            "repos.../omega: ",
        ),
        (
            "bad email",
            POLICY.replacen(
                r#"committer_emails: ["user+agent@example.org"]"#,
                r#"committer_emails: ["user"]"#,
                1,
            ),
            "templates.feature-branch.committer_emails[0]: ",
        ),
        (
            "unknown push mode",
            POLICY.replacen("push_modes: [gateway]", "push_modes: [ftp]", 1),
            "repos.omega-code.push_modes[0]: ",
        ),
        (
            "unknown ticket link",
            POLICY.replacen("ticket_link: trailer", "ticket_link: footer", 1),
            "repos.omega-code.ticket_link: ",
        ),
        (
            "duplicate key",
            POLICY.replacen("    max_ttl: 4h\n", "    max_ttl: 4h\n    max_ttl: 5h\n", 1),
            "templates.feature-branch",
        ),
        (
            "unknown repo in template",
            POLICY.replacen(
                "repos: [omega-code, homelab-scripts]",
                "repos: [omega-code, nope]",
                1,
            ),
            "templates.feature-branch.repos: nope is not in the repo registry",
        ),
        (
            "commit_sign without emails",
            POLICY.replacen(r#"    committer_emails: ["user+agent@example.org"]"#, "", 1),
            "templates.feature-branch.committer_emails: required with commit_sign",
        ),
        (
            "commit_sign without key",
            POLICY.replacen("    signing_key: agent-ed25519-01\n", "", 1),
            "templates.feature-branch.signing_key: required with commit_sign",
        ),
        (
            "push without branches",
            POLICY.replacen(r#"    branches: ["agent/*"]"#, "", 1),
            "templates.feature-branch.branches: required with commit_sign or push",
        ),
        (
            "zero ttl",
            POLICY.replacen("max_ttl: 4h", "max_ttl: 0s", 1),
            "templates.feature-branch.max_ttl: must be at least 5m",
        ),
        (
            "ttl under the minimum",
            POLICY.replacen("max_ttl: 4h", "max_ttl: 299s", 1),
            "templates.feature-branch.max_ttl: must be at least 5m",
        ),
        (
            "zero rate",
            POLICY.replacen("max_ops_per_minute: 20", "max_ops_per_minute: 0", 1),
            "templates.feature-branch.max_ops_per_minute: must be at least 1",
        ),
        (
            "no operations",
            POLICY.replacen(
                "operations: [fetch, commit_sign, push]",
                "operations: []",
                1,
            ),
            "templates.feature-branch.operations: must list at least one operation",
        ),
        (
            "empty push modes",
            POLICY.replacen("push_modes: [gateway]", "push_modes: []", 1),
            "repos.omega-code.push_modes: must list at least one push mode",
        ),
        (
            "http upstream",
            POLICY.replacen(
                "ssh://git@github.com/user/omega-code.git",
                "http://github.com/user/omega-code.git",
                1,
            ),
            "repos.omega-code.upstream: must be an ssh:// or https:// URL",
        ),
        (
            "a password in the upstream URL",
            POLICY.replacen(
                UPSTREAM,
                "https://user:ghp_secret@github.com/user/omega-code.git",
                1,
            ),
            "repos.omega-code.upstream: must not hold a password",
        ),
        (
            "an upstream host read as an ssh option",
            POLICY.replacen(UPSTREAM, "ssh://-oProxyCommand=sh/omega-code.git", 1),
            "repos.omega-code.upstream: the host must not be empty or start with '-'",
        ),
        (
            "an upstream user read as an ssh option",
            POLICY.replacen(
                UPSTREAM,
                "ssh://-oProxyCommand=sh@github.com/omega-code.git",
                1,
            ),
            "repos.omega-code.upstream: the user must not be empty or start with '-'",
        ),
        (
            "no upstream host",
            POLICY.replacen(UPSTREAM, "ssh://git@/omega-code.git", 1),
            "repos.omega-code.upstream: the host must not be empty",
        ),
        (
            "a space in the upstream",
            POLICY.replacen(UPSTREAM, "ssh://git@github.com/omega code.git", 1),
            "repos.omega-code.upstream: printable ASCII only",
        ),
        (
            "a direct_ssh host read as an ssh option",
            POLICY.replacen("hosts: [github.com]", "hosts: [\"-oProxyCommand=sh\"]", 1),
            "repos.dotfiles.direct_ssh.hosts: each host",
        ),
        (
            "direct_ssh without its section",
            POLICY.replacen("    direct_ssh:\n      hosts: [github.com]\n", "", 1),
            "repos.dotfiles.direct_ssh: required",
        ),
        (
            "direct_ssh section unused",
            POLICY.replacen("push_modes: [direct_ssh]", "push_modes: [gateway]", 1),
            "repos.dotfiles.direct_ssh: only allowed",
        ),
        (
            "unknown top-level key",
            format!("{POLICY}\napprovers: []\n"),
            "approvers: ",
        ),
        ("not YAML", "repos: [unclosed".to_owned(), ""),
    ];
    let mut failures = Vec::new();
    for (name, yaml, expected) in cases {
        match PolicyConfig::from_yaml(&yaml) {
            Ok(_) => failures.push(format!("{name}: accepted")),
            Err(e) if !e.to_string().starts_with(expected) => {
                failures.push(format!(
                    "{name}: {:?} should start with {expected:?}",
                    e.to_string()
                ));
            }
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn ticket_request_errors_name_the_field() {
    let cases = [
        (REQUEST.replace("ttl: 2h", "ttl: two hours"), "limits.ttl: "),
        (
            REQUEST.replace("max_pushes: 2", "max_pushes: lots"),
            "limits.max_pushes: ",
        ),
        (
            REQUEST.replace("[\"agent/oauth-*\"]", "[\"agent/**\"]"),
            "scope.branches[0]: ",
        ),
        (
            REQUEST.replace("[\"src/auth/**\", \"tests/auth/**\"]", "[\"/etc/passwd\"]"),
            "ticket.expected_paths[0]: ",
        ),
        (
            REQUEST.replace("  title: Add OAuth login\n", ""),
            "ticket: ",
        ),
        (
            REQUEST.replace("template: feature-branch", "template: x\nstate: active"),
            "state: ",
        ),
        (format!("{REQUEST}\napproval: yes\n"), "approval: "),
    ];
    for (yaml, expected) in cases {
        let error = TicketRequest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(
            error.starts_with(expected),
            "{error:?} should start with {expected:?}"
        );
    }
}
