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
use writ_core::config::{
    Key, NotesRef, ObjectFormat, PathsCheck, PolicyConfig, TicketLink, UpstreamKey,
};
use writ_core::ticket::Operation;
use writ_core::ticket::TicketRequest;
use writ_core::units::Duration;

const UPSTREAM: &str = "ssh://git@github.com/user/omega-code.git";

#[test]
fn the_test_policy_parses_with_defaults() {
    let config = config();
    let omega = config.repo(&repo("omega-code")).unwrap();
    assert_eq!(omega.protected_refs.len(), 2);
    assert_eq!(omega.ticket_link, TicketLink::Trailer);
    assert_eq!(omega.object_format, ObjectFormat::Sha1, "the default");
    let sha256 = PolicyConfig::from_yaml(&POLICY.replacen(
        "ticket_link: trailer",
        "ticket_link: trailer\n    object_format: sha256",
        1,
    ))
    .unwrap();
    assert_eq!(
        sha256.repo(&repo("omega-code")).unwrap().object_format,
        ObjectFormat::Sha256
    );
    let dotfiles = config.repo(&repo("dotfiles")).unwrap();
    // Not written: the ledger only (a project's commit conventions may not allow a trailer).
    assert!(!POLICY.contains("dotfiles:\n    ticket_link"));
    assert_eq!(dotfiles.ticket_link, TicketLink::LedgerOnly, "the default");
    // Notes are written by the daemon (M4.7): taken.
    let notes =
        PolicyConfig::from_yaml(&POLICY.replacen("ticket_link: trailer", "ticket_link: notes", 1))
            .unwrap();
    let omega = notes.repo(&"omega-code".parse().unwrap()).unwrap();
    assert_eq!(omega.ticket_link, TicketLink::Notes);
    // Under git's own notes ref unless the repo says otherwise.
    assert_eq!(omega.notes_ref, None);
    assert_eq!(omega.notes_ref(), NotesRef::Commits);
    assert_eq!(omega.notes_ref().as_ref_name(), "refs/notes/commits");
    for (value, expected, name) in [
        ("commits", NotesRef::Commits, "refs/notes/commits"),
        ("writ", NotesRef::Writ, "refs/notes/writ"),
    ] {
        let set = PolicyConfig::from_yaml(&POLICY.replacen(
            "ticket_link: trailer",
            &format!("ticket_link: notes\n    notes_ref: {value}"),
            1,
        ))
        .unwrap();
        let omega = set.repo(&"omega-code".parse().unwrap()).unwrap();
        assert_eq!(omega.notes_ref(), expected);
        assert_eq!(omega.notes_ref().as_ref_name(), name);
    }
    let quick = config.template(&"quick-fix".parse().unwrap()).unwrap();
    assert_eq!(quick.paths_check, PathsCheck::Deny);
    // Defaults: no force push, expected paths not required.
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
             upstream_credential: upstream-forgejo-01\n    templates: []\n  dotfiles:\n"
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

/// The review after M7.6 (P-1): a key's id, a recipient's name and a pinned host name each
/// name a file (or, for a host, what ssh matches ignoring case): two equal ignoring case would
/// share it. Refused, the second named; the same name in its own case is the control.
#[test]
fn keys_recipients_and_hosts_are_unique_ignoring_case() {
    let cases = [
        (
            "  deploy-dotfiles-01: { use: upstream, kind: ssh, algorithm: ed25519 }\n",
            "  deploy-dotfiles-01: { use: upstream, kind: ssh, algorithm: ed25519 }\n  \
             Agent-ed25519-01: { use: signing, format: ssh, algorithm: ed25519 }\n",
            "keys.agent-ed25519-01",
        ),
        (
            "  forgejo.home: [",
            "  GitHub.com: [\"ssh-ed25519 \
             AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\"]\n  \
             forgejo.home: [",
            "upstream_hosts.github.com",
        ),
        (
            "\nrepos:\n",
            "\nrecipients:\n  recovery: { recipient: \
             age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p }\n  se-01: { \
             backend: se-cryptokit }\n  SE-01: { backend: se-cryptokit }\n\nrepos:\n",
            "recipients.se-01",
        ),
    ];
    for (from, to, path) in cases {
        let policy = POLICY.replacen(from, to, 1);
        assert_ne!(policy, POLICY, "{path}");
        let error = PolicyConfig::from_yaml(&policy).unwrap_err();
        assert_eq!(error.path, path, "{error}");
        assert!(
            error
                .message
                .starts_with("another entry has the same name ignoring case"),
            "{error}"
        );
    }
    // The control: one entry of each, in any case, is taken.
    let policy = POLICY.replacen(
        "  forgejo.home: [",
        "  Codeberg.org: [\"ssh-ed25519 \
         AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\"]\n  forgejo.home: [",
        1,
    );
    PolicyConfig::from_yaml(&policy).unwrap();
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
            "a repo's push modes, removed in format 2",
            POLICY.replacen(
                "    ticket_link: trailer",
                "    push_modes: [gateway]\n    ticket_link: trailer",
                1,
            ),
            "repos.omega-code.push_modes: removed in format 2 (M7.9.6): every push goes \
             through the gateway",
        ),
        (
            "a template's push modes, removed in format 2",
            POLICY.replacen(
                "    paths_check: warn\n",
                "    paths_check: warn\n    push_modes: [gateway]\n",
                1,
            ),
            "templates.feature-branch.push_modes: removed in format 2",
        ),
        (
            "a repo's direct_ssh, removed in format 2",
            POLICY.replacen(
                "    templates: [quick-fix]\n",
                "    templates: [quick-fix]\n    direct_ssh:\n      hosts: [github.com]\n",
                1,
            ),
            "repos.dotfiles.direct_ssh: removed in format 2",
        ),
        (
            "no format: format 1",
            POLICY.replacen("format: 2\n", "", 1),
            "format: missing: a policy names its format (`format: 2` at its top); without it, \
             it is format 1, from before M7.9.6, which writ migrate rewrites",
        ),
        (
            "format 1 named",
            POLICY.replacen("format: 2\n", "format: 1\n", 1),
            "format: format 1: this Writ reads format 2 only",
        ),
        (
            "a newer format",
            POLICY.replacen("format: 2\n", "format: 3\n", 1),
            "format: format 3: this Writ reads format 2 only",
        ),
        (
            "a format that isn't a number",
            POLICY.replacen("format: 2\n", "format: two\n", 1),
            "format: ",
        ),
        (
            "unknown ticket link",
            POLICY.replacen("ticket_link: trailer", "ticket_link: footer", 1),
            "repos.omega-code.ticket_link: ",
        ),
        (
            // Where notes go means nothing without notes: a mistake, not a setting.
            "notes_ref without notes",
            POLICY.replacen(
                "ticket_link: trailer",
                "ticket_link: trailer\n    notes_ref: writ",
                1,
            ),
            "repos.omega-code.notes_ref: only allowed when ticket_link is notes",
        ),
        (
            "unknown notes ref",
            POLICY.replacen(
                "ticket_link: trailer",
                "ticket_link: notes\n    notes_ref: refs/notes/writ",
                1,
            ),
            "repos.omega-code.notes_ref: ",
        ),
        (
            "unknown object format",
            POLICY.replacen(
                "ticket_link: trailer",
                "ticket_link: trailer\n    object_format: sha3",
                1,
            ),
            "repos.omega-code.object_format: ",
        ),
        (
            "duplicate key",
            POLICY.replacen("    max_ttl: 4h\n", "    max_ttl: 4h\n    max_ttl: 5h\n", 1),
            "templates.feature-branch",
        ),
        (
            "unknown template in a repo",
            POLICY.replacen(
                "templates: [feature-branch, quick-fix]\n",
                "templates: [feature-branch, nope]\n",
                1,
            ),
            "repos.homelab-scripts.templates: nope is not a template",
        ),
        (
            "a repo without its templates",
            POLICY.replacen("    templates: [quick-fix]\n", "", 1),
            "repos.dotfiles: ",
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
            // git reads a `receive.maxInputSize` of 0 as no limit.
            "zero push size",
            POLICY.replacen("max_push_size: 50MB", "max_push_size: 0", 1),
            "templates.feature-branch.max_push_size: must be at least 1 byte",
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
            "http upstream",
            POLICY.replacen(
                "ssh://git@github.com/user/omega-code.git",
                "http://github.com/user/omega-code.git",
                1,
            ),
            "repos.omega-code.upstream: http:// would send the token in clear: use https://",
        ),
        (
            "a password in the upstream URL",
            POLICY.replacen(
                UPSTREAM,
                "https://user:ghp_secret@github.com/user/omega-code.git",
                1,
            ),
            "repos.omega-code.upstream: no password in the URL",
        ),
        (
            "an upstream host read as an ssh option",
            POLICY.replacen(UPSTREAM, "ssh://-oProxyCommand=sh/omega-code.git", 1),
            "repos.omega-code.upstream: invalid host",
        ),
        (
            "an upstream user read as an ssh option",
            POLICY.replacen(
                UPSTREAM,
                "ssh://-oProxyCommand=sh@github.com/omega-code.git",
                1,
            ),
            "repos.omega-code.upstream: invalid user",
        ),
        (
            "no upstream host",
            POLICY.replacen(UPSTREAM, "ssh://git@/omega-code.git", 1),
            "repos.omega-code.upstream: invalid host",
        ),
        (
            "a space in the upstream",
            POLICY.replacen(UPSTREAM, "ssh://git@github.com/omega code.git", 1),
            "repos.omega-code.upstream: printable ASCII only",
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
            "repos.omega-code.limits.max_pushes: ",
        ),
        (
            REQUEST.replace("[\"agent/oauth-*\"]", "[\"agent/**\"]"),
            "repos.omega-code.branches[0]: ",
        ),
        (
            REQUEST.replace("[\"src/auth/**\", \"tests/auth/**\"]", "[\"/etc/passwd\"]"),
            "repos.omega-code.expected_paths[0]: ",
        ),
        (
            REQUEST.replace("  title: Add OAuth login\n", ""),
            "ticket: ",
        ),
        (format!("state: active\n{REQUEST}"), "state: "),
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

const PIN: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

/// A policy with one repo and one template signing with `agent-01` for two emails; `keys` is
/// the whole `keys:` section.
fn signing_text(keys: &str) -> String {
    format!(
        r#"format: 2
keys:
{keys}
  upstream-01: {{ use: upstream, kind: ssh, algorithm: ed25519 }}
upstream_hosts:
  example.org: ["{PIN}"]
repos:
  demo:
    upstream: ssh://git@example.org/demo.git
    upstream_credential: upstream-01
    templates: [feature]
templates:
  feature:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ.invalid", "bot@writ.invalid"]
    signing_key: agent-01
    max_ttl: 1h
    max_signatures: 5
    max_pushes: 5
    max_ops_per_minute: 5
    max_push_size: 1MB
"#
    )
}

fn error_of(text: &str) -> String {
    PolicyConfig::from_yaml(text).unwrap_err().to_string()
}

/// `got` is the error `expected` names (`<field>: <message start>`): the parser puts where
/// in the text a value failed between the two.
fn assert_error(got: &str, expected: &str) {
    let (field, message) = expected.split_once(": ").unwrap_or((expected, ""));
    let (got_field, got_message) = got.split_once(": ").unwrap_or((got, ""));
    let got_message = match got_message.strip_prefix("line ") {
        Some(rest) => rest.split_once(": ").map_or(rest, |(_, m)| m),
        None => got_message,
    };
    assert!(
        got_field == field && got_message.starts_with(message),
        "{got:?} should be {expected:?}"
    );
}

#[test]
fn a_template_signs_only_with_a_declared_signing_key_carrying_its_emails() {
    let ssh = "  agent-01: { use: signing, format: ssh, algorithm: ed25519 }";
    let config = PolicyConfig::from_yaml(&signing_text(ssh)).unwrap();
    let id = "agent-01".parse().unwrap();
    assert!(matches!(config.key(&id), Some(Key::Signing(_))));
    assert_eq!(
        config.key_users(&id).templates,
        vec!["feature".parse().unwrap()]
    );
    // A key nobody declared, and an upstream credential named as a signing key.
    assert_eq!(
        error_of(&signing_text(ssh).replace("signing_key: agent-01", "signing_key: agent-09")),
        "templates.feature.signing_key: agent-09 is not declared in keys"
    );
    assert_eq!(
        error_of(&signing_text(ssh).replace("signing_key: agent-01", "signing_key: upstream-01")),
        "templates.feature.signing_key: keys.upstream-01 is an upstream credential (use: \
         upstream), not a signing key"
    );
    // An OpenPGP key: a user id for every committer email.
    let openpgp = |uids: &str| {
        format!("  agent-01: {{ use: signing, format: openpgp, algorithm: p256{uids} }}")
    };
    assert_eq!(
        error_of(&signing_text(&openpgp(""))),
        "templates.feature.committer_emails: agent@writ.invalid has no user id in \
         keys.agent-01.uids (the OpenPGP key would sign commits a remote shows as unverified)"
    );
    assert_eq!(
        error_of(&signing_text(&openpgp(
            ", uids: [\"Agent <agent@writ.invalid>\"]"
        ))),
        "templates.feature.committer_emails: bot@writ.invalid has no user id in \
         keys.agent-01.uids (the OpenPGP key would sign commits a remote shows as unverified)"
    );
    let both = openpgp(", uids: [\"Agent <agent@writ.invalid>\", \"<bot@writ.invalid>\"]");
    let config = PolicyConfig::from_yaml(&signing_text(&both)).unwrap();
    assert_eq!(config.uids(&id).len(), 2);
    // The template's name must be the key's.
    let named = signing_text(&both).replace(
        "    signing_key: agent-01",
        "    committer_name: Agent\n    signing_key: agent-01",
    );
    assert_eq!(
        error_of(&named),
        "templates.feature.committer_name: keys.agent-01.uids has no user id \"Agent \
         <bot@writ.invalid>\": the OpenPGP key must carry the name the commits do"
    );
}

#[test]
fn each_key_takes_the_fields_its_use_and_kind_need_and_no_others() {
    let error = |key: &str| error_of(&signing_text(&format!("  agent-01: {{ {key} }}")));
    for (key, expected) in [
        (
            "use: signing, algorithm: ed25519",
            "keys.agent-01.format: required for a signing key",
        ),
        (
            "use: signing, format: ssh",
            "keys.agent-01.algorithm: required for a signing key",
        ),
        (
            "use: signing, format: ssh, algorithm: ed25519, kind: ssh",
            "keys.agent-01.kind: only for an upstream credential",
        ),
        (
            "use: signing, format: ssh, algorithm: ed25519, host: github.com",
            "keys.agent-01.host: only for an upstream token",
        ),
        (
            "use: signing, format: ssh, algorithm: ed25519, uids: [\"<a@b>\"]",
            "keys.agent-01.uids: user ids are for an OpenPGP key; this one is format: ssh",
        ),
        (
            "use: signing, format: x509, algorithm: ed25519",
            "keys.agent-01.format: \"x509\" is not a signature format (x509 is not supported): \
             expected one of ssh, openpgp",
        ),
        (
            "use: signing, format: ssh, algorithm: rsa2048",
            "keys.agent-01.algorithm: \"rsa2048\" is not a key algorithm (RSA keys are 3072 or \
             4096 bits): expected one of ed25519, p256, p384, rsa3072, rsa4096",
        ),
        (
            "use: signing, format: ssh, algorithm: ed25519, hash: sha1",
            "keys.agent-01.hash: \"sha1\" is not a hash (nothing under SHA-256 is offered): \
             expected one of sha256, sha384, sha512",
        ),
        (
            "use: signing, format: ssh, algorithm: ed25519, backend: Yubi Key",
            "keys.agent-01.backend: invalid backend",
        ),
        (
            "use: agent, format: ssh, algorithm: ed25519",
            "keys.agent-01.use: \"agent\" is not a key use",
        ),
        (
            "format: ssh, algorithm: ed25519",
            "keys.agent-01: missing field `use`",
        ),
        (
            "use: signing, format: ssh, algorithm: ed25519, purpose: commits",
            "keys.agent-01.purpose: unknown field",
        ),
        (
            "use: upstream",
            "keys.agent-01.kind: required for an upstream credential (ssh or token)",
        ),
        (
            "use: upstream, kind: ssh",
            "keys.agent-01.algorithm: required for an ssh credential",
        ),
        (
            "use: upstream, kind: ssh, algorithm: ed25519, format: ssh",
            "keys.agent-01.format: only for a signing key",
        ),
        (
            "use: upstream, kind: ssh, algorithm: ed25519, hash: sha256",
            "keys.agent-01.hash: only for a signing key",
        ),
        (
            "use: upstream, kind: ssh, algorithm: ed25519, uids: [\"<a@b>\"]",
            "keys.agent-01.uids: only for an OpenPGP signing key",
        ),
        (
            "use: upstream, kind: ssh, algorithm: ed25519, host: github.com",
            "keys.agent-01.host: only for an upstream token",
        ),
        (
            "use: upstream, kind: token",
            "keys.agent-01.host: required for a token",
        ),
        (
            "use: upstream, kind: token, host: github.com, algorithm: ed25519",
            "keys.agent-01.algorithm: a token has no algorithm",
        ),
        (
            "use: upstream, kind: token, host: \"https://github.com\"",
            "keys.agent-01.host: invalid token host",
        ),
        (
            "use: upstream, kind: password",
            "keys.agent-01.kind: \"password\" is not an upstream",
        ),
    ] {
        assert_error(&error(key), expected);
    }
}

#[test]
fn a_key_s_user_ids_are_one_to_sixteen_and_distinct() {
    let error = |uids: &str| {
        error_of(&signing_text(&format!(
            "  agent-01: {{ use: signing, format: openpgp, algorithm: ed25519, uids: {uids} }}"
        )))
    };
    assert_eq!(
        error("[]"),
        "keys.agent-01.uids: must list 1 to 16 user ids (or be left out)"
    );
    let seventeen: Vec<String> = (0..17).map(|i| format!("\"<a{i}@b>\"")).collect();
    assert_eq!(
        error(&format!("[{}]", seventeen.join(", "))),
        "keys.agent-01.uids: must list 1 to 16 user ids (or be left out)"
    );
    assert_eq!(
        error("[\"<a@b>\", \"<a@b>\"]"),
        "keys.agent-01.uids: a user id is listed twice"
    );
    assert!(error("[\"no address\"]").contains("must end with <local@domain>"));
}

/// The test policy with omega-code's upstream and credential replaced, and `keys` added.
fn with_upstream(upstream: &str, credential: &str, keys: &str) -> String {
    POLICY
        .replacen(
            "upstream: ssh://git@github.com/user/omega-code.git\n    upstream_credential: upstream-github-01",
            &format!("upstream: {upstream}\n    upstream_credential: {credential}"),
            1,
        )
        .replacen("keys:\n", &format!("keys:\n{keys}"), 1)
}

#[test]
fn a_repo_s_credential_is_declared_for_its_url_and_its_host_pinned() {
    let token = "  gh-token: { use: upstream, kind: token, host: GitHub.com }\n";
    // A token for the URL's host (compared ignoring case), an SSH key on a pinned host.
    let https = PolicyConfig::from_yaml(&with_upstream(
        "https://github.com/user/omega-code.git",
        "gh-token",
        token,
    ))
    .unwrap();
    assert!(matches!(
        https.key(&"gh-token".parse().unwrap()),
        Some(Key::Upstream(UpstreamKey::Token { .. }))
    ));
    let pinned = with_upstream(
        "ssh://git@forgejo.lan:2222/user/omega-code.git",
        "upstream-github-01",
        "",
    )
    .replacen(
        "upstream_hosts:\n",
        &format!("upstream_hosts:\n  \"[forgejo.lan]:2222\": [\"{PIN}\"]\n"),
        1,
    );
    let config = PolicyConfig::from_yaml(&pinned).unwrap();
    let host = "[forgejo.lan]:2222".to_owned().try_into().unwrap();
    assert_eq!(config.host_users(&host), vec![repo("omega-code")]);
    for (text, expected) in [
        (
            with_upstream(UPSTREAM, "nobody-01", ""),
            "repos.omega-code.upstream_credential: nobody-01 is not declared in keys",
        ),
        (
            with_upstream(UPSTREAM, "agent-ed25519-01", ""),
            "repos.omega-code.upstream_credential: keys.agent-ed25519-01 is a signing key (use: \
             signing), not an upstream credential",
        ),
        (
            with_upstream(UPSTREAM, "gh-token", token),
            "repos.omega-code.upstream_credential: keys.gh-token is a token (kind: token): an \
             ssh:// upstream needs kind: ssh",
        ),
        (
            with_upstream(
                "https://github.com/user/omega-code.git",
                "upstream-github-01",
                "",
            ),
            "repos.omega-code.upstream_credential: keys.upstream-github-01 is an SSH key (kind: \
             ssh): an https:// upstream needs kind: token",
        ),
        (
            with_upstream(
                "https://codeberg.org/user/omega-code.git",
                "gh-token",
                token,
            ),
            "repos.omega-code.upstream_credential: keys.gh-token is a token for GitHub.com, not \
             for this upstream's host codeberg.org",
        ),
        (
            with_upstream(
                "ssh://git@gitlab.com/user/omega-code.git",
                "upstream-github-01",
                "",
            ),
            "repos.omega-code.upstream: its host gitlab.com has no pin in upstream_hosts",
        ),
        (
            // Another port is another host to ssh.
            with_upstream(
                "ssh://git@github.com:2222/user/omega-code.git",
                "upstream-github-01",
                "",
            ),
            "repos.omega-code.upstream: its host [github.com]:2222 has no pin in upstream_hosts",
        ),
    ] {
        assert_error(&error_of(&text), expected);
    }
}

#[test]
fn host_pins_are_plain_one_to_sixteen_distinct_keys() {
    let pins = |entry: &str| {
        POLICY.replacen(
            "upstream_hosts:\n",
            &format!("upstream_hosts:\n{entry}\n"),
            1,
        )
    };
    // A host no repo uses yet is valid: pinned before its repo is added.
    let config = PolicyConfig::from_yaml(&pins(&format!("  codeberg.org: [\"{PIN}\"]"))).unwrap();
    let codeberg = "codeberg.org".to_owned().try_into().unwrap();
    assert!(config.upstream_hosts().contains_key(&codeberg));
    assert!(config.host_users(&codeberg).is_empty());
    let seventeen = vec![format!("\"{PIN}\""); 17].join(", ");
    for (entry, expected) in [
        (
            "  codeberg.org: []".to_owned(),
            "upstream_hosts.codeberg.org: must pin 1 to 16 keys",
        ),
        (
            format!("  codeberg.org: [{seventeen}]"),
            "upstream_hosts.codeberg.org: must pin 1 to 16 keys",
        ),
        (
            format!("  codeberg.org: [\"{PIN}\", \"{PIN}\"]"),
            "upstream_hosts.codeberg.org: a key is pinned twice",
        ),
        (
            format!("  \"*.codeberg.org\": [\"{PIN}\"]"),
            "upstream_hosts.*.codeberg.org: invalid upstream host",
        ),
        (
            "  codeberg.org: [\"ssh-dss AAAAB3NzaC1kc3M=\"]".to_owned(),
            "upstream_hosts.codeberg.org[0]: invalid host key",
        ),
        (
            format!("  codeberg.org: [\"{PIN} comment\"]"),
            "upstream_hosts.codeberg.org[0]: invalid host key",
        ),
    ] {
        assert_error(&error_of(&pins(&entry)), expected);
    }
    let many: String = (0..=256)
        .map(|i| format!("  h{i}.example.org: [\"{PIN}\"]\n"))
        .collect();
    assert_eq!(
        error_of(&pins(many.trim_end())),
        "upstream_hosts: at most 256 hosts are pinned"
    );
}

#[test]
fn the_fields_that_moved_are_refused_naming_their_new_place() {
    assert_eq!(
        error_of(&POLICY.replacen(
            "    operations: [fetch]\n",
            "    repos: [omega-code]\n    operations: [fetch]\n",
            1
        )),
        "templates.read-only.repos: moved in M6.2: templates no longer list repos; name the \
         template in each repo's repos.<name>.templates"
    );
    assert_eq!(
        error_of(&format!(
            "{POLICY}signing_keys:\n  agent-ed25519-01:\n    uids: [\"<a@b>\"]\n"
        )),
        "signing_keys: moved in M6.2: declare each signing key under keys.<id> (use: signing, \
         its format and algorithm, and its uids there)"
    );
    // `keys` is required: a policy without it is the old shape.
    let old = POLICY.replacen(&POLICY[..POLICY.find("upstream_hosts:").unwrap()], "", 1);
    assert!(
        error_of(&old).contains("missing field `keys`"),
        "{}",
        error_of(&old)
    );
}

#[test]
fn repos_name_their_templates_and_an_empty_list_closes_one() {
    let config = config();
    let (feature, read_only) = (
        "feature-branch".parse().unwrap(),
        "read-only".parse().unwrap(),
    );
    assert!(config.allows(&repo("omega-code"), &read_only));
    assert!(!config.allows(&repo("homelab-scripts"), &read_only));
    assert!(!config.allows(&repo("nowhere"), &feature));
    assert_eq!(
        config.template_users(&feature),
        vec![repo("homelab-scripts"), repo("omega-code")]
    );
    // A template no repo names is valid: a profile not used yet.
    let unused = POLICY.replacen("    templates: [quick-fix]\n", "    templates: []\n", 1);
    let config = PolicyConfig::from_yaml(&unused).unwrap();
    assert!(config.repo(&repo("dotfiles")).unwrap().templates.is_empty());
    assert_eq!(
        config.template_users(&"quick-fix".parse().unwrap()),
        vec![repo("homelab-scripts"), repo("omega-code")]
    );
    // What uses each key.
    let users = config.key_users(&"upstream-forgejo-01".parse().unwrap());
    assert_eq!(users.repos, vec![repo("homelab-scripts")]);
    assert!(users.templates.is_empty());
    assert_eq!(users.to_string(), "repos homelab-scripts");
    assert!(config.key_users(&"nobody".parse().unwrap()).is_empty());
}

/// A policy using every field with a value other than its default.
const EVERYTHING: &str = r#"format: 2
keys:
  agent-pgp:
    use: signing
    format: openpgp
    algorithm: rsa4096
    hash: sha512
    uids: ["Writ agent <user+agent@example.org>", "Writ agent <bot@example.org>"]
  azure: { use: upstream, kind: ssh, algorithm: rsa3072, backend: software }
  gh-token: { use: upstream, kind: token, host: github.com }
upstream_hosts:
  "[forgejo.home]:2222": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC="]
repos:
  "true":
    upstream: https://bot@github.com/user/true.git
    upstream_credential: gh-token
    templates: []
    object_format: sha256
  omega:
    upstream: "ssh://git@forgejo.home:2222/user/omega.git"
    upstream_credential: azure
    templates: [quick, "12", unsigned]
    protected_refs: ["refs/heads/main", "refs/tags/*"]
    ticket_link: notes
    notes_ref: writ
templates:
  unsigned:
    unsigned_fetch: true
    max_ttl: 1h
    max_ops_per_minute: 5
  "12":
    operations: [fetch]
    max_ttl: 1d
    max_signatures: 0
    max_pushes: 0
    max_ops_per_minute: 1
    max_push_size: 0
  quick:
    operations: [fetch, commit_sign, push]
    branches: ["agent/fix-*", main]
    force_push: true
    committer_emails: [user+agent@example.org, bot@example.org]
    committer_name: Writ agent
    signing_key: agent-pgp
    max_ttl: 90m
    max_signatures: 10
    max_pushes: 5
    max_ops_per_minute: 10
    max_push_size: 52428800
    paths_check: deny
    require_expected_paths: true
    max_renewals: 3
"#;

#[test]
fn the_canonical_layout_reads_back_as_the_same_policy() {
    for text in [POLICY, EVERYTHING] {
        let policy = PolicyConfig::from_yaml(text).unwrap();
        let written = policy.to_yaml();
        let read = PolicyConfig::from_yaml(&written).unwrap_or_else(|e| panic!("{e}\n{written}"));
        assert_eq!(read, policy, "{written}");
        // One layout: writing it again changes nothing.
        assert_eq!(read.to_yaml(), written);
    }
    // The layout itself, for the reader of a diff.
    let written = PolicyConfig::from_yaml(EVERYTHING).unwrap().to_yaml();
    assert!(
        written.starts_with(
            "format: 2\n\nkeys:\n  agent-pgp:\n    use: signing\n    format: openpgp\n"
        )
    );
    assert!(written.contains(
        "\n  azure:\n    use: upstream\n    kind: ssh\n    algorithm: rsa3072\n  gh-token:"
    ));
    assert!(
        written.contains("\nupstream_hosts:\n  \"[forgejo.home]:2222\":\n    - \"ssh-ed25519 AAAA")
    );
    assert!(
        written.contains("\n  \"true\":\n    upstream: \"https://bot@github.com/user/true.git\"\n")
    );
    assert!(written.contains("    templates: [\"12\", quick, unsigned]\n"));
    // An unsigned_fetch template's implied fields left out.
    assert!(written.contains(
        "\n  unsigned:\n    unsigned_fetch: true\n    max_ttl: 1h\n    max_ops_per_minute: 5\n"
    ));
    assert!(written.contains("    max_ttl: \"1d\"\n"));
    assert!(written.contains("    max_ttl: 90m\n"));
    assert!(written.contains("    max_push_size: 50MiB\n"));
    assert!(written.contains("    committer_name: \"Writ agent\"\n"));
    // Defaults are left out.
    let plain = PolicyConfig::from_yaml(POLICY).unwrap().to_yaml();
    assert!(!plain.contains("backend:") && !plain.contains("paths_check: warn"));
    assert!(plain.contains("  dotfiles:\n    upstream: \"ssh://git@github.com/user/dotfiles.git\"\n    upstream_credential: deploy-dotfiles-01\n    templates: [quick-fix]\n"));
    // An empty policy.
    let empty = PolicyConfig::from_yaml("format: 2\nkeys: {}\nrepos: {}\ntemplates: {}\n").unwrap();
    assert_eq!(
        empty.to_yaml(),
        "format: 2\n\nkeys: {}\n\nrepos: {}\n\ntemplates: {}\n"
    );
}

/// The policy with a template `fetch_unsigned` (`unsigned_fetch: true`, `fields` its other
/// lines) named by omega-code.
fn with_unsigned(fields: &str) -> String {
    POLICY
        .replacen(
            "templates: [feature-branch, quick-fix, read-only]",
            "templates: [feature-branch, quick-fix, read-only, fetch_unsigned]",
            1,
        )
        .replacen(
            "templates:\n  feature-branch:",
            &format!(
                "templates:\n  fetch_unsigned:\n    unsigned_fetch: true\n{fields}  feature-branch:"
            ),
            1,
        )
}

const UNSIGNED: &str = "    max_ttl: 1h\n    max_ops_per_minute: 20\n";

#[test]
fn an_unsigned_fetch_template_fetches_only_for_an_hour_at_most_once_per_repo() {
    // At the bound: read, and the repo names it.
    let config = PolicyConfig::from_yaml(&with_unsigned(UNSIGNED)).unwrap();
    let name = "fetch_unsigned".parse().unwrap();
    let template = config.template(&name).unwrap();
    assert!(template.unsigned_fetch);
    assert_eq!(
        template.operations,
        std::collections::BTreeSet::from([Operation::Fetch])
    );
    assert_eq!(
        (
            template.max_signatures,
            template.max_pushes,
            template.max_push_size.bytes()
        ),
        (0, 0, 0)
    );
    assert!(config.allows(&repo("omega-code"), &name));
    // Any other template still writes them: one left out is missing.
    assert_error(
        &error_of(&POLICY.replacen("    max_pushes: 30\n", "", 1)),
        "templates.feature-branch: missing field `max_pushes`",
    );
    // Off by default: no template of the test policy grants without a signature.
    let plain = PolicyConfig::from_yaml(POLICY).unwrap();
    assert!(plain.templates().values().all(|t| !t.unsigned_fetch));
    // Past the bound by a second; any field it implies written, even as fetch implies it
    // (one way to write it), each named.
    let implied = |field: &str| {
        format!(
            "templates.fetch_unsigned.{field}: not written with unsigned_fetch: true (fetch \
             only: its operation is implied, and a fetch uses no count)"
        )
    };
    for (fields, expected) in [
        (
            UNSIGNED.replacen("max_ttl: 1h", "max_ttl: 3601s", 1),
            "templates.fetch_unsigned.max_ttl: 3601s: an unsigned_fetch template's leases last \
             at most 1h"
                .to_owned(),
        ),
        (
            format!("{UNSIGNED}    operations: [fetch, push]\n"),
            implied("operations"),
        ),
        (
            format!("{UNSIGNED}    operations: [fetch]\n"),
            implied("operations"),
        ),
        (
            format!("{UNSIGNED}    max_signatures: 0\n"),
            implied("max_signatures"),
        ),
        (
            format!("{UNSIGNED}    max_pushes: 1\n"),
            implied("max_pushes"),
        ),
        (
            format!("{UNSIGNED}    max_push_size: 0\n"),
            implied("max_push_size"),
        ),
    ] {
        assert_error(&error_of(&with_unsigned(&fields)), &expected);
    }
    // A second one named by the same repo: refused, naming both; named by another repo, read.
    let two = with_unsigned(UNSIGNED)
        .replacen("fetch_unsigned]", "fetch_unsigned, zz_unsigned]", 1)
        .replacen(
            "templates:\n  fetch_unsigned:",
            &format!(
                "templates:\n  zz_unsigned:\n    unsigned_fetch: true\n{UNSIGNED}  fetch_unsigned:"
            ),
            1,
        );
    assert_error(
        &error_of(&two),
        "repos.omega-code.templates: fetch_unsigned and zz_unsigned are both unsigned_fetch \
         templates: a repo names at most one",
    );
    let apart = two
        .replacen("fetch_unsigned, zz_unsigned]", "fetch_unsigned]", 1)
        .replacen(
            "    templates: [quick-fix]\n",
            "    templates: [quick-fix, zz_unsigned]\n",
            1,
        );
    PolicyConfig::from_yaml(&apart).unwrap();
}

#[test]
fn a_closed_repo_refuses_every_ticket_with_its_reason() {
    let closed = PolicyConfig::from_yaml(&POLICY.replacen(
        "templates: [feature-branch, quick-fix, read-only]",
        "templates: []",
        1,
    ))
    .unwrap();
    let reason = "repos.omega-code: repo omega-code is closed: it allows no template \
                  (repos.omega-code.templates is empty)";
    // Picked by the daemon, or named by the ticket: the same reason.
    for yaml in [
        REQUEST.to_owned(),
        REQUEST.replacen("    template: feature-branch\n", "", 1),
    ] {
        let rejection =
            writ_core::fit::submit(&closed, &request(&yaml), &submission(1)).unwrap_err();
        assert_eq!(rejection.reasons, vec![reason.to_owned()], "{yaml}");
    }
    // The same ticket fits once the repo allows the template again.
    writ_core::fit::submit(&config(), &request(REQUEST), &submission(1)).unwrap();
}

#[test]
fn one_entry_is_written_alone_as_the_whole_policy_writes_it() {
    use writ_core::config::Section;
    let policy = PolicyConfig::from_yaml(POLICY).unwrap();
    assert_eq!(
        policy.entry_yaml(Section::Repos, "dotfiles").unwrap(),
        "dotfiles:\n  upstream: \"ssh://git@github.com/user/dotfiles.git\"\n  \
         upstream_credential: deploy-dotfiles-01\n  templates: [quick-fix]\n"
    );
    assert_eq!(
        policy
            .entry_yaml(Section::Keys, "upstream-forgejo-01")
            .unwrap(),
        "upstream-forgejo-01:\n  use: upstream\n  kind: ssh\n  algorithm: rsa4096\n"
    );
    assert!(
        policy
            .entry_yaml(Section::UpstreamHosts, "github.com")
            .unwrap()
            .starts_with("github.com:\n  - \"ssh-ed25519 AAAA")
    );
    assert!(
        policy
            .entry_yaml(Section::Templates, "read-only")
            .unwrap()
            .starts_with("read-only:\n  operations: [fetch]\n  max_ttl: 8h\n")
    );
    assert_eq!(policy.entry_yaml(Section::Repos, "nowhere"), None);
    assert_eq!(
        policy.entry_yaml(Section::Keys, "omega-code"),
        None,
        "another section's name"
    );
    // Each entry, in every section, is the text of the whole policy at its place.
    let whole = policy.to_yaml();
    for section in Section::ALL {
        for name in policy.entry_names(section) {
            let entry = policy.entry_yaml(section, &name).unwrap();
            let indented: String = entry.lines().map(|l| format!("  {l}\n")).collect();
            assert!(whole.contains(&indented), "{section}.{name}");
        }
    }
}

fn edits(args: &[&str]) -> Vec<writ_core::config::edit::FieldEdit> {
    args.iter()
        .map(|a| writ_core::config::edit::FieldEdit::parse(a).unwrap())
        .collect()
}

fn edited(
    section: writ_core::config::Section,
    name: &str,
    args: &[&str],
) -> Result<PolicyConfig, String> {
    writ_core::config::edit::edit(
        &config(),
        section,
        name,
        &edits(args),
        writ_core::fit::DEFAULT_MIN_TTL,
    )
    .map_err(|e| e.to_string())
}

#[test]
fn set_changes_exactly_the_fields_named_in_every_syntax() {
    use writ_core::config::Section;
    let before = config();
    let template = |p: &PolicyConfig| {
        p.template(&"feature-branch".parse().unwrap())
            .unwrap()
            .clone()
    };
    // `=` replaces a value; `+=`, `-=` add to and take from a list; `!` unsets; `=` alone
    // empties a list.
    let after = edited(
        Section::Templates,
        "feature-branch",
        &[
            "max_ttl=2h",
            "branches+=agent/hotfix-*",
            "committer_emails-=user+agent@example.org",
            "committer_emails+=bot@example.org",
            "force_push=true",
            "max_signatures=7",
            "max_renewals=2",
        ],
    )
    .unwrap();
    let (old, new) = (template(&before), template(&after));
    assert_eq!(new.max_ttl, Duration::from_seconds(7200));
    assert_eq!(new.branches.len(), 2);
    assert_eq!(
        new.committer_emails
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>(),
        ["bot@example.org"]
    );
    assert!(new.force_push && new.max_signatures == 7 && new.max_renewals == Some(2));
    // Nothing else moved: the other fields, the other templates, the other sections.
    assert_eq!(new.operations, old.operations);
    assert_eq!(new.max_pushes, old.max_pushes);
    assert_eq!(new.paths_check, old.paths_check);
    assert_eq!(after.repos(), before.repos());
    assert_eq!(after.keys(), before.keys());
    for other in ["quick-fix", "read-only"] {
        let name = other.parse().unwrap();
        assert_eq!(after.template(&name), before.template(&name));
    }
    // `!` back to the default, `=` alone empties a list (and a repo with none is closed).
    let unset = writ_core::config::edit::edit(
        &after,
        Section::Templates,
        "feature-branch",
        &edits(&["max_renewals!", "force_push!"]),
        writ_core::fit::DEFAULT_MIN_TTL,
    )
    .unwrap();
    assert_eq!(template(&unset).max_renewals, None);
    assert!(!template(&unset).force_push);
    let closed = edited(Section::Repos, "homelab-scripts", &["templates="]).unwrap();
    assert!(
        closed
            .repo(&repo("homelab-scripts"))
            .unwrap()
            .templates
            .is_empty()
    );
    // A comma-separated list replaces one; a host's keys.
    let repo_edit = edited(
        Section::Repos,
        "dotfiles",
        &["templates=quick-fix,feature-branch"],
    )
    .unwrap();
    let dotfiles = repo_edit.repo(&repo("dotfiles")).unwrap();
    assert_eq!(dotfiles.templates.len(), 2);
    let key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC=";
    let host = edited(
        Section::UpstreamHosts,
        "github.com",
        &[&format!("keys+={key}")],
    )
    .unwrap();
    let github = "github.com".to_owned().try_into().unwrap();
    assert_eq!(host.upstream_hosts()[&github].len(), 2);
    // A key's changeable fields: its hash (a token's host and a key's user ids likewise).
    let uids = edited(Section::Keys, "agent-ed25519-01", &["hash=sha256"]).unwrap();
    assert!(matches!(
        uids.key(&"agent-ed25519-01".parse().unwrap()),
        Some(Key::Signing(k)) if k.hash.map(|h| h.as_str()) == Some("sha256")
    ));
}

#[test]
fn a_set_the_policy_refuses_or_a_field_that_cant_change_is_refused_with_its_reason() {
    use writ_core::config::Section;
    for (section, name, args, expected) in [
        (
            Section::Keys,
            "agent-ed25519-01",
            &["algorithm=rsa4096"][..],
            "keys.agent-ed25519-01.algorithm: can't change: it is what the key is (writ admin key rotate agent-ed25519-01 makes a new key, declared otherwise)",
        ),
        (
            Section::Keys,
            "upstream-github-01",
            &["use=signing"][..],
            "keys.upstream-github-01.use: can't change",
        ),
        (
            Section::Keys,
            "upstream-github-01",
            &["backend=yubikey"][..],
            "keys.upstream-github-01.backend: can't change",
        ),
        (
            Section::Templates,
            "feature-branch",
            &["max_ttl!"][..],
            "templates.feature-branch.max_ttl: required: it can't be unset",
        ),
        (
            Section::Templates,
            "feature-branch",
            &["max_ttl="][..],
            "templates.feature-branch.max_ttl: empty: field= empties a list",
        ),
        (
            Section::Templates,
            "feature-branch",
            &["max_signatures=many"][..],
            "templates.feature-branch.max_signatures: \"many\" is not a count",
        ),
        (
            Section::Templates,
            "feature-branch",
            &["force_push=yes"][..],
            "templates.feature-branch.force_push: \"yes\": true or false",
        ),
        (
            Section::Templates,
            "feature-branch",
            &["max_ttl+=1h"][..],
            "templates.feature-branch.max_ttl: += and -= are for a list",
        ),
        (
            Section::Templates,
            "feature-branch",
            &["branches+=agent/*"][..],
            "templates.feature-branch.branches: \"agent/*\" is listed already",
        ),
        (
            Section::Templates,
            "feature-branch",
            &["branches-=main"][..],
            "templates.feature-branch.branches: \"main\" is not listed",
        ),
        (
            Section::Templates,
            "feature-branch",
            &["max_tll=1h"][..],
            "templates.feature-branch.max_tll: template has no field \"max_tll\": it takes unsigned_fetch, operations, branches",
        ),
        (
            Section::Templates,
            "nowhere",
            &["max_ttl=1h"][..],
            "templates.nowhere: no template nowhere in the policy",
        ),
        // What the policy itself refuses, read back whole.
        (
            Section::Templates,
            "feature-branch",
            &["max_ttl=1m"][..],
            "templates.feature-branch.max_ttl: must be at least 5m",
        ),
        (
            Section::Templates,
            "feature-branch",
            &["signing_key=upstream-github-01"][..],
            "templates.feature-branch.signing_key: keys.upstream-github-01 is an upstream credential",
        ),
        (
            Section::Templates,
            "feature-branch",
            &["unsigned_fetch=true"][..],
            "templates.feature-branch.operations: not written with unsigned_fetch: true",
        ),
        (
            Section::Repos,
            "omega-code",
            &["templates+=nope"][..],
            "repos.omega-code.templates: nope is not a template",
        ),
        (
            Section::Repos,
            "omega-code",
            &["upstream=ssh://git@gitlab.com/x.git"][..],
            "repos.omega-code.upstream: its host gitlab.com has no pin in upstream_hosts",
        ),
        (
            Section::UpstreamHosts,
            "github.com",
            &["keys="][..],
            "upstream_hosts.github.com: must pin 1 to 16 keys",
        ),
    ] {
        let error = edited(section, name, args).unwrap_err();
        assert!(error.starts_with(expected), "{args:?}: {error}");
    }
}

#[test]
fn an_entry_something_uses_is_never_removed_and_one_nothing_uses_is() {
    use writ_core::config::Section;
    use writ_core::config::edit::remove;
    let min = writ_core::fit::DEFAULT_MIN_TTL;
    let policy = config();
    for (section, name, expected) in [
        (
            Section::Templates,
            "quick-fix",
            "repos.dotfiles.templates: quick-fix is not a template",
        ),
        (
            Section::Keys,
            "upstream-forgejo-01",
            "repos.homelab-scripts.upstream_credential: upstream-forgejo-01 is not declared in keys",
        ),
        (
            Section::Keys,
            "agent-ed25519-01",
            "templates.feature-branch.signing_key: agent-ed25519-01 is not declared in keys",
        ),
        (
            Section::UpstreamHosts,
            "forgejo.home",
            "repos.homelab-scripts.upstream: its host forgejo.home has no pin",
        ),
        (
            Section::Repos,
            "nowhere",
            "repos.nowhere: no repo nowhere in the policy",
        ),
    ] {
        let error = remove(&policy, section, name, min).unwrap_err().to_string();
        assert!(error.starts_with(expected), "{section}.{name}: {error}");
    }
    // A repo (nothing names repos), then what it alone used.
    let without = remove(&policy, Section::Repos, "homelab-scripts", min).unwrap();
    assert!(without.repo(&repo("homelab-scripts")).is_none());
    let without = remove(&without, Section::Keys, "upstream-forgejo-01", min).unwrap();
    let without = remove(&without, Section::UpstreamHosts, "forgejo.home", min).unwrap();
    assert!(
        without
            .upstream_hosts()
            .keys()
            .all(|h| h.as_str() != "forgejo.home")
    );
    assert_eq!(without.templates(), policy.templates());
}

#[test]
fn add_makes_an_entry_from_its_fields_and_says_which_required_ones_are_missing() {
    use writ_core::config::Section;
    use writ_core::config::edit::{add, current, missing};
    let min = writ_core::fit::DEFAULT_MIN_TTL;
    let given = edits(&[
        "operations=fetch",
        "max_ttl=1h",
        "max_signatures=0",
        "max_pushes=0",
    ]);
    assert_eq!(
        missing(Section::Templates, &given),
        ["max_ops_per_minute", "max_push_size"]
    );
    let error = add(&config(), Section::Templates, "fetch-only", &given, min)
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("templates.fetch-only: "), "{error}");
    assert!(
        error.contains("missing field `max_ops_per_minute`"),
        "{error}"
    );
    let mut all = given.clone();
    all.extend(edits(&["max_ops_per_minute=5", "max_push_size=0"]));
    assert!(missing(Section::Templates, &all).is_empty());
    let added = add(&config(), Section::Templates, "fetch-only", &all, min).unwrap();
    let template = added.template(&"fetch-only".parse().unwrap()).unwrap();
    assert_eq!(template.max_ops_per_minute, 5);
    assert!(
        added
            .template_users(&"fetch-only".parse().unwrap())
            .is_empty()
    );
    // One by that name already: refused, pointing to edit.
    assert_eq!(
        add(&config(), Section::Templates, "read-only", &all, min)
            .unwrap_err()
            .to_string(),
        "templates.read-only: there is a template read-only already (writ admin template edit \
         read-only changes it)"
    );
    // A host, a key, a repo naming them, chained.
    let host = add(
        &added,
        Section::UpstreamHosts,
        "codeberg.org",
        &edits(&[&format!("keys={PIN}")]),
        min,
    )
    .unwrap();
    let key = add(
        &host,
        Section::Keys,
        "codeberg-01",
        &edits(&["use=upstream", "kind=ssh", "algorithm=rsa3072"]),
        min,
    );
    // What a key is can't change, so it is set only when the key is added.
    let key = key.unwrap();
    let repo = add(
        &key,
        Section::Repos,
        "mirror",
        &edits(&[
            "upstream=ssh://git@codeberg.org/me/mirror.git",
            "upstream_credential=codeberg-01",
            "templates=fetch-only",
        ]),
        min,
    )
    .unwrap();
    assert_eq!(
        repo.key_users(&"codeberg-01".parse().unwrap()).repos,
        vec![repo_name("mirror")]
    );
    // The values a prompt starts from.
    let values = current(&repo, Section::Repos, "mirror").unwrap();
    assert_eq!(values["templates"], "fetch-only");
    assert_eq!(values["upstream_credential"], "codeberg-01");
    assert!(
        !values.contains_key("ticket_link"),
        "a default isn't a value"
    );
    let values = current(&config(), Section::Templates, "feature-branch").unwrap();
    assert_eq!(values["committer_emails"], "user+agent@example.org");
    assert_eq!(values["max_ttl"], "4h");
    assert_eq!(current(&config(), Section::Repos, "nowhere"), None);
}

fn repo_name(name: &str) -> writ_core::names::RepoName {
    name.parse().unwrap()
}

#[test]
fn a_policy_with_no_entry_is_one_to_start_from() {
    // What the setup guide starts from: entries added later by signed changes.
    let empty = "format: 2\nkeys: {}\nrepos: {}\ntemplates: {}\n";
    let config = PolicyConfig::from_yaml(empty).unwrap();
    assert!(config.keys().is_empty());
    assert!(config.upstream_hosts().is_empty());
    // Written back in Writ's layout, it reads the same.
    let written = config.to_yaml();
    assert_eq!(
        PolicyConfig::from_yaml(&written).unwrap().to_yaml(),
        written,
        "{written}"
    );
}

/// The test policy with `proxies` (each line one entry), extra `keys`, and `omega-code`
/// reached through `repo_proxy` when given.
fn with_proxies(proxies: &str, keys: &str, repo_proxy: Option<&str>) -> String {
    let mut text = POLICY
        .replacen("\nrepos:\n", &format!("\nproxies:\n{proxies}\nrepos:\n"), 1)
        .replacen("keys:\n", &format!("keys:\n{keys}"), 1);
    if let Some(proxy) = repo_proxy {
        text = text.replacen(
            "    upstream_credential: upstream-github-01\n",
            &format!("    upstream_credential: upstream-github-01\n    proxy: {proxy}\n"),
            1,
        );
    }
    text
}

#[test]
fn a_proxy_takes_a_credential_exactly_with_a_user_on_its_host() {
    use writ_core::config::{ProxyScheme, Section};
    use writ_core::names::ProxyName;

    let tor_key = "  tor-pass: { use: upstream, kind: token, host: Tor }\n";
    let ok = with_proxies(
        "  tor: { url: \"socks5://writ@tor:9050\", credential: tor-pass, connect_timeout: 2m }\n  \
         office: { url: \"http://[::1]:3128\" }\n",
        tor_key,
        Some("tor"),
    );
    let policy = PolicyConfig::from_yaml(&ok).unwrap();
    let tor: ProxyName = "tor".parse().unwrap();
    let proxy = policy.proxy(&tor).unwrap();
    assert_eq!(proxy.url.scheme(), ProxyScheme::Socks5);
    assert_eq!(proxy.connect_timeout().seconds(), 120);
    let office = policy.proxy(&"office".parse().unwrap()).unwrap();
    assert_eq!(office.connect_timeout().seconds(), 30);
    assert_eq!(
        policy.proxy_users(&tor),
        vec!["omega-code".parse().unwrap()]
    );
    let users = policy.key_users(&"tor-pass".parse().unwrap());
    assert_eq!(users.proxies, vec![tor.clone()]);
    assert_eq!(users.to_string(), "proxies tor");
    assert_eq!(
        policy.entry_names(Section::Proxies),
        vec!["office".to_owned(), "tor".to_owned()]
    );
    // The canonical layout reads back to itself, the section between the pins and the repos.
    let written = policy.to_yaml();
    assert_eq!(PolicyConfig::from_yaml(&written).unwrap(), policy);
    let pins = written.find("\nupstream_hosts:").unwrap();
    let proxies = written.find("\nproxies:\n").unwrap();
    let repos = written.find("\nrepos:\n").unwrap();
    assert!(pins < proxies && proxies < repos, "{written}");
    assert_eq!(
        policy.entry_yaml(Section::Proxies, "tor").unwrap(),
        "tor:\n  url: \"socks5://writ@tor:9050\"\n  credential: tor-pass\n  connect_timeout: 2m\n"
    );
    assert!(written.contains("    proxy: tor\n"), "{written}");

    let signing = "  sign-key: { use: signing, format: ssh, algorithm: ed25519 }\n";
    let ssh_key = "  ssh-key: { use: upstream, kind: ssh, algorithm: ed25519 }\n";
    let other_host = "  elsewhere: { use: upstream, kind: token, host: proxy.corp }\n";
    for (case, text, expected) in [
        (
            "a user without a credential",
            with_proxies("  tor: { url: \"socks5://writ@tor:9050\" }\n", "", None),
            "proxies.tor.credential: required with a user in the URL",
        ),
        (
            "a credential without a user",
            with_proxies(
                "  tor: { url: \"socks5://tor:9050\", credential: tor-pass }\n",
                tor_key,
                None,
            ),
            "proxies.tor.credential: only with a user in the URL",
        ),
        (
            "an undeclared credential",
            with_proxies(
                "  tor: { url: \"socks5://u@tor:9050\", credential: nowhere }\n",
                "",
                None,
            ),
            "proxies.tor.credential: nowhere is not declared in keys",
        ),
        (
            "a signing key",
            with_proxies(
                "  tor: { url: \"socks5://u@tor:9050\", credential: sign-key }\n",
                signing,
                None,
            ),
            "proxies.tor.credential: keys.sign-key is not a token",
        ),
        (
            "an ssh credential",
            with_proxies(
                "  tor: { url: \"socks5://u@tor:9050\", credential: ssh-key }\n",
                ssh_key,
                None,
            ),
            "proxies.tor.credential: keys.ssh-key is not a token",
        ),
        (
            "a token for another host",
            with_proxies(
                "  tor: { url: \"socks5://u@tor:9050\", credential: elsewhere }\n",
                other_host,
                None,
            ),
            "proxies.tor.credential: keys.elsewhere is a token for proxy.corp, not for this \
             proxy's host tor",
        ),
        (
            "a timeout under 1s",
            with_proxies(
                "  tor: { url: \"socks5://tor:9050\", connect_timeout: 0s }\n",
                "",
                None,
            ),
            "proxies.tor.connect_timeout: 0s, must be from 1s to 5m",
        ),
        (
            "a timeout over 5m",
            with_proxies(
                "  tor: { url: \"socks5://tor:9050\", connect_timeout: 301s }\n",
                "",
                None,
            ),
            "proxies.tor.connect_timeout: 301s, must be from 1s to 5m",
        ),
        (
            "an unknown field",
            with_proxies("  tor: { url: \"socks5://tor:9050\", via: x }\n", "", None),
            "proxies.tor.via: unknown field `via`, expected one of url, credential, connect_timeout",
        ),
        (
            "a bad URL",
            with_proxies("  tor: { url: \"socks5h://tor:9050\" }\n", "", None),
            "proxies.tor.url: write socks5://",
        ),
        (
            "a repo naming no declared proxy",
            with_proxies(
                "  tor: { url: \"socks5://tor:9050\" }\n",
                "",
                Some("elsewhere"),
            ),
            "repos.omega-code.proxy: elsewhere is not declared in proxies",
        ),
    ] {
        assert_error(&error_of(&text), expected);
        let _ = case;
    }
    // The timeout's bounds themselves are taken.
    for bound in ["1s", "5m"] {
        let text = with_proxies(
            &format!("  tor: {{ url: \"socks5://tor:9050\", connect_timeout: {bound} }}\n"),
            "",
            None,
        );
        assert!(PolicyConfig::from_yaml(&text).is_ok(), "{bound}");
    }
    // One key is a repo's credential or a proxy's, never both.
    let shared = with_upstream(
        "https://github.com/user/omega-code.git",
        "gh-token",
        "  gh-token: { use: upstream, kind: token, host: github.com }\n",
    )
    .replacen(
        "\nrepos:\n",
        "\nproxies:\n  gh: { url: \"http://u@github.com:3128\", credential: gh-token }\n\nrepos:\n",
        1,
    );
    assert_error(
        &error_of(&shared),
        "repos.omega-code.upstream_credential: keys.gh-token is the password of proxies.gh",
    );
}

#[test]
fn at_most_sixty_four_proxies_are_declared() {
    let proxies = |n: usize| -> String {
        (0..n)
            .map(|i| format!("  p{i}: {{ url: \"socks5://proxy:1080\" }}\n"))
            .collect()
    };
    assert!(PolicyConfig::from_yaml(&with_proxies(&proxies(64), "", None)).is_ok());
    assert_error(
        &error_of(&with_proxies(&proxies(65), "", None)),
        "proxies: at most 64 proxies are declared",
    );
}

#[test]
fn a_proxy_is_edited_field_by_field_and_a_repo_names_it() {
    use writ_core::config::Section;
    use writ_core::config::edit::{self, FieldEdit};
    use writ_core::units::Duration;

    let policy = PolicyConfig::from_yaml(POLICY).unwrap();
    let edits = |list: &[&str]| -> Vec<FieldEdit> {
        list.iter().map(|e| FieldEdit::parse(e).unwrap()).collect()
    };
    let min = Duration::from_seconds(300);
    let added = edit::add(
        &policy,
        Section::Proxies,
        "tor",
        &edits(&["url=socks5://127.0.0.1:9050", "connect_timeout=2m"]),
        min,
    )
    .unwrap();
    let routed = edit::edit(
        &added,
        Section::Repos,
        "omega-code",
        &edits(&["proxy=tor"]),
        min,
    )
    .unwrap();
    let repo = routed.repo(&"omega-code".parse().unwrap()).unwrap();
    assert_eq!(repo.proxy.as_ref().map(|p| p.as_str()), Some("tor"));
    let direct = edit::edit(
        &routed,
        Section::Repos,
        "omega-code",
        &edits(&["proxy!"]),
        min,
    )
    .unwrap();
    assert_eq!(
        direct.repo(&"omega-code".parse().unwrap()).unwrap().proxy,
        None
    );
    // A required field is required; a timeout back to its default is written no more.
    let error = edit::add(&policy, Section::Proxies, "bare", &[], min).unwrap_err();
    assert_error(&error.to_string(), "proxies.bare: missing field `url`");
    let unset = edit::edit(
        &added,
        Section::Proxies,
        "tor",
        &edits(&["connect_timeout!"]),
        min,
    )
    .unwrap();
    assert_eq!(
        unset.entry_yaml(Section::Proxies, "tor").unwrap(),
        "tor:\n  url: \"socks5://127.0.0.1:9050\"\n"
    );
    // Removed while a repo names it: refused by the read back.
    let error = edit::remove(&routed, Section::Proxies, "tor", min).unwrap_err();
    assert_error(
        &error.to_string(),
        "repos.omega-code.proxy: tor is not declared in proxies",
    );
}

/// A recovery recipient of the right form (age1 and 58 bech32 characters).
const RECOVERY: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";

/// The test policy with `recipients` (each line one entry).
fn with_recipients(recipients: &str) -> String {
    POLICY.replacen(
        "\nrepos:\n",
        &format!("\nrecipients:\n{recipients}\nrepos:\n"),
        1,
    )
}

#[test]
fn the_keystore_s_recipients_are_a_hardware_key_and_the_recovery_key_beside_it() {
    use writ_core::config::{Recipient, Section};
    let text = with_recipients(&format!(
        "  se-01: {{ backend: se-cryptokit }}\n  recovery: {{ recipient: {RECOVERY} }}\n"
    ));
    let policy = PolicyConfig::from_yaml(&text).unwrap();
    assert!(policy.hardware_keystore());
    let (name, recovery) = policy.recovery_recipient().unwrap();
    assert_eq!((name.as_str(), recovery.as_str()), ("recovery", RECOVERY));
    assert!(matches!(
        policy.recipients().get(&"se-01".parse().unwrap()),
        Some(Recipient::Hardware { backend }) if backend.as_str() == "se-cryptokit"
    ));
    assert_eq!(
        policy.entry_names(Section::Recipients),
        vec!["recovery".to_owned(), "se-01".to_owned()]
    );
    // The canonical layout reads back to itself, the section between the proxies and the
    // repos.
    let written = policy.to_yaml();
    assert_eq!(PolicyConfig::from_yaml(&written).unwrap(), policy);
    let recipients = written.find("\nrecipients:\n").unwrap();
    assert!(
        recipients < written.find("\nrepos:\n").unwrap(),
        "{written}"
    );
    assert_eq!(
        policy.entry_yaml(Section::Recipients, "se-01").unwrap(),
        "se-01:\n  backend: se-cryptokit\n"
    );
    assert_eq!(
        policy.entry_yaml(Section::Recipients, "recovery").unwrap(),
        format!("recovery:\n  recipient: {RECOVERY}\n")
    );
    // A passphrase keystore may have the recovery recipient alone; none at all is the default.
    let alone = PolicyConfig::from_yaml(&with_recipients(&format!(
        "  recovery: {{ recipient: {RECOVERY} }}\n"
    )))
    .unwrap();
    assert!(!alone.hardware_keystore());
    assert!(alone.recovery_recipient().is_some());
    let none = PolicyConfig::from_yaml(POLICY).unwrap();
    assert!(!none.hardware_keystore() && none.recovery_recipient().is_none());
    assert!(!none.to_yaml().contains("recipients:"));
}

#[test]
fn a_recipient_the_policy_cant_hold_is_refused_naming_it() {
    let recovery = format!("  recovery: {{ recipient: {RECOVERY} }}\n");
    let mut nine = recovery.clone();
    for i in 0..8 {
        nine.push_str(&format!("  se-{i}: {{ backend: se-cryptokit }}\n"));
    }
    let mut eight = recovery.clone();
    for i in 0..7 {
        eight.push_str(&format!("  se-{i}: {{ backend: se-cryptokit }}\n"));
    }
    assert!(
        PolicyConfig::from_yaml(&with_recipients(&eight)).is_ok(),
        "eight recipients"
    );
    let cases: Vec<(String, &str)> = vec![
        (
            "  se-01: { backend: se-cryptokit }\n".to_owned(),
            "recipients: a hardware recipient needs the recovery recipient beside it",
        ),
        (
            format!("{recovery}  second: {{ recipient: {RECOVERY} }}\n"),
            "recipients: at most one recovery recipient",
        ),
        (nine, "recipients: at most 8 recipients are declared"),
        (
            format!("{recovery}  se-01: {{ backend: software }}\n"),
            "recipients.se-01.backend: a recipient is a hardware device's key",
        ),
        (
            format!("  both: {{ backend: se-cryptokit, recipient: {RECOVERY} }}\n"),
            "recipients.both: a recipient is a hardware key (backend) or the recovery key",
        ),
        ("  empty: {}\n".to_owned(), "recipients.empty: a recipient takes backend"),
        (
            "  bad: { recipient: AGE1QL3Z7HJY54PW3HYWW5AYYFG7ZQGVC7W3J2ELW8ZMRJ2KG5SFN9AQMCAC8P }\n"
                .to_owned(),
            "recipients.bad.recipient: an age X25519 recipient starts with age1",
        ),
        (
            "  bad: { recipient: age1se1qgg9h7ylml6v }\n".to_owned(),
            "recipients.bad.recipient: an age X25519 recipient is age1 and 58 characters",
        ),
        (
            format!("  bad: {{ recipient: {} }}\n", RECOVERY.replace('q', "b")),
            "recipients.bad.recipient: an age X25519 recipient is lower-case bech32",
        ),
        (
            format!("{recovery}  se-01: {{ backend: se-cryptokit, host: x }}\n"),
            "recipients.se-01.host: unknown field `host`, expected one of backend, recipient",
        ),
    ];
    for (recipients, expected) in cases {
        assert_error(&error_of(&with_recipients(&recipients)), expected);
    }
}

#[test]
fn recipients_are_added_set_and_removed_as_entries_and_the_rules_hold() {
    use writ_core::config::Section;
    use writ_core::config::edit;
    let min = writ_core::fit::DEFAULT_MIN_TTL;
    let start = PolicyConfig::from_yaml(POLICY).unwrap();
    // The recovery key first, then a hardware key beside it.
    let recovery = format!("recipient={RECOVERY}");
    let with_recovery = edit::add(
        &start,
        Section::Recipients,
        "recovery",
        &edits(&[&recovery]),
        min,
    )
    .unwrap();
    let hardware = edit::add(
        &with_recovery,
        Section::Recipients,
        "se-01",
        &edits(&["backend=se-cryptokit"]),
        min,
    )
    .unwrap();
    assert!(hardware.hardware_keystore());
    // A hardware key first: refused, the recovery key missing.
    let error = edit::add(
        &start,
        Section::Recipients,
        "se-01",
        &edits(&["backend=se-cryptokit"]),
        min,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.starts_with("recipients: a hardware recipient needs the recovery recipient"),
        "{error}"
    );
    // The recovery key replaced in place; its backend never set.
    let other = RECOVERY.replace("ql3z", "qq3z");
    let replaced = edit::edit(
        &hardware,
        Section::Recipients,
        "recovery",
        &edits(&[&format!("recipient={other}")]),
        min,
    )
    .unwrap();
    assert_eq!(replaced.recovery_recipient().unwrap().1.as_str(), other);
    let error = edit::edit(
        &hardware,
        Section::Recipients,
        "se-01",
        &edits(&["backend=yubikey"]),
        min,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("backend"), "{error}");
    // The recovery key can't go while a hardware key needs it; the hardware key can.
    let error = edit::remove(&hardware, Section::Recipients, "recovery", min)
        .unwrap_err()
        .to_string();
    assert!(
        error.starts_with("recipients: a hardware recipient needs the recovery recipient"),
        "{error}"
    );
    let back = edit::remove(&hardware, Section::Recipients, "se-01", min).unwrap();
    assert_eq!(back, with_recovery);
}

#[test]
fn the_daemon_unseals_by_an_approver_unless_the_policy_says_auto() {
    use writ_core::config::Unseal;
    let policy = PolicyConfig::from_yaml(POLICY).unwrap();
    assert_eq!(policy.unseal(), Unseal::Approver);
    assert!(
        !policy.to_yaml().contains("unseal:"),
        "the default is left out"
    );
    let auto = PolicyConfig::from_yaml(&format!("{POLICY}\nunseal: auto\n")).unwrap();
    assert_eq!(auto.unseal(), Unseal::Auto);
    let written = auto.to_yaml();
    assert!(written.ends_with("\nunseal: auto\n"), "{written}");
    assert_eq!(PolicyConfig::from_yaml(&written).unwrap(), auto);
    assert_eq!(policy.with_unseal(Unseal::Auto), auto);
    assert_eq!(auto.with_unseal(Unseal::Approver), policy);
    assert_eq!(
        PolicyConfig::from_yaml(&format!("{POLICY}\nunseal: approver\n")).unwrap(),
        policy
    );
    for bad in ["yes", "Auto", "passphrase", "\"\""] {
        assert_error(
            &error_of(&format!("{POLICY}\nunseal: {bad}\n")),
            "unseal: unknown variant",
        );
    }
}

/// The review after M7.6 (P-3): list fields are split on commas, and `current` joins with
/// them, so a pattern or uid holding one came back as two (`template add --from` widened a
/// template). Commas are refused where the edit syntax can't carry them, and a template
/// copied with `--from`'s edits is the template it copies.
#[test]
fn a_template_copied_field_by_field_is_the_same_and_commas_are_refused() {
    use writ_core::config::Section;
    use writ_core::config::edit::{self, Change, FieldEdit};
    use writ_core::pattern::{BranchPattern, RefPattern};
    for bad in ["agent/x,y*", "a,b"] {
        let error = bad.parse::<BranchPattern>().unwrap_err();
        assert_eq!(
            (error.kind, error.why.as_str()),
            ("branch pattern", "must not contain ','")
        );
    }
    let error = "refs/heads/a,b".parse::<RefPattern>().unwrap_err();
    assert_eq!(error.why, "must not contain ','");
    let error = "Doe, John <j@example.org>"
        .parse::<writ_core::names::Uid>()
        .unwrap_err();
    assert!(error.to_string().contains("no ',' in the name"), "{error}");
    // `--from`: every field of the template set on a new one gives the same template.
    let policy = PolicyConfig::from_yaml(POLICY).unwrap();
    for name in ["feature-branch", "quick-fix", "read-only"] {
        let current = edit::current(&policy, Section::Templates, name).unwrap();
        let edits: Vec<FieldEdit> = current
            .iter()
            .map(|(field, value)| FieldEdit {
                field: (*field).to_owned(),
                change: Change::Set(value.clone()),
            })
            .collect();
        let copied = edit::add(
            &policy,
            Section::Templates,
            "copy",
            &edits,
            writ_core::fit::MIN_TTL_FLOOR,
        )
        .unwrap();
        assert_eq!(
            copied.template(&"copy".parse().unwrap()),
            policy.template(&name.parse().unwrap()),
            "{name}"
        );
    }
}
