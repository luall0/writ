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
    Key, NotesRef, ObjectFormat, PathsCheck, PolicyConfig, PushMode, TicketLink, UpstreamKey,
};
use writ_core::ticket::Operation;
use writ_core::ticket::TicketRequest;

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
    assert!(dotfiles.direct_ssh.is_some());
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
        r#"keys:
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
const EVERYTHING: &str = r#"keys:
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
    templates: [quick, "12"]
    protected_refs: ["refs/heads/main", "refs/tags/*"]
    push_modes: [gateway, direct_ssh]
    ticket_link: notes
    notes_ref: writ
    direct_ssh: { hosts: [github.com], allow_account_wide: true }
templates:
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
    push_modes: [gateway, proxy]
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
    assert!(written.starts_with("keys:\n  agent-pgp:\n    use: signing\n    format: openpgp\n"));
    assert!(written.contains(
        "\n  azure:\n    use: upstream\n    kind: ssh\n    algorithm: rsa3072\n  gh-token:"
    ));
    assert!(
        written.contains("\nupstream_hosts:\n  \"[forgejo.home]:2222\":\n    - \"ssh-ed25519 AAAA")
    );
    assert!(
        written.contains("\n  \"true\":\n    upstream: \"https://bot@github.com/user/true.git\"\n")
    );
    assert!(written.contains("    templates: [\"12\", quick]\n"));
    assert!(written.contains("    max_ttl: \"1d\"\n"));
    assert!(written.contains("    max_ttl: 90m\n"));
    assert!(written.contains("    max_push_size: 50MiB\n"));
    assert!(written.contains("    committer_name: \"Writ agent\"\n"));
    // Defaults are left out.
    let plain = PolicyConfig::from_yaml(POLICY).unwrap().to_yaml();
    assert!(!plain.contains("backend:") && !plain.contains("paths_check: warn"));
    assert!(plain.contains("  dotfiles:\n    upstream: \"ssh://git@github.com/user/dotfiles.git\"\n    upstream_credential: deploy-dotfiles-01\n    templates: [quick-fix]\n    push_modes: [direct_ssh]\n    direct_ssh:\n      hosts: [github.com]\n"));
    // An empty policy.
    let empty = PolicyConfig::from_yaml("keys: {}\nrepos: {}\ntemplates: {}\n").unwrap();
    assert_eq!(empty.to_yaml(), "keys: {}\n\nrepos: {}\n\ntemplates: {}\n");
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
