//! `writ admin <noun> set` and `remove` (M6.2) with the real binaries: only the fields named
//! change, in one signed change shown as a diff; a change made in between refuses it; a field
//! that is what a key is never changes; an entry something uses is never removed; a removed
//! key is deleted from the keystore for good once the change applies (its public half kept in
//! the `admin` line, the id declared again making a new key), and a key left on disk is
//! deleted at the next unseal.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;
use std::io::{Read as _, Write as _};
use std::process::Stdio;

use writ_core::config::PolicyConfig;
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::{audit_events, stderr, stdout};

const POLICY: &str = r#"
keys:
  agent-01:
    use: signing
    format: ssh
    algorithm: ed25519
  agent-02:
    use: signing
    format: ssh
    algorithm: ed25519
  upstream-01:
    use: upstream
    kind: ssh
    algorithm: ed25519
upstream_hosts:
  remote.invalid:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    templates: [feature]
templates:
  feature:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-01
    max_ttl: 2h
    max_signatures: 40
    max_pushes: 20
    max_ops_per_minute: 100
    max_push_size: 10MB
"#;

/// The policy in force, as `writ admin show policy` prints it, and parsed.
fn in_force(daemon: &Daemon) -> (String, PolicyConfig) {
    let out = daemon.run(&["admin", "show", "policy"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    let policy = PolicyConfig::from_yaml(&text).unwrap();
    (text, policy)
}

/// The version of the policy in force, from `writ admin show`'s line on stderr.
fn version(daemon: &Daemon) -> String {
    let out = daemon.run(&["admin", "show", "policy"], "");
    stderr(&out)
        .split_whitespace()
        .nth(2)
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn set_changes_only_the_fields_named_and_a_change_made_in_between_refuses_it() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let (_, before) = in_force(&daemon);
    assert_eq!(version(&daemon), "1");

    // The fields named, in one signed change shown as a diff.
    let out = daemon.run(
        &[
            "admin",
            "template",
            "set",
            "feature",
            "max_signatures=7",
            "branches+=agent/fix-*",
            "--yes",
        ],
        "",
    );
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let said = stdout(&out);
    // The harness wrote the policy by hand: the first field change writes it in Writ's
    // layout, and says so.
    assert!(said.contains("isn't in Writ's layout"), "{said}");
    assert!(
        said.contains("with template feature set: max_signatures=7 branches+=agent/fix-*"),
        "{said}"
    );
    assert!(
        said.contains("\n+     max_signatures: 7\n")
            && said.contains("\n+     branches: [agent/*, agent/fix-*]\n"),
        "{said}"
    );
    assert!(said.contains("Applied: policy is version 2"), "{said}");
    let (text, after) = in_force(&daemon);
    let expected = writ_core::config::edit::edit(
        &before,
        writ_core::config::Section::Templates,
        "feature",
        &[
            writ_core::config::edit::FieldEdit::parse("max_signatures=7").unwrap(),
            writ_core::config::edit::FieldEdit::parse("branches+=agent/fix-*").unwrap(),
        ],
        writ_core::fit::DEFAULT_MIN_TTL,
    )
    .unwrap();
    assert_eq!(after, expected, "exactly the fields named");
    assert_eq!(text, after.to_yaml(), "in Writ's layout");
    let lines = audit_events(&daemon.audit(), "admin", "allowed");
    assert!(
        lines.last().unwrap()["reason"]
            .as_str()
            .unwrap()
            .starts_with("policy: version 2 (sha256 "),
        "{lines:?}"
    );

    // A field that is what a key is: refused here, with its reason, nothing sent.
    let out = daemon.run(
        &["admin", "key", "set", "agent-01", "algorithm=p256", "--yes"],
        "",
    );
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains(
            "keys.agent-01.algorithm: can't change: it is what the key is (writ admin key rotate \
             agent-01 makes a new key, declared otherwise)"
        ),
        "{}",
        stderr(&out)
    );
    // What the policy refuses: the reason, naming the field.
    let out = daemon.run(
        &["admin", "repo", "set", "demo", "templates+=nope", "--yes"],
        "",
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("repos.demo.templates: nope is not a template"),
        "{}",
        stderr(&out)
    );
    // Not field=value at all: refused before anything is asked of the daemon.
    let out = daemon.run(&["admin", "repo", "set", "demo", "templates", "--yes"], "");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("is not field=value"),
        "{}",
        stderr(&out)
    );
    assert_eq!(version(&daemon), "2");

    // A change made while another waits at its prompt: the one that waited is refused when
    // signed, naming the version, and changes nothing.
    let mut waiting = daemon
        .writ(&[
            "admin",
            "repo",
            "set",
            "demo",
            "protected_refs+=refs/heads/release",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut shown = Vec::new();
    let mut stdout_pipe = waiting.stdout.take().unwrap();
    let mut byte = [0u8; 1];
    while !shown.ends_with(b"Sign this change? [y/N] ") {
        let read = stdout_pipe.read(&mut byte).unwrap();
        assert_eq!(
            read,
            1,
            "writ ended before its prompt: {}",
            String::from_utf8_lossy(&shown)
        );
        shown.push(byte[0]);
    }
    let out = daemon.run(
        &[
            "admin",
            "template",
            "set",
            "feature",
            "max_pushes=3",
            "--yes",
        ],
        "",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    waiting.stdin.take().unwrap().write_all(b"y\n").unwrap();
    let mut rest = String::new();
    stdout_pipe.read_to_string(&mut rest).unwrap();
    let mut err = String::new();
    waiting
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert_eq!(waiting.wait().unwrap().code(), Some(1), "{rest}");
    assert!(
        err.contains("is version 3, not the one this change replaces (version 2)"),
        "{err}"
    );
    let (_, last) = in_force(&daemon);
    assert_eq!(version(&daemon), "3");
    assert!(
        last.repo(&"demo".parse().unwrap())
            .unwrap()
            .protected_refs
            .is_empty()
    );
}

#[test]
fn a_removed_key_is_deleted_for_good_and_what_something_uses_is_never_removed() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Https);
    let out = daemon.unseal();
    assert!(out.status.success(), "{}", stderr(&out));
    let keys = daemon.root().join("s/keys");

    // In use: refused, naming what uses it.
    for (args, why) in [
        (
            &["key", "remove", "agent-01"][..],
            "key agent-01 is in use by templates feature: take it off them first",
        ),
        (
            &["key", "remove", "upstream-01"][..],
            "key upstream-01 is in use by repos demo: take it off them first",
        ),
        (
            &["template", "remove", "feature"][..],
            "template feature is in use by repos demo: take it off them first",
        ),
    ] {
        let mut full = vec!["admin"];
        full.extend_from_slice(args);
        full.push("--yes");
        let out = daemon.run(&full, "");
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(stderr(&out).contains(why), "{args:?}: {}", stderr(&out));
    }
    // Without a terminal, only --yes answers the questions.
    let out = daemon.run(&["admin", "key", "remove", "agent-02"], "");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out)
            .contains("removing key agent-02 asks to confirm: without a terminal, give --yes"),
        "{}",
        stderr(&out)
    );
    assert!(keys.join("signing/agent-02.age").exists());
    assert_eq!(version(&daemon), "1");

    // Removed: deleted once the change applies, its public half printed and in the line.
    let public = fs::read_to_string(keys.join("signing/agent-02.pub")).unwrap();
    let public = public.trim();
    let out = daemon.run(&["admin", "key", "remove", "agent-02", "--yes"], "");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let said = stdout(&out);
    assert!(
        said.contains("deletes it from the keystore for good"),
        "{said}"
    );
    assert!(
        said.contains("Deleted signing ssh ed25519 agent-02 (SHA256:")
            && said.trim_end().ends_with(public),
        "{said}"
    );
    for file in ["signing/agent-02.age", "signing/agent-02.pub"] {
        assert!(!keys.join(file).exists(), "{file}");
    }
    let lines = audit_events(&daemon.audit(), "admin", "allowed");
    let reason = lines.last().unwrap()["reason"].as_str().unwrap().to_owned();
    assert!(
        reason.contains("; removed signing ssh ed25519 agent-02 (SHA256:")
            && reason.ends_with(public),
        "{reason}"
    );
    let (_, policy) = in_force(&daemon);
    assert!(policy.key(&"agent-02".parse().unwrap()).is_none());

    // Declared again: a new key, never the old one.
    let (text, _) = in_force(&daemon);
    let again = text.replacen(
        "keys:\n",
        "keys:\n  agent-02:\n    use: signing\n    format: ssh\n    algorithm: ed25519\n",
        1,
    );
    let file = daemon.root().join("again.yaml");
    fs::write(&file, &again).unwrap();
    let out = daemon.run(
        &["admin", "apply", "policy", file.to_str().unwrap(), "--yes"],
        "",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let made = stdout(&out);
    let fresh = made
        .lines()
        .find_map(|l| l.strip_prefix("New signing key agent-02 (register it on the remote): "))
        .unwrap_or_else(|| panic!("no new key: {made}"));
    assert_ne!(fresh, public, "the old key came back");

    // A repo with an active lease: the lease said before the change; then what it alone used
    // is removed too (its credential's file deleted, its host's pin).
    let ticket = "repos:\n  demo:\n    operations: [fetch]\n    branches: [\"agent/x\"]\n\
                  ticket:\n  title: \"Read\"\n  task: Read\nlimits:\n  ttl: 30m\n";
    let lease = daemon.lease("read", ticket);
    let out = daemon.run(&["admin", "repo", "remove", "demo", "--yes"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains(&format!(
            "These active leases reach repo demo and can no longer use it once it is removed: \
             {lease}"
        )),
        "{}",
        stdout(&out)
    );
    let out = daemon.run(&["admin", "key", "remove", "upstream-01", "--yes"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!keys.join("upstream/upstream-01.age").exists());
    let (_, policy) = in_force(&daemon);
    let host = policy.upstream_hosts().keys().next().unwrap().to_string();
    let out = daemon.run(&["admin", "host", "remove", &host, "--yes"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let (_, policy) = in_force(&daemon);
    assert!(policy.upstream_hosts().is_empty() && policy.repos().is_empty());

    // A key left on disk (the daemon stopped before it deleted one): deleted at the next
    // unseal, said in the audit log.
    daemon.stop();
    for ext in ["age", "pub"] {
        fs::copy(
            keys.join(format!("signing/agent-01.{ext}")),
            keys.join(format!("signing/stray.{ext}")),
        )
        .unwrap();
    }
    daemon.restart();
    let out = daemon.unseal();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!keys.join("signing/stray.age").exists() && !keys.join("signing/stray.pub").exists());
    assert!(
        keys.join("signing/agent-01.age").exists(),
        "a declared key stays"
    );
    let notes = audit_events(&daemon.audit(), "admin", "done");
    assert!(
        notes.iter().any(|l| l["reason"]
            == "signing key stray: deleted from the keystore at unseal (the policy in force no \
                longer declares it)"),
        "{notes:?}"
    );
}
