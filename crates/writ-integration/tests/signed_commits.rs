//! M3 end to end: commits signed by the daemon through `writ-sign`, with the real `git` and
//! `ssh`, against the gateway in-process: every denial, with the reason the agent sees and
//! its audit line.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;
use std::path::Path;
use std::process::Output;

use writ_core::lease::State;
use writ_core::names::TicketId;
use writ_crypto::keys::KeyKind;
use writ_integration::gateway::{GitGateway, Listen, POLICY, TICKET, now};
use writ_integration::{audit_events, stderr};

/// git's status when the signing program fails.
const SIGNING_FAILED: i32 = 128;
/// `git commit-tree`'s status when the signing program fails.
const COMMIT_TREE_FAILED: i32 = 1;

/// One repo, `main` and tags protected, its commits carrying their `Writ:` trailer; a
/// template that refuses paths outside the ticket's.
const STRICT: &str = r#"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    protected_refs: ["refs/heads/main", "refs/tags/*"]
    ticket_link: trailer
templates:
  strict:
    repos: [demo]
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-01
    max_ttl: 1h
    max_signatures: 100
    max_pushes: 100
    max_ops_per_minute: 1000
    max_push_size: 50MB
    paths_check: deny
"#;

/// The harness's ticket with something more (YAML lines under the top level).
fn ticket(extra: &str) -> String {
    format!("{TICKET}{extra}")
}

/// [`TICKET`] with `extra` lines in its repository's block (indented four spaces).
fn in_repo(extra: &str) -> String {
    let branches = "    branches: [\"agent/*\"]\n";
    assert!(TICKET.contains(branches), "the fixture changed");
    TICKET.replacen(branches, &format!("{branches}{extra}"), 1)
}

/// `git commit -S` with a `Writ:` trailer for `lease`, as the session `key`.
fn commit(gw: &GitGateway, key: &str, work: &Path, lease: &str, extra: &[&str]) -> Output {
    let trailer = format!("Writ: {lease}");
    let mut args = vec!["commit", "-q", "-S", "--allow-empty", "-m", "change"];
    args.extend_from_slice(extra);
    args.extend(["--trailer", &trailer]);
    gw.git_as(key, work, &args)
}

/// The commit was refused: git's status, the reason the agent sees, the audit line's code.
fn assert_refused(gw: &GitGateway, out: &Output, reason: &str, code: Option<&str>) {
    assert_eq!(
        out.status.code(),
        Some(SIGNING_FAILED),
        "{reason}: {}",
        stderr(out)
    );
    assert!(
        stderr(out).contains(reason),
        "expected {reason:?} in:\n{}",
        stderr(out)
    );
    if let Some(code) = code {
        let audit = fs::read_to_string(gw.root().join("audit.jsonl")).unwrap();
        let denied = audit_events(&audit, "sign", "denied");
        let last = denied.last().expect("a denied sign line");
        assert_eq!(last["code"], code, "{last}");
    }
}

fn head(gw: &GitGateway, work: &Path) -> String {
    gw.git_ok(work, &["rev-parse", "HEAD"]).trim().to_owned()
}

fn signed_commits_verify_and_are_in_the_ledger(kind: KeyKind) {
    let gw = GitGateway::start(kind, Listen::Tcp);
    gw.seed_repo();
    let work = gw.clone("work");
    gw.wire_signing(&work);
    let lease = gw.service.list(false).unwrap().tickets[0].id.clone();

    fs::write(work.join("feature"), "x\n").unwrap();
    gw.git_ok(&work, &["add", "feature"]);
    let out = commit(&gw, "session", &work, lease.as_str(), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = gw.git(&work, &["verify-commit", "HEAD"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("Good \"git\" signature for agent@writ"),
        "{}",
        stderr(&out)
    );
    // The ledger holds the commit git wrote (its signature in it), for this lease and repo,
    // with the template's key; the audit line names it.
    let id = head(&gw, &work);
    let ledger = gw.ledger(&lease);
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].commit.as_str(), id);
    assert_eq!(ledger[0].repo.as_str(), "demo");
    assert_eq!(ledger[0].key.as_str(), "agent-01");
    let audit = fs::read_to_string(gw.root().join("audit.jsonl")).unwrap();
    let signed = audit_events(&audit, "sign", "allowed");
    assert_eq!(signed.len(), 1, "one line per signature: {signed:?}");
    assert_eq!(signed[0]["commit"], id.as_str());
    assert_eq!(signed[0]["committer"], "agent@writ");
    assert_eq!(signed[0]["lease"], lease.as_str());

    // Signed commits push like any other.
    gw.git_ok(
        &work,
        &["push", "-q", "origin", "HEAD:refs/heads/agent/signed"],
    );
}

#[test]
fn ed25519_commits_signed_by_the_daemon_verify_and_are_in_the_ledger() {
    signed_commits_verify_and_are_in_the_ledger(KeyKind::Ed25519);
}

#[test]
fn p256_commits_signed_by_the_daemon_verify_and_are_in_the_ledger() {
    signed_commits_verify_and_are_in_the_ledger(KeyKind::P256);
}

#[test]
fn what_the_commit_says_is_checked() {
    let gw = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, STRICT);
    gw.seed_repo();
    let work = gw.clone("work");
    gw.wire_signing(&work);
    let lease = gw.service.list(false).unwrap().tickets[0].id.clone();
    let id = lease.as_str();

    // A committer email the lease doesn't allow.
    let out = commit(&gw, "session", &work, id, &[]);
    assert!(
        out.status.success(),
        "the allowed case signs: {}",
        stderr(&out)
    );
    let out = gw.git(
        &work,
        &[
            "-c",
            "user.email=me@personal.example",
            "commit",
            "-q",
            "-S",
            "--allow-empty",
            "-m",
            "x",
            "--trailer",
            &format!("Writ: {id}"),
        ],
    );
    assert_refused(
        &gw,
        &out,
        &format!("writ: outside ticket {id}: committer email \"me@personal.example\" not allowed"),
        Some("committer"),
    );
    // The committer allowed, the author someone else (the user's personal identity): the
    // author is checked like the committer.
    let out = gw.git(
        &work,
        &[
            "commit",
            "-q",
            "-S",
            "--allow-empty",
            "--author",
            "Me <me@personal.example>",
            "-m",
            "x",
            "--trailer",
            &format!("Writ: {id}"),
        ],
    );
    assert_refused(
        &gw,
        &out,
        &format!(
            "writ: outside ticket {id}: author email \"me@personal.example\" not allowed (the \
             author, like the committer, must be one of the lease's committer_emails)"
        ),
        Some("author"),
    );

    // The `Writ:` trailer: missing, another lease's, twice.
    let out = gw.git(
        &work,
        &["commit", "-q", "-S", "--allow-empty", "-m", "no trailer"],
    );
    assert_refused(
        &gw,
        &out,
        &format!("writ: repo demo needs a `Writ: {id}` trailer in the commit message"),
        Some("ticket_link"),
    );
    let other = "wrt_01JD8X0000000000000000000Z";
    let out = commit(&gw, "session", &work, other, &[]);
    assert_refused(
        &gw,
        &out,
        &format!("writ: the commit needs exactly one `Writ: {id}` trailer"),
        Some("ticket_link"),
    );
    // Written in the message: `--trailer` would fold two identical ones into one.
    let twice = format!("change\n\nWrit: {id}\nWrit: {id}\n");
    let out = gw.git(
        &work,
        &["commit", "-q", "-S", "--allow-empty", "-m", &twice],
    );
    assert_refused(
        &gw,
        &out,
        &format!("writ: the commit needs exactly one `Writ: {id}` trailer"),
        Some("ticket_link"),
    );

    // A tag: releases stay a human act.
    let out = gw.git(&work, &["tag", "-s", "v1", "-m", "release"]);
    assert_eq!(out.status.code(), Some(SIGNING_FAILED), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("writ: only commits are signed (no tags: releases stay a human act)"),
        "{}",
        stderr(&out)
    );
    let audit = fs::read_to_string(gw.root().join("audit.jsonl")).unwrap();
    assert_eq!(
        audit_events(&audit, "sign", "denied").last().unwrap()["code"],
        "object_type"
    );
    assert_eq!(gw.ledger(&lease).len(), 1, "only the allowed commit");
}

#[test]
fn paths_outside_the_ticket_are_refused_with_paths_check_deny() {
    let gw = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, STRICT);
    gw.seed_repo();
    let work = gw.clone("work");
    gw.wire_signing(&work);
    let lease = gw.session_with("paths", &in_repo("    expected_paths: [\"src/**\"]\n"));
    let id = lease.as_str();

    fs::create_dir_all(work.join("src/auth")).unwrap();
    fs::write(work.join("src/auth/login.rs"), "fn login() {}\n").unwrap();
    gw.git_ok(&work, &["add", "-A"]);
    let out = commit(&gw, "paths", &work, id, &[]);
    assert!(
        out.status.success(),
        "inside expected_paths: {}",
        stderr(&out)
    );

    fs::create_dir_all(work.join("docs")).unwrap();
    fs::write(work.join("docs/notes.md"), "notes\n").unwrap();
    fs::write(work.join("src/auth/login.rs"), "fn login() { todo!() }\n").unwrap();
    gw.git_ok(&work, &["add", "-A"]);
    let out = commit(&gw, "paths", &work, id, &[]);
    assert_refused(
        &gw,
        &out,
        &format!(
            "writ: outside ticket {id}: files outside expected_paths: docs/notes.md. If needed, \
             submit an amendment (ticket.amends: {id})"
        ),
        Some("paths"),
    );
    assert_eq!(gw.ledger(&lease).len(), 1);
}

/// `git mktree` in `work` (it writes the modes it is given, `40755` included).
fn mktree(gw: &GitGateway, work: &Path, listing: &str) -> String {
    use std::io::Write as _;
    let mut child = gw
        .git_command("false", work, &["mktree"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(listing.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "mktree {listing}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

#[test]
fn a_directory_with_a_non_standard_mode_cannot_hide_its_files() {
    // `*` covers `.github` but not `.github/evil.yml`: read as a file, the `40755` directory
    // would pass. git reads it as a directory (its type bits), and so would a checkout.
    for check in ["deny", "warn"] {
        let policy = STRICT.replace("paths_check: deny", &format!("paths_check: {check}"));
        let gw = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, &policy);
        gw.seed_repo();
        let work = gw.clone("work");
        gw.wire_signing(&work);
        let lease = gw.session_with("paths", &in_repo("    expected_paths: [\"*\"]\n"));
        let id = lease.as_str();
        let blob = gw.git_ok(&work, &["hash-object", "-w", "README"]);
        let inner = mktree(
            &gw,
            &work,
            &format!("100644 blob {}\tevil.yml\n", blob.trim()),
        );
        let readme = gw.git_ok(&work, &["rev-parse", "HEAD:README"]);
        let sign = |mode: &str| {
            let tree = mktree(
                &gw,
                &work,
                &format!(
                    "100644 blob {}\tREADME\n{mode} tree {inner}\t.github\n",
                    readme.trim()
                ),
            );
            let message = format!("change\n\nWrit: {id}\n");
            gw.git_as(
                "paths",
                &work,
                &["commit-tree", "-S", &tree, "-p", "HEAD", "-m", &message],
            )
        };

        let out = sign("40755");
        assert_eq!(
            out.status.code(),
            Some(COMMIT_TREE_FAILED),
            "{check}: {}",
            stderr(&out)
        );
        let reason = "cannot sign: a tree entry has a non-standard mode (git writes only \
                      100644, 100755, 120000, 40000 and 160000)";
        assert!(stderr(&out).contains(reason), "{check}: {}", stderr(&out));
        let audit = fs::read_to_string(gw.root().join("audit.jsonl")).unwrap();
        let denied = audit_events(&audit, "sign", "denied");
        assert_eq!(denied.len(), 1, "{check}: {denied:?}");
        assert_eq!(denied[0]["reason"], reason, "{check}");
        assert_eq!(denied[0]["lease"], id, "{check}");
        assert_eq!(denied[0]["repo"], "demo", "{check}");
        assert!(gw.ledger(&lease).is_empty(), "{check}");

        // The same directory as git writes it: its file is seen, outside `*`.
        let out = sign("40000");
        let audit = fs::read_to_string(gw.root().join("audit.jsonl")).unwrap();
        if check == "deny" {
            assert_eq!(
                out.status.code(),
                Some(COMMIT_TREE_FAILED),
                "{}",
                stderr(&out)
            );
            let reason = format!(
                "writ: outside ticket {id}: files outside expected_paths: .github/evil.yml. If \
                 needed, submit an amendment (ticket.amends: {id})"
            );
            assert!(stderr(&out).contains(&reason), "{}", stderr(&out));
            let denied = audit_events(&audit, "sign", "denied");
            assert_eq!(denied.len(), 2, "{denied:?}");
            assert_eq!(denied[1]["code"], "paths");
            assert!(gw.ledger(&lease).is_empty());
        } else {
            assert!(out.status.success(), "{check}: {}", stderr(&out));
            let signed = audit_events(&audit, "sign", "allowed");
            assert_eq!(signed.len(), 1, "{signed:?}");
            assert_eq!(
                signed[0]["warnings"],
                serde_json::json!(["files outside expected_paths: .github/evil.yml"])
            );
            assert_eq!(gw.ledger(&lease).len(), 1);
        }
    }
}

#[test]
fn signatures_stop_at_the_lease_s_count_and_rate() {
    let gw = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, STRICT);
    gw.seed_repo();
    let work = gw.clone("work");
    gw.wire_signing(&work);

    let few = gw.session_with("few", &in_repo("    limits:\n      max_signatures: 2\n"));
    for _ in 0..2 {
        let out = commit(&gw, "few", &work, few.as_str(), &[]);
        assert!(out.status.success(), "under the limit: {}", stderr(&out));
    }
    let out = commit(&gw, "few", &work, few.as_str(), &[]);
    assert_refused(
        &gw,
        &out,
        &format!("writ: lease {few}: all 2 signatures used"),
        Some("limit"),
    );

    // Two a minute: the third within the minute is refused (the test takes seconds; were it
    // to take a minute, the third would sign and the test fail, never pass by luck).
    let slow = gw.session_with("slow", &ticket("limits:\n  max_ops_per_minute: 2\n"));
    for _ in 0..2 {
        let out = commit(&gw, "slow", &work, slow.as_str(), &[]);
        assert!(out.status.success(), "under the rate: {}", stderr(&out));
    }
    let out = commit(&gw, "slow", &work, slow.as_str(), &[]);
    assert_refused(
        &gw,
        &out,
        &format!("writ: lease {slow}: over 2 operations per minute, retry shortly"),
        Some("rate"),
    );
    assert_eq!(gw.ledger(&few).len(), 2);
    assert_eq!(gw.ledger(&slow).len(), 2);
}

#[test]
fn no_lease_an_expired_or_a_revoked_one_says_why() {
    let gw = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gw.seed_repo();
    let work = gw.clone("work");
    gw.wire_signing(&work);
    let lease = gw.service.list(false).unwrap().tickets[0].id.clone();
    let as_key = |name: &str, lease: &TicketId| {
        let key = gw.root().join("keys").join(name);
        let trailer = format!("Writ: {lease}");
        gw.git_with(
            &gw.ssh_command(&key, true),
            &work,
            &[
                "commit",
                "-q",
                "-S",
                "--allow-empty",
                "-m",
                "x",
                "--trailer",
                &trailer,
            ],
        )
    };

    // No session at all.
    let out = as_key("none", &lease);
    let missing = gw.root().join("keys/none-cert.pub");
    assert_refused(
        &gw,
        &out,
        &format!(
            "writ-sign: cannot reach the daemon with this session: no lease: there is no \
             session certificate at {}",
            missing.display()
        ),
        None,
    );

    // A certificate past its end (its lease expired with it).
    gw.forged_session(&gw.ca, "expired", 0, now() - 10);
    let out = as_key("expired", &lease);
    assert_refused(
        &gw,
        &out,
        "writ-sign: cannot reach the daemon with this session: lease \
         wrt_01JD8X0000000000000000000 expired at",
        None,
    );

    // A revoked lease: the certificate is still valid in time, the daemon refuses it.
    let revoked = gw.session("revoked");
    assert!(
        as_key("revoked", &revoked).status.success(),
        "before the revocation"
    );
    gw.revoke(&revoked);
    let out = as_key("revoked", &revoked);
    assert_refused(
        &gw,
        &out,
        &format!(
            "writ-sign: cannot reach the daemon with this session: the daemon refused the \
             session certificate of lease {revoked}"
        ),
        None,
    );
}

#[test]
fn a_violation_revokes_a_lease_that_asks_for_it() {
    let gw = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, STRICT);
    gw.seed_repo();
    let work = gw.clone("work");
    gw.wire_signing(&work);
    let lease = gw.session_with("strict", &ticket("on_violation: revoke_lease\n"));
    let id = lease.as_str();

    // Running out of signatures is no violation; a wrong committer is one.
    let out = gw.git_as(
        "strict",
        &work,
        &[
            "-c",
            "user.email=me@personal.example",
            "commit",
            "-q",
            "-S",
            "--allow-empty",
            "-m",
            "x",
            "--trailer",
            &format!("Writ: {id}"),
        ],
    );
    assert_refused(
        &gw,
        &out,
        "committer email \"me@personal.example\" not allowed",
        Some("committer"),
    );
    let audit = fs::read_to_string(gw.root().join("audit.jsonl")).unwrap();
    let revoked = audit_events(&audit, "revoke", "done");
    assert_eq!(revoked.len(), 1, "{revoked:?}");
    assert_eq!(revoked[0]["lease"], id);
    assert!(
        revoked[0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("violation (committer): outside ticket"),
        "{}",
        revoked[0]
    );
    // The lease is over: even a good commit is refused now.
    let out = commit(&gw, "strict", &work, id, &[]);
    assert_refused(
        &gw,
        &out,
        "the daemon refused the session certificate",
        None,
    );
}

#[test]
fn a_revocation_completes_while_a_commit_is_being_signed() {
    // M3.5: the signer runs outside the service's lock. A real `git commit -S` whose
    // signature is held at the gate: the service answers and a revocation completes
    // meanwhile; the signature, when it comes, is discarded and no commit is written.
    let gw = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gw.seed_repo();
    let work = gw.clone("work");
    gw.wire_signing(&work);
    let lease = gw.session("held");
    let before = head(&gw, &work);
    let closed = gw.signer.close();
    std::thread::scope(|scope| {
        let committing = scope.spawn(|| commit(&gw, "held", &work, lease.as_str(), &[]));
        gw.signer.wait_entered();
        assert!(
            gw.service
                .list(false)
                .unwrap()
                .tickets
                .iter()
                .any(|t| t.id == lease),
            "the listing answers"
        );
        gw.revoke(&lease);
        assert_eq!(gw.service.show(&lease).unwrap().state, State::Revoked);
        // The revocation dropped the session at once: the agent learns the lease ended
        // without waiting for the device.
        let out = committing.join().unwrap();
        assert_refused(&gw, &out, "writ: the lease ended", None);
        closed.open();
    });
    // The call still in the daemon ends with its own refusal once the signer answers.
    let audit = gw.root().join("audit.jsonl");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let line = loop {
        let text = fs::read_to_string(&audit).unwrap();
        if let Some(line) = audit_events(&text, "sign", "denied").pop() {
            break line;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the held call never ended"
        );
        // poll: the call runs on after its session was dropped; only its audit line says it
        // ended. Bounded by `deadline`.
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert_eq!(line["code"], "not_active", "{line}");
    assert!(
        line["reason"]
            .as_str()
            .unwrap()
            .ends_with("(while the commit was being signed); the signature was discarded"),
        "{line}"
    );
    assert_eq!(head(&gw, &work), before, "no commit written");
    assert!(gw.ledger(&lease).is_empty(), "nothing in the ledger");
}

/// The harness's policy with `line` added to the repo `demo`.
fn with_repo_line(line: &str) -> String {
    let protected = "    protected_refs: [\"refs/heads/main\", \"refs/tags/*\"]\n";
    let policy = POLICY.replace(protected, &format!("{protected}    {line}\n"));
    assert_ne!(policy, POLICY, "the repo line was added");
    policy
}

#[test]
fn ticket_link_trailer_is_required_only_when_the_repo_asks() {
    let no_trailer = ["commit", "-q", "-S", "--allow-empty", "-m", "no trailer"];
    // No `ticket_link` (`ledger_only`, the default), and `ledger_only` written out: a commit
    // with no `Writ:` trailer is signed, and the ledger links it to its lease.
    for policy in [
        POLICY.to_owned(),
        with_repo_line("ticket_link: ledger_only"),
    ] {
        let gw = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, &policy);
        gw.seed_repo();
        let work = gw.clone("work");
        gw.wire_signing(&work);
        let out = gw.git(&work, &no_trailer);
        assert!(out.status.success(), "{}", stderr(&out));
        let id = head(&gw, &work);
        let message = gw.git_ok(&work, &["log", "-1", "--format=%B"]);
        assert!(!message.contains("Writ:"), "{message}");
        let ledger = gw.ledger(&gw.lease);
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].commit.as_str(), id);
        let out = gw.git(&work, &["verify-commit", "HEAD"]);
        assert!(out.status.success(), "{}", stderr(&out));
    }

    // `trailer`: the same commit is refused; with its trailer, signed.
    let gw = GitGateway::start_with(
        KeyKind::Ed25519,
        Listen::Tcp,
        &with_repo_line("ticket_link: trailer"),
    );
    gw.seed_repo();
    let work = gw.clone("work");
    gw.wire_signing(&work);
    let id = gw.lease.clone();
    let out = gw.git(&work, &no_trailer);
    assert_refused(
        &gw,
        &out,
        &format!("writ: repo demo needs a `Writ: {id}` trailer in the commit message"),
        Some("ticket_link"),
    );
    assert!(gw.ledger(&id).is_empty());
    let out = commit(&gw, "session", &work, id.as_str(), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let ledger = gw.ledger(&id);
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].commit.as_str(), head(&gw, &work));
}

#[test]
fn paths_check_off_signs_any_path_without_a_warning() {
    let paths = in_repo("    expected_paths: [\"src/**\"]\n");
    // The same commit, outside expected_paths, under `warn` then `off`.
    let mut warnings = Vec::new();
    for check in ["warn", "off"] {
        let policy = STRICT.replace("paths_check: deny", &format!("paths_check: {check}"));
        assert_ne!(policy, STRICT);
        let gw = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, &policy);
        gw.seed_repo();
        let work = gw.clone("work");
        gw.wire_signing(&work);
        let lease = gw.session_with("paths", &paths);
        fs::create_dir_all(work.join("docs")).unwrap();
        fs::write(work.join("docs/notes.md"), "notes\n").unwrap();
        gw.git_ok(&work, &["add", "-A"]);
        let out = commit(&gw, "paths", &work, lease.as_str(), &[]);
        assert!(out.status.success(), "{check}: {}", stderr(&out));
        let id = head(&gw, &work);
        let ledger = gw.ledger(&lease);
        assert_eq!(ledger.len(), 1, "{check}");
        assert_eq!(ledger[0].commit.as_str(), id);
        let audit = fs::read_to_string(gw.root().join("audit.jsonl")).unwrap();
        let signed = audit_events(&audit, "sign", "allowed");
        assert_eq!(signed.len(), 1, "{check}: {signed:?}");
        assert_eq!(signed[0]["commit"], id.as_str());
        warnings.push(signed[0].get("warnings").cloned());
    }
    assert_eq!(
        warnings,
        [
            Some(serde_json::json!([
                "files outside expected_paths: docs/notes.md"
            ])),
            None
        ],
        "warn records the paths, off doesn't look"
    );
}
