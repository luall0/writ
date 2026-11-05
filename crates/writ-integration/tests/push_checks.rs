//! Every push check of `gateway` mode with the real `git`, `ssh` and `writ-sign` (M4): each
//! refusal comes with a reason the agent can read and its code in the audit log, nothing moves
//! in the mirror (nor upstream), and the allowed push next to each refusal goes through.

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

use writ_crypto::keys::KeyKind;
use writ_integration::gateway::{GitGateway, Listen, POLICY};
use writ_integration::{audit_events, stderr};

/// A clone of the seeded repo, wired for signing.
fn setup() -> (GitGateway, std::path::PathBuf) {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    let work = gateway.clone("work");
    (gateway, work)
}

/// The push was refused before any ref moved: git's status, the reason the agent reads, the
/// audit line's code, and the ref absent from the mirror (or where it was).
fn assert_refused(gateway: &GitGateway, out: &Output, reason: &str, code: &str) {
    assert_eq!(out.status.code(), Some(1), "{reason}: {}", stderr(out));
    assert!(
        stderr(out).contains(reason),
        "expected {reason:?} in:\n{}",
        stderr(out)
    );
    let audit = fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();
    let denied = audit_events(&audit, "push", "denied");
    let last = denied.last().expect("a denied push line");
    assert_eq!(last["code"], code, "{last}");
}

fn push(gateway: &GitGateway, work: &Path, refspec: &str) -> Output {
    gateway.git(work, &["push", "origin", refspec])
}

#[test]
fn a_branch_outside_the_lease_is_refused() {
    let (gateway, work) = setup();
    gateway.commit_signed(&work, "f", "x\n");
    let out = push(&gateway, &work, "HEAD:refs/heads/feature/x");
    assert_refused(&gateway, &out, "branch feature/x not allowed", "ref");
    assert_eq!(gateway.bare_ref("refs/heads/feature/x"), None);
    // In the lease's branches: the same commit goes through.
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
}

#[test]
fn a_force_push_or_a_deletion_is_refused_without_force_push() {
    let (gateway, work) = setup();
    let first = gateway.commit_signed(&work, "f", "1\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    // Another history for the same branch.
    gateway.git_ok(&work, &["reset", "-q", "--hard", "HEAD~1"]);
    gateway.commit_signed(&work, "g", "2\n");
    let out = push(&gateway, &work, "+HEAD:refs/heads/agent/x");
    assert_refused(
        &gateway,
        &out,
        "force push to refs/heads/agent/x not allowed",
        "force_push",
    );
    let out = push(&gateway, &work, ":refs/heads/agent/x");
    assert_refused(
        &gateway,
        &out,
        "deleting refs/heads/agent/x needs force_push",
        "force_push",
    );
    assert_eq!(
        gateway.bare_ref("refs/heads/agent/x").as_deref(),
        Some(first.as_str())
    );
    // Moving forward from where it is: fine.
    gateway.git_ok(&work, &["reset", "-q", "--hard", &first]);
    gateway.commit_signed(&work, "h", "3\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
}

#[test]
fn a_commit_not_signed_under_this_lease_is_refused() {
    let (gateway, work) = setup();
    // Unsigned.
    fs::write(work.join("f"), "x\n").unwrap();
    gateway.git_ok(&work, &["add", "f"]);
    gateway.git_ok(&work, &["commit", "-q", "-m", "unsigned"]);
    let unsigned = gateway
        .git_ok(&work, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    let out = push(&gateway, &work, "HEAD:refs/heads/agent/x");
    assert_refused(
        &gateway,
        &out,
        &format!(
            "commit {unsigned} was not signed under this lease (or a lease it renews) for repo demo"
        ),
        "unsigned",
    );
    // An unsigned commit under a signed one: the signed commit is in the ledger, its parent
    // isn't, and it never reaches the mirror either.
    let signed = gateway.commit_signed(&work, "g", "y\n");
    let out = push(&gateway, &work, "HEAD:refs/heads/agent/x");
    assert_refused(
        &gateway,
        &out,
        &format!("commit {unsigned} was not signed under this lease"),
        "unsigned",
    );
    assert_eq!(gateway.bare_ref("refs/heads/agent/x"), None);
    let present = gateway.git(
        &gateway.root().join("repos/demo.git"),
        &["cat-file", "-e", &signed],
    );
    assert_eq!(
        present.status.code(),
        Some(1),
        "the refused objects never landed"
    );

    // Signed under another lease (its own session, its own trailer).
    gateway.git_ok(&work, &["reset", "-q", "--hard", "origin/main"]);
    let other = gateway.session("other");
    let theirs = gateway.commit_signed_as("other", &other, &work, "h", "z\n");
    let out = push(&gateway, &work, "HEAD:refs/heads/agent/x");
    assert_refused(
        &gateway,
        &out,
        &format!("commit {theirs} was not signed under this lease"),
        "unsigned",
    );
    // The other lease may push it.
    let out = gateway.git_as(
        "other",
        &work,
        &["push", "-q", "origin", "HEAD:refs/heads/agent/y"],
    );
    assert!(out.status.success(), "{}", stderr(&out));
}

/// A lease whose pushes are at most 2 KB.
const SMALL_PUSHES: &str = r#"
repos:
  demo:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    limits:
      max_push_size: 2KB
ticket:
  title: Small pushes
  task: Push little
"#;

/// The review after M5.5 (S7): git was handed the lease's `max_push_size`, not the smaller of
/// the lease's and the template's in force, so after a signed change lowered the template git
/// took in a pack the policy refuses; and a ticket asking 0, which git reads as no limit, was
/// accepted.
#[test]
fn git_takes_in_no_more_than_the_template_in_force_allows() {
    use writ_approval::AdminParsed;
    use writ_core::authority::{AdminTarget, AdminText};
    use writ_core::canonical::Canonical;
    use writ_core::config::PolicyConfig;
    use writ_core::signed::{Admin, Replaced};
    let (gateway, work) = setup();
    // 0, which git reads as no limit: rejected at submission.
    let zero = SMALL_PUSHES.replace("max_push_size: 2KB", "max_push_size: 0");
    let key = writ_crypto::keys::generate(writ_crypto::keys::KeyKind::Ed25519).unwrap();
    let error = gateway
        .service
        .submit(
            key.public_key(),
            zero.as_bytes(),
            &writ_core::caller::CallerFacts::default(),
        )
        .unwrap_err();
    assert!(
        matches!(
            &error,
            writ_approval::ServiceError::Refused {
                code: writ_approval::RefusalCode::Rejected,
                reasons,
                ..
            } if reasons.as_slice() == [
                "repos.demo fits no template: spike: limits.max_push_size must be at least 1 byte"
            ]
        ),
        "{error:?}"
    );

    // A lease of 1MB; then the template lowered to 2KB by a signed change.
    let lease = gateway.session_with(
        "wide",
        &SMALL_PUSHES.replace("max_push_size: 2KB", "max_push_size: 1MB"),
    );
    // Committed (and signed) while the lease still fits its template.
    let mut random = vec![0u8; 20_000];
    std::io::Read::read_exact(&mut fs::File::open("/dev/urandom").unwrap(), &mut random).unwrap();
    let content = random
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    gateway.commit_signed_as("wide", &lease, &work, "big", &content);
    let shown = gateway.service.admin_show(AdminTarget::Policy).unwrap();
    let lowered = shown
        .text
        .replace("max_push_size: 50MB", "max_push_size: 2KB");
    assert_ne!(lowered, shown.text, "the fixture changed");
    let document = Admin::new(
        shown.daemon.clone(),
        AdminTarget::Policy,
        Replaced {
            version: shown.version,
            digest: shown.digest.clone(),
        },
        AdminText::try_from(lowered.clone()).unwrap(),
    )
    .canonical_bytes()
    .unwrap();
    let request = writ_proto::AdminRequest {
        signature: writ_crypto::sshsig::sign(
            &gateway.approver,
            writ_core::lease::APPROVAL_NAMESPACE,
            &document,
        )
        .unwrap(),
        document: String::from_utf8(document).unwrap(),
    };
    let facts = writ_core::caller::CallerFacts::default();
    let checked = gateway.service.check_admin(&request, &facts).unwrap();
    gateway
        .service
        .commit_admin(
            &checked,
            AdminParsed::Policy(PolicyConfig::from_yaml(&lowered).unwrap()),
            vec![],
            Default::default(),
            &facts,
        )
        .unwrap();

    // The pack, about 40KB, under the lease's 1MB and over the template's 2KB, now: signing
    // refuses a lease that no longer fits, the push is checked for its operation and repo
    // only, then decided whole at the hook. git refuses it first, from the template's bound,
    // so the daemon never takes in a pack the policy would refuse.
    let out = gateway.git_as(
        "wide",
        &work,
        &["push", "origin", "HEAD:refs/heads/agent/big"],
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("pack exceeds maximum allowed size"),
        "{}",
        stderr(&out)
    );
    assert_eq!(gateway.bare_ref("refs/heads/agent/big"), None);
}

#[test]
fn a_pack_over_max_push_size_is_refused() {
    let (gateway, work) = setup();
    let lease = gateway.session_with("small", SMALL_PUSHES);
    let mut random = vec![0u8; 20_000];
    std::io::Read::read_exact(&mut fs::File::open("/dev/urandom").unwrap(), &mut random).unwrap();
    let content = random
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    gateway.commit_signed_as("small", &lease, &work, "big", &content);
    let out = gateway.git_as(
        "small",
        &work,
        &["push", "origin", "HEAD:refs/heads/agent/big"],
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    // git refuses it first (receive.maxInputSize: the lease's, under the template's), before
    // the hook.
    assert!(
        stderr(&out).contains("pack exceeds maximum allowed size"),
        "{}",
        stderr(&out)
    );
    assert_eq!(gateway.bare_ref("refs/heads/agent/big"), None);
    // Refused by git, still in the audit log.
    let audit = fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();
    let denied = audit_events(&audit, "push", "denied");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert!(
        denied[0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("the push ended before its checks"),
        "{denied:?}"
    );
    // A small one under the same lease goes through.
    gateway.git_ok(&work, &["reset", "-q", "--hard", "origin/main"]);
    gateway.commit_signed_as("small", &lease, &work, "small", "x\n");
    let out = gateway.git_as(
        "small",
        &work,
        &["push", "-q", "origin", "HEAD:refs/heads/agent/small"],
    );
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn a_ref_that_differs_only_in_case_from_one_the_repo_has_is_refused() {
    let (gateway, work) = setup();
    gateway.commit_signed(&work, "f", "x\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    gateway.commit_signed(&work, "g", "y\n");
    let out = push(&gateway, &work, "HEAD:refs/heads/agent/X");
    assert_refused(
        &gateway,
        &out,
        "refs/heads/agent/X differs only in case from a ref the repo has",
        "invalid",
    );
    assert_eq!(gateway.bare_ref("refs/heads/agent/X"), None);
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/z"]);
}

#[test]
fn a_commit_whose_paths_changed_since_signing_is_refused() {
    let (gateway, work) = setup();
    let commit = gateway.commit_signed(&work, "f", "x\n");
    // What signing saw, as the ledger keeps it: replaced by the digest of other paths, as if
    // the objects pushed weren't the ones the daemon checked (a SHA-1 collision would do it).
    let db = rusqlite::Connection::open(gateway.root().join("leases.db")).unwrap();
    let changed = db
        .execute(
            "UPDATE ledger SET paths_digest = ?1 WHERE commit_id = ?2",
            rusqlite::params![writ_git_digest(&["other"]), commit],
        )
        .unwrap();
    assert_eq!(changed, 1, "the fixture edited the ledger");
    let out = push(&gateway, &work, "HEAD:refs/heads/agent/x");
    assert_refused(
        &gateway,
        &out,
        &format!(
            "commit {commit}: the paths it touches are not the ones checked when it was signed"
        ),
        "paths_changed",
    );
    assert_eq!(gateway.bare_ref("refs/heads/agent/x"), None);
    // With the digest signing computed, the same push goes through: the check compares what
    // it should, not anything.
    db.execute(
        "UPDATE ledger SET paths_digest = ?1 WHERE commit_id = ?2",
        rusqlite::params![writ_git_digest(&["f"]), commit],
    )
    .unwrap();
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
}

/// `writ_git::paths::digest`, for the fixture.
fn writ_git_digest(paths: &[&str]) -> String {
    let owned: Vec<String> = paths.iter().map(|p| (*p).to_owned()).collect();
    writ_git::paths::digest(&owned)
}

#[test]
fn a_push_is_refused_when_its_hook_is_missing() {
    // Without its pre-receive hook git would take a push with no check at all: the gateway
    // refuses to run receive-pack then, whatever removed the hook.
    let (gateway, work) = setup();
    gateway.commit_signed(&work, "f", "x\n");
    let hook = gateway.root().join("run/hooks/pre-receive");
    let saved = fs::read(&hook).unwrap();
    fs::remove_file(&hook).unwrap();
    let out = push(&gateway, &work, "HEAD:refs/heads/agent/x");
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("writ: internal error: the push hook is missing"),
        "{}",
        stderr(&out)
    );
    assert_eq!(gateway.bare_ref("refs/heads/agent/x"), None);
    assert_eq!(gateway.upstream_ref("refs/heads/agent/x"), None);
    // The hook back: the same push goes through.
    fs::write(&hook, saved).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
    }
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
}

/// The harness's policy with `repo` added to the repo `demo` and `template` to the template.
fn push_modes_policy(repo: &str, template: &str) -> String {
    let protected = "    protected_refs: [\"refs/heads/main\", \"refs/tags/*\"]\n";
    let size = "    max_push_size: 50MB\n";
    let policy = POLICY
        .replace(protected, &format!("{protected}{repo}"))
        .replace(size, &format!("{size}{template}"));
    assert_eq!(
        policy.len(),
        POLICY.len() + repo.len() + template.len(),
        "both lines added"
    );
    policy
}

#[test]
fn push_modes_without_gateway_refuse_a_gateway_push() {
    for (repo, template) in [
        // The registry has no gateway mode for the repo.
        ("    push_modes: [proxy]\n", "    push_modes: [proxy]\n"),
        (
            "    push_modes: [direct_ssh]\n    \
             direct_ssh: { hosts: [github.com], allow_account_wide: false }\n",
            "    push_modes: [direct_ssh]\n",
        ),
        // The registry has it, the template doesn't.
        (
            "    push_modes: [gateway, proxy]\n",
            "    push_modes: [proxy]\n",
        ),
    ] {
        let gateway = GitGateway::start_with(
            KeyKind::Ed25519,
            Listen::Tcp,
            &push_modes_policy(repo, template),
        );
        gateway.seed_repo();
        let work = gateway.clone("work");
        gateway.commit_signed(&work, "f", "x\n");
        let out = push(&gateway, &work, "HEAD:refs/heads/agent/x");
        assert_refused(
            &gateway,
            &out,
            &format!(
                "writ: outside ticket {}: push mode gateway not allowed for repo demo",
                gateway.lease
            ),
            "push_mode",
        );
        assert_eq!(
            gateway.bare_ref("refs/heads/agent/x"),
            None,
            "{repo}{template}"
        );
        assert_eq!(gateway.upstream_ref("refs/heads/agent/x"), None);
    }
    // Both with gateway: the same push goes through.
    let gateway = GitGateway::start_with(
        KeyKind::Ed25519,
        Listen::Tcp,
        &push_modes_policy(
            "    push_modes: [gateway, proxy]\n",
            "    push_modes: [gateway, proxy]\n",
        ),
    );
    gateway.seed_repo();
    let work = gateway.clone("work");
    let id = gateway.commit_signed(&work, "f", "x\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    assert_eq!(gateway.upstream_ref("refs/heads/agent/x"), Some(id));
}

/// The review after M5.5 (L10): the gateway checked the hook was a file, not that git could run
/// it; git skips a hook it can't execute without a word, and would take a push with no
/// decision. One the daemon's user can't run refuses every push, logged.
#[test]
fn a_hook_git_cannot_run_refuses_every_push() {
    use std::os::unix::fs::PermissionsExt;
    let (gateway, work) = setup();
    let lease = gateway.session("agent");
    let hook = gateway.root().join("run/hooks/pre-receive");
    let mode = fs::metadata(&hook).unwrap().permissions().mode();
    assert_ne!(mode & 0o100, 0, "the hook the gateway wrote runs");
    fs::set_permissions(&hook, fs::Permissions::from_mode(mode & !0o111)).unwrap();
    gateway.commit_signed_as("agent", &lease, &work, "a", "a\n");
    let out = gateway.git_as(
        "agent",
        &work,
        &["push", "origin", "HEAD:refs/heads/agent/a"],
    );
    assert_ne!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("internal error: the push hook is missing or can't be run"),
        "{}",
        stderr(&out)
    );
    assert_eq!(gateway.bare_ref("refs/heads/agent/a"), None);
    let audit = fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();
    let denied = audit_events(&audit, "push", "denied");
    assert!(
        denied.iter().any(|e| e["reason"]
            .as_str()
            .is_some_and(|r| r.contains("the push hook is missing or can't be run"))),
        "{denied:?}"
    );
    // Runnable again: the push goes through.
    fs::set_permissions(&hook, fs::Permissions::from_mode(mode)).unwrap();
    let out = gateway.git_as(
        "agent",
        &work,
        &["push", "-q", "origin", "HEAD:refs/heads/agent/a"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}
