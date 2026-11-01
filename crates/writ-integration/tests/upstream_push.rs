//! Pushes reaching upstream through the daemon (M4): the remote gets what the agent pushed
//! and nothing else, with the daemon's credential (the agent host holds none); a ref upstream
//! moved, or a push the remote refuses, comes back to the agent with the remote's reason, and
//! the mirror never holds a ref the remote didn't take.

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

use writ_crypto::keys::KeyKind;
use writ_integration::gateway::{GitGateway, Listen};
use writ_integration::{audit_events, stderr};

fn setup() -> (GitGateway, std::path::PathBuf) {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    let work = gateway.clone("work");
    (gateway, work)
}

/// A commit on upstream's `branch`, made without the daemon (someone else pushing).
fn upstream_commit(gateway: &GitGateway, branch: &str, file: &str) -> String {
    let other = gateway.root().join("elsewhere");
    if !other.exists() {
        gateway.git_ok(
            gateway.root(),
            &[
                "clone",
                "-q",
                gateway.remote.repo("demo").to_str().unwrap(),
                other.to_str().unwrap(),
            ],
        );
    }
    gateway.git_ok(&other, &["fetch", "-q", "origin"]);
    let start = format!("origin/{branch}");
    gateway.git_ok(&other, &["checkout", "-q", "-B", branch, &start]);
    fs::write(other.join(file), "upstream\n").unwrap();
    gateway.git_ok(&other, &["add", file]);
    gateway.git_ok(&other, &["commit", "-q", "-m", file]);
    gateway.git_ok(
        &other,
        &["push", "-q", "origin", &format!("HEAD:refs/heads/{branch}")],
    );
    gateway
        .git_ok(&other, &["rev-parse", "HEAD"])
        .trim()
        .to_owned()
}

#[test]
fn a_push_reaches_upstream_with_the_daemon_s_credential_only() {
    let (gateway, work) = setup();
    let head = gateway.commit_signed(&work, "f", "x\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    assert_eq!(
        gateway.upstream_ref("refs/heads/agent/x").as_deref(),
        Some(head.as_str())
    );
    assert_eq!(
        gateway.bare_ref("refs/heads/agent/x").as_deref(),
        Some(head.as_str())
    );
    assert_eq!(gateway.remote.receive_packs(), 1);
    // The signed commit is upstream as the daemon signed it: the ledger's id.
    let ledger: Vec<String> = gateway
        .ledger(&gateway.lease)
        .iter()
        .map(|e| e.commit.as_str().to_owned())
        .collect();
    assert_eq!(ledger, std::slice::from_ref(&head));

    // The agent host's keys reach the daemon, never the remote.
    let direct = gateway.git(
        &work,
        &[
            "push",
            &format!("ssh://git@127.0.0.1:{}/demo.git", gateway.remote.port),
            "HEAD:refs/heads/agent/direct",
        ],
    );
    assert_eq!(direct.status.code(), Some(128), "{}", stderr(&direct));
    assert_eq!(gateway.upstream_ref("refs/heads/agent/direct"), None);
    // Nothing on the agent host's disk but its session (the harness's keys directory).
    let keys: Vec<String> = fs::read_dir(gateway.root().join("keys"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(keys.iter().all(|k| k.starts_with("session")), "{keys:?}");
}

#[test]
fn upstream_moved_the_push_is_refused_then_fetch_rebase_re_sign_and_push_again() {
    let (gateway, work) = setup();
    let first = gateway.commit_signed(&work, "f", "1\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);

    // Upstream moves while the next push is on its way (after the daemon's sync): the remote
    // has another commit on the branch by the time the daemon pushes.
    let moved = upstream_commit(&gateway, "agent/x", "theirs");
    gateway.git_ok(
        &gateway.remote.repo("demo"),
        &["update-ref", "refs/heads/agent/x", &first],
    );
    gateway
        .remote
        .before_next_push(&["update-ref", "refs/heads/agent/x", &moved]);
    let second = gateway.commit_signed(&work, "g", "2\n");
    let out = gateway.git(&work, &["push", "origin", "HEAD:refs/heads/agent/x"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("writ: repo demo: upstream refused the push")
            && stderr(&out).contains("stale info"),
        "{}",
        stderr(&out)
    );
    // Nothing of it in the mirror; upstream keeps its own.
    assert_eq!(
        gateway.bare_ref("refs/heads/agent/x").as_deref(),
        Some(first.as_str())
    );
    assert_eq!(
        gateway.upstream_ref("refs/heads/agent/x").as_deref(),
        Some(moved.as_str())
    );
    let present = gateway.git(
        &gateway.root().join("repos/demo.git"),
        &["cat-file", "-e", &second],
    );
    assert_eq!(
        present.status.code(),
        Some(1),
        "the refused objects never landed"
    );
    let audit = fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();
    let denied = audit_events(&audit, "push", "denied");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert!(
        denied[0]["reason"]
            .as_str()
            .unwrap()
            .contains("upstream refused the push"),
        "{denied:?}"
    );

    // The agent's way out: fetch through the daemon, rebase (re-signed), push again.
    gateway.git_ok(&work, &["fetch", "-q", "origin"]);
    let trailer = format!("Writ: {}", gateway.lease);
    gateway.git_ok(&work, &["rebase", "-q", "origin/agent/x"]);
    // The rebased commit is a new one: signed again through writ-sign.
    gateway.git_ok(
        &work,
        &[
            "commit",
            "-q",
            "-S",
            "--amend",
            "--no-edit",
            "--trailer",
            &trailer,
        ],
    );
    let rebased = gateway
        .git_ok(&work, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    assert_eq!(
        gateway.upstream_ref("refs/heads/agent/x").as_deref(),
        Some(rebased.as_str())
    );
    assert_eq!(
        gateway.bare_ref("refs/heads/agent/x").as_deref(),
        Some(rebased.as_str())
    );
}

#[test]
fn the_remote_s_refusal_reaches_the_agent_and_never_the_mirror() {
    let (gateway, work) = setup();
    write_hook(
        &gateway.remote.repo("demo"),
        "#!/bin/sh\necho 'branch agent/no is closed on the remote' >&2\nexit 1\n",
    );
    gateway.commit_signed(&work, "f", "x\n");
    let out = gateway.git(&work, &["push", "origin", "HEAD:refs/heads/agent/no"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("upstream refused the push")
            && stderr(&out).contains("branch agent/no is closed on the remote"),
        "{}",
        stderr(&out)
    );
    assert_eq!(gateway.bare_ref("refs/heads/agent/no"), None);
    assert_eq!(gateway.upstream_ref("refs/heads/agent/no"), None);
    // Escapes from the remote never reach the agent's terminal raw.
    write_hook(
        &gateway.remote.repo("demo"),
        "#!/bin/sh\nprintf 'evil \\033[31mred\\033]0;title\\007\\n' >&2\nexit 1\n",
    );
    let out = gateway.git(&work, &["push", "origin", "HEAD:refs/heads/agent/no"]);
    assert_eq!(out.status.code(), Some(1));
    let shown = stderr(&out);
    let ours = shown
        .lines()
        .find(|l| l.contains("writ: repo demo: upstream refused the push"))
        .expect("the daemon's refusal line");
    assert!(
        !ours.contains('\u{1b}') && !ours.contains('\u{7}'),
        "{ours:?}"
    );
    // With the remote's hook gone, the same push goes through.
    fs::remove_file(gateway.remote.repo("demo").join("hooks/pre-receive")).unwrap();
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/no"]);
}

fn write_hook(repo: &Path, script: &str) {
    use std::os::unix::fs::PermissionsExt;
    let hooks = repo.join("hooks");
    fs::create_dir_all(&hooks).unwrap();
    let path = hooks.join("pre-receive");
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}
