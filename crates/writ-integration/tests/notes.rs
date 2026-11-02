//! Notes (M4.7): a repo with `ticket_link: notes` takes commits without a trailer, and once a
//! push is upstream, the daemon writes each pushed commit's lease in a note under the repo's
//! `notes_ref` (`refs/notes/commits` by default, `refs/notes/writ` if it says so) and pushes it
//! upstream itself, the commits untouched. Two leases pushing
//! at once both get their notes; a notes ref upstream moved meanwhile is merged; a remote that
//! refuses the notes leaves the branch pushed, an audit line, and the notes written next time;
//! an agent never pushes a notes ref.

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
use std::time::Duration;

use writ_core::names::TicketId;
use writ_crypto::keys::KeyKind;
use writ_integration::gateway::{GitGateway, Listen, POLICY};
use writ_integration::stderr;

/// How long a notes job may take to show its line.
const NOTES_WITHIN: Duration = Duration::from_secs(60);

fn notes_policy() -> String {
    POLICY.replacen(
        "    protected_refs:",
        "    ticket_link: notes\n    protected_refs:",
        1,
    )
}

fn setup() -> (GitGateway, std::path::PathBuf) {
    let gateway = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, &notes_policy());
    gateway.seed_repo();
    let work = gateway.clone("work");
    (gateway, work)
}

/// Every allowed `notes` line's count, added up: how many notes reached upstream.
fn notes_pushed(gateway: &GitGateway) -> u64 {
    gateway
        .audited("notes", "allowed")
        .iter()
        .map(|line| line["count"].as_u64().unwrap())
        .sum()
}

/// Waits until `total` notes reached upstream (allowed `notes` lines), at most
/// [`NOTES_WITHIN`].
fn wait_for_notes(gateway: &GitGateway, total: u64) {
    let deadline = std::time::Instant::now() + NOTES_WITHIN;
    while notes_pushed(gateway) < total {
        assert!(
            std::time::Instant::now() < deadline,
            "{} notes pushed within {NOTES_WITHIN:?}, expected {total}",
            notes_pushed(gateway)
        );
        // poll: the notes job runs on its own after the push; only its audit line says it
        // ended. Bounded by `deadline`.
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(notes_pushed(gateway), total, "no note pushed twice");
}

fn write_hook(repo: &Path, script: &str) {
    use std::os::unix::fs::PermissionsExt;
    let hooks = repo.join("hooks");
    fs::create_dir_all(&hooks).unwrap();
    let path = hooks.join("pre-receive");
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn note_for(lease: &TicketId) -> String {
    format!("Writ: {lease}\n")
}

#[test]
fn a_push_leaves_a_note_per_commit_upstream_the_commits_untouched() {
    let (gateway, work) = setup();
    let first = gateway.commit_signed_plain("session", &work, "f", "1\n");
    let second = gateway.commit_signed_plain("session", &work, "g", "2\n");
    let message = gateway.git_ok(&work, &["log", "-1", "--format=%B"]);
    assert!(!message.contains("Writ:"), "no trailer: {message}");
    let objects: Vec<String> = [&first, &second]
        .iter()
        .map(|c| gateway.git_ok(&work, &["cat-file", "commit", c]))
        .collect();

    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    wait_for_notes(&gateway, 2);

    let lease = gateway.lease.clone();
    assert_eq!(gateway.upstream_note(&first), Some(note_for(&lease)));
    assert_eq!(gateway.upstream_note(&second), Some(note_for(&lease)));
    // The seed commit, pushed by nobody through the daemon, has none.
    let seed = gateway.upstream_ref("refs/heads/main").unwrap();
    assert_eq!(gateway.upstream_note(&seed), None);
    // Same ids, same bytes, signature included: the commits are as the agent made them.
    assert_eq!(
        gateway.upstream_ref("refs/heads/agent/x").as_deref(),
        Some(second.as_str())
    );
    let upstream = gateway.remote.repo("demo");
    for (commit, object) in [&first, &second].iter().zip(&objects) {
        assert_eq!(
            &gateway.git_ok(&upstream, &["cat-file", "commit", commit]),
            object
        );
        assert!(object.contains("gpgsig "), "{object}");
    }
    // One line for the lease: how many, with which credential, on which ref.
    let lines = gateway.audited("notes", "allowed");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["lease"], lease.as_str());
    assert_eq!(lines[0]["repo"], "demo");
    assert_eq!(lines[0]["key"], "upstream-01");
    assert_eq!(lines[0]["refs"][0], "refs/notes/commits");
    assert_eq!(lines[0]["count"], 2);
    // The mirror holds the notes upstream holds, and an agent can fetch them.
    assert_eq!(
        gateway.bare_ref("refs/notes/commits"),
        gateway.upstream_ref("refs/notes/commits")
    );
    assert_eq!(gateway.upstream_ref("refs/notes/writ"), None);
    gateway.git_ok(
        &work,
        &[
            "fetch",
            "-q",
            "origin",
            "refs/notes/commits:refs/notes/commits",
        ],
    );
    assert_eq!(
        gateway.git_ok(&work, &["notes", "show", &first]),
        note_for(&lease)
    );
    // git's own notes ref: a plain `git log` shows it.
    let log = gateway.git_ok(&work, &["log", "-1", &first]);
    assert!(log.contains(&format!("Notes:\n    Writ: {lease}")), "{log}");

    // A later push notes only its own commits.
    let third = gateway.commit_signed_plain("session", &work, "h", "3\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    wait_for_notes(&gateway, 3);
    assert_eq!(gateway.upstream_note(&third), Some(note_for(&lease)));
}

#[test]
fn a_repo_without_notes_gets_none() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    let work = gateway.clone("work");
    let head = gateway.commit_signed(&work, "f", "1\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    // The push's receive-pack has given the mirror back once the client has its answer: a
    // notes job would hold it now, so taking it means none runs.
    gateway
        .runtime
        .block_on(gateway.mirrors.lock(&"demo".parse().unwrap()))
        .unwrap();
    assert_eq!(gateway.upstream_ref("refs/notes/commits"), None);
    assert_eq!(gateway.upstream_ref("refs/notes/writ"), None);
    assert_eq!(gateway.upstream_note(&head), None);
    assert!(gateway.audited("notes", "allowed").is_empty());
    assert!(gateway.audited("notes", "denied").is_empty());
    // Its reconcile does nothing either.
    let pushes = gateway.remote.receive_packs();
    gateway
        .runtime
        .block_on(gateway.gateway.reconcile_notes(&"demo".parse().unwrap()));
    assert_eq!(gateway.remote.receive_packs(), pushes);
    assert_eq!(gateway.upstream_ref("refs/notes/commits"), None);
}

#[test]
fn leases_pushing_to_one_repo_at_once_all_get_their_notes() {
    let (gateway, _) = setup();
    const LEASES: usize = 4;
    const COMMITS: usize = 3;
    let agents: Vec<(String, TicketId, std::path::PathBuf)> = (0..LEASES)
        .map(|n| {
            let name = format!("agent{n}");
            let lease = gateway.session(&name);
            let work = gateway.clone(&format!("work{n}"));
            (name, lease, work)
        })
        .collect();
    let mut signed: Vec<(TicketId, String)> = Vec::new();
    for (name, lease, work) in &agents {
        for c in 0..COMMITS {
            let commit =
                gateway.commit_signed_plain(name, work, &format!("{name}-{c}"), &format!("{c}\n"));
            signed.push((lease.clone(), commit));
        }
    }
    // Every agent pushes its branch at the same moment.
    let barrier = std::sync::Barrier::new(LEASES);
    std::thread::scope(|scope| {
        for (name, _, work) in &agents {
            let (gateway, barrier) = (&gateway, &barrier);
            scope.spawn(move || {
                barrier.wait();
                let refspec = format!("HEAD:refs/heads/agent/{name}");
                let out = gateway.git_as(name, work, &["push", "-q", "origin", &refspec]);
                assert!(out.status.success(), "{name}: {}", stderr(&out));
            });
        }
    });
    wait_for_notes(&gateway, (LEASES * COMMITS) as u64);
    for (lease, commit) in &signed {
        assert_eq!(
            gateway.upstream_note(commit),
            Some(note_for(lease)),
            "{commit}"
        );
    }
    assert!(gateway.audited("notes", "denied").is_empty());
    // Each lease's lines add up to its own commits.
    for (_, lease, _) in &agents {
        let mine: u64 = gateway
            .audited("notes", "allowed")
            .iter()
            .filter(|l| l["lease"] == lease.as_str())
            .map(|l| l["count"].as_u64().unwrap())
            .sum();
        assert_eq!(mine, COMMITS as u64, "{lease}");
    }
}

#[test]
fn a_notes_ref_upstream_moved_meanwhile_is_merged_and_pushed_again() {
    let (gateway, work) = setup();
    let upstream = gateway.remote.repo("demo");
    let seed = gateway.upstream_ref("refs/heads/main").unwrap();
    // Someone else's notes, put upstream just before the daemon's push reaches it.
    let elsewhere = gateway.root().join("elsewhere");
    gateway.git_ok(
        gateway.root(),
        &[
            "clone",
            "-q",
            upstream.to_str().unwrap(),
            elsewhere.to_str().unwrap(),
        ],
    );
    gateway.git_ok(&elsewhere, &["notes", "add", "-m", "Theirs", &seed]);
    gateway.git_ok(
        &elsewhere,
        &[
            "push",
            "-q",
            "origin",
            "refs/notes/commits:refs/notes/theirs",
        ],
    );
    let theirs = gateway.git_ok(&upstream, &["rev-parse", "refs/notes/theirs"]);
    gateway
        .remote
        .before_next_push(&["update-ref", "refs/notes/commits", theirs.trim()]);

    let head = gateway.commit_signed_plain("session", &work, "f", "1\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    wait_for_notes(&gateway, 1);
    assert_eq!(gateway.upstream_note(&head), Some(note_for(&gateway.lease)));
    assert_eq!(gateway.upstream_note(&seed).as_deref(), Some("Theirs\n"));
    // Branch push, notes push refused, notes push again.
    assert_eq!(gateway.remote.receive_packs(), 3);
}

#[test]
fn a_remote_refusing_the_notes_leaves_the_branch_pushed_a_line_and_the_notes_for_next_time() {
    let (gateway, work) = setup();
    let upstream = gateway.remote.repo("demo");
    // The remote takes branches, not notes.
    write_hook(
        &upstream,
        "#!/bin/sh\nwhile read old new ref; do case \"$ref\" in refs/notes/*) \
         echo 'notes are not taken here' >&2; exit 1;; esac; done\nexit 0\n",
    );
    let first = gateway.commit_signed_plain("session", &work, "f", "1\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    assert_eq!(
        gateway.upstream_ref("refs/heads/agent/x").as_deref(),
        Some(first.as_str())
    );
    let denied = gateway.wait_for_audit("notes", "denied", 1, NOTES_WITHIN);
    assert_eq!(denied[0]["lease"], gateway.lease.as_str());
    assert_eq!(denied[0]["count"], 1);
    let reason = denied[0]["reason"].as_str().unwrap();
    assert!(
        reason.contains("upstream refused the push")
            && reason.contains("pre-receive hook declined")
            && reason.contains("notes are not taken here"),
        "{reason}"
    );
    assert_eq!(gateway.upstream_ref("refs/notes/commits"), None);
    assert!(gateway.audited("notes", "allowed").is_empty());

    // The remote takes notes again: the next push writes the missing note with its own.
    fs::remove_file(upstream.join("hooks/pre-receive")).unwrap();
    let second = gateway.commit_signed_plain("session", &work, "g", "2\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    wait_for_notes(&gateway, 2);
    assert_eq!(
        gateway.upstream_note(&first),
        Some(note_for(&gateway.lease))
    );
    assert_eq!(
        gateway.upstream_note(&second),
        Some(note_for(&gateway.lease))
    );
}

#[test]
fn an_agent_pushing_a_notes_ref_is_refused() {
    for policy in [notes_policy(), POLICY.to_owned()] {
        let gateway = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, &policy);
        gateway.seed_repo();
        let work = gateway.clone("work");
        let head = gateway.commit_signed_plain("session", &work, "f", "1\n");
        gateway.git_ok(&work, &["notes", "add", "-m", "Writ: wrt_forged", &head]);
        for (refspec, refused) in [
            (
                "refs/notes/commits:refs/notes/commits",
                "refs/notes/commits",
            ),
            ("refs/notes/commits:refs/notes/writ", "refs/notes/writ"),
        ] {
            let out = gateway.git(&work, &["push", "origin", refspec]);
            assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
            assert!(
                stderr(&out).contains(&format!("{refused} is not a branch")),
                "{}",
                stderr(&out)
            );
            let last = gateway.audited("push", "denied").pop().unwrap();
            assert_eq!(last["code"], "ref", "{last}");
            assert_eq!(gateway.bare_ref(refused), None);
            assert_eq!(gateway.upstream_ref(refused), None);
        }
    }
}

#[test]
fn notes_reach_an_https_upstream_with_its_token() {
    let gateway = GitGateway::start_https_with(&notes_policy());
    gateway.seed_repo();
    let work = gateway.clone("work");
    let head = gateway.commit_signed_plain("session", &work, "f", "1\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    wait_for_notes(&gateway, 1);
    assert_eq!(gateway.upstream_note(&head), Some(note_for(&gateway.lease)));
    // The branch and the notes, each one push over HTTPS.
    assert_eq!(gateway.https.as_ref().unwrap().receive_packs(), 2);
}

#[test]
fn notes_go_under_refs_notes_writ_when_the_repo_says_so() {
    let policy = notes_policy().replacen(
        "ticket_link: notes",
        "ticket_link: notes\n    notes_ref: writ",
        1,
    );
    let gateway = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, &policy);
    gateway.seed_repo();
    let work = gateway.clone("work");
    let head = gateway.commit_signed_plain("session", &work, "f", "1\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    wait_for_notes(&gateway, 1);
    assert_eq!(
        gateway.upstream_note_in("refs/notes/writ", &head),
        Some(note_for(&gateway.lease))
    );
    assert_eq!(gateway.upstream_note(&head), None);
    assert_eq!(gateway.upstream_ref("refs/notes/commits"), None);
    let line = gateway.audited("notes", "allowed").pop().unwrap();
    assert_eq!(line["refs"][0], "refs/notes/writ");
}

/// Forgets the note state of these commits in the ledger: what a daemon stopped between
/// upstream taking a push and recording its notes leaves, or a commit pushed before the repo
/// asked for notes.
fn forget_notes(gateway: &GitGateway, commits: &[&str]) {
    let db = rusqlite::Connection::open(gateway.root().join("leases.db")).unwrap();
    for commit in commits {
        let changed = db
            .execute(
                "UPDATE ledger SET note = NULL, note_credential = NULL WHERE commit_id = ?1",
                [commit],
            )
            .unwrap();
        assert_eq!(changed, 1, "{commit}");
    }
}

fn reconcile(gateway: &GitGateway) {
    gateway
        .runtime
        .block_on(gateway.gateway.reconcile_notes(&"demo".parse().unwrap()));
}

#[test]
fn commits_upstream_whose_notes_were_never_recorded_get_them_at_the_reconcile() {
    let (gateway, work) = setup();
    let upstream = gateway.remote.repo("demo");
    // Upstream takes the branch, not the notes: the push's own job leaves them waiting...
    write_hook(
        &upstream,
        "#!/bin/sh\nwhile read old new ref; do case \"$ref\" in refs/notes/*) exit 1;; esac; \
         done\nexit 0\n",
    );
    let first = gateway.commit_signed_plain("session", &work, "f", "1\n");
    let second = gateway.commit_signed_plain("session", &work, "g", "2\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    gateway.wait_for_audit("notes", "denied", 1, NOTES_WITHIN);
    fs::remove_file(upstream.join("hooks/pre-receive")).unwrap();
    // ...and the record of them is lost (a daemon stopped at the wrong moment, or commits
    // pushed before the repo asked for notes).
    forget_notes(&gateway, &[&first, &second]);
    // Signed, never pushed: upstream doesn't have it, it gets no note.
    let unpushed = gateway.commit_signed_plain("session", &work, "h", "3\n");

    reconcile(&gateway);
    assert_eq!(
        gateway.upstream_note(&first),
        Some(note_for(&gateway.lease))
    );
    assert_eq!(
        gateway.upstream_note(&second),
        Some(note_for(&gateway.lease))
    );
    assert_eq!(gateway.upstream_note(&unpushed), None);
    assert_eq!(notes_pushed(&gateway), 2);
    // Once written, a reconcile has nothing more to do.
    let pushes = gateway.remote.receive_packs();
    reconcile(&gateway);
    assert_eq!(gateway.remote.receive_packs(), pushes);
    assert_eq!(notes_pushed(&gateway), 2);
    // Pushed now, it is noted by its push's job.
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    wait_for_notes(&gateway, 3);
    assert_eq!(
        gateway.upstream_note(&unpushed),
        Some(note_for(&gateway.lease))
    );
}

#[test]
fn notes_left_waiting_go_at_the_reconcile_without_another_push() {
    let (gateway, work) = setup();
    let upstream = gateway.remote.repo("demo");
    write_hook(
        &upstream,
        "#!/bin/sh\nwhile read old new ref; do case \"$ref\" in refs/notes/*) exit 1;; esac; \
         done\nexit 0\n",
    );
    let head = gateway.commit_signed_plain("session", &work, "f", "1\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    gateway.wait_for_audit("notes", "denied", 1, NOTES_WITHIN);
    assert_eq!(gateway.upstream_note(&head), None);
    // Still refused: another denied line, still waiting.
    reconcile(&gateway);
    assert_eq!(gateway.audited("notes", "denied").len(), 2);
    assert_eq!(gateway.upstream_note(&head), None);
    // The remote takes notes again: the next reconcile writes it, no push needed.
    fs::remove_file(upstream.join("hooks/pre-receive")).unwrap();
    reconcile(&gateway);
    assert_eq!(gateway.upstream_note(&head), Some(note_for(&gateway.lease)));
    assert_eq!(notes_pushed(&gateway), 1);
}
