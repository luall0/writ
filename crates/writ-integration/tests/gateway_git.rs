//! The gateway with the real `git` and `ssh`: fetch and push through it, the pre-receive check
//! (and its audit lines), session certificates (only valid ones from a real lease get in), and
//! the same protocol over a Unix socket. Signing is in `signed_commits.rs`.

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
use std::process::Command;

use writ_crypto::ca::CertificateAuthority;
use writ_crypto::keys::{KeyKind, generate};
use writ_integration::gateway::{GitGateway, Listen, now};
use writ_integration::{audit_events, stderr};

#[test]
fn fetch_and_push_through_the_gateway() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    let work = gateway.clone("work");
    assert_eq!(fs::read_to_string(work.join("README")).unwrap(), "demo\n");
    let main_before = gateway.bare_ref("refs/heads/main");

    let head = gateway.commit_signed(&work, "feature", "x\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    assert_eq!(
        gateway.bare_ref("refs/heads/agent/x").as_deref(),
        Some(head.as_str())
    );

    // A protected ref: refused by the daemon through the pre-receive callback, with its
    // reason shown by git, and nothing lands.
    let out = gateway.git(&work, &["push", "origin", "HEAD:refs/heads/main"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("writ: refs/heads/main is protected"),
        "{}",
        stderr(&out)
    );
    assert_eq!(gateway.bare_ref("refs/heads/main"), main_before);

    gateway.git_ok(&work, &["tag", "v1"]);
    let out = gateway.git(&work, &["push", "origin", "refs/tags/v1"]);
    assert!(
        stderr(&out).contains("writ: refs/tags/v1 is protected"),
        "{}",
        stderr(&out)
    );
    assert_eq!(gateway.bare_ref("refs/tags/v1"), None);

    // Both refusals are in the audit log, written before git was answered.
    let audit = fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();
    let refused = audit_events(&audit, "push", "denied");
    assert_eq!(refused.len(), 2, "{refused:?}");
    assert_eq!(refused[0]["code"], "protected_ref");
    assert_eq!(
        refused[0]["reason"],
        "refs/heads/main is protected in repo demo"
    );
    assert_eq!(refused[0]["refs"][0], "refs/heads/main");
    assert_eq!(refused[0]["repo"], "demo");
    assert_eq!(
        refused[1]["reason"],
        "refs/tags/v1 is protected in repo demo"
    );
    // The accepted push has its one line too.
    let accepted = audit_events(&audit, "push", "allowed");
    assert_eq!(accepted.len(), 1, "{accepted:?}");
    assert_eq!(accepted[0]["refs"][0], "refs/heads/agent/x");

    // Fetch sees the pushed branch.
    let other = gateway.clone("other");
    gateway.git_ok(&other, &["fetch", "-q", "origin"]);
    let fetched = gateway.git_ok(&other, &["rev-parse", "origin/agent/x"]);
    assert_eq!(fetched.trim(), head);
}

#[test]
fn malformed_objects_never_land() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    let work = gateway.clone("work");
    // Tree entries git's fsck only warns about by default, refused here at error level: a
    // `.GIT` blob and a `.git` tree (git's own directory, the family of checkout CVEs), `.`
    // and `..`. Made with plumbing, which doesn't check.
    let blob = gateway.git_ok(&work, &["hash-object", "-w", "README"]);
    let blob = blob.trim();
    let inner = mktree(&gateway, &work, &format!("100644 blob {blob}\tconfig\n"));
    let mut trees: Vec<(String, String, &str)> = [
        (format!("100644 blob {blob}\t.GIT\n"), "hasDotgit"),
        (format!("040000 tree {inner}\t.git\n"), "hasDotgit"),
        (format!("040000 tree {inner}\t..\n"), "hasDotdot"),
        (format!("040000 tree {inner}\t.\n"), "hasDot"),
        // Modes git reads by their type bits but never writes: a directory `40755` (its
        // files hidden from a reader of the mode as written), a file `100664`.
        (format!("40755 tree {inner}\t.github\n"), "badFilemode"),
        (format!("100664 blob {blob}\tREADME\n"), "badFilemode"),
    ]
    .into_iter()
    .map(|(listing, check)| (mktree(&gateway, &work, &listing), listing, check))
    .collect();
    // A zero-padded directory mode (`mktree` would write `40000`): the bytes as they are.
    let mut padded = b"040000 .github\0".to_vec();
    padded.extend(
        (0..inner.len() / 2).map(|i| u8::from_str_radix(&inner[2 * i..2 * i + 2], 16).unwrap()),
    );
    let path = gateway.root().join("padded-tree");
    fs::write(&path, &padded).unwrap();
    let tree = gateway.git_ok(
        &work,
        &[
            "hash-object",
            "-t",
            "tree",
            "-w",
            "--literally",
            path.to_str().unwrap(),
        ],
    );
    trees.push((
        tree.trim().to_owned(),
        "040000 tree .github".to_owned(),
        "zeroPaddedFilemode",
    ));
    for (tree, listing, check) in &trees {
        let tree = tree.as_str();
        let commit = gateway.git_ok(&work, &["commit-tree", tree, "-p", "HEAD", "-m", "bad"]);
        let out = gateway.git(
            &work,
            &[
                "push",
                "origin",
                &format!("{}:refs/heads/agent/bad", commit.trim()),
            ],
        );
        assert_eq!(out.status.code(), Some(1), "{listing}: accepted");
        assert!(stderr(&out).contains(check), "{listing}: {}", stderr(&out));
        assert_eq!(
            gateway.bare_ref("refs/heads/agent/bad"),
            None,
            "{listing}: nothing landed"
        );
    }
    // Each refusal, made by git before the hook, is in the audit log.
    let audit = fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();
    let refused = audit_events(&audit, "push", "denied");
    assert_eq!(refused.len(), trees.len(), "{refused:?}");
    assert!(
        refused.iter().all(|e| e["reason"]
            .as_str()
            .unwrap()
            .starts_with("the push ended before its checks")),
        "{refused:?}"
    );
    // A good commit still goes through, on the same connection setup.
    gateway.commit_signed(&work, "feature", "x\n");
    gateway.git_ok(
        &work,
        &["push", "-q", "origin", "HEAD:refs/heads/agent/good"],
    );
}

#[test]
fn only_valid_session_certificates_get_in() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    let url = format!("{}/demo.git", gateway.url);
    let ls_remote = |key: &Path, with_cert: bool| {
        gateway.git_with(
            &gateway.ssh_command(key, with_cert),
            gateway.root(),
            &["ls-remote", &url],
        )
    };
    let key = |name: &str| gateway.root().join("keys").join(name);
    // Refused at authentication, and for nothing else (a host key ssh distrusts, a gateway
    // gone): git's 128 and ssh's own words for a key the server didn't take.
    let refused = |out: std::process::Output, what: &str| {
        assert_eq!(out.status.code(), Some(128), "{what}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("Permission denied (publickey)"),
            "{what}: {}",
            stderr(&out)
        );
    };

    assert!(ls_remote(&key("session"), true).status.success());

    let other_ca = CertificateAuthority::new(generate(KeyKind::Ed25519).unwrap());
    gateway.forged_session(&other_ca, "foreign", 0, now() + 3600);
    refused(ls_remote(&key("foreign"), true), "unknown CA");

    gateway.forged_session(&gateway.ca, "expired", 0, now() - 10);
    refused(ls_remote(&key("expired"), true), "expired");

    gateway.forged_session(&gateway.ca, "early", now() + 600, now() + 3600);
    refused(ls_remote(&key("early"), true), "not valid yet");

    // Our own CA, valid dates, but no lease behind it: refused.
    gateway.forged_session(&gateway.ca, "leaseless", 0, now() + 3600);
    refused(ls_remote(&key("leaseless"), true), "no lease");

    refused(ls_remote(&key("session"), false), "plain key");

    let lease = gateway.session("revoked");
    assert!(ls_remote(&key("revoked"), true).status.success());
    gateway.revoke(&lease);
    refused(ls_remote(&key("revoked"), true), "revoked");

    // Commands other than git and writ-sign are refused with a reason.
    let ssh = gateway.ssh_command(&key("session"), true);
    let host = gateway.url.trim_start_matches("ssh://");
    let (destination, port) = host.rsplit_once(':').unwrap();
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("{ssh} -p {port} {destination} id"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("writ: command not allowed"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn the_same_protocol_works_over_a_unix_socket() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Unix);
    gateway.seed_repo();
    let work = gateway.clone("work");
    gateway.commit_signed(&work, "f", "over a unix socket\n");
    gateway.git_ok(
        &work,
        &["push", "-q", "origin", "HEAD:refs/heads/agent/unix"],
    );
    assert!(gateway.bare_ref("refs/heads/agent/unix").is_some());
    let out = gateway.git(&work, &["push", "origin", "HEAD:refs/heads/main"]);
    assert!(
        stderr(&out).contains("writ: refs/heads/main is protected"),
        "{}",
        stderr(&out)
    );
}

/// A tree from `git mktree --missing` (plumbing: no check on the names).
fn mktree(gateway: &GitGateway, work: &Path, listing: &str) -> String {
    use std::io::Write as _;
    let mut child = Command::new("git")
        .args(["mktree", "--missing"])
        .current_dir(work)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", gateway.root().join("gitconfig"))
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
    assert!(out.status.success(), "mktree: {listing}");
    let tree = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    assert_eq!(tree.len(), 40, "mktree made the tree");
    tree
}

/// A lease that may push and sign, not fetch.
const NO_FETCH: &str = r#"
scope:
  repos: [demo]
  operations: [commit_sign, push]
  branches: ["agent/*"]
ticket:
  title: No fetch
  task: Push without fetching
"#;

/// A lease of two operations a minute.
const TWO_A_MINUTE: &str = r#"
scope:
  repos: [demo]
  operations: [fetch, commit_sign, push]
  branches: ["agent/*"]
ticket:
  title: Slow
  task: Fetch slowly
limits:
  max_ops_per_minute: 2
"#;

#[test]
fn a_fetch_goes_through_the_policy_and_counts_against_the_rate() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    let work = gateway.clone("work");
    let audit = || fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();

    // A lease without `fetch`: refused by the policy, with its code in the log.
    gateway.session_with("no-fetch", NO_FETCH);
    let out = gateway.git_as("no-fetch", &work, &["fetch", "origin"]);
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("fetch not allowed"),
        "{}",
        stderr(&out)
    );
    let denied = audit_events(&audit(), "fetch", "denied");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0]["code"], "operation");

    // Two operations a minute: two fetches pass, the third is refused for the rate.
    gateway.session_with("slow", TWO_A_MINUTE);
    for n in 0..2 {
        let out = gateway.git_as("slow", &work, &["fetch", "-q", "origin"]);
        assert!(out.status.success(), "fetch {n}: {}", stderr(&out));
    }
    let out = gateway.git_as("slow", &work, &["fetch", "origin"]);
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("over 2 operations per minute"),
        "{}",
        stderr(&out)
    );
    let denied = audit_events(&audit(), "fetch", "denied");
    assert_eq!(denied.len(), 2, "{denied:?}");
    assert_eq!(denied[1]["code"], "rate");
    // Every allowed fetch has its line: the clone, and the slow lease's two.
    assert_eq!(audit_events(&audit(), "fetch", "allowed").len(), 3);
}

#[test]
fn a_fetch_by_id_gets_only_what_refs_reach_whatever_the_protocol_asked() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    // Upstream: main one commit further, and a branch `gone`.
    let seed = gateway.root().join("seed");
    let bare = gateway.remote.repo("demo");
    let bare = bare.to_str().unwrap();
    let first = gateway
        .git_ok(&seed, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    gateway.git_ok(&seed, &["commit", "-q", "--allow-empty", "-m", "second"]);
    gateway.git_ok(&seed, &["checkout", "-q", "-b", "gone"]);
    gateway.git_ok(&seed, &["commit", "-q", "--allow-empty", "-m", "gone"]);
    let gone = gateway
        .git_ok(&seed, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    gateway.git_ok(&seed, &["push", "-q", bare, "main", "gone"]);
    // The mirror syncs both, then `gone` is deleted upstream: the next sync prunes the ref,
    // its commit stays in the mirror's objects, reached by no ref.
    let work = gateway.clone("work");
    assert_eq!(
        gateway.bare_ref("refs/heads/gone").as_deref(),
        Some(gone.as_str())
    );
    gateway.git_ok(&seed, &["push", "-q", bare, ":gone"]);
    gateway.git_ok(&work, &["fetch", "-q", "--prune", "origin"]);
    assert_eq!(gateway.bare_ref("refs/heads/gone"), None);
    gateway.git_ok(
        &gateway.root().join("repos/demo.git"),
        &["cat-file", "-e", &gone],
    );

    for version in ["2", "1", "0"] {
        let probe = gateway.root().join(format!("probe-v{version}"));
        gateway.git_ok(gateway.root(), &["init", "-q", probe.to_str().unwrap()]);
        let url = format!("{}/demo.git", gateway.url);
        let protocol = format!("protocol.version={version}");
        // A reachable commit that isn't a tip: served by its id.
        let out = gateway.git(&probe, &["-c", &protocol, "fetch", "-q", &url, &first]);
        assert!(out.status.success(), "v{version}: {}", stderr(&out));
        gateway.git_ok(&probe, &["cat-file", "-e", &first]);
        // The commit no ref reaches: refused, even when the client asks for protocol v2
        // (where git would serve any object it holds): the gateway's upload-pack speaks v0.
        let out = gateway.git(&probe, &["-c", &protocol, "fetch", "-q", &url, &gone]);
        assert_eq!(out.status.code(), Some(128), "v{version}: {}", stderr(&out));
        assert!(
            stderr(&out).contains(&format!("upload-pack: not our ref {gone}")),
            "v{version}: {}",
            stderr(&out)
        );
        let missing = gateway.git(&probe, &["cat-file", "-e", &gone]);
        assert_eq!(
            missing.status.code(),
            Some(1),
            "v{version}: the object never came"
        );
    }
    // Each fetch went through the policy: the clone, the pruning fetch, two per version.
    let audit = fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();
    assert_eq!(audit_events(&audit, "fetch", "allowed").len(), 8);
    assert!(audit_events(&audit, "fetch", "denied").is_empty());
}

#[test]
fn every_protocol_version_a_client_asks_for_works_served_in_v0() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    let seed = gateway.root().join("seed");
    let bare = gateway.remote.repo("demo");
    fs::write(seed.join("second.txt"), "second\n").unwrap();
    gateway.git_ok(&seed, &["add", "second.txt"]);
    gateway.git_ok(&seed, &["commit", "-q", "-m", "second"]);
    gateway.git_ok(&seed, &["push", "-q", bare.to_str().unwrap(), "main"]);
    let url = format!("{}/demo.git", gateway.url);
    let root = gateway.root();

    // Clones with git's default (it asks for v2) and each version asked: the same refs and
    // content.
    let mut listings = Vec::new();
    for (name, config) in [
        ("default", None),
        ("v2", Some("protocol.version=2")),
        ("v1", Some("protocol.version=1")),
        ("v0", Some("protocol.version=0")),
    ] {
        let dir = root.join(format!("clone-{name}"));
        let mut args = Vec::new();
        if let Some(config) = config {
            args.extend(["-c", config]);
        }
        args.extend(["clone", "-q", &url, dir.to_str().unwrap()]);
        gateway.git_ok(root, &args);
        assert_eq!(
            fs::read_to_string(dir.join("second.txt")).unwrap(),
            "second\n",
            "{name}"
        );
        listings.push(gateway.git_ok(
            &dir,
            &[
                "for-each-ref",
                "--format=%(refname) %(objectname)",
                "refs/remotes",
            ],
        ));
    }
    assert!(listings.iter().all(|l| l == &listings[0]), "{listings:?}");
    assert!(
        listings[0].contains("refs/remotes/origin/main"),
        "{listings:?}"
    );

    // ls-remote with v2 asked.
    let main = gateway.bare_ref("refs/heads/main").unwrap();
    let listed = gateway.git_ok(root, &["-c", "protocol.version=2", "ls-remote", &url]);
    assert!(
        listed.contains(&format!("{main}\trefs/heads/main")),
        "{listed}"
    );

    // A shallow clone, then deepened by one commit.
    let shallow = root.join("shallow");
    gateway.git_ok(
        root,
        &[
            "clone",
            "-q",
            "--depth",
            "1",
            &url,
            shallow.to_str().unwrap(),
        ],
    );
    let count = |dir: &std::path::Path| {
        gateway
            .git_ok(dir, &["rev-list", "--count", "HEAD"])
            .trim()
            .to_owned()
    };
    assert_eq!(count(&shallow), "1");
    gateway.git_ok(&shallow, &["fetch", "-q", "--deepen", "1", "origin"]);
    assert_eq!(count(&shallow), "2");

    // A partial clone: the gateway advertises no filter; git says so and clones it whole.
    let filtered = root.join("filtered");
    let out = gateway.git(
        root,
        &[
            "clone",
            "--filter=blob:none",
            &url,
            filtered.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("filtering not recognized by server"),
        "{}",
        stderr(&out)
    );
    let missing = gateway.git_ok(
        &filtered,
        &["rev-list", "--objects", "--missing=print", "--all"],
    );
    assert!(!missing.lines().any(|l| l.starts_with('?')), "{missing}");

    // A push right after a v2 fetch.
    let work = root.join("clone-default");
    gateway.git_ok(
        &work,
        &["-c", "protocol.version=2", "fetch", "-q", "origin"],
    );
    let head = gateway.commit_signed(&work, "mine.txt", "mine\n");
    gateway.git_ok(
        &work,
        &[
            "-c",
            "protocol.version=2",
            "push",
            "-q",
            "origin",
            "HEAD:refs/heads/agent/v2",
        ],
    );
    assert_eq!(
        gateway.bare_ref("refs/heads/agent/v2").as_deref(),
        Some(head.as_str())
    );
    assert_eq!(
        gateway.upstream_ref("refs/heads/agent/v2").as_deref(),
        Some(head.as_str())
    );
    let audit = fs::read_to_string(root.join("audit.jsonl")).unwrap();
    assert!(audit_events(&audit, "fetch", "denied").is_empty());
    assert_eq!(audit_events(&audit, "push", "allowed").len(), 1);
}

#[test]
fn a_fetch_is_refused_when_upstream_refuses_the_sync() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    // The remote stops taking the daemon's credential before the mirror's first sync.
    gateway
        .remote
        .authorize(generate(KeyKind::Ed25519).unwrap().public_key().clone());
    let work = gateway.root().join("work");
    let out = gateway.git(
        gateway.root(),
        &[
            "clone",
            &format!("{}/demo.git", gateway.url),
            work.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("writ: cannot sync from upstream: repo demo: sync failed"),
        "{}",
        stderr(&out)
    );
    let audit = fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();
    let denied = audit_events(&audit, "fetch", "denied");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert!(
        denied[0]["reason"]
            .as_str()
            .unwrap()
            .contains("Permission denied"),
        "{denied:?}"
    );
    assert_eq!(gateway.bare_ref("refs/heads/main"), None, "nothing synced");
}
