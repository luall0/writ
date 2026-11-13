//! M5's keys and tokens through admin changes, with the real binaries on a sealed keystore: a
//! signed policy naming a signing key and an upstream credential the keystore lacks makes
//! both (sealed, their public halves printed) and uses them at once, and after a restart; a
//! token added with `writ admin token` (encrypted by `writ`, never in clear on the daemon
//! host) reaches an HTTPS upstream at once, while an `https://` repo without its token is
//! refused with the command to run, the daemon unsealed all the same; a notifier's sealed
//! token starts its notifier when added.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use writ_integration::daemon::{Approvals, Daemon, ssh_options};
use writ_integration::https_remote::HttpsRemote;
use writ_integration::remote::PLACEHOLDER_UPSTREAM;
use writ_integration::telegram::TOKEN as BOT_TOKEN;
use writ_integration::{audit_events, stderr, stdout};

const POLICY: &str = r#"
keys:
  agent-01:
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
    protected_refs: ["refs/heads/main"]
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

/// The template a new policy adds, signing with a key the keystore lacks.
const OTHER: &str = r#"  other:
    operations: [fetch, commit_sign]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-02
    max_ttl: 1h
    max_signatures: 5
    max_pushes: 0
    max_ops_per_minute: 10
    max_push_size: 1MB
"#;

/// Every regular file under `dir` (sockets and links left out).
fn files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let kind = fs::symlink_metadata(&path).unwrap().file_type();
        if kind.is_dir() {
            found.extend(files(&path));
        } else if kind.is_file() {
            found.push(path);
        }
    }
    found
}

/// No file of the daemon (its state, keys, boot tier, configuration) holds `secret`.
fn nowhere_on_the_daemon_host(daemon: &Daemon, secret: &str) {
    let mut checked = files(&daemon.root().join("s"));
    checked.push(daemon.root().join("writd.yaml"));
    checked.push(daemon.root().join("writd.err"));
    for path in checked {
        let bytes = fs::read(&path).unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes).contains(secret),
            "{} holds the secret",
            path.display()
        );
    }
}

/// `writ admin apply policy <text> --yes`.
fn apply_policy(daemon: &Daemon, text: &str) -> Output {
    let file = daemon.root().join("new-policy.yaml");
    fs::write(&file, text).unwrap();
    daemon.run(
        &["admin", "apply", "policy", file.to_str().unwrap(), "--yes"],
        "",
    )
}

/// The public key `writ admin apply` printed for the new key `id`.
fn printed_key(out: &str, what: &str, id: &str) -> String {
    let prefix = format!("New {what} {id} (register it on the remote): ");
    out.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("no {what} {id} printed: {out}"))
        .to_owned()
}

#[test]
fn a_policy_naming_new_keys_creates_them_and_uses_them_at_once() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    let out = daemon.unseal();
    assert!(out.status.success(), "{}", stderr(&out));
    let shown = daemon.run(&["admin", "show", "policy"], "");
    let before = stdout(&shown);
    let demo_url = before
        .lines()
        .find_map(|l| l.trim().strip_prefix("upstream: "))
        .unwrap()
        .to_owned();
    assert_ne!(demo_url, PLACEHOLDER_UPSTREAM);
    // Two keys declared, neither in the keystore: a template signing with agent-02 (demo
    // allows it), a repo reached with upstream-02.
    let next = before
        .replace(
            "keys:\n",
            "keys:\n  agent-02:\n    use: signing\n    format: ssh\n    algorithm: ed25519\n  \
             upstream-02:\n    use: upstream\n    kind: ssh\n    algorithm: ed25519\n",
        )
        .replace(
            "    templates: [feature]\n",
            "    templates: [feature, other]\n",
        )
        .replace(
            "templates:\n",
            &format!(
                "  second:\n    upstream: {demo_url}\n    upstream_credential: upstream-02\n    \
                 templates: []\ntemplates:\n{OTHER}"
            ),
        );
    let out = apply_policy(&daemon, &next);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let said = stdout(&out);
    let signing = printed_key(&said, "signing key", "agent-02");
    let upstream = printed_key(&said, "upstream credential", "upstream-02");
    assert!(signing.starts_with("ssh-ed25519 "), "{signing}");
    assert!(
        !said.contains("New signing key agent-01") && !said.contains("upstream-01 (register"),
        "only the new keys are printed: {said}"
    );

    // In the keystore: sealed to the recipient, the public halves the ones printed.
    let keys = daemon.root().join("s/keys");
    for (dir, id, public) in [
        ("signing", "agent-02", &signing),
        ("upstream", "upstream-02", &upstream),
    ] {
        let sealed = fs::read(keys.join(dir).join(format!("{id}.age"))).unwrap();
        assert!(
            sealed.starts_with(b"age-encryption.org/v1\n-> X25519 "),
            "{id}"
        );
        assert!(!String::from_utf8_lossy(&sealed).contains("PRIVATE KEY"));
        let half = fs::read_to_string(keys.join(dir).join(format!("{id}.pub"))).unwrap();
        assert_eq!(half.trim(), public.as_str(), "{id}");
    }
    // In the `admin` line.
    let lines = audit_events(&daemon.audit(), "admin", "allowed");
    let reason = lines.last().unwrap()["reason"].as_str().unwrap().to_owned();
    assert!(
        reason.contains(&format!("; created signing key agent-02: {signing}")),
        "{reason}"
    );
    assert!(
        reason.contains(&format!(
            "; created upstream credential upstream-02: {upstream}"
        )),
        "{reason}"
    );

    // Used at once: a lease of the new template gets agent-02 for its commits.
    let ticket = "repos:\n  demo:\n    template: other\n    operations: [fetch, commit_sign]\n    \
                  branches: [\"agent/x\"]\nticket:\n  title: \"Other\"\n  task: Other\n\
                  limits:\n  ttl: 30m\n";
    let lease = daemon.lease("other", ticket);
    let granted = fs::read_to_string(daemon.session(&lease).join("signing_key.pub")).unwrap();
    assert_eq!(granted.trim(), signing);

    // The same policy again (another edit): nothing made twice, nothing printed.
    let again = next.replace("max_signatures: 5", "max_signatures: 4");
    let out = apply_policy(&daemon, &again);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!stdout(&out).contains("New "), "{}", stdout(&out));

    // After a restart, the unseal opens them from the keystore, matched to their halves.
    daemon.restart();
    let out = daemon.unseal();
    assert!(out.status.success(), "{}", stderr(&out));
    let listed = daemon.print("signing-keys");
    assert!(listed.contains(&signing), "{listed}");
    let lease = daemon.lease("other-again", ticket);
    let granted = fs::read_to_string(daemon.session(&lease).join("signing_key.pub")).unwrap();
    assert_eq!(granted.trim(), signing);
}

/// `git ls-remote` of `repo` through the gateway with a lease's session.
fn ls_remote(daemon: &Daemon, lease: &str, repo: &str) -> Output {
    let ssh = format!(
        "ssh {}",
        ssh_options(&daemon.root().join("known_hosts"), &daemon.session(lease)).join(" ")
    );
    Command::new("git")
        .args([
            "ls-remote",
            &format!("ssh://git@127.0.0.1:{}/{repo}.git", daemon.agents_port),
        ])
        .env("GIT_SSH_COMMAND", ssh)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", daemon.root().join("home"))
        .output()
        .unwrap()
}

/// `writ admin token <id> --yes`, the token on stdin.
fn add_token(daemon: &Daemon, id: &str, token: &str) -> Output {
    daemon.run(&["admin", "token", id, "--yes"], &format!("{token}\n"))
}

const HTTPS_TOKEN: &str = "writ-test-sealed-https-token-0123456789";

/// A bare repo `web` on an HTTPS test remote, with one commit on `main`.
fn web_remote(runtime: &tokio::runtime::Runtime, root: &Path) -> (HttpsRemote, String) {
    let remote = HttpsRemote::start(runtime, root, HTTPS_TOKEN);
    let git = |cwd: &Path, args: &[&str]| {
        let out = Command::new("git")
            .args(["-c", "user.name=Up", "-c", "user.email=up@example.com"])
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    git(root, &["init", "-q", "--bare", "web.git"]);
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    git(&seed, &["init", "-q", "-b", "main"]);
    git(&seed, &["commit", "-q", "--allow-empty", "-m", "first"]);
    git(
        &seed,
        &["push", "-q", root.join("web.git").to_str().unwrap(), "main"],
    );
    let main = git(&seed, &["rev-parse", "HEAD"]);
    (remote, main)
}

#[test]
fn a_token_added_from_the_mac_is_used_at_once_and_never_in_clear_on_disk() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let remote_dir = tempfile::tempdir().unwrap();
    let (remote, main) = web_remote(&runtime, remote_dir.path());
    let policy = POLICY
        .replace(
            "keys:\n",
            "keys:\n  token-01:\n    use: upstream\n    kind: token\n    host: 127.0.0.1\n",
        )
        .replace(
            "templates:\n  feature:",
            &format!(
                "  web:\n    upstream: {}\n    upstream_credential: token-01\n    \
                 templates: [feature]\ntemplates:\n  feature:",
                remote.url("web")
            ),
        );
    let ca = remote_dir.path().join("web-ca.pem");
    fs::write(&ca, &remote.ca_pem).unwrap();
    let mut daemon = Daemon::start_sealed_with(&policy, Approvals::Https, |yaml| {
        yaml.replace(
            "mirrors: { fresh_for: 0s }",
            &format!("mirrors: {{ fresh_for: 0s, ca_certs: {} }}", ca.display()),
        )
    });
    // No token yet: the unseal opens the daemon all the same.
    let out = daemon.unseal();
    assert!(out.status.success(), "{}", stderr(&out));
    daemon.wait_for_log("no token yet", writ_integration::WAIT_LIMIT);
    let ticket = "repos:\n  demo:\n    operations: [fetch]\n    branches: [\"agent/x\"]\n  \
                  web:\n    operations: [fetch]\n    branches: [\"agent/x\"]\nticket:\n  title: \"Web\"\n  task: Web\n\
                  limits:\n  ttl: 30m\n";
    let lease = daemon.lease("web", ticket);
    let out = ls_remote(&daemon, &lease, "web");
    assert_eq!(out.status.code(), Some(128), "{}", stdout(&out));
    // The agent is told no credential's id (the review after M7.6, M-5); the daemon's log and
    // the audit line name it, with the command that adds it.
    assert!(
        stderr(&out).contains(
            "repo web: the daemon has no usable credential for upstream (its log and audit line \
             say which, and why)"
        ) && !stderr(&out).contains("token-01"),
        "{}",
        stderr(&out)
    );
    assert!(
        daemon.audit().contains(
            "upstream credential token-01 has no token yet: an approver adds it with `writ \
             admin token token-01`"
        ),
        "the audit line names it"
    );
    // The other repo is not held up.
    let out = ls_remote(&daemon, &lease, "demo");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));

    // Added from the Mac: in force at once, on disk only sealed.
    let out = add_token(&daemon, "token-01", HTTPS_TOKEN);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let said = stdout(&out);
    assert!(said.contains("it replaces no token."), "{said}");
    assert!(
        said.contains("Token token-01 in force (file sha256 "),
        "{said}"
    );
    let out = ls_remote(&daemon, &lease, "web");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stdout(&out).contains(&format!("{main}\trefs/heads/main")),
        "{}",
        stdout(&out)
    );
    let file = daemon.root().join("s/keys/tokens/token-01.age");
    let sealed = fs::read(&file).unwrap();
    assert!(sealed.starts_with(b"age-encryption.org/v1\n-> X25519 "));
    nowhere_on_the_daemon_host(&daemon, HTTPS_TOKEN);
    let lines = audit_events(&daemon.audit(), "admin", "allowed");
    let reason = lines.last().unwrap()["reason"].as_str().unwrap().to_owned();
    assert!(
        reason.starts_with("token token-01: version 1 (sha256 "),
        "{reason}"
    );
    assert!(
        reason.ends_with(" replaces version 0 (no token)"),
        "{reason}"
    );

    // Rotated (to one upstream refuses): used at once, the file it replaces named.
    let digest = writ_core::authority::TextDigest::of_bytes(&sealed);
    let out = add_token(&daemon, "token-01", "writ-test-wrong-token-9876543210");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains(&format!("it replaces the token file sha256 {digest}.")),
        "{}",
        stdout(&out)
    );
    let out = ls_remote(&daemon, &lease, "web");
    assert_eq!(out.status.code(), Some(128), "{}", stdout(&out));
    let out = add_token(&daemon, "token-01", HTTPS_TOKEN);
    assert!(out.status.success(), "{}", stderr(&out));

    // An id the policy doesn't declare as a token, nor a notifier uses: refused, said,
    // nothing written.
    let out = add_token(&daemon, "token-02", HTTPS_TOKEN);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains(
            "token token-02: the policy in force declares no token token-02 (keys.token-02, \
             kind: token), and no notifier keeps it sealed"
        ),
        "{}",
        stderr(&out)
    );
    assert!(!daemon.root().join("s/keys/tokens/token-02.age").exists());

    // After a restart, the unseal opens it from the keystore.
    daemon.restart();
    let out = daemon.unseal();
    assert!(out.status.success(), "{}", stderr(&out));
    let lease = daemon.lease("web-again", ticket);
    let out = ls_remote(&daemon, &lease, "web");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    nowhere_on_the_daemon_host(&daemon, HTTPS_TOKEN);

    // The key taken out (its file deleted with it) and declared again (the review after
    // M7.6, A-6): its change count outlived the file and the restart, so the next change
    // names it, and the id's first change, `version 0`, can never apply again.
    let out = apply_policy(&daemon, POLICY);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert!(!file.exists(), "deleted with its key");
    let out = apply_policy(&daemon, &policy);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let out = add_token(&daemon, "token-01", HTTPS_TOKEN);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert!(
        stdout(&out).contains("it replaces no token."),
        "{}",
        stdout(&out)
    );
    let lines = audit_events(&daemon.audit(), "admin", "allowed");
    let reason = lines.last().unwrap()["reason"].as_str().unwrap().to_owned();
    assert!(
        reason.starts_with("token token-01: version 4 (sha256 ")
            && reason.ends_with(" replaces version 3 (no token)"),
        "{reason}"
    );
    drop(runtime);
}

#[test]
fn a_sealed_notifier_token_starts_its_notifier_when_added() {
    let daemon = Daemon::start_sealed_with(POLICY, Approvals::Ssh, |yaml| {
        yaml.replace(
            "token: { boot: telegram-token }",
            "token: { sealed: bot-01 }",
        )
    });
    let out = daemon.unseal();
    assert!(out.status.success(), "{}", stderr(&out));
    daemon.wait_for_log(
        "notifier not started: its token is not in the keystore",
        writ_integration::WAIT_LIMIT,
    );
    let out = add_token(&daemon, "bot-01", BOT_TOKEN);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert!(daemon.root().join("s/keys/tokens/bot-01.age").exists());
    // Started: the next ticket is notified, with the token added (the fake checks it).
    let request = daemon.request(
        "notified",
        "repos:\n  demo:\n    operations: [fetch]\n    branches: [\"agent/x\"]\n\
         ticket:\n  title: \"N\"\n  task: N\n",
    );
    let id = request.id.clone();
    let deadline = std::time::Instant::now() + writ_integration::WAIT_LIMIT;
    let mut count = 1;
    while !daemon
        .telegram
        .wait_for(count)
        .iter()
        .any(|message| message.contains(&id))
    {
        assert!(
            std::time::Instant::now() < deadline,
            "no notification for {id}"
        );
        count += 1;
    }
    nowhere_on_the_daemon_host(&daemon, BOT_TOKEN);
    drop(request);
}

#[test]
fn the_development_keystore_takes_no_token_from_the_mac() {
    let daemon = Daemon::start(POLICY, Approvals::Https);
    let out = add_token(&daemon, "upstream-01", HTTPS_TOKEN);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains(
            "the daemon serves no keystore recipient: its development keystore takes tokens \
             as files"
        ),
        "{}",
        stderr(&out)
    );
}

#[test]
fn every_declared_key_is_read_from_the_approver_s_machine_with_its_public_half_only() {
    // A token declared and used by no repo yet: the policy may hold it before its repo.
    let policy = POLICY.replace(
        "keys:\n",
        "keys:\n  token-01:\n    use: upstream\n    kind: token\n    host: 127.0.0.1\n",
    );
    let daemon = Daemon::start_sealed(&policy, Approvals::Https);
    // Sealed: refused, as every read is.
    let out = daemon.run(&["admin", "key", "list"], "");
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(stderr(&out).contains("daemon sealed"), "{}", stderr(&out));
    let out = daemon.unseal();
    assert!(out.status.success(), "{}", stderr(&out));

    let out = daemon.run(&["admin", "key", "list"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let listed = stdout(&out);
    // The upstream key: the public half `writd upstream-keys` prints, by its fingerprint.
    let printed = daemon.print("upstream-keys");
    let line = printed.lines().next().unwrap();
    let public = line
        .split(' ')
        .skip(1)
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let fingerprint = writ_crypto::ssh_key::PublicKey::from_openssh(&public)
        .unwrap()
        .fingerprint(writ_crypto::ssh_key::HashAlg::Sha256)
        .to_string();
    assert!(
        listed
            .lines()
            .any(|l| l == format!("upstream-01  upstream ssh ed25519  {fingerprint}  repos demo")),
        "{listed}"
    );
    assert!(
        listed
            .lines()
            .any(|l| l.starts_with("agent-01  signing ssh ed25519  SHA256:")
                && l.ends_with("  templates feature")),
        "{listed}"
    );
    assert!(
        listed.lines().any(|l| l
            == "token-01  upstream token for 127.0.0.1  not added yet (writ admin token)  unused"),
        "{listed}"
    );
    let out = daemon.run(&["admin", "key", "show", "upstream-01", "--public"], "");
    assert_eq!(stdout(&out).trim(), public);

    // Added: said, its value nowhere in what the read gives.
    let out = add_token(&daemon, "token-01", HTTPS_TOKEN);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = daemon.run(&["admin", "key", "show", "token-01"], "");
    let shown = stdout(&out);
    assert!(shown.contains("\ntoken: added\n"), "{shown}");
    assert!(!shown.contains(HTTPS_TOKEN));
    let out = daemon.run(&["admin", "key", "list"], "");
    assert!(!stdout(&out).contains(HTTPS_TOKEN));
}
