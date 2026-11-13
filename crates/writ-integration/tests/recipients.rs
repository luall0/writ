//! The keystore's recipients (M7.6, `recipients` in the policy) with the real `writd` and
//! `writ`: the recovery key made and checked from the approver's machine, declared live on a
//! passphrase keystore (its identity wrapped to it too, a challenge it opens, kept across a
//! restart, replaced, removed); on the Mac, against the fake `writ-se`, a hardware recipient
//! taking the keystore live (the identity and the token rewrapped to it, the token unwrapped
//! by the device at each operation, the unseal with no passphrase), and the refusals.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use writ_integration::daemon::{Approvals, Daemon, ssh_options};
use writ_integration::https_remote::HttpsRemote;
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

/// `writ recovery new`: the secret key and the recipient it prints.
fn new_recovery_key(daemon: &Daemon) -> (String, String) {
    let out = daemon.run(&["recovery", "new"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let said = stdout(&out);
    let secret = said
        .lines()
        // The key: the first line with text after the one that announces it.
        .skip_while(|l| !l.starts_with("Recovery key "))
        .skip(1)
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or_else(|| panic!("{said}"))
        .to_owned();
    let recipient = said
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("writ admin recipient add recovery recipient=")
        })
        .unwrap_or_else(|| panic!("{said}"))
        .to_owned();
    (secret, recipient)
}

fn ok(out: &Output) {
    assert!(out.status.success(), "{}{}", stdout(out), stderr(out));
}

fn keys(daemon: &Daemon) -> std::path::PathBuf {
    daemon.root().join("s/keys")
}

/// The stanzas' tags of an age file.
fn stanza_tags(file: &Path) -> Vec<String> {
    let bytes = fs::read(file).unwrap();
    String::from_utf8_lossy(&bytes)
        .lines()
        .take_while(|l| !l.starts_with("---"))
        .filter_map(|l| l.strip_prefix("-> "))
        .map(|l| l.split(' ').next().unwrap().to_owned())
        // age's own random stanza, on every file it writes.
        .filter(|tag| !tag.ends_with("-grease"))
        .collect()
}

#[test]
fn a_recovery_key_on_a_passphrase_keystore_opens_it_and_is_checked_from_the_approver_s_machine() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    ok(&daemon.unseal());
    let (secret, recipient) = new_recovery_key(&daemon);
    // Nothing secret is written by `writ recovery new`, anywhere under the test's root.
    fn holds(dir: &Path, secret: &[u8]) -> bool {
        fs::read_dir(dir).unwrap().any(|e| {
            let path = e.unwrap().path();
            match fs::symlink_metadata(&path).unwrap().is_dir() {
                true => holds(&path, secret),
                false => {
                    fs::read(&path).is_ok_and(|b| b.windows(secret.len()).any(|w| w == secret))
                }
            }
        })
    }
    assert!(!holds(daemon.root(), secret.as_bytes()));
    // No recovery key yet: the check says so.
    let out = daemon.run(&["recovery", "check"], &format!("{secret}\n"));
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("declares no recovery recipient"),
        "{}",
        stderr(&out)
    );

    // Declared live: the identity wrapped to it too, the passphrase still the way in.
    let given = format!("recipient={recipient}");
    ok(&daemon.run(
        &["admin", "recipient", "add", "recovery", &given, "--yes"],
        "",
    ));
    let dir = keys(&daemon);
    assert_eq!(stanza_tags(&dir.join("identity.age")), ["scrypt"]);
    assert_eq!(stanza_tags(&dir.join("identity.recovery.age")), ["X25519"]);
    assert!(dir.join("recovery-check.age").exists());
    let lines = audit_events(&daemon.audit(), "admin", "allowed");
    assert!(!lines.is_empty());
    let out = daemon.run(&["admin", "recipient", "list"], "");
    ok(&out);
    assert_eq!(
        stdout(&out).trim(),
        format!("recovery  recovery {recipient}")
    );
    let out = daemon.run(&["admin", "recipient", "show", "recovery"], "");
    ok(&out);
    assert!(
        stdout(&out).contains("unwraps: everything, off the daemon's host"),
        "{}",
        stdout(&out)
    );

    // The right key checks; another is named by its recipient.
    let out = daemon.run(&["recovery", "check"], &format!("{secret}\n"));
    ok(&out);
    assert!(
        stdout(&out).starts_with("Recovery key checked: it is recipient recovery"),
        "{}",
        stdout(&out)
    );
    let (other, other_recipient) = new_recovery_key(&daemon);
    let out = daemon.run(&["recovery", "check"], &format!("{other}\n"));
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains(&format!(
            "not the daemon's recovery key: this key's recipient is {other_recipient}, not the \
             daemon's recovery recipient {recipient}"
        )),
        "{}",
        stderr(&out)
    );

    // A start again: the passphrase unseals, the recovery key still checks.
    daemon.restart();
    ok(&daemon.unseal());
    ok(&daemon.run(&["recovery", "check"], &format!("{secret}\n")));

    // Replaced: the old key no longer checks, the new one does; removed: its files go.
    let given = format!("recipient={other_recipient}");
    ok(&daemon.run(
        &["admin", "recipient", "set", "recovery", &given, "--yes"],
        "",
    ));
    let out = daemon.run(
        &["recovery", "check"],
        &format!(
            "{secret}
"
        ),
    );
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    ok(&daemon.run(&["recovery", "check"], &format!("{other}\n")));
    ok(&daemon.run(&["admin", "recipient", "remove", "recovery", "--yes"], ""));
    for file in [
        "identity.recovery.age",
        "recovery-check.age",
        "recovery-check.sha256",
    ] {
        assert!(!dir.join(file).exists(), "{file}");
    }
    assert_eq!(stanza_tags(&dir.join("identity.age")), ["scrypt"]);
    // A hardware key without the daemon having its device, or without a recovery key: refused.
    let out = daemon.run(
        &[
            "admin",
            "recipient",
            "add",
            "se-01",
            "backend=se-cryptokit",
            "--yes",
        ],
        "",
    );
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out)
            .contains("recipients: a hardware recipient needs the recovery recipient beside it"),
        "{}",
        stderr(&out)
    );
}

fn on_the_mac() -> bool {
    std::env::consts::OS == "macos"
}

const HTTPS_TOKEN: &str = "writ-test-recipients-https-token-0123456789";

/// A bare repo `web` on an HTTPS test remote, with one commit on `main`.
fn web_remote(runtime: &tokio::runtime::Runtime, root: &Path) -> HttpsRemote {
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
    remote
}

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

/// On the Mac, against the fake `writ-se` (no blob of a test ever reaches the real Secure
/// Enclave here): a hardware recipient declared live takes the keystore.
#[test]
fn on_the_mac_a_hardware_recipient_takes_the_keystore_live_and_unwraps_the_token_per_use() {
    if !on_the_mac() {
        return;
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let remote_dir = tempfile::tempdir().unwrap();
    let remote = web_remote(&runtime, remote_dir.path());
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
    let helper = writ_integration::binaries::bin("writ-fake-se");
    let mut daemon = Daemon::start_sealed_with(&policy, Approvals::Ssh, |yaml| {
        format!(
            "{}signers:\n  se_cryptokit:\n    helper: {}\n",
            yaml.replace(
                "mirrors: { fresh_for: 0s }",
                &format!("mirrors: {{ fresh_for: 0s, ca_certs: {} }}", ca.display()),
            ),
            helper.display()
        )
    });
    ok(&daemon.unseal());
    ok(&daemon.run(
        &["admin", "token", "token-01", "--yes"],
        &format!("{HTTPS_TOKEN}\n"),
    ));
    let dir = keys(&daemon);
    let token = dir.join("tokens/token-01.age");
    assert_eq!(
        stanza_tags(&token),
        ["X25519"],
        "to the identity, on a passphrase keystore"
    );

    // The recovery key, then a hardware key: in one change each.
    let (secret, recipient) = new_recovery_key(&daemon);
    ok(&daemon.run(
        &[
            "admin",
            "recipient",
            "add",
            "recovery",
            &format!("recipient={recipient}"),
            "--yes",
        ],
        "",
    ));
    let out = daemon.run(
        &[
            "admin",
            "recipient",
            "add",
            "se-01",
            "backend=se-cryptokit",
            "--yes",
        ],
        "",
    );
    ok(&out);
    assert!(
        daemon
            .audit()
            .contains("recipient se-01 created in its device: age1se1"),
        "{}",
        daemon.audit()
    );
    // The identity is the device's now (no scrypt), the token the device's and the recovery
    // key's; the recovery file still the recovery key's.
    assert_eq!(stanza_tags(&dir.join("identity.age")), ["piv-p256"]);
    let mut tags = stanza_tags(&token);
    tags.sort();
    assert_eq!(tags, ["X25519", "piv-p256"]);
    assert_eq!(stanza_tags(&dir.join("identity.recovery.age")), ["X25519"]);

    // The token is unwrapped by the device for each operation.
    let ticket = "repos:\n  web:\n    operations: [fetch]\n    branches: [\"agent/x\"]\n\
                  ticket:\n  title: \"Web\"\n  task: Web\nlimits:\n  ttl: 30m\n";
    let lease = daemon.lease("web", ticket);
    let out = ls_remote(&daemon, &lease, "web");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));

    // A start again: the device unseals, whatever passphrase is typed.
    daemon.restart();
    let out = daemon.run(&["unseal"], "not the passphrase at all\n");
    ok(&out);
    let out = ls_remote(&daemon, &lease, "web");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    ok(&daemon.run(&["recovery", "check"], &format!("{secret}\n")));

    // The recovery key can't go while the hardware key needs it; the last hardware key can't
    // go at all.
    let out = daemon.run(&["admin", "recipient", "remove", "recovery", "--yes"], "");
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("needs the recovery recipient beside it"),
        "{}",
        stderr(&out)
    );
    let out = daemon.run(&["admin", "recipient", "remove", "se-01", "--yes"], "");
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("the last hardware recipient can't be removed: going back to a passphrase is writd recover"),
        "{}",
        stderr(&out)
    );
    let refused = audit_events(&daemon.audit(), "admin", "denied");
    assert!(refused.iter().any(|l| {
        l["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("last hardware recipient")
    }));
}
