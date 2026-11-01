//! `writ init` with the real `writd`, `writ`, `writ-sign`, `git` and `ssh`: wrapper mode (the
//! default), where the agent works through `writ git` while the operator's own git, in the
//! same clone, keeps the operator's key, email and remotes; and `--whole-repo`, for a clone
//! dedicated to an agent. `--undo` leaves the repo's config as it was.

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
use std::process::{Command, Output, Stdio};

use writ_core::names::TicketId;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::LineEnding;
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::{audit_events, stderr, stdout, write_secret};

const POLICY: &str = r#"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    protected_refs: ["refs/heads/main"]
templates:
  feature:
    repos: [demo]
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-01
    max_ttl: 2h
    max_signatures: 40
    max_pushes: 20
    max_ops_per_minute: 100
    max_push_size: 10MB
    paths_check: warn
"#;

const OAUTH: &str = r#"
scope:
  repos: [demo]
  operations: [fetch, commit_sign, push]
  branches: ["agent/oauth"]
ticket:
  title: "Add OAuth login"
  task: Add GitHub OAuth login behind a feature flag
  expected_paths: ["src/**"]
limits:
  ttl: 1h
"#;

/// A daemon with a signed lease: the lease id and the daemon's signing public key.
fn granted() -> (Daemon, String, String) {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let request = daemon.request("oauth", OAUTH);
    let id = request.id.clone();
    let out = daemon.run(&["sign", &id, "--yes"], "");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let (status, out, err) = request.finish();
    assert_eq!(status.code(), Some(0), "{out}{err}");
    let key = fs::read_to_string(daemon.session(&id).join("signing_key.pub")).unwrap();
    assert!(key.starts_with("ssh-ed25519 "), "{key}");
    (daemon, id, key)
}

#[test]
fn writd_signing_keys_prints_the_key_a_lease_signs_with() {
    // What the operator registers on an account (a signing key) is the key the lease's
    // commits are signed with, and nothing else.
    let (daemon, _, key) = granted();
    let printed = daemon.print("signing-keys");
    assert_eq!(
        printed,
        format!("agent-01 {} (templates: feature)", key.trim()),
        "{printed}"
    );
    // The upstream credential is another key, and is not listed there.
    let upstream = daemon.print("upstream-keys");
    assert!(
        upstream.starts_with("upstream-01 ssh-ed25519 "),
        "{upstream}"
    );
    assert!(!printed.contains(upstream.split(' ').nth(2).unwrap()));
}

/// Plain git, as the operator runs it: the throwaway home's `.gitconfig`, no system config.
fn git(daemon: &Daemon, cwd: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", daemon.root().join("home"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn git_ok(daemon: &Daemon, cwd: &Path, args: &[&str]) -> String {
    let out = git(daemon, cwd, args);
    assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
    stdout(&out)
}

/// `writ`, as the agent runs it, in `cwd`.
fn writ(daemon: &Daemon, cwd: &Path, args: &[&str]) -> Output {
    daemon
        .writ(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn writ_ok(daemon: &Daemon, cwd: &Path, args: &[&str]) -> String {
    let out = writ(daemon, cwd, args);
    assert!(out.status.success(), "writ {args:?}: {}", stderr(&out));
    stdout(&out)
}

/// The repo's own config, entry by entry.
fn local_config(daemon: &Daemon, repo: &Path) -> String {
    stdout(&git(daemon, repo, &["config", "--local", "--list"]))
}

/// `git verify-commit` of `rev` with `principal key` as the only allowed signer.
fn verified_by(daemon: &Daemon, repo: &Path, rev: &str, principal: &str, key: &str) -> bool {
    let allowed = daemon.root().join(format!("allowed-{principal}"));
    fs::write(&allowed, format!("{principal} {}\n", key.trim())).unwrap();
    let option = format!("gpg.ssh.allowedSignersFile={}", allowed.display());
    let out = git(daemon, repo, &["-c", &option, "verify-commit", rev]);
    out.status.success()
        && stderr(&out).contains(&format!("Good \"git\" signature for {principal}"))
}

fn ledger(daemon: &Daemon, lease: &str) -> Vec<String> {
    let lease: TicketId = lease.parse().unwrap();
    writ_store::Store::open(&daemon.root().join("s/leases.db"))
        .unwrap()
        .ledger_for_lease(&lease)
        .unwrap()
        .into_iter()
        .map(|e| e.commit.as_str().to_owned())
        .collect()
}

#[test]
fn wrapper_mode_signs_through_writ_git_and_leaves_the_operator_s_git_alone() {
    let (daemon, id, agent_key) = granted();
    let root = daemon.root().to_owned();
    // The operator's own setup: their email, their SSH signing key, their remote.
    let operator = generate(KeyKind::Ed25519).unwrap();
    let operator_key = root.join("operator_key");
    write_secret(
        &operator_key,
        operator.to_openssh(LineEnding::LF).unwrap().as_bytes(),
    );
    fs::write(
        root.join("home/.gitconfig"),
        format!(
            "[user]\n\tname = Operator\n\temail = me@operator.example\n\tsigningkey = {}\n\
             [gpg]\n\tformat = ssh\n[init]\n\tdefaultBranch = main\n",
            operator_key.display()
        ),
    )
    .unwrap();
    let operator_public = operator.public_key().to_openssh().unwrap();
    // The operator's `origin` is the repo's upstream (GitHub, say): the daemon's test remote.
    let origin = daemon.remote.repo("demo");
    let repo = root.join("repo");
    fs::create_dir_all(&repo).unwrap();
    git_ok(&daemon, &repo, &["init", "-q"]);
    git_ok(
        &daemon,
        &repo,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    fs::write(repo.join("README"), "demo\n").unwrap();
    git_ok(&daemon, &repo, &["add", "-A"]);
    git_ok(&daemon, &repo, &["commit", "-q", "-m", "seed"]);
    let seed = git_ok(&daemon, &repo, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();

    // Wired: nothing in the repo's git config changes.
    let before = local_config(&daemon, &repo);
    let out = writ_ok(&daemon, &repo, &["init", "demo"]);
    assert!(out.contains("wrapper mode"), "{out}");
    assert!(
        out.contains("`writ git push origin` and `writ git fetch origin` go through the daemon"),
        "{out}"
    );
    assert!(out.contains("Committer email: agent@writ."), "{out}");
    assert_eq!(local_config(&daemon, &repo), before);
    assert!(repo.join(".git/writ/config").is_file());
    let again = writ(&daemon, &repo, &["init", "demo"]);
    assert_eq!(again.status.code(), Some(1));
    assert!(
        stderr(&again).contains("already wired for Writ (wrapper mode, repo demo)"),
        "{}",
        stderr(&again)
    );

    // The agent's commit, through `writ git`: signed by the daemon, as the agent.
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::write(repo.join("src/oauth.rs"), "pub fn login() {}\n").unwrap();
    let trailer = format!("Writ: {id}");
    writ_ok(&daemon, &repo, &["git", "add", "-A"]);
    writ_ok(
        &daemon,
        &repo,
        &[
            "git",
            "commit",
            "-q",
            "-m",
            "Add OAuth",
            "--trailer",
            &trailer,
        ],
    );
    assert_eq!(
        git_ok(&daemon, &repo, &["log", "-1", "--format=%ce"]).trim(),
        "agent@writ"
    );
    assert!(verified_by(
        &daemon,
        &repo,
        "HEAD",
        "agent@writ",
        &agent_key
    ));
    let agent_commit = git_ok(&daemon, &repo, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    assert_eq!(ledger(&daemon, &id), std::slice::from_ref(&agent_commit));

    // The operator's commit, plain git, same clone: their key, their email.
    fs::write(repo.join("notes.md"), "mine\n").unwrap();
    git_ok(&daemon, &repo, &["add", "notes.md"]);
    git_ok(
        &daemon,
        &repo,
        &["commit", "-q", "-S", "-m", "Operator's notes"],
    );
    assert_eq!(
        git_ok(&daemon, &repo, &["log", "-1", "--format=%ce"]).trim(),
        "me@operator.example"
    );
    assert!(verified_by(
        &daemon,
        &repo,
        "HEAD",
        "me@operator.example",
        &operator_public
    ));
    assert!(!verified_by(
        &daemon,
        &repo,
        "HEAD",
        "agent@writ",
        &agent_key
    ));

    // The settings exist only for what runs through writ.
    let plain = git(&daemon, &repo, &["config", "core.sshCommand"]);
    assert_eq!(plain.status.code(), Some(1), "no SSH command in plain git");
    let wrapped = writ_ok(&daemon, &repo, &["git", "config", "core.sshCommand"]);
    assert!(wrapped.contains("CertificateFile="), "{wrapped}");
    let child = writ_ok(
        &daemon,
        &repo,
        &["exec", "--", "sh", "-c", "git config writ.repo"],
    );
    assert_eq!(child.trim(), "demo", "a program's own git sees the wiring");
    // ... in any repository: a commit it makes in another clone is refused by writ-sign
    // before anything is sent, so it never reaches the daemon as demo's.
    let other = root.join("other");
    fs::create_dir_all(&other).unwrap();
    git_ok(&daemon, &other, &["init", "-q"]);
    let signed_before = ledger(&daemon, &id).len();
    let out = writ(
        &daemon,
        &repo,
        &[
            "exec",
            "--",
            "git",
            "-C",
            other.to_str().unwrap(),
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            &format!("elsewhere\n\n{trailer}"),
        ],
    );
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("but the Writ settings are for"),
        "{}",
        stderr(&out)
    );
    assert_eq!(ledger(&daemon, &id).len(), signed_before, "nothing signed");
    let out = git(&daemon, &repo, &["push", "writ", "HEAD"]);
    assert_eq!(out.status.code(), Some(128));
    assert!(
        stderr(&out).contains("'writ' does not appear to be a git repository"),
        "{}",
        stderr(&out)
    );
    git_ok(
        &daemon,
        &repo,
        &["push", "-q", "origin", "HEAD:refs/heads/main"],
    );

    // Any git command goes through: a rebase signs the rewritten commits again.
    git_ok(
        &daemon,
        &repo,
        &["checkout", "-q", "-b", "agent/oauth", &seed],
    );
    fs::create_dir_all(repo.join("src")).unwrap();
    for name in ["src/a.rs", "src/b.rs"] {
        fs::write(repo.join(name), "x\n").unwrap();
        writ_ok(&daemon, &repo, &["git", "add", "-A"]);
        writ_ok(
            &daemon,
            &repo,
            &["git", "commit", "-q", "-m", name, "--trailer", &trailer],
        );
    }
    assert_eq!(ledger(&daemon, &id).len(), 3);
    writ_ok(&daemon, &repo, &["git", "rebase", "-q", "main"]);
    let rebased = ledger(&daemon, &id);
    assert_eq!(rebased.len(), 5, "both rewritten commits signed again");
    let head = git_ok(&daemon, &repo, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    assert_eq!(rebased.last(), Some(&head));
    assert!(verified_by(
        &daemon,
        &repo,
        "HEAD",
        "agent@writ",
        &agent_key
    ));
    assert!(verified_by(
        &daemon,
        &repo,
        "HEAD~1",
        "agent@writ",
        &agent_key
    ));
    // The agent fetches through the daemon (its mirror syncs main, which the operator pushed
    // upstream), then pushes: only the agent's signed commits are new. It says `origin`, as
    // it would without Writ: the rewrite sends it to the daemon.
    writ_ok(&daemon, &repo, &["git", "fetch", "-q", "origin"]);
    let rewritten = writ_ok(
        &daemon,
        &repo,
        &["git", "remote", "get-url", "--push", "origin"],
    );
    assert!(
        rewritten.trim().ends_with("/demo.git") && rewritten.starts_with("ssh://git@127.0.0.1:"),
        "{rewritten}"
    );
    writ_ok(
        &daemon,
        &repo,
        &["git", "push", "-q", "origin", "HEAD:refs/heads/agent/oauth"],
    );
    assert_eq!(
        git_ok(&daemon, &origin, &["rev-parse", "refs/heads/agent/oauth"]).trim(),
        head,
        "upstream has the agent's branch, through the daemon"
    );
    // The operator's plain git still reaches `origin` itself.
    let direct = git_ok(&daemon, &repo, &["remote", "get-url", "--push", "origin"]);
    assert_eq!(direct.trim(), origin.to_str().unwrap());

    // Undone: the record is gone, the config as it was, `writ git` refuses.
    writ_ok(&daemon, &repo, &["init", "--undo"]);
    assert!(!repo.join(".git/writ").exists());
    assert_eq!(local_config(&daemon, &repo), before);
    let out = writ(&daemon, &repo, &["git", "status"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("this repo isn't wired for Writ"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn whole_repo_mode_wires_a_dedicated_clone_and_undo_restores_it() {
    let (daemon, id, agent_key) = granted();
    let root = daemon.root().to_owned();
    fs::write(
        root.join("home/.gitconfig"),
        "[user]\n\tname = Agent\n[init]\n\tdefaultBranch = main\n",
    )
    .unwrap();
    let repo = root.join("repo");
    fs::create_dir_all(&repo).unwrap();
    git_ok(&daemon, &repo, &["init", "-q"]);
    let origin = daemon.remote.repo("demo");
    git_ok(
        &daemon,
        &repo,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    // Last in the file: `--undo` adds the values it puts back at the end of the config.
    git_ok(
        &daemon,
        &repo,
        &["config", "--local", "user.email", "someone@before.example"],
    );
    let before = local_config(&daemon, &repo);

    let out = writ_ok(&daemon, &repo, &["init", "demo", "--whole-repo"]);
    assert!(out.contains("whole repo"), "{out}");
    assert!(
        out.contains("every push and fetch to it goes through the daemon, plain git too"),
        "{out}"
    );
    let config = local_config(&daemon, &repo);
    assert!(config.contains("writ.repo=demo"), "{config}");
    assert!(config.contains("user.email=agent@writ"), "{config}");

    // Plain git, no -S: signed by the daemon (commit.gpgSign), with no prompt.
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::write(repo.join("src/oauth.rs"), "pub fn login() {}\n").unwrap();
    git_ok(&daemon, &repo, &["add", "-A"]);
    let trailer = format!("Writ: {id}");
    git_ok(
        &daemon,
        &repo,
        &["commit", "-q", "-m", "Add OAuth", "--trailer", &trailer],
    );
    assert!(verified_by(
        &daemon,
        &repo,
        "HEAD",
        "agent@writ",
        &agent_key
    ));
    let first = git_ok(&daemon, &repo, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();

    // `paths_check: warn`: outside expected_paths, signed, the warning recorded.
    fs::write(repo.join("README"), "readme\n").unwrap();
    git_ok(&daemon, &repo, &["add", "-A"]);
    git_ok(
        &daemon,
        &repo,
        &["commit", "-q", "-m", "Readme", "--trailer", &trailer],
    );
    let second = git_ok(&daemon, &repo, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    let signed = audit_events(&daemon.audit(), "sign", "allowed");
    assert_eq!(signed.len(), 2, "{signed:?}");
    assert_eq!(signed[0]["commit"], first.as_str());
    assert!(signed[0].get("warnings").is_none(), "{}", signed[0]);
    assert_eq!(signed[1]["commit"], second.as_str());
    assert_eq!(
        signed[1]["warnings"][0],
        "files outside expected_paths: README"
    );
    // Every signed commit is in the ledger, with its lease and key.
    let lease: TicketId = id.parse().unwrap();
    let entries = writ_store::Store::open(&root.join("s/leases.db"))
        .unwrap()
        .ledger_for_lease(&lease)
        .unwrap();
    let commits: Vec<&str> = entries.iter().map(|e| e.commit.as_str()).collect();
    assert_eq!(commits, [first.as_str(), second.as_str()]);
    assert!(
        entries
            .iter()
            .all(|e| e.key.as_str() == "agent-01" && e.repo.as_str() == "demo")
    );
    // Plain git, `origin`: through the daemon in this clone.
    git_ok(
        &daemon,
        &repo,
        &["push", "-q", "origin", "HEAD:refs/heads/agent/oauth"],
    );
    assert_eq!(
        git_ok(&daemon, &origin, &["rev-parse", "refs/heads/agent/oauth"]).trim(),
        second,
        "upstream has the branch, through the daemon"
    );

    // A locked config stops the undo before it adds anything: the wiring stays recorded.
    let wired = local_config(&daemon, &repo);
    fs::write(repo.join(".git/config.lock"), "").unwrap();
    let out = writ(&daemon, &repo, &["init", "--undo"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("git config --unset-all") && stderr(&out).contains("failed"),
        "{}",
        stderr(&out)
    );
    fs::remove_file(repo.join(".git/config.lock")).unwrap();
    assert_eq!(local_config(&daemon, &repo), wired);
    assert!(repo.join(".git/writ/config").exists());

    // Undone: every key back as it was, the operator's email included.
    writ_ok(&daemon, &repo, &["init", "--undo"]);
    assert_eq!(local_config(&daemon, &repo), before);
    assert!(!repo.join(".git/writ").exists());
}
