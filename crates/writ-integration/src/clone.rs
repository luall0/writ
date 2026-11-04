//! An agent's clone of the repo `demo` (its `origin` the daemon's test remote), and the `git`
//! and `writ` an agent or the operator runs in it: plain `git` with the throwaway home's
//! config only, `writ` with the daemon's endpoints and any extra environment
//! (`WRIT_SESSION`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use writ_core::names::TicketId;

use crate::daemon::Daemon;
use crate::{stderr, stdout};

/// Plain git in `cwd`: the throwaway home's `.gitconfig`, no system config, no prompt.
pub fn git(daemon: &Daemon, cwd: &Path, args: &[&str]) -> Output {
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

/// [`git`], which must succeed: its stdout.
pub fn git_ok(daemon: &Daemon, cwd: &Path, args: &[&str]) -> String {
    let out = git(daemon, cwd, args);
    assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
    stdout(&out)
}

/// `writ` in `cwd`, with `env` on top of the daemon's settings, no terminal.
pub fn writ(daemon: &Daemon, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    daemon
        .writ(args)
        .current_dir(cwd)
        .envs(env.iter().copied())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// [`writ`], which must succeed: its stdout.
pub fn writ_ok(daemon: &Daemon, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
    let out = writ(daemon, cwd, args, env);
    assert!(
        out.status.success(),
        "writ {args:?}: {}{}",
        stdout(&out),
        stderr(&out)
    );
    stdout(&out)
}

/// A clone `name` of `demo` (its `main` a commit upstream has, made there the first time),
/// its `origin` the upstream, the operator's identity in the throwaway home. Not wired.
pub fn clone(daemon: &Daemon, name: &str) -> PathBuf {
    let root = daemon.root();
    let config = root.join("home/.gitconfig");
    if !config.exists() {
        fs::write(
            &config,
            "[user]\n\tname = Operator\n\temail = me@operator.example\n[init]\n\tdefaultBranch = main\n",
        )
        .unwrap();
    }
    if !root.join("upstream-seed").exists() {
        daemon.upstream_commit("main", "seed");
    }
    let repo = root.join(name);
    let origin = daemon.remote.repo("demo");
    git_ok(
        daemon,
        root,
        &[
            "clone",
            "-q",
            origin.to_str().unwrap(),
            repo.to_str().unwrap(),
        ],
    );
    repo
}

/// The commits the ledger holds for `lease`, in signing order.
pub fn ledger(daemon: &Daemon, lease: &str) -> Vec<String> {
    let lease: TicketId = lease.parse().unwrap();
    writ_store::Store::open(&daemon.root().join("s/leases.db"))
        .unwrap()
        .ledger_for_lease(&lease)
        .unwrap()
        .into_iter()
        .map(|e| e.commit.as_str().to_owned())
        .collect()
}
