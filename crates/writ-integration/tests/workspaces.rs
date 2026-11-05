//! Multi-repo workspaces (M6.1) with the real `writd`, `writ`, `writ-sign`, `git` and `ssh`:
//! `writ init` at a folder of repositories (no repo named), one agent at the folder working on
//! two of them under one lease through `writ git -C` and `writ exec -C`, the repository behind
//! git's global options, the run recorded in the workspace's timings file, and `writ init
//! --undo` at the root taking every repository and the root back.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use writ_core::names::TicketId;
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::{stderr, stdout};

/// Two registry repos on the same test upstream (the placeholder is rewritten to it): `demo`
/// as it is, `web` needing the `Writ:` trailer.
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
  web:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    templates: [feature]
    protected_refs: ["refs/heads/main"]
    ticket_link: trailer
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
    paths_check: warn
"#;

/// One ticket for both repositories.
const BOTH: &str = r#"
repos:
  demo:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
  web:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
ticket:
  title: "Login across the API and the web app"
  task: Add the login route to the API and its button to the web app
  estimate: { coding: 20m, checks: 5m }
limits:
  ttl: 1h
"#;

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

/// `writ`, as the agent runs it, in `cwd`, with no terminal.
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

/// A refusal: exit 1 and the exact words on stderr.
fn refused(out: &Output, words: &str) {
    assert_eq!(out.status.code(), Some(1), "{}{}", stdout(out), stderr(out));
    assert!(
        stderr(out).contains(words),
        "{words}\nnot in:\n{}",
        stderr(out)
    );
}

/// Every path under `root` (relative, sorted), git's own directories left out.
fn tree(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_name() == ".git" {
                continue;
            }
            out.push(path.strip_prefix(root).unwrap().display().to_string());
            if entry.file_type().unwrap().is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

/// What `writ init --undo` must give back: the files, and each repository's own config and
/// `info/exclude`.
fn state(daemon: &Daemon, root: &Path, repos: &[&str]) -> (Vec<String>, Vec<(String, String)>) {
    let repos = repos
        .iter()
        .map(|repo| {
            let dir = root.join(repo);
            let exclude = fs::read_to_string(dir.join(".git/info/exclude")).unwrap_or_default();
            (
                stdout(&git(daemon, &dir, &["config", "--local", "--list"])),
                exclude,
            )
        })
        .collect();
    (tree(root), repos)
}

fn ledger(daemon: &Daemon, lease: &str) -> Vec<(String, String)> {
    let lease: TicketId = lease.parse().unwrap();
    writ_store::Store::open(&daemon.root().join("s/leases.db"))
        .unwrap()
        .ledger_for_lease(&lease)
        .unwrap()
        .into_iter()
        .map(|e| (e.repo.as_str().to_owned(), e.commit.as_str().to_owned()))
        .collect()
}

/// A daemon, its lease for both repos, and a workspace folder with `api` (the upstream's
/// clone after the operator's first push) and `web` (a second clone), a plain folder, a
/// hidden repository and a link to `api`, none of which is a workspace repository.
fn workspace() -> (Daemon, String, std::path::PathBuf) {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let lease = daemon.lease("both", BOTH);
    // The operator's identity in the throwaway home, as `clone` writes it: without it, git
    // falls back to the account's full name, which a CI runner's account doesn't have.
    fs::write(
        daemon.root().join("home/.gitconfig"),
        "[user]\n\tname = Operator\n\temail = me@operator.example\n",
    )
    .unwrap();
    // As the processes see it: on macOS the temporary directory is a link
    // (`/var` → `/private/var`), and `writ` records the folder it runs in.
    fs::create_dir_all(daemon.root().join("ws/api")).unwrap();
    let root = fs::canonicalize(daemon.root().join("ws")).unwrap();
    let upstream = daemon.remote.repo("demo");
    let api = root.join("api");
    git_ok(&daemon, &api, &["init", "-q", "-b", "main"]);
    git_ok(
        &daemon,
        &api,
        &["remote", "add", "origin", upstream.to_str().unwrap()],
    );
    fs::write(api.join("README"), "workspace\n").unwrap();
    git_ok(&daemon, &api, &["add", "-A"]);
    git_ok(&daemon, &api, &["commit", "-q", "-m", "seed"]);
    git_ok(
        &daemon,
        &api,
        &["push", "-q", "origin", "HEAD:refs/heads/main"],
    );
    git_ok(
        &daemon,
        &root,
        &["clone", "-q", upstream.to_str().unwrap(), "web"],
    );
    fs::create_dir_all(root.join("notes")).unwrap();
    fs::create_dir_all(root.join(".cache")).unwrap();
    git_ok(&daemon, &root.join(".cache"), &["init", "-q"]);
    std::os::unix::fs::symlink(root.join("api"), root.join("link")).unwrap();
    (daemon, lease, root)
}

#[test]
fn one_agent_at_a_workspace_root_works_on_two_repositories_under_one_lease() {
    let (daemon, id, root) = workspace();
    let api = root.join("api");
    let before = state(&daemon, &root, &["api", "web"]);

    // No terminal, and no --repo: refused, nothing wired.
    let out = writ(&daemon, &root, &["init", "--agents", "claude"]);
    refused(
        &out,
        "no terminal to confirm the registry names: pass --repo <dir>=<name> (or <dir>=- to \
         leave it out) for each of: api (by default demo), web (by default demo) (nothing was \
         wired)",
    );
    // A folder that isn't one of the repositories, or two of them under one name: refused.
    let out = writ(
        &daemon,
        &root,
        &["init", "--agents", "claude", "--repo", "notes=demo"],
    );
    refused(
        &out,
        "--repo notes: not a repository right under this folder (found: api, web)",
    );
    let out = writ(
        &daemon,
        &root,
        &[
            "init", "--agents", "claude", "--repo", "api=demo", "--repo", "web=demo",
        ],
    );
    refused(
        &out,
        "api and web are both named demo: one registry name per repository",
    );
    assert_eq!(
        state(&daemon, &root, &["api", "web"]),
        before,
        "nothing wired"
    );

    // Wired, each repository under its registry name, the skill at the root only.
    let out = writ_ok(
        &daemon,
        &root,
        &[
            "init",
            "--agents",
            "claude",
            "--agents-md",
            "--repo",
            "api=demo",
            "--repo",
            "web/=web",
        ],
    );
    assert!(
        out.starts_with(&format!(
            "Workspace wired for Writ at {} (wrapper mode",
            root.display()
        )),
        "{out}"
    );
    assert!(out.contains("\n  api  repo demo, origin "), "{out}");
    assert!(out.contains("\n  web  repo web, origin "), "{out}");
    assert!(
        out.contains("Not wired: link (a link: wire the folder it points at)."),
        "{out}"
    );
    assert!(!out.contains("notes") && !out.contains(".cache"), "{out}");
    let skill = fs::read_to_string(root.join(".claude/skills/writ-workspace/SKILL.md")).unwrap();
    assert!(skill.starts_with("---\nname: writ-workspace\n"), "{skill}");
    assert!(
        skill.contains("- `api`: repo `demo`\n- `web`: repo `web`"),
        "{skill}"
    );
    assert!(
        skill.contains("`.claude/skills/writ-workspace/timings.md`"),
        "{skill}"
    );
    assert!(!api.join(".claude").exists(), "no skill in a repository");
    let agents_md = fs::read_to_string(root.join("AGENTS.md")).unwrap();
    assert!(agents_md.contains("`writ-workspace` skill"), "{agents_md}");
    // Wrapper mode: no repository's config changed.
    assert_eq!(state(&daemon, &root, &["api", "web"]).1, before.1);
    let out = writ(
        &daemon,
        &root,
        &["init", "--agents", "none", "--repo", "api=demo"],
    );
    refused(
        &out,
        "this folder is already a Writ workspace (2 repositories)",
    );

    // At the root, which is no repository: the workspace's repositories, listed.
    let out = writ(&daemon, &root, &["git", "status"]);
    refused(&out, "is a Writ workspace, not a repository wired for Writ");
    assert!(
        stderr(&out).contains("  api  repo demo  (writ git -C api …)"),
        "{}",
        stderr(&out)
    );
    let out = writ(&daemon, &root, &["exec", "--", "true"]);
    refused(&out, "is a Writ workspace, not a repository wired for Writ");
    let out = writ(&daemon, &root, &["policy"]);
    refused(&out, "this folder is a Writ workspace: name the repo");

    // The repository behind git's global options, as git finds it.
    for (args, repo) in [
        (&["git", "-C", "api", "config", "writ.repo"][..], "demo"),
        (&["git", "-C", "web", "config", "writ.repo"], "web"),
        (
            &["git", "-C", "", "-C", "web", "config", "writ.repo"],
            "web",
        ),
        (
            &[
                "git",
                "-c",
                "core.quotepath=off",
                "-C",
                "api",
                "config",
                "writ.repo",
            ],
            "demo",
        ),
        (
            &[
                "git",
                "--git-dir=web/.git",
                "--work-tree=web",
                "config",
                "writ.repo",
            ],
            "web",
        ),
        (
            &["git", "--git-dir", "api/.git", "config", "writ.repo"],
            "demo",
        ),
        (
            &["git", "--no-pager", "-C", "api", "config", "writ.repo"],
            "demo",
        ),
    ] {
        assert_eq!(writ_ok(&daemon, &root, args).trim(), repo, "{args:?}");
    }
    // From inside a repository too, and from one into the other.
    assert_eq!(
        writ_ok(&daemon, &api, &["git", "config", "writ.repo"]).trim(),
        "demo"
    );
    assert_eq!(
        writ_ok(
            &daemon,
            &api,
            &["git", "-C", "../web", "config", "writ.repo"]
        )
        .trim(),
        "web"
    );
    // What it can't place: refused with its reason, git never run.
    let out = writ(&daemon, &root, &["git", "--bogus", "-C", "api", "status"]);
    refused(
        &out,
        "writ: --bogus: not an option git takes before its command (writ git refuses what it \
         can't place: put the command's own options after the command)",
    );
    let out = writ(&daemon, &root, &["git", "-C"]);
    refused(&out, "writ: -C needs a value, as git asks");
    let out = writ(&daemon, &root, &["git", "-C", "notes", "status"]);
    refused(&out, "writ: not in a git repository (");
    // A version or help asks for no repository.
    assert!(writ_ok(&daemon, &root, &["git", "--version"]).starts_with("git version "));

    // `writ exec -C`: the program in that repository, under its wiring.
    let out = writ_ok(
        &daemon,
        &root,
        &[
            "exec",
            "-C",
            "web",
            "--",
            "sh",
            "-c",
            "git config writ.repo && pwd",
        ],
    );
    assert_eq!(
        out,
        format!("web\n{}\n", root.join("web").display()),
        "{out}"
    );
    let out = writ(&daemon, &root, &["exec", "-C", "nowhere", "--", "true"]);
    refused(&out, "-C ");
    assert!(
        stderr(&out).contains("nowhere: not a directory"),
        "{}",
        stderr(&out)
    );

    // One lease, a commit in each repository; `web` needs the trailer, `demo` doesn't.
    let trailer = format!("Writ: {id}");
    fs::write(api.join("login.rs"), "pub fn login() {}\n").unwrap();
    writ_ok(
        &daemon,
        &root,
        &["git", "-C", "api", "switch", "-q", "-c", "agent/login"],
    );
    writ_ok(&daemon, &root, &["git", "-C", "api", "add", "-A"]);
    writ_ok(
        &daemon,
        &root,
        &["git", "-C", "api", "commit", "-q", "-m", "Login route"],
    );
    let web = root.join("web");
    fs::write(web.join("button.html"), "<button>Log in</button>\n").unwrap();
    writ_ok(
        &daemon,
        &root,
        &["git", "-C", "web", "switch", "-q", "-c", "agent/login"],
    );
    writ_ok(&daemon, &root, &["git", "-C", "web", "add", "-A"]);
    let out = writ(
        &daemon,
        &root,
        &["git", "-C", "web", "commit", "-q", "-m", "Login button"],
    );
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(&format!(
            "writ: repo web needs a `Writ: {id}` trailer in the commit message"
        )),
        "{}",
        stderr(&out)
    );
    writ_ok(
        &daemon,
        &root,
        &[
            "git",
            "-C",
            "web",
            "commit",
            "-q",
            "-m",
            "Login button",
            "--trailer",
            &trailer,
        ],
    );
    let api_head = git_ok(&daemon, &api, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    let web_head = git_ok(&daemon, &web, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    assert_eq!(
        ledger(&daemon, &id),
        [
            ("demo".to_owned(), api_head.clone()),
            ("web".to_owned(), web_head.clone())
        ]
    );
    // Both pushed through the daemon, by `origin` as the agent would say it.
    writ_ok(
        &daemon,
        &root,
        &["git", "-C", "api", "fetch", "-q", "origin"],
    );
    writ_ok(
        &daemon,
        &root,
        &[
            "git",
            "-C",
            "api",
            "push",
            "-q",
            "origin",
            "HEAD:refs/heads/agent/login-api",
        ],
    );
    writ_ok(
        &daemon,
        &root,
        &["git", "-C", "web", "fetch", "-q", "origin"],
    );
    writ_ok(
        &daemon,
        &root,
        &[
            "git",
            "-C",
            "web",
            "push",
            "-q",
            "origin",
            "HEAD:refs/heads/agent/login-web",
        ],
    );
    let upstream = daemon.remote.repo("demo");
    assert_eq!(
        git_ok(
            &daemon,
            &upstream,
            &["rev-parse", "refs/heads/agent/login-api"]
        )
        .trim(),
        api_head
    );
    assert_eq!(
        git_ok(
            &daemon,
            &upstream,
            &["rev-parse", "refs/heads/agent/login-web"]
        )
        .trim(),
        web_head
    );

    // A phase marked and the lease closed at the root: the run in the workspace's timings
    // file, under both repositories.
    let out = writ_ok(&daemon, &root, &["mark", "checks"]);
    assert!(
        out.contains(&format!("Marked the end of checks under lease {id}")),
        "{out}"
    );
    let out = writ_ok(&daemon, &root, &["close", "--summary", "Login in both"]);
    let timings = root.join(".claude/skills/writ-workspace/timings.md");
    assert!(
        out.contains(&format!("Recorded in {}", timings.display())),
        "{out}"
    );
    let text = fs::read_to_string(&timings).unwrap();
    assert!(text.contains("\n## demo + web\n"), "{text}");
    assert!(text.contains(&format!(" {id}: used ")), "{text}");

    // Undone in one repository only: refused, the root named.
    let out = writ(&daemon, &api, &["init", "--undo"]);
    refused(
        &out,
        &format!(
            "this repository was wired with the workspace at {}: run `writ init --undo` there",
            root.display()
        ),
    );
    // Undone at the root: every repository and the root as before, the timings kept.
    let out = writ_ok(&daemon, &root, &["init", "--undo"]);
    assert!(
        out.contains("  api: wiring removed (wrapper mode)."),
        "{out}"
    );
    assert!(
        out.contains("  web: wiring removed (wrapper mode)."),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "Kept {}: what the agent learned",
            timings.display()
        )),
        "{out}"
    );
    let after = state(&daemon, &root, &["api", "web"]);
    assert_eq!(after.1, before.1, "every repository's config and exclude");
    let kept = [
        ".claude",
        ".claude/skills",
        ".claude/skills/writ-workspace",
        ".claude/skills/writ-workspace/timings.md",
    ];
    let mut expected: Vec<String> = before.0.clone();
    // The commits made the files the agent added.
    expected.extend(["api/login.rs", "web/button.html"].map(str::to_owned));
    expected.extend(kept.map(str::to_owned));
    expected.sort();
    assert_eq!(after.0, expected);
    assert!(!api.join(".git/writ").exists() && !web.join(".git/writ").exists());
    let out = writ(&daemon, &root, &["git", "-C", "api", "status"]);
    refused(&out, "this repo isn't wired for Writ");
}

#[test]
fn a_meta_repository_at_the_root_is_wired_whole_only_when_named_and_undone_exactly() {
    let (daemon, _, root) = workspace();
    // The root is a repository too, ignoring its children.
    git_ok(&daemon, &root, &["init", "-q", "-b", "main"]);
    fs::write(
        root.join(".gitignore"),
        "/api/\n/web/\n/notes/\n/link\n/.cache/\n",
    )
    .unwrap();
    git_ok(
        &daemon,
        &root,
        &["config", "user.email", "meta@operator.example"],
    );
    let before = state(&daemon, &root, &[".", "api", "web"]);

    // Not named: left out (it is never wired by default).
    let out = writ_ok(
        &daemon,
        &root,
        &[
            "init", "--agents", "none", "--repo", "api=demo", "--repo", "web=-",
        ],
    );
    assert!(out.contains("\n  api  repo demo"), "{out}");
    assert!(
        out.contains("Left out: . (this folder's own repository).\nLeft out: web."),
        "{out}"
    );
    let out = writ(&daemon, &root, &["git", "status"]);
    refused(&out, "is a Writ workspace, not a repository wired for Writ");
    writ_ok(&daemon, &root, &["init", "--undo"]);
    assert_eq!(state(&daemon, &root, &[".", "api", "web"]), before);

    // Named, in whole-repo mode: plain git in each is the agent's.
    let out = writ_ok(
        &daemon,
        &root,
        &[
            "init",
            "--whole-repo",
            "--agents",
            "claude",
            "--email",
            "agent@writ",
            "--repo",
            ".=web",
            "--repo",
            "api=demo",
            "--repo",
            "web=-",
        ],
    );
    assert!(
        out.contains("(whole repo: plain git in each is the agent's)"),
        "{out}"
    );
    assert_eq!(
        git_ok(&daemon, &root, &["config", "writ.repo"]).trim(),
        "web"
    );
    assert_eq!(
        git_ok(&daemon, &root.join("api"), &["config", "writ.repo"]).trim(),
        "demo"
    );
    assert_eq!(
        git_ok(&daemon, &root, &["config", "user.email"]).trim(),
        "agent@writ"
    );
    // The root's repository ignores what the workspace added.
    let exclude = fs::read_to_string(root.join(".git/info/exclude")).unwrap();
    assert!(exclude.contains("\n/.writ-workspace\n"), "{exclude}");
    assert!(
        exclude.contains("\n/.claude/skills/writ-workspace/\n"),
        "{exclude}"
    );
    let status = git_ok(&daemon, &root, &["status", "--porcelain", "--ignored=no"]);
    assert_eq!(
        status, "?? .gitignore\n",
        "only the operator's own file is new"
    );
    // The root's repository is the one `writ git` works in at the root.
    assert_eq!(
        writ_ok(&daemon, &root, &["git", "config", "writ.repo"]).trim(),
        "web"
    );

    // Undone: the three repositories and the root exactly as before.
    let out = writ_ok(&daemon, &root, &["init", "--undo"]);
    assert!(
        out.contains("  . (this folder's own repository): wiring removed (whole-repo mode)."),
        "{out}"
    );
    assert!(
        out.contains("  api: wiring removed (whole-repo mode)."),
        "{out}"
    );
    let after = state(&daemon, &root, &[".", "api", "web"]);
    assert_eq!(after.1, before.1, "every repository's config and exclude");
    let mut expected = before.0.clone();
    expected.extend(
        [
            ".claude",
            ".claude/skills",
            ".claude/skills/writ-workspace",
            ".claude/skills/writ-workspace/timings.md",
        ]
        .map(str::to_owned),
    );
    expected.sort();
    assert_eq!(after.0, expected);
}
