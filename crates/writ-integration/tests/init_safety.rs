//! `writ init` made safe to run and to take back (the review after M7.6, `W-1` to `W-12`),
//! with the real `writ` and `git` and no daemon (wiring needs none): everything that can
//! refuse refuses before anything is written; an init stopped part way is taken back whole by
//! `--undo`; what it added comes back out byte for byte; an `origin` it can't send through the
//! daemon whole is refused, naming the fix; worktrees of one repository are wired once; a
//! global skill stays while another repository uses it; one `writ git` command names one
//! session; a record in a hostile place is refused, never waited on.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;
use writ_integration::binaries::bin;
use writ_integration::{stderr, stdout};

/// A throwaway host: the operator's home (its `.gitconfig`), the agent's Writ home, and
/// folders for repositories. No daemon: `writ init` reaches none.
struct Host {
    _dir: TempDir,
    /// The temporary directory, canonical (what git and `writ` print).
    root: PathBuf,
}

/// What a repository looks like from outside: every path in its working tree (with the
/// bytes of each file), its git config, its `exclude` file, whether a record is there, and the
/// host's list of wired repositories.
#[derive(Debug, PartialEq, Eq)]
struct State {
    tree: BTreeMap<String, Option<Vec<u8>>>,
    config: String,
    exclude: Option<Vec<u8>>,
    record: bool,
    listed: Option<String>,
}

impl Host {
    fn new() -> Self {
        writ_integration::tools::require();
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let host = Self { _dir: dir, root };
        fs::create_dir_all(host.home()).unwrap();
        fs::write(
            host.home().join(".gitconfig"),
            "[user]\n\tname = Operator\n\temail = me@operator.example\n[init]\n\tdefaultBranch \
             = main\n",
        )
        .unwrap();
        host
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn home(&self) -> PathBuf {
        self.root().join("home")
    }

    fn writ_home(&self) -> PathBuf {
        self.root().join("writ")
    }

    /// Plain git, as the operator runs it: the throwaway home's `.gitconfig`, no system config.
    fn git(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn git_ok(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.git(cwd, args);
        assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
        stdout(&out)
    }

    /// `writ` as the operator runs it in `cwd`, with no terminal, and `env` on top.
    fn writ_with(&self, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(bin("writ"));
        command
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home())
            .env("WRIT_HOME", self.writ_home())
            .env("WRIT_KNOWN_HOSTS", self.root().join("known_hosts"))
            .env("WRIT_URL", "ssh://127.0.0.1:2222")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::null());
        for (key, value) in env {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    fn writ(&self, cwd: &Path, args: &[&str]) -> Output {
        self.writ_with(cwd, args, &[])
    }

    fn writ_ok(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.writ(cwd, args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "writ {args:?}: {}{}",
            stdout(&out),
            stderr(&out)
        );
        stdout(&out)
    }

    /// A repository at `<root>/<path>` with one commit and `origin` on a remote.
    fn repo(&self, path: &str) -> PathBuf {
        let repo = self.root().join(path);
        fs::create_dir_all(&repo).unwrap();
        self.git_ok(&repo, &["init", "-q"]);
        let name = repo.file_name().unwrap().to_string_lossy().into_owned();
        let origin = format!("git@github.com:me/{name}.git");
        self.git_ok(&repo, &["remote", "add", "origin", &origin]);
        fs::write(repo.join("README"), "demo\n").unwrap();
        self.git_ok(&repo, &["add", "-A"]);
        self.git_ok(&repo, &["commit", "-q", "-m", "seed"]);
        repo
    }

    fn state(&self, repo: &Path) -> State {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                if entry.file_name() == ".git" {
                    continue;
                }
                let path = entry.path();
                let name = path.strip_prefix(root).unwrap().display().to_string();
                if entry.file_type().unwrap().is_dir() {
                    out.insert(name, None);
                    walk(root, &path, out);
                } else {
                    out.insert(name, Some(fs::read(&path).unwrap()));
                }
            }
        }
        let mut tree = BTreeMap::new();
        walk(repo, repo, &mut tree);
        let git_dir = repo.join(".git");
        State {
            tree,
            config: if git_dir.exists() {
                self.git_ok(repo, &["config", "--local", "--list"])
            } else {
                String::new()
            },
            exclude: fs::read(git_dir.join("info/exclude")).ok(),
            record: git_dir.join("writ").exists(),
            // Emptied once everything is taken back: as good as none.
            listed: fs::read_to_string(self.writ_home().join("repos"))
                .ok()
                .filter(|text| !text.is_empty()),
        }
    }
}

/// `--undo` keeps the timings file (what the agent learned), and so the folders that hold
/// it: checked to hold nothing else, then removed, for the rest to be compared with before.
fn drop_kept_timings(root: &Path) {
    let folder = root.join(".claude");
    let mut left = Vec::new();
    for dir in ["", "/skills", "/skills/writ"] {
        for entry in fs::read_dir(format!("{}{dir}", folder.display())).unwrap() {
            left.push(
                entry
                    .unwrap()
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .display()
                    .to_string(),
            );
        }
    }
    left.sort();
    assert_eq!(
        left,
        [
            ".claude/skills",
            ".claude/skills/writ",
            ".claude/skills/writ/timings.md"
        ]
    );
    fs::remove_dir_all(folder).unwrap();
}

/// A refusal: exit 1, the words on stderr.
fn refused(out: &Output, words: &str) {
    assert_eq!(out.status.code(), Some(1), "{}{}", stdout(out), stderr(out));
    assert!(
        stderr(out).contains(words),
        "{words}\nnot in:\n{}",
        stderr(out)
    );
}

#[test]
fn everything_that_can_refuse_refuses_before_anything_is_written() {
    let host = Host::new();
    let repo = host.repo("demo");
    let run = |args: &[&str], env: &[(&str, &str)], words: &str| {
        let before = host.state(&repo);
        let out = host.writ_with(&repo, args, env);
        refused(&out, words);
        refused(&out, "(nothing was wired)");
        assert_eq!(host.state(&repo), before, "{args:?}: nothing written");
    };
    let whole = ["init", "demo", "--whole-repo", "--agents", "claude,cursor"];
    let wrapper = ["init", "demo", "--agents", "claude,cursor"];

    // The second agent folder's SKILL.md is someone else's: refused before the first is made.
    let theirs = repo.join(".cursor/skills/writ/SKILL.md");
    fs::create_dir_all(theirs.parent().unwrap()).unwrap();
    fs::write(&theirs, "my own skill").unwrap();
    let before = host.state(&repo);
    let out = host.writ(&repo, &whole);
    refused(&out, ".cursor/skills/writ/SKILL.md exists and isn't Writ's");
    assert_eq!(host.state(&repo), before);
    fs::remove_dir_all(repo.join(".cursor")).unwrap();
    // The timings path taken by a folder.
    fs::create_dir_all(repo.join(".claude/skills/writ/timings.md")).unwrap();
    let before = host.state(&repo);
    let out = host.writ(&repo, &whole);
    refused(&out, "timings.md is there and isn't a timings file");
    assert_eq!(host.state(&repo), before);
    fs::remove_dir_all(repo.join(".claude")).unwrap();
    // AGENTS.md a folder, with --agents-md.
    fs::create_dir_all(repo.join("AGENTS.md")).unwrap();
    let out = host.writ(
        &repo,
        &[
            "init",
            "demo",
            "--whole-repo",
            "--agents",
            "none",
            "--agents-md",
        ],
    );
    refused(&out, "AGENTS.md is there and isn't a regular file");
    fs::remove_dir(repo.join("AGENTS.md")).unwrap();

    // An origin the daemon can't take whole: each refused, naming the command that fixes it.
    host.git_ok(
        &repo,
        &[
            "config",
            "remote.origin.pushurl",
            "https://github.com/me/demo.git",
        ],
    );
    run(
        &whole,
        &[],
        "`origin` has a push URL of its own (https://github.com/me/demo.git): git pushes \
         there, past the daemon. Remove it: `git config --unset-all remote.origin.pushurl`",
    );
    host.git_ok(&repo, &["config", "--unset-all", "remote.origin.pushurl"]);
    // ... set in the user's own config too.
    host.git_ok(
        &repo,
        &[
            "config",
            "--global",
            "remote.origin.pushurl",
            "git@elsewhere:me/demo.git",
        ],
    );
    run(
        &wrapper,
        &[],
        "`origin` has a push URL of its own (git@elsewhere:me/demo.git)",
    );
    host.git_ok(
        &repo,
        &["config", "--global", "--unset-all", "remote.origin.pushurl"],
    );
    host.git_ok(
        &repo,
        &[
            "config",
            "--add",
            "remote.origin.url",
            "git@gitlab.com:me/demo.git",
        ],
    );
    run(
        &whole,
        &[],
        "`origin` has 2 URLs (git@github.com:me/demo.git, git@gitlab.com:me/demo.git): git \
         pushes to each, and only one would go through the daemon. Keep one: `git remote \
         set-url --delete origin <url>`",
    );
    host.git_ok(
        &repo,
        &[
            "remote",
            "set-url",
            "--delete",
            "origin",
            "git@gitlab.com:me/demo.git",
        ],
    );
    host.git_ok(
        &repo,
        &[
            "remote",
            "set-url",
            "origin",
            "https://me:hunter2@github.com/me/demo.git",
        ],
    );
    let before = host.state(&repo);
    let out = host.writ(&repo, &whole);
    refused(
        &out,
        "`origin`'s URL holds a credential (https://<redacted>@github.com/me/demo.git)",
    );
    refused(
        &out,
        "`git remote set-url origin https://github.com/me/demo.git`",
    );
    assert!(!stderr(&out).contains("hunter2"), "{}", stderr(&out));
    assert!(!stdout(&out).contains("hunter2"), "{}", stdout(&out));
    assert_eq!(host.state(&repo), before);
    // A token standing as the user name is one too.
    host.git_ok(
        &repo,
        &[
            "remote",
            "set-url",
            "origin",
            "https://ghp_token@github.com/me/demo.git",
        ],
    );
    let out = host.writ(&repo, &wrapper);
    refused(
        &out,
        "holds a credential (https://<redacted>@github.com/me/demo.git)",
    );
    assert!(!stderr(&out).contains("ghp_token"), "{}", stderr(&out));
    host.git_ok(
        &repo,
        &["remote", "set-url", "origin", "git@github.com:me/demo.git"],
    );
    // A `writ` remote of the user's: refused in wrapper mode (git would push to both)...
    host.git_ok(
        &repo,
        &["remote", "add", "writ", "ssh://elsewhere.example/x.git"],
    );
    run(
        &wrapper,
        &[],
        "a `writ` remote is already set (ssh://elsewhere.example/x.git): writ init adds its \
         own, and git would push to both. Rename or remove yours (`git remote rename writ \
         <name>`)",
    );
    // ... and in whole-repo mode when it has a push URL of its own.
    host.git_ok(
        &repo,
        &[
            "config",
            "remote.writ.pushurl",
            "ssh://elsewhere.example/x.git",
        ],
    );
    run(&whole, &[], "a `writ` remote is already set");
    host.git_ok(&repo, &["remote", "remove", "writ"]);

    // Two sessions named: refused before anything is checked further.
    let a = "wrt_01JD8X0000000000000000000A";
    let b = "wrt_01JD8X0000000000000000000B";
    run(
        &["init", "demo", "--agents", "none", "--lease", a],
        &[("WRIT_SESSION", b)],
        &format!(
            "--lease {a}, but WRIT_SESSION names lease {b}: one wiring works under one session"
        ),
    );
    // WRIT_SESSION naming a lease this host has no session of.
    run(
        &["init", "demo", "--agents", "none", "--whole-repo"],
        &[("WRIT_SESSION", b)],
        &format!("WRIT_SESSION names lease {b}: no granted session for it on this host"),
    );

    // At a workspace: --global, and a member's origin, refused before anything is written.
    let folder = host.root().join("ws");
    let api = host.repo("ws/api");
    host.git_ok(
        &api,
        &[
            "config",
            "remote.origin.pushurl",
            "https://github.com/me/api.git",
        ],
    );
    let ws_before = host.state(&folder);
    let out = host.writ(
        &folder,
        &["init", "--repo", "api=api", "--agents", "claude"],
    );
    refused(&out, "api: `origin` has a push URL of its own");
    assert_eq!(host.state(&folder), ws_before);
    let config = host.git_ok(&api, &["config", "--local", "--list"]);
    assert!(!config.contains("writ."), "{config}");
    host.git_ok(&api, &["config", "--unset-all", "remote.origin.pushurl"]);
    let out = host.writ(
        &folder,
        &[
            "init", "--repo", "api=api", "--agents", "claude", "--global",
        ],
    );
    refused(
        &out,
        "--global at a workspace: its skill lists this folder's repositories",
    );
    assert_eq!(host.state(&folder), ws_before);
    assert!(!host.home().join(".claude").exists());

    // Everything allowed: it wires, and comes back whole.
    let before = host.state(&repo);
    host.writ_ok(&repo, &whole);
    host.writ_ok(&repo, &["init", "--undo"]);
    drop_kept_timings(&repo);
    assert_eq!(host.state(&repo), before);
}

/// What a stop part way says.
const PART_WAY: &str =
    "writ init stopped part way (`writ init --undo` here takes back what it did)";

#[test]
fn an_init_stopped_part_way_is_taken_back_whole_by_undo() {
    let host = Host::new();
    let repo = host.repo("demo");
    let listed =
        |host: &Host| fs::read_to_string(host.writ_home().join("repos")).unwrap_or_default();

    // Whole repo, its config locked: the record and the list hold it, `--undo` takes it back.
    let before = host.state(&repo);
    fs::write(repo.join(".git/config.lock"), "").unwrap();
    let out = host.writ(
        &repo,
        &["init", "demo", "--whole-repo", "--agents", "claude"],
    );
    refused(&out, PART_WAY);
    assert!(repo.join(".git/writ/config").is_file());
    assert!(
        listed(&host).contains(&format!("repo {}", repo.display())),
        "listed as soon as the record is there"
    );
    fs::remove_file(repo.join(".git/config.lock")).unwrap();
    host.writ_ok(&repo, &["init", "--undo"]);
    assert_eq!(
        host.state(&repo),
        before,
        "stopped before the skill: nothing kept"
    );

    // Wrapper mode, the timings file can't be written: both skills and their exclude lines
    // were, and all of it comes back out.
    fs::create_dir_all(repo.join(".claude/skills/writ/timings.md.tmp")).unwrap();
    let before = host.state(&repo);
    let out = host.writ(&repo, &["init", "demo", "--agents", "claude,cursor"]);
    refused(&out, PART_WAY);
    assert!(repo.join(".cursor/skills/writ/SKILL.md").is_file());
    let exclude = fs::read_to_string(repo.join(".git/info/exclude")).unwrap();
    assert!(exclude.contains("/.cursor/skills/writ/"), "{exclude}");
    // Run again: refused as wired, with the way back.
    let again = host.writ(&repo, &["init", "demo", "--agents", "claude"]);
    refused(&again, "`writ init --undo` first");
    host.writ_ok(&repo, &["init", "--undo"]);
    assert_eq!(host.state(&repo), before);
    fs::remove_dir_all(repo.join(".claude")).unwrap();

    // A workspace whose second repository's config is locked: the first wired whole, the
    // record and the list hold both, `--undo` at the root takes every one back.
    let folder = host.root().join("ws");
    let api = host.repo("ws/api");
    let web = host.repo("ws/web");
    let before = (host.state(&folder), host.state(&api), host.state(&web));
    fs::write(web.join(".git/config.lock"), "").unwrap();
    let out = host.writ(
        &folder,
        &[
            "init",
            "--repo",
            "api=api",
            "--repo",
            "web=web",
            "--whole-repo",
            "--agents",
            "claude",
        ],
    );
    refused(&out, PART_WAY);
    refused(&out, "wiring web");
    assert!(
        host.git_ok(&api, &["config", "--local", "--list"])
            .contains("writ.repo=api")
    );
    assert!(
        listed(&host).contains(&format!("workspace {}", folder.display())),
        "{}",
        listed(&host)
    );
    fs::remove_file(web.join(".git/config.lock")).unwrap();
    host.writ_ok(&folder, &["init", "--undo"]);
    assert!(!folder.join(".claude").exists(), "stopped before the skill");
    assert_eq!(
        (host.state(&folder), host.state(&api), host.state(&web)),
        before
    );
}

#[test]
fn what_writ_init_added_comes_back_out_byte_for_byte() {
    let host = Host::new();
    let repo = host.repo("demo");
    // A tracked AGENTS.md in CRLF with no final line break, and no exclude file at all.
    let agents = b"# Agents\r\nBe kind.".to_vec();
    fs::write(repo.join("AGENTS.md"), &agents).unwrap();
    host.git_ok(&repo, &["add", "AGENTS.md"]);
    host.git_ok(&repo, &["commit", "-q", "-m", "agents"]);
    fs::remove_file(repo.join(".git/info/exclude")).unwrap();
    let before = host.state(&repo);

    host.writ_ok(
        &repo,
        &["init", "demo", "--agents", "claude", "--agents-md"],
    );
    let pointed = fs::read(repo.join("AGENTS.md")).unwrap();
    assert!(pointed.starts_with(b"# Agents\r\nBe kind.\r\nGit goes through"));
    assert!(pointed.ends_with(b"\r\n"), "in the file's own line breaks");
    assert!(repo.join(".git/info/exclude").is_file());
    host.writ_ok(&repo, &["init", "--undo"]);
    drop_kept_timings(&repo);
    assert_eq!(fs::read(repo.join("AGENTS.md")).unwrap(), agents);
    assert!(
        !repo.join(".git/info/exclude").exists(),
        "made by writ init: gone"
    );
    assert_eq!(host.state(&repo), before);
    assert_eq!(
        host.git_ok(&repo, &["status", "--porcelain"]),
        "",
        "a clean tree"
    );
}

#[test]
fn a_push_rule_of_the_user_s_never_takes_origin_past_the_daemon() {
    let host = Host::new();
    // The operator pushes to GitHub over another URL: a common rule, shorter than origin.
    host.git_ok(
        host.root(),
        &[
            "config",
            "--global",
            "url.ssh://git@elsewhere.example/.pushInsteadOf",
            "git@github.com:",
        ],
    );
    let daemon = "ssh://git@127.0.0.1:2222/demo.git";
    let wrapped = host.repo("wrapped");
    let direct = host.git_ok(&wrapped, &["remote", "get-url", "--push", "origin"]);
    assert_eq!(direct.trim(), "ssh://git@elsewhere.example/me/wrapped.git");
    host.writ_ok(&wrapped, &["init", "demo", "--agents", "none"]);
    let pushed = host.writ_ok(&wrapped, &["git", "remote", "get-url", "--push", "origin"]);
    assert_eq!(pushed.trim(), daemon);
    let fetched = host.writ_ok(&wrapped, &["git", "remote", "get-url", "origin"]);
    assert_eq!(fetched.trim(), daemon);
    // Plain git, beside it, keeps the operator's own rule.
    let plain = host.git_ok(&wrapped, &["remote", "get-url", "--push", "origin"]);
    assert_eq!(plain, direct);

    let whole = host.repo("whole");
    host.writ_ok(
        &whole,
        &["init", "demo", "--whole-repo", "--agents", "none"],
    );
    let pushed = host.git_ok(&whole, &["remote", "get-url", "--push", "origin"]);
    assert_eq!(pushed.trim(), daemon, "plain git in a whole-repo clone");
    host.writ_ok(&whole, &["init", "--undo"]);
    let back = host.git_ok(&whole, &["remote", "get-url", "--push", "origin"]);
    assert_eq!(back.trim(), "ssh://git@elsewhere.example/me/whole.git");
}

#[test]
fn worktrees_of_one_repository_in_a_workspace_are_wired_once() {
    let host = Host::new();
    let folder = host.root().join("ws");
    let main = host.repo("ws/main");
    host.git_ok(&main, &["worktree", "add", "-q", "-b", "feat", "../feat"]);
    let before = (host.state(&folder), host.state(&main));
    // The worktree can't be named: it isn't one of the repositories found.
    let out = host.writ(
        &folder,
        &[
            "init",
            "--repo",
            "main=demo",
            "--repo",
            "feat=web",
            "--agents",
            "none",
        ],
    );
    refused(
        &out,
        "--repo feat: not a repository right under this folder (found: main)",
    );
    assert_eq!((host.state(&folder), host.state(&main)), before);
    let out = host.writ_ok(
        &folder,
        &["init", "--repo", "main=demo", "--agents", "none"],
    );
    assert!(
        out.contains(
            "Not wired: feat (a worktree of a repository already here (one git directory, one \
             wiring))."
        ),
        "{out}"
    );
    host.writ_ok(&folder, &["init", "--undo"]);
    assert_eq!((host.state(&folder), host.state(&main)), before);
}

#[test]
fn a_global_skill_stays_while_another_wired_repository_uses_it() {
    let host = Host::new();
    let a = host.repo("a");
    let b = host.repo("b");
    let skill = host.home().join(".claude/skills/writ/SKILL.md");
    host.writ_ok(&a, &["init", "demo", "--global", "--agents", "claude"]);
    assert!(skill.is_file());
    host.writ_ok(&b, &["init", "demo", "--global", "--agents", "claude"]);
    let out = host.writ_ok(&a, &["init", "--undo"]);
    assert!(
        out.contains(&format!(
            "Kept {}: another wired repository uses it ({}).",
            skill.display(),
            b.display()
        )),
        "{out}"
    );
    assert!(skill.is_file());
    let out = host.writ_ok(&b, &["skill", "update"]);
    assert!(out.contains("up to date"), "{out}");
    // The last one using it takes it back.
    host.writ_ok(&b, &["init", "--undo"]);
    assert!(!skill.exists());
    assert!(
        host.home().join(".claude/skills/writ/timings.md").is_file(),
        "what the agent learned stays"
    );
}

#[test]
fn one_writ_git_command_names_one_session_however_current_moves() {
    let host = Host::new();
    let repo = host.repo("demo");
    host.writ_ok(&repo, &["init", "demo", "--agents", "none"]);
    // Before any grant: `current`, pointing at nothing.
    let session = host.writ_ok(&repo, &["git", "config", "writ.session"]);
    assert!(session.trim().ends_with("sessions/current"), "{session}");
    let sessions = host.writ_home().join("sessions");
    let (a, b) = (
        "wrt_01JD8X0000000000000000000A",
        "wrt_01JD8X0000000000000000000B",
    );
    fs::create_dir_all(sessions.join(a)).unwrap();
    fs::create_dir_all(sessions.join(b)).unwrap();
    std::os::unix::fs::symlink(a, sessions.join("current")).unwrap();
    // `current` moves to B while the command runs: everything it runs still names A.
    let script = format!(
        "ln -sfn {b} '{}' && git config writ.session && git config user.signingkey && printf \
         '%s\\n' \"$GIT_SSH_COMMAND\"",
        sessions.join("current").display()
    );
    let out = host.writ_ok(&repo, &["exec", "--", "sh", "-c", &script]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert!(lines[0].ends_with(&format!("sessions/{a}")), "{out}");
    assert!(
        lines[1].ends_with(&format!("sessions/{a}/signing_key.pub")),
        "{out}"
    );
    assert!(lines[2].contains(&format!("sessions/{a}/key")), "{out}");
    assert_eq!(
        fs::read_link(sessions.join("current")).unwrap(),
        PathBuf::from(b),
        "it did move"
    );
    // The next command follows it.
    let session = host.writ_ok(&repo, &["git", "config", "writ.session"]);
    assert!(
        session.trim().ends_with(&format!("sessions/{b}")),
        "{session}"
    );
}

#[test]
fn a_record_in_a_hostile_place_is_refused_never_waited_on() {
    let host = Host::new();
    let repo = host.repo("demo");
    host.writ_ok(&repo, &["init", "demo", "--agents", "none"]);
    let record = repo.join(".git/writ/config");
    fs::remove_file(&record).unwrap();
    let made = Command::new("mkfifo").arg(&record).status().unwrap();
    assert!(made.success());
    // A FIFO: `git config -f` would wait on it for ever.
    for args in [
        &["git", "status"][..],
        &["init", "--undo"],
        &["exec", "--", "true"],
    ] {
        let out = host.writ(&repo, args);
        refused(
            &out,
            "writ/config is not a Writ wiring record (a link, or not a regular file)",
        );
    }
    fs::remove_file(&record).unwrap();
    std::os::unix::fs::symlink("/dev/zero", &record).unwrap();
    let out = host.writ(&repo, &["git", "status"]);
    refused(
        &out,
        "writ/config is not a Writ wiring record (a link, or not a regular file)",
    );
}
