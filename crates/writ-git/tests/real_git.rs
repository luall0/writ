//! `writ-git` against the real `git`: commits it writes parse, the paths it says a commit
//! touches are the ones `writ_git::paths` computes, the id of a commit it signs is the one
//! `writ_git::signed` computes, and its trailers are the ones `writ_git::trailers` finds.
//! Both object formats (SHA-1 and SHA-256). Never the user's git configuration.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use writ_git::Commit;
use writ_git::object::ObjectType;
use writ_git::paths::{Evidence, touched};

struct Repo {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl Repo {
    fn new(format: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("repo");
        let repo = Self { _dir: dir, path };
        fs::create_dir_all(&repo.path).unwrap();
        repo.git(&["init", "-q", &format!("--object-format={format}")]);
        repo
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new("git");
        command
            .args(args)
            .current_dir(&self.path)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.path.parent().unwrap())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Agent")
            .env("GIT_AUTHOR_EMAIL", "agent@writ")
            .env("GIT_COMMITTER_NAME", "Agent")
            .env("GIT_COMMITTER_EMAIL", "agent@writ")
            .env("GIT_AUTHOR_DATE", "1700000000 +0000")
            .env("GIT_COMMITTER_DATE", "1700000000 +0000");
        command
    }

    fn git(&self, args: &[&str]) -> String {
        let out = self.command(args).output().unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn git_bytes(&self, args: &[&str]) -> Vec<u8> {
        let out = self.command(args).output().unwrap();
        assert!(out.status.success(), "git {args:?}");
        out.stdout
    }

    fn write(&self, path: &str, text: &str) {
        let file = self.path.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, text).unwrap();
    }

    fn commit(&self, message: &str) -> String {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", message]);
        self.head()
    }

    fn head(&self) -> String {
        self.git(&["rev-parse", "HEAD"]).trim().to_owned()
    }

    /// The commit's parents and every tree reachable from it and its parents: more than
    /// `writ-sign` sends, never less.
    fn evidence(&self, commit: &str) -> Evidence {
        let parents = self.git(&["log", "-1", "--format=%P", commit]);
        let parents: Vec<&str> = parents.split_whitespace().collect();
        let mut items = Vec::new();
        let mut trees = BTreeSet::new();
        for rev in std::iter::once(commit).chain(parents.iter().copied()) {
            if rev != commit {
                items.push((
                    ObjectType::Commit,
                    self.git_bytes(&["cat-file", "commit", rev]),
                ));
            }
            trees.insert(
                self.git(&["rev-parse", &format!("{rev}^{{tree}}")])
                    .trim()
                    .to_owned(),
            );
            for line in self.git(&["ls-tree", "-r", "-t", rev]).lines() {
                let mut fields = line.split_whitespace();
                if fields.nth(1) == Some("tree") {
                    trees.insert(fields.next().unwrap().to_owned());
                }
            }
        }
        for tree in trees {
            items.push((
                ObjectType::Tree,
                self.git_bytes(&["cat-file", "tree", &tree]),
            ));
        }
        Evidence::new(self.parse(commit).algo(), items)
    }

    fn parse(&self, commit: &str) -> Commit {
        Commit::parse(self.git_bytes(&["cat-file", "commit", commit])).unwrap()
    }

    /// What git says the commit touches: the diff to its first parent (a merge too), every
    /// path of a root commit.
    fn git_touched(&self, commit: &str) -> Vec<String> {
        let parents = self.git(&["log", "-1", "--format=%P", commit]);
        let first_parent = parents.split_whitespace().next().map(str::to_owned);
        let mut args = vec![
            "diff-tree",
            "-r",
            "--no-renames",
            "--name-only",
            "--no-commit-id",
        ];
        match &first_parent {
            Some(parent) => args.extend([parent.as_str(), commit]),
            None => args.extend(["--root", commit]),
        }
        let out = self.git(&args);
        let mut paths: Vec<String> = out.lines().map(str::to_owned).collect();
        paths.sort();
        paths.dedup();
        paths
    }
}

fn check_paths(repo: &Repo, commit: &str) -> Vec<String> {
    let ours = touched(&repo.parse(commit), &repo.evidence(commit)).unwrap();
    assert_eq!(ours, repo.git_touched(commit), "commit {commit}");
    ours
}

#[test]
fn touched_paths_are_git_s() {
    for format in ["sha1", "sha256"] {
        let repo = Repo::new(format);
        repo.write("README", "x\n");
        repo.write("src/auth/login.rs", "a\n");
        repo.write("src/billing/pay.rs", "b\n");
        let root = repo.commit("root");
        assert_eq!(
            check_paths(&repo, &root),
            ["README", "src/auth/login.rs", "src/billing/pay.rs"]
        );

        repo.write("src/auth/login.rs", "a2\n");
        repo.write("src/auth/oauth/callback.rs", "c\n");
        let change = repo.commit("change");
        assert_eq!(
            check_paths(&repo, &change),
            ["src/auth/login.rs", "src/auth/oauth/callback.rs"]
        );

        // A directory removed, a file becoming a directory, a mode change.
        fs::remove_dir_all(repo.path.join("src/billing")).unwrap();
        fs::remove_file(repo.path.join("README")).unwrap();
        repo.write("README/index.md", "r\n");
        use std::os::unix::fs::PermissionsExt;
        repo.write("src/auth/login.rs", "main\n");
        let login = repo.path.join("src/auth/login.rs");
        fs::set_permissions(&login, fs::Permissions::from_mode(0o755)).unwrap();
        let reshape = repo.commit("reshape");
        assert!(
            repo.git(&["ls-tree", "HEAD", "src/auth/login.rs"])
                .starts_with("100755")
        );
        assert_eq!(
            check_paths(&repo, &reshape),
            [
                "README",
                "README/index.md",
                "src/auth/login.rs",
                "src/billing/pay.rs"
            ]
        );

        // An empty commit touches nothing.
        let empty = repo.commit("empty");
        assert_eq!(check_paths(&repo, &empty), Vec::<String>::new());

        // A merge: what it brings into its branch, against its first parent (the side
        // branch's new file, and a conflict resolved by hand).
        repo.git(&["checkout", "-q", "-b", "side", &change]);
        repo.write("src/auth/login.rs", "side\n");
        repo.write("side.txt", "s\n");
        repo.commit("side");
        repo.git(&["checkout", "-q", "-"]);
        let out = repo
            .command(&["merge", "-q", "side", "-m", "merge"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "a conflict");
        repo.write("src/auth/login.rs", "resolved\n");
        repo.git(&["add", "-A"]);
        repo.git(&["commit", "-q", "--no-edit"]);
        let merge = repo.head();
        assert_eq!(repo.parse(&merge).parents().len(), 2);
        assert_eq!(
            check_paths(&repo, &merge),
            ["side.txt", "src/auth/login.rs"]
        );
    }
}

#[test]
fn a_missing_tree_leaves_the_paths_unknown() {
    let repo = Repo::new("sha1");
    repo.write("a/b/c.txt", "1\n");
    repo.commit("one");
    repo.write("a/b/c.txt", "2\n");
    let two = repo.commit("two");
    let commit = repo.parse(&two);
    let parent = repo.git(&["rev-parse", "HEAD~1"]).trim().to_owned();
    let subtree = repo.git(&["rev-parse", "HEAD:a/b"]).trim().to_owned();
    let tree = |rev: &str| repo.git_bytes(&["cat-file", "tree", rev]);
    // Everything but the new a/b tree.
    let items = vec![
        (
            ObjectType::Commit,
            repo.git_bytes(&["cat-file", "commit", &parent]),
        ),
        (ObjectType::Tree, tree("HEAD~1^{tree}")),
        (ObjectType::Tree, tree("HEAD^{tree}")),
        (ObjectType::Tree, tree("HEAD~1:a")),
        (ObjectType::Tree, tree("HEAD:a")),
        (ObjectType::Tree, tree("HEAD~1:a/b")),
    ];
    let error = touched(&commit, &Evidence::new(commit.algo(), items)).unwrap_err();
    assert_eq!(error.to_string(), format!("object {subtree} was not sent"));
}

#[test]
fn commits_git_writes_parse() {
    let repo = Repo::new("sha1");
    repo.write("f", "x\n");
    let id = repo.commit("Subject line\n\nBody.\n\nWrit: wrt_01JD8X0000000000000000000A\n");
    let commit = repo.parse(&id);
    assert_eq!(commit.committer_email(), "agent@writ");
    assert_eq!(commit.writ_trailers(), ["wrt_01JD8X0000000000000000000A"]);
    assert!(commit.parents().is_empty());
    // A commit with another encoding.
    repo.git(&["config", "i18n.commitEncoding", "ISO-8859-1"]);
    let id = repo.commit("latin");
    assert!(String::from_utf8_lossy(repo.parse(&id).bytes()).contains("\nencoding ISO-8859-1\n"));
}

/// A signing program that keeps the buffer git asks it to sign, and signs with a fixed text.
fn fake_signer(dir: &Path) -> (PathBuf, PathBuf, &'static str) {
    let signature =
        "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAA\nAAAA\n-----END SSH SIGNATURE-----\n";
    let kept = dir.join("buffer");
    let script = dir.join("fake-signer.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nfor last; do :; done\ncp \"$last\" {kept}\nprintf '%s' '{signature}' > \"$last.sig\"\n",
            kept = kept.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    (script, kept, signature)
}

#[test]
fn the_signed_id_is_the_commit_git_writes() {
    for format in ["sha1", "sha256"] {
        let repo = Repo::new(format);
        let (script, kept, signature) = fake_signer(repo.path.parent().unwrap());
        repo.git(&["config", "gpg.format", "ssh"]);
        repo.git(&["config", "gpg.ssh.program", script.to_str().unwrap()]);
        repo.git(&["config", "user.signingkey", "key::ssh-ed25519 AAAA test"]);
        repo.write("f", "1\n");
        repo.commit("first");
        for message in ["signed\n\nWrit: wrt_X", "second\n\nmore"] {
            repo.write("f", message);
            repo.git(&["add", "-A"]);
            repo.git(&["commit", "-q", "-S", "-m", message]);
            let buffer = Commit::parse(fs::read(&kept).unwrap()).unwrap();
            let ours = writ_git::signed::signed_id(&buffer, signature).unwrap();
            assert_eq!(ours.as_str(), repo.head(), "{format}");
            assert_eq!(
                writ_git::signed::signed_bytes(&buffer, signature).unwrap(),
                repo.git_bytes(&["cat-file", "commit", "HEAD"])
            );
        }
    }
}

#[test]
fn trailers_are_git_s() {
    let repo = Repo::new("sha1");
    let messages = [
        "S\n\nWrit: wrt_A\n",
        "S\n\nBody.\n\nWrit: wrt_A\nCo-authored-by: X <x@y>\n",
        "S\n\nWrit : wrt_A\n",
        "S\n\nWrit: wrt_A\n  continued\n",
        "Writ: wrt_A\n",
        "S\n\nSome text\nWrit: wrt_A\n",
        "S\n\nBody line\nSigned-off-by: A <a@x>\nWrit: wrt_A\n",
        "S\n\none\ntwo\nthree\nfour\nSigned-off-by: A <a@x>\n",
        "S\n\nWrit: wrt_A\n\nThanks.\n",
        "S\n\nwrit: wrt_A\nWRIT: wrt_B\n",
        "S\n\nWrit: wrt_A\n# a comment\n",
        "S\n\n(cherry picked from commit abc)\nWrit: wrt_A\n",
        "S\n\nWrit:wrt_A\n",
        "S\n\n Writ: wrt_A\n",
        "S\n\nWrit: wrt_A\n\n\n\n",
    ];
    for message in messages {
        let mut child = repo
            .command(&["interpret-trailers", "--parse", "--no-divider"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(message.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let git: Vec<String> = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        let ours: Vec<String> = writ_git::trailers::parse(message.as_bytes())
            .into_iter()
            .map(|t| format!("{}: {}", t.key, t.value))
            .collect();
        assert_eq!(ours, git, "{message:?}");
    }
}
