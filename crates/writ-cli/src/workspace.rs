//! Multi-repo workspaces (`docs/architecture/clients.md`, workspaces): a folder whose child
//! repositories, one level down, one agent at the folder works on. `writ init` there (no repo
//! named) wires each child as `writ init <repo>` would, without a skill of its own, installs
//! the `writ-workspace` skill at the root, and records the workspace in `<root>/.writ-workspace`
//! (git config format), so `writ init --undo` at the root takes every repository back.
//!
//! The record is in the working folder, the agent's to write too: it is read bounded (a
//! regular file, never a link, at most [`MAX_RECORD`] bytes, at most [`MAX_MEMBERS`]
//! repositories), each repository a folder right under the root ([`valid_dir`]), and
//! `--undo` takes back only a repository whose own record names this root.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use writ_core::names::{RepoName, TicketId};

use crate::{display, wiring};

/// The workspace's record, at its root.
pub const RECORD: &str = ".writ-workspace";

/// The largest record read: past it, it isn't one `writ init` wrote.
pub const MAX_RECORD: u64 = 64 * 1024;

/// The most repositories a workspace holds (and `writ init` wires at once).
pub const MAX_MEMBERS: usize = 256;

/// The longest folder name taken as a repository's.
const MAX_DIR_NAME: usize = 255;

/// One repository of a workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Its folder, right under the root (`.`: the root's own repository).
    pub dir: String,
    /// Its name in the daemon's registry.
    pub repo: RepoName,
}

/// What `writ init` recorded at a workspace root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    pub root: PathBuf,
    /// In the order they were wired.
    pub members: Vec<Member>,
    /// The lease every repository is pinned to (`writ init --lease`).
    pub lease: Option<TicketId>,
    /// Every entry, for the skill's (`skill.*`).
    pub entries: Vec<(String, String)>,
}

impl Workspace {
    /// The values of `key`, in order.
    pub fn values<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.entries
            .iter()
            .filter(move |(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The timings file the workspace's skill uses.
    pub fn timings(&self) -> Option<PathBuf> {
        self.values("skill.timings").next().map(PathBuf::from)
    }

    /// The folder of a member.
    pub fn path(&self, member: &Member) -> PathBuf {
        if member.dir == "." {
            self.root.clone()
        } else {
            self.root.join(&member.dir)
        }
    }

    /// The repositories, as `writ git` at the root and `writ policy` list them: one line each.
    pub fn listing(&self) -> String {
        let width = self
            .members
            .iter()
            .map(|m| m.dir.chars().count())
            .max()
            .unwrap_or(0);
        self.members
            .iter()
            .map(|m| {
                format!(
                    "  {:<width$}  repo {}  (writ git -C {} …)",
                    display::clean(&m.dir),
                    m.repo,
                    display::clean(&m.dir)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// `<root>/.writ-workspace`.
pub fn record_path(root: &Path) -> PathBuf {
    root.join(RECORD)
}

/// Whether `name` is a folder name a workspace repository may have: `.` (the root's own
/// repository), or one plain name (no `/`, not hidden, no control character, at most 255
/// bytes).
pub fn valid_dir(name: &str) -> bool {
    name == "."
        || (!name.is_empty()
            && name.len() <= MAX_DIR_NAME
            && !name.starts_with('.')
            && !name.contains('/')
            && !name.chars().any(char::is_control))
}

/// The workspace recorded at `root`, if there is one.
pub fn load(root: &Path) -> anyhow::Result<Option<Workspace>> {
    let path = record_path(root);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    if !meta.file_type().is_file() {
        bail!(
            "{} is not a workspace record (a link, or not a regular file)",
            path.display()
        );
    }
    if meta.len() > MAX_RECORD {
        bail!(
            "{} is larger than {MAX_RECORD} bytes: not a workspace record",
            path.display()
        );
    }
    let entries = wiring::read_file(root, &path)?;
    parse(root, entries).map(Some)
}

/// A record's entries, checked.
fn parse(root: &Path, entries: Vec<(String, String)>) -> anyhow::Result<Workspace> {
    let invalid = |why: &str| {
        anyhow::anyhow!(
            "{} is not a workspace record: {why}",
            root.join(RECORD).display()
        )
    };
    let mut members: Vec<Member> = Vec::new();
    let mut lease = None;
    for (key, value) in &entries {
        if let Some(dir) = key
            .strip_prefix("member.")
            .and_then(|k| k.strip_suffix(".repo"))
        {
            if !valid_dir(dir) {
                return Err(invalid(&format!(
                    "{} is not a folder right under the root",
                    display::clean(dir)
                )));
            }
            if members.iter().any(|m| m.dir == dir) {
                return Err(invalid(&format!("{} twice", display::clean(dir))));
            }
            if members.len() >= MAX_MEMBERS {
                return Err(invalid(&format!("more than {MAX_MEMBERS} repositories")));
            }
            let repo = value.parse().map_err(|e: writ_core::names::NameError| {
                invalid(&format!(
                    "{}: {}",
                    display::clean(dir),
                    display::clean(&e.to_string())
                ))
            })?;
            members.push(Member {
                dir: dir.to_owned(),
                repo,
            });
        } else if key == "writ.lease" {
            lease = Some(value.parse().map_err(|e: writ_core::names::NameError| {
                invalid(&format!("writ.lease: {}", display::clean(&e.to_string())))
            })?);
        }
    }
    Ok(Workspace {
        root: root.to_path_buf(),
        members,
        lease,
        entries,
    })
}

/// The workspace `dir` is in: the one recorded at `dir`, or the one the repository at `dir`
/// was wired from (its `writ.workspace`), when that root's record still lists it.
pub fn find(dir: &Path) -> Option<Workspace> {
    if let Ok(Some(workspace)) = load(dir) {
        return Some(workspace);
    }
    let wired = wiring::load(dir).ok()??;
    let root = wired.workspace?;
    let workspace = load(&root).ok()??;
    let common = std::fs::canonicalize(&wired.common_dir).ok()?;
    workspace
        .members
        .iter()
        .any(|m| {
            wiring::common_dir(&workspace.path(m))
                .ok()
                .and_then(|c| std::fs::canonicalize(c).ok())
                .is_some_and(|c| c == common)
        })
        .then_some(workspace)
}

/// A folder left aside, shown escaped, and why.
pub type Aside = (String, &'static str);

/// The folders right under `root` that are git repositories of their own (sorted), and the
/// ones left aside with why (a link, a name `writ init` won't take).
pub fn children(root: &Path) -> anyhow::Result<(Vec<String>, Vec<Aside>)> {
    let mut found = Vec::new();
    let mut aside = Vec::new();
    let entries =
        std::fs::read_dir(root).with_context(|| format!("cannot read {}", root.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("cannot read {}", root.display()))?;
        let path = entry.path();
        let name = entry.file_name();
        let shown = display::clean(&name.to_string_lossy());
        if name.as_encoded_bytes().starts_with(b".") {
            continue;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let has_git = std::fs::symlink_metadata(path.join(".git")).is_ok();
        if kind.is_symlink() {
            if has_git {
                aside.push((shown, "a link: wire the folder it points at"));
            }
            continue;
        }
        if !kind.is_dir() || !has_git {
            continue;
        }
        let Some(text) = name.to_str().filter(|n| valid_dir(n)) else {
            aside.push((
                shown,
                "a name writ init doesn't take (not UTF-8, or a control character)",
            ));
            continue;
        };
        if !is_top_level(&path) {
            aside.push((shown, "its .git isn't a repository git opens"));
            continue;
        }
        if found.len() >= MAX_MEMBERS {
            bail!(
                "more than {MAX_MEMBERS} repositories in {}: wire them in smaller folders",
                root.display()
            );
        }
        found.push(text.to_owned());
    }
    found.sort();
    aside.sort();
    Ok((found, aside))
}

/// Whether `dir` is the top of a git repository (its working tree's root).
pub fn is_top_level(dir: &Path) -> bool {
    let Ok(top) = wiring::git(dir, &["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    let top = PathBuf::from(top.trim_end_matches('\n'));
    match (std::fs::canonicalize(top), std::fs::canonicalize(dir)) {
        (Ok(top), Ok(dir)) => top == dir,
        _ => false,
    }
}

/// The registry name a repository gets by default: its `origin` URL's last part (without
/// `.git`), else its folder's name; none when neither is a registry name.
pub fn default_name(origin: Option<&str>, folder: &str) -> Option<RepoName> {
    let from_origin = origin.and_then(|url| {
        let url = url.trim_end_matches('/');
        let last = url.rsplit(['/', ':']).next()?;
        last.strip_suffix(".git").unwrap_or(last).parse().ok()
    });
    from_origin.or_else(|| folder.parse().ok())
}

/// `--repo <dir>=<name>`: a folder and its registry name, or `-` to leave it out.
pub fn parse_answer(text: &str) -> Result<(String, Option<RepoName>), String> {
    let Some((dir, name)) = text.rsplit_once('=') else {
        return Err(format!(
            "{}: give it as <dir>=<registry name> (or <dir>=- to leave it out)",
            display::clean(text)
        ));
    };
    let trimmed = dir.trim_end_matches('/');
    let dir = if trimmed.is_empty() { dir } else { trimmed };
    if !valid_dir(dir) {
        return Err(format!(
            "{}: not a folder right under the workspace root",
            display::clean(dir)
        ));
    }
    if name == "-" {
        return Ok((dir.to_owned(), None));
    }
    let repo = name
        .parse()
        .map_err(|e: writ_core::names::NameError| display::clean(&e.to_string()))?;
    Ok((dir.to_owned(), Some(repo)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repository_folder_is_one_plain_name_right_under_the_root() {
        for good in [".", "api", "web app", "a.b", "x=y"] {
            assert!(valid_dir(good), "{good}");
        }
        let long = "a".repeat(256);
        for bad in [
            "",
            "..",
            ".git",
            ".hidden",
            "a/b",
            "/abs",
            "a\nb",
            "a\u{1b}b",
            long.as_str(),
        ] {
            assert!(!valid_dir(bad), "{bad:?}");
        }
        assert!(valid_dir(&"a".repeat(255)));
    }

    #[test]
    fn the_default_name_is_origin_s_last_part_then_the_folder_s() {
        let name = |o: Option<&str>, f: &str| default_name(o, f).map(|n| n.to_string());
        assert_eq!(
            name(Some("git@github.com:me/api.git"), "x"),
            Some("api".into())
        );
        assert_eq!(
            name(Some("https://h/me/web-app/"), "x"),
            Some("web-app".into())
        );
        assert_eq!(
            name(Some("ssh://git@h:22/me/tools"), "x"),
            Some("tools".into())
        );
        assert_eq!(name(Some("git@h:lib.git"), "x"), Some("lib".into()));
        // An origin whose last part isn't a registry name: the folder's.
        assert_eq!(
            name(Some("https://h/me/.git"), "folder"),
            Some("folder".into())
        );
        assert_eq!(name(None, "folder"), Some("folder".into()));
        // Neither: no default, the answer must name it.
        assert_eq!(name(Some("https://h/-x"), "web app"), None);
    }

    #[test]
    fn repo_answers_are_read_strictly() {
        let ok = |t: &str| parse_answer(t).map(|(d, r)| (d, r.map(|r| r.to_string())));
        assert_eq!(ok("api=api"), Ok(("api".into(), Some("api".into()))));
        assert_eq!(ok("api/=web"), Ok(("api".into(), Some("web".into()))));
        assert_eq!(ok("a=b=c"), Ok(("a=b".into(), Some("c".into()))));
        assert_eq!(ok(".=meta"), Ok((".".into(), Some("meta".into()))));
        assert_eq!(ok("vendor=-"), Ok(("vendor".into(), None)));
        assert_eq!(
            ok("api"),
            Err("api: give it as <dir>=<registry name> (or <dir>=- to leave it out)".into())
        );
        assert_eq!(
            ok("../x=a"),
            Err("../x: not a folder right under the workspace root".into())
        );
        assert_eq!(
            ok("a/b=a"),
            Err("a/b: not a folder right under the workspace root".into())
        );
        assert_eq!(
            ok("api=-x"),
            Err("invalid repo name \"-x\": must not start with '.' or '-'".into())
        );
        assert_eq!(
            ok("api="),
            Err("invalid repo name \"\": must be 1 to 100 characters".into())
        );
    }

    #[test]
    fn a_hostile_record_is_refused_whole() {
        let root = Path::new("/w");
        let entry = |k: &str, v: &str| (k.to_owned(), v.to_owned());
        let good = parse(
            root,
            vec![
                entry("writ.lease", "wrt_01JD8X0000000000000000000A"),
                entry("member.api.repo", "api"),
                entry("member...repo", "meta"),
                entry(
                    "skill.timings",
                    "/w/.claude/skills/writ-workspace/timings.md",
                ),
            ],
        )
        .unwrap();
        assert_eq!(good.members.len(), 2);
        assert_eq!(good.path(&good.members[1]), PathBuf::from("/w"));
        assert_eq!(
            good.timings(),
            Some(PathBuf::from("/w/.claude/skills/writ-workspace/timings.md"))
        );
        for (entries, why) in [
            (
                vec![entry("member.../x.repo", "a")],
                "../x is not a folder right under the root",
            ),
            (
                vec![entry("member./etc.repo", "a")],
                "/etc is not a folder right under the root",
            ),
            (
                vec![entry("member..git.repo", "a")],
                ".git is not a folder right under the root",
            ),
            (
                vec![entry("member.a.repo", "x"), entry("member.a.repo", "y")],
                "a twice",
            ),
            (
                vec![entry("member.a.repo", "-x")],
                "a: invalid repo name \"-x\": must not start with '.' or '-'",
            ),
            (vec![entry("writ.lease", "nope")], "writ.lease: invalid "),
        ] {
            let error = crate::error_of(parse(root, entries));
            assert!(
                error.starts_with(&format!(
                    "/w/.writ-workspace is not a workspace record: {why}"
                )),
                "{error}"
            );
        }
        let many: Vec<_> = (0..=MAX_MEMBERS)
            .map(|i| entry(&format!("member.r{i}.repo"), &format!("r{i}")))
            .collect();
        let error = crate::error_of(parse(root, many));
        assert!(error.ends_with("more than 256 repositories"), "{error}");
        let most: Vec<_> = (0..MAX_MEMBERS)
            .map(|i| entry(&format!("member.r{i}.repo"), &format!("r{i}")))
            .collect();
        assert_eq!(parse(root, most).unwrap().members.len(), MAX_MEMBERS);
    }

    #[test]
    fn a_record_that_is_a_link_or_too_large_is_not_read() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(load(root.path()).unwrap(), None);
        let elsewhere = root.path().join("elsewhere");
        std::fs::write(&elsewhere, "[member \"a\"]\n\trepo = a\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, record_path(root.path())).unwrap();
        let error = crate::error_of(load(root.path()));
        assert!(
            error.ends_with("is not a workspace record (a link, or not a regular file)"),
            "{error}"
        );
        std::fs::remove_file(record_path(root.path())).unwrap();
        let mut big = String::from("[writ]\n");
        while big.len() as u64 <= MAX_RECORD {
            big.push_str(
                "\tnote = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
            );
        }
        std::fs::write(record_path(root.path()), &big).unwrap();
        let error = crate::error_of(load(root.path()));
        assert!(
            error.ends_with("is larger than 65536 bytes: not a workspace record"),
            "{error}"
        );
    }
}
