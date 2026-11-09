//! The repositories `writ init` wired on this host (`<home>/repos`, M7): one line each,
//! `repo <path>` or `workspace <path>`, the absolute path of a repository's top or of a
//! workspace root. `writ init` adds its line, `writ init --undo` removes it; `writ init
//! --list`, `writ init --undo --all` and `writ skill update --all` read it, and the uninstall
//! asks them. It is an index only: what each one is (its mode, a workspace's repositories)
//! comes from its own record, as `--undo` reads it.
//!
//! The file is the user's, so an agent can write it: it is read bounded (larger than
//! [`MAX_BYTES`], it is refused whole; past [`MAX_ENTRIES`], the rest is skipped), and an
//! entry is used only if its path is absolute and normalized, at most [`MAX_PATH`] bytes, with
//! no control or hidden character, a directory there and not a link, holding `writ init`'s own
//! record of that kind. Anything else is skipped and named, escaped: nothing the file says can
//! make Writ act on what it didn't wire.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::{display, wiring, workspace};

/// The file, in Writ's home.
pub const FILE: &str = "repos";
/// The largest file read: past it, the file is refused whole.
pub const MAX_BYTES: u64 = 256 * 1024;
/// The most entries used; the rest are skipped.
pub const MAX_ENTRIES: usize = 4096;
/// The longest path an entry may name.
pub const MAX_PATH: usize = 4096;

/// What an entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Repo,
    Workspace,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Repo => "repo",
            Self::Workspace => "workspace",
        }
    }
}

/// One entry, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: Kind,
    pub path: PathBuf,
}

/// What reading the file gave: the entries to use, and the lines skipped with why (both
/// escaped for a terminal).
#[derive(Debug, Default)]
pub struct Listing {
    pub entries: Vec<Entry>,
    pub skipped: Vec<(String, String)>,
}

fn file(home: &Path) -> PathBuf {
    home.join(FILE)
}

/// The file's text: empty when there is none; refused whole when larger than [`MAX_BYTES`],
/// not a regular file, or not UTF-8.
fn read_text(home: &Path) -> anyhow::Result<String> {
    let path = file(home);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    if !metadata.is_file() {
        anyhow::bail!(
            "{} is not a regular file (a link?): not read",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .and_then(|f| f.take(MAX_BYTES.saturating_add(1)).read_to_end(&mut bytes))
        .with_context(|| format!("cannot read {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BYTES {
        anyhow::bail!(
            "{} is larger than {MAX_BYTES} bytes: not read (nothing is done from it)",
            path.display()
        );
    }
    String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8: not read", path.display()))
}

/// An entry's line, parsed: its kind and path, or why not (the path is only checked as
/// text here).
fn parse(line: &str) -> Result<Entry, &'static str> {
    let (kind, path) = match line.split_once(' ') {
        Some(("repo", path)) => (Kind::Repo, path),
        Some(("workspace", path)) => (Kind::Workspace, path),
        _ => return Err("not an entry (repo <path> or workspace <path>)"),
    };
    if path.len() > MAX_PATH {
        return Err("a path longer than Writ takes");
    }
    if path
        .chars()
        .any(|c| c.is_control() || writ_core::text::is_hidden_char(c))
    {
        return Err("a path with control or hidden characters");
    }
    let Some(relative) = path.strip_prefix('/') else {
        return Err("not an absolute path");
    };
    // On the text: `Path::components` drops a `.` and a trailing `/` silently.
    let normalized = !relative.is_empty()
        && relative
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..");
    if !normalized {
        return Err("not a normalized path (., .., // or a trailing /)");
    }
    Ok(Entry {
        kind,
        path: PathBuf::from(path),
    })
}

/// Whether `entry` is what `writ init` wired there: a directory, not a link, holding the
/// record of its kind (a repository wired on its own, not one of a workspace's).
fn check(entry: &Entry) -> Result<(), String> {
    let path = &entry.path;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => return Err("a link".to_owned()),
        Ok(m) if !m.is_dir() => return Err("not a directory".to_owned()),
        Ok(_) => {}
        Err(_) => return Err("not there any more".to_owned()),
    }
    let recorded = match entry.kind {
        Kind::Workspace => matches!(workspace::load(path), Ok(Some(found)) if found.root == *path),
        Kind::Repo => matches!(wiring::load(path), Ok(Some(_))) && workspace::find(path).is_none(),
    };
    if recorded {
        Ok(())
    } else {
        Err(format!(
            "holds no writ init record of a {}",
            entry.kind.as_str()
        ))
    }
}

/// The entries of the file, checked; each line skipped is named, escaped. Refused whole when
/// the file can't be trusted to be read at all.
pub fn read(home: &Path) -> anyhow::Result<Listing> {
    let text = read_text(home)?;
    let mut listing = Listing::default();
    for (n, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let shown = display::clean(line);
        if n >= MAX_ENTRIES {
            listing
                .skipped
                .push((shown, format!("past the first {MAX_ENTRIES} lines")));
            continue;
        }
        let entry = match parse(line) {
            Ok(entry) => entry,
            Err(why) => {
                listing.skipped.push((shown, why.to_owned()));
                continue;
            }
        };
        if listing.entries.contains(&entry) {
            continue;
        }
        match check(&entry) {
            Ok(()) => listing.entries.push(entry),
            Err(why) => listing.skipped.push((shown, why)),
        }
    }
    Ok(listing)
}

/// Rewrites the file with `edit` applied to its well-formed lines (a line that isn't one is
/// dropped): to a private temporary file beside it, then renamed into place.
fn rewrite(home: &Path, edit: impl FnOnce(&mut Vec<Entry>)) -> anyhow::Result<()> {
    let text = read_text(home).unwrap_or_default();
    let mut entries: Vec<Entry> = text.lines().filter_map(|l| parse(l).ok()).collect();
    edit(&mut entries);
    let mut out = String::new();
    for entry in entries.iter().take(MAX_ENTRIES) {
        out.push_str(&format!(
            "{} {}\n",
            entry.kind.as_str(),
            entry.path.display()
        ));
    }
    crate::session::create_private_dir(home)?;
    let path = file(home);
    let temporary = home.join(format!(".{FILE}.new"));
    let _ = std::fs::remove_file(&temporary);
    crate::session::write_private(&temporary, out.as_bytes())?;
    std::fs::rename(&temporary, &path).with_context(|| format!("cannot write {}", path.display()))
}

/// Adds `path` (once): `writ init` wired it. A path that couldn't be read back as an entry
/// (control characters…) is said and left out: the list can't name it.
pub fn add(home: &Path, kind: Kind, path: &Path) -> anyhow::Result<()> {
    let line = format!("{} {}", kind.as_str(), path.display());
    let Ok(entry) = parse(&line) else {
        eprintln!(
            "writ: {} is not on {}: its path can't be listed there (`writ init --undo` in it \
             still works)",
            display::clean(&path.display().to_string()),
            file(home).display()
        );
        return Ok(());
    };
    rewrite(home, |entries| {
        if !entries.contains(&entry) {
            entries.push(entry);
        }
    })
}

/// Removes `path`'s entries: `writ init --undo` took it back.
pub fn remove(home: &Path, path: &Path) -> anyhow::Result<()> {
    if !file(home).exists() {
        return Ok(());
    }
    rewrite(home, |entries| entries.retain(|e| e.path != path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_is_a_known_kind_and_a_clean_absolute_path() {
        assert_eq!(
            parse("repo /srv/omega code"),
            Ok(Entry {
                kind: Kind::Repo,
                path: PathBuf::from("/srv/omega code"),
            })
        );
        for (line, why) in [
            ("repos /a", "not an entry (repo <path> or workspace <path>)"),
            ("/a", "not an entry (repo <path> or workspace <path>)"),
            ("repo a/b", "not an absolute path"),
            (
                "repo /a/../etc",
                "not a normalized path (., .., // or a trailing /)",
            ),
            (
                "repo /a/./b",
                "not a normalized path (., .., // or a trailing /)",
            ),
            (
                "repo /a//b",
                "not a normalized path (., .., // or a trailing /)",
            ),
            (
                "repo /a/",
                "not a normalized path (., .., // or a trailing /)",
            ),
            (
                "repo /a\u{1b}[2Jb",
                "a path with control or hidden characters",
            ),
            (
                "repo /a\u{202e}b",
                "a path with control or hidden characters",
            ),
        ] {
            assert_eq!(parse(line), Err(why), "{line:?}");
        }
        let at = format!("repo /{}", "a".repeat(MAX_PATH - 1));
        assert!(parse(&at).is_ok());
        let past = format!("repo /{}", "a".repeat(MAX_PATH));
        assert_eq!(parse(&past), Err("a path longer than Writ takes"));
    }

    #[test]
    fn an_oversized_file_is_refused_whole_and_a_link_too() {
        let home = tempfile::tempdir().unwrap();
        let at = "x".repeat(usize::try_from(MAX_BYTES).unwrap());
        std::fs::write(home.path().join(FILE), &at).unwrap();
        let listing = read(home.path()).unwrap();
        assert_eq!(listing.entries, []);
        std::fs::write(home.path().join(FILE), format!("{at}x")).unwrap();
        let error = crate::error_of(read(home.path()));
        assert!(
            error.ends_with(&format!(
                "is larger than {MAX_BYTES} bytes: not read (nothing is done from it)"
            )),
            "{error}"
        );
        std::fs::remove_file(home.path().join(FILE)).unwrap();
        let elsewhere = home.path().join("elsewhere");
        std::fs::write(&elsewhere, "repo /tmp\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.path().join(FILE)).unwrap();
        let error = crate::error_of(read(home.path()));
        assert!(
            error.ends_with("is not a regular file (a link?): not read"),
            "{error}"
        );
    }

    #[test]
    fn a_line_that_names_nothing_wired_is_skipped_and_named_escaped() {
        let home = tempfile::tempdir().unwrap();
        let plain = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join(FILE),
            format!(
                "repo {}\nworkspace /nowhere/at/all\nrepo /a\u{1b}[31m\n",
                plain.path().display()
            ),
        )
        .unwrap();
        let listing = read(home.path()).unwrap();
        assert_eq!(listing.entries, []);
        let skipped: Vec<(&str, &str)> = listing
            .skipped
            .iter()
            .map(|(line, why)| (line.as_str(), why.as_str()))
            .collect();
        let plain_line = format!("repo {}", plain.path().display());
        assert_eq!(
            skipped,
            [
                (plain_line.as_str(), "holds no writ init record of a repo"),
                ("workspace /nowhere/at/all", "not there any more"),
                (
                    "repo /a\\u{1b}[31m",
                    "a path with control or hidden characters"
                ),
            ]
        );
    }

    #[test]
    fn entries_are_added_once_and_removed() {
        let home = tempfile::tempdir().unwrap();
        let (a, b) = (Path::new("/w/a"), Path::new("/w/b b"));
        add(home.path(), Kind::Repo, a).unwrap();
        add(home.path(), Kind::Workspace, b).unwrap();
        add(home.path(), Kind::Repo, a).unwrap();
        let text = std::fs::read_to_string(home.path().join(FILE)).unwrap();
        assert_eq!(text, "repo /w/a\nworkspace /w/b b\n");
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(home.path().join(FILE))
                .unwrap()
                .permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
        remove(home.path(), a).unwrap();
        let text = std::fs::read_to_string(home.path().join(FILE)).unwrap();
        assert_eq!(text, "workspace /w/b b\n");
        // A path the list can't hold is left out, not written.
        add(home.path(), Kind::Repo, Path::new("/w/x\ny")).unwrap();
        let text = std::fs::read_to_string(home.path().join(FILE)).unwrap();
        assert_eq!(text, "workspace /w/b b\n");
    }
}
