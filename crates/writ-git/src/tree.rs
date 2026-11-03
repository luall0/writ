//! Tree objects (`<mode> <name>\0<raw id>` entries), parsed strictly: an entry git's own
//! `fsck` would refuse as a path (empty, `.`, `..`, a `/` in the name, a name twice, `.git` as
//! any filesystem reads it) makes the whole tree unreadable here, and so does a mode git
//! doesn't write ([`MODES`]).
//!
//! git reads any mode by its type bits (`canon_mode`): `40755` or `040000` is a directory to
//! it, `100664` a file. Reading only the modes git writes, and refusing the others, keeps this
//! walk from seeing a leaf where git sees a directory (and the files under it).

use std::collections::BTreeMap;

use crate::object::{HashAlgo, ObjectId};

/// Why a tree can't be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TreeError {
    #[error("an entry is cut short")]
    CutShort,
    #[error("an entry has an invalid mode")]
    Mode,
    /// A mode git reads but never writes (`40755`, zero-padded `040000`, `100664`…): git
    /// takes its type from the type bits, which a reader of the modes as written would miss.
    #[error("a tree entry has a non-standard mode")]
    NonStandardMode,
    #[error("an entry has an invalid name")]
    Name,
    #[error("a name appears twice")]
    Duplicate,
    /// An entry some filesystem reads as `.git`: checked out, it would be the repository's
    /// own directory (hooks, config).
    #[error("an entry is named .git")]
    DotGit,
}

/// The modes git writes, and the only ones read here: a file, an executable file, a
/// symbolic link, a directory, a submodule (gitlink).
pub const MODES: [&[u8]; 5] = [b"100644", b"100755", b"120000", b"40000", b"160000"];

/// The mode of a directory.
const TREE_MODE: &[u8] = b"40000";

/// What an entry points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A directory (mode `40000`).
    Tree,
    /// A file, a link, a submodule (its commit isn't walked). Its path is touched when it
    /// changes.
    Leaf,
}

/// One entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    /// The mode as written (a mode change is a change).
    pub mode: Vec<u8>,
    pub id: ObjectId,
}

/// A tree's entries by name.
pub type Entries = BTreeMap<Vec<u8>, Entry>;

/// Parses a tree's content.
pub fn parse(algo: HashAlgo, content: &[u8]) -> Result<Entries, TreeError> {
    let mut entries = Entries::new();
    let mut rest = content;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or(TreeError::CutShort)?;
        let (mode, after) = rest.split_at_checked(space).ok_or(TreeError::CutShort)?;
        let after = after.get(1..).ok_or(TreeError::CutShort)?;
        if mode.is_empty() || mode.len() > 6 || !mode.iter().all(|b| (b'0'..=b'7').contains(b)) {
            return Err(TreeError::Mode);
        }
        if !MODES.contains(&mode) {
            return Err(TreeError::NonStandardMode);
        }
        let nul = after
            .iter()
            .position(|&b| b == 0)
            .ok_or(TreeError::CutShort)?;
        let (name, after) = after.split_at_checked(nul).ok_or(TreeError::CutShort)?;
        let after = after.get(1..).ok_or(TreeError::CutShort)?;
        if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
            return Err(TreeError::Name);
        }
        if is_dotgit(name) {
            return Err(TreeError::DotGit);
        }
        let (raw, after) = after
            .split_at_checked(algo.raw_len())
            .ok_or(TreeError::CutShort)?;
        let kind = if mode == TREE_MODE {
            EntryKind::Tree
        } else {
            EntryKind::Leaf
        };
        let entry = Entry {
            kind,
            mode: mode.to_vec(),
            id: ObjectId::from_raw(algo, raw),
        };
        if entries.insert(name.to_vec(), entry).is_some() {
            return Err(TreeError::Duplicate);
        }
        rest = after;
    }
    Ok(entries)
}

/// Characters HFS+ ignores in a name (git's `is_hfs_dotgit`).
fn hfs_ignored(c: char) -> bool {
    matches!(
        c,
        '\u{200C}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{206A}'..='\u{206F}' | '\u{FEFF}'
    )
}

/// Whether some filesystem reads `name` as `.git` (git's `verify_path`): in any case, with
/// characters HFS+ ignores, with NTFS's trailing dots and spaces, an alternate data stream
/// (`.git::$INDEX_ALLOCATION`), its short name `git~1`, or behind a backslash (a separator on
/// NTFS).
pub fn is_dotgit(name: &[u8]) -> bool {
    let folded: String = String::from_utf8_lossy(name)
        .chars()
        .filter(|&c| !hfs_ignored(c))
        .collect::<String>()
        .to_ascii_lowercase();
    folded.split('\\').any(|component| {
        if component == "git~1" {
            return true;
        }
        let Some(rest) = component.strip_prefix(".git") else {
            return false;
        };
        let rest = rest.split(':').next().unwrap_or(rest);
        rest.chars().all(|c| c == '.' || c == ' ')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(mode: &str, name: &[u8], id: u8) -> Vec<u8> {
        let mut bytes = format!("{mode} ").into_bytes();
        bytes.extend_from_slice(name);
        bytes.push(0);
        bytes.extend_from_slice(&[id; 20]);
        bytes
    }

    #[test]
    fn parses_entries() {
        let mut content = entry("100644", b"README", 1);
        content.extend(entry("40000", b"src", 2));
        content.extend(entry("120000", b"link", 3));
        let entries = parse(HashAlgo::Sha1, &content).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[&b"src"[..]].kind, EntryKind::Tree);
        assert_eq!(entries[&b"README"[..]].kind, EntryKind::Leaf);
        assert_eq!(
            entries[&b"link"[..]].id.as_str(),
            "0303030303030303030303030303030303030303"
        );
        assert!(parse(HashAlgo::Sha1, b"").unwrap().is_empty());
    }

    #[test]
    fn refuses_malformed_trees() {
        let good = entry("100644", b"a", 1);
        let cases: Vec<(Vec<u8>, TreeError)> = vec![
            (good[..good.len() - 1].to_vec(), TreeError::CutShort),
            (b"100644 a".to_vec(), TreeError::CutShort),
            (b"100644".to_vec(), TreeError::CutShort),
            (entry("10064x", b"a", 1), TreeError::Mode),
            (entry("1006440", b"a", 1), TreeError::Mode),
            (entry("100644", b"", 1), TreeError::Name),
            (entry("100644", b".", 1), TreeError::Name),
            (entry("40000", b"..", 1), TreeError::Name),
            (entry("100644", b"a/b", 1), TreeError::Name),
            ([good.clone(), good].concat(), TreeError::Duplicate),
        ];
        for (content, expected) in cases {
            assert_eq!(
                parse(HashAlgo::Sha1, &content),
                Err(expected.clone()),
                "{expected}: {:?}",
                String::from_utf8_lossy(&content)
            );
        }
        for name in [
            &b".git"[..],
            b".GIT",
            b".Git.",
            b".git ",
            b".git. .",
            b".git::$INDEX_ALLOCATION",
            b"git~1",
            b"GIT~1",
            ".g\u{200c}it".as_bytes(),
            "\u{feff}.git".as_bytes(),
            b"a\\.git",
        ] {
            assert_eq!(
                parse(HashAlgo::Sha1, &entry("40000", name, 1)),
                Err(TreeError::DotGit),
                "{}",
                String::from_utf8_lossy(name)
            );
        }
        for name in [
            &b".gitignore"[..],
            b".github",
            b".gitmodules",
            b"git",
            b"x.git",
            b".git~1",
        ] {
            assert!(
                parse(HashAlgo::Sha1, &entry("100644", name, 1)).is_ok_and(|e| e.len() == 1),
                "{}",
                String::from_utf8_lossy(name)
            );
        }
        // A SHA-1 entry read as SHA-256 is cut short.
        assert_eq!(
            parse(HashAlgo::Sha256, &entry("100644", b"a", 1)),
            Err(TreeError::CutShort)
        );
    }

    #[test]
    fn only_the_modes_git_writes_are_read() {
        for (mode, kind) in [
            ("100644", EntryKind::Leaf),
            ("100755", EntryKind::Leaf),
            ("120000", EntryKind::Leaf),
            ("40000", EntryKind::Tree),
            // A submodule's commit is not a tree: its path is a leaf.
            ("160000", EntryKind::Leaf),
        ] {
            let entries = parse(HashAlgo::Sha1, &entry(mode, b"x", 1)).unwrap();
            assert_eq!(entries[&b"x"[..]].kind, kind, "{mode}");
            assert_eq!(entries[&b"x"[..]].mode, mode.as_bytes(), "{mode}");
        }
        // Modes git reads by their type bits but never writes: directories with permission
        // bits or zero-padded, files with other permissions, a link or a gitlink with bits,
        // types git doesn't know. Each would be a leaf to a reader of the mode as written.
        for mode in [
            "40755", "41777", "40644", "40001", "040000", "040755", "000644", "100664", "100600",
            "100000", "100777", "120777", "160644", "60000", "20000", "0", "000000", "4000",
        ] {
            assert_eq!(
                parse(HashAlgo::Sha1, &entry(mode, b"x", 1)),
                Err(TreeError::NonStandardMode),
                "{mode}"
            );
        }
        // The first bad entry refuses the whole tree, wherever it is.
        let mut content = entry("100644", b"a", 1);
        content.extend(entry("40755", b"b", 2));
        content.extend(entry("40000", b"c", 3));
        assert_eq!(
            parse(HashAlgo::Sha1, &content),
            Err(TreeError::NonStandardMode)
        );
        // Past six digits or with a digit that isn't octal, the mode isn't one at all.
        assert_eq!(
            parse(HashAlgo::Sha1, &entry("0040000", b"x", 1)),
            Err(TreeError::Mode)
        );
        assert_eq!(
            parse(HashAlgo::Sha1, &entry("40008", b"x", 1)),
            Err(TreeError::Mode)
        );
    }
}
