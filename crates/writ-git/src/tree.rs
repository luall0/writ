//! Tree objects (`<mode> <name>\0<raw id>` entries), parsed strictly: an entry git's own
//! `fsck` would refuse as a path (empty, `.`, `..`, a `/` in the name, a name twice, `.git` as
//! any filesystem reads it) makes the whole tree unreadable here, and so does a mode git
//! doesn't write ([`MODES`]).
//!
//! git reads any mode by its type bits (`canon_mode`): `40755` or `040000` is a directory to
//! it, `100664` a file. Reading only the modes git writes, and refusing the others, keeps this
//! walk from seeing a leaf where git sees a directory (and the files under it).

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

/// An entry's mode: one of the five git writes ([`MODES`]), so a parsed entry holds no copy
/// of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `100644`.
    File,
    /// `100755`.
    Executable,
    /// `120000`.
    Link,
    /// `40000`.
    Tree,
    /// `160000` (gitlink).
    Submodule,
}

impl Mode {
    /// The mode as git writes it, if it is one of [`MODES`].
    fn read(bytes: &[u8]) -> Option<Self> {
        Some(match bytes {
            b"100644" => Self::File,
            b"100755" => Self::Executable,
            b"120000" => Self::Link,
            b"40000" => Self::Tree,
            b"160000" => Self::Submodule,
            _ => return None,
        })
    }

    /// The mode as written.
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::File => b"100644",
            Self::Executable => b"100755",
            Self::Link => b"120000",
            Self::Tree => TREE_MODE,
            Self::Submodule => b"160000",
        }
    }
}

/// An entry's id as its raw bytes, held in place: no allocation per entry (the review after
/// M7.6, G-10: a hex `String`, a mode `Vec` and a name `Vec` made a 16 MiB tree of short
/// names cost several times its bytes once parsed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawId {
    algo: HashAlgo,
    bytes: [u8; 32],
}

impl RawId {
    fn new(algo: HashAlgo, raw: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        for (to, from) in bytes.iter_mut().zip(raw) {
            *to = *from;
        }
        Self { algo, bytes }
    }

    /// The id, as the rest of the crate names objects.
    pub fn to_id(&self) -> ObjectId {
        let raw = self.bytes.get(..self.algo.raw_len()).unwrap_or_default();
        ObjectId::from_raw(self.algo, raw)
    }
}

/// One entry. Its name is the key it is found under, borrowed from the tree's content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    /// The mode as written (a mode change is a change).
    pub mode: Mode,
    pub id: RawId,
}

/// What one parsed entry holds in memory, its name borrowed: [`ENTRY_BYTES`] bytes beside
/// the tree's content, which is at least 28 bytes an entry (`40000 a\0` and a SHA-1). A
/// parsed tree is held in one vector sized up front, so it costs at most about twice the
/// bytes it was read from, whatever its names (the review after M7.6, G-10).
pub const ENTRY_BYTES: usize = std::mem::size_of::<(&[u8], Entry)>();

/// A tree's entries, sorted by name, the names borrowed from its content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entries<'a> {
    sorted: Vec<(&'a [u8], Entry)>,
}

impl<'a> Entries<'a> {
    /// No entries (no tree).
    pub fn new() -> Self {
        Self::default()
    }

    /// The entry named `name`.
    pub fn get(&self, name: &[u8]) -> Option<&Entry> {
        let found = self
            .sorted
            .binary_search_by(|(each, _)| (*each).cmp(name))
            .ok()?;
        self.sorted.get(found).map(|(_, entry)| entry)
    }

    /// The names, sorted.
    pub fn names(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.sorted.iter().map(|(name, _)| *name)
    }

    pub fn len(&self) -> usize {
        self.sorted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sorted.is_empty()
    }
}

/// The fewest bytes a tree entry takes in a tree's content: a mode, a space, a one-byte name,
/// its NUL, a raw SHA-1.
const MIN_ENTRY_LEN: usize = 5 + 1 + 1 + 1 + 20;

/// Parses a tree's content.
pub fn parse(algo: HashAlgo, content: &[u8]) -> Result<Entries<'_>, TreeError> {
    // Sized up front from the content's length: never more than one entry per
    // `MIN_ENTRY_LEN` bytes, and no copy left behind by growing.
    let mut sorted = Vec::with_capacity(content.len() / MIN_ENTRY_LEN);
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
        let mode = Mode::read(mode).ok_or(TreeError::NonStandardMode)?;
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
        let kind = if mode == Mode::Tree {
            EntryKind::Tree
        } else {
            EntryKind::Leaf
        };
        let entry = Entry {
            kind,
            mode,
            id: RawId::new(algo, raw),
        };
        sorted.push((name, entry));
        rest = after;
    }
    sorted.sort_unstable_by(|a, b| a.0.cmp(b.0));
    if sorted
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if a.0 == b.0))
    {
        return Err(TreeError::Duplicate);
    }
    Ok(Entries { sorted })
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
        // The short name takes NTFS's trailing dots and spaces as well (git's
        // `is_ntfs_dotgit`; the review after M7.6, G-8: `git~1.` and `GIT~1 ` were missed).
        let Some(rest) = component
            .strip_prefix(".git")
            .or_else(|| component.strip_prefix("git~1"))
        else {
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
        assert_eq!(entries.get(b"src").unwrap().kind, EntryKind::Tree);
        assert_eq!(entries.get(b"README").unwrap().kind, EntryKind::Leaf);
        assert_eq!(
            entries.get(b"link").unwrap().id.to_id().as_str(),
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
            b"git~1.",
            b"GIT~1 ",
            b"git~1. .",
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
            b"git~1x",
            b"git~1.x",
            b"git~10",
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

    /// The review after M7.6, G-10: each entry held its mode, its hex id and its name in
    /// allocations of their own, in a map's nodes: several times the tree's bytes. An entry
    /// is now a fixed few dozen bytes, in one vector sized from the content.
    #[test]
    fn a_parsed_tree_costs_at_most_twice_its_bytes() {
        const { assert!(ENTRY_BYTES <= 2 * MIN_ENTRY_LEN) };
        // The worst case: the shortest entries git allows, as many as fit in 1 MiB.
        let mut content = Vec::new();
        let mut n = 0u32;
        while content.len() < 1 << 20 {
            // Names of three bytes, each once, never `.`, `..` or with a `/` or a NUL.
            let letter = |k: u32| b'a' + u8::try_from(k % 26).unwrap();
            let name = [letter(n / 676), letter(n / 26), letter(n)];
            content.extend(entry("100644", &name, 1));
            n += 1;
            if n == 26 * 26 * 26 {
                break;
            }
        }
        let entries = parse(HashAlgo::Sha1, &content).unwrap();
        assert_eq!(entries.len(), usize::try_from(n).unwrap());
        let held = entries.sorted.capacity() * ENTRY_BYTES;
        assert!(
            held <= 2 * content.len(),
            "{held} for {} bytes",
            content.len()
        );
        // Sorted by name, found by name.
        let names: Vec<&[u8]> = entries.names().collect();
        assert!(names.windows(2).all(|w| w[0] < w[1]));
        assert!(entries.get(b"abc").is_some());
        assert!(entries.get(b"ab").is_none());
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
            let content = entry(mode, b"x", 1);
            let entries = parse(HashAlgo::Sha1, &content).unwrap();
            assert_eq!(entries.get(b"x").unwrap().kind, kind, "{mode}");
            assert_eq!(
                entries.get(b"x").unwrap().mode.as_bytes(),
                mode.as_bytes(),
                "{mode}"
            );
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
