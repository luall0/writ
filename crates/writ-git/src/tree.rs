//! Tree objects (`<mode> <name>\0<raw id>` entries), parsed strictly: an entry git's own
//! `fsck` would refuse as a path (empty, `.`, `..`, a `/` in the name, a name twice) makes
//! the whole tree unreadable here.

use std::collections::BTreeMap;

use crate::object::{HashAlgo, ObjectId};

/// Why a tree can't be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TreeError {
    #[error("an entry is cut short")]
    CutShort,
    #[error("an entry has an invalid mode")]
    Mode,
    #[error("an entry has an invalid name")]
    Name,
    #[error("a name appears twice")]
    Duplicate,
}

/// What an entry points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A directory (mode `40000`).
    Tree,
    /// Anything else: a file, a link, a submodule. Its path is touched when it changes.
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
        let nul = after
            .iter()
            .position(|&b| b == 0)
            .ok_or(TreeError::CutShort)?;
        let (name, after) = after.split_at_checked(nul).ok_or(TreeError::CutShort)?;
        let after = after.get(1..).ok_or(TreeError::CutShort)?;
        if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
            return Err(TreeError::Name);
        }
        let (raw, after) = after
            .split_at_checked(algo.raw_len())
            .ok_or(TreeError::CutShort)?;
        let kind = if mode == b"40000" || mode == b"040000" {
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
        // A SHA-1 entry read as SHA-256 is cut short.
        assert_eq!(
            parse(HashAlgo::Sha256, &entry("100644", b"a", 1)),
            Err(TreeError::CutShort)
        );
    }
}
