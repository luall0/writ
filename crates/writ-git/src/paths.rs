//! The paths a commit touches, for `paths_check` (`docs/lease-model.md`, rules).
//!
//! The daemon has no copy of the agent's repository when it signs (the commit isn't even
//! written yet), so `writ-sign` sends the objects the comparison needs: the first parent
//! commit and the trees that differ. Nothing in them is believed: each object's id is
//! computed here from its bytes ([`Evidence`]), and only the objects the commit's own ids lead
//! to are read. An agent can leave an object out (the paths are then unknown, which `deny`
//! refuses) but can't make a path look untouched: a tree that isn't the one named has another
//! id.
//!
//! A commit touches the paths that differ from its first parent; a root commit, every path in
//! its tree. A merge is no exception: what it brings into its branch is checked, including
//! what comes from the other parents (`git diff <merge>^1 <merge>`), so a merge can't carry in
//! files the lease doesn't cover.
//!
//! The walk is bounded whatever the trees: it visits at most [`MAX_ENTRIES`] entries, lists
//! at most [`MAX_PATHS`] paths, follows at most [`MAX_DEPTH`] levels, builds no path longer
//! than [`MAX_PATH_LEN`] bytes, and at most [`MAX_PATH_BYTES`] bytes of paths in all (so trees
//! that share subtrees, or long names, can't make it use more memory than that).

use std::collections::{BTreeSet, HashMap};

use crate::commit::Commit;
use crate::object::{HashAlgo, ObjectId, ObjectType};
use crate::tree::{self, EntryKind, TreeError};

/// Tree entries the walk may visit, whatever the trees.
pub const MAX_ENTRIES: usize = 1_000_000;

/// Paths a commit may touch here; past it, its paths are unknown.
pub const MAX_PATHS: usize = 100_000;

/// The deepest directory the walk follows.
pub const MAX_DEPTH: usize = 256;

/// The longest path the walk builds, in bytes (Linux's `PATH_MAX`).
pub const MAX_PATH_LEN: usize = 4096;

/// The bytes of every path the walk builds, files and directories, added up.
pub const MAX_PATH_BYTES: usize = 64 * 1024 * 1024;

/// Why the touched paths can't be computed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathsError {
    #[error("object {0} was not sent")]
    Missing(ObjectId),
    #[error("parent {0} is not a commit")]
    Parent(ObjectId),
    #[error("tree {0} is malformed: {1}")]
    Tree(ObjectId, TreeError),
    #[error("the commit's trees have too many entries to check")]
    TooManyEntries,
    #[error("the commit touches too many paths to check")]
    TooManyPaths,
    #[error("the commit's trees are nested too deep to check")]
    TooDeep,
    #[error("the commit has a path longer than {MAX_PATH_LEN} bytes")]
    PathTooLong,
    #[error("the commit's paths are too long in all to check")]
    TooManyBytes,
}

/// Objects sent along with a commit, by the id computed from their bytes. Objects the
/// collision detection refuses, and types other than commits and trees, are left out.
#[derive(Debug, Default)]
pub struct Evidence {
    objects: HashMap<ObjectId, (ObjectType, Vec<u8>)>,
}

impl Evidence {
    pub fn new(algo: HashAlgo, items: impl IntoIterator<Item = (ObjectType, Vec<u8>)>) -> Self {
        let objects = items
            .into_iter()
            .filter(|(kind, _)| matches!(kind, ObjectType::Commit | ObjectType::Tree))
            .filter_map(|(kind, content)| {
                let id = algo.hash(kind, &content).ok()?;
                Some((id, (kind, content)))
            })
            .collect();
        Self { objects }
    }

    fn get(&self, id: &ObjectId, kind: ObjectType) -> Result<&[u8], PathsError> {
        match self.objects.get(id) {
            Some((found, content)) if *found == kind => Ok(content),
            _ => Err(PathsError::Missing(id.clone())),
        }
    }
}

/// The walk's bounds ([`Limits::DEFAULT`]: the constants above).
#[derive(Debug, Clone, Copy)]
struct Limits {
    entries: usize,
    paths: usize,
    depth: usize,
    path_len: usize,
    bytes: usize,
}

impl Limits {
    const DEFAULT: Limits = Limits {
        entries: MAX_ENTRIES,
        paths: MAX_PATHS,
        depth: MAX_DEPTH,
        path_len: MAX_PATH_LEN,
        bytes: MAX_PATH_BYTES,
    };
}

/// A digest of a list of paths (SHA-256 over each path, sorted, followed by a NUL), in hex:
/// what the ledger keeps of the paths checked at signing, compared at push time.
pub fn digest(paths: &[String]) -> String {
    use sha2::Digest as _;
    let mut sorted: Vec<&String> = paths.iter().collect();
    sorted.sort();
    let mut hasher = sha2::Sha256::new();
    for path in sorted {
        hasher.update(path.as_bytes());
        hasher.update([0u8]);
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The paths `commit` touches, sorted (a path that isn't UTF-8 is shown with `�` in place
/// of the bytes that aren't).
pub fn touched(commit: &Commit, evidence: &Evidence) -> Result<Vec<String>, PathsError> {
    touched_within(commit, evidence, Limits::DEFAULT)
}

fn touched_within(
    commit: &Commit,
    evidence: &Evidence,
    limits: Limits,
) -> Result<Vec<String>, PathsError> {
    let parent_tree = match commit.parents().first() {
        None => None,
        Some(parent) => {
            let content = evidence.get(parent, ObjectType::Commit)?;
            let tree = tree_of(commit.algo(), content)
                .ok_or_else(|| PathsError::Parent(parent.clone()))?;
            Some(tree)
        }
    };
    let mut walk = Walk {
        evidence,
        algo: commit.algo(),
        limits,
        entries: 0,
        bytes: 0,
    };
    let paths = walk.diff(parent_tree.as_ref(), commit.tree())?;
    Ok(paths
        .into_iter()
        .map(|path| String::from_utf8_lossy(&path).into_owned())
        .collect())
}

/// The tree of a commit object (its first line).
fn tree_of(algo: HashAlgo, content: &[u8]) -> Option<ObjectId> {
    let line = content.split(|&b| b == b'\n').next()?;
    ObjectId::parse_hex(algo, line.strip_prefix(b"tree ")?).ok()
}

struct Walk<'a> {
    evidence: &'a Evidence,
    algo: HashAlgo,
    limits: Limits,
    /// Entries visited so far.
    entries: usize,
    /// Bytes of the paths built so far.
    bytes: usize,
}

/// A comparison still to make: the subtrees at `prefix` on each side.
struct Pending {
    prefix: Vec<u8>,
    old: Option<ObjectId>,
    new: Option<ObjectId>,
    depth: usize,
}

impl Walk<'_> {
    /// The paths that differ between two trees (`old` `None`: every path of `new`).
    fn diff(
        &mut self,
        old: Option<&ObjectId>,
        new: &ObjectId,
    ) -> Result<BTreeSet<Vec<u8>>, PathsError> {
        let mut paths = BTreeSet::new();
        let mut pending = vec![Pending {
            prefix: Vec::new(),
            old: old.cloned(),
            new: Some(new.clone()),
            depth: 0,
        }];
        while let Some(next) = pending.pop() {
            if next.old == next.new {
                continue;
            }
            if next.depth > self.limits.depth {
                return Err(PathsError::TooDeep);
            }
            let old = self.entries_of(next.old.as_ref())?;
            let new = self.entries_of(next.new.as_ref())?;
            let names: BTreeSet<&Vec<u8>> = old.keys().chain(new.keys()).collect();
            for name in names {
                self.entries = self.entries.saturating_add(1);
                if self.entries > self.limits.entries {
                    return Err(PathsError::TooManyEntries);
                }
                let (before, after) = (old.get(name), new.get(name));
                if let (Some(b), Some(a)) = (before, after)
                    && b.id == a.id
                    && b.mode == a.mode
                {
                    continue;
                }
                let mut path = self.path(&next.prefix, name)?;
                let tree = |e: Option<&tree::Entry>| {
                    e.filter(|e| e.kind == EntryKind::Tree)
                        .map(|e| e.id.clone())
                };
                let leaf = |e: Option<&tree::Entry>| e.is_some_and(|e| e.kind == EntryKind::Leaf);
                let (old_tree, new_tree) = (tree(before), tree(after));
                let descend = old_tree.is_some() || new_tree.is_some();
                if leaf(before) || leaf(after) {
                    let listed = if descend {
                        // A file became a directory or the other way: listed and walked.
                        self.count(path.len())?;
                        path.clone()
                    } else {
                        std::mem::take(&mut path)
                    };
                    paths.insert(listed);
                    if paths.len() > self.limits.paths {
                        return Err(PathsError::TooManyPaths);
                    }
                }
                if descend {
                    pending.push(Pending {
                        prefix: path,
                        old: old_tree,
                        new: new_tree,
                        depth: next.depth.saturating_add(1),
                    });
                }
            }
        }
        Ok(paths)
    }

    /// `prefix/name`, within the length and byte bounds (counted once per path built).
    fn path(&mut self, prefix: &[u8], name: &[u8]) -> Result<Vec<u8>, PathsError> {
        let len = prefix
            .len()
            .saturating_add(usize::from(!prefix.is_empty()))
            .saturating_add(name.len());
        if len > self.limits.path_len {
            return Err(PathsError::PathTooLong);
        }
        self.count(len)?;
        let mut path = Vec::with_capacity(len);
        path.extend_from_slice(prefix);
        if !prefix.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(name);
        Ok(path)
    }

    /// Counts `len` more bytes of paths against the budget.
    fn count(&mut self, len: usize) -> Result<(), PathsError> {
        self.bytes = self.bytes.saturating_add(len);
        if self.bytes > self.limits.bytes {
            return Err(PathsError::TooManyBytes);
        }
        Ok(())
    }

    fn entries_of(&self, id: Option<&ObjectId>) -> Result<tree::Entries, PathsError> {
        let Some(id) = id else {
            return Ok(tree::Entries::new());
        };
        let content = self.evidence.get(id, ObjectType::Tree)?;
        tree::parse(self.algo, content).map_err(|e| PathsError::Tree(id.clone(), e))
    }
}

#[cfg(test)]
#[allow(clippy::string_slice, clippy::arithmetic_side_effects)]
mod tests {

    #[test]
    fn the_digest_is_of_the_sorted_paths_and_tells_lists_apart() {
        let list = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(digest(&list(&["b", "a"])), digest(&list(&["a", "b"])));
        assert_ne!(digest(&list(&["a", "b"])), digest(&list(&["ab"])));
        assert_ne!(digest(&list(&["a"])), digest(&list(&["a", "a"])));
        assert_ne!(digest(&list(&[])), digest(&list(&[""])));
        // SHA-256 of nothing: an empty list.
        assert_eq!(
            digest(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    use super::*;

    const ALGO: HashAlgo = HashAlgo::Sha1;

    /// A tree object from (mode, name, id) entries, and its id.
    fn tree(entries: &[(&str, &str, &ObjectId)]) -> (ObjectId, Vec<u8>) {
        let mut sorted: Vec<_> = entries.to_vec();
        sorted.sort_by_key(|(_, name, _)| name.to_owned());
        let mut content = Vec::new();
        for (mode, name, id) in sorted {
            content.extend_from_slice(format!("{mode} {name}\0").as_bytes());
            let raw: Vec<u8> = (0..id.as_str().len() / 2)
                .map(|i| u8::from_str_radix(&id.as_str()[2 * i..2 * i + 2], 16).unwrap())
                .collect();
            content.extend(raw);
        }
        (ALGO.hash(ObjectType::Tree, &content).unwrap(), content)
    }

    fn blob(text: &str) -> ObjectId {
        ALGO.hash(ObjectType::Blob, text.as_bytes()).unwrap()
    }

    fn commit_object(tree: &ObjectId, parents: &[&ObjectId]) -> Vec<u8> {
        let parents: String = parents.iter().map(|p| format!("parent {p}\n")).collect();
        format!("tree {tree}\n{parents}author A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\nm\n")
            .into_bytes()
    }

    /// The paths of a root commit on `top`, with `sent` as evidence.
    fn root_paths(
        top: &ObjectId,
        sent: Vec<(ObjectType, Vec<u8>)>,
        limits: Limits,
    ) -> Result<Vec<String>, PathsError> {
        let commit = Commit::parse(commit_object(top, &[])).unwrap();
        touched_within(&commit, &Evidence::new(ALGO, sent), limits)
    }

    /// `count` files named `f000000`… holding the same blob, as one tree.
    fn files(count: usize) -> (ObjectId, Vec<u8>) {
        let x = blob("x");
        let names: Vec<String> = (0..count).map(|i| format!("f{i:06}")).collect();
        let entries: Vec<(&str, &str, &ObjectId)> =
            names.iter().map(|n| ("100644", n.as_str(), &x)).collect();
        tree(&entries)
    }

    #[test]
    fn a_shared_subtree_cannot_blow_up_the_walk() {
        // Each level holds the level below twice: 2^40 paths in a few hundred bytes.
        let mut sent = Vec::new();
        let (mut top, content) = tree(&[("100644", "f", &blob("x"))]);
        sent.push((ObjectType::Tree, content));
        for _ in 0..40 {
            let (next, content) = tree(&[("40000", "a", &top), ("40000", "b", &top)]);
            sent.push((ObjectType::Tree, content));
            top = next;
        }
        assert_eq!(
            root_paths(&top, sent, Limits::DEFAULT),
            Err(PathsError::TooManyPaths)
        );
    }

    #[test]
    fn long_names_cannot_blow_up_the_walk() {
        // The M3 review's F1: one directory with a long name holding many files made the
        // walk hold the name once per file. 20,000 paths of about 4 KB pass the byte budget.
        let (inner, inner_content) = files(20_000);
        let name = "d".repeat(4000);
        let (top, top_content) = tree(&[("40000", &name, &inner)]);
        let sent = vec![
            (ObjectType::Tree, inner_content),
            (ObjectType::Tree, top_content),
        ];
        assert_eq!(
            root_paths(&top, sent, Limits::DEFAULT),
            Err(PathsError::TooManyBytes)
        );
    }

    #[test]
    fn path_length_is_bounded_on_both_sides() {
        let with = |file_len: usize| {
            let x = blob("x");
            let file = "f".repeat(file_len);
            let (inner, inner_content) = tree(&[("100644", &file, &x)]);
            let dir = "d".repeat(4000);
            let (top, top_content) = tree(&[("40000", &dir, &inner)]);
            let sent = vec![
                (ObjectType::Tree, inner_content),
                (ObjectType::Tree, top_content),
            ];
            root_paths(&top, sent, Limits::DEFAULT)
        };
        // 4000 + "/" + 95 = 4096 bytes.
        let longest = with(MAX_PATH_LEN - 4001).unwrap();
        assert_eq!(longest.len(), 1);
        assert_eq!(longest[0].len(), MAX_PATH_LEN);
        assert_eq!(with(MAX_PATH_LEN - 4000), Err(PathsError::PathTooLong));
        // One name alone, too.
        let name = "n".repeat(MAX_PATH_LEN + 1);
        let (top, content) = tree(&[("100644", &name, &blob("x"))]);
        assert_eq!(
            root_paths(&top, vec![(ObjectType::Tree, content)], Limits::DEFAULT),
            Err(PathsError::PathTooLong)
        );
    }

    #[test]
    fn path_bytes_are_bounded_on_both_sides() {
        // Paths "d", "d/a", "d/b": 1 + 3 + 3 = 7 bytes.
        let (inner, inner_content) =
            tree(&[("100644", "a", &blob("1")), ("100644", "b", &blob("2"))]);
        let (top, top_content) = tree(&[("40000", "d", &inner)]);
        let sent = vec![
            (ObjectType::Tree, inner_content),
            (ObjectType::Tree, top_content),
        ];
        let limits = |bytes| Limits {
            bytes,
            ..Limits::DEFAULT
        };
        assert_eq!(
            root_paths(&top, sent.clone(), limits(7)),
            Ok(vec!["d/a".to_owned(), "d/b".to_owned()])
        );
        assert_eq!(
            root_paths(&top, sent, limits(6)),
            Err(PathsError::TooManyBytes)
        );
    }

    #[test]
    fn paths_are_bounded_on_both_sides() {
        // 100 directories sharing one tree of 1,000 files: exactly MAX_PATHS paths.
        let with = |extra: bool| {
            let (inner, inner_content) = files(1000);
            let names: Vec<String> = (0..100).map(|i| format!("d{i:03}")).collect();
            let x = blob("x");
            let mut entries: Vec<(&str, &str, &ObjectId)> = names
                .iter()
                .map(|n| ("40000", n.as_str(), &inner))
                .collect();
            if extra {
                entries.push(("100644", "zz", &x));
            }
            let (top, top_content) = tree(&entries);
            let sent = vec![
                (ObjectType::Tree, inner_content),
                (ObjectType::Tree, top_content),
            ];
            root_paths(&top, sent, Limits::DEFAULT)
        };
        assert_eq!(with(false).map(|p| p.len()), Ok(MAX_PATHS));
        assert_eq!(with(true), Err(PathsError::TooManyPaths));
    }

    #[test]
    fn entries_are_bounded_on_both_sides() {
        // 1,000 directories on each side, each holding 999 entries alike but one: 1,000 +
        // 1,000 × 999 = MAX_ENTRIES entries visited for 1,000 paths.
        let with = |extra: bool| {
            let x = blob("x");
            let names: Vec<String> = (0..999).map(|i| format!("f{i:03}")).collect();
            let side = |last: &ObjectId| {
                let mut entries: Vec<(&str, &str, &ObjectId)> = names[..998]
                    .iter()
                    .map(|n| ("100644", n.as_str(), &x))
                    .collect();
                entries.push(("100644", names[998].as_str(), last));
                tree(&entries)
            };
            let (old_inner, old_inner_content) = side(&blob("old"));
            let (new_inner, new_inner_content) = side(&blob("new"));
            let dirs: Vec<String> = (0..1000).map(|i| format!("d{i:03}")).collect();
            let top = |inner: &ObjectId| {
                let mut entries: Vec<(&str, &str, &ObjectId)> =
                    dirs.iter().map(|d| ("40000", d.as_str(), inner)).collect();
                if extra {
                    entries.push(("100644", "same", &x));
                }
                tree(&entries)
            };
            let (old_top, old_top_content) = top(&old_inner);
            let (new_top, new_top_content) = top(&new_inner);
            let parent = commit_object(&old_top, &[]);
            let parent_id = ALGO.hash(ObjectType::Commit, &parent).unwrap();
            let commit = Commit::parse(commit_object(&new_top, &[&parent_id])).unwrap();
            let sent = vec![
                (ObjectType::Commit, parent),
                (ObjectType::Tree, old_inner_content),
                (ObjectType::Tree, new_inner_content),
                (ObjectType::Tree, old_top_content),
                (ObjectType::Tree, new_top_content),
            ];
            touched_within(&commit, &Evidence::new(ALGO, sent), Limits::DEFAULT)
        };
        assert_eq!(with(false).map(|p| p.len()), Ok(1000));
        assert_eq!(with(true), Err(PathsError::TooManyEntries));
    }

    #[test]
    fn evidence_is_only_what_its_bytes_hash_to() {
        let (old, old_content) = tree(&[("100644", "a", &blob("1"))]);
        let (new, new_content) = tree(&[("100644", "a", &blob("2"))]);
        let parent = commit_object(&old, &[]);
        let parent_id = ALGO.hash(ObjectType::Commit, &parent).unwrap();
        let commit = Commit::parse(commit_object(&new, &[&parent_id])).unwrap();
        let all = vec![
            (ObjectType::Commit, parent.clone()),
            (ObjectType::Tree, old_content.clone()),
            (ObjectType::Tree, new_content.clone()),
        ];
        assert_eq!(
            touched(&commit, &Evidence::new(ALGO, all.clone())),
            Ok(vec!["a".to_owned()])
        );
        // The old tree swapped for the new one (so "nothing changed"): it isn't the old
        // tree, so the old tree is missing.
        let lying = vec![
            (ObjectType::Commit, parent.clone()),
            (ObjectType::Tree, new_content.clone()),
        ];
        assert_eq!(
            touched(&commit, &Evidence::new(ALGO, lying)),
            Err(PathsError::Missing(old.clone()))
        );
        // A tree sent as a commit is not the commit.
        let mislabeled = vec![
            (ObjectType::Tree, parent),
            (ObjectType::Tree, old_content),
            (ObjectType::Tree, new_content),
        ];
        assert_eq!(
            touched(&commit, &Evidence::new(ALGO, mislabeled)),
            Err(PathsError::Missing(parent_id))
        );
    }

    #[test]
    fn a_merge_is_checked_against_its_first_parent() {
        // The M3 review's F3: a merge whose tree is its second parent's touched nothing
        // under "what differs from every parent". Against the first parent, what the merge
        // brings in is there.
        let (main, main_content) = tree(&[("100644", "src.rs", &blob("1"))]);
        let (other, other_content) = tree(&[
            ("100644", "src.rs", &blob("1")),
            ("100644", "secrets.yml", &blob("s")),
        ]);
        let first = commit_object(&main, &[]);
        let first_id = ALGO.hash(ObjectType::Commit, &first).unwrap();
        let second = commit_object(&other, &[]);
        let second_id = ALGO.hash(ObjectType::Commit, &second).unwrap();
        let merge = Commit::parse(commit_object(&other, &[&first_id, &second_id])).unwrap();
        let sent = vec![
            (ObjectType::Commit, first),
            (ObjectType::Tree, main_content),
            (ObjectType::Tree, other_content),
        ];
        // The second parent isn't needed (nor sent).
        assert_eq!(
            touched(&merge, &Evidence::new(ALGO, sent)),
            Ok(vec!["secrets.yml".to_owned()])
        );
    }

    #[test]
    fn a_malformed_tree_is_no_answer() {
        let bad = b"100644 a/b\0aaaaaaaaaaaaaaaaaaaa".to_vec();
        let id = ALGO.hash(ObjectType::Tree, &bad).unwrap();
        let commit = Commit::parse(commit_object(&id, &[])).unwrap();
        assert_eq!(
            touched(&commit, &Evidence::new(ALGO, [(ObjectType::Tree, bad)])),
            Err(PathsError::Tree(id, TreeError::Name))
        );
    }

    #[test]
    fn depth_is_bounded_on_both_sides() {
        let nested = |levels: usize| {
            let mut sent = Vec::new();
            let (mut top, content) = tree(&[("100644", "f", &blob("x"))]);
            sent.push((ObjectType::Tree, content));
            for _ in 0..levels {
                let (next, content) = tree(&[("40000", "d", &top)]);
                sent.push((ObjectType::Tree, content));
                top = next;
            }
            root_paths(&top, sent, Limits::DEFAULT)
        };
        let deepest = nested(MAX_DEPTH).unwrap();
        assert_eq!(deepest.len(), 1);
        assert_eq!(deepest[0].len(), MAX_DEPTH * 2 + 1);
        assert_eq!(nested(MAX_DEPTH + 1), Err(PathsError::TooDeep));
    }
}
