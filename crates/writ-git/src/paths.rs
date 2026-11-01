//! The paths a commit touches, for `paths_check` (`docs/lease-model.md`, rules).
//!
//! The daemon has no copy of the agent's repository when it signs (the commit isn't even
//! written yet), so `writ-sign` sends the objects the comparison needs: the parent commits
//! and the trees that differ. Nothing in them is believed: each object's id is computed here
//! from its bytes ([`Evidence`]), and only the objects the commit's own ids lead to are
//! read. An agent can leave an object out (the paths are then unknown, which `deny` refuses)
//! but can't make a path look untouched: a tree that isn't the one named has another id.
//!
//! A commit touches the paths that differ from its parent; a root commit, every path in its
//! tree; a merge, the paths that differ from every parent (what the merge itself changed,
//! like `git diff-tree -c`). The walk is bounded, so trees that share subtrees can't make it
//! list more than [`MAX_PATHS`] paths or visit more than [`MAX_ENTRIES`] entries.

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

/// Why the touched paths can't be computed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathsError {
    #[error("object {0} was not sent")]
    Missing(ObjectId),
    #[error("parent {0} is not a commit")]
    Parent(ObjectId),
    #[error("tree {0} is malformed: {1}")]
    Tree(ObjectId, TreeError),
    #[error("the commit touches too many paths to check")]
    TooMany,
    #[error("the commit's trees are nested too deep to check")]
    TooDeep,
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

/// The paths `commit` touches, sorted (a path that isn't UTF-8 is shown with `�` in place
/// of the bytes that aren't).
pub fn touched(commit: &Commit, evidence: &Evidence) -> Result<Vec<String>, PathsError> {
    let mut walk = Walk {
        evidence,
        algo: commit.algo(),
        entries: 0,
    };
    let mut touched: Option<BTreeSet<Vec<u8>>> = None;
    if commit.parents().is_empty() {
        touched = Some(walk.diff(None, Some(commit.tree()))?);
    }
    for parent in commit.parents() {
        let content = evidence.get(parent, ObjectType::Commit)?;
        let parent_tree =
            tree_of(commit.algo(), content).ok_or_else(|| PathsError::Parent(parent.clone()))?;
        let changed = walk.diff(Some(&parent_tree), Some(commit.tree()))?;
        touched = Some(match touched {
            None => changed,
            Some(before) => before.intersection(&changed).cloned().collect(),
        });
    }
    Ok(touched
        .unwrap_or_default()
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
    /// Entries visited so far, across every comparison of the commit.
    entries: usize,
}

/// A comparison still to make: the subtrees at `prefix` on each side.
struct Pending {
    prefix: Vec<u8>,
    old: Option<ObjectId>,
    new: Option<ObjectId>,
    depth: usize,
}

impl Walk<'_> {
    /// The paths that differ between two trees (`None`: no tree, every path of the other).
    fn diff(
        &mut self,
        old: Option<&ObjectId>,
        new: Option<&ObjectId>,
    ) -> Result<BTreeSet<Vec<u8>>, PathsError> {
        let mut paths = BTreeSet::new();
        let mut pending = vec![Pending {
            prefix: Vec::new(),
            old: old.cloned(),
            new: new.cloned(),
            depth: 0,
        }];
        while let Some(next) = pending.pop() {
            if next.old == next.new {
                continue;
            }
            if next.depth > MAX_DEPTH {
                return Err(PathsError::TooDeep);
            }
            let old = self.entries_of(next.old.as_ref())?;
            let new = self.entries_of(next.new.as_ref())?;
            let names: BTreeSet<&Vec<u8>> = old.keys().chain(new.keys()).collect();
            for name in names {
                self.entries = self.entries.saturating_add(1);
                if self.entries > MAX_ENTRIES {
                    return Err(PathsError::TooMany);
                }
                let (before, after) = (old.get(name), new.get(name));
                if let (Some(b), Some(a)) = (before, after)
                    && b.id == a.id
                    && b.mode == a.mode
                {
                    continue;
                }
                let mut path = next.prefix.clone();
                if !path.is_empty() {
                    path.push(b'/');
                }
                path.extend_from_slice(name);
                let tree = |e: Option<&tree::Entry>| {
                    e.filter(|e| e.kind == EntryKind::Tree)
                        .map(|e| e.id.clone())
                };
                let leaf = |e: Option<&tree::Entry>| e.is_some_and(|e| e.kind == EntryKind::Leaf);
                if leaf(before) || leaf(after) {
                    paths.insert(path.clone());
                    if paths.len() > MAX_PATHS {
                        return Err(PathsError::TooMany);
                    }
                }
                let (old_tree, new_tree) = (tree(before), tree(after));
                if old_tree.is_some() || new_tree.is_some() {
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
        let commit = Commit::parse(commit_object(&top, &[])).unwrap();
        let evidence = Evidence::new(ALGO, sent);
        assert_eq!(touched(&commit, &evidence), Err(PathsError::TooMany));
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
            let commit = Commit::parse(commit_object(&top, &[])).unwrap();
            touched(&commit, &Evidence::new(ALGO, sent))
        };
        let deepest = nested(MAX_DEPTH).unwrap();
        assert_eq!(deepest.len(), 1);
        assert_eq!(deepest[0].len(), MAX_DEPTH * 2 + 1);
        assert_eq!(nested(MAX_DEPTH + 1), Err(PathsError::TooDeep));
    }
}
