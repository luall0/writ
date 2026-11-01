//! Reading a push in git's quarantine (`receive-pack` keeps the pushed objects in
//! `<mirror>/objects/tmp_objdir-incoming-*` until its pre-receive hook says yes): the facts the
//! push decision needs, read from the objects git verified (its own hashing, collision
//! detection and `fsck`), never from what the agent says.
//!
//! - the commits the push brings that the mirror doesn't have ([`Quarantine::new_commits`]),
//!   bounded in number;
//! - whether a ref moves forward ([`Quarantine::is_ancestor`]), whether a new ref has a twin
//!   differing only in case ([`Quarantine::case_twin`]), the kind of each new tip;
//! - what the push weighs on disk ([`Quarantine::size`]);
//! - the paths each commit touches, computed again with `writ_git::paths` from the objects
//!   here ([`Quarantine::touched_paths`]), compared with what signing saw.
//!
//! The hook names the quarantine; the path is believed only if it is a directory (not a link)
//! right under this mirror's `objects` with git's quarantine prefix. git runs here with the
//! quarantine as its object directory, the mirror's objects as alternates, and
//! `GIT_QUARANTINE_PATH` set, so nothing it runs can move a ref.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use writ_core::config::ObjectFormat;
use writ_git::object::ObjectType;
use writ_git::paths::Evidence;
use writ_git::{Commit, HashAlgo};

use crate::git::{self, Hooks};
use crate::process::{self, RunError};
use crate::{MirrorError, Result, shown};

/// The prefix of the quarantine directories `receive-pack` makes.
const QUARANTINE_PREFIX: &str = "tmp_objdir-incoming-";
/// How long one read of the quarantine may take.
const READ_DEADLINE: Duration = Duration::from_secs(120);
/// The most bytes of objects read to compute one commit's paths (what a sign request may
/// carry): past it the paths are unknown.
pub const MAX_EVIDENCE: usize = 16 << 20;
/// The most bytes of a tree listing read for one commit.
const MAX_LISTING: usize = 64 << 20;
/// The most bytes of a list of commit ids read (64 bytes and a newline each).
const MAX_ID_LIST: usize = 1 << 24;

/// A push's quarantine, or none (a push that only deletes refs sends no pack).
#[derive(Debug, Clone)]
pub struct Quarantine {
    mirror: PathBuf,
    objects: Option<PathBuf>,
    algo: HashAlgo,
}

impl Quarantine {
    /// The quarantine at `path` of the mirror at `mirror`, in the repo's object `format`.
    pub fn open(mirror: &Path, path: Option<&Path>, format: ObjectFormat) -> Result<Self> {
        let algo = match format {
            ObjectFormat::Sha1 => HashAlgo::Sha1,
            ObjectFormat::Sha256 => HashAlgo::Sha256,
        };
        let objects = match path {
            None => None,
            Some(path) => Some(check(mirror, path)?),
        };
        Ok(Self {
            mirror: mirror.to_owned(),
            objects,
            algo,
        })
    }

    /// git, reading this push: the quarantine's objects, then the mirror's.
    fn git(&self, args: &[&str]) -> tokio::process::Command {
        let mut cmd = git::command(Hooks::None);
        cmd.arg("--git-dir").arg(&self.mirror).args(args);
        if let Some(objects) = &self.objects {
            cmd.env("GIT_OBJECT_DIRECTORY", objects)
                .env(
                    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                    self.mirror.join("objects"),
                )
                .env("GIT_QUARANTINE_PATH", objects);
        }
        cmd
    }

    async fn run(
        &self,
        args: &[&str],
        stdin: Option<Vec<u8>>,
        max_stdout: usize,
    ) -> Result<process::Finished> {
        match process::run(self.git(args), stdin, READ_DEADLINE, max_stdout).await {
            Ok(done) => Ok(done),
            Err(RunError::Timeout) => Err(MirrorError::Read("git took too long".to_owned())),
            Err(RunError::Spawn(e) | RunError::Wait(e)) => Err(MirrorError::Spawn(e)),
        }
    }

    async fn run_ok(
        &self,
        args: &[&str],
        stdin: Option<Vec<u8>>,
        max_stdout: usize,
    ) -> Result<Vec<u8>> {
        let done = self.run(args, stdin, max_stdout).await?;
        if !done.status.success() {
            return Err(MirrorError::Read(shown(&done.stderr)));
        }
        Ok(done.stdout)
    }

    /// The commits reachable from `tips` that no ref of the mirror reaches: what the push
    /// brings. More than `max` refuses the push ([`MirrorError::TooManyCommits`]).
    pub async fn new_commits(&self, tips: &[String], max: usize) -> Result<Vec<String>> {
        if tips.is_empty() {
            return Ok(Vec::new());
        }
        let input: String = tips.iter().map(|t| format!("{t}\n")).collect();
        let count = format!("--max-count={}", max.saturating_add(1));
        // `--not --all` on the command line doesn't apply to the tips read from stdin.
        let out = self
            .run_ok(
                &["rev-list", &count, "--not", "--all", "--stdin"],
                Some(input.into_bytes()),
                MAX_ID_LIST,
            )
            .await?;
        let commits: Vec<String> = String::from_utf8_lossy(&out)
            .lines()
            .map(str::to_owned)
            .collect();
        if commits.len() > max {
            return Err(MirrorError::TooManyCommits(max));
        }
        Ok(commits)
    }

    /// The kind git gives each object (`commit`, `tag`, …; `missing` for none).
    pub async fn kinds(&self, ids: &[String]) -> Result<Vec<String>> {
        let input: String = ids.iter().map(|id| format!("{id}\n")).collect();
        let out = self
            .run_ok(
                &["cat-file", "--batch-check=%(objecttype)"],
                Some(input.into_bytes()),
                MAX_ID_LIST,
            )
            .await?;
        let kinds: Vec<String> = String::from_utf8_lossy(&out)
            .lines()
            .map(|line| line.rsplit(' ').next().unwrap_or(line).to_owned())
            .collect();
        if kinds.len() != ids.len() {
            return Err(MirrorError::Read(
                "git gave no kind for an object".to_owned(),
            ));
        }
        Ok(kinds)
    }

    /// Whether `old` is an ancestor of `new` (a fast-forward).
    pub async fn is_ancestor(&self, old: &str, new: &str) -> Result<bool> {
        let done = self
            .run(&["merge-base", "--is-ancestor", old, new], None, 0)
            .await?;
        match done.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(MirrorError::Read(shown(&done.stderr))),
        }
    }

    /// Whether the mirror has a ref named like `name` ignoring case, but not exactly `name`.
    pub async fn case_twin(&self, name: &str) -> Result<bool> {
        let out = self
            .run_ok(
                &[
                    "for-each-ref",
                    "--ignore-case",
                    "--format=%(refname)",
                    "--",
                    name,
                ],
                None,
                MAX_ID_LIST,
            )
            .await?;
        Ok(String::from_utf8_lossy(&out)
            .lines()
            .any(|found| found != name && found.eq_ignore_ascii_case(name)))
    }

    /// What the push holds on disk: every file in the quarantine, in bytes (links not
    /// followed).
    pub fn size(&self) -> Result<u64> {
        let Some(objects) = &self.objects else {
            return Ok(0);
        };
        let mut total: u64 = 0;
        let mut pending = vec![(objects.clone(), 0usize)];
        while let Some((dir, depth)) = pending.pop() {
            let entries = std::fs::read_dir(&dir).map_err(|source| MirrorError::Io {
                what: "cannot read the quarantine",
                path: dir.clone(),
                source,
            })?;
            for entry in entries {
                let entry = entry.map_err(|source| MirrorError::Io {
                    what: "cannot read the quarantine",
                    path: dir.clone(),
                    source,
                })?;
                let meta = entry
                    .path()
                    .symlink_metadata()
                    .map_err(|source| MirrorError::Io {
                        what: "cannot read the quarantine",
                        path: entry.path(),
                        source,
                    })?;
                if meta.is_dir() && depth < 4 {
                    pending.push((entry.path(), depth.saturating_add(1)));
                } else if meta.is_file() {
                    total = total.saturating_add(meta.len());
                }
            }
        }
        Ok(total)
    }

    /// The paths the commit `id` touches (against its first parent, a merge too), computed
    /// with `writ_git::paths` from the objects git verified, as their digest
    /// (`writ_git::paths::digest`); `None` when they can't be computed (objects over
    /// [`MAX_EVIDENCE`], the walk's bounds, a commit that isn't signed in this format).
    pub async fn touched_paths(&self, id: &str) -> Result<Option<String>> {
        let mut left = MAX_EVIDENCE;
        let Some(mut found) = self.cat(&[id.to_owned()], "commit", &mut left).await? else {
            return Ok(None);
        };
        let Some((_, signed)) = found.pop() else {
            return Ok(None);
        };
        let Ok(unsigned) = writ_git::signed::unsigned_bytes(&signed, self.algo) else {
            return Ok(None);
        };
        let Ok(commit) = Commit::parse(unsigned) else {
            return Ok(None);
        };
        let tree = commit.tree().as_str().to_owned();
        let mut trees = BTreeSet::from([tree.clone()]);
        let mut items = Vec::new();
        match commit.parents().first() {
            Some(parent) => {
                let parent = parent.as_str().to_owned();
                let Some(mut found) = self.cat(&[parent], "commit", &mut left).await? else {
                    return Ok(None);
                };
                let Some((_, content)) = found.pop() else {
                    return Ok(None);
                };
                let Some(parent_tree) = tree_header(&content) else {
                    return Ok(None);
                };
                trees.insert(parent_tree.clone());
                trees.extend(self.changed_trees(Some(&parent_tree), &tree).await?);
                items.push((ObjectType::Commit, content));
            }
            None => trees.extend(self.changed_trees(None, &tree).await?),
        }
        let trees: Vec<String> = trees.into_iter().collect();
        let Some(found) = self.cat(&trees, "tree", &mut left).await? else {
            return Ok(None);
        };
        items.extend(found.into_iter().map(|(_, c)| (ObjectType::Tree, c)));
        let evidence = Evidence::new(self.algo, items);
        Ok(writ_git::paths::touched(&commit, &evidence)
            .ok()
            .map(|paths| writ_git::paths::digest(&paths)))
    }

    /// The trees that differ between two trees (both sides), or every tree under `new`.
    async fn changed_trees(&self, old: Option<&str>, new: &str) -> Result<Vec<String>> {
        let args: Vec<&str> = match old {
            Some(old) => vec![
                "diff-tree",
                "-r",
                "-t",
                "-z",
                "--raw",
                "--no-renames",
                "--no-abbrev",
                old,
                new,
            ],
            None => vec!["ls-tree", "-r", "-t", "-z", "--full-tree", new],
        };
        let out = self.run_ok(&args, None, MAX_LISTING).await?;
        Ok(parse_trees(&out, old.is_some()))
    }

    /// The content of each object (`git cat-file --batch`), checked to be of `kind`; `None`
    /// once they would spend more than `left` (taken from it).
    async fn cat(
        &self,
        ids: &[String],
        kind: &str,
        left: &mut usize,
    ) -> Result<Option<Vec<(String, Vec<u8>)>>> {
        if ids.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let input: String = ids.iter().map(|id| format!("{id}\n")).collect();
        // Headers are short: what is past the budget means the objects are.
        let cap = left.saturating_add(ids.len().saturating_mul(160));
        let out = self
            .run_ok(&["cat-file", "--batch"], Some(input.into_bytes()), cap)
            .await?;
        Ok(parse_batch(&out, ids, kind, left))
    }
}

/// Checks that `path` is a quarantine of the mirror at `mirror`: a directory, not a link,
/// right under its `objects`, named as git names them. Returns the path as the file system
/// resolves it.
fn check(mirror: &Path, path: &Path) -> Result<PathBuf> {
    let refuse = |why: &str| MirrorError::NotAQuarantine(format!("{}: {why}", path.display()));
    let meta = path
        .symlink_metadata()
        .map_err(|_| refuse("does not exist"))?;
    if !meta.is_dir() {
        return Err(refuse("not a directory"));
    }
    let resolved = path
        .canonicalize()
        .map_err(|_| refuse("cannot be resolved"))?;
    let objects = mirror
        .join("objects")
        .canonicalize()
        .map_err(|_| refuse("the mirror has no objects directory"))?;
    let named = resolved
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with(QUARANTINE_PREFIX));
    if resolved.parent() != Some(objects.as_path()) || !named {
        return Err(refuse("not a quarantine of this mirror"));
    }
    Ok(resolved)
}

/// The `tree` header of a commit's bytes.
fn tree_header(content: &[u8]) -> Option<String> {
    let first = content.split(|&b| b == b'\n').next()?;
    let id = std::str::from_utf8(first).ok()?.strip_prefix("tree ")?;
    id.bytes()
        .all(|b| b.is_ascii_hexdigit())
        .then(|| id.to_owned())
}

/// Tree ids in `diff-tree -t -z --raw` output (`with_diff`) or `ls-tree -t -z` output.
fn parse_trees(out: &[u8], with_diff: bool) -> Vec<String> {
    let mut trees = Vec::new();
    let mut records = out.split(|&b| b == 0);
    while let Some(record) = records.next() {
        let record = String::from_utf8_lossy(record);
        if with_diff {
            // `:<old mode> <new mode> <old id> <new id> <status>`, then the path.
            let Some(fields) = record.strip_prefix(':') else {
                continue;
            };
            records.next();
            let fields: Vec<&str> = fields.split(' ').collect();
            if let [old_mode, new_mode, old_id, new_id, ..] = fields.as_slice() {
                for (mode, id) in [(old_mode, old_id), (new_mode, new_id)] {
                    if *mode == "040000" && id.bytes().any(|b| b != b'0') {
                        trees.push((*id).to_owned());
                    }
                }
            }
        } else if let Some((meta, _path)) = record.split_once('\t')
            && let [_, "tree", id] = meta.split(' ').collect::<Vec<_>>().as_slice()
        {
            trees.push((*id).to_owned());
        }
    }
    trees
}

/// The objects in `git cat-file --batch` output for `ids`, each of `kind`, within `left`;
/// `None` past it, or for a missing object or another kind.
fn parse_batch(
    mut out: &[u8],
    ids: &[String],
    kind: &str,
    left: &mut usize,
) -> Option<Vec<(String, Vec<u8>)>> {
    let mut objects = Vec::new();
    for id in ids {
        let end = out.iter().position(|&b| b == b'\n')?;
        let (header, rest) = out.split_at_checked(end)?;
        let header = std::str::from_utf8(header).ok()?;
        let [found_id, found, size] = header.split(' ').collect::<Vec<_>>()[..] else {
            return None;
        };
        if found_id != id || found != kind {
            return None;
        }
        let size: usize = size.parse().ok()?;
        *left = left.checked_sub(size)?;
        let rest = rest.get(1..)?;
        let (content, after) = rest.split_at_checked(size)?;
        objects.push((id.clone(), content.to_vec()));
        out = after.strip_prefix(b"\n")?;
    }
    Some(objects)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_output_is_read_within_the_budget_on_both_sides() {
        let out = b"t1 tree 3\nabc\nt2 tree 2\nde\n";
        let ids = ["t1".to_owned(), "t2".to_owned()];
        let mut left = 5;
        assert_eq!(
            parse_batch(out, &ids, "tree", &mut left),
            Some(vec![
                ("t1".to_owned(), b"abc".to_vec()),
                ("t2".to_owned(), b"de".to_vec())
            ])
        );
        assert_eq!(left, 0);
        let mut left = 4;
        assert_eq!(parse_batch(out, &ids, "tree", &mut left), None);
        // Another kind, another id, a missing object, cut short: none.
        let mut left = 100;
        assert_eq!(parse_batch(out, &ids, "commit", &mut left), None);
        let swapped = ["t2".to_owned(), "t1".to_owned()];
        assert_eq!(parse_batch(out, &swapped, "tree", &mut 100), None);
        assert_eq!(
            parse_batch(b"t1 missing\n", &ids[..1], "tree", &mut 100),
            None
        );
        assert_eq!(
            parse_batch(b"t1 tree 3\nab", &ids[..1], "tree", &mut 100),
            None
        );
    }

    #[test]
    fn only_a_quarantine_of_the_mirror_is_believed() {
        let dir = tempfile::tempdir().unwrap();
        let mirror = dir.path().join("demo.git");
        let objects = mirror.join("objects");
        std::fs::create_dir_all(objects.join("tmp_objdir-incoming-abc")).unwrap();
        std::fs::create_dir_all(objects.join("pack")).unwrap();
        std::fs::create_dir_all(dir.path().join("tmp_objdir-incoming-elsewhere")).unwrap();
        let open = |path: &Path| Quarantine::open(&mirror, Some(path), ObjectFormat::Sha1);
        assert!(open(&objects.join("tmp_objdir-incoming-abc")).is_ok());
        assert!(
            open(&objects.join("pack/../tmp_objdir-incoming-abc")).is_ok(),
            "resolved first"
        );
        for bad in [
            objects.join("pack"),
            dir.path().join("tmp_objdir-incoming-elsewhere"),
            objects.join("tmp_objdir-incoming-missing"),
            objects.clone(),
        ] {
            let result = open(&bad);
            assert!(
                matches!(result, Err(MirrorError::NotAQuarantine(_))),
                "{}: {result:?}",
                bad.display()
            );
        }
        // A link with the right name, pointing at the right place: refused, it isn't one.
        let link = objects.join("tmp_objdir-incoming-link");
        std::os::unix::fs::symlink(objects.join("tmp_objdir-incoming-abc"), &link).unwrap();
        assert!(matches!(open(&link), Err(MirrorError::NotAQuarantine(_))));
        // No quarantine at all (a push that only deletes).
        assert!(Quarantine::open(&mirror, None, ObjectFormat::Sha1).is_ok());
    }

    #[test]
    fn tree_ids_are_read_from_both_listings() {
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        let z = "0".repeat(40);
        let diff = format!(
            ":040000 040000 {a} {b} M\0dir\0:100644 100644 {a} {b} M\0dir/f\0:000000 040000 {z} {b} A\0new\0"
        );
        assert_eq!(
            parse_trees(diff.as_bytes(), true),
            [a.clone(), b.clone(), b.clone()]
        );
        let list = format!("040000 tree {a}\tdir\0100644 blob {b}\tdir/f\0");
        assert_eq!(parse_trees(list.as_bytes(), false), [a]);
    }
}
