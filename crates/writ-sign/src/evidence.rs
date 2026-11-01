//! The objects the daemon needs to compute the paths a commit touches (`writ_git::paths`):
//! its first parent commit, its tree and that parent's tree, and every subtree that differs,
//! read from the repository git is committing in. The daemon checks each one against the ids
//! in the commit, so what is sent here is a convenience: sending less leaves the paths
//! unknown (refused with `paths_check: deny`), sending something else is ignored.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use anyhow::{Context, bail};
use writ_proto::sign::{EvidenceKind, MAX_SIGN_INPUT};

/// What a body may spend on evidence, keeping room for the object and the framing.
fn budget(object: &[u8]) -> usize {
    MAX_SIGN_INPUT
        .saturating_sub(object.len())
        .saturating_sub(64 * 1024)
}

/// Objects read from git, by id.
type Objects = Vec<(String, Vec<u8>)>;

/// What one object costs in a body: its bytes and its header line.
fn cost(size: usize) -> usize {
    size.saturating_add(32)
}

/// The evidence for `object`, or none when it isn't a commit or doesn't fit in a request.
pub fn gather(object: &[u8]) -> anyhow::Result<Vec<(EvidenceKind, Vec<u8>)>> {
    let Some((tree, parents)) = headers(object) else {
        return Ok(Vec::new());
    };
    let mut left = budget(object);
    let mut items = Vec::new();
    let mut trees = BTreeSet::from([tree.clone()]);
    match parents.first() {
        // A merge too: the daemon compares a commit with its first parent only.
        Some(parent) => {
            let Some(mut found) = cat(std::slice::from_ref(parent), "commit", &mut left)? else {
                return Ok(Vec::new());
            };
            let (_, content) = found.pop().context("git gave no parent commit")?;
            let parent_tree = headers(&content)
                .map(|(t, _)| t)
                .with_context(|| format!("parent {parent} has no tree"))?;
            trees.insert(parent_tree.clone());
            trees.extend(changed_trees(Some(&parent_tree), &tree)?);
            items.push((EvidenceKind::Commit, content));
        }
        None => trees.extend(changed_trees(None, &tree)?),
    }
    let trees: Vec<String> = trees.into_iter().collect();
    let Some(found) = cat(&trees, "tree", &mut left)? else {
        return Ok(Vec::new());
    };
    items.extend(found.into_iter().map(|(_, c)| (EvidenceKind::Tree, c)));
    Ok(items)
}

/// The `tree` and `parent` ids of a commit's headers; `None` if it isn't a commit.
fn headers(object: &[u8]) -> Option<(String, Vec<String>)> {
    let end = object
        .windows(2)
        .position(|w| w == b"\n\n")
        .unwrap_or(object.len());
    let text = String::from_utf8_lossy(object.get(..end)?);
    let mut lines = text.lines();
    let tree = lines.next()?.strip_prefix("tree ")?.to_owned();
    let parents = lines
        .map_while(|l| l.strip_prefix("parent "))
        .map(str::to_owned)
        .collect();
    Some((tree, parents))
}

/// The trees that differ between two trees (both sides), or every tree under `new`.
fn changed_trees(old: Option<&str>, new: &str) -> anyhow::Result<Vec<String>> {
    // PATH: the agent host's git, the one that called this shim.
    let mut command = Command::new("git");
    match old {
        Some(old) => command.args([
            "diff-tree",
            "-r",
            "-t",
            "-z",
            "--raw",
            "--no-renames",
            "--no-abbrev",
            old,
            new,
        ]),
        None => command.args(["ls-tree", "-r", "-t", "-z", "--full-tree", new]),
    };
    let out = command
        .stderr(Stdio::null())
        .output()
        .context("cannot run git")?;
    if !out.status.success() {
        bail!("git could not compare the trees");
    }
    let mut trees = Vec::new();
    let mut records = out.stdout.split(|&b| b == 0);
    while let Some(record) = records.next() {
        let record = String::from_utf8_lossy(record);
        if old.is_some() {
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
        } else if let Some((meta, _path)) = record.split_once('\t') {
            // `<mode> <type> <id>\t<path>`
            if let [_, "tree", id] = meta.split(' ').collect::<Vec<_>>().as_slice() {
                trees.push((*id).to_owned());
            }
        }
    }
    Ok(trees)
}

/// The content of each object (`git cat-file --batch`), checked to be of `kind`; `None` once
/// they would spend more than `left` (what they spend is taken from it), without reading the
/// rest.
fn cat(ids: &[String], kind: &str, left: &mut usize) -> anyhow::Result<Option<Objects>> {
    if ids.is_empty() {
        return Ok(Some(Vec::new()));
    }
    // PATH: the agent host's git, the one that called this shim.
    let mut child = Command::new("git")
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("cannot run git cat-file")?;
    let mut stdin = child.stdin.take().context("no stdin")?;
    let request: String = ids.iter().map(|id| format!("{id}\n")).collect();
    let writer = std::thread::spawn(move || stdin.write_all(request.as_bytes()));
    let stdout = child.stdout.take().context("no stdout")?;
    let read = read_batch(BufReader::new(stdout), ids, kind, left);
    if !matches!(read, Ok(Some(_))) {
        // Over the budget or failed: the rest isn't read.
        let _ = child.kill();
    }
    let _ = writer.join();
    let _ = child.wait();
    read
}

/// The objects `git cat-file --batch` writes for `ids`, within `left`.
fn read_batch(
    mut reader: impl BufRead,
    ids: &[String],
    kind: &str,
    left: &mut usize,
) -> anyhow::Result<Option<Objects>> {
    let mut objects = Vec::new();
    for id in ids {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        let fields: Vec<&str> = header.trim_end().split(' ').collect();
        let [_, found, size] = fields.as_slice() else {
            bail!("git has no object {id}");
        };
        if *found != kind {
            bail!("{id} is a {found}, not a {kind}");
        }
        let size: usize = size.parse().context("git cat-file gave no size")?;
        match left.checked_sub(cost(size)) {
            Some(rest) => *left = rest,
            None => return Ok(None),
        }
        let mut content = vec![0; size.saturating_add(1)];
        reader.read_exact(&mut content)?;
        content.pop();
        objects.push((id.clone(), content));
    }
    Ok(Some(objects))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_tree_and_parents() {
        let commit = b"tree aaa\nparent bbb\nparent ccc\nauthor A <a@x> 1 +0000\n\nparent ddd\n";
        assert_eq!(
            headers(commit),
            Some(("aaa".to_owned(), vec!["bbb".to_owned(), "ccc".to_owned()]))
        );
        assert_eq!(headers(b"object aaa\ntype commit\n\nm"), None);
        assert_eq!(headers(b""), None);
    }

    #[test]
    fn reading_stops_at_the_budget_on_both_sides() {
        let batch = b"t1 tree 3\nabc\nt2 tree 2\nde\n";
        let ids = ["t1".to_owned(), "t2".to_owned()];
        let exact = cost(3) + cost(2);
        let mut left = exact;
        let read = read_batch(&batch[..], &ids, "tree", &mut left).unwrap();
        assert_eq!(
            read,
            Some(vec![
                ("t1".to_owned(), b"abc".to_vec()),
                ("t2".to_owned(), b"de".to_vec())
            ])
        );
        assert_eq!(left, 0);
        let mut left = exact - 1;
        assert_eq!(
            read_batch(&batch[..], &ids, "tree", &mut left).unwrap(),
            None
        );
    }
}
