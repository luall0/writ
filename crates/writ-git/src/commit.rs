//! A commit object as git hands it to the signing program: the agent's bytes, parsed
//! strictly. Only the layout git itself writes is accepted (`tree`, `parent`s, `author`,
//! `committer`, then `encoding` and `mergetag` if any, a blank line, the message); anything
//! else, a signature already in it included, is refused rather than guessed at.

use writ_core::policy::ObjectKind;

use crate::object::{HashAlgo, ObjectError, ObjectId};
use crate::trailers;

/// The most parents a commit may have here (an octopus merge of a hundred branches). Only
/// the first one is compared for the touched paths, but each is parsed and kept.
pub const MAX_PARENTS: usize = 100;

/// Why the bytes are not a commit this daemon signs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitError {
    #[error("the commit has no blank line between its headers and its message")]
    NoMessage,
    #[error("the commit's {0} header is missing or out of place")]
    Missing(&'static str),
    #[error("the commit has an unexpected header {0:?}")]
    Header(String),
    #[error("the commit is signed already")]
    AlreadySigned,
    #[error("the commit has more than {MAX_PARENTS} parents")]
    TooManyParents,
    #[error("the commit's {0} line is not `name <email> time zone`")]
    Ident(&'static str),
    #[error("the commit's {0}: {1}")]
    Id(&'static str, ObjectError),
}

/// What kind of object a signing request carries, from its first bytes: a commit starts
/// with its `tree` line, an annotated tag with its `object` line. Anything else (a push
/// certificate, a blob) is none of git's signed objects.
pub fn kind(bytes: &[u8]) -> ObjectKind {
    if bytes.starts_with(b"tree ") {
        ObjectKind::Commit
    } else if bytes.starts_with(b"object ") {
        ObjectKind::Tag
    } else {
        ObjectKind::Other
    }
}

/// A parsed commit, holding the exact bytes it was parsed from (the bytes signed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    bytes: Vec<u8>,
    algo: HashAlgo,
    tree: ObjectId,
    parents: Vec<ObjectId>,
    committer_email: String,
    /// Where the message starts in `bytes`.
    message: usize,
}

impl Commit {
    /// Parses the bytes of an unsigned commit.
    pub fn parse(bytes: Vec<u8>) -> Result<Self, CommitError> {
        let end = find(&bytes, b"\n\n").ok_or(CommitError::NoMessage)?;
        // The headers with their last newline; the message after the blank line.
        let headers = bytes.get(..=end).ok_or(CommitError::NoMessage)?;
        let message = end.checked_add(2).ok_or(CommitError::NoMessage)?;
        let mut lines = Lines::new(headers);

        let tree_hex = lines.value(b"tree").ok_or(CommitError::Missing("tree"))?;
        let algo = match tree_hex.len() {
            40 => HashAlgo::Sha1,
            64 => HashAlgo::Sha256,
            _ => {
                let id = String::from_utf8_lossy(tree_hex).into_owned();
                return Err(CommitError::Id("tree", ObjectError::InvalidId(id)));
            }
        };
        let tree = ObjectId::parse_hex(algo, tree_hex).map_err(|e| CommitError::Id("tree", e))?;
        let mut parents = Vec::new();
        while let Some(hex) = lines.value(b"parent") {
            if parents.len() >= MAX_PARENTS {
                return Err(CommitError::TooManyParents);
            }
            parents.push(ObjectId::parse_hex(algo, hex).map_err(|e| CommitError::Id("parent", e))?);
        }
        let author = lines
            .value(b"author")
            .ok_or(CommitError::Missing("author"))?;
        email(author).ok_or(CommitError::Ident("author"))?;
        let committer = lines
            .value(b"committer")
            .ok_or(CommitError::Missing("committer"))?;
        let committer_email = email(committer)
            .and_then(|e| String::from_utf8(e.to_vec()).ok())
            .ok_or(CommitError::Ident("committer"))?;
        lines.value(b"encoding");
        while lines.value(b"mergetag").is_some() {
            // Its continuation lines (the tag object, one space in front of each line).
            while lines.continuation().is_some() {}
        }
        if let Some(rest) = lines.next_name() {
            let signed = [HashAlgo::Sha1, HashAlgo::Sha256]
                .iter()
                .any(|algo| rest == algo.signature_header().as_bytes());
            return Err(if signed {
                CommitError::AlreadySigned
            } else {
                CommitError::Header(String::from_utf8_lossy(rest).into_owned())
            });
        }
        Ok(Self {
            bytes,
            algo,
            tree,
            parents,
            committer_email,
            message,
        })
    }

    /// The exact bytes parsed: what git asked to sign.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn algo(&self) -> HashAlgo {
        self.algo
    }

    pub fn tree(&self) -> &ObjectId {
        &self.tree
    }

    pub fn parents(&self) -> &[ObjectId] {
        &self.parents
    }

    /// The committer's email, as written (compared exactly by the policy).
    pub fn committer_email(&self) -> &str {
        &self.committer_email
    }

    /// The message: everything after the blank line.
    pub fn message(&self) -> &[u8] {
        self.bytes.get(self.message..).unwrap_or_default()
    }

    /// The values of the message's `Writ:` trailers (the key in any case, as git matches it).
    pub fn writ_trailers(&self) -> Vec<String> {
        trailers::parse(self.message())
            .into_iter()
            .filter(|t| t.key.eq_ignore_ascii_case("writ"))
            .map(|t| t.value)
            .collect()
    }
}

/// The position of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The email of an ident line value (`Name <email> 1700000000 +0000`): between its one `<`
/// and the `>` after it, which a space, the time in seconds and the zone follow.
fn email(ident: &[u8]) -> Option<&[u8]> {
    let open = ident.iter().position(|&b| b == b'<')?;
    let close = ident.iter().position(|&b| b == b'>')?;
    let count = |c: u8| ident.iter().filter(|&&b| b == c).count();
    if close <= open || count(b'<') != 1 || count(b'>') != 1 {
        return None;
    }
    let tail = ident.get(close.checked_add(1)?..)?.strip_prefix(b" ")?;
    let space = tail.iter().position(|&b| b == b' ')?;
    let time = tail.get(..space)?;
    let zone = tail.get(space.checked_add(1)?..)?;
    let digits = |s: &[u8]| s.iter().all(u8::is_ascii_digit);
    let time_ok = !time.is_empty() && time.len() <= 20 && digits(time);
    let zone_ok = match zone {
        [sign, rest @ ..] => matches!(sign, b'+' | b'-') && rest.len() == 4 && digits(rest),
        [] => false,
    };
    if !time_ok || !zone_ok {
        return None;
    }
    ident.get(open.checked_add(1)?..close)
}

/// The header lines, read in order.
struct Lines<'a> {
    rest: &'a [u8],
}

impl<'a> Lines<'a> {
    fn new(headers: &'a [u8]) -> Self {
        Self { rest: headers }
    }

    /// The next line, without its newline, if it satisfies `accept`.
    fn take_if(&mut self, accept: impl Fn(&[u8]) -> bool) -> Option<&'a [u8]> {
        let end = self.rest.iter().position(|&b| b == b'\n')?;
        let line = self.rest.get(..end)?;
        if !accept(line) {
            return None;
        }
        self.rest = self.rest.get(end.checked_add(1)?..)?;
        Some(line)
    }

    /// The value of the next line if it is the header `name` (`name value`).
    fn value(&mut self, name: &[u8]) -> Option<&'a [u8]> {
        let line = self.take_if(|line| {
            line.strip_prefix(name)
                .is_some_and(|rest| rest.first() == Some(&b' '))
        })?;
        line.get(name.len().checked_add(1)?..)
    }

    /// The next line if it continues the previous header (starts with a space).
    fn continuation(&mut self) -> Option<&'a [u8]> {
        self.take_if(|line| line.first() == Some(&b' '))
    }

    /// The name of the next header line, if any line is left.
    fn next_name(&self) -> Option<&'a [u8]> {
        let line = self.rest.split(|&b| b == b'\n').next()?;
        if self.rest.is_empty() {
            return None;
        }
        Some(line.split(|&b| b == b' ').next().unwrap_or(line))
    }
}

#[cfg(test)]
#[allow(clippy::string_slice, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    const TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
    const PARENT: &str = "8b137891791fe96927ad78e64b0aad7bded08bdc";

    fn commit(headers: &str, message: &str) -> Vec<u8> {
        format!("{headers}\n{message}").into_bytes()
    }

    fn base(extra: &str) -> String {
        format!(
            "tree {TREE}\nparent {PARENT}\nauthor A U <a@x> 1700000000 +0000\n\
             committer Agent <agent@writ> 1700000000 +0100\n{extra}"
        )
    }

    #[test]
    fn parses_what_git_writes() {
        let c = Commit::parse(commit(&base(""), "Subject\n\nWrit: wrt_X\n")).unwrap();
        assert_eq!(c.tree().as_str(), TREE);
        assert_eq!(c.parents().len(), 1);
        assert_eq!(c.parents()[0].as_str(), PARENT);
        assert_eq!(c.committer_email(), "agent@writ");
        assert_eq!(c.message(), b"Subject\n\nWrit: wrt_X\n");
        assert_eq!(c.writ_trailers(), vec!["wrt_X".to_owned()]);
        assert_eq!(c.algo(), HashAlgo::Sha1);
        // An encoding and a mergetag (with its continuation lines).
        let extra = "encoding ISO-8859-1\nmergetag object abc\n type commit\n tag v1\n";
        let c = Commit::parse(commit(&base(extra), "m\n")).unwrap();
        assert_eq!(c.message(), b"m\n");
        // A root commit, and an empty message.
        let root = format!("tree {TREE}\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n");
        assert!(
            Commit::parse(commit(&root, ""))
                .unwrap()
                .parents()
                .is_empty()
        );
    }

    #[test]
    fn refuses_anything_else() {
        let cases: Vec<(Vec<u8>, CommitError)> = vec![
            (base("").into_bytes(), CommitError::NoMessage),
            (
                commit(&base("gpgsig -----BEGIN SSH SIGNATURE-----\n x\n"), "m"),
                CommitError::AlreadySigned,
            ),
            (
                commit(&base("gpgsig-sha256 x\n"), "m"),
                CommitError::AlreadySigned,
            ),
            (
                commit(&base("x-custom 1\n"), "m"),
                CommitError::Header("x-custom".into()),
            ),
            (
                commit(
                    &base("parent 8b137891791fe96927ad78e64b0aad7bded08bdc\n"),
                    "m",
                ),
                CommitError::Header("parent".into()),
            ),
            (
                commit(&base("encoding a\nencoding b\n"), "m"),
                CommitError::Header("encoding".into()),
            ),
            (
                commit(&format!("parent {PARENT}\ntree {TREE}\n"), "m"),
                CommitError::Missing("tree"),
            ),
            (
                commit(&format!("tree {TREE}\ncommitter A <a@x> 1 +0000\n"), "m"),
                CommitError::Missing("author"),
            ),
            (
                commit(&format!("tree {TREE}\nauthor A <a@x> 1 +0000\n"), "m"),
                CommitError::Missing("committer"),
            ),
            (
                commit(&base("").replace("<agent@writ>", "<a@x> <b@y>"), "m"),
                CommitError::Ident("committer"),
            ),
            (
                commit(&base("").replace("<agent@writ>", "agent@writ>"), "m"),
                CommitError::Ident("committer"),
            ),
            (
                commit(&base("").replace("<agent@writ>", ">agent@writ<"), "m"),
                CommitError::Ident("committer"),
            ),
            (
                commit(&base("").replace(" 1700000000 +0100", ""), "m"),
                CommitError::Ident("committer"),
            ),
            (
                commit(
                    &base("").replace("1700000000 +0100", "1700000000 0100"),
                    "m",
                ),
                CommitError::Ident("committer"),
            ),
            (
                commit(&base("").replace("1700000000 +0100", "x +0100"), "m"),
                CommitError::Ident("committer"),
            ),
            (
                commit(
                    &base("").replace("1700000000 +0100", "1700000000 +01000"),
                    "m",
                ),
                CommitError::Ident("committer"),
            ),
            (
                commit(&base("").replace("<a@x> 1700000000 +0000", "<a@x>"), "m"),
                CommitError::Ident("author"),
            ),
            (
                commit(&base("").replace(TREE, &TREE.to_uppercase()), "m"),
                CommitError::Id("tree", ObjectError::InvalidId(TREE.to_uppercase())),
            ),
            (
                commit(&base("").replace(PARENT, &PARENT[..39]), "m"),
                CommitError::Id("parent", ObjectError::InvalidId(PARENT[..39].into())),
            ),
        ];
        for (bytes, expected) in cases {
            assert_eq!(
                Commit::parse(bytes.clone()),
                Err(expected),
                "{}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }

    #[test]
    fn parents_are_bounded_on_both_sides() {
        let with = |n: usize| {
            let parents: String = (0..n).map(|_| format!("parent {PARENT}\n")).collect();
            commit(
                &format!(
                    "tree {TREE}\n{parents}author A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n"
                ),
                "m",
            )
        };
        assert_eq!(
            Commit::parse(with(MAX_PARENTS)).unwrap().parents().len(),
            MAX_PARENTS
        );
        assert_eq!(
            Commit::parse(with(MAX_PARENTS + 1)),
            Err(CommitError::TooManyParents)
        );
    }

    #[test]
    fn kinds_from_the_first_bytes() {
        assert_eq!(kind(b"tree abc\n"), ObjectKind::Commit);
        assert_eq!(kind(b"object abc\ntype commit\n"), ObjectKind::Tag);
        assert_eq!(kind(b"certificate version 0.1\n"), ObjectKind::Other);
        assert_eq!(kind(b""), ObjectKind::Other);
    }
}
