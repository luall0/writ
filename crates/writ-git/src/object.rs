//! Object ids: lowercase hex of a SHA-1 (40 characters) or SHA-256 (64) over git's object
//! encoding (`<type> <size>\0<content>`). An id is always computed here from the bytes; the
//! sender's word for it is never taken.
//!
//! SHA-1 is computed with collision detection (the algorithm of git's own `sha1dc`): an
//! object built to collide with another is refused, not given the id it claims.

use std::fmt;

use sha2::Digest as _;
use writ_core::names::CommitId;

/// Why an object id can't be had.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObjectError {
    /// The SHA-1 collision detection found an attack in the object.
    #[error("the object is built to collide with another one (SHA-1 collision attack)")]
    Collision,
    #[error("invalid object id {0:?}")]
    InvalidId(String),
}

/// The repository's hash algorithm, told by the length of the ids in a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlgo {
    Sha1,
    Sha256,
}

impl HashAlgo {
    /// Bytes of a raw id.
    pub fn raw_len(self) -> usize {
        match self {
            HashAlgo::Sha1 => 20,
            HashAlgo::Sha256 => 32,
        }
    }

    /// Characters of a hex id.
    pub fn hex_len(self) -> usize {
        match self {
            HashAlgo::Sha1 => 40,
            HashAlgo::Sha256 => 64,
        }
    }

    /// The policy's name for it.
    pub fn object_format(self) -> writ_core::config::ObjectFormat {
        match self {
            HashAlgo::Sha1 => writ_core::config::ObjectFormat::Sha1,
            HashAlgo::Sha256 => writ_core::config::ObjectFormat::Sha256,
        }
    }

    /// The header git puts a commit's signature in: `gpgsig`, or `gpgsig-sha256` in a
    /// SHA-256 repository.
    pub fn signature_header(self) -> &'static str {
        match self {
            HashAlgo::Sha1 => "gpgsig",
            HashAlgo::Sha256 => "gpgsig-sha256",
        }
    }

    /// The id of an object of `kind` with `content`.
    pub fn hash(self, kind: ObjectType, content: &[u8]) -> Result<ObjectId, ObjectError> {
        let header = format!("{} {}\0", kind.name(), content.len());
        let raw: Vec<u8> = match self {
            HashAlgo::Sha1 => {
                let mut hasher = sha1_checked::Sha1::new();
                hasher.update(header.as_bytes());
                hasher.update(content);
                let result = hasher.try_finalize();
                if result.has_collision() {
                    return Err(ObjectError::Collision);
                }
                result.hash().to_vec()
            }
            HashAlgo::Sha256 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(header.as_bytes());
                hasher.update(content);
                hasher.finalize().to_vec()
            }
        };
        Ok(ObjectId::from_raw(self, &raw))
    }
}

/// The object types git stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ObjectType {
    /// The name in git's object encoding.
    pub fn name(self) -> &'static str {
        match self {
            ObjectType::Commit => "commit",
            ObjectType::Tree => "tree",
            ObjectType::Blob => "blob",
            ObjectType::Tag => "tag",
        }
    }
}

/// An object id: lowercase hex, of its algorithm's length.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId {
    algo: HashAlgo,
    hex: String,
}

impl ObjectId {
    /// From the raw bytes of a tree entry (their length is checked by the caller).
    pub(crate) fn from_raw(algo: HashAlgo, raw: &[u8]) -> Self {
        let hex = raw.iter().map(|b| format!("{b:02x}")).collect();
        Self { algo, hex }
    }

    /// From hex text in an object (a commit's `tree` and `parent` lines): lowercase hex of
    /// `algo`'s length only.
    pub fn parse_hex(algo: HashAlgo, text: &[u8]) -> Result<Self, ObjectError> {
        let valid = text.len() == algo.hex_len()
            && text
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b));
        let hex = std::str::from_utf8(text).ok().filter(|_| valid);
        match hex {
            Some(hex) => Ok(Self {
                algo,
                hex: hex.to_owned(),
            }),
            None => Err(ObjectError::InvalidId(
                String::from_utf8_lossy(text).into_owned(),
            )),
        }
    }

    pub fn algo(&self) -> HashAlgo {
        self.algo
    }

    pub fn as_str(&self) -> &str {
        &self.hex
    }

    /// The same id as the policy's commit id.
    pub fn to_commit_id(&self) -> Result<CommitId, ObjectError> {
        self.hex
            .parse()
            .map_err(|_| ObjectError::InvalidId(self.hex.clone()))
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex)
    }
}

#[cfg(test)]
#[allow(clippy::string_slice, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_git_s() {
        // `git hash-object -t blob --stdin <<< ''` and the empty tree, in both formats.
        assert_eq!(
            HashAlgo::Sha1
                .hash(ObjectType::Blob, b"\n")
                .unwrap()
                .as_str(),
            "8b137891791fe96927ad78e64b0aad7bded08bdc"
        );
        assert_eq!(
            HashAlgo::Sha1.hash(ObjectType::Tree, b"").unwrap().as_str(),
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        );
        assert_eq!(
            HashAlgo::Sha256
                .hash(ObjectType::Tree, b"")
                .unwrap()
                .as_str(),
            "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321"
        );
    }

    #[test]
    fn hex_ids_are_strict() {
        let good = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
        assert_eq!(
            ObjectId::parse_hex(HashAlgo::Sha1, good.as_bytes())
                .unwrap()
                .as_str(),
            good
        );
        for bad in [
            &good.to_uppercase()[..],
            &good[..39],
            "4b825dc642cb6eb9a060e54bf8d69288fbee490g",
            "",
        ] {
            assert_eq!(
                ObjectId::parse_hex(HashAlgo::Sha1, bad.as_bytes()),
                Err(ObjectError::InvalidId(bad.to_owned())),
                "{bad}"
            );
        }
        // A SHA-1 id in a SHA-256 repository.
        assert_eq!(
            ObjectId::parse_hex(HashAlgo::Sha256, good.as_bytes()),
            Err(ObjectError::InvalidId(good.to_owned()))
        );
    }
}
