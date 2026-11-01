//! The commit git writes once the signature is in it, and its id: what the ledger records.
//!
//! git signs the commit's bytes, then puts the signature in a `gpgsig` header (`gpgsig-sha256`
//! in a SHA-256 repository) at the end of the headers, each line of the signature after a
//! space (`do_sign_commit` in git's `commit.c`), and writes that object. The id of the
//! unsigned bytes would let the same commit be pushed without its signature; the id of this
//! one only matches the commit the daemon signed.

use crate::commit::Commit;
use crate::object::{ObjectError, ObjectId, ObjectType};

/// Why the signed commit can't be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignedError {
    /// The armored signature doesn't end its last line: its header would run into the
    /// message.
    #[error("the signature doesn't end with a newline")]
    Unterminated,
    #[error(transparent)]
    Object(#[from] ObjectError),
}

/// The bytes of `commit` with `signature` (the armored text the signing program wrote, every
/// line ended) in its signature header, as git builds them.
pub fn signed_bytes(commit: &Commit, signature: &str) -> Result<Vec<u8>, SignedError> {
    if !signature.ends_with('\n') {
        return Err(SignedError::Unterminated);
    }
    let bytes = commit.bytes();
    // Right after the newline that ends the last header (the blank line follows).
    let at = bytes
        .windows(2)
        .position(|w| w == b"\n\n")
        .and_then(|p| p.checked_add(1))
        .unwrap_or(bytes.len());
    let (headers, rest) = bytes.split_at_checked(at).unwrap_or((bytes, b""));
    let mut header = commit.algo().signature_header().as_bytes().to_vec();
    for line in signature.split_inclusive('\n') {
        header.push(b' ');
        header.extend_from_slice(line.as_bytes());
    }
    Ok([headers, &header, rest].concat())
}

/// The id of the signed commit.
pub fn signed_id(commit: &Commit, signature: &str) -> Result<ObjectId, SignedError> {
    let bytes = signed_bytes(commit, signature)?;
    Ok(commit.algo().hash(ObjectType::Commit, &bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signature_goes_after_the_headers() {
        let commit = Commit::parse(
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
              author A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\nm\n"
                .to_vec(),
        )
        .unwrap();
        let signed = signed_bytes(&commit, "-----BEGIN X-----\nabc\n-----END X-----\n").unwrap();
        assert_eq!(
            String::from_utf8(signed).unwrap(),
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\
             gpgsig -----BEGIN X-----\n abc\n -----END X-----\n\nm\n"
        );
    }

    #[test]
    fn a_signature_must_end_its_last_line() {
        let commit = Commit::parse(
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
              author A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\nm\n"
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            signed_bytes(&commit, "-----BEGIN X-----\nabc\n-----END X-----"),
            Err(SignedError::Unterminated)
        );
        assert_eq!(
            signed_id(&commit, "-----BEGIN X-----\nabc\n-----END X-----"),
            Err(SignedError::Unterminated)
        );
    }
}
