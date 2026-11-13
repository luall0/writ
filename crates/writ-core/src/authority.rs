//! The files that grant authority, as the daemon holds them since M5: the policy (repo
//! registry and templates), `approvers` and `readers`. After `writd init` they change only by
//! an approver's signed admin change (`writ-admin/2`, [`crate::signed::Admin`]) or
//! `writd recover` on the host; the daemon keeps every version, and names each by the SHA-256
//! of its text ([`TextDigest`]).
//!
//! And the sealed tokens (an `https://` upstream's, a notifier's kept sealed): added from the
//! approver's machine, encrypted there to the keystore's recipient, by a signed `writ-token/3`
//! ([`crate::signed::Token`]) naming the id's change count it replaces and the token file in
//! force ([`PreviousToken`]), and carrying the ciphertext ([`SealedToken`]).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The longest text an admin change may carry, in bytes: escaped as JSON (at most twice its
/// size, control characters being refused), the request stays within the 256 KiB body.
pub const MAX_ADMIN_TEXT: usize = 100 * 1024;

/// Which file an admin change replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminTarget {
    /// The repo registry and the templates (`policy.yaml`).
    Policy,
    /// Who may sign (`approvers`).
    Approvers,
    /// Who may use the approval API (`readers`).
    Readers,
}

impl AdminTarget {
    pub const ALL: [AdminTarget; 3] = [Self::Policy, Self::Approvers, Self::Readers];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Approvers => "approvers",
            Self::Readers => "readers",
        }
    }
}

impl fmt::Display for AdminTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An admin target that isn't one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not policy, approvers or readers")]
pub struct AdminTargetError(pub String);

impl FromStr for AdminTarget {
    type Err = AdminTargetError;

    fn from_str(s: &str) -> Result<Self, AdminTargetError> {
        Self::ALL
            .into_iter()
            .find(|t| t.as_str() == s)
            .ok_or_else(|| AdminTargetError(s.chars().take(32).collect()))
    }
}

/// The SHA-256 of a text, 64 lowercase hex characters: how an admin change names the version
/// it replaces.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TextDigest(String);

/// A digest that isn't 64 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a text digest is 64 lowercase hex characters (SHA-256)")]
pub struct TextDigestError;

impl TextDigest {
    /// The digest of `text`.
    pub fn of(text: &str) -> Self {
        Self::of_bytes(text.as_bytes())
    }

    /// The digest of `bytes` (a sealed token's file).
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(
            Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        )
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TextDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for TextDigest {
    type Error = TextDigestError;

    fn try_from(value: String) -> Result<Self, TextDigestError> {
        let hex = |c: char| c.is_ascii_digit() || ('a'..='f').contains(&c);
        if value.len() != 64 || !value.chars().all(hex) {
            return Err(TextDigestError);
        }
        Ok(Self(value))
    }
}

impl From<TextDigest> for String {
    fn from(value: TextDigest) -> String {
        value.0
    }
}

/// The text of an authority file in an admin change: at most [`MAX_ADMIN_TEXT`] bytes, no
/// control character but newlines and tabs (it is shown to the approver as is).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AdminText(String);

/// An admin text that can't be taken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdminTextError {
    #[error("the file is {0} bytes: at most {MAX_ADMIN_TEXT} are taken")]
    TooLong(usize),
    #[error("the file holds a control character (only newlines and tabs are taken)")]
    Control,
}

impl AdminText {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Its digest.
    pub fn digest(&self) -> TextDigest {
        TextDigest::of(&self.0)
    }
}

impl TryFrom<String> for AdminText {
    type Error = AdminTextError;

    fn try_from(value: String) -> Result<Self, AdminTextError> {
        if value.len() > MAX_ADMIN_TEXT {
            return Err(AdminTextError::TooLong(value.len()));
        }
        if value
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            return Err(AdminTextError::Control);
        }
        Ok(Self(value))
    }
}

impl From<AdminText> for String {
    fn from(value: AdminText) -> String {
        value.0
    }
}

/// The longest sealed token a `writ-token/3` may carry, in characters of base64: an age file
/// holding a token of at most 1 KiB, to one recipient, is a few hundred bytes.
pub const MAX_SEALED_TOKEN: usize = 8 * 1024;

/// A token encrypted to the keystore's recipient: the age file, in standard base64 (with its
/// padding), at most [`MAX_SEALED_TOKEN`] characters. Only the keystore's identity reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SealedToken(String);

/// A sealed token that can't be taken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealedTokenError {
    #[error("the sealed token is {0} characters: at most {MAX_SEALED_TOKEN} are taken")]
    TooLong(usize),
    #[error("the sealed token is not standard base64")]
    NotBase64,
}

impl SealedToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SealedToken {
    type Error = SealedTokenError;

    fn try_from(value: String) -> Result<Self, SealedTokenError> {
        if value.len() > MAX_SEALED_TOKEN {
            return Err(SealedTokenError::TooLong(value.len()));
        }
        let body = value.trim_end_matches('=');
        let padding = value.len().saturating_sub(body.len());
        let alphabet = |c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/';
        if value.is_empty()
            || !value.len().is_multiple_of(4)
            || padding > 2
            || !body.chars().all(alphabet)
        {
            return Err(SealedTokenError::NotBase64);
        }
        Ok(Self(value))
    }
}

impl From<SealedToken> for String {
    fn from(value: SealedToken) -> String {
        value.0
    }
}

/// The token file a `writ-token/3` replaces: none yet (`none`), or the one whose bytes have
/// this digest. Replayed, or signed against a file no longer there, a change does nothing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum PreviousToken {
    None,
    File(TextDigest),
}

impl fmt::Display for PreviousToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::File(digest) => digest.fmt(f),
        }
    }
}

/// A previous token that is neither `none` nor a digest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the token replaced is `none` or a digest of 64 lowercase hex characters (SHA-256)")]
pub struct PreviousTokenError;

impl TryFrom<String> for PreviousToken {
    type Error = PreviousTokenError;

    fn try_from(value: String) -> Result<Self, PreviousTokenError> {
        if value == "none" {
            return Ok(Self::None);
        }
        TextDigest::try_from(value)
            .map(Self::File)
            .map_err(|_| PreviousTokenError)
    }
}

impl From<PreviousToken> for String {
    fn from(value: PreviousToken) -> String {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_digests_and_texts_are_read_strictly() {
        for target in AdminTarget::ALL {
            assert_eq!(target.as_str().parse::<AdminTarget>().unwrap(), target);
        }
        for bad in ["Policy", "templates", "", "policy "] {
            assert_eq!(
                bad.parse::<AdminTarget>(),
                Err(AdminTargetError(bad.to_owned())),
                "{bad:?}"
            );
        }
        let digest = TextDigest::of("");
        assert_eq!(
            digest.as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(TextDigest::try_from(digest.to_string()).unwrap(), digest);
        for bad in ["E3B0", &"g".repeat(64), &"a".repeat(63), &"a".repeat(65)] {
            assert_eq!(
                TextDigest::try_from(bad.to_owned()),
                Err(TextDigestError),
                "{bad}"
            );
        }
        // The text's bounds, on both sides.
        assert!(AdminText::try_from("a".repeat(MAX_ADMIN_TEXT)).is_ok());
        assert_eq!(
            AdminText::try_from("a".repeat(MAX_ADMIN_TEXT + 1)),
            Err(AdminTextError::TooLong(MAX_ADMIN_TEXT + 1))
        );
        assert!(AdminText::try_from("repos:\n\tx: 1\n".to_owned()).is_ok());
        for bad in ["a\rb", "\u{1b}[2J", "a\u{0}b", "\u{85}"] {
            assert_eq!(
                AdminText::try_from(bad.to_owned()),
                Err(AdminTextError::Control),
                "{bad:?}"
            );
        }
    }
    #[test]
    fn sealed_tokens_and_the_file_they_replace_are_read_strictly() {
        // The bound, on both sides.
        assert!(SealedToken::try_from("A".repeat(MAX_SEALED_TOKEN)).is_ok());
        assert_eq!(
            SealedToken::try_from("A".repeat(MAX_SEALED_TOKEN + 4)),
            Err(SealedTokenError::TooLong(MAX_SEALED_TOKEN + 4))
        );
        for good in ["YWdl", "YWc=", "YQ==", "a+b/"] {
            assert_eq!(
                SealedToken::try_from(good.to_owned()).unwrap().as_str(),
                good
            );
        }
        // Hostile or malformed: never taken.
        for bad in [
            "",
            "YWd",
            "YQ===",
            "Y===",
            "YW-l",
            "YW_l",
            "YW l",
            "YWdl\n",
            "=YWd",
            "YQ=a",
            "\u{1b}[2J",
            "YWÿl",
        ] {
            assert_eq!(
                SealedToken::try_from(bad.to_owned()),
                Err(SealedTokenError::NotBase64),
                "{bad:?}"
            );
        }
        assert_eq!(
            PreviousToken::try_from("none".to_owned()),
            Ok(PreviousToken::None)
        );
        let digest = TextDigest::of_bytes(b"age file");
        assert_eq!(
            PreviousToken::try_from(digest.to_string()),
            Ok(PreviousToken::File(digest.clone()))
        );
        assert_eq!(
            PreviousToken::File(digest.clone()).to_string(),
            digest.to_string()
        );
        for bad in ["None", "", "null", "E3B0", &"a".repeat(63)] {
            assert_eq!(
                PreviousToken::try_from(bad.to_owned()),
                Err(PreviousTokenError),
                "{bad}"
            );
        }
    }
}
