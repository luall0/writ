//! Validated names and identifiers: repos, templates, key ids, emails, ticket ids, commit ids
//! and key fingerprints.
//!
//! Each is a string newtype that can only hold a valid value, so the rest of the policy never
//! re-checks a name.

use std::fmt;
use std::str::FromStr;

/// A value that failed validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind} {value:?}: {why}")]
pub struct NameError {
    pub kind: &'static str,
    pub value: String,
    pub why: &'static str,
}

macro_rules! string_newtype {
    ($(#[$meta:meta])* $name:ident, $kind:literal, $validate:path) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = NameError;

            fn try_from(value: String) -> Result<Self, NameError> {
                match $validate(&value) {
                    Ok(()) => Ok(Self(value)),
                    Err(why) => Err(NameError { kind: $kind, value, why }),
                }
            }
        }

        impl FromStr for $name {
            type Err = NameError;

            fn from_str(value: &str) -> Result<Self, NameError> {
                Self::try_from(value.to_owned())
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

string_newtype!(
    /// A repo in the registry: a plain name (`omega-code`), never a path.
    RepoName, "repo name", validate_plain_name
);
string_newtype!(
    /// A template name.
    TemplateName, "template name", validate_plain_name
);
string_newtype!(
    /// The id of a key or credential held by the signer (`agent-ed25519-01`).
    KeyId, "key id", validate_plain_name
);
string_newtype!(
    /// A committer email, compared exactly (case included).
    Email, "email", validate_email
);
string_newtype!(
    /// An OpenPGP user id a key is certified with: `Name <local@domain>` (or `<local@domain>`
    /// alone), printable ASCII, the address an [`Email`].
    Uid, "OpenPGP user id", validate_uid
);
string_newtype!(
    /// A ticket id, which is also the id of the lease it becomes: `wrt_` + a ULID.
    TicketId, "ticket id", validate_ticket_id
);
string_newtype!(
    /// A git object id: lowercase hex, 40 (SHA-1) or 64 (SHA-256) characters.
    CommitId, "commit id", validate_commit_id
);
string_newtype!(
    /// An SSH key fingerprint as OpenSSH prints it: `SHA256:` + 43 base64 characters.
    KeyFingerprint, "key fingerprint", validate_fingerprint
);
string_newtype!(
    /// The SSHSIG namespace of a proof an agent signing key makes for a remote (`gitea`):
    /// never `git` (commit signatures, made only under a lease and recorded in the ledger)
    /// nor Writ's own (`writ-approval`, anything starting with `writ`).
    ProofNamespace, "proof namespace", validate_proof_namespace
);

/// `[A-Za-z0-9._-]`, 1 to 100 characters, not starting with `.` or `-`, not ending in `.git`.
fn validate_plain_name(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > 100 {
        return Err("must be 1 to 100 characters");
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("only letters, digits, '.', '_' and '-' are allowed");
    }
    if value.starts_with('.') || value.starts_with('-') {
        return Err("must not start with '.' or '-'");
    }
    if value.ends_with(".git") {
        return Err("must not end with .git");
    }
    Ok(())
}

/// An enforced identity the approver reads on screen: printable ASCII only, so neither a
/// look-alike letter (a Cyrillic `а`) nor an invisible character can make one address pass
/// for another.
fn validate_email(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > 254 {
        return Err("must be 1 to 254 characters");
    }
    if !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("printable ASCII only: no spaces, control or non-ASCII characters");
    }
    if value.contains(['<', '>', '"', ',']) {
        return Err("no '<', '>', '\"' or ','");
    }
    match value.split_once('@') {
        Some((local, domain))
            if !local.is_empty() && !domain.is_empty() && !domain.contains('@') =>
        {
            Ok(())
        }
        _ => Err("must be local@domain"),
    }
}

/// `Name <email>`: printable ASCII and spaces, at most 256 characters, the name without
/// `<`, `>` or leading and trailing spaces, then one space (when there is a name), then the
/// address in angle brackets, which must be an [`Email`]. What a remote compares to the
/// committer, so read as strictly as one.
fn validate_uid(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > 256 {
        return Err("must be 1 to 256 characters");
    }
    if !value.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
        return Err("printable ASCII and spaces only");
    }
    let inner = value
        .strip_suffix('>')
        .and_then(|rest| rest.rsplit_once('<'))
        .ok_or("must end with <local@domain>")?;
    let (name, email) = inner;
    if !name.is_empty() {
        let name = name
            .strip_suffix(' ')
            .ok_or("a space between the name and <local@domain>")?;
        if name.is_empty() || name.starts_with(' ') || name.ends_with(' ') {
            return Err("the name must not be empty or start or end with a space");
        }
        if name.contains(['<', '>']) {
            return Err("no '<' or '>' in the name");
        }
    }
    validate_email(email).map_err(|_| "the address in <> must be a valid email")
}

impl Uid {
    /// The address in its angle brackets.
    pub fn email(&self) -> Email {
        let address = self
            .0
            .strip_suffix('>')
            .and_then(|rest| rest.rsplit_once('<'))
            .map_or("", |(_, email)| email);
        // Checked when the user id was made.
        Email(address.to_owned())
    }
}

/// Crockford base32, the ULID alphabet.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn validate_ticket_id(value: &str) -> Result<(), &'static str> {
    let ulid = value.strip_prefix("wrt_").ok_or("must start with wrt_")?;
    if ulid.len() != 26 || !ulid.bytes().all(|b| CROCKFORD.contains(&b)) {
        return Err("must be wrt_ followed by a 26-character ULID");
    }
    // 26 characters carry 130 bits; a ULID is 128, so the first character is at most 7.
    if ulid.as_bytes().first().is_none_or(|&first| first > b'7') {
        return Err("ULID out of range");
    }
    Ok(())
}

fn validate_commit_id(value: &str) -> Result<(), &'static str> {
    if (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err("must be 40 or 64 lowercase hex characters")
    }
}

/// `[A-Za-z0-9._@-]`, 1 to 64 characters; `git` and `writ…` (in any case) are refused.
fn validate_proof_namespace(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > 64 {
        return Err("must be 1 to 64 characters");
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'-'))
    {
        return Err("only letters, digits, '.', '_', '@' and '-' are allowed");
    }
    let lower = value.to_ascii_lowercase();
    if lower == "git" {
        return Err(
            "git is the namespace of commit signatures: the daemon makes them only \
             under a lease, recorded in its ledger",
        );
    }
    if lower.starts_with("writ") {
        return Err("namespaces starting with writ are Writ's own (writ-approval)");
    }
    Ok(())
}

fn validate_fingerprint(value: &str) -> Result<(), &'static str> {
    let b64 = value
        .strip_prefix("SHA256:")
        .ok_or("must start with SHA256:")?;
    if b64.len() == 43
        && b64
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        Ok(())
    } else {
        Err("must be SHA256: followed by 43 base64 characters")
    }
}

impl TicketId {
    /// Builds an id from its ULID parts: milliseconds since the epoch (48 bits) and 80 random
    /// bits. The daemon supplies both; this crate reads no clock and no randomness.
    // The shifts are bounded by the loops (i < 10, i < 26): every one stays below 128 bits.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn from_parts(unix_ms: u64, random: [u8; 10]) -> Self {
        let mut value: u128 = u128::from(unix_ms & 0xFFFF_FFFF_FFFF) << 80;
        for (i, byte) in random.iter().enumerate() {
            value |= u128::from(*byte) << (8 * (9 - i));
        }
        let mut text = String::with_capacity(30);
        text.push_str("wrt_");
        for i in (0..26).rev() {
            // Masked to 5 bits: always an index into the 32-character alphabet.
            let index = usize::from(u8::try_from((value >> (5 * i)) & 0x1F).unwrap_or(0));
            text.push(char::from(CROCKFORD.get(index).copied().unwrap_or(b'0')));
        }
        Self(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_namespaces_never_git_nor_writ_s_own() {
        for good in [
            "gitea",
            "file",
            "a",
            "x@example.org",
            "gitea.v2",
            &"n".repeat(64),
        ] {
            assert!(good.parse::<ProofNamespace>().is_ok(), "{good}");
        }
        for (bad, why) in [
            ("git", "commit signatures"),
            ("GIT", "commit signatures"),
            ("Git", "commit signatures"),
            ("writ-approval", "Writ's own"),
            ("writ", "Writ's own"),
            ("WRIT-proof", "Writ's own"),
            ("writer", "Writ's own"),
            ("", "1 to 64"),
            (&"n".repeat(65), "1 to 64"),
            ("gi t", "only letters"),
            ("git\n", "only letters"),
            ("gitéa", "only letters"),
            ("a/b", "only letters"),
        ] {
            let error = bad.parse::<ProofNamespace>().unwrap_err();
            assert!(error.why.contains(why), "{bad:?}: {error}");
        }
    }

    #[test]
    fn plain_names() {
        for good in ["omega-code", "a", "homelab_scripts", "x.y"] {
            assert!(good.parse::<RepoName>().is_ok(), "{good}");
        }
        for bad in ["", "../x", "a/b", ".hidden", "-x", "omega.git", "a b", "é"] {
            assert_eq!(
                bad.parse::<RepoName>().unwrap_err().kind,
                "repo name",
                "{bad}"
            );
        }
    }

    #[test]
    fn emails() {
        assert!("user+agent@example.org".parse::<Email>().is_ok());
        for uid in [
            "Agent <agent@writ.invalid>",
            "<agent@writ.invalid>",
            "A B (bot) <a@b>",
        ] {
            let parsed = uid.parse::<Uid>().unwrap();
            assert!(uid.ends_with(&format!("<{}>", parsed.email())), "{uid}");
        }
        for (bad, why) in [
            ("Agent agent@writ.invalid", "must end with <local@domain>"),
            (
                "Agent<agent@writ.invalid>",
                "a space between the name and <local@domain>",
            ),
            (
                "Agent  <agent@writ.invalid>",
                "the name must not be empty or start or end with a space",
            ),
            (
                " <agent@writ.invalid>",
                "the name must not be empty or start or end with a space",
            ),
            ("A <b> <agent@writ.invalid>", "no '<' or '>' in the name"),
            (
                "Agent <not-an-email>",
                "the address in <> must be a valid email",
            ),
            ("Agent <a@b>\n", "printable ASCII and spaces only"),
            ("Agént <a@b>", "printable ASCII and spaces only"),
        ] {
            assert_eq!(bad.parse::<Uid>().unwrap_err().why, why, "{bad:?}");
        }
        let long = format!("{} <a@b>", "n".repeat(251));
        assert_eq!(
            long.parse::<Uid>().unwrap_err().why,
            "must be 1 to 256 characters"
        );
        let ascii = "printable ASCII only";
        for (bad, why) in [
            ("", "1 to 254 characters"),
            ("x", "local@domain"),
            ("@x", "local@domain"),
            ("x@", "local@domain"),
            ("a@b@c", "local@domain"),
            ("a b@c", ascii),
            ("<a@b>", "no '<'"),
            ("a@b\n", ascii),
            // Look-alikes and invisibles in an enforced identity.
            ("user@gm\u{430}il.com", ascii),
            ("user@gmail.com\u{202e}", ascii),
            ("user@gmail.com\u{e0041}", ascii),
            ("us\u{200b}er@gmail.com", ascii),
            ("\u{e9}lise@example.org", ascii),
        ] {
            let error = bad.parse::<Email>().unwrap_err().to_string();
            assert!(error.contains(why), "{bad:?}: {error}");
        }
        // At the length limit.
        let long = format!("{}@b.c", "a".repeat(250));
        assert_eq!(long.len(), 254);
        assert!(long.parse::<Email>().is_ok());
        assert_eq!(
            format!("a{long}").parse::<Email>().unwrap_err().why,
            "must be 1 to 254 characters"
        );
    }

    #[test]
    fn ticket_ids_are_ulids() {
        let id = TicketId::from_parts(1_793_455_331_000, [0xFF; 10]);
        assert_eq!(id.as_str().len(), 30);
        assert!(id.as_str().parse::<TicketId>().is_ok());
        assert_eq!(
            TicketId::from_parts(0, [0; 10]).as_str(),
            "wrt_00000000000000000000000000"
        );
        // Ordered by time, like ULIDs.
        assert!(TicketId::from_parts(1, [0; 10]) < TicketId::from_parts(2, [0; 10]));
        for bad in [
            "wrt_",
            "wrt_8ZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "lease_01JD8X",
            "wrt_0000000000000000000000000I",
        ] {
            assert_eq!(
                bad.parse::<TicketId>().unwrap_err().kind,
                "ticket id",
                "{bad}"
            );
        }
    }

    #[test]
    fn commit_ids_and_fingerprints() {
        assert!(
            "9e1c2f0000000000000000000000000000000000"
                .parse::<CommitId>()
                .is_ok()
        );
        assert!(
            "9E1C2F0000000000000000000000000000000000"
                .parse::<CommitId>()
                .is_err()
        );
        assert_eq!("9e1c".parse::<CommitId>().unwrap_err().kind, "commit id");
        let fp = format!("SHA256:{}", "A".repeat(43));
        assert!(fp.parse::<KeyFingerprint>().is_ok());
        assert_eq!(
            "SHA256:short".parse::<KeyFingerprint>().unwrap_err().kind,
            "key fingerprint"
        );
        assert!(
            format!("MD5:{}", "A".repeat(43))
                .parse::<KeyFingerprint>()
                .is_err()
        );
    }
}
