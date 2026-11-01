//! The other documents an approver may sign, besides tickets: a refusal and a revocation,
//! required when the daemon's `decisions` setting is `signed`, and a proof, always required:
//! the approver lets an agent signing key sign one message for a remote that asks for it
//! before it shows commits as verified (Forgejo, Gitea).
//!
//! Like a ticket, each is a [`Canonical`] document: canonical bytes, `kind` first, decoded only
//! from exactly those bytes. The `kind` keeps one signed document from
//! ever being read as another: a refusal can't pass for an approval, nor a revocation for a
//! refusal, nor a proof for any of them. Replaying one only repeats it (refusing a refused
//! ticket, revoking a revoked lease, the same signature over the same message), which changes
//! nothing.

use serde::{Deserialize, Serialize};

use crate::canonical::Canonical;
use crate::names::{KeyId, ProofNamespace, TicketId};

/// The longest feedback a refusal may carry.
pub const MAX_FEEDBACK_CHARS: usize = 4_000;

/// The longest message a proof may sign, in bytes (a remote's challenge: Forgejo's is a
/// 64-character token).
pub const MAX_PROOF_MESSAGE_BYTES: usize = 4_096;

/// Only `"writ-refusal/1"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum RefusalKind {
    #[default]
    #[serde(rename = "writ-refusal/1")]
    V1,
}

/// Only `"writ-revocation/1"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum RevocationKind {
    #[default]
    #[serde(rename = "writ-revocation/1")]
    V1,
}

/// Only `"writ-proof/1"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ProofKind {
    #[default]
    #[serde(rename = "writ-proof/1")]
    V1,
}

/// What a proof signs: a remote's message, 1 to [`MAX_PROOF_MESSAGE_BYTES`] bytes of UTF-8,
/// exactly as given (no newline added or removed: `ssh-keygen -Y sign` signs its input as it
/// is). Remote-written text: shown escaped, never interpreted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProofMessage(String);

/// A proof message that is empty or too long.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the message to sign is {0} bytes: it must be 1 to {MAX_PROOF_MESSAGE_BYTES}")]
pub struct ProofMessageError(pub usize);

impl ProofMessage {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProofMessage {
    type Error = ProofMessageError;

    fn try_from(value: String) -> Result<Self, ProofMessageError> {
        if value.is_empty() || value.len() > MAX_PROOF_MESSAGE_BYTES {
            return Err(ProofMessageError(value.len()));
        }
        Ok(Self(value))
    }
}

impl From<ProofMessage> for String {
    fn from(value: ProofMessage) -> String {
        value.0
    }
}

/// The approver lets agent signing key `key` sign `message` in `namespace`: the SSHSIG a
/// remote asks for to prove the key is its account's (Forgejo and Gitea: namespace `gitea`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub kind: ProofKind,
    pub key: KeyId,
    pub namespace: ProofNamespace,
    pub message: ProofMessage,
}

impl Canonical for Proof {
    const KIND: &'static str = "writ-proof/1";
}

impl Proof {
    pub fn new(key: KeyId, namespace: ProofNamespace, message: ProofMessage) -> Self {
        Self {
            kind: ProofKind::V1,
            key,
            namespace,
            message,
        }
    }
}

/// The approver refuses a pending ticket, with feedback for the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    pub kind: RefusalKind,
    pub ticket: TicketId,
    pub feedback: String,
}

/// The approver revokes a lease, or withdraws a pending ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub kind: RevocationKind,
    pub id: TicketId,
}

impl Canonical for Refusal {
    const KIND: &'static str = "writ-refusal/1";
}

impl Refusal {
    pub fn new(ticket: TicketId, feedback: String) -> Self {
        Self {
            kind: RefusalKind::V1,
            ticket,
            feedback,
        }
    }
}

impl Canonical for Revocation {
    const KIND: &'static str = "writ-revocation/1";
}

impl Revocation {
    pub fn new(id: TicketId) -> Self {
        Self {
            kind: RevocationKind::V1,
            id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::CanonicalError;

    fn id(n: u8) -> TicketId {
        TicketId::from_parts(1_800_000_000_000, [n; 10])
    }

    #[test]
    fn each_kind_matches_its_serde_name() {
        let refusal = Refusal::new(id(1), String::new())
            .canonical_bytes()
            .unwrap();
        assert!(refusal.starts_with(format!(r#"{{"kind":"{}""#, Refusal::KIND).as_bytes()));
        let revocation = Revocation::new(id(1)).canonical_bytes().unwrap();
        assert!(revocation.starts_with(format!(r#"{{"kind":"{}""#, Revocation::KIND).as_bytes()));
        let proof = proof("gitea", "t").canonical_bytes().unwrap();
        assert!(proof.starts_with(format!(r#"{{"kind":"{}""#, Proof::KIND).as_bytes()));
    }

    fn proof(namespace: &str, message: &str) -> Proof {
        Proof::new(
            "agent-01".parse().unwrap(),
            namespace.parse().unwrap(),
            message.to_owned().try_into().unwrap(),
        )
    }

    #[test]
    fn a_proof_is_pinned_strict_and_bounded() {
        let proof = proof("gitea", "e3b0c442\n");
        let bytes = proof.canonical_bytes().unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            r#"{"kind":"writ-proof/1","key":"agent-01","namespace":"gitea","message":"e3b0c442\n"}"#
        );
        assert_eq!(Proof::from_canonical(&bytes).unwrap(), proof);
        // A proof is never a refusal or a revocation, nor the other way round.
        assert!(matches!(
            Revocation::from_canonical(&bytes),
            Err(CanonicalError::Decode { .. })
        ));
        let revocation = Revocation::new(id(1)).canonical_bytes().unwrap();
        assert!(matches!(
            Proof::from_canonical(&revocation),
            Err(CanonicalError::Decode { .. })
        ));
        // The namespace and the message are checked as the document is read.
        let text = String::from_utf8(bytes).unwrap();
        for (bad, why) in [
            (text.replace("\"gitea\"", "\"git\""), "commit signatures"),
            (text.replace("\"gitea\"", "\"writ-approval\""), "Writ's own"),
            (text.replace("\"e3b0c442\\n\"", "\"\""), "0 bytes"),
            (
                text.replace("e3b0c442\\n", &"a".repeat(MAX_PROOF_MESSAGE_BYTES + 1)),
                "4097 bytes",
            ),
        ] {
            let error = Proof::from_canonical(bad.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(error.contains(why), "{bad}: {error}");
        }
        // At the bound: fine.
        let longest = text.replace("e3b0c442\\n", &"a".repeat(MAX_PROOF_MESSAGE_BYTES));
        assert!(Proof::from_canonical(longest.as_bytes()).is_ok());
        assert_eq!(
            ProofMessage::try_from("é".repeat(2049)).unwrap_err(),
            ProofMessageError(4098)
        );
    }

    #[test]
    fn canonical_forms_are_pinned_and_strict() {
        let refusal = Refusal::new(id(1), "don't touch \"billing\"".to_owned());
        let bytes = refusal.canonical_bytes().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(
            text.starts_with(r#"{"kind":"writ-refusal/1","ticket":"wrt_"#),
            "{text}"
        );
        assert!(
            text.ends_with(r#""feedback":"don't touch \"billing\""}"#),
            "{text}"
        );
        assert_eq!(Refusal::from_canonical(&bytes).unwrap(), refusal);

        let revocation = Revocation::new(id(2));
        let bytes = revocation.canonical_bytes().unwrap();
        assert!(bytes.starts_with(br#"{"kind":"writ-revocation/1","id":"wrt_"#));
        assert_eq!(Revocation::from_canonical(&bytes).unwrap(), revocation);

        // One kind is never read as another, and only canonical bytes decode.
        assert!(matches!(
            Revocation::from_canonical(&refusal.canonical_bytes().unwrap()),
            Err(CanonicalError::Decode { .. })
        ));
        assert!(matches!(
            Refusal::from_canonical(&bytes),
            Err(CanonicalError::Decode { .. })
        ));
        let spaced = String::from_utf8(bytes).unwrap().replace(':', ": ");
        assert!(matches!(
            Revocation::from_canonical(spaced.as_bytes()),
            Err(CanonicalError::NotCanonical { .. })
        ));
    }
}
