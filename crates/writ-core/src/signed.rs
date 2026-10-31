//! The other documents an approver may sign, besides tickets: a refusal and a revocation,
//! required when the daemon's `decisions` setting is `signed`.
//!
//! Like a ticket, each has canonical bytes (compact JSON, fields in declared order, `kind`
//! first) and decodes only from exactly those bytes. The `kind` keeps one signed document from
//! ever being read as another: a refusal can't pass for an approval, nor a revocation for a
//! refusal. Replaying one only repeats it (refusing a refused ticket, revoking a revoked
//! lease), which changes nothing.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::names::TicketId;

/// The longest feedback a refusal may carry.
pub const MAX_FEEDBACK_CHARS: usize = 4_000;

/// Errors from encoding or decoding a signed document.
#[derive(Debug, thiserror::Error)]
pub enum SignedError {
    #[error("not a canonical {kind}: {why}")]
    Decode { kind: &'static str, why: String },
    #[error("not a canonical {0}: the bytes are valid but not in canonical form")]
    NotCanonical(&'static str),
    #[error("can't encode the {kind}: {why}")]
    Encode { kind: &'static str, why: String },
}

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

impl Refusal {
    const KIND: &'static str = "writ-refusal/1";

    pub fn new(ticket: TicketId, feedback: String) -> Self {
        Self {
            kind: RefusalKind::V1,
            ticket,
            feedback,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SignedError> {
        encode(self, Self::KIND)
    }

    pub fn from_canonical(bytes: &[u8]) -> Result<Self, SignedError> {
        decode(bytes, Self::KIND, Self::canonical_bytes)
    }
}

impl Revocation {
    const KIND: &'static str = "writ-revocation/1";

    pub fn new(id: TicketId) -> Self {
        Self {
            kind: RevocationKind::V1,
            id,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SignedError> {
        encode(self, Self::KIND)
    }

    pub fn from_canonical(bytes: &[u8]) -> Result<Self, SignedError> {
        decode(bytes, Self::KIND, Self::canonical_bytes)
    }
}

fn encode<T: Serialize>(value: &T, kind: &'static str) -> Result<Vec<u8>, SignedError> {
    serde_json::to_vec(value).map_err(|e| SignedError::Encode {
        kind,
        why: e.to_string(),
    })
}

fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    kind: &'static str,
    reencode: impl Fn(&T) -> Result<Vec<u8>, SignedError>,
) -> Result<T, SignedError> {
    let value: T = serde_json::from_slice(bytes).map_err(|e| SignedError::Decode {
        kind,
        why: e.to_string(),
    })?;
    if reencode(&value)? != bytes {
        return Err(SignedError::NotCanonical(kind));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> TicketId {
        TicketId::from_parts(1_800_000_000_000, [n; 10])
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
        assert!(Revocation::from_canonical(&refusal.canonical_bytes().unwrap()).is_err());
        assert!(Refusal::from_canonical(&bytes).is_err());
        let spaced = String::from_utf8(bytes).unwrap().replace(':', ": ");
        assert!(Revocation::from_canonical(spaced.as_bytes()).is_err());
    }
}
