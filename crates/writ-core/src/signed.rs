//! The other documents an approver may sign, besides tickets: a refusal and a revocation,
//! required when the daemon's `decisions` setting is `signed`.
//!
//! Like a ticket, each is a [`Canonical`] document: canonical bytes, `kind` first, decoded only
//! from exactly those bytes. The `kind` keeps one signed document from
//! ever being read as another: a refusal can't pass for an approval, nor a revocation for a
//! refusal. Replaying one only repeats it (refusing a refused ticket, revoking a revoked
//! lease), which changes nothing.

use serde::{Deserialize, Serialize};

use crate::canonical::Canonical;
use crate::names::TicketId;

/// The longest feedback a refusal may carry.
pub const MAX_FEEDBACK_CHARS: usize = 4_000;

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
