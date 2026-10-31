//! Canonical bytes: the one encoding of every document an approver signs (a ticket, a
//! refusal, a revocation).
//!
//! The canonical bytes of a document are compact JSON (no whitespace) with its fields in the
//! order its type declares them, set-like lists sorted and deduplicated, absent values as
//! `null`. The first field, `kind` ([`Canonical::KIND`]: `writ-ticket/1`, …), names the format,
//! so one signed document can never be read as another. [`Canonical::from_canonical`] accepts
//! only bytes that re-encode to exactly themselves.

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Errors from encoding or decoding canonical bytes. `kind` is the document's
/// [`Canonical::KIND`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    #[error("not a canonical {kind} document: {why}")]
    Decode { kind: &'static str, why: String },
    #[error("not a canonical {kind} document: the bytes are valid but not in canonical form")]
    NotCanonical { kind: &'static str },
    #[error("can't encode the {kind} document: {why}")]
    Encode { kind: &'static str, why: String },
}

/// A document with canonical bytes. Implementors declare their fields in canonical order,
/// `kind` first, as a one-value enum that only accepts [`Canonical::KIND`].
pub trait Canonical: Serialize + DeserializeOwned + Sized {
    /// The format name, the value of the `kind` field (`writ-ticket/1`).
    const KIND: &'static str;

    /// The canonical bytes: what an approver signs and the daemon verifies.
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        serde_json::to_vec(self).map_err(|e| CanonicalError::Encode {
            kind: Self::KIND,
            why: e.to_string(),
        })
    }

    /// Decodes canonical bytes, refusing anything that isn't exactly canonical (other field
    /// order, whitespace, unsorted or duplicate set entries, unknown fields, another kind).
    fn from_canonical(bytes: &[u8]) -> Result<Self, CanonicalError> {
        let value: Self = serde_json::from_slice(bytes).map_err(|e| CanonicalError::Decode {
            kind: Self::KIND,
            why: e.to_string(),
        })?;
        if value.canonical_bytes()? != bytes {
            return Err(CanonicalError::NotCanonical { kind: Self::KIND });
        }
        Ok(value)
    }
}
