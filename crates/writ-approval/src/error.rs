//! [`ServiceError`]: why the approval service didn't do what was asked.

use writ_core::names::TicketId;
use writ_store::StoreError;

/// Why a request was turned down: a stable code that tests (and, later, clients) match on,
/// never the message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    /// The ticket fits no template or isn't a valid ticket (every reason given).
    Rejected,
    /// The ticket file isn't UTF-8.
    NotUtf8,
    /// The session key's algorithm isn't accepted (Ed25519 or P-256 only).
    SessionKey,
    /// Too many tickets wait, in all or for this session.
    TooManyPending,
    /// More submissions from this address than the rate allows.
    RateLimited,
    /// The ticket or lease isn't in a state that allows this (not pending, nothing to revoke,
    /// a lease that is gone).
    WrongState,
    /// A signature that can't be accepted: unreadable, another namespace, a key not in
    /// `approvers`, other bytes, non-canonical bytes, or none where one is required.
    Signature,
    /// The signed ticket can't become or amend a lease (narrowing, fit, expiry, subject).
    Lifecycle,
    /// The feedback is empty or too long.
    Feedback,
    /// The ticket's session can't be used: its stored key doesn't match, or the daemon can't
    /// watch the process the lease is bound to.
    Session,
    /// A proof that can't be made: not a `writ-proof/1` document (a namespace refused, a
    /// message empty or too long), a key no template signs with, or the signer failed.
    Proof,
    /// The daemon is sealed: nothing but `info` and an unseal is served.
    Sealed,
    /// An unseal that can't be accepted: not this boot's or this daemon's document, a
    /// signature not an approver's, a wrong passphrase, or a keystore that doesn't open.
    Unseal,
    /// An admin change that can't be accepted: not a `writ-admin/2` document, against a
    /// version no longer in force, or a file that doesn't pass the startup checks.
    Admin,
}

/// Why a request to the service failed. What a client may see is its `Display`; an internal
/// cause ([`ServiceError::Internal`], [`ServiceError::AuditLog`]) stays in the `source` chain,
/// for the daemon's log only.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// Turned down, for the reasons given (already in the audit log when it is a denial).
    #[error("{message}")]
    Refused {
        code: RefusalCode,
        message: String,
        /// Every reason, when there are several (a ticket that fits no template).
        reasons: Vec<String>,
    },
    #[error("ticket {0} does not exist")]
    NotFound(TicketId),
    /// The audit log can't be written: nothing was done (no change without its line).
    #[error("the audit log can't be written; nothing was done")]
    AuditLog(#[source] StoreError),
    /// The configuration can't work (found at startup).
    #[error("invalid configuration: {0}")]
    Config(String),
    /// A fault inside the daemon (the store, a poisoned lock, the clock). Fails closed.
    #[error("internal error in the daemon (see its log)")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl ServiceError {
    /// Turned down for one reason.
    pub fn refused(code: RefusalCode, message: impl Into<String>) -> Self {
        Self::Refused {
            code,
            message: message.into(),
            reasons: Vec::new(),
        }
    }

    /// A ticket rejected, with every reason.
    pub fn rejected(message: impl Into<String>, reasons: Vec<String>) -> Self {
        Self::Refused {
            code: RefusalCode::Rejected,
            message: message.into(),
            reasons,
        }
    }

    /// The refusal's code, if this is a refusal.
    pub fn code(&self) -> Option<RefusalCode> {
        match self {
            Self::Refused { code, .. } => Some(*code),
            _ => None,
        }
    }

    pub fn internal(cause: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Internal(cause.into())
    }

    /// Every reason joined with `; `, or the message when there are none: the reason the
    /// audit log records.
    pub fn reason_text(&self) -> String {
        match self {
            Self::Refused { reasons, .. } if !reasons.is_empty() => reasons.join("; "),
            other => other.to_string(),
        }
    }

    /// The error and its causes, `: `-separated: for the daemon's log, never for a client.
    pub fn detail(&self) -> String {
        let mut text = self.to_string();
        let mut source = std::error::Error::source(self);
        while let Some(cause) = source {
            text.push_str(": ");
            text.push_str(&cause.to_string());
            source = cause.source();
        }
        text
    }
}

/// What a client sees: the message and reasons of a refusal, the bare message otherwise
/// (never an internal cause).
impl From<ServiceError> for writ_proto::ApiError {
    fn from(error: ServiceError) -> Self {
        match error {
            ServiceError::Refused {
                message, reasons, ..
            } => Self::with_reasons(message, reasons),
            other => Self::new(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clients_never_see_an_internal_cause() {
        let internal = ServiceError::internal("disk on fire at /var/lib/writ/leases.db");
        let shown = writ_proto::ApiError::from(ServiceError::internal("disk on fire"));
        assert_eq!(shown.message, "internal error in the daemon (see its log)");
        assert!(shown.reasons.is_empty());
        assert_eq!(
            internal.detail(),
            "internal error in the daemon (see its log): disk on fire at /var/lib/writ/leases.db"
        );
        let rejected = ServiceError::rejected("ticket rejected", vec!["a".into(), "b".into()]);
        assert_eq!(rejected.reason_text(), "a; b");
        let api = writ_proto::ApiError::from(rejected);
        assert_eq!(api.message, "ticket rejected");
        assert_eq!(api.reasons, vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(
            ServiceError::refused(RefusalCode::Feedback, "no").reason_text(),
            "no"
        );
    }
}
