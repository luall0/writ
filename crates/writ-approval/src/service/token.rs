//! Sealed tokens: an approver's signed `writ-token/2` puts a token (encrypted on their machine
//! to the keystore's recipient) in place of the token file in force for one credential. The
//! service checks the document and its signature ([`Service::check_token`]); the daemon, which
//! holds the token files, opens the ciphertext and checks it is a token, then has the change
//! logged against the file it found ([`Service::commit_token`]) before it writes the file.
//! Every attempt is one `admin` line, which never holds the token.

use writ_core::authority::{PreviousToken, TextDigest};
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::names::KeyFingerprint;
use writ_core::signed::Token;
use writ_proto::{TokenApplied, TokenRequest};
use writ_store::{AuditEvent, EventKind, Outcome};

use super::Service;
use crate::{RefusalCode, ServiceError};

/// A token change whose document and signature passed: what the daemon opens and checks
/// before [`Service::commit_token`]. Only [`Service::check_token`] makes one (its fields are
/// private), so holding one proves the check ran.
#[derive(Debug, Clone)]
pub struct CheckedToken {
    token: Token,
    approver: KeyFingerprint,
}

impl CheckedToken {
    /// The change, as checked.
    pub fn token(&self) -> &Token {
        &self.token
    }

    /// The approver key that signed it.
    pub fn approver(&self) -> &KeyFingerprint {
        &self.approver
    }
}

fn refused(reason: impl Into<String>) -> ServiceError {
    ServiceError::refused(RefusalCode::Admin, reason)
}

impl Service {
    /// Checks a token change's document and signature: the daemon open, the document a
    /// `writ-token/2` decoded strictly, signed by an approver in force. A refusal is logged.
    pub fn check_token(
        &self,
        request: &TokenRequest,
        caller: &CallerFacts,
    ) -> Result<CheckedToken, ServiceError> {
        self.opened()?;
        let checked = self.token_document(request);
        if let Err(e) = &checked {
            self.admin_failed(None, None, &format!("token: {e}"), caller);
        }
        checked
    }

    fn token_document(&self, request: &TokenRequest) -> Result<CheckedToken, ServiceError> {
        let token = Token::from_canonical(request.document.as_bytes())
            .map_err(|e| refused(format!("not a writ-token/2 document: {e}")))?;
        if token.daemon != self.boot.daemon {
            return Err(refused(format!(
                "the token change names daemon {}, not this one ({})",
                token.daemon, self.boot.daemon
            )));
        }
        let approver = self
            .verify_approver(request.document.as_bytes(), &request.signature)
            .map_err(|reason| ServiceError::refused(RefusalCode::Signature, reason))?;
        Ok(CheckedToken { token, approver })
    }

    /// Logs a checked token change against the file the daemon found in force (`current`):
    /// refused (and logged) unless it is the one the change names; otherwise the `admin`
    /// line, with the new file's digest (`digest`), before the daemon writes it. If the log
    /// can't take it, the token is not put in force.
    pub fn commit_token(
        &self,
        checked: &CheckedToken,
        current: &PreviousToken,
        digest: &TextDigest,
        caller: &CallerFacts,
    ) -> Result<TokenApplied, ServiceError> {
        self.opened()?;
        let id = &checked.token.id;
        if &checked.token.previous != current {
            let error = refused(format!(
                "token {id}: the token in force is {current}, not the one this change replaces \
                 ({}): it changed since it was shown (run writ admin token {id} again)",
                checked.token.previous
            ));
            self.admin_failed(Some(&checked.approver), None, &error.to_string(), caller);
            return Err(error);
        }
        let (now, mut inner) = self.begin()?;
        let event = AuditEvent::new(now, EventKind::Admin, Outcome::Allowed)
            .approver(&checked.approver)
            .caller(caller)
            .reason(format!("token {id}: sha256 {digest} replaces {current}"));
        Self::log(&mut inner, &event)?;
        Ok(TokenApplied {
            id: id.clone(),
            digest: digest.clone(),
            replaced: current.clone(),
            signed_by: checked.approver.clone(),
        })
    }
}
