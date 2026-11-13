//! Sealed tokens: an approver's signed `writ-token/3` puts a token (encrypted on their machine
//! to the keystore's recipient) in place of the token file in force for one credential. The
//! service checks the document and its signature ([`Service::check_token`]); the daemon, which
//! holds the token files, opens the ciphertext and checks it is a token, then has the change
//! committed ([`Service::commit_token`]): under the state lock, the id's change count and the
//! file in force checked against what the document replaces, the `admin` line, the count
//! bumped in the store, and the file written. The count only grows and outlives the id's
//! file, so a change applies once (the review after M7.6, A-6). Every attempt is one `admin`
//! line, which never holds the token.

use writ_core::authority::{PreviousToken, TextDigest};
use writ_core::caller::CallerFacts;
use writ_core::names::{KeyFingerprint, KeyId};
use writ_core::signed::Token;
use writ_proto::{TokenApplied, TokenRequest};
use writ_store::{AuditEvent, EventKind, Outcome};

use super::{Service, internal};
use crate::{RefusalCode, ServiceError};

/// A token change whose document and signature passed: what the daemon opens and checks
/// before [`Service::commit_token`]. Only [`Service::check_token`] makes one (its fields are
/// private), so holding one proves the check ran; it is never copied (what holds one moves
/// it).
#[derive(Debug)]
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

/// The file a change replaces, as a line names it.
fn named(previous: &PreviousToken) -> String {
    match previous {
        PreviousToken::None => "no token".to_owned(),
        PreviousToken::File(digest) => format!("sha256 {digest}"),
    }
}

impl Service {
    /// Checks a token change's document and signature: the daemon open, the document a
    /// `writ-token/3` decoded strictly, signed by an approver in force, naming this daemon.
    /// A refusal is logged.
    pub fn check_token(
        &self,
        request: &TokenRequest,
        caller: &CallerFacts,
    ) -> Result<CheckedToken, ServiceError> {
        self.opened()?;
        let checked = self
            .approver_document(
                &request.document,
                &request.signature,
                |t: &Token| &t.daemon,
                "token change",
                RefusalCode::Admin,
            )
            .map(|(token, approver)| CheckedToken { token, approver });
        if let Err(e) = &checked {
            self.admin_failed(None, None, &format!("token: {e}"), caller);
        }
        checked
    }

    /// How many token changes of `id` were applied (0: none yet), kept once `id` leaves the
    /// policy: what a `writ-token/3` replacing its token names as `version`.
    pub fn token_version(&self, id: &KeyId) -> Result<u64, ServiceError> {
        self.opened()?;
        self.lock()?.store.token_version(id).map_err(internal)
    }

    /// Commits a checked token change against the file the daemon found in force
    /// (`current`), under the state lock: refused (and logged) unless the id's change count
    /// is the one the change names and `current` the file it replaces; then the `admin` line
    /// with the new file's digest (`digest`), the count bumped in the store, and `write` (the
    /// daemon's write of the file). If the log can't take the line, nothing is counted or
    /// written; a count or a file that can't be written refuses the change, logged (a count
    /// bumped stays: the document is spent).
    pub fn commit_token(
        &self,
        checked: &CheckedToken,
        current: &PreviousToken,
        digest: &TextDigest,
        caller: &CallerFacts,
        write: impl FnOnce() -> Result<(), String>,
    ) -> Result<TokenApplied, ServiceError> {
        self.opened()?;
        let token = &checked.token;
        let id = &token.id;
        let (now, mut inner) = self.begin()?;
        let deny = |inner: &mut super::Inner, error: ServiceError| {
            let event = AuditEvent::new(now, EventKind::Admin, Outcome::Denied)
                .approver(&checked.approver)
                .caller(caller)
                .reason(error.to_string());
            Self::write_best_effort(inner, &event);
            Err(error)
        };
        let count = match inner.store.token_version(id) {
            Ok(count) => count,
            Err(e) => {
                tracing::error!(error = %e, "cannot read a token's change count");
                return deny(&mut inner, internal(e));
            }
        };
        if token.version != count {
            let error = refused(format!(
                "token {id}: {count} changes of it were applied, not the {} this change \
                 replaces: it was applied already, or another came first (run writ admin \
                 token {id} again)",
                token.version
            ));
            return deny(&mut inner, error);
        }
        if &token.previous != current {
            let error = refused(format!(
                "token {id}: the token in force is {current}, not the one this change replaces \
                 ({}): it changed since it was shown (run writ admin token {id} again)",
                token.previous
            ));
            return deny(&mut inner, error);
        }
        let next = count
            .checked_add(1)
            .ok_or_else(|| internal("token version overflow"))?;
        let event = AuditEvent::new(now, EventKind::Admin, Outcome::Allowed)
            .approver(&checked.approver)
            .caller(caller)
            .reason(format!(
                "token {id}: version {next} (sha256 {digest}) replaces version {count} ({})",
                named(current)
            ));
        Self::logged(&mut inner, event, |inner| {
            inner
                .store
                .bump_token_version(id, count)
                .map_err(internal)?;
            write().map_err(|why| refused(format!("token {id}: not written: {why}")))
        })?;
        Ok(TokenApplied {
            id: id.clone(),
            version: next,
            digest: digest.clone(),
            replaced: current.clone(),
            signed_by: checked.approver.clone(),
        })
    }
}
