//! Proofs (`writ prove-key`, docs/architecture/approvals.md): an agent signing key signs a
//! remote's message (Forgejo and Gitea ask for one before they show its commits as verified)
//! once an approver signed the `writ-proof/1` document naming the key, the namespace and the
//! message. A reader key alone gets nothing: the approver's signature is required whatever
//! the daemon's `decisions`.
//!
//! Like a commit signature, in three phases, so the signer never runs under the state lock:
//! the document and the approver's signature checked (under the lock), the signature (through
//! the signer's queue), the audit line (under the lock). The signature leaves the daemon only
//! once its line is written. The request is untrusted: decoded strictly (canonical bytes
//! only), the namespace never `git` or Writ's own, the message at most 4 KiB, the key one a
//! template signs commits with.

use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::names::KeyFingerprint;
use writ_core::signed::Proof;
use writ_proto::{ProveRequest, Proved};
use writ_signer::SignerError;
use writ_store::{AuditEvent, EventKind, Outcome};

use super::approver::Denied;
use super::{Service, internal};
use crate::{RefusalCode, ServiceError};

/// What the first phase checked: the proof, who approved it, and the denial to log if the
/// next phase fails.
struct Checked {
    proof: Proof,
    approver: KeyFingerprint,
    denied: Denied,
}

impl Service {
    /// Signs a remote's message with an agent signing key, as the approver's proof says.
    /// Every outcome is one `prove` line in the audit log (key, namespace, the message's
    /// SHA-256, the approver).
    pub fn prove(
        &self,
        request: &ProveRequest,
        caller: &CallerFacts,
    ) -> Result<Proved, ServiceError> {
        let checked = self.check_proof(request, caller)?;
        let Checked {
            proof,
            approver,
            denied,
        } = checked;
        let message = proof.message.as_str().as_bytes();
        let signer = &*self.opened()?.signer;
        // The key's declared SSHSIG hash (a template's key is always declared).
        let hash = self
            .config
            .signing_keys
            .get(&proof.key)
            .map_or(writ_crypto::sshsig::DEFAULT_HASH, |key| key.hash);
        let signed = writ_signer::public_key(signer, &proof.key).and_then(|public| {
            writ_signer::sshsig(signer, &proof.key, proof.namespace.as_str(), hash, message)
                .map(|signature| (public, signature))
        });
        let (now, mut inner) = self.begin()?;
        let (public, signature) = match signed {
            Ok(signed) => signed,
            Err(e) => {
                if !matches!(e, SignerError::UnknownKey(_)) {
                    tracing::warn!(key = %proof.key, error = %e, "a proof's signature failed");
                }
                let reason = match e {
                    SignerError::UnknownKey(id) => format!("the signer has no key {id}"),
                    SignerError::Busy => "the signer is busy; retry shortly".to_owned(),
                    _ => "the signer failed (see the daemon's log)".to_owned(),
                };
                return denied.deny(&mut inner, RefusalCode::Proof, reason);
            }
        };
        let public_key = public.to_openssh().map_err(internal)?;
        let event = AuditEvent::new(now, EventKind::Prove, Outcome::Allowed)
            .caller(caller)
            .approver(&approver)
            .proof(
                &proof.key,
                &proof.namespace,
                writ_crypto::sshsig::message_digest(message),
            );
        Self::logged(&mut inner, event, |_| Ok(()))?;
        Ok(Proved {
            signature,
            public_key,
        })
    }

    /// The first phase, under the lock: the document read strictly, the key one a template
    /// signs with, the approver's signature over exactly these bytes. A refusal is logged.
    fn check_proof(
        &self,
        request: &ProveRequest,
        caller: &CallerFacts,
    ) -> Result<Checked, ServiceError> {
        let (now, mut inner) = self.begin()?;
        let denied = Denied::new(
            AuditEvent::new(now, EventKind::Prove, Outcome::Denied).caller(caller),
            "proof refused",
        );
        let proof = match Proof::from_canonical(request.proof.as_bytes()) {
            Ok(proof) => proof,
            Err(e) => return denied.deny(&mut inner, RefusalCode::Proof, e.to_string()),
        };
        let digest = writ_crypto::sshsig::message_digest(proof.message.as_str().as_bytes());
        let denied = denied.with(|event| event.proof(&proof.key, &proof.namespace, digest));
        let approver = match self.verify_approver(request.proof.as_bytes(), &request.signature) {
            Ok(approver) => approver,
            Err(reason) => return denied.deny(&mut inner, RefusalCode::Signature, reason),
        };
        let denied = denied.approver(&approver);
        let signs_commits = self
            .config
            .policy
            .templates()
            .values()
            .any(|template| template.signing_key.as_ref() == Some(&proof.key));
        if !signs_commits {
            let reason = format!(
                "{} is not a key a template signs commits with: only agent signing keys make \
                 proofs",
                proof.key
            );
            return denied.deny(&mut inner, RefusalCode::Proof, reason);
        }
        Ok(Checked {
            proof,
            approver,
            denied,
        })
    }
}
