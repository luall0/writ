//! Sealed tokens: which file is in force for a credential, and a checked `writ-token/3` put
//! in force.

use super::{Opener, TokenUse};
use crate::keystore;
use std::sync::{Arc, PoisonError};
use writ_approval::CheckedToken;
use writ_core::authority::TextDigest;
use writ_core::caller::CallerFacts;
use writ_core::names::KeyId;
use writ_mirror::credential::UpstreamToken;
use writ_mirror::known_hosts::PinnedHosts;
use writ_proto::{TokenApplied, TokenShown};

impl Opener {
    /// What the token `id` is for, from the policy in force and `writd.yaml`'s notifiers: an
    /// id neither uses is refused.
    pub(super) fn token_use(&self, id: &KeyId) -> Result<TokenUse<'_>, String> {
        let inner = &self.0;
        let policy = inner.service.policy();
        let declared = keystore::tokens_declared(&policy);
        let notifier = inner.sealed_notifier(id);
        let upstream = declared.contains(id);
        if !upstream && notifier.is_none() {
            return Err(format!(
                "token {id}: the policy in force declares no token {id} (keys.{id}, kind: \
                 token), and no notifier keeps it sealed"
            ));
        }
        Ok(TokenUse { upstream, notifier })
    }

    pub(super) fn show_token(&self, id: &KeyId) -> Result<TokenShown, String> {
        self.token_use(id)?;
        let open = self.0.open.get().ok_or("the daemon is not open")?;
        let previous = open.live.token_in_force(id).map_err(|e| format!("{e:#}"))?;
        let version = self
            .0
            .service
            .token_version(id)
            .map_err(|e| e.to_string())?;
        Ok(TokenShown {
            daemon: self.0.service.daemon().clone(),
            id: id.clone(),
            version,
            previous,
        })
    }

    /// Puts a checked `writ-token/3` in force: its id one a repo or a notifier uses, its
    /// ciphertext opened by the keystore's identity and a token; committed by the service
    /// against the id's change count and the file in force, the file written under the same
    /// lock as its line and its count (the review after M7.6, A-6); then used at once (the
    /// mirrors that use it opened again, the notifier started with it). A refusal is logged
    /// once.
    pub(super) async fn apply_token(
        &self,
        checked: CheckedToken,
        caller: CallerFacts,
    ) -> Result<TokenApplied, String> {
        let inner = &self.0;
        let id = checked.token().id.clone();
        let approver = checked.approver().clone();
        let refuse = |reason: String| {
            let reason = format!("token {id}: {reason}");
            inner
                .service
                .admin_failed(Some(&approver), None, &reason, &caller);
            reason
        };
        let gateway = inner.gateway.get().ok_or("the daemon is not started yet")?;
        let open = inner
            .open
            .get()
            .ok_or_else(|| refuse("the daemon is not open".to_owned()))?;
        let used = self.token_use(&id).map_err(refuse)?;
        let file = writ_crypto::sealed::decode(checked.token().sealed.as_str())
            .map_err(|e| refuse(e.to_string()))?;
        let digest = TextDigest::of_bytes(&file);
        let (live, service, caller_owned, id_owned) = (
            open.live.clone(),
            inner.service.clone(),
            caller.clone(),
            id.clone(),
        );
        let (upstream, notifier) = (used.upstream, used.notifier.is_some());
        let committed = tokio::task::spawn_blocking(move || {
            let (service, caller, id) = (&service, &caller_owned, &id_owned);
            let refuse = |reason: String| {
                let reason = format!("token {id}: {reason}");
                service.admin_failed(Some(checked.approver()), None, &reason, caller);
                reason
            };
            // Opened with the ways in force, the keystore's state held to the write.
            let (staged, plaintext) = live
                .stage_token(id, &file)
                .map_err(|e| refuse(format!("{e:#} (is it sealed to this daemon's recipient?)")))?;
            // Checked as a token now, then dropped: the mirrors unwrap it again at each use.
            if upstream {
                UpstreamToken::from_bytes(&plaintext)
                    .map_err(|why| refuse(format!("not a token: {why}")))?;
            }
            let bot_token = match notifier {
                true => Some(
                    keystore::bot_token(id, &plaintext).map_err(|e| refuse(format!("{e:#}")))?,
                ),
                false => None,
            };
            drop(plaintext);
            let current = staged.in_force().map_err(|e| refuse(format!("{e:#}")))?;
            let applied = service
                .commit_token(&checked, &current, &digest, caller, move || {
                    staged.write().map_err(|e| format!("{e:#}"))
                })
                .map_err(|e| e.to_string())?;
            Ok::<_, String>((applied, bot_token))
        })
        .await
        .map_err(|_| "the change stopped".to_owned())?;
        let (applied, bot_token) = committed?;
        let digest = &applied.digest;
        tracing::info!(token = %id, digest = %digest, approver = %applied.signed_by, "token in force");
        if let (Some(token), Some(telegram)) = (bot_token, used.notifier) {
            self.start_notifier(&id, token, telegram);
        }
        let upstream_token = match used.upstream {
            true => match open.live.token_ref(&id) {
                Ok(Some(token)) => Some(Arc::new(token)),
                Ok(None) => None,
                Err(e) => return Err(refuse(format!("written but not read back: {e:#}"))),
            },
            false => None,
        };
        if let Some(token) = upstream_token {
            open.tokens
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id.clone(), token);
            let policy = inner.service.policy();
            let reopened = match (
                gateway.mirrors(),
                PinnedHosts::from_policy(policy.upstream_hosts()),
            ) {
                (Ok(mirrors), Ok(pinned)) => open
                    .mirrors_for(&mirrors, &policy, pinned)
                    .await
                    .map_err(|e| e.to_string()),
                (Err(e), _) => Err(e),
                (_, Err(e)) => Err(e.to_string()),
            };
            match reopened {
                Ok(mirrors) => gateway.set_mirrors(mirrors),
                Err(e) => {
                    return Err(format!(
                        "token {id} is in force, but the mirrors that use it could not open \
                         again: {e}"
                    ));
                }
            }
        }
        Ok(applied)
    }
}
