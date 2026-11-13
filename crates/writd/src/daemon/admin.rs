//! Admin changes put in force: the new text checked against the rest of the configuration,
//! the keys it declares made, those it drops deleted, the keystore wrapped to its recipients.

use super::{Created, Forget, Opener};
use crate::config::KeystoreConfig;
use crate::declared::Declarations;
use crate::keystore;
use anyhow::{Context, bail};
use std::collections::BTreeMap;
use std::sync::PoisonError;
use writ_approval::{AdminParsed, CheckedAdmin};
use writ_core::authority::AdminTarget;
use writ_core::caller::CallerFacts;
use writ_core::config::PolicyConfig;
use writ_core::names::KeyId;
use writ_mirror::Mirrors;
use writ_mirror::known_hosts::PinnedHosts;
use writ_proto::{AdminApplied, CreatedKey, KeyRole, RemovedKey};
use writ_signer::Signer;

impl Opener {
    /// Puts a checked admin change in force: the new text parsed and checked against the
    /// rest of the configuration (a registry change opens its new mirrors first), recorded
    /// by the service, then swapped in and written back. A refusal is logged once.
    pub(super) async fn apply_admin(
        &self,
        checked: CheckedAdmin,
        caller: CallerFacts,
    ) -> Result<AdminApplied, String> {
        let inner = &self.0;
        let gateway = inner.gateway.get().ok_or("the daemon is not started yet")?;
        let target = checked.admin().target;
        let text = checked.admin().text.as_str().to_owned();
        let approver = checked.approver().clone();
        let refuse = |reason: String| {
            inner
                .service
                .admin_failed(Some(&approver), Some(target), &reason, &caller);
            reason
        };
        enum Ready {
            Policy(Mirrors),
            Readers(Vec<writ_crypto::readers::Reader>),
            Approvers,
        }
        let (mut created, mut openpgp_created) = (Vec::new(), Created::new());
        let mut removed: Vec<(RemovedKey, Forget)> = Vec::new();
        let mut recipients_changed = false;
        let (parsed, ready) = match target {
            AdminTarget::Policy => {
                let (policy, declared) =
                    crate::authority::parse_policy(&text, inner.config.min_ttl)
                        .and_then(|policy| {
                            let declared = crate::declared::declarations(&policy)?;
                            Ok((policy, declared))
                        })
                        .map_err(|e| refuse(format!("{e:#}")))?;
                let pinned = PinnedHosts::from_policy(policy.upstream_hosts())
                    .map_err(|e| refuse(e.to_string()))?;
                let open = inner
                    .open
                    .get()
                    .ok_or_else(|| refuse("the daemon is not open".to_owned()))?;
                // The keystore's recipients (M7.6): the last hardware one never goes, and a new
                // one is made in its device before the change is recorded.
                let in_force = inner.service.policy();
                if in_force.hardware_keystore() && !policy.hardware_keystore() {
                    return Err(refuse(
                        "recipients: the last hardware recipient can't be removed: going back to \
                         a passphrase is writd recover, on the daemon's host"
                            .to_owned(),
                    ));
                }
                recipients_changed = in_force.recipients() != policy.recipients();
                // Auto-unseal (M7.6): only with every key and secret in hardware.
                if policy.unseal() == writ_core::config::Unseal::Auto {
                    let missing = crate::autounseal::missing(&inner.config, &policy)
                        .map_err(|e| refuse(format!("{e:#}")))?;
                    if !missing.is_empty() {
                        return Err(refuse(format!(
                            "unseal: auto: not everything is in hardware yet: {}",
                            missing.join("; ")
                        )));
                    }
                }
                // What a kept key is never changes (the review after M7.6, D-1): the daemon's
                // own rule, whatever text the change brings.
                if let Some(why) = changed_identity(&in_force, &policy) {
                    return Err(refuse(why));
                }
                if recipients_changed {
                    self.make_recipients(&policy)
                        .await
                        .map_err(|e| refuse(format!("{e:#}")))?;
                }
                (created, openpgp_created) = self
                    .keys_for(&declared)
                    .await
                    .map_err(|e| refuse(format!("{e:#}")))?;
                let mirrors = open
                    .mirrors_for(&gateway.mirrors().map_err(refuse)?, &policy, pinned)
                    .await
                    .map_err(|e| refuse(e.to_string()))?;
                let key_uses = crate::declared::key_uses(&declared);
                removed = self.removed_keys(&policy);
                (
                    AdminParsed::Policy(policy, key_uses),
                    Ready::Policy(mirrors),
                )
            }
            AdminTarget::Approvers => {
                let approvers = crate::authority::parse_approvers(&text)
                    .map_err(|e| refuse(format!("{e:#}")))?;
                crate::authority::one_key_one_purpose(&approvers, &gateway.readers().now())
                    .map_err(|e| refuse(e.to_string()))?;
                (AdminParsed::Approvers(approvers), Ready::Approvers)
            }
            AdminTarget::Readers => {
                let readers =
                    crate::authority::parse_readers(&text).map_err(|e| refuse(format!("{e:#}")))?;
                let approvers = inner
                    .service
                    .admin_show(AdminTarget::Approvers)
                    .map_err(|e| refuse(e.to_string()))?;
                let approvers = crate::authority::parse_approvers(&approvers.text)
                    .map_err(|e| refuse(format!("{e:#}")))?;
                crate::authority::one_key_one_purpose(&approvers, &readers)
                    .map_err(|e| refuse(e.to_string()))?;
                (AdminParsed::Readers, Ready::Readers(readers))
            }
        };
        let (service, caller_owned) = (inner.service.clone(), caller.clone());
        let shown: Vec<RemovedKey> = removed.iter().map(|(key, _)| key.clone()).collect();
        let mut applied = tokio::task::spawn_blocking(move || {
            service.commit_admin(
                &checked,
                parsed,
                created,
                shown,
                openpgp_created,
                &caller_owned,
            )
        })
        .await
        .map_err(|_| "the change stopped".to_owned())?
        .map_err(|e| e.to_string())?;
        // In force: its file written back now, whatever follows (the review after M7.6, D-7: a
        // rewrap that failed returned before this, and the next start took the file for a hand
        // edit).
        let path = crate::authority::path(&inner.config, target);
        if let Err(e) = crate::authority::write_back(path, &text) {
            tracing::warn!(%target, error = %format!("{e:#}"), "cannot write the file in force back");
        }
        match ready {
            Ready::Policy(mirrors) => {
                gateway.set_mirrors(mirrors);
                self.forget(&removed).await;
                self.write_certificates();
                if recipients_changed {
                    match self.rewrap().await {
                        // What it did to the data key (S-8): in the answer and the audit log.
                        Ok(said) => {
                            for line in &said {
                                tracing::warn!("keystore: {line}");
                                inner.service.admin_note(&format!("keystore: {line}"));
                            }
                            applied.keystore = said;
                        }
                        Err(e) => {
                            let reason = format!(
                                "the policy is in force, but the keystore isn't wrapped to its \
                                 recipients yet ({e:#}): the next unseal finishes it"
                            );
                            tracing::error!("{reason}");
                            inner.service.admin_note(&reason);
                            return Err(reason);
                        }
                    }
                }
            }
            Ready::Readers(readers) => gateway.readers().replace(readers),
            Ready::Approvers => {}
        }
        tracing::info!(%target, version = applied.version, approver = %applied.signed_by, "admin change applied");
        for key in &applied.created {
            tracing::info!(id = %key.id, role = key.role.as_str(), public_key = %key.public_key, "key created");
        }
        Ok(applied)
    }

    /// Makes, in its device, each hardware recipient `policy` declares that the keystore
    /// doesn't hold yet (M7.6), each logged with its recipient.
    pub(super) async fn make_recipients(
        &self,
        policy: &writ_core::config::PolicyConfig,
    ) -> anyhow::Result<()> {
        let inner = self.0.clone();
        let policy = policy.clone();
        let made = tokio::task::spawn_blocking(move || {
            let KeystoreConfig::Sealed(sealed) = &inner.config.keystore else {
                bail!("the development keystore takes no recipient");
            };
            keystore::recipients::make_missing(&inner.config, sealed, &policy)
        })
        .await
        .context("the change stopped")??;
        for (name, recipient) in made {
            tracing::info!(recipient = %name, public = %recipient, "hardware recipient created");
            self.0.service.admin_note(&format!(
                "recipient {name} created in its device: {recipient}"
            ));
        }
        Ok(())
    }

    /// The keystore rewrapped to the recipients of the policy in force (M7.6), its data key
    /// rotated when a way in was taken out (S-8: at once on a hardware keystore, owed until
    /// the next unseal on a passphrase one), then the tokens' references and the mirrors that
    /// hold them renewed (a rewrapped file is another version). What to tell the approver.
    pub(super) async fn rewrap(&self) -> anyhow::Result<Vec<String>> {
        let inner = self.0.clone();
        let open = inner.open.get().context("the daemon is not open")?;
        let (live, config, policy) = (
            open.live.clone(),
            inner.config.clone(),
            inner.service.policy(),
        );
        let (applied, tokens) = tokio::task::spawn_blocking(move || {
            let applied = live.apply_recipients(&config, &policy)?;
            let tokens = live.token_refs(&policy)?;
            anyhow::Ok((applied, tokens))
        })
        .await
        .context("the change stopped")??;
        for line in &applied.changed {
            tracing::info!("keystore: {line}");
        }
        *open.tokens.write().unwrap_or_else(PoisonError::into_inner) = tokens;
        inner
            .service
            .set_token_recipients(open.live.token_recipients());
        inner.service.set_keystore(
            open.live
                .sealed_parts()
                .map(|(_, recipient)| recipient.to_string()),
            open.live.rotation_owed(),
        );
        let gateway = inner
            .gateway
            .get()
            .context("the gateway is not started yet")?;
        let policy = inner.service.policy();
        let pinned = PinnedHosts::from_policy(policy.upstream_hosts())?;
        let mirrors = open
            .mirrors_for(
                &gateway.mirrors().map_err(|e| anyhow::anyhow!(e))?,
                &policy,
                pinned,
            )
            .await?;
        gateway.set_mirrors(mirrors);
        Ok(applied.said)
    }

    /// Hands the signers every key `declared` names that they don't hold yet: from the
    /// keystore, or made there now as declared. The keys new to the signers, to register.
    pub(super) async fn keys_for(
        &self,
        declared: &Declarations,
    ) -> anyhow::Result<(Vec<CreatedKey>, Created)> {
        let open = self.0.open.get().context("the daemon is not open")?;
        let declared = declared.clone();
        let (live, signing, upstream) = (
            open.live.clone(),
            open.signing.clone(),
            open.upstream.clone(),
        );
        // Files, and a signer's queue: off the async threads.
        tokio::task::spawn_blocking(move || {
            let mut added = Vec::new();
            let mut openpgp = Created::new();
            for (id, key) in &declared {
                let signer = match key.role {
                    KeyRole::Signing => &signing,
                    KeyRole::Upstream => &upstream,
                };
                let held = writ_signer::public_key(&**signer, id).is_ok();
                // A device's key is made by the use's own backend, which then holds it.
                let mut devices = BTreeMap::new();
                if let Some(device) = signer
                    .on(key.backend.name())
                    .filter(|_| key.backend.is_device())
                {
                    devices.insert(key.backend, device.clone());
                }
                let makers = keystore::Makers::running(devices);
                // Every declared key, held or not, checked against its declaration (the review
                // after M7.6, D-1), its OpenPGP creation time kept (a key made by a change then
                // refused is found again by the retry).
                if held {
                    let meta = live.check_held(id, key, &makers)?;
                    if let Some(created) = meta.created {
                        openpgp.insert(id.clone(), created);
                    }
                    continue;
                }
                let (stored, made) = live.key_or_make(id, key, &makers)?;
                if let Some(created) = stored.meta.created {
                    openpgp.insert(id.clone(), created);
                }
                let name = crate::declared::named(key.role, id);
                let public_key = match stored.key {
                    keystore::Material::Software(pair) => {
                        signer
                            .add_key_on(key.backend.name(), id.clone(), pair)
                            .with_context(|| name.clone())?
                            .public_key
                    }
                    keystore::Material::Device { public, .. } => {
                        if !made {
                            bail!(
                                "{name} is in the keystore but its {} backend doesn't hold it: \
                                 restart the daemon to give it back",
                                key.backend.name()
                            );
                        }
                        public
                    }
                };
                if made {
                    tracing::info!(%id, role = key.role.as_str(), "key made in the keystore");
                }
                added.push(CreatedKey {
                    id: id.clone(),
                    role: key.role,
                    public_key: public_key.to_openssh()?,
                });
            }
            Ok((added, openpgp))
        })
        .await
        .context("the change stopped")?
    }

    /// The keys the policy in force declares that `next` doesn't (or declares for another
    /// use: the old one goes, the new one is made), each with its public half from the signer
    /// that holds it, for the `admin` line and the reply; and how to delete it once `next` is
    /// in force. A token a sealed notifier uses keeps its file.
    pub(super) fn removed_keys(&self, next: &PolicyConfig) -> Vec<(RemovedKey, Forget)> {
        let inner = &self.0;
        let Some(open) = inner.open.get() else {
            return Vec::new();
        };
        let current = inner.service.policy();
        let notifier = |id: &KeyId| inner.sealed_notifier(id).is_some();
        let mut removed = Vec::new();
        for (id, key) in current.keys() {
            let kept = next.key(id).is_some_and(|other| {
                role_of(other) == role_of(key) && other.is_made() == key.is_made()
            });
            if kept {
                continue;
            }
            let (forget, public) = match role_of(key) {
                Some(role) => {
                    let signer = match role {
                        KeyRole::Signing => &open.signing,
                        KeyRole::Upstream => &open.upstream,
                    };
                    (
                        Forget::Key(role),
                        writ_signer::public_key(&**signer, id).ok(),
                    )
                }
                None => (
                    Forget::Token {
                        keep_file: notifier(id),
                    },
                    None,
                ),
            };
            removed.push((
                RemovedKey {
                    id: id.clone(),
                    description: key.describe(),
                    public_key: public.as_ref().and_then(|p| p.to_openssh().ok()),
                    fingerprint: public.as_ref().map(|p| {
                        p.fingerprint(writ_crypto::ssh_key::HashAlg::Sha256)
                            .to_string()
                    }),
                },
                forget,
            ));
        }
        removed
    }

    /// Deletes the keys a change took out, now that it is in force: out of the signer that
    /// held each (never signed with again), then out of the keystore, for good. A failure is
    /// logged: the next unseal's sweep deletes what is left.
    pub(super) async fn forget(&self, removed: &[(RemovedKey, Forget)]) {
        let Some(open) = self.0.open.get() else {
            return;
        };
        for (key, forget) in removed {
            let id = key.id.clone();
            match forget {
                Forget::Key(role) => {
                    let signer = match role {
                        KeyRole::Signing => open.signing.clone(),
                        KeyRole::Upstream => open.upstream.clone(),
                    };
                    let (live, role) = (open.live.clone(), *role);
                    let done = tokio::task::spawn_blocking(move || {
                        match signer.remove_key(&id) {
                            Ok(()) | Err(writ_signer::SignerError::UnknownKey(_)) => {}
                            Err(e) => return Err(anyhow::anyhow!("{e}")),
                        }
                        live.forget(&id, role)
                    })
                    .await;
                    match done {
                        Ok(Ok(())) => tracing::info!(id = %key.id, "key deleted from the keystore"),
                        Ok(Err(e)) => tracing::error!(
                            id = %key.id,
                            error = %format!("{e:#}"),
                            "cannot delete the key: the next unseal does"
                        ),
                        Err(_) => tracing::error!(
                            id = %key.id,
                            "cannot delete the key: the next unseal does"
                        ),
                    }
                }
                Forget::Token { keep_file } => {
                    open.tokens
                        .write()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&id);
                    if !keep_file && let Err(e) = open.live.forget_token(&id) {
                        tracing::error!(id = %key.id, error = %format!("{e:#}"), "cannot delete the token");
                    }
                }
            }
        }
    }
}

/// Why `next` can't be in force when `current` is: a key both declare, for the same use, whose
/// format, algorithm or backend differs (what the key is: `writ admin key rotate` makes a new
/// one, declared otherwise). None when every kept key is what it was.
fn changed_identity(current: &PolicyConfig, next: &PolicyConfig) -> Option<String> {
    let (Ok(current), Ok(next)) = (
        crate::declared::declarations(current),
        crate::declared::declarations(next),
    ) else {
        return None;
    };
    for (id, was) in &current {
        let Some(now) = next.get(id).filter(|now| now.role == was.role) else {
            continue;
        };
        let field = if now.format != was.format {
            "format"
        } else if now.algorithm != was.algorithm {
            "algorithm"
        } else if now.backend != was.backend {
            "backend"
        } else {
            continue;
        };
        return Some(format!(
            "keys.{id}.{field}: can't change: it is what the key is (writ admin key rotate {id} \
             makes a new key, declared otherwise)"
        ));
    }
    None
}

/// What signs with a declared key: the agent keys' signer, the upstream one, or none (a
/// token).
fn role_of(key: &writ_core::config::Key) -> Option<KeyRole> {
    match key {
        writ_core::config::Key::Signing(_) => Some(KeyRole::Signing),
        writ_core::config::Key::Upstream(writ_core::config::UpstreamKey::Ssh { .. }) => {
            Some(KeyRole::Upstream)
        }
        writ_core::config::Key::Upstream(writ_core::config::UpstreamKey::Token { .. }) => None,
    }
}
