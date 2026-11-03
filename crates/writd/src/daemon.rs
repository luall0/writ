//! What an unseal opens: [`Opener`] takes what the keystore holds (the CA key, the agent
//! signing keys, the upstream credentials and tokens, the sealed notifiers' tokens, the
//! authority MAC's key) and starts what needs them (the signers, the mirrors, the service's
//! keys, the mirror sync), then writes the authority files in force back to their files. The
//! sealed keystore is opened by an approver's `writ unseal` ([`Unsealer`]); the development
//! keystore, at start. Once open, it puts admin changes in force ([`AdminApplier`]).

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, bail};
use std::collections::BTreeMap;
use writ_approval::{Opened, Service};
use writ_core::caller::CallerFacts;
use writ_core::config::PolicyConfig;
use writ_core::names::KeyFingerprint;
use writ_crypto::ca::CertificateAuthority;

use writ_approval::{AdminParsed, CheckedAdmin};
use writ_core::authority::AdminTarget;
use writ_core::names::KeyId;
use writ_gateway::{AdminApplier, Gateway, Unsealer};
use writ_mirror::credential::UpstreamToken;
use writ_mirror::{MirrorConfig, Mirrors};
use writ_platform::{BoxFuture, KeystoreUnlock, Passphrase, UnsealRequest};
use writ_proto::AdminApplied;
use writ_proto::PassphraseText;
use writ_signer::Signer;

use crate::config::{Config, KeystoreConfig, NotifierConfig, TokenConfig};
use crate::keystore::{self, Opened as Keystore};
use crate::platform::{self, LateNotifiers};

/// The upstream credentials: the signer holding the `ssh://` keys, the `https://` tokens.
type Upstream = (Arc<dyn Signer>, BTreeMap<KeyId, Arc<UpstreamToken>>);

/// Starts what the keystore holds. Cloned into the gateway as its [`Unsealer`].
#[derive(Clone)]
pub struct Opener(Arc<Inner>);

struct Inner {
    config: Arc<Config>,
    policy: PolicyConfig,
    /// The authority files' texts the daemon started with: written back once open.
    texts: BTreeMap<AdminTarget, String>,
    /// The upstream credentials, once open: a registry change opens new mirrors with them.
    upstream: OnceLock<Upstream>,
    mirrors: MirrorConfig,
    service: Arc<Service>,
    notifiers: Arc<LateNotifiers>,
    /// Set right after the gateway starts, before any listener runs.
    gateway: OnceLock<Gateway>,
}

impl Opener {
    pub fn new(
        config: Arc<Config>,
        policy: PolicyConfig,
        texts: BTreeMap<AdminTarget, String>,
        mirrors: MirrorConfig,
        service: Arc<Service>,
        notifiers: Arc<LateNotifiers>,
    ) -> Self {
        Self(Arc::new(Inner {
            config,
            policy,
            texts,
            upstream: OnceLock::new(),
            mirrors,
            service,
            notifiers,
            gateway: OnceLock::new(),
        }))
    }

    pub fn set_gateway(&self, gateway: Gateway) {
        let _ = self.0.gateway.set(gateway);
    }

    /// Starts what `keystore` holds and opens the service; `approver` signed the unseal
    /// (`None`: the development keystore, open at start). Fails, the daemon still sealed,
    /// when a mirror can't open or the service refuses the keys (another CA, a template's
    /// signing key missing).
    pub async fn open(
        &self,
        keystore: Keystore,
        approver: Option<&KeyFingerprint>,
        caller: &CallerFacts,
    ) -> anyhow::Result<()> {
        let inner = &self.0;
        let gateway = inner
            .gateway
            .get()
            .context("the gateway is not started yet")?;
        let Keystore {
            keys,
            authority,
            tokens,
            mut bot_tokens,
        } = keystore;
        let signer = platform::signer(keys.signing)?;
        let upstream = platform::upstream_signer(keys.upstream)?;
        let mirrors = Mirrors::open(
            inner.mirrors.clone(),
            inner.policy.repos(),
            upstream.clone(),
            &tokens,
        )
        .await?;
        let opened = Opened {
            ca: CertificateAuthority::new(keys.ca),
            signer,
            authority,
        };
        let (service, approver_owned, caller_owned) =
            (inner.service.clone(), approver.cloned(), caller.clone());
        tokio::task::spawn_blocking(move || {
            service.unseal(opened, approver_owned.as_ref(), &caller_owned)
        })
        .await
        .context("the unseal stopped")?
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        gateway.set_mirrors(mirrors);
        let _ = inner.upstream.set((upstream, tokens));
        self.sync_files();
        // Open: the notifiers whose token was sealed join the others.
        for notifier in &inner.config.notifiers {
            let NotifierConfig::Telegram(telegram) = notifier;
            if let TokenConfig::Sealed(id) = &telegram.token
                && let Some(token) = bot_tokens.remove(id)
            {
                match platform::telegram_notifier(token, telegram) {
                    Ok(notifier) => inner.notifiers.add(notifier),
                    Err(e) => tracing::error!(token = %id, error = %e, "notifier not started"),
                }
            }
        }
        crate::spawn_mirror_sync(
            gateway.clone(),
            Duration::from_secs(inner.config.mirrors.sync_every.seconds()),
        );
        Ok(())
    }

    /// Writes the authority files in force back to the files `writd.yaml` names, now that
    /// their MAC was checked: a file that differs (a hand edit) is set aside, never applied,
    /// and said in the log and the audit log.
    fn sync_files(&self) {
        let inner = &self.0;
        let Ok(now) = crate::now() else { return };
        for (target, text) in &inner.texts {
            let path = crate::authority::path(&inner.config, *target);
            match crate::authority::sync_file(path, text, now) {
                Ok(crate::authority::Synced::SetAside(aside)) => {
                    let reason = format!(
                        "{target}: {} differed from the version in force: set aside as {} \
                         (never applied; writ admin apply or writd recover puts a file in \
                         force), the version in force written back",
                        path.display(),
                        aside.display()
                    );
                    tracing::warn!("{reason}");
                    inner.service.admin_note(&reason);
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(%target, error = %format!("{e:#}"), "cannot write the file in force back")
                }
            }
        }
    }

    /// Puts a checked admin change in force: the new text parsed and checked against the
    /// rest of the configuration (a registry change opens its new mirrors first), recorded
    /// by the service, then swapped in and written back. A refusal is logged once.
    async fn apply_admin(
        &self,
        checked: CheckedAdmin,
        caller: CallerFacts,
    ) -> Result<AdminApplied, String> {
        let inner = &self.0;
        let gateway = inner.gateway.get().ok_or("the daemon is not started yet")?;
        let target = checked.admin.target;
        let text = checked.admin.text.as_str().to_owned();
        let refuse = |reason: String| {
            inner
                .service
                .admin_failed(Some(&checked.approver), Some(target), &reason, &caller);
            reason
        };
        enum Ready {
            Policy(Mirrors),
            Readers(Vec<writ_crypto::readers::Reader>),
            Approvers,
        }
        let (parsed, ready) = match target {
            AdminTarget::Policy => {
                let policy =
                    crate::authority::parse_policy(&text).map_err(|e| refuse(format!("{e:#}")))?;
                let (upstream, tokens) = inner
                    .upstream
                    .get()
                    .ok_or_else(|| refuse("the daemon is not open".to_owned()))?;
                let mirrors = gateway
                    .mirrors()
                    .map_err(refuse)?
                    .with_registry(policy.repos(), upstream.clone(), tokens)
                    .await
                    .map_err(|e| refuse(e.to_string()))?;
                (AdminParsed::Policy(policy), Ready::Policy(mirrors))
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
        let (service, checked_owned, caller_owned) =
            (inner.service.clone(), checked.clone(), caller.clone());
        let applied = tokio::task::spawn_blocking(move || {
            service.commit_admin(&checked_owned, parsed, &caller_owned)
        })
        .await
        .map_err(|_| "the change stopped".to_owned())?
        .map_err(|e| e.to_string())?;
        match ready {
            Ready::Policy(mirrors) => gateway.set_mirrors(mirrors),
            Ready::Readers(readers) => gateway.readers().replace(readers),
            Ready::Approvers => {}
        }
        let path = crate::authority::path(&inner.config, target);
        if let Err(e) = crate::authority::write_back(path, &text) {
            tracing::warn!(%target, error = %format!("{e:#}"), "cannot write the file in force back");
        }
        tracing::info!(%target, version = applied.version, approver = %applied.signed_by, "admin change applied");
        Ok(applied)
    }

    /// Opens the sealed keystore with `passphrase` (scrypt: off the async threads): every key
    /// and token the configuration names. Its errors name what failed, never a secret.
    async fn open_keystore(&self, passphrase: PassphraseText) -> anyhow::Result<Keystore> {
        let inner = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let KeystoreConfig::Sealed(sealed) = &inner.config.keystore else {
                bail!("this daemon's keystore is not sealed");
            };
            let unlock: Arc<dyn KeystoreUnlock> = platform::unlock(sealed);
            let request =
                UnsealRequest::with_passphrase(Passphrase::new(passphrase.expose().to_owned()));
            drop(passphrase);
            let key = unlock.unlock(&request)?;
            drop(request);
            keystore::open(&inner.config, &inner.policy, key.identity()?)
        })
        .await
        .context("the unseal stopped")?
    }
}

impl Unsealer for Opener {
    fn unseal(
        &self,
        passphrase: PassphraseText,
        approver: KeyFingerprint,
        caller: CallerFacts,
    ) -> BoxFuture<'static, Result<(), String>> {
        let me = self.clone();
        Box::pin(async move {
            let opened = me
                .open_keystore(passphrase)
                .await
                .map_err(|e| format!("{e:#}"))?;
            me.open(opened, Some(&approver), &caller)
                .await
                .map_err(|e| format!("{e:#}"))?;
            tracing::info!(%approver, "unsealed");
            Ok(())
        })
    }
}

impl AdminApplier for Opener {
    fn apply(
        &self,
        checked: CheckedAdmin,
        caller: CallerFacts,
    ) -> BoxFuture<'static, Result<AdminApplied, String>> {
        let me = self.clone();
        Box::pin(async move { me.apply_admin(checked, caller).await })
    }
}
