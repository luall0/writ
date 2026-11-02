//! What an unseal opens: [`Opener`] takes what the keystore holds (the CA key, the agent
//! signing keys, the upstream credentials and tokens, the sealed notifiers' tokens) and
//! starts what needs them (the signers, the mirrors, the service's keys, the mirror sync).
//! The sealed keystore is opened by an approver's `writ unseal` ([`Unsealer`]); the
//! development keystore, at start.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, bail};
use writ_approval::{Opened, Service};
use writ_core::caller::CallerFacts;
use writ_core::config::PolicyConfig;
use writ_core::names::KeyFingerprint;
use writ_crypto::ca::CertificateAuthority;
use writ_gateway::{Gateway, Unsealer};
use writ_mirror::{MirrorConfig, Mirrors};
use writ_platform::{BoxFuture, KeystoreUnlock, Passphrase, UnsealRequest};
use writ_proto::PassphraseText;

use crate::config::{Config, KeystoreConfig, NotifierConfig, TokenConfig};
use crate::keystore::{self, Opened as Keystore};
use crate::platform::{self, LateNotifiers};

/// Starts what the keystore holds. Cloned into the gateway as its [`Unsealer`].
#[derive(Clone)]
pub struct Opener(Arc<Inner>);

struct Inner {
    config: Arc<Config>,
    policy: PolicyConfig,
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
        mirrors: MirrorConfig,
        service: Arc<Service>,
        notifiers: Arc<LateNotifiers>,
    ) -> Self {
        Self(Arc::new(Inner {
            config,
            policy,
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
            tokens,
            mut bot_tokens,
        } = keystore;
        let signer = platform::signer(keys.signing)?;
        let upstream = platform::upstream_signer(keys.upstream)?;
        let mirrors = Mirrors::open(
            inner.mirrors.clone(),
            inner.policy.repos(),
            upstream,
            &tokens,
        )
        .await?;
        // A retry after a refused unseal finds the mirrors of the first: the same ones.
        let _ = gateway.set_mirrors(mirrors.clone());
        let opened = Opened {
            ca: CertificateAuthority::new(keys.ca),
            signer,
        };
        let (service, approver_owned, caller_owned) =
            (inner.service.clone(), approver.cloned(), caller.clone());
        tokio::task::spawn_blocking(move || {
            service.unseal(opened, approver_owned.as_ref(), &caller_owned)
        })
        .await
        .context("the unseal stopped")?
        .map_err(|e| anyhow::anyhow!("{e}"))?;
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
            mirrors,
            gateway.clone(),
            Duration::from_secs(inner.config.mirrors.sync_every.seconds()),
        );
        Ok(())
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
