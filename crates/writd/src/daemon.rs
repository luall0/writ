//! What an unseal opens: [`Opener`] takes what the keystore holds (the CA key, the agent
//! signing keys, the upstream credentials and tokens, the sealed notifiers' tokens, the
//! authority MAC's key) and starts what needs them (the signers, the mirrors, the service's
//! keys, the mirror sync), then writes the authority files in force back to their files. The
//! sealed keystore is opened by an approver's `writ unseal` ([`Unsealer`]); the development
//! keystore, at start. Once open, it puts admin changes in force ([`AdminApplier`]): a policy
//! declaring a key the keystore lacks makes it and hands it to the running signer
//! (`Signer::add_key`), its host pins go to the mirrors, and a token an approver sealed on
//! their machine is opened with the identity kept open, written, and used at once.
//!
//! One concern per file (the review after M7.6, D-13): [`open`] (the keystore opened and what
//! it holds started), [`admin`] (admin changes), [`token`] (sealed tokens), [`ca`] and [`tls`]
//! (their rotations), [`show`] (the keys); this file holds the state they share, the
//! helpers several use, and the gateway's interfaces, which hand each request to its file.

mod admin;
mod ca;
mod open;
mod show;
mod tls;
mod token;

/// The creation time of each OpenPGP key a change added to the signer.
type Created = std::collections::BTreeMap<KeyId, u32>;

use std::sync::{Arc, OnceLock, PoisonError, RwLock};

use std::collections::BTreeMap;
use writ_approval::Service;
use writ_core::caller::CallerFacts;
use writ_core::config::PolicyConfig;
use writ_core::names::KeyFingerprint;

use writ_approval::{CheckedAdmin, CheckedToken};
use writ_core::authority::AdminTarget;
use writ_core::names::KeyId;
use writ_gateway::{AdminApplier, Gateway, Unsealer};
use writ_mirror::credential::Tokens;
use writ_mirror::known_hosts::PinnedHosts;
use writ_mirror::{MirrorConfig, Mirrors};
use writ_platform::BoxFuture;
use writ_proto::PassphraseText;
use writ_proto::{AdminApplied, KeyRole, KeysShown, TokenApplied, TokenShown};
use writ_signer::route::Routed;

use crate::config::{Config, KeystoreConfig, NotifierConfig, TelegramConfig, TokenConfig};
use crate::keystore::{self, Live};
use crate::platform::LateNotifiers;

/// What stays open once the keystore is: where keys and tokens added later go, the signers
/// they are added to, the `https://` tokens in force.
struct Open {
    live: Arc<Live>,
    /// The agent signing keys' signer, over each backend (the service holds it too).
    signing: Arc<Routed>,
    /// The `ssh://` upstream credentials' signer, over each backend (the mirrors hold it too).
    upstream: Arc<Routed>,
    /// The tokens in force, as references: each unwrapped only when an operation uses it.
    tokens: RwLock<Tokens>,
    /// The backend the SSH CA's key is on (M7.6: a rotation moves it).
    ca_backend: RwLock<crate::declared::Backend>,
}

impl Open {
    fn tokens(&self) -> Tokens {
        // poisoned: the map is replaced one entry at a time; what is there stands.
        self.tokens
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// `mirrors` again for the registry of `policy` with the hosts `pinned`, the upstream
    /// signer and the tokens in force: the one way a change, a rewrap and a token reopen the
    /// mirrors (the review after M7.6, D-13).
    async fn mirrors_for(
        &self,
        mirrors: &Mirrors,
        policy: &PolicyConfig,
        pinned: PinnedHosts,
    ) -> writ_mirror::Result<Mirrors> {
        mirrors
            .with_registry(
                policy.repos(),
                policy.proxies(),
                pinned,
                self.upstream.clone(),
                &self.tokens(),
            )
            .await
    }
}

/// How a key a change took out is deleted once it is in force.
#[derive(Debug, Clone, Copy)]
enum Forget {
    /// A key, from its signer and the keystore.
    Key(KeyRole),
    /// An upstream token, from the mirrors' tokens and, unless a sealed notifier uses the same
    /// id, the keystore.
    Token { keep_file: bool },
}

/// What a token id is for: an `https://` upstream's credential, a sealed notifier's token, or
/// both.
struct TokenUse<'a> {
    upstream: bool,
    notifier: Option<&'a TelegramConfig>,
}

/// Starts what the keystore holds. Cloned into the gateway as its [`Unsealer`].
#[derive(Clone)]
pub struct Opener(Arc<Inner>);

struct Inner {
    config: Arc<Config>,
    policy: PolicyConfig,
    /// The authority files' texts the daemon started with: written back once open.
    texts: BTreeMap<AdminTarget, String>,
    /// Set once open: a registry change opens new mirrors with its credentials.
    open: OnceLock<Open>,
    mirrors: MirrorConfig,
    service: Arc<Service>,
    notifiers: Arc<LateNotifiers>,
    /// Set right after the gateway starts, before any listener runs.
    gateway: OnceLock<Gateway>,
    /// The HTTPS approval API's identity the listeners serve, replaced by a rotation (M7.5).
    tls: OnceLock<Arc<writ_crypto::tls::TlsIdentity>>,
    /// Set when the daemon opens itself (M7.6, `unseal: auto`): the unseal is logged so.
    automatic: std::sync::atomic::AtomicBool,
    /// Where the background tasks it starts go (the mirrors' sync): supervised by `writd run`.
    spawner: crate::supervise::Spawner,
}

impl Inner {
    /// The notifier that keeps the token `id` sealed, if one does (`token: { sealed: <id> }`).
    fn sealed_notifier(&self, id: &KeyId) -> Option<&TelegramConfig> {
        self.config.notifiers.iter().find_map(|n| {
            let NotifierConfig::Telegram(telegram) = n;
            matches!(&telegram.token, TokenConfig::Sealed(sealed) if sealed == id)
                .then_some(telegram)
        })
    }
}

impl Opener {
    pub fn new(
        config: Arc<Config>,
        policy: PolicyConfig,
        texts: BTreeMap<AdminTarget, String>,
        mirrors: MirrorConfig,
        service: Arc<Service>,
        notifiers: Arc<LateNotifiers>,
        spawner: crate::supervise::Spawner,
    ) -> Self {
        Self(Arc::new(Inner {
            config,
            policy,
            texts,
            open: OnceLock::new(),
            mirrors,
            service,
            notifiers,
            gateway: OnceLock::new(),
            tls: OnceLock::new(),
            automatic: std::sync::atomic::AtomicBool::new(false),
            spawner,
        }))
    }

    /// The HTTPS approval API's identity, as the listeners serve it.
    pub fn set_tls(&self, tls: Arc<writ_crypto::tls::TlsIdentity>) {
        let _ = self.0.tls.set(tls);
    }

    fn tls(&self) -> Result<&Arc<writ_crypto::tls::TlsIdentity>, String> {
        self.0
            .tls
            .get()
            .ok_or_else(|| "the HTTPS approval API is not started".to_owned())
    }

    pub fn set_gateway(&self, gateway: Gateway) {
        let _ = self.0.gateway.set(gateway);
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

    fn token_show(&self, id: KeyId) -> BoxFuture<'static, Result<TokenShown, String>> {
        let me = self.clone();
        Box::pin(async move { me.show_token(&id) })
    }

    fn recovery_show(&self) -> BoxFuture<'static, Result<writ_proto::RecoveryShown, String>> {
        let me = self.clone();
        Box::pin(async move {
            let KeystoreConfig::Sealed(sealed) = &me.0.config.keystore else {
                return Err("the development keystore has no recovery recipient".to_owned());
            };
            keystore::recipients::recovery_shown(sealed, &me.0.service.policy())
                .map_err(|e| format!("{e:#}"))
        })
    }

    fn apply_token(
        &self,
        checked: CheckedToken,
        caller: CallerFacts,
    ) -> BoxFuture<'static, Result<TokenApplied, String>> {
        let me = self.clone();
        Box::pin(async move { me.apply_token(checked, caller).await })
    }

    fn keys_show(&self) -> BoxFuture<'static, Result<KeysShown, String>> {
        let me = self.clone();
        // A signer's queue: off the async threads.
        Box::pin(async move {
            tokio::task::spawn_blocking(move || me.show_keys())
                .await
                .map_err(|_| "the read stopped".to_owned())?
        })
    }

    fn auto_unseal_show(&self) -> BoxFuture<'static, Result<writ_proto::AutoUnsealShown, String>> {
        let me = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let policy = me.0.service.policy();
                let missing = crate::autounseal::missing(&me.0.config, &policy)
                    .map_err(|e| format!("{e:#}"))?;
                Ok(writ_proto::AutoUnsealShown {
                    unseal: policy.unseal().as_str().to_owned(),
                    missing,
                })
            })
            .await
            .map_err(|_| "the read stopped".to_owned())?
        })
    }

    fn ca_show(&self) -> BoxFuture<'static, Result<writ_proto::CaShown, String>> {
        let me = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || me.show_ca())
                .await
                .map_err(|_| "the read stopped".to_owned())?
        })
    }

    fn rotate_ca(
        &self,
        checked: writ_approval::CheckedCa,
        caller: CallerFacts,
    ) -> BoxFuture<'static, Result<writ_proto::CaRotated, String>> {
        let me = self.clone();
        // Files and a device: off the async threads; run to its end even if the client goes.
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let done = me.rotate_ca_now(&checked, &caller);
                // A refusal after the check, logged once, here.
                if let Err(why) = &done {
                    me.0.service.ca_refused(&checked, why, &caller);
                }
                done
            })
            .await
            .map_err(|_| "the rotation stopped".to_owned())?
        })
    }

    fn tls_show(&self) -> BoxFuture<'static, Result<writ_proto::TlsShown, String>> {
        let me = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || me.show_tls())
                .await
                .map_err(|_| "the read stopped".to_owned())?
        })
    }

    fn rotate_tls(
        &self,
        checked: writ_approval::CheckedTls,
        caller: CallerFacts,
    ) -> BoxFuture<'static, Result<writ_proto::TlsRotated, String>> {
        let me = self.clone();
        // Files and a device: off the async threads; run to its end even if the client goes.
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let done = me.rotate(&checked, &caller);
                // A refusal after the check, logged once, here.
                if let Err(why) = &done {
                    me.0.service.tls_refused(&checked, why, &caller);
                }
                done
            })
            .await
            .map_err(|_| "the rotation stopped".to_owned())?
        })
    }
}

/// A public key's fingerprint as the protocol names it.
fn fingerprint_of(
    key: &writ_crypto::ssh_key::PublicKey,
) -> Result<writ_core::names::KeyFingerprint, String> {
    key.fingerprint(writ_crypto::ssh_key::HashAlg::Sha256)
        .to_string()
        .parse()
        .map_err(|e: writ_core::names::NameError| e.to_string())
}
