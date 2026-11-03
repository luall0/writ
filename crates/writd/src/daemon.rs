//! What an unseal opens: [`Opener`] takes what the keystore holds (the CA key, the agent
//! signing keys, the upstream credentials and tokens, the sealed notifiers' tokens, the
//! authority MAC's key) and starts what needs them (the signers, the mirrors, the service's
//! keys, the mirror sync), then writes the authority files in force back to their files. The
//! sealed keystore is opened by an approver's `writ unseal` ([`Unsealer`]); the development
//! keystore, at start. Once open, it puts admin changes in force ([`AdminApplier`]): a policy
//! naming a key the keystore lacks makes it and hands it to the running signer
//! (`Signer::add_key`), and a token an approver sealed on their machine is opened with the
//! identity kept open, written, and used at once.

use std::sync::{Arc, OnceLock, PoisonError, RwLock};
use std::time::Duration;

use anyhow::{Context, bail};
use std::collections::BTreeMap;
use writ_approval::{Opened, Service};
use writ_core::caller::CallerFacts;
use writ_core::config::PolicyConfig;
use writ_core::names::KeyFingerprint;
use writ_crypto::ca::CertificateAuthority;

use writ_approval::{AdminParsed, CheckedAdmin, CheckedToken};
use writ_core::authority::{AdminTarget, TextDigest};
use writ_core::names::KeyId;
use writ_gateway::{AdminApplier, Gateway, Unsealer};
use writ_mirror::credential::UpstreamToken;
use writ_mirror::{MirrorConfig, Mirrors};
use writ_platform::{BoxFuture, KeystoreUnlock, Passphrase, UnsealRequest};
use writ_proto::PassphraseText;
use writ_proto::{AdminApplied, CreatedKey, KeyRole, TokenApplied, TokenShown};
use writ_signer::Signer;

use crate::config::{Config, KeystoreConfig, NotifierConfig, TelegramConfig, TokenConfig};
use crate::keystore::{self, Live, Opened as Keystore};
use crate::platform::{self, LateNotifiers};

/// What stays open once the keystore is: where keys and tokens added later go, the signers
/// they are added to, the `https://` tokens in force.
struct Open {
    live: Arc<Live>,
    /// The agent signing keys' signer (the service holds it too).
    signing: Arc<dyn Signer>,
    /// The `ssh://` upstream credentials' signer (the mirrors hold it too).
    upstream: Arc<dyn Signer>,
    tokens: RwLock<BTreeMap<KeyId, Arc<UpstreamToken>>>,
}

impl Open {
    fn tokens(&self) -> BTreeMap<KeyId, Arc<UpstreamToken>> {
        // poisoned: the map is replaced one entry at a time; what is there stands.
        self.tokens
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
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
            open: OnceLock::new(),
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
            live,
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
            signer: signer.clone(),
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
        let _ = inner.open.set(Open {
            live: Arc::new(live),
            signing: signer,
            upstream,
            tokens: RwLock::new(tokens),
        });
        self.sync_files();
        // Open: the notifiers whose token was sealed join the others; one whose token isn't
        // in the keystore yet stays off until `writ admin token` adds it.
        for notifier in &inner.config.notifiers {
            let NotifierConfig::Telegram(telegram) = notifier;
            if let TokenConfig::Sealed(id) = &telegram.token {
                match bot_tokens.remove(id) {
                    Some(token) => self.start_notifier(id, token, telegram),
                    None => tracing::warn!(
                        token = %id,
                        "notifier not started: its token is not in the keystore (writ admin \
                         token {id} adds it)"
                    ),
                }
            }
        }
        crate::spawn_mirror_sync(
            gateway.clone(),
            Duration::from_secs(inner.config.mirrors.sync_every.seconds()),
        );
        Ok(())
    }

    /// Starts (or restarts, with a new token) the notifier whose sealed token is `id`.
    fn start_notifier(
        &self,
        id: &KeyId,
        token: writ_platform::notify::telegram::BotToken,
        telegram: &TelegramConfig,
    ) {
        match platform::telegram_notifier(token, telegram) {
            Ok(notifier) => self.0.notifiers.set(id, notifier),
            Err(e) => tracing::error!(token = %id, error = %e, "notifier not started"),
        }
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
        let mut created = Vec::new();
        let (parsed, ready) = match target {
            AdminTarget::Policy => {
                let policy = crate::authority::parse_policy(&text, inner.config.min_ttl)
                    .map_err(|e| refuse(format!("{e:#}")))?;
                let open = inner
                    .open
                    .get()
                    .ok_or_else(|| refuse("the daemon is not open".to_owned()))?;
                created = self
                    .keys_for(&policy)
                    .await
                    .map_err(|e| refuse(format!("{e:#}")))?;
                let mirrors = gateway
                    .mirrors()
                    .map_err(refuse)?
                    .with_registry(policy.repos(), open.upstream.clone(), &open.tokens())
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
            service.commit_admin(&checked_owned, parsed, created, &caller_owned)
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
        for key in &applied.created {
            tracing::info!(id = %key.id, role = key.role.as_str(), public_key = %key.public_key, "key created");
        }
        Ok(applied)
    }

    /// Hands the signers every key `policy` names that they don't hold yet: from the
    /// keystore, or made there now (Ed25519). The keys new to the signers, to register.
    async fn keys_for(&self, policy: &PolicyConfig) -> anyhow::Result<Vec<CreatedKey>> {
        let open = self.0.open.get().context("the daemon is not open")?;
        let (upstream_ids, _) = keystore::upstream_credentials(policy)?;
        let wanted: Vec<(KeyRole, KeyId)> = keystore::signing_ids(policy)
            .into_iter()
            .map(|id| (KeyRole::Signing, id.clone()))
            .chain(
                upstream_ids
                    .into_iter()
                    .map(|id| (KeyRole::Upstream, id.clone())),
            )
            .collect();
        let (live, signing, upstream) = (
            open.live.clone(),
            open.signing.clone(),
            open.upstream.clone(),
        );
        // Files, and a signer's queue: off the async threads.
        tokio::task::spawn_blocking(move || {
            let mut added = Vec::new();
            for (role, id) in wanted {
                let signer = match role {
                    KeyRole::Signing => &signing,
                    KeyRole::Upstream => &upstream,
                };
                if writ_signer::public_key(&**signer, &id).is_ok() {
                    continue;
                }
                let (key, made) = live.key_or_make(role, &id)?;
                let key = writ_crypto::keypair::KeyPair::from_ssh(key)?;
                let info = signer
                    .add_key(id.clone(), key)
                    .with_context(|| format!("{} {id}", role.as_str()))?;
                if made {
                    tracing::info!(%id, role = role.as_str(), "key made in the keystore");
                }
                added.push(CreatedKey {
                    id,
                    role,
                    public_key: info.public_key.to_openssh()?,
                });
            }
            Ok(added)
        })
        .await
        .context("the change stopped")?
    }

    /// What the token `id` is for, from the policy in force and `writd.yaml`'s notifiers: an
    /// id neither uses is refused.
    fn token_use(&self, id: &KeyId) -> Result<TokenUse<'_>, String> {
        let inner = &self.0;
        let policy = inner.service.policy();
        let (_, https) = keystore::upstream_credentials(&policy).map_err(|e| e.to_string())?;
        let notifier = inner.config.notifiers.iter().find_map(|n| {
            let NotifierConfig::Telegram(telegram) = n;
            matches!(&telegram.token, TokenConfig::Sealed(sealed) if sealed == id)
                .then_some(telegram)
        });
        let upstream = https.contains(id);
        if !upstream && notifier.is_none() {
            return Err(format!(
                "token {id}: no https:// repo of the policy in force names it as its \
                 upstream_credential, and no notifier keeps it sealed"
            ));
        }
        Ok(TokenUse { upstream, notifier })
    }

    fn show_token(&self, id: &KeyId) -> Result<TokenShown, String> {
        self.token_use(id)?;
        let open = self.0.open.get().ok_or("the daemon is not open")?;
        let previous = open.live.token_in_force(id).map_err(|e| format!("{e:#}"))?;
        Ok(TokenShown {
            id: id.clone(),
            previous,
        })
    }

    /// Puts a checked `writ-token/1` in force: its id one a repo or a notifier uses, its
    /// ciphertext opened by the keystore's identity and a token; logged by the service against
    /// the file in force; then written, and used at once (the mirrors that use it opened
    /// again, the notifier started with it). A refusal is logged once.
    async fn apply_token(
        &self,
        checked: CheckedToken,
        caller: CallerFacts,
    ) -> Result<TokenApplied, String> {
        let inner = &self.0;
        let id = checked.token.id.clone();
        let refuse = |reason: String| {
            let reason = format!("token {id}: {reason}");
            inner
                .service
                .admin_failed(Some(&checked.approver), None, &reason, &caller);
            reason
        };
        let gateway = inner.gateway.get().ok_or("the daemon is not started yet")?;
        let open = inner
            .open
            .get()
            .ok_or_else(|| refuse("the daemon is not open".to_owned()))?;
        let used = self.token_use(&id).map_err(refuse)?;
        let file = writ_crypto::sealed::decode(checked.token.sealed.as_str())
            .map_err(|e| refuse(e.to_string()))?;
        let plaintext = open
            .live
            .open_token(&id, &file)
            .map_err(|e| refuse(format!("{e:#} (is it sealed to this daemon's recipient?)")))?;
        let upstream_token = match used.upstream {
            true => Some(Arc::new(
                UpstreamToken::from_bytes(&plaintext)
                    .map_err(|why| refuse(format!("not a token: {why}")))?,
            )),
            false => None,
        };
        let bot_token = match used.notifier {
            Some(_) => {
                Some(keystore::bot_token(&id, &plaintext).map_err(|e| refuse(format!("{e:#}")))?)
            }
            None => None,
        };
        drop(plaintext);
        let current = open
            .live
            .token_in_force(&id)
            .map_err(|e| refuse(format!("{e:#}")))?;
        let digest = TextDigest::of_bytes(&file);
        let (service, checked_owned, caller_owned, digest_owned) = (
            inner.service.clone(),
            checked.clone(),
            caller.clone(),
            digest.clone(),
        );
        let applied = tokio::task::spawn_blocking(move || {
            service.commit_token(&checked_owned, &current, &digest_owned, &caller_owned)
        })
        .await
        .map_err(|_| "the change stopped".to_owned())?
        .map_err(|e| e.to_string())?;
        if let Err(e) = open.live.write_token(&id, &file) {
            return Err(refuse(format!("logged but not written: {e:#}")));
        }
        tracing::info!(token = %id, digest = %digest, approver = %applied.signed_by, "token in force");
        if let (Some(token), Some(telegram)) = (bot_token, used.notifier) {
            self.start_notifier(&id, token, telegram);
        }
        if let Some(token) = upstream_token {
            open.tokens
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id.clone(), token);
            let policy = inner.service.policy();
            let reopened = match gateway.mirrors() {
                Ok(mirrors) => mirrors
                    .with_registry(policy.repos(), open.upstream.clone(), &open.tokens())
                    .await
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e),
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

    fn token_show(&self, id: KeyId) -> BoxFuture<'static, Result<TokenShown, String>> {
        let me = self.clone();
        Box::pin(async move { me.show_token(&id) })
    }

    fn apply_token(
        &self,
        checked: CheckedToken,
        caller: CallerFacts,
    ) -> BoxFuture<'static, Result<TokenApplied, String>> {
        let me = self.clone();
        Box::pin(async move { me.apply_token(checked, caller).await })
    }
}
