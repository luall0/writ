//! What an unseal opens: [`Opener`] takes what the keystore holds (the CA key, the agent
//! signing keys, the upstream credentials and tokens, the sealed notifiers' tokens, the
//! authority MAC's key) and starts what needs them (the signers, the mirrors, the service's
//! keys, the mirror sync), then writes the authority files in force back to their files. The
//! sealed keystore is opened by an approver's `writ unseal` ([`Unsealer`]); the development
//! keystore, at start. Once open, it puts admin changes in force ([`AdminApplier`]): a policy
//! declaring a key the keystore lacks makes it and hands it to the running signer
//! (`Signer::add_key`), its host pins go to the mirrors, and a token an approver sealed on
//! their machine is opened with the identity kept open, written, and used at once.

/// The creation time of each OpenPGP key a change added to the signer.
type Created = std::collections::BTreeMap<KeyId, u32>;

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
use writ_mirror::known_hosts::PinnedHosts;
use writ_mirror::{MirrorConfig, Mirrors};
use writ_platform::{BoxFuture, KeystoreUnlock, Passphrase, UnsealRequest};
use writ_proto::PassphraseText;
use writ_proto::{
    AdminApplied, CreatedKey, KeyRole, KeyShown, KeysShown, RemovedKey, TokenApplied, TokenShown,
};
use writ_signer::Signer;
use writ_signer::route::Routed;

use crate::config::{Config, KeystoreConfig, NotifierConfig, TelegramConfig, TokenConfig};
use crate::declared::Declarations;
use crate::keystore::{self, Live, Opened as Keystore};
use crate::platform::{self, LateNotifiers};

/// What stays open once the keystore is: where keys and tokens added later go, the signers
/// they are added to, the `https://` tokens in force.
struct Open {
    live: Arc<Live>,
    /// The agent signing keys' signer, over each backend (the service holds it too).
    signing: Arc<Routed>,
    /// The `ssh://` upstream credentials' signer, over each backend (the mirrors hold it too).
    upstream: Arc<Routed>,
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
            tls: OnceLock::new(),
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

    /// The certificate in force, its key's backend, and what a `writ-tls/1` names.
    fn show_tls(&self) -> Result<writ_proto::TlsShown, String> {
        let fingerprint = self
            .tls()?
            .fingerprint()
            .parse()
            .map_err(|e| format!("the certificate in force: {e}"))?;
        let backend = keystore::tls_files(&self.0.config)
            .backend()
            .map_err(|e| format!("{e:#}"))?;
        Ok(writ_proto::TlsShown {
            daemon: self.0.service.daemon().clone(),
            fingerprint,
            backend: backend.name().to_owned(),
            backends: platform::backends_shown(),
        })
    }

    /// A checked `writ-tls/1` done (see [`AdminApplier::rotate_tls`]): refused unless it names
    /// the certificate in force and a backend this daemon has; the new key and certificate
    /// written beside the old, built into the next identity, renamed over the old, then put in
    /// force for every handshake from now on; and the approvers told.
    fn rotate(
        &self,
        checked: &writ_approval::CheckedTls,
    ) -> Result<writ_proto::TlsRotated, String> {
        let inner = &self.0;
        let rotation = checked.rotation();
        let identity = self.tls()?;
        let previous = identity.fingerprint();
        if rotation.replaces.as_str() != previous {
            return Err(format!(
                "it replaces certificate {}, but {previous} is in force (rotated meanwhile?): \
                 writ admin tls rotate again",
                rotation.replaces
            ));
        }
        let backend = platform::BACKENDS
            .iter()
            .copied()
            .find(|b| b.name() == rotation.backend.as_str())
            .ok_or_else(|| {
                format!(
                    "this daemon has no backend {} (writ admin key list names them)",
                    rotation.backend
                )
            })?;
        let makers = platform::makers(&inner.config).map_err(|e| format!("{e:#}"))?;
        let config = inner.config.clone();
        let next = keystore::tls_files(&config)
            .rotate(backend, &makers, |pair| {
                platform::tls_identity(&config, pair)
            })
            .map_err(|e| format!("{e:#}"))?;
        let fingerprint = next.fingerprint();
        identity.replace(next);
        tracing::info!(
            previous = %previous,
            fingerprint = %fingerprint,
            backend = backend.name(),
            "the HTTPS approval API's TLS key was rotated: approvers re-pin"
        );
        let _ = writ_platform::Notifier::notify(
            &*inner.notifiers,
            &writ_platform::Notification {
                title: "Writ: TLS key rotated".to_owned(),
                message: format!(
                    "The HTTPS approval API's TLS key was rotated (backend {}): its certificate is \
                 now {fingerprint}. Approvers re-pin it in ~/.writ/tls_pins.",
                    backend.name()
                ),
                priority: writ_platform::notify::Priority::Default,
                tags: vec!["tls".to_owned()],
            },
        );
        Ok(writ_proto::TlsRotated {
            previous: rotation.replaces.clone(),
            fingerprint: fingerprint
                .parse()
                .map_err(|e| format!("the new certificate: {e}"))?,
            backend: backend.name().to_owned(),
        })
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
        let openpgp: std::collections::BTreeMap<KeyId, u32> = keys
            .signing
            .iter()
            .filter_map(|k| k.meta.created.map(|created| (k.id.clone(), created)))
            .collect();
        let platform::UseSigner {
            signer,
            refused: mut unusable,
        } = platform::signer(&inner.config, keys.signing)?;
        let upstream = platform::upstream_signer(&inner.config, keys.upstream)?;
        unusable.extend(upstream.refused);
        let upstream = upstream.signer;
        let mirrors = Mirrors::open(
            inner.mirrors.clone(),
            inner.policy.repos(),
            inner.policy.proxies(),
            upstream.clone(),
            &tokens,
        )
        .await?;
        let opened = Opened {
            ca: CertificateAuthority::new(keys.ca),
            signer: signer.clone(),
            authority,
            openpgp,
        };
        let (service, approver_owned, caller_owned) =
            (inner.service.clone(), approver.cloned(), caller.clone());
        tokio::task::spawn_blocking(move || {
            service.unseal(opened, approver_owned.as_ref(), &caller_owned)
        })
        .await
        .context("the unseal stopped")?
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        // A key whose stored bytes its device refused is listed and signs nothing: said once in
        // the audit log (the daemon's log has it too), its leases denied by name.
        for (id, why) in &unusable {
            inner.service.admin_note(&format!(
                "key {id} is unusable: its stored bytes were refused at unseal ({why}); writ \
                 admin key rotate replaces it"
            ));
        }
        gateway.set_mirrors(mirrors);
        let _ = inner.open.set(Open {
            live: Arc::new(live),
            signing: signer,
            upstream,
            tokens: RwLock::new(tokens),
        });
        self.sweep_keys().await;
        self.sync_files();
        self.write_certificates();
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

    /// Deletes the keys the keystore holds that the policy in force no longer declares: left
    /// by a change that took them out, the daemon stopping before it deleted them. Each is said
    /// in the log and the audit log; a failure is logged and tried again at the next unseal.
    async fn sweep_keys(&self) {
        let inner = &self.0;
        let Some(open) = inner.open.get() else {
            return;
        };
        let (live, policy) = (open.live.clone(), inner.service.policy());
        let swept = tokio::task::spawn_blocking(move || {
            let declared = crate::declared::declarations(&policy)?;
            keystore::sweep(&live, &declared)
        })
        .await;
        match swept {
            Ok(Ok(swept)) => {
                for key in swept {
                    let reason = format!(
                        "{key}: deleted from the keystore at unseal (the policy in force no \
                         longer declares it)"
                    );
                    tracing::warn!("{reason}");
                    inner.service.admin_note(&reason);
                }
            }
            Ok(Err(e)) => tracing::error!(error = %format!("{e:#}"), "cannot sweep the keystore"),
            Err(_) => tracing::error!("cannot sweep the keystore"),
        }
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
        let target = checked.admin().target;
        let text = checked.admin().text.as_str().to_owned();
        let refuse = |reason: String| {
            inner
                .service
                .admin_failed(Some(checked.approver()), Some(target), &reason, &caller);
            reason
        };
        enum Ready {
            Policy(Mirrors),
            Readers(Vec<writ_crypto::readers::Reader>),
            Approvers,
        }
        let (mut created, mut openpgp_created) = (Vec::new(), Created::new());
        let mut removed: Vec<(RemovedKey, Forget)> = Vec::new();
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
                (created, openpgp_created) = self
                    .keys_for(&declared)
                    .await
                    .map_err(|e| refuse(format!("{e:#}")))?;
                let mirrors = gateway
                    .mirrors()
                    .map_err(refuse)?
                    .with_registry(
                        policy.repos(),
                        policy.proxies(),
                        pinned,
                        open.upstream.clone(),
                        &open.tokens(),
                    )
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
        let (service, checked_owned, caller_owned) =
            (inner.service.clone(), checked.clone(), caller.clone());
        let shown: Vec<RemovedKey> = removed.iter().map(|(key, _)| key.clone()).collect();
        let applied = tokio::task::spawn_blocking(move || {
            service.commit_admin(
                &checked_owned,
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
        match ready {
            Ready::Policy(mirrors) => {
                gateway.set_mirrors(mirrors);
                self.forget(&removed).await;
                self.write_certificates();
            }
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

    /// Hands the signers every key `declared` names that they don't hold yet: from the
    /// keystore, or made there now as declared. The keys new to the signers, to register.
    async fn keys_for(
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
                if writ_signer::public_key(&**signer, id).is_ok() {
                    continue;
                }
                // A device's key is made by the use's own backend, which then holds it.
                let mut devices = BTreeMap::new();
                if let Some(device) = signer
                    .on(key.backend.name())
                    .filter(|_| key.backend.is_device())
                {
                    devices.insert(key.backend, device.clone());
                }
                let makers = keystore::Makers::running(devices);
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
    fn removed_keys(&self, next: &PolicyConfig) -> Vec<(RemovedKey, Forget)> {
        let inner = &self.0;
        let Some(open) = inner.open.get() else {
            return Vec::new();
        };
        let current = inner.service.policy();
        let notifier = |id: &KeyId| {
            inner.config.notifiers.iter().any(|n| {
                let NotifierConfig::Telegram(telegram) = n;
                matches!(&telegram.token, TokenConfig::Sealed(sealed) if sealed == id)
            })
        };
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
    async fn forget(&self, removed: &[(RemovedKey, Forget)]) {
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

    /// What the token `id` is for, from the policy in force and `writd.yaml`'s notifiers: an
    /// id neither uses is refused.
    fn token_use(&self, id: &KeyId) -> Result<TokenUse<'_>, String> {
        let inner = &self.0;
        let policy = inner.service.policy();
        let declared = keystore::tokens_declared(&policy);
        let notifier = inner.config.notifiers.iter().find_map(|n| {
            let NotifierConfig::Telegram(telegram) = n;
            matches!(&telegram.token, TokenConfig::Sealed(sealed) if sealed == id)
                .then_some(telegram)
        });
        let upstream = declared.contains(id);
        if !upstream && notifier.is_none() {
            return Err(format!(
                "token {id}: the policy in force declares no token {id} (keys.{id}, kind: \
                 token), and no notifier keeps it sealed"
            ));
        }
        Ok(TokenUse { upstream, notifier })
    }

    /// Every key the policy in force declares, with its public half from the signer that
    /// holds it, or for a token whether it was added; and what uses it.
    fn show_keys(&self) -> Result<KeysShown, String> {
        let inner = &self.0;
        let open = inner.open.get().ok_or("the daemon is not open")?;
        let policy = inner.service.policy();
        let version = inner
            .service
            .in_force()
            .versions
            .get(&AdminTarget::Policy)
            .map(|(version, _)| *version)
            .ok_or("no policy version in force")?;
        let tokens = open.tokens();
        let mut keys = Vec::new();
        for (id, key) in policy.keys() {
            let users = policy.key_users(id);
            let signer = match key {
                writ_core::config::Key::Signing(_) => Some(&open.signing),
                writ_core::config::Key::Upstream(writ_core::config::UpstreamKey::Ssh {
                    ..
                }) => Some(&open.upstream),
                writ_core::config::Key::Upstream(writ_core::config::UpstreamKey::Token {
                    ..
                }) => None,
            };
            let public = match signer {
                Some(signer) => Some(
                    writ_signer::public_key(&**signer, id).map_err(|e| format!("key {id}: {e}"))?,
                ),
                None => None,
            };
            let (public_key, fingerprint) = match &public {
                Some(public) => (
                    Some(public.to_openssh().map_err(|e| format!("key {id}: {e}"))?),
                    Some(
                        public
                            .fingerprint(writ_crypto::ssh_key::HashAlg::Sha256)
                            .to_string(),
                    ),
                ),
                None => (None, None),
            };
            keys.push(KeyShown {
                id: id.clone(),
                description: key.describe(),
                public_key,
                fingerprint,
                openpgp: inner.service.openpgp_shown(id),
                token_added: signer.is_none().then(|| tokens.contains_key(id)),
                repos: users.repos,
                templates: users.templates,
                proxies: users.proxies,
            });
        }
        Ok(KeysShown {
            version,
            keys,
            backends: platform::backends_shown(),
        })
    }

    fn show_token(&self, id: &KeyId) -> Result<TokenShown, String> {
        self.token_use(id)?;
        let open = self.0.open.get().ok_or("the daemon is not open")?;
        let previous = open.live.token_in_force(id).map_err(|e| format!("{e:#}"))?;
        Ok(TokenShown {
            daemon: self.0.service.daemon().clone(),
            id: id.clone(),
            previous,
        })
    }

    /// Puts a checked `writ-token/2` in force: its id one a repo or a notifier uses, its
    /// ciphertext opened by the keystore's identity and a token; logged by the service against
    /// the file in force; then written, and used at once (the mirrors that use it opened
    /// again, the notifier started with it). A refusal is logged once.
    async fn apply_token(
        &self,
        checked: CheckedToken,
        caller: CallerFacts,
    ) -> Result<TokenApplied, String> {
        let inner = &self.0;
        let id = checked.token().id.clone();
        let refuse = |reason: String| {
            let reason = format!("token {id}: {reason}");
            inner
                .service
                .admin_failed(Some(checked.approver()), None, &reason, &caller);
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
            let reopened = match (
                gateway.mirrors(),
                PinnedHosts::from_policy(policy.upstream_hosts()),
            ) {
                (Ok(mirrors), Ok(pinned)) => mirrors
                    .with_registry(
                        policy.repos(),
                        policy.proxies(),
                        pinned,
                        open.upstream.clone(),
                        &open.tokens(),
                    )
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

    /// Writes each OpenPGP key's certificate, as the service made it (at unseal, on a policy
    /// change), beside the key: what `writd signing-keys` prints. Best effort: the certificate
    /// a lease gets comes from the service, never from this file.
    fn write_certificates(&self) {
        let inner = &self.0;
        let policy = inner.service.policy();
        for (id, _) in policy
            .signing_keys()
            .filter(|(_, key)| key.format == writ_core::config::KeyFormat::Openpgp)
        {
            if let Some(certificate) = inner.service.openpgp_certificate(id)
                && let Err(e) = keystore::write_certificate(&inner.config, id, &certificate)
            {
                tracing::warn!(key = %id, error = %format!("{e:#}"), "cannot write the certificate");
            }
        }
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
            let declared = crate::declared::declarations(&inner.policy)?;
            keystore::open(&inner.config, &declared, &inner.policy, key.identity()?)
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

    fn keys_show(&self) -> BoxFuture<'static, Result<KeysShown, String>> {
        let me = self.clone();
        // A signer's queue: off the async threads.
        Box::pin(async move {
            tokio::task::spawn_blocking(move || me.show_keys())
                .await
                .map_err(|_| "the read stopped".to_owned())?
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
        _caller: CallerFacts,
    ) -> BoxFuture<'static, Result<writ_proto::TlsRotated, String>> {
        let me = self.clone();
        // Files and a device: off the async threads; run to its end even if the client goes.
        Box::pin(async move {
            tokio::task::spawn_blocking(move || me.rotate(&checked))
                .await
                .map_err(|_| "the rotation stopped".to_owned())?
        })
    }
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
