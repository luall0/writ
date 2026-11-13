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

use writ_approval::{AdminParsed, CheckedAdmin, CheckedToken};
use writ_core::authority::{AdminTarget, TextDigest};
use writ_core::names::KeyId;
use writ_gateway::{AdminApplier, Gateway, Unsealer};
use writ_mirror::credential::{Tokens, UpstreamToken};
use writ_mirror::known_hosts::PinnedHosts;
use writ_mirror::{MirrorConfig, Mirrors};
use writ_platform::{BoxFuture, Passphrase, UnsealRequest};
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

    /// The SSH CA in force, its backend, and the CA it replaced while trusted (M7.6).
    fn show_ca(&self) -> Result<writ_proto::CaShown, String> {
        let inner = &self.0;
        let open = inner.open.get().ok_or("the daemon is not open")?;
        let public = inner.service.ca_in_force().map_err(|e| e.to_string())?;
        let retired = match &inner.config.keystore {
            KeystoreConfig::Sealed(sealed) => {
                keystore::ca::retired(sealed, inner.service.now_unix())
                    .map_err(|e| format!("{e:#}"))?
                    .into_iter()
                    .filter(|(_, until)| *until > inner.service.now_unix())
                    .map(|(key, until)| {
                        Ok::<_, String>(writ_proto::RetiredCa {
                            fingerprint: fingerprint_of(&key)?,
                            until,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?
            }
            KeystoreConfig::Dev(_) => Vec::new(),
        };
        Ok(writ_proto::CaShown {
            daemon: inner.service.daemon().clone(),
            fingerprint: fingerprint_of(&public)?,
            public_key: public.to_openssh().map_err(|e| e.to_string())?,
            backend: open
                .ca_backend
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .name()
                .to_owned(),
            retired,
            backends: platform::backends_shown(),
        })
    }

    /// A checked `writ-ca/1` done (see [`AdminApplier::rotate_ca`]): refused unless it names
    /// the CA in force and a backend this daemon has (one in software refused under `unseal:
    /// auto`, the review after M7.6, D-2); the new key made there and staged beside the old
    /// with its backend's marker (D-4), its audit line written (refused without it, S-2), the
    /// key moved over the old (the point of no return), the new CA put in force for every
    /// certificate from now on, then the old one recorded as trusted until the last lease active
    /// once the new one was in force ends (D-3). What fails after the point of no return is said
    /// as "rotated, but …".
    fn rotate_ca_now(
        &self,
        checked: &writ_approval::CheckedCa,
        caller: &CallerFacts,
    ) -> Result<writ_proto::CaRotated, String> {
        let inner = &self.0;
        let rotation = checked.rotation();
        let open = inner.open.get().ok_or("the daemon is not open")?;
        let gateway = inner
            .gateway
            .get()
            .ok_or("the gateway is not started yet")?;
        // The sealed state held for the whole rotation: a rotation of the data key waits, so
        // the new CA is never sealed to an identity being replaced (step 8's handoff).
        let Some((sealed, sealing)) = open.live.sealing() else {
            return Err("the development keystore's CA is a file: it isn't rotated".to_owned());
        };
        let recipient = sealing.recipient().clone();
        let old = inner.service.ca_in_force().map_err(|e| e.to_string())?;
        let previous = fingerprint_of(&old)?;
        if rotation.replaces != previous {
            return Err(format!(
                "it replaces CA {}, but {previous} is in force (rotated meanwhile?): writ admin \
                 ca rotate again",
                rotation.replaces
            ));
        }
        // Counted only now: a replay, naming a CA no longer in force, takes no rotation's place.
        inner.service.count_ca(checked).map_err(|e| e.to_string())?;
        let backend = platform::BACKENDS
            .iter()
            .copied()
            .find(|b| b.name() == rotation.backend.as_str())
            .ok_or_else(|| {
                format!(
                    "this daemon has no backend {} (it has: {})",
                    rotation.backend,
                    platform::BACKENDS
                        .iter()
                        .map(|b| b.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
        // Under auto-unseal everything is in hardware: a CA back in software would make the
        // next start refuse itself (the review after M7.6, D-2).
        if !backend.is_device()
            && inner.service.policy().unseal() == writ_core::config::Unseal::Auto
        {
            return Err(
                "unseal: auto is in force, and this would put the CA's key in software: turn \
                 auto-unseal off first (writ admin auto-unseal off)"
                    .to_owned(),
            );
        }
        let fail = |e: anyhow::Error| format!("{e:#}");
        let (material, meta) = match backend.is_device() {
            false => (
                keystore::Material::Software(
                    writ_crypto::keypair::KeyPair::generate(
                        writ_crypto::algorithm::KeyAlgorithm::Ed25519,
                    )
                    .map_err(|e| e.to_string())?,
                ),
                writ_crypto::keyfile::KeyMeta::SSH,
            ),
            true => platform::makers(&inner.config)
                .and_then(|makers| {
                    makers.make(
                        &keystore::CA_ID.parse()?,
                        &crate::declared::Declared {
                            role: KeyRole::Signing,
                            format: writ_crypto::algorithm::SignatureFormat::Ssh,
                            algorithm: writ_crypto::algorithm::KeyAlgorithm::P256,
                            hash: writ_crypto::algorithm::Hash::Sha256,
                            backend,
                        },
                    )
                })
                .map_err(fail)?,
        };
        let public = material.public_key();
        // The new CA signs before anything is written.
        let (signer, refused) = platform::ca(
            &inner.config,
            keystore::StoredKey {
                id: keystore::CA_ID
                    .parse()
                    .map_err(|e: writ_core::names::NameError| e.to_string())?,
                // A second copy for the signer, read back from what the file will hold.
                key: material
                    .encode(meta)
                    .and_then(|text| keystore::Material::decode(text.as_bytes(), public.clone()))
                    .map(|(material, _)| material)
                    .map_err(fail)?,
                meta,
            },
        )
        .map_err(fail)?;
        if let Some((_, why)) = refused.first() {
            return Err(format!("the new CA key was refused by its device: {why}"));
        }
        let fingerprint = fingerprint_of(&public)?;
        keystore::ca::stage(sealed, &recipient, &material, meta, backend.name()).map_err(fail)?;
        // The line first: no line, no rotation.
        if let Err(e) = inner.service.ca_rotating(checked, &fingerprint, caller) {
            keystore::ca::unstage(sealed);
            return Err(e.to_string());
        }
        // The gateway takes the new CA's certificates before any is issued, and the old one's
        // while its deadline is worked out below.
        let now = inner.service.now_unix();
        let still = keystore::ca::retired(sealed, now).unwrap_or_default();
        let trusted = |old_until: u64, kept: &[(writ_crypto::ssh_key::PublicKey, u64)]| {
            std::iter::once((old.clone(), old_until))
                .chain(kept.iter().cloned())
                .collect::<Vec<_>>()
        };
        let mut but = Vec::new();
        match keystore::ca::commit(sealed) {
            Ok(()) => {}
            Err(keystore::ca::Committed::NotInForce(why)) => {
                keystore::ca::unstage(sealed);
                return Err(why);
            }
            Err(keystore::ca::Committed::Unfinished(why)) => but.push(format!(
                "its public half and marker aren't moved in yet ({why}): the next start does it"
            )),
        }
        gateway.set_authorities(&public, &trusted(u64::MAX, &still));
        if let Err(e) = inner.service.replace_ca(checked, signer) {
            but.push(format!(
                "the running daemon still signs with the old CA ({e}): restart it"
            ));
        }
        *open
            .ca_backend
            .write()
            .unwrap_or_else(PoisonError::into_inner) = backend;
        // The old CA's deadline, read now that every new certificate is the new CA's: no lease
        // the old one certified is recorded after this (the review after M7.6, D-3), and none
        // lasts longer than the longest template allows (S-9).
        let longest = inner
            .service
            .policy()
            .templates()
            .values()
            .map(|t| t.max_ttl.seconds())
            .max()
            .unwrap_or(0);
        let until = match inner.service.last_active_expiry() {
            Ok(until) => until
                .filter(|until| *until > now)
                .map(|until| until.min(now.saturating_add(longest))),
            Err(e) => {
                but.push(format!("the active leases can't be read ({e}): the old CA is kept as long as the longest template allows"));
                Some(now.saturating_add(longest))
            }
        };
        let kept = match keystore::ca::retire(sealed, &old, until, now) {
            Ok(kept) => kept,
            Err(e) => {
                but.push(format!(
                    "the retired CAs' record can't be written ({e:#}): leases the old CA \
                     certified are refused after a restart"
                ));
                until
                    .map(|u| (old.clone(), u))
                    .into_iter()
                    .chain(still)
                    .collect()
            }
        };
        gateway.set_authorities(&public, &kept);
        for why in &but {
            let reason = format!("SSH CA rotated to {fingerprint}, but {why}");
            tracing::error!("{reason}");
            inner.service.admin_note(&reason);
        }
        tracing::info!(previous = %previous, ca = %fingerprint, backend = backend.name(), "SSH CA rotated");
        Ok(writ_proto::CaRotated {
            previous,
            fingerprint,
            public_key: public.to_openssh().map_err(|e| e.to_string())?,
            backend: backend.name().to_owned(),
            previous_until: until,
        })
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
        caller: &CallerFacts,
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
        // Counted only now: a replay, naming a certificate no longer in force, takes no
        // rotation's place.
        inner
            .service
            .count_tls(checked)
            .map_err(|e| e.to_string())?;
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
        let service = inner.service.clone();
        let next = keystore::tls_files(&config)
            .rotate(
                backend,
                &makers,
                |pair| platform::tls_identity(&config, pair),
                // The line first (the review after M7.6, S-2): no line, no rotation.
                |built| {
                    let fingerprint = built
                        .fingerprint()
                        .parse()
                        .map_err(|e| anyhow::anyhow!("the new certificate: {e}"))?;
                    service
                        .tls_rotating(checked, &fingerprint, caller)
                        .map_err(|e| anyhow::anyhow!("{e}"))
                },
            )
            .map_err(|e| format!("{e:#}"))?;
        let fingerprint = next.fingerprint();
        identity.replace(next);
        tracing::info!(
            previous = %previous,
            fingerprint = %fingerprint,
            backend = backend.name(),
            "the HTTPS approval API's TLS key was rotated: approvers re-pin"
        );
        // Through the service's queue (the review after M7.6, D-9): never inline, under the
        // admin lock, on a sink that may take seconds.
        inner.service.notify_rotation(writ_platform::Notification {
            title: "Writ: TLS key rotated".to_owned(),
            message: format!(
                "The HTTPS approval API's TLS key was rotated (backend {}): its certificate is \
                 now {fingerprint}. Approvers re-pin it in ~/.writ/tls_pins.",
                backend.name()
            ),
            priority: writ_platform::notify::Priority::Default,
            tags: vec!["tls".to_owned()],
        });
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
            settled,
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
        let ca_backend = match &keys.ca.key {
            keystore::Material::Device { backend, .. } => *backend,
            keystore::Material::Software(_) => crate::declared::Backend::Software,
        };
        // The CA's marker, which auto-unseal's check reads while sealed, is the key's own
        // (the review after M7.6, D-4): one that says otherwise is refused, named.
        if let KeystoreConfig::Sealed(sealed) = &inner.config.keystore {
            let marked = keystore::ca::backend(sealed)?;
            if marked != ca_backend.name() {
                bail!(
                    "{}: the CA's backend marker says {marked}, but its key is on {}: put {} \
                     there (the key is what it is)",
                    sealed.dir.join("ca.backend").display(),
                    ca_backend.name(),
                    ca_backend.name()
                );
            }
        }
        let (ca, refused) = platform::ca(&inner.config, keys.ca)?;
        unusable.extend(refused);
        // The CAs the gateway takes: this one, and one a rotation replaced, while its leases
        // last (M7.6).
        let retired = match &inner.config.keystore {
            KeystoreConfig::Sealed(sealed) => {
                keystore::ca::retired(sealed, inner.service.now_unix())?
            }
            KeystoreConfig::Dev(_) => Vec::new(),
        };
        gateway.set_authorities(ca.public_key(), &retired);
        let ca = writ_crypto::ca::CertificateAuthority::with_signer(ca);
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
            ca,
            signer: signer.clone(),
            authority,
            openpgp,
        };
        // Before the service reports open, so no admin change can run meanwhile (the review
        // after M7.6, D-8): the keys the policy in force no longer declares deleted, the files
        // in force written back.
        let live = Arc::new(live);
        self.sweep_keys(live.clone()).await;
        self.sync_files();
        let (service, approver_owned, caller_owned) =
            (inner.service.clone(), approver.cloned(), caller.clone());
        let automatic = inner.automatic.load(std::sync::atomic::Ordering::SeqCst);
        tokio::task::spawn_blocking(move || {
            let by = match (&approver_owned, automatic) {
                (Some(approver), _) => writ_approval::UnsealedBy::Approver(approver),
                (None, true) => writ_approval::UnsealedBy::Automatic,
                (None, false) => writ_approval::UnsealedBy::DevKeystore,
            };
            service.unseal_by(opened, by, &caller_owned)
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
        // A rotation of the data key the unseal did (S-8): one line each in the audit log.
        for line in &settled {
            tracing::warn!("keystore: {line}");
            inner.service.admin_note(&format!("keystore: {line}"));
        }
        gateway.set_mirrors(mirrors);
        inner.service.set_token_recipients(live.token_recipients());
        inner.service.set_keystore(
            live.sealed_parts()
                .map(|(_, recipient)| recipient.to_string()),
            live.rotation_owed(),
        );
        let _ = inner.open.set(Open {
            live,
            signing: signer,
            upstream,
            tokens: RwLock::new(tokens),
            ca_backend: RwLock::new(ca_backend),
        });
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
        let (gateway, every) = (
            gateway.clone(),
            Duration::from_secs(inner.config.mirrors.sync_every.seconds()),
        );
        inner.spawner.spawn(
            "mirror sync",
            Box::new(move || Box::pin(crate::mirror_sync(gateway.clone(), every))),
        );
        Ok(())
    }

    /// Deletes the keys the keystore holds that the policy in force no longer declares: left
    /// by a change that took them out, the daemon stopping before it deleted them. Each is said
    /// in the log and the audit log; a failure is logged and tried again at the next unseal.
    async fn sweep_keys(&self, live: Arc<keystore::Live>) {
        let inner = &self.0;
        let policy = inner.service.policy();
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
    async fn make_recipients(
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
    async fn rewrap(&self) -> anyhow::Result<Vec<String>> {
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
        let mirrors = gateway
            .mirrors()
            .map_err(|e| anyhow::anyhow!(e))?
            .with_registry(
                policy.repos(),
                policy.proxies(),
                pinned,
                open.upstream.clone(),
                &open.tokens(),
            )
            .await?;
        gateway.set_mirrors(mirrors);
        Ok(applied.said)
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
    async fn apply_token(
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

    /// The daemon opens itself through its hardware (M7.6, `unseal: auto`): its keystore's
    /// identity unwrapped by its devices, the service opened with no approver, logged as
    /// automatic and notified. The start checked first that everything is in hardware.
    /// A refusal (the versions in force altered at rest among them) is one `unseal` line,
    /// denied, and stops the start.
    pub async fn unseal_automatically(&self) -> anyhow::Result<()> {
        self.0
            .automatic
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let caller = writ_core::caller::CallerFacts::default();
        let opened = match self.open_keystore(PassphraseText::new(String::new())).await {
            Ok(opened) => self.open(opened, None, &caller).await,
            Err(e) => Err(e),
        };
        if let Err(e) = opened {
            let (service, reason) = (self.0.service.clone(), format!("automatic: {e:#}"));
            let _ = tokio::task::spawn_blocking(move || {
                service.unseal_failed(None, &reason, &caller);
            })
            .await;
            return Err(e);
        }
        tracing::info!("unsealed automatically");
        Ok(())
    }

    /// Opens the sealed keystore with `passphrase` (scrypt: off the async threads), or its
    /// hardware: every key and token the configuration names. Its errors name what failed,
    /// never a secret.
    async fn open_keystore(&self, passphrase: PassphraseText) -> anyhow::Result<Keystore> {
        let inner = self.0.clone();
        tokio::task::spawn_blocking(move || {
            if !matches!(&inner.config.keystore, KeystoreConfig::Sealed(_)) {
                bail!("this daemon's keystore is not sealed");
            }
            let request =
                UnsealRequest::with_passphrase(Passphrase::new(passphrase.expose().to_owned()));
            drop(passphrase);
            // The hardware recipients' devices when they wrap the identity (M7.6), else the
            // passphrase.
            let (key, hardware) = keystore::unseal_key(&inner.config, &request)?;
            let declared = crate::declared::declarations(&inner.policy)?;
            // The passphrase kept until the keystore is open: a rotation of the data key it
            // owes wraps the new identity with it (S-8). Wiped on drop.
            let opened = keystore::open(
                &inner.config,
                &declared,
                &inner.policy,
                &inner.service.in_force(),
                key,
                hardware,
                request.passphrase.as_ref(),
            );
            drop(request);
            opened
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

/// A public key's fingerprint as the protocol names it.
fn fingerprint_of(
    key: &writ_crypto::ssh_key::PublicKey,
) -> Result<writ_core::names::KeyFingerprint, String> {
    key.fingerprint(writ_crypto::ssh_key::HashAlg::Sha256)
        .to_string()
        .parse()
        .map_err(|e: writ_core::names::NameError| e.to_string())
}
