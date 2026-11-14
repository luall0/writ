//! Opening: the keystore opened (by an approver's unseal, or the daemon's hardware), what
//! it holds started, the files in force written back.

use super::{Open, Opener};
use crate::config::{KeystoreConfig, NotifierConfig, TelegramConfig, TokenConfig};
use crate::keystore::{self, Opened as Keystore};
use crate::platform;
use anyhow::{Context, bail};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use writ_approval::Opened;
use writ_core::caller::CallerFacts;
use writ_core::names::KeyFingerprint;
use writ_core::names::KeyId;
use writ_mirror::Mirrors;
use writ_platform::{Passphrase, UnsealRequest};
use writ_proto::PassphraseText;

impl Opener {
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
        let (ca, ca_refused) = platform::ca(&inner.config, keys.ca)?;
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
        // A key its device refused (its stored bytes, its point or its probe) is listed and
        // signs nothing: said once in the audit log (the daemon's log has it too), with what
        // replaces it, its leases denied by name; the CA's, every grant refused.
        for (id, why) in &unusable {
            inner.service.admin_note(&format!(
                "key {id} is unusable: refused at unseal ({why}); writ admin key rotate {id} \
                 replaces it"
            ));
        }
        for (_, why) in &ca_refused {
            inner.service.admin_note(&format!(
                "the CA key is unusable: refused at unseal ({why}); writ admin ca \
                 rotate --backend {} replaces it, every grant refused until then",
                ca_backend.name()
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
    pub(super) async fn sweep_keys(&self, live: Arc<keystore::Live>) {
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
    pub(super) fn start_notifier(
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
    pub(super) fn sync_files(&self) {
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

    /// Writes each OpenPGP key's certificate, as the service made it (at unseal, on a policy
    /// change), beside the key: what `writd signing-keys` prints. Best effort: the certificate
    /// a lease gets comes from the service, never from this file.
    pub(super) fn write_certificates(&self) {
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
    pub(super) async fn open_keystore(
        &self,
        passphrase: PassphraseText,
    ) -> anyhow::Result<Keystore> {
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
