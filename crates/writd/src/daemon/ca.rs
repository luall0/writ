//! The SSH CA (M7.6): shown, and rotated on an approver's checked `writ-ca/1`.

use super::{Opener, fingerprint_of};
use crate::config::KeystoreConfig;
use crate::keystore;
use crate::platform;
use std::sync::PoisonError;
use writ_core::caller::CallerFacts;
use writ_proto::KeyRole;

impl Opener {
    /// The SSH CA in force, its backend, and the CA it replaced while trusted (M7.6).
    pub(super) fn show_ca(&self) -> Result<writ_proto::CaShown, String> {
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
    pub(super) fn rotate_ca_now(
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
        let backend = platform::backend_named(rotation.backend.as_str()).ok_or_else(|| {
            format!(
                "this daemon has no backend {} (it has: {})",
                rotation.backend,
                platform::backend_names()
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
}
