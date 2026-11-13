//! The HTTPS approval API's TLS key (M7.5): shown, and rotated on an approver's checked
//! `writ-tls/1`.

use super::Opener;
use crate::keystore;
use crate::platform;
use writ_core::caller::CallerFacts;

impl Opener {
    /// The certificate in force, its key's backend, and what a `writ-tls/1` names.
    pub(super) fn show_tls(&self) -> Result<writ_proto::TlsShown, String> {
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
    pub(super) fn rotate(
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
        let backend = platform::backend_named(rotation.backend.as_str()).ok_or_else(|| {
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
}
