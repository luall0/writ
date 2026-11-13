//! What the approver reads of the signers: every declared key's public half.

use super::Opener;
use crate::platform;
use writ_core::authority::AdminTarget;
use writ_proto::{KeyShown, KeysShown};

impl Opener {
    /// Every key the policy in force declares, with its public half from the signer that
    /// holds it, or for a token whether it was added; and what uses it.
    pub(super) fn show_keys(&self) -> Result<KeysShown, String> {
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
}
