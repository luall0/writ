//! The OpenPGP keys the service signs with: each one's creation time (from the keystore, at
//! unseal or when a policy change adds it), and its certificate, made again from the key, its
//! creation time and the user ids the policy gives it, at unseal and on every policy change.
//! Every self-signature carries the key's creation time, so the same inputs give the same
//! certificate: nothing here is state to keep in step with the policy.

use std::collections::BTreeMap;

use writ_core::config::PolicyConfig;
use writ_core::names::{KeyId, Uid};
use writ_crypto::algorithm::SignatureFormat;
use writ_signer::Signer;

use super::Service;
use crate::{KeyUse, ServiceError};

/// A certified OpenPGP key: the user ids its certificate carries, the certificate (armored),
/// and its fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Certified {
    pub(crate) uids: Vec<Uid>,
    pub(crate) certificate: String,
    pub(crate) fingerprint: String,
}

/// The OpenPGP keys the signer holds: their creation times, and the certificates of those a
/// template uses.
#[derive(Debug, Default)]
pub(crate) struct OpenpgpKeys {
    pub(crate) created: BTreeMap<KeyId, u32>,
    pub(crate) certified: BTreeMap<KeyId, Certified>,
}

/// The certificates of every OpenPGP key `policy`'s templates use, made through `signer`:
/// each key's creation time from `created`, its user ids from the policy, the self-signatures
/// with its declared hash.
pub(crate) fn certify(
    policy: &PolicyConfig,
    keys: &BTreeMap<KeyId, KeyUse>,
    signer: &dyn Signer,
    created: &BTreeMap<KeyId, u32>,
) -> Result<BTreeMap<KeyId, Certified>, ServiceError> {
    let mut certified = BTreeMap::new();
    for id in policy
        .templates()
        .values()
        .filter_map(|t| t.signing_key.as_ref())
    {
        let Some(key_use) = keys.get(id) else {
            continue;
        };
        if key_use.format != SignatureFormat::Openpgp || certified.contains_key(id) {
            continue;
        }
        let at = created.get(id).copied().ok_or_else(|| {
            ServiceError::Config(format!(
                "OpenPGP key {id}: the keystore gave no creation time for it"
            ))
        })?;
        let uids = policy.uids(id).to_vec();
        let texts: Vec<&str> = uids.iter().map(Uid::as_str).collect();
        let certificate = writ_signer::openpgp_certificate(signer, id, at, key_use.hash, &texts)
            .map_err(|e| ServiceError::Config(format!("OpenPGP key {id}: {e}")))?;
        let fingerprint = writ_signer::openpgp_key(signer, id, at)
            .map_err(|e| ServiceError::Config(format!("OpenPGP key {id}: {e}")))?
            .fingerprint_hex();
        certified.insert(
            id.clone(),
            Certified {
                uids,
                certificate,
                fingerprint,
            },
        );
    }
    Ok(certified)
}

/// What a new set of certificates changes, for the admin line: each key whose user ids are
/// new or changed, with them.
pub(crate) fn changes(
    old: &BTreeMap<KeyId, Certified>,
    new: &BTreeMap<KeyId, Certified>,
) -> String {
    new.iter()
        .filter(|(id, cert)| old.get(*id).is_none_or(|o| o.uids != cert.uids))
        .map(|(id, cert)| {
            let uids: Vec<&str> = cert.uids.iter().map(Uid::as_str).collect();
            format!(
                "; certified OpenPGP key {id} ({}): {}",
                cert.fingerprint,
                uids.join(", ")
            )
        })
        .collect()
}

impl Service {
    /// The OpenPGP keys in force.
    pub(crate) fn openpgp(&self) -> std::sync::RwLockReadGuard<'_, OpenpgpKeys> {
        // poisoned: the maps are replaced whole; the last one written stands.
        self.openpgp
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Replaces the OpenPGP keys in force.
    pub(crate) fn set_openpgp(&self, keys: OpenpgpKeys) {
        *self
            .openpgp
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = keys;
    }

    /// The creation time of the OpenPGP key `id` (what its fingerprint is computed over), if
    /// the daemon holds one. Copied out: the lock is released before anything signs, so a
    /// slow signer never holds up an admin change that replaces these keys.
    pub(crate) fn openpgp_created(&self, id: &KeyId) -> Option<u32> {
        self.openpgp().created.get(id).copied()
    }

    /// Signs `data` with the key `id` in the format `key_use` declares: an SSHSIG in
    /// `namespace`, or an OpenPGP signature made at `time` (an OpenPGP signature has no
    /// namespace). The only path from the service to the signer for a commit or a proof. No
    /// lock is held while the signer runs.
    pub(crate) fn signature(
        &self,
        signer: &dyn Signer,
        id: &KeyId,
        key_use: KeyUse,
        namespace: &str,
        data: &[u8],
        time: u32,
    ) -> Result<String, writ_signer::SignerError> {
        match key_use.format {
            SignatureFormat::Ssh => writ_signer::sshsig(signer, id, namespace, key_use.hash, data),
            SignatureFormat::Openpgp => {
                let created = self
                    .openpgp_created(id)
                    .ok_or_else(|| writ_signer::SignerError::Failed(id.clone()))?;
                writ_signer::openpgp_signature(signer, id, created, key_use.hash, data, time)
            }
        }
    }

    /// The armored certificate of the OpenPGP key `id`, if a template uses it.
    pub fn openpgp_certificate(&self, id: &KeyId) -> Option<String> {
        self.openpgp()
            .certified
            .get(id)
            .map(|c| c.certificate.clone())
    }

    /// The fingerprint (40 hex characters) and certificate of the OpenPGP key `id`, as
    /// certified for the policy in force; none before it has user ids.
    pub fn openpgp_shown(&self, id: &KeyId) -> Option<writ_proto::OpenpgpShown> {
        self.openpgp()
            .certified
            .get(id)
            .map(|c| writ_proto::OpenpgpShown {
                fingerprint: c.fingerprint.clone(),
                certificate: c.certificate.clone(),
            })
    }
}
