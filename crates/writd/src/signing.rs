//! The agent signing keys `writd.yaml` declares (`signing_keys`), checked before anything is
//! served: each declaration against its backend (`writ_crypto::algorithm::check`), the
//! policy against the declarations (`PolicyConfig::check_signing_keys`), and each key the
//! keystore holds against its declaration. Every refusal names the key and the reason; a
//! combination is never adjusted to one that works.

use std::collections::BTreeMap;

use anyhow::bail;
use writ_core::config::{DeclaredFormat, PolicyConfig};
use writ_core::names::KeyId;
use writ_crypto::algorithm::{Hash, KeyAlgorithm, SignatureFormat, SignerHash};
use writ_crypto::keyfile::KeyMeta;
use writ_crypto::keypair::KeyPair;
use writ_crypto::ssh_key::PublicKey;

use crate::config::{BackendConfig, Config};

/// A declared key, checked against its backend: `hash` is the one it signs with (the one set,
/// or the strongest allowed when it was left out).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Declared {
    pub format: SignatureFormat,
    pub algorithm: KeyAlgorithm,
    pub hash: Hash,
    pub backend: BackendConfig,
}

/// Every declared key, by id.
pub type Declarations = BTreeMap<KeyId, Declared>;

/// The (algorithm, signer hash) pairs a backend supports.
fn pairs(backend: BackendConfig) -> Vec<(KeyAlgorithm, SignerHash)> {
    match backend {
        BackendConfig::Software => writ_signer::software::pairs(),
    }
}

/// The declarations of `config`, each checked against its backend.
pub fn declarations(config: &Config) -> anyhow::Result<Declarations> {
    let mut declared = Declarations::new();
    for (id, key) in &config.signing_keys {
        if key.format == SignatureFormat::Openpgp {
            bail!(
                "signing_keys.{id}: format openpgp is refused by this build until OpenPGP \
                 signatures land (M5.5)"
            );
        }
        let hash = writ_crypto::algorithm::check(
            key.format,
            key.algorithm,
            key.hash,
            key.backend.name(),
            &pairs(key.backend),
        )
        .map_err(|why| anyhow::anyhow!("signing_keys.{id}: {why}"))?;
        declared.insert(
            id.clone(),
            Declared {
                format: key.format,
                algorithm: key.algorithm,
                hash,
                backend: key.backend,
            },
        );
    }
    Ok(declared)
}

/// What the policy's cross-check needs: each declared key's format.
pub fn formats(declared: &Declarations) -> BTreeMap<KeyId, DeclaredFormat> {
    declared
        .iter()
        .map(|(id, key)| {
            let format = match key.format {
                SignatureFormat::Ssh => DeclaredFormat::Ssh,
                SignatureFormat::Openpgp => DeclaredFormat::Openpgp,
            };
            (id.clone(), format)
        })
        .collect()
}

/// Checks the policy against the declarations: every template's key declared, user ids
/// only on OpenPGP keys, and one for each committer email those keys sign for.
pub fn check_policy(policy: &PolicyConfig, declared: &Declarations) -> anyhow::Result<()> {
    policy
        .check_signing_keys(&formats(declared))
        .map_err(|e| anyhow::anyhow!("policy: {e}"))
}

/// Checks a key the keystore holds (its public half, and what its file says it is) against
/// its declaration: the same algorithm and format, or the daemon doesn't start.
pub fn check_key(
    id: &KeyId,
    declared: &Declared,
    public: &PublicKey,
    meta: &KeyMeta,
) -> anyhow::Result<()> {
    let held = KeyAlgorithm::of_public(public.key_data());
    if held != Some(declared.algorithm) {
        bail!(
            "signing key {id}: declared {} but the keystore holds a {} key (a key never \
             changes algorithm: declare it as it is, or give the new one another id)",
            declared.algorithm,
            held.map_or_else(|| public.algorithm().to_string(), |a| a.to_string())
        );
    }
    if meta.format != declared.format {
        bail!(
            "signing key {id}: declared format {} but the keystore holds it for {} (a key \
             signs in one format: declare it as it is, or give the new one another id)",
            declared.format,
            meta.format
        );
    }
    Ok(())
}

/// A new key as `declared` describes it, made now.
pub fn make(declared: &Declared) -> anyhow::Result<(KeyPair, KeyMeta)> {
    let key = KeyPair::generate(declared.algorithm)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok((key, KeyMeta::new(declared.format, now)?))
}

/// The declaration of `id`, or why there is none.
pub fn declared<'a>(declared: &'a Declarations, id: &KeyId) -> anyhow::Result<&'a Declared> {
    declared.get(id).ok_or_else(|| {
        anyhow::anyhow!("signing key {id} is not declared in writd.yaml's signing_keys")
    })
}

/// SSH Ed25519 declarations of `ids` (SHA-512, software), for tests.
#[cfg(test)]
pub fn ssh_ed25519(ids: &[&str]) -> Declarations {
    ids.iter()
        .map(|id| {
            (
                id.parse().unwrap_or_else(|_| panic!("{id}: not a key id")),
                Declared {
                    format: SignatureFormat::Ssh,
                    algorithm: KeyAlgorithm::Ed25519,
                    hash: Hash::Sha512,
                    backend: BackendConfig::Software,
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decl(format: SignatureFormat, algorithm: KeyAlgorithm) -> Declared {
        Declared {
            format,
            algorithm,
            hash: Hash::Sha512,
            backend: BackendConfig::Software,
        }
    }

    #[test]
    fn a_key_held_with_another_algorithm_or_format_is_refused_by_name() {
        let id: KeyId = "agent-01".parse().unwrap();
        let key = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let ssh = decl(SignatureFormat::Ssh, KeyAlgorithm::Ed25519);
        check_key(&id, &ssh, &key.public_key(), &KeyMeta::SSH).unwrap();
        let p256 = decl(SignatureFormat::Ssh, KeyAlgorithm::P256);
        assert_eq!(
            check_key(&id, &p256, &key.public_key(), &KeyMeta::SSH)
                .unwrap_err()
                .to_string(),
            "signing key agent-01: declared p256 but the keystore holds a ed25519 key (a key \
             never changes algorithm: declare it as it is, or give the new one another id)"
        );
        let openpgp = KeyMeta::new(SignatureFormat::Openpgp, 1).unwrap();
        assert_eq!(
            check_key(&id, &ssh, &key.public_key(), &openpgp)
                .unwrap_err()
                .to_string(),
            "signing key agent-01: declared format ssh but the keystore holds it for openpgp (a \
             key signs in one format: declare it as it is, or give the new one another id)"
        );
    }
}
