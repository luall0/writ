//! The keys the policy declares (`keys.<id>`) and the daemon makes: every signing key and
//! every `ssh` upstream credential, each checked against the backend that holds it
//! (`writ_crypto::algorithm::check`) whenever a policy is read (at start, at `writd init` and
//! `writd recover`, on every admin change); and each key the keystore holds checked against its
//! declaration. A token's declaration is checked too (its backend), though the daemon never
//! makes one. Every refusal names the field and the reason; a combination is never adjusted to
//! one that works.

use std::collections::BTreeMap;
use std::str::FromStr;

use anyhow::bail;
use writ_core::config::{BackendName, Key, PolicyConfig, UpstreamKey};
use writ_core::names::KeyId;
use writ_crypto::algorithm::{Hash, KeyAlgorithm, SignatureFormat, SignerHash};
use writ_crypto::keyfile::KeyMeta;
use writ_crypto::keypair::KeyPair;
use writ_crypto::ssh_key::PublicKey;
use writ_proto::KeyRole;

/// A backend this daemon has.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Backend {
    /// In the daemon's memory, from its keystore.
    #[default]
    Software,
}

impl Backend {
    /// Every backend this build has.
    pub const ALL: [Backend; 1] = [Backend::Software];

    pub fn name(self) -> &'static str {
        match self {
            Backend::Software => "software",
        }
    }

    /// The backend a declaration names, at `at` (`keys.<id>.backend`), or why this daemon
    /// has none by that name.
    fn of(name: &BackendName, at: &str) -> anyhow::Result<Self> {
        Self::ALL
            .into_iter()
            .find(|b| b.name() == name.as_str())
            .ok_or_else(|| {
                let have: Vec<&str> = Self::ALL.iter().map(|b| b.name()).collect();
                anyhow::anyhow!(
                    "{at}: this daemon has no backend {name} (it has: {})",
                    have.join(", ")
                )
            })
    }

    /// The (algorithm, signer hash) pairs it signs with.
    fn pairs(self) -> Vec<(KeyAlgorithm, SignerHash)> {
        match self {
            Backend::Software => writ_signer::software::pairs(),
        }
    }
}

/// A key the daemon makes and holds, as declared and checked against its backend: `hash` is
/// the one it signs with (the one set, or the strongest allowed when it was left out; for an
/// upstream credential, the strongest its algorithm takes in SSH, though ssh asks for its own).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Declared {
    pub role: KeyRole,
    pub format: SignatureFormat,
    pub algorithm: KeyAlgorithm,
    pub hash: Hash,
    pub backend: Backend,
}

/// Every key the daemon makes, by id.
pub type Declarations = BTreeMap<KeyId, Declared>;

/// A policy name read as `writ-crypto`'s type: the two lists are the same names (checked by a
/// test), so this only fails if they ever drift apart.
fn crypto<T: FromStr>(name: &str, at: &str) -> anyhow::Result<T>
where
    T::Err: std::fmt::Display,
{
    name.parse().map_err(|e| anyhow::anyhow!("{at}: {e}"))
}

/// The keys `policy` declares that the daemon makes (its signing keys and `ssh` upstream
/// credentials), each checked against its backend; a token's backend is checked too.
pub fn declarations(policy: &PolicyConfig) -> anyhow::Result<Declarations> {
    let mut declared = Declarations::new();
    for (id, key) in policy.keys() {
        let at = format!("keys.{id}");
        let backend = Backend::of(key.backend(), &format!("{at}.backend"))?;
        let (role, format, algorithm, hash) = match key {
            Key::Signing(k) => (
                KeyRole::Signing,
                crypto::<SignatureFormat>(k.format.as_str(), &format!("{at}.format"))?,
                crypto::<KeyAlgorithm>(k.algorithm.as_str(), &format!("{at}.algorithm"))?,
                k.hash
                    .map(|h| crypto::<Hash>(h.as_str(), &format!("{at}.hash")))
                    .transpose()?,
            ),
            Key::Upstream(UpstreamKey::Ssh { algorithm, .. }) => (
                KeyRole::Upstream,
                SignatureFormat::Ssh,
                crypto::<KeyAlgorithm>(algorithm.as_str(), &format!("{at}.algorithm"))?,
                None,
            ),
            // A token: sealed bytes the daemon never signs with.
            Key::Upstream(UpstreamKey::Token { .. }) => continue,
        };
        let hash = writ_crypto::algorithm::check(
            format,
            algorithm,
            hash,
            backend.name(),
            &backend.pairs(),
        )
        .map_err(|why| anyhow::anyhow!("{at}: {why}"))?;
        declared.insert(
            id.clone(),
            Declared {
                role,
                format,
                algorithm,
                hash,
                backend,
            },
        );
    }
    Ok(declared)
}

/// How each signing key signs, for the approval service.
pub fn key_uses(declared: &Declarations) -> writ_approval::KeyUses {
    declared
        .iter()
        .filter(|(_, key)| key.role == KeyRole::Signing)
        .map(|(id, key)| {
            let key_use = writ_approval::KeyUse {
                format: key.format,
                hash: key.hash,
            };
            (id.clone(), key_use)
        })
        .collect()
}

/// How a key is named in messages: `signing key agent-01`, `upstream credential forgejo-01`.
pub fn named(role: KeyRole, id: &KeyId) -> String {
    format!("{} {id}", role.as_str())
}

/// Checks a key the keystore holds (its public half, and what its file says it is) against
/// its declaration: the same algorithm and format, or nothing goes on.
pub fn check_key(
    id: &KeyId,
    declared: &Declared,
    public: &PublicKey,
    meta: &KeyMeta,
) -> anyhow::Result<()> {
    let held = KeyAlgorithm::of_public(public.key_data());
    let name = named(declared.role, id);
    if held != Some(declared.algorithm) {
        bail!(
            "{name}: declared {} but the keystore holds a {} key (a key never changes \
             algorithm: declare it as it is, or give the new one another id)",
            declared.algorithm,
            held.map_or_else(|| public.algorithm().to_string(), |a| a.to_string())
        );
    }
    if meta.format != declared.format {
        bail!(
            "{name}: declared format {} but the keystore holds it for {} (a key signs in one \
             format: declare it as it is, or give the new one another id)",
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

/// The armored OpenPGP certificate of `key` with `uids`, each self-signature made with the
/// key itself (on the host: `writd init`, `writd recover`): the same certificate the running
/// daemon makes through its signer. `None` for an SSH key, or a key without user ids yet (a
/// certificate without one doesn't import).
pub fn certificate(
    key: &crate::keystore::StoredKey,
    declared: &Declared,
    uids: &[writ_core::names::Uid],
) -> anyhow::Result<Option<String>> {
    let Some(created) = key.meta.created else {
        return Ok(None);
    };
    if declared.format != SignatureFormat::Openpgp || uids.is_empty() {
        return Ok(None);
    }
    let openpgp = writ_crypto::openpgp::OpenpgpKey::new(&key.key.public_key(), created)?;
    let mut certified = Vec::with_capacity(uids.len());
    for uid in uids {
        let prepared = writ_crypto::openpgp::certification(&openpgp, declared.hash, uid.as_str())?;
        let (data, hash) = prepared.signer_input();
        let signature = key.key.sign(data, hash)?;
        certified.push((uid.as_str(), prepared.packet(&signature)?));
    }
    Ok(Some(writ_crypto::openpgp::certificate(
        &openpgp, &certified,
    )?))
}

/// What `writd signing-keys` prints for a key: its id and SSH public key for an SSH key; its
/// id, `openpgp`, its fingerprint and algorithm for an OpenPGP one.
pub fn describe(id: &KeyId, public: &PublicKey, meta: &KeyMeta) -> anyhow::Result<String> {
    match meta.created {
        Some(created) => {
            let key = writ_crypto::openpgp::OpenpgpKey::new(public, created)?;
            Ok(format!(
                "{id} openpgp {} ({})",
                key.fingerprint_hex(),
                key.algorithm()
            ))
        }
        None => Ok(format!("{id} {}", public.to_openssh()?)),
    }
}

#[cfg(test)]
mod tests {
    use writ_core::config::{HashName, KeyFormat};

    use super::*;

    fn decl(role: KeyRole, format: SignatureFormat, algorithm: KeyAlgorithm) -> Declared {
        Declared {
            role,
            format,
            algorithm,
            hash: Hash::Sha512,
            backend: Backend::Software,
        }
    }

    #[test]
    fn a_key_held_with_another_algorithm_or_format_is_refused_by_name() {
        let id: KeyId = "agent-01".parse().unwrap();
        let key = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let ssh = decl(
            KeyRole::Signing,
            SignatureFormat::Ssh,
            KeyAlgorithm::Ed25519,
        );
        check_key(&id, &ssh, &key.public_key(), &KeyMeta::SSH).unwrap();
        let p256 = decl(KeyRole::Signing, SignatureFormat::Ssh, KeyAlgorithm::P256);
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
        let rsa = decl(
            KeyRole::Upstream,
            SignatureFormat::Ssh,
            KeyAlgorithm::Rsa4096,
        );
        assert_eq!(
            check_key(&id, &rsa, &key.public_key(), &KeyMeta::SSH)
                .unwrap_err()
                .to_string(),
            "upstream credential agent-01: declared rsa4096 but the keystore holds a ed25519 key \
             (a key never changes algorithm: declare it as it is, or give the new one another id)"
        );
    }

    #[test]
    fn the_policy_s_names_are_writ_crypto_s() {
        // Both directions: a name the policy takes is one the daemon reads, and the other way.
        let algorithms: Vec<&str> = writ_core::config::KeyAlgorithm::ALL
            .iter()
            .map(|a| a.as_str())
            .collect();
        let crypto_algorithms: Vec<&str> = KeyAlgorithm::ALL.iter().map(|a| a.name()).collect();
        assert_eq!(algorithms, crypto_algorithms);
        let formats: Vec<&str> = KeyFormat::ALL.iter().map(|f| f.as_str()).collect();
        let crypto_formats: Vec<&str> = SignatureFormat::ALL.iter().map(|f| f.name()).collect();
        assert_eq!(formats, crypto_formats);
        for hash in HashName::ALL {
            assert_eq!(hash.as_str().parse::<Hash>().unwrap().name(), hash.as_str());
        }
    }

    fn policy(keys: &str) -> PolicyConfig {
        PolicyConfig::from_yaml(&format!("keys:\n{keys}\nrepos: {{}}\ntemplates: {{}}\n")).unwrap()
    }

    #[test]
    fn each_declaration_is_resolved_on_its_backend_or_refused_by_name() {
        let declared = declarations(&policy(
            "  a: { use: signing, format: ssh, algorithm: ed25519 }\n  \
             b: { use: signing, format: openpgp, algorithm: p384 }\n  \
             c: { use: upstream, kind: ssh, algorithm: rsa3072 }\n  \
             t: { use: upstream, kind: token, host: github.com }",
        ))
        .unwrap();
        let id = |name: &str| name.parse::<KeyId>().unwrap();
        assert_eq!(
            declared[&id("a")].hash,
            Hash::Sha512,
            "the strongest left out"
        );
        assert_eq!(declared[&id("b")].hash, Hash::Sha384, "the curve's own");
        assert_eq!(declared[&id("c")].role, KeyRole::Upstream);
        assert_eq!(declared[&id("c")].algorithm, KeyAlgorithm::Rsa3072);
        assert!(!declared.contains_key(&id("t")), "a token is never made");
        assert_eq!(key_uses(&declared).len(), 2, "signing keys only");
        for (keys, why) in [
            (
                "  a: { use: signing, format: openpgp, algorithm: p256, hash: sha512 }",
                "keys.a: openpgp signs p256 keys with sha256, not sha512",
            ),
            (
                "  a: { use: signing, format: ssh, algorithm: ed25519, hash: sha384 }",
                "keys.a: ssh signs ed25519 keys with sha256, sha512, not sha384",
            ),
            (
                "  a: { use: signing, format: ssh, algorithm: ed25519, backend: yubikey }",
                "keys.a.backend: this daemon has no backend yubikey (it has: software)",
            ),
            (
                "  t: { use: upstream, kind: token, host: github.com, backend: tpm }",
                "keys.t.backend: this daemon has no backend tpm (it has: software)",
            ),
        ] {
            assert_eq!(
                declarations(&policy(keys)).unwrap_err().to_string(),
                why,
                "{keys}"
            );
        }
    }
}
