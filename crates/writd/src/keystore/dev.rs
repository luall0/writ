//! The development keystore: plain key files in a private directory, generated on first
//! start, and the HTTPS upstreams' tokens the operator wrote there. Refused by a release build
//! (and by any build without the `dev-keystore` feature).

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use writ_core::config::PolicyConfig;
use writ_core::names::KeyId;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{LineEnding, PrivateKey};
use writ_mirror::credential::{MAX_TOKEN_FILE, TokenRef, TokenSource, Tokens, UpstreamToken};
use writ_platform::notify::telegram::BotToken;
use writ_proto::KeyRole;

use super::{
    Boot, Keys, StoredKey, TlsKeyPair, of_role, private_dir, tokens_declared, write_private,
};
use crate::declared::{Declarations, Declared};

/// The TLS key and certificate of the dev keystore, made on first start.
/// Where the development keystore keeps the TLS key and certificate.
pub fn tls_files(dir: &Path) -> super::tls::TlsFiles {
    super::tls::TlsFiles {
        key: dir.join("tls-01"),
        cert: dir.join("tls-01.crt"),
    }
}

fn dev_tls(dir: &Path) -> anyhow::Result<TlsKeyPair> {
    let files = tls_files(dir);
    files.finish()?;
    // The key is written first: a cert without its key (or a key alone, after a crash
    // between the two writes) is a pair to make again, in software.
    if !(files.cert.exists() && files.key.exists()) {
        for leftover in [&files.cert, &files.key, &files.public()] {
            match std::fs::remove_file(leftover) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(e).with_context(|| format!("cannot remove {}", leftover.display()));
                }
                _ => {}
            }
        }
        files.make(
            crate::declared::Backend::Software,
            &super::Makers::default(),
        )?;
    }
    files.read()
}

/// The dev keystore's key `name`, generated on first start.
fn dev_key(dir: &Path, name: &str) -> anyhow::Result<PrivateKey> {
    let path = dir.join(name);
    if path.exists() {
        // A private file of the daemon's user, read into memory wiped on drop.
        let pem = writ_platform::fs::read_secret(&path, "the key", 1 << 16)?;
        return Ok(PrivateKey::from_openssh(pem.as_slice())?);
    }
    let key = generate(KeyKind::Ed25519)?;
    write_private(&path, key.to_openssh(LineEnding::LF)?.as_bytes())?;
    Ok(key)
}

/// The directory of the keys of `role` in the development keystore `dir`.
fn role_dir(dir: &Path, role: KeyRole) -> std::path::PathBuf {
    dir.join(match role {
        KeyRole::Signing => "signing",
        KeyRole::Upstream => "upstream",
    })
}

/// Where the key `id` of `role` is in the development keystore `dir`.
pub fn key_path(dir: &Path, role: KeyRole, id: &KeyId) -> std::path::PathBuf {
    role_dir(dir, role).join(id.as_str())
}

/// The ids of the keys of `role` the development keystore holds (its file names that are
/// key ids; a certificate, a device key's public half or anything else left out).
pub fn held(dir: &Path, role: KeyRole) -> anyhow::Result<Vec<KeyId>> {
    let dir = role_dir(dir, role);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", dir.display())),
    };
    let mut ids = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("cannot read {}", dir.display()))?;
        if let Some(id) = entry
            .file_name()
            .to_str()
            .filter(|name| {
                !name.starts_with('.') && !name.ends_with(".asc") && !name.ends_with(".pub")
            })
            .and_then(|name| name.parse::<KeyId>().ok())
        {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// The declared key `id`, from `<dir>/signing/<id>` or `<dir>/upstream/<id>` (a `writ-key/1`
/// file, or an OpenSSH key), checked against its declaration; made there now, as declared,
/// when it is missing. Whether it was made is the second value.
pub fn key_or_make(
    dir: &Path,
    id: &KeyId,
    declared: &Declared,
    makers: &super::Makers,
) -> anyhow::Result<(StoredKey, bool)> {
    allowed()?;
    dev_key_or_make(dir, id, declared, makers)
}

/// [`key_or_make`], once the build is known to take the development keystore.
fn dev_key_or_make(
    dir: &Path,
    id: &KeyId,
    declared: &Declared,
    makers: &super::Makers,
) -> anyhow::Result<(StoredKey, bool)> {
    let dir = role_dir(dir, declared.role);
    private_dir(&dir)?;
    let path = dir.join(id.as_str());
    // A device's key keeps its public half beside it (its file holds what the device keeps).
    let public_path = dir.join(format!("{id}.pub"));
    if !path.exists() {
        let (key, meta) = makers.make(id, declared)?;
        if declared.backend.is_device() {
            write_private(
                &public_path,
                writ_crypto::keyfile::encode_public(&key.public_key(), meta)?.as_bytes(),
            )?;
        }
        write_private(&path, key.encode(meta)?.as_bytes())?;
        let made = StoredKey {
            id: id.clone(),
            key,
            meta,
        };
        return Ok((made, true));
    }
    // Twice the largest stored part, in hex, and its header.
    let text = writ_platform::fs::read_secret(&path, "the key", 1 << 18)?;
    let public = match public_path.exists() {
        true => {
            let line =
                writ_platform::fs::read_secret(&public_path, "the key's public half", 1 << 16)?;
            Some(writ_crypto::keyfile::decode_public(&line)?.0)
        }
        false => None,
    };
    let (key, meta) = match public {
        Some(public) => super::Material::decode(&text, public)?,
        None => {
            let (key, meta) = writ_crypto::keyfile::decode_secret(&text)
                .with_context(|| format!("{}: not a key", path.display()))?;
            (super::Material::Software(key), meta)
        }
    };
    crate::declared::check_key(id, declared, &key.public_key(), &meta)?;
    Ok((
        StoredKey {
            id: id.clone(),
            key,
            meta,
        },
        false,
    ))
}

/// Every declared key of `role`, each made on first start as declared.
fn dev_keys_of(
    dir: &Path,
    declared: &Declarations,
    role: KeyRole,
    makers: &super::Makers,
) -> anyhow::Result<Vec<StoredKey>> {
    of_role(declared, role)
        .map(|(id, key)| Ok(dev_key_or_make(dir, id, key, makers)?.0))
        .collect()
}

/// The tokens of `https://` repos, from `<dir>/tokens/<id>`: written by the operator (the
/// token alone, mode 0600), never generated. A missing or malformed one stops the daemon.
fn dev_tokens(dir: &Path, policy: &PolicyConfig) -> anyhow::Result<Tokens> {
    let ids = tokens_declared(policy);
    let dir = dir.join("tokens");
    private_dir(&dir)?;
    let source: Arc<dyn TokenSource> = Arc::new(DevTokens { dir: dir.clone() });
    ids.into_iter()
        .map(|id| {
            let path = dir.join(id.as_str());
            let missing = || {
                format!(
                    "upstream token {id} is declared: write it alone to {} (mode 0600)",
                    path.display()
                )
            };
            if !path.exists() {
                bail!("{}", missing());
            }
            let bytes = writ_platform::fs::read_secret(&path, "the upstream token", MAX_TOKEN_FILE)
                .with_context(missing)?;
            // Checked now (the operator wrote it by hand), read again at each use.
            UpstreamToken::from_bytes(&bytes)
                .map_err(|why| anyhow::anyhow!("{}: not a token: {why}", path.display()))?;
            let version = writ_core::authority::TextDigest::of_bytes(&bytes);
            Ok((
                id.clone(),
                Arc::new(TokenRef::new(
                    id.clone(),
                    version.as_str().to_owned(),
                    source.clone(),
                )),
            ))
        })
        .collect()
}

/// The development keystore's tokens, read from their files at each use.
struct DevTokens {
    dir: std::path::PathBuf,
}

impl TokenSource for DevTokens {
    fn unwrap(&self, id: &KeyId, version: &str) -> std::result::Result<UpstreamToken, String> {
        let path = self.dir.join(id.as_str());
        let bytes = writ_platform::fs::read_secret(&path, "the upstream token", MAX_TOKEN_FILE)
            .map_err(|e| format!("{e}"))?;
        if writ_core::authority::TextDigest::of_bytes(&bytes).as_str() != version {
            return Err(format!(
                "{}: changed since the daemon started: restart it to use the new token",
                path.display()
            ));
        }
        UpstreamToken::from_bytes(&bytes).map_err(|why| format!("not a token: {why}"))
    }
}

/// The development keystore's authority MAC key, `<dir>/authority-key` (32 bytes, 0600),
/// made on first start.
pub fn authority_key(dir: &Path) -> anyhow::Result<writ_crypto::authority::AuthorityKey> {
    allowed()?;
    dev_authority_key(dir)
}

/// [`authority_key`], once the build is known to take the development keystore.
fn dev_authority_key(dir: &Path) -> anyhow::Result<writ_crypto::authority::AuthorityKey> {
    // The first thing a fresh development keystore is asked for: its directory may not exist.
    private_dir(dir)?;
    let path = dir.join("authority-key");
    if !path.exists() {
        let key = writ_crypto::authority::AuthorityKey::generate()?;
        write_private(&path, key.as_bytes())?;
    }
    let bytes = writ_platform::fs::read_secret(&path, "the authority key", 64)?;
    Ok(writ_crypto::authority::AuthorityKey::from_bytes(&bytes)?)
}

/// The tokens of the notifiers that keep theirs sealed, from `<dir>/tokens/<id>` (the token
/// alone, mode 0600). A missing or malformed one stops the daemon, never naming the token.
pub fn bot_tokens(
    dir: &Path,
    ids: &std::collections::BTreeSet<KeyId>,
) -> anyhow::Result<std::collections::BTreeMap<KeyId, BotToken>> {
    allowed()?;
    ids.iter()
        .map(|id| {
            let path = dir.join("tokens").join(id.as_str());
            if !path.exists() {
                bail!(
                    "notifier token {id} is not in the keystore: write it alone to {} (mode 0600)",
                    path.display()
                );
            }
            Ok((id.clone(), BotToken::from_file(&path)?))
        })
        .collect()
}

/// Refuses unless this build takes the development keystore: an explicit build feature, and a
/// debug build. A release build, or one without the feature, refuses plaintext keys whatever
/// its profile says.
fn allowed() -> anyhow::Result<()> {
    if !(cfg!(feature = "dev-keystore") && cfg!(debug_assertions)) {
        bail!(
            "keystore.dev holds unencrypted keys for tests and development: only a debug build \
             with the dev-keystore feature takes it (use keystore.sealed)"
        );
    }
    Ok(())
}

/// The daemon's keys, from the development keystore in `dir`: every declared key, made on
/// first start.
pub fn keys(dir: &Path, declared: &Declarations, makers: &super::Makers) -> anyhow::Result<Keys> {
    allowed()?;
    private_dir(dir)?;
    Ok(Keys {
        ca: dev_ca(dir)?,
        signing: dev_keys_of(dir, declared, KeyRole::Signing, makers)?,
        upstream: dev_keys_of(dir, declared, KeyRole::Upstream, makers)?,
    })
}

/// The development keystore's host and TLS keys, and the CA's public half.
pub fn boot(dir: &Path) -> anyhow::Result<Boot> {
    allowed()?;
    private_dir(dir)?;
    Ok(Boot {
        host: dev_key(dir, "host")?,
        tls: dev_tls(dir)?,
        ca_public: dev_key(dir, "ca")?.public_key().clone(),
    })
}

/// The development keystore's CA key, in software.
fn dev_ca(dir: &Path) -> anyhow::Result<super::StoredKey> {
    let key = dev_key(dir, "ca")?;
    let meta = writ_crypto::keyfile::KeyMeta::SSH;
    Ok(super::StoredKey {
        id: super::sealed::CA_ID.parse()?,
        key: super::Material::Software(writ_crypto::keypair::KeyPair::from_ssh(key)?),
        meta,
    })
}

/// The `https://` repos' tokens, from the development keystore in `dir`.
pub fn tokens(dir: &Path, policy: &PolicyConfig) -> anyhow::Result<Tokens> {
    // `keys` refused a build without the dev keystore already; checked again, never assumed.
    allowed()?;
    dev_tokens(dir, policy)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    const PIN: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    /// Two signing keys (one used, one not), an RSA upstream key, a token.
    fn policy() -> PolicyConfig {
        PolicyConfig::from_yaml(&format!(
            "format: 2\nkeys:
  agent-01: {{ use: signing, format: ssh, algorithm: ed25519 }}
  agent-unused: {{ use: signing, format: openpgp, algorithm: p256 }}
  key-01: {{ use: upstream, kind: ssh, algorithm: rsa3072 }}
  token-01: {{ use: upstream, kind: token, host: example.org }}
upstream_hosts:
  example.org: [\"{PIN}\"]
repos:
  plain:
    upstream: ssh://git@example.org/u/plain.git
    upstream_credential: key-01
    templates: []
  web:
    upstream: https://example.org/u/web.git
    upstream_credential: token-01
    templates: []
  web2:
    upstream: https://x-token-auth@example.org/u/web2.git
    upstream_credential: token-01
    templates: []
templates: {{}}
"
        ))
        .unwrap()
    }

    #[test]
    fn every_declared_key_is_made_once_as_declared_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let declared = crate::declared::declarations(&policy()).unwrap();
        // The build's dev-keystore gate aside (`keys` checks it first): what it reads.
        let makers = super::super::Makers::default();
        let makers = &makers;
        let keys = |dir: &Path, declared: &Declarations| -> anyhow::Result<Keys> {
            Ok(Keys {
                ca: dev_ca(dir)?,
                signing: dev_keys_of(dir, declared, KeyRole::Signing, makers)?,
                upstream: dev_keys_of(dir, declared, KeyRole::Upstream, makers)?,
            })
        };
        let first = keys(dir.path(), &declared).unwrap();
        let ids = |keys: &[StoredKey]| keys.iter().map(|k| k.id.to_string()).collect::<Vec<_>>();
        // Every key the policy declares, a template naming it or not; never a token.
        assert_eq!(ids(&first.signing), ["agent-01", "agent-unused"]);
        assert_eq!(ids(&first.upstream), ["key-01"]);
        assert_eq!(
            writ_crypto::algorithm::KeyAlgorithm::of_public(
                first.upstream[0].key.public_key().key_data()
            ),
            Some(writ_crypto::algorithm::KeyAlgorithm::Rsa3072),
            "an upstream key of the declared algorithm"
        );
        assert!(first.signing[1].meta.created.is_some(), "an OpenPGP key");
        assert!(!dir.path().join("upstream/token-01").exists());
        let again = keys(dir.path(), &declared).unwrap();
        assert_eq!(
            again.upstream[0].key.public_key(),
            first.upstream[0].key.public_key(),
            "kept"
        );
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.path().join("signing/agent-01")), 0o600);
        assert_eq!(mode(&dir.path().join("upstream")), 0o700);
        // Declared otherwise than the keystore holds it: refused, by name.
        let other = PolicyConfig::from_yaml(
            &policy()
                .to_yaml()
                .replace("algorithm: rsa3072", "algorithm: rsa4096"),
        )
        .unwrap();
        let error = format!(
            "{:#}",
            keys(dir.path(), &crate::declared::declarations(&other).unwrap())
                .err()
                .unwrap()
        );
        assert!(
            error.starts_with(
                "upstream credential key-01: declared rsa4096 but the keystore holds a rsa3072 key"
            ),
            "{error}"
        );
    }

    #[test]
    fn a_declared_token_is_the_operator_s_never_made() {
        let dir = tempfile::tempdir().unwrap();
        let policy = policy();
        // Missing: the daemon stops, saying where the token goes.
        let error = format!("{:#}", dev_tokens(dir.path(), &policy).unwrap_err());
        assert!(error.contains("token-01"), "{error}");
        assert!(error.contains("tokens/token-01 (mode 0600)"), "{error}");
        let path = dir.path().join("tokens/token-01");
        let token = "writ-test-token-0123456789abcdefghij";
        // Readable by others: refused (read_secret), the token never in the error.
        std::fs::write(&path, format!("{token}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = format!("{:#}", dev_tokens(dir.path(), &policy).unwrap_err());
        assert!(!error.contains(token), "{error}");
        assert!(
            error.contains("0600") || error.contains("readable"),
            "{error}"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let tokens = dev_tokens(dir.path(), &policy).unwrap();
        assert_eq!(tokens.len(), 1, "one id, two repos");
        let held = tokens.values().next().unwrap();
        assert!(
            !format!("{held:?}").contains(token),
            "a reference holds no secret"
        );
        // Read again at each use; a file changed since the start is refused until a restart.
        assert_eq!(
            format!("{:?}", held.unwrap().unwrap()),
            "UpstreamToken(<redacted>)"
        );
        std::fs::write(&path, "another-token\n").unwrap();
        let why = held.unwrap().unwrap_err();
        assert!(
            why.ends_with("changed since the daemon started: restart it to use the new token"),
            "{why}"
        );
        std::fs::write(&path, format!("{token}\n")).unwrap();
        assert!(held.unwrap().is_ok());
        // Malformed: refused, the token never in the error.
        std::fs::write(&path, format!("{token} and more\n")).unwrap();
        let error = format!("{:#}", dev_tokens(dir.path(), &policy).unwrap_err());
        assert!(
            error.ends_with("not a token: not printable ASCII without spaces"),
            "{error}"
        );
        assert!(!error.contains(token), "{error}");
    }

    #[test]
    fn a_fresh_keystore_makes_its_authority_key_first_and_keeps_it() {
        let root = tempfile::tempdir().unwrap();
        // Nothing yet: `writd run`'s first start asks for the authority key before any other.
        let dir = root.path().join("data/keys");
        let first = dev_authority_key(&dir).unwrap();
        assert_eq!(
            dev_authority_key(&dir).unwrap().as_bytes(),
            first.as_bytes(),
            "kept"
        );
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("authority-key")), 0o600);
    }

    #[test]
    fn a_tls_pair_cut_short_by_a_crash_is_made_again() {
        let dir = tempfile::tempdir().unwrap();
        let pin = |dir: &Path| {
            writ_crypto::tls::fingerprint_pem(&dev_tls(dir).unwrap().cert_pem).unwrap()
        };
        let first = pin(dir.path());
        assert_eq!(pin(dir.path()), first, "kept");
        // The key written, the cert not: a crash between the two writes.
        std::fs::remove_file(dir.path().join("tls-01.crt")).unwrap();
        let second = pin(dir.path());
        assert_ne!(second, first);
        // The cert alone.
        std::fs::remove_file(dir.path().join("tls-01")).unwrap();
        assert_ne!(pin(dir.path()), second);
        let mode = std::fs::metadata(dir.path().join("tls-01"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
