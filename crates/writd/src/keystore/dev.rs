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
use writ_mirror::credential::{MAX_TOKEN_FILE, UpstreamToken};
use writ_platform::notify::telegram::BotToken;

use super::{Boot, Keys, TlsKeyPair, make_tls, private_dir, upstream_credentials, write_private};

/// The TLS key and certificate of the dev keystore, made on first start.
fn dev_tls(dir: &Path) -> anyhow::Result<TlsKeyPair> {
    let (cert_path, key_path) = (dir.join("tls-01.crt"), dir.join("tls-01"));
    // The key is written first: a cert without its key (or a key alone, after a crash
    // between the two writes) is a pair to make again.
    if !(cert_path.exists() && key_path.exists()) {
        for leftover in [&cert_path, &key_path] {
            match std::fs::remove_file(leftover) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(e).with_context(|| format!("cannot remove {}", leftover.display()));
                }
                _ => {}
            }
        }
        make_tls(&key_path, &cert_path, &|path, pem| {
            std::fs::write(path, pem).with_context(|| format!("cannot write {}", path.display()))
        })?;
    }
    let cert_pem = std::fs::read_to_string(&cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?;
    Ok(TlsKeyPair {
        key: dev_key(dir, "tls-01")?,
        cert_pem,
    })
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

/// The signing keys every template names, from `<dir>/signing/<id>`, each generated on first
/// start (a key id is a plain name, never a path).
fn dev_signing_keys(dir: &Path, policy: &PolicyConfig) -> anyhow::Result<Vec<(KeyId, PrivateKey)>> {
    let ids = policy
        .templates()
        .values()
        .filter_map(|t| t.signing_key.as_ref());
    dev_keys(&dir.join("signing"), ids)
}

/// The credentials of `ssh://` repos, from `<dir>/upstream/<id>`, each generated on first
/// start; `writd upstream-keys` prints their public keys, to add on each remote.
fn dev_upstream_keys(
    dir: &Path,
    policy: &PolicyConfig,
) -> anyhow::Result<Vec<(KeyId, PrivateKey)>> {
    let (keys, _) = upstream_credentials(policy)?;
    dev_keys(&dir.join("upstream"), keys.into_iter())
}

/// The tokens of `https://` repos, from `<dir>/tokens/<id>`: written by the operator (the
/// token alone, mode 0600), never generated. A missing or malformed one stops the daemon.
fn dev_tokens(
    dir: &Path,
    policy: &PolicyConfig,
) -> anyhow::Result<std::collections::BTreeMap<KeyId, Arc<UpstreamToken>>> {
    let (_, ids) = upstream_credentials(policy)?;
    let dir = dir.join("tokens");
    private_dir(&dir)?;
    ids.into_iter()
        .map(|id| {
            let path = dir.join(id.as_str());
            let missing = || {
                format!(
                    "upstream credential {id} (an https:// repo's) is a token: write it alone to \
                     {} (mode 0600)",
                    path.display()
                )
            };
            if !path.exists() {
                bail!("{}", missing());
            }
            let bytes = writ_platform::fs::read_secret(&path, "the upstream token", MAX_TOKEN_FILE)
                .with_context(missing)?;
            let token = UpstreamToken::from_bytes(&bytes)
                .map_err(|why| anyhow::anyhow!("{}: not a token: {why}", path.display()))?;
            Ok((id.clone(), Arc::new(token)))
        })
        .collect()
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

/// One key per distinct id, in the private directory `dir`.
fn dev_keys<'a>(
    dir: &Path,
    ids: impl Iterator<Item = &'a KeyId>,
) -> anyhow::Result<Vec<(KeyId, PrivateKey)>> {
    let ids: std::collections::BTreeSet<&KeyId> = ids.collect();
    private_dir(dir)?;
    ids.into_iter()
        .map(|id| Ok((id.clone(), dev_key(dir, id.as_str())?)))
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

/// The daemon's keys, from the development keystore in `dir`.
pub fn keys(dir: &Path, policy: &PolicyConfig) -> anyhow::Result<Keys> {
    allowed()?;
    private_dir(dir)?;
    Ok(Keys {
        ca: dev_key(dir, "ca")?,
        signing: dev_signing_keys(dir, policy)?,
        upstream: dev_upstream_keys(dir, policy)?,
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

/// The `https://` repos' tokens, from the development keystore in `dir`.
pub fn tokens(
    dir: &Path,
    policy: &PolicyConfig,
) -> anyhow::Result<std::collections::BTreeMap<KeyId, Arc<UpstreamToken>>> {
    // `keys` refused a build without the dev keystore already; checked again, never assumed.
    allowed()?;
    dev_tokens(dir, policy)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn one_signing_key_per_template_key_id_kept_across_starts() {
        let dir = tempfile::tempdir().unwrap();
        let policy = PolicyConfig::from_yaml(include_str!(
            "../../../writ-core/tests/fixtures/policy.yaml"
        ))
        .unwrap();
        // Two templates name agent-ed25519-01, one names none: one key.
        let first = dev_signing_keys(dir.path(), &policy).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0.as_str(), "agent-ed25519-01");
        let again = dev_signing_keys(dir.path(), &policy).unwrap();
        assert_eq!(again[0].1.public_key(), first[0].1.public_key(), "kept");
        let path = dir.path().join("signing/agent-ed25519-01");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = std::fs::metadata(dir.path().join("signing"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
    }

    const HTTPS_POLICY: &str = "\
repos:
  plain:
    upstream: ssh://git@example.org/u/plain.git
    upstream_credential: key-01
  web:
    upstream: https://example.org/u/web.git
    upstream_credential: token-01
  web2:
    upstream: https://x-token-auth@example.com/u/web2.git
    upstream_credential: token-01
templates: {}
";

    #[test]
    fn https_repos_take_the_operator_s_token_and_ssh_repos_a_generated_key() {
        let dir = tempfile::tempdir().unwrap();
        let policy = PolicyConfig::from_yaml(HTTPS_POLICY).unwrap();
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
        assert_eq!(
            format!("{:?}", tokens.values().next().unwrap()),
            "UpstreamToken(<redacted>)"
        );
        // Malformed: refused, the token never in the error.
        std::fs::write(&path, format!("{token} and more\n")).unwrap();
        let error = format!("{:#}", dev_tokens(dir.path(), &policy).unwrap_err());
        assert!(
            error.ends_with("not a token: not printable ASCII without spaces"),
            "{error}"
        );
        assert!(!error.contains(token), "{error}");
        // Only the ssh repo's credential gets a key.
        let keys = dev_upstream_keys(dir.path(), &policy).unwrap();
        let ids: Vec<&str> = keys.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["key-01"]);
        assert!(!dir.path().join("upstream/token-01").exists());
    }

    #[test]
    fn one_credential_id_for_a_key_and_a_token_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let both = HTTPS_POLICY.replace(
            "upstream_credential: key-01",
            "upstream_credential: token-01",
        );
        let policy = PolicyConfig::from_yaml(&both).unwrap();
        for error in [
            format!("{:#}", dev_tokens(dir.path(), &policy).unwrap_err()),
            format!("{:#}", dev_upstream_keys(dir.path(), &policy).unwrap_err()),
        ] {
            assert_eq!(
                error,
                "upstream credential token-01 is named by an ssh:// repo (a key) and an https:// \
                 repo (a token): give each its own id"
            );
        }
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
