//! `writd init <writd.yaml>`: makes the sealed keystore, once. Run on the daemon host as the
//! daemon's user; asks for the passphrase twice (one line of stdin when it isn't a terminal).
//!
//! It makes the keystore's identity (wrapped with the passphrase), the boot tier (the host
//! key, the TLS key and its certificate), the CA key, and every agent signing key and `ssh://`
//! upstream credential the policy names, each its own age file to the identity's recipient;
//! then prints what the operator pins and registers. It refuses a keystore already there, and
//! leaves nothing behind when it fails.

use std::path::Path;

use anyhow::{Context, bail};
use writ_core::config::PolicyConfig;
use writ_core::names::KeyId;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{LineEnding, PrivateKey};
use writ_platform::{DataKey, Passphrase};

use super::sealed::{Layout, seal, write_public};
use super::{PublicKeys, make_tls, private_dir, signing_ids, upstream_credentials, write_private};
use crate::config::{Config, KeystoreConfig, SealedConfig};

/// Wraps the identity with the passphrase: the platform's choice (`platform::enroll`), or a
/// cheap work factor in tests.
pub type Enroll<'a> = &'a dyn Fn(&SealedConfig, &Passphrase, &DataKey) -> anyhow::Result<()>;

pub fn init(path: &Path) -> anyhow::Result<()> {
    let config = Config::load(path)?;
    let KeystoreConfig::Sealed(sealed) = &config.keystore else {
        bail!(
            "{}: `writd init` makes a sealed keystore: set keystore.sealed (dir, boot)",
            path.display()
        );
    };
    // The three files, read and checked before anything is made: they become the versions
    // in force.
    let texts = crate::authority::read_files(&config)?;
    let policy = crate::authority::parse_policy(
        texts
            .get(&writ_core::authority::AdminTarget::Policy)
            .map(String::as_str)
            .unwrap_or_default(),
        config.min_ttl,
    )
    .with_context(|| config.policy.display().to_string())?;
    crate::authority::check(&texts, config.min_ttl)?;
    refuse_existing(sealed)?;
    let db = config.state_dir.join("leases.db");
    if db.exists()
        && writ_store::Store::open(&db)?
            .authority_in_force()?
            .is_some()
    {
        bail!(
            "{}: the state already holds authority files in force (another keystore's): a new \
             keystore takes a new state_dir",
            config.state_dir.display()
        );
    }
    let typed = writ_crypto::passphrase::read(
        "Keystore passphrase (it opens every secret: keep it in a password manager): ",
        Some("The same passphrase again: "),
        true,
    )?;
    let passphrase = Passphrase::new(typed.as_str().to_owned());
    drop(typed);
    // Nothing is written before here.
    crate::keystore::private_dir(&config.state_dir)?;
    let store = writ_store::Store::open(&db)?;
    let made = make(sealed, &policy, &passphrase, &crate::platform::enroll)?;
    crate::authority::seed(
        &store,
        &made.authority,
        texts,
        crate::now()?,
        config.min_ttl,
    )?;
    print(sealed, &policy, &made);
    Ok(())
}

/// What `writd init` made, to print.
pub struct Made {
    /// The authority MAC's key, to record the files' first versions with.
    pub authority: writ_crypto::authority::AuthorityKey,
    pub recipient: String,
    pub keys: PublicKeys,
}

/// Refuses unless both directories are missing or empty: a keystore is never made over
/// another, nor beside files someone else put there.
fn refuse_existing(sealed: &SealedConfig) -> anyhow::Result<()> {
    for (dir, what) in [
        (&sealed.dir, "keystore.sealed.dir"),
        (&sealed.boot, "keystore.sealed.boot"),
    ] {
        match std::fs::read_dir(dir) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    bail!(
                        "{what} {} is not empty: a keystore is made once, into empty directories",
                        dir.display()
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", dir.display())),
        }
    }
    Ok(())
}

/// Empties the keystore's directories if `writd init` fails part way (they were empty when it
/// began): a half-made keystore would be refused by the next `writd init`.
struct Undo<'a> {
    dirs: [&'a Path; 2],
    done: bool,
}

impl Drop for Undo<'_> {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        for dir in self.dirs {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let _ = if path.is_dir() {
                    std::fs::remove_dir_all(&path)
                } else {
                    std::fs::remove_file(&path)
                };
            }
        }
    }
}

/// Makes the keystore in `sealed`'s directories, which must be missing or empty.
pub fn make(
    sealed: &SealedConfig,
    policy: &PolicyConfig,
    passphrase: &Passphrase,
    enroll: Enroll<'_>,
) -> anyhow::Result<Made> {
    refuse_existing(sealed)?;
    // Before any file: a policy naming one id as a key and a token is refused here.
    let (upstream_ids, _tokens) = upstream_credentials(policy)?;
    private_dir(&sealed.dir)?;
    private_dir(&sealed.boot)?;
    let mut undo = Undo {
        dirs: [&sealed.dir, &sealed.boot],
        done: false,
    };
    let layout = Layout(sealed);

    let data_key = DataKey::generate()?;
    let recipient = data_key.recipient()?;
    enroll(sealed, passphrase, &data_key)?;
    drop(data_key);
    let recipient_text = recipient.to_string();
    write_public(&layout.recipient(), &format!("{recipient_text}\n"))?;
    let to: [&dyn age::Recipient; 1] = [&recipient];

    // The boot tier: read at a sealed start.
    let host = generate(KeyKind::Ed25519)?;
    write_private(&layout.host(), host.to_openssh(LineEnding::LF)?.as_bytes())?;
    let cert_pem = make_tls(&layout.tls_key(), &layout.tls_cert(), &|path, pem| {
        write_public(path, pem)
    })?;
    let tls_fingerprint = writ_crypto::tls::fingerprint_pem(&cert_pem)?;

    // Sealed: each its own age file, its public half beside it.
    let sealed_key = |secret: &Path, public: &Path| -> anyhow::Result<PrivateKey> {
        let key = generate(KeyKind::Ed25519)?;
        seal(secret, key.to_openssh(LineEnding::LF)?.as_bytes(), &to)?;
        write_public(public, &format!("{}\n", key.public_key().to_openssh()?))?;
        Ok(key)
    };
    sealed_key(&layout.ca(), &layout.ca_public())?;
    let authority = writ_crypto::authority::AuthorityKey::generate()?;
    seal(&layout.authority(), authority.as_bytes(), &to)?;
    private_dir(&layout.signing_dir())?;
    private_dir(&layout.upstream_dir())?;
    let keys = |ids: std::collections::BTreeSet<&KeyId>,
                secret: &dyn Fn(&KeyId) -> std::path::PathBuf,
                public: &dyn Fn(&KeyId) -> std::path::PathBuf|
     -> anyhow::Result<Vec<_>> {
        ids.into_iter()
            .map(|id| {
                let key = sealed_key(&secret(id), &public(id))?;
                Ok((id.clone(), key.public_key().clone()))
            })
            .collect()
    };
    let signing = keys(signing_ids(policy), &|id| layout.signing(id), &|id| {
        layout.signing_public(id)
    })?;
    let upstream = keys(upstream_ids, &|id| layout.upstream(id), &|id| {
        layout.upstream_public(id)
    })?;
    undo.done = true;
    Ok(Made {
        authority,
        recipient: recipient_text,
        keys: PublicKeys {
            host: host.public_key().clone(),
            tls_fingerprint,
            signing,
            upstream,
        },
    })
}

/// What the operator pins and registers, as `writd host-key`, `tls-fingerprint`,
/// `upstream-keys` and `signing-keys` print it later.
fn print(sealed: &SealedConfig, policy: &PolicyConfig, made: &Made) {
    let openssh = |key: &writ_crypto::ssh_key::PublicKey| key.to_openssh().unwrap_or_default();
    println!(
        "keystore made: {} (boot tier: {})",
        sealed.dir.display(),
        sealed.boot.display()
    );
    println!("recipient: {}", made.recipient);
    println!("host key: {}", openssh(&made.keys.host));
    println!("TLS fingerprint: {}", made.keys.tls_fingerprint);
    for (id, key) in &made.keys.upstream {
        println!(
            "upstream key {id}: {} (repos: {})",
            openssh(key),
            crate::repos_using(policy, id).join(", ")
        );
    }
    for (id, key) in &made.keys.signing {
        println!(
            "signing key {id}: {} (templates: {})",
            openssh(key),
            crate::templates_using(policy, id).join(", ")
        );
    }
}
