//! `writd init <writd.yaml>`: makes the sealed keystore, once. Run on the daemon host as the
//! daemon's user; asks for the passphrase twice (one line of stdin when it isn't a terminal).
//!
//! It makes the keystore's identity (wrapped with the passphrase), the boot tier (the host
//! key, the TLS key and its certificate), the CA key, and every key the policy declares (its
//! signing keys and `ssh` upstream credentials, as `keys.<id>` describes each), each its own
//! age file to the identity's recipient;
//! then prints what the operator pins and registers. It refuses a keystore already there, and
//! leaves nothing behind when it fails.

use std::path::Path;

use anyhow::{Context, bail};
use writ_core::config::PolicyConfig;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{LineEnding, PrivateKey};
use writ_platform::{DataKey, Passphrase};

use super::sealed::{Layout, seal, write_public};
use writ_proto::KeyRole;

use super::{PublicKeys, of_role, private_dir, write_private};
use crate::config::{Config, KeystoreConfig, SealedConfig};
use crate::declared::Declarations;

/// Wraps the identity with the passphrase: the platform's choice (`platform::enroll`), or a
/// cheap work factor in tests.
pub type Enroll<'a> = &'a dyn Fn(&SealedConfig, &Passphrase, &DataKey) -> anyhow::Result<()>;

pub fn init(path: &Path, tls_backend: &str, ca_backend: &str) -> anyhow::Result<()> {
    let config = Config::load(path)?;
    // The backends the HTTPS approval API's key and the SSH CA's key are made on (the Secure
    // Enclave on a Mac, from the installer): ones this daemon has, checked before anything is
    // asked.
    let backend = |flag: &str, name: &str| {
        crate::platform::BACKENDS
            .iter()
            .copied()
            .find(|b| b.name() == name)
            .ok_or_else(|| {
                let names: Vec<&str> = crate::platform::BACKENDS.iter().map(|b| b.name()).collect();
                anyhow::anyhow!(
                    "{flag} {name}: this daemon has no such backend (it has: {})",
                    names.join(", ")
                )
            })
    };
    let tls_backend = backend("--tls-backend", tls_backend)?;
    let ca_backend = backend("--ca-backend", ca_backend)?;
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
    let declared = crate::declared::declarations(&policy)
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
    // A keystore whose identity is wrapped to hardware (M7.6, a hardware recipient in the
    // policy) has no passphrase: none is asked.
    let passphrase = match policy.hardware_keystore() {
        true => None,
        false => {
            let typed = writ_crypto::passphrase::read(
                "Keystore passphrase (it opens every secret: keep it in a password manager): ",
                Some("The same passphrase again: "),
                true,
            )?;
            let passphrase = Passphrase::new(typed.as_str().to_owned());
            drop(typed);
            Some(passphrase)
        }
    };
    // Nothing is written before here.
    crate::keystore::private_dir(&config.state_dir)?;
    let store = writ_store::Store::open(&db)?;
    // A device backend a key or the TLS key lives on answers before anything is made.
    crate::platform::check_devices(&config, &declared)?;
    let makers = crate::platform::makers(&config)?;
    for device in [tls_backend, ca_backend]
        .into_iter()
        .filter(|b| b.is_device())
    {
        makers.device(device)?;
    }
    let made = make(
        sealed,
        &declared,
        &policy,
        passphrase.as_ref(),
        &crate::platform::enroll,
        tls_backend,
        &makers,
    )?;
    if ca_backend.is_device() {
        super::sealed::make_ca(sealed, &made.data_key, ca_backend, &makers)?;
    }
    let mut undo = Undo {
        dirs: [&sealed.dir, &sealed.boot],
        done: false,
    };
    // The recipients (M7.6): each hardware one made in its device, then the identity wrapped
    // to them and to the recovery recipient.
    let recipients = super::recipients::make_missing(&config, sealed, &policy)?;
    let hardware = super::recipients::load(&config, sealed)?;
    super::recipients::reconcile(sealed, &policy, &hardware, &made.data_key, &[])?;
    // The keystore and the state are made together or not at all: a state that can't take
    // the files' first versions leaves the directories empty again, so `writd init` can run
    // once more (the review after M5.5, L7: they stayed full, and every later init refused).
    crate::authority::seed(
        &store,
        &made.authority,
        texts,
        crate::now()?,
        config.min_ttl,
    )?;
    undo.done = true;
    print(sealed, &policy, &made);
    for (name, recipient) in &recipients {
        println!("hardware recipient {name}: {recipient} (no passphrase: the device unseals)");
    }
    if let Some((name, _)) = policy.recovery_recipient() {
        println!(
            "recovery recipient {name}: the keystore opens with it too (writ recovery check \
             proves you hold it)"
        );
    }
    Ok(())
}

/// What `writd init` made, to print.
pub struct Made {
    /// The authority MAC's key, to record the files' first versions with.
    pub authority: writ_crypto::authority::AuthorityKey,
    pub recipient: String,
    pub keys: PublicKeys,
    /// The keystore's data key (wiped on drop): its identity wrapped to the recipients next.
    pub data_key: DataKey,
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
    declared: &Declarations,
    policy: &PolicyConfig,
    passphrase: Option<&Passphrase>,
    enroll: Enroll<'_>,
    tls_backend: crate::declared::Backend,
    makers: &super::Makers,
) -> anyhow::Result<Made> {
    refuse_existing(sealed)?;
    private_dir(&sealed.dir)?;
    private_dir(&sealed.boot)?;
    let mut undo = Undo {
        dirs: [&sealed.dir, &sealed.boot],
        done: false,
    };
    let layout = Layout(sealed);

    let data_key = DataKey::generate()?;
    let recipient = data_key.recipient()?;
    // No passphrase: a hardware keystore, its identity wrapped to its recipients next.
    if let Some(passphrase) = passphrase {
        enroll(sealed, passphrase, &data_key)?;
    }
    let recipient_text = recipient.to_string();
    write_public(&layout.recipient(), &format!("{recipient_text}\n"))?;
    let to: [&dyn age::Recipient; 1] = [&recipient];

    // The boot tier: read at a sealed start.
    let host = generate(KeyKind::Ed25519)?;
    write_private(&layout.host(), host.to_openssh(LineEnding::LF)?.as_bytes())?;
    let tls = super::sealed::tls_files(sealed);
    tls.make(tls_backend, makers)?;
    let cert_pem = writ_platform::fs::read_authority(&tls.cert, "the TLS certificate")?;
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
    let mut signing = Vec::new();
    for (id, key) in of_role(declared, KeyRole::Signing) {
        let made = super::sealed::make_key(&layout, &recipient, id, key, makers)?;
        // An OpenPGP key's certificate, with the user ids the policy gives it.
        if let Some(certificate) =
            crate::declared::certificate(&made, key, policy.uids(id), makers)?
        {
            write_public(
                &layout.signing_dir().join(format!("{id}.asc")),
                &certificate,
            )?;
        }
        signing.push((made.id, made.key.public_key(), made.meta));
    }
    let mut upstream = Vec::new();
    for (id, key) in of_role(declared, KeyRole::Upstream) {
        let made = super::sealed::make_key(&layout, &recipient, id, key, makers)?;
        upstream.push((made.id, made.key.public_key()));
    }
    undo.done = true;
    Ok(Made {
        authority,
        data_key,
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
            crate::joined(&policy.key_users(id).repos)
        );
    }
    for (id, key, meta) in &made.keys.signing {
        let described = crate::declared::describe(id, key, meta).unwrap_or_default();
        println!(
            "signing key {}: {} (templates: {})",
            id,
            described
                .strip_prefix(&format!("{id} "))
                .unwrap_or(&described),
            crate::joined(&policy.key_users(id).templates)
        );
    }
}
