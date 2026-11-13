//! `writd recover <writd.yaml> <policy|approvers|readers> <file>`: puts a file in force from
//! the daemon host, when no admin change can (every approver or reader key lost), or to apply
//! a file edited there. Run as the daemon's user, with the daemon stopped (refused while
//! `writd run` holds the state's lock, [`crate::lock`]). It needs the
//! keystore's passphrase: with the host, that opens every secret already, so recovery gives
//! nobody anything new. The file is checked like an admin change (with the two others in
//! force), recorded as a new version under the keystore's MAC, logged (`admin`, no approver),
//! and written to the file `writd.yaml` names. A policy's keys the keystore lacks are made
//! first, as an admin change would make them (each logged, its public half printed).

use std::path::Path;

use std::io::Read as _;

use anyhow::{Context, bail};
use writ_core::authority::AdminTarget;
use writ_store::{AuditEvent, AuditLog, EventKind, Outcome, Store};

use crate::config::{Config, KeystoreConfig};

pub fn recover(path: &Path, target: &str, file: &Path) -> anyhow::Result<()> {
    let config = Config::load(path)?;
    let target: AdminTarget = target.parse()?;
    let text = writ_platform::fs::read_authority(file, &format!("{target} file"))?;
    let db = config.state_dir.join("leases.db");
    if !db.exists() {
        bail!(
            "{}: no state: `writd init` makes it",
            config.state_dir.display()
        );
    }
    // Before the passphrase is asked: refused while the daemon runs.
    let _lock = crate::lock::hold(&config.state_dir, crate::lock::Holder::Recovery)?;
    // The data key: from the passphrase, or the offline recovery key (M7.6). Never from the
    // hardware alone: host access must not replace a signed change.
    let (key, data_key, how) = match &config.keystore {
        KeystoreConfig::Sealed(sealed) => {
            let typed = writ_crypto::passphrase::read(
                "Keystore passphrase, or the recovery key: ",
                None,
                false,
            )?;
            let (data_key, how, recovery) = recovery_or_passphrase(sealed, typed.as_str())?;
            drop(typed);
            (
                crate::keystore::sealed_authority_key(sealed, data_key.way()?)?,
                Some((data_key, recovery)),
                how,
            )
        }
        KeystoreConfig::Dev(dir) => (
            crate::keystore::dev_authority_key(dir)?,
            None,
            "the development keystore",
        ),
    };
    // A policy: its keys checked against their backends, and those the keystore lacks made,
    // before the version is recorded (a version naming keys the keystore lacks would never
    // start).
    let made = match target {
        AdminTarget::Policy => {
            let policy = crate::authority::parse_policy(&text, config.min_ttl)
                .with_context(|| file.display().to_string())?;
            let declared = crate::declared::declarations(&policy)
                .with_context(|| file.display().to_string())?;
            crate::keystore::make_missing(
                &config,
                &declared,
                &crate::platform::makers(&config)?,
                data_key.as_ref().map(|(key, _)| key),
            )?
        }
        AdminTarget::Approvers | AdminTarget::Readers => Vec::new(),
    };
    // A policy's recipients (M7.6): the hardware ones it declares made in their device, every
    // file wrapped to them, and a passphrase set when no hardware one is left.
    if let (AdminTarget::Policy, KeystoreConfig::Sealed(sealed), Some((data_key, recovery))) =
        (target, &config.keystore, &data_key)
    {
        let policy = crate::authority::parse_policy(&text, config.min_ttl)?;
        recipients(&config, sealed, &policy, data_key, recovery.as_ref())?;
    }
    let store = Store::open(&db)?;
    let (old, version, digest) = crate::authority::recover(
        &store,
        &key,
        target,
        text.clone(),
        crate::now()?,
        config.min_ttl,
        |others| trust_others(target, others),
    )?;
    let mut audit = AuditLog::open(&config.state_dir.join("audit.jsonl"))?;
    for (id, role, public, _) in &made {
        audit
            .append(
                &AuditEvent::new(crate::now()?, EventKind::Key, Outcome::Allowed)
                    .key(id)
                    .reason(format!(
                        "{} made by writd recover: {}",
                        role.as_str(),
                        public.to_openssh()?
                    )),
            )
            .context("the audit log can't be written: the key is made all the same")?;
        println!(
            "New {} {id} (register it on the remote): {}",
            role.as_str(),
            public.to_openssh()?
        );
    }
    audit
        .append(
            &AuditEvent::new(crate::now()?, EventKind::Admin, Outcome::Allowed).reason(format!(
                "{target}: version {version} (sha256 {digest}) replaces version {old}, recovered \
                 on the host with {how}"
            )),
        )
        .context("the audit log can't be written: the version is in force all the same")?;
    let path = crate::authority::path(&config, target);
    crate::authority::write_back(path, &text)?;
    println!("{target}: version {version} in force (recovered on the host). Start the daemon.");
    Ok(())
}

/// What opened the keystore: its data key, how (for the audit line), and the recovery key's
/// way when it was the recovery key (it opens what a hardware keystore wrapped to it).
type Opened = (
    writ_platform::DataKey,
    &'static str,
    Option<writ_platform::unlock::x25519::X25519Unwrap>,
);

/// The data key from what was typed: an age secret key opens the recovery file
/// (`identity.recovery.age`); anything else is the passphrase, on a keystore that has one.
fn recovery_or_passphrase(
    sealed: &crate::config::SealedConfig,
    typed: &str,
) -> anyhow::Result<Opened> {
    use writ_platform::unlock::x25519::X25519Unwrap;
    if let Ok(identity) = typed.trim().parse::<age::x25519::Identity>() {
        let paths = crate::keystore::recipients::Paths(sealed);
        if !paths.recovery_identity().exists() {
            bail!("this keystore has no recovery recipient: give its passphrase");
        }
        let way = X25519Unwrap::new("recovery", identity);
        let key = writ_platform::unlock::data_key(&paths.recovery_identity(), &[&way])
            .map_err(|e| anyhow::anyhow!("the recovery key doesn't open this keystore: {e}"))?;
        return Ok((key, "the recovery key", Some(way)));
    }
    if crate::keystore::hardware_wrapped(sealed)? {
        bail!("this keystore has no passphrase (its hardware opens it): give the recovery key");
    }
    let passphrase = writ_platform::Passphrase::new(typed.to_owned());
    let key = crate::platform::data_key(
        sealed,
        &writ_platform::UnsealRequest::with_passphrase(passphrase),
    )?;
    Ok((key, "the keystore's passphrase", None))
}

/// The keystore brought in line with `policy`'s recipients from the host (M7.6): its hardware
/// ones made in their device and loaded, every file rewrapped (the recovery key and the
/// identity open what is wrapped to the hardware), then, with no hardware recipient left on a
/// keystore the hardware opened, a new passphrase asked twice and the identity wrapped to it.
fn recipients(
    config: &Config,
    sealed: &crate::config::SealedConfig,
    policy: &writ_core::config::PolicyConfig,
    key: &writ_platform::DataKey,
    recovery: Option<&writ_platform::unlock::x25519::X25519Unwrap>,
) -> anyhow::Result<()> {
    for (name, recipient) in crate::keystore::recipients::make_missing(config, sealed, policy)? {
        println!("hardware recipient {name}: {recipient}");
    }
    // A recipient its device no longer opens (the device lost) is dropped, if the recovered
    // policy no longer declares it; one it declares is refused.
    let (hardware, refused) = crate::keystore::recipients::load_each(config, sealed)?;
    for (name, why) in &refused {
        if policy.recipients().contains_key(name) {
            bail!("recipient {name}: {why:#}: take it out of the policy to recover without it");
        }
        println!("recipient {name}: its device doesn't open it ({why:#}): dropped");
    }
    let identity = key.way()?;
    let mut ways: Vec<&dyn writ_platform::KeystoreUnwrap> = vec![&identity];
    if let Some(way) = recovery {
        ways.push(way);
    }
    for h in &hardware {
        ways.push(&h.way);
    }
    for line in crate::keystore::recipients::reconcile(sealed, policy, &hardware, key, &ways)? {
        println!("keystore: {line}");
    }
    for (name, _) in &refused {
        crate::keystore::recipients::forget(sealed, name)?;
    }
    if !policy.hardware_keystore() && crate::keystore::hardware_wrapped(sealed)? {
        let typed = writ_crypto::passphrase::read(
            "No hardware recipient is left: a new keystore passphrase: ",
            Some("The same passphrase again: "),
            true,
        )?;
        let passphrase = writ_platform::Passphrase::new(typed.as_str().to_owned());
        drop(typed);
        let path = crate::keystore::recipients::Paths(sealed).identity();
        let fresh = path.with_file_name(".identity.age.recover");
        let _ = std::fs::remove_file(&fresh);
        crate::platform::enroll_at(&fresh, &passphrase, key)?;
        std::fs::rename(&fresh, &path)
            .with_context(|| format!("cannot move the new identity file to {}", path.display()))?;
        println!("keystore: the identity wrapped to the new passphrase");
    }
    Ok(())
}

/// The versions in force are altered (their MAC isn't this keystore's): shows the operator
/// the other two files as the state holds them, and asks whether to seal them with `target`'s.
/// Only `y` or `yes` trusts them; anything else, or no answer, changes nothing.
fn trust_others(target: AdminTarget, others: &[(AdminTarget, &str)]) -> anyhow::Result<bool> {
    use std::io::{BufRead as _, Write as _};
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "The versions in force don't carry this keystore's MAC: they were altered at rest, or \
         the state is another keystore's. Recovering {target} seals the other two with it. As \
         the state holds them:"
    )?;
    for (other, text) in others {
        writeln!(out, "--- {other}")?;
        for line in text.lines() {
            writeln!(
                out,
                "  {}",
                writ_core::text::strip(line, writ_core::text::Newlines::Drop, 4096)
            )?;
        }
    }
    write!(
        out,
        "Trust them and seal all three with this keystore? [y/N] "
    )?;
    out.flush()?;
    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .take(16)
        .read_line(&mut answer)
        .context("cannot read the answer")?;
    writeln!(out)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}
