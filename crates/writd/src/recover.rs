//! `writd recover <writd.yaml> <policy|approvers|readers> <file>`: puts a file in force from
//! the daemon host, when no admin change can (every approver or reader key lost), or to apply
//! a file edited there. Run as the daemon's user, with the daemon stopped (refused while
//! `writd run` holds the state's lock, [`crate::lock`]). It needs the
//! keystore's passphrase, or its recovery key (M7.6: the only way into a keystore its
//! hardware opens): with the host, either opens every secret already, so recovery gives
//! nobody anything new. The file is checked like an admin change (with the two others in
//! force), recorded as a new version under the keystore's MAC, logged (`admin`, no approver),
//! and written to the file `writd.yaml` names. A policy's keys the keystore lacks are made
//! first, as an admin change would make them (each logged, its public half printed).
//!
//! Every check runs and every question is asked before the keystore is touched (the review
//! after M7.6, S-6): a refusal or a "no" changes nothing. A rotation of the data key the
//! keystore owes, or the recovered policy calls for (a recipient taken out), is done here
//! (S-8).

use std::path::Path;

use std::io::Read as _;

use anyhow::{Context, bail};
use writ_core::authority::AdminTarget;
use writ_core::config::PolicyConfig;
use writ_core::names::KeyId;
use writ_platform::unlock::x25519::X25519Unwrap;
use writ_platform::{DataKey, Passphrase};
use writ_store::{AuditEvent, AuditLog, EventKind, Outcome, Store};

use crate::config::{Config, KeystoreConfig, SealedConfig};
use crate::keystore::{recipients, rotation};

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
    // A rotation of the data key cut short (S-8), settled from the keystore's own record
    // before the identity is read.
    if let KeystoreConfig::Sealed(sealed) = &config.keystore {
        for line in rotation::settle(sealed)? {
            println!("keystore: {line}");
        }
    }
    // The data key: from the passphrase, or the offline recovery key (M7.6). Never from the
    // hardware alone: host access must not replace a signed change.
    let (key, unlocked) = match &config.keystore {
        KeystoreConfig::Sealed(sealed) => {
            let typed = writ_crypto::passphrase::read(
                "Keystore passphrase, or the recovery key: ",
                None,
                false,
            )?;
            let unlocked = recovery_or_passphrase(sealed, typed.as_str())?;
            drop(typed);
            (
                crate::keystore::sealed_authority_key(sealed, unlocked.key.way()?)?,
                Some(unlocked),
            )
        }
        KeystoreConfig::Dev(dir) => (crate::keystore::dev_authority_key(dir)?, None),
    };
    let how = unlocked
        .as_ref()
        .map_or("the development keystore", |u| u.how);
    // Checked first: the file, the versions in force (and whether to trust them), the new set
    // as a start would read it; then what the keystore will need (its recipients' devices, a
    // new passphrase). Nothing is written before all of it answered.
    let declared = match target {
        AdminTarget::Policy => {
            let policy = crate::authority::parse_policy(&text, config.min_ttl)
                .with_context(|| file.display().to_string())?;
            Some(
                crate::declared::declarations(&policy)
                    .with_context(|| file.display().to_string())?,
            )
        }
        AdminTarget::Approvers | AdminTarget::Readers => None,
    };
    let store = Store::open(&db)?;
    let prepared = crate::authority::prepare_recover(
        &store,
        &key,
        target,
        text.clone(),
        config.min_ttl,
        |others| trust_others(target, others),
    )?;
    let policy = prepared.loaded.policy.clone();
    let plan = match (&config.keystore, &unlocked) {
        (KeystoreConfig::Sealed(sealed), Some(unlocked)) => Some(plan(
            &config,
            sealed,
            &policy,
            target == AdminTarget::Policy,
            unlocked,
        )?),
        _ => None,
    };

    // Now the keystore. A policy's keys checked against their backends, and those the
    // keystore lacks made, before the version is recorded (a version naming keys the
    // keystore lacks would never start).
    let made = match &declared {
        Some(declared) => crate::keystore::make_missing(
            &config,
            declared,
            &crate::platform::makers(&config)?,
            unlocked.as_ref().map(|u| &u.key),
        )?,
        None => Vec::new(),
    };
    let rotated = match (plan, &config.keystore, &unlocked) {
        (Some(plan), KeystoreConfig::Sealed(sealed), Some(unlocked)) => {
            keystore(&config, sealed, &policy, unlocked, plan)?
        }
        _ => None,
    };
    let (old, version, digest) = prepared.record(&store, crate::now()?)?;
    let mut audit = AuditLog::open(&config.state_dir.join("audit.jsonl"))?;
    if let Some(rotated) = rotated {
        audit
            .append(
                &AuditEvent::new(crate::now()?, EventKind::Admin, Outcome::Allowed)
                    .reason(format!("keystore: by writd recover, {rotated}")),
            )
            .context("the audit log can't be written: the data key is rotated all the same")?;
    }
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

/// What opened the keystore: its data key, how (for the audit line), the recovery key's way
/// when it was the recovery key (it opens what a hardware keystore wrapped to it), the
/// passphrase when it was the passphrase (a rotation wraps the new identity with it).
struct Unlocked {
    key: DataKey,
    how: &'static str,
    recovery: Option<X25519Unwrap>,
    passphrase: Option<Passphrase>,
}

/// The data key from what was typed: an age secret key opens the recovery file
/// (`identity.recovery.age`); anything else is the passphrase, on a keystore that has one.
fn recovery_or_passphrase(sealed: &SealedConfig, typed: &str) -> anyhow::Result<Unlocked> {
    if let Ok(identity) = typed.trim().parse::<age::x25519::Identity>() {
        let paths = recipients::Paths(sealed);
        if !paths.recovery_identity().exists() {
            bail!("this keystore has no recovery recipient: give its passphrase");
        }
        let way = X25519Unwrap::new("recovery", identity);
        let key = writ_platform::unlock::data_key(&paths.recovery_identity(), &[&way])
            .map_err(|e| anyhow::anyhow!("the recovery key doesn't open this keystore: {e}"))?;
        return Ok(Unlocked {
            key,
            how: "the recovery key",
            recovery: Some(way),
            passphrase: None,
        });
    }
    if crate::keystore::hardware_wrapped(sealed)? {
        bail!("this keystore has no passphrase (its hardware opens it): give the recovery key");
    }
    let passphrase = Passphrase::new(typed.to_owned());
    let key = crate::platform::data_key(
        sealed,
        &writ_platform::UnsealRequest::with_passphrase(Passphrase::new(typed.to_owned())),
    )?;
    Ok(Unlocked {
        key,
        how: "the keystore's passphrase",
        recovery: None,
        passphrase: Some(passphrase),
    })
}

/// What the keystore needs, worked out (and asked) before anything is written.
struct Plan {
    /// Whether the policy's recipients are brought in force (a recovered policy).
    recipients: bool,
    /// Why the data key is rotated: none, no rotation.
    rotate: Vec<String>,
    /// What the new identity is wrapped with on a passphrase keystore (the one typed, or a
    /// new one); none on a hardware keystore.
    passphrase: Option<Passphrase>,
    /// Whether that passphrase is a new one.
    new_passphrase: bool,
}

/// The keystore's needs for `policy` (the one in force once recovered), checked and asked:
/// a recipient its device no longer opens refused when the policy still declares it, a
/// rotation owed or called for, and with it a new passphrase when the keystore goes back to
/// one, or the recovery key opened a passphrase keystore.
fn plan(
    config: &Config,
    sealed: &SealedConfig,
    policy: &PolicyConfig,
    recipients_too: bool,
    unlocked: &Unlocked,
) -> anyhow::Result<Plan> {
    if recipients_too {
        // A recipient its device no longer opens (the device lost) is dropped, if the
        // recovered policy no longer declares it; one it declares is refused.
        let (_, refused) = recipients::load_each(config, sealed)?;
        for (name, why) in &refused {
            if policy.recipients().contains_key(name) {
                bail!("recipient {name}: {why:#}: take it out of the policy to recover without it");
            }
        }
    }
    let mut rotate = rotation::owed(sealed, policy)?;
    if recipients_too
        && !policy.hardware_keystore()
        && crate::keystore::hardware_wrapped(sealed)?
        && rotate.is_empty()
    {
        rotate.push("the hardware recipients given up for a passphrase".to_owned());
    }
    let (passphrase, new_passphrase) = match (rotate.is_empty(), policy.hardware_keystore()) {
        (true, _) | (false, true) => (None, false),
        (false, false) => match (
            &unlocked.passphrase,
            crate::keystore::hardware_wrapped(sealed)?,
        ) {
            (Some(typed), false) => (Some(Passphrase::new(typed.expose().to_owned())), false),
            (_, hardware) => {
                let prompt = match hardware {
                    true => "No hardware recipient is left: a new keystore passphrase: ",
                    false => {
                        "The data key is rotated, and the recovery key opened the keystore: a \
                         new keystore passphrase: "
                    }
                };
                let typed = writ_crypto::passphrase::read(
                    prompt,
                    Some("The same passphrase again: "),
                    true,
                )?;
                let passphrase = Passphrase::new(typed.as_str().to_owned());
                drop(typed);
                (Some(passphrase), true)
            }
        },
    };
    Ok(Plan {
        recipients: recipients_too,
        rotate,
        passphrase,
        new_passphrase,
    })
}

/// The keystore brought in line with `policy` from the host (M7.6): its hardware recipients
/// made in their device and loaded, its data key rotated when the plan says (S-8), every file
/// rewrapped (the recovery key and the identity open what is wrapped to the hardware). What
/// a rotation did, for the audit log.
fn keystore(
    config: &Config,
    sealed: &SealedConfig,
    policy: &PolicyConfig,
    unlocked: &Unlocked,
    plan: Plan,
) -> anyhow::Result<Option<String>> {
    let rotated = (!plan.rotate.is_empty()).then(|| crate::keystore::rotated_said(&plan.rotate));
    if plan.recipients {
        for (name, recipient) in recipients::make_missing(config, sealed, policy)? {
            println!("hardware recipient {name}: {recipient}");
        }
    }
    let (hardware, refused) = recipients::load_each(config, sealed)?;
    let dropped: Vec<KeyId> = match plan.recipients {
        true => refused.iter().map(|(name, _)| name.clone()).collect(),
        false => Vec::new(),
    };
    for (name, why) in refused.iter().filter(|_| plan.recipients) {
        println!("recipient {name}: its device doesn't open it ({why:#}): dropped");
    }
    let ways_of = |key: &DataKey| -> anyhow::Result<X25519Unwrap> { Ok(key.way()?) };
    let key = match plan.rotate.is_empty() {
        true => DataKey::from_bytes(*unlocked.key.as_bytes()),
        false => {
            rotation::record_owed(sealed, &plan.rotate)?;
            let identity = ways_of(&unlocked.key)?;
            let mut ways: Vec<&dyn writ_platform::KeystoreUnwrap> = vec![&identity];
            if let Some(way) = &unlocked.recovery {
                ways.push(way);
            }
            ways.extend(
                hardware
                    .iter()
                    .map(|h| &h.way as &dyn writ_platform::KeystoreUnwrap),
            );
            let wrap = match &plan.passphrase {
                Some(passphrase) => rotation::Wrap::Passphrase(passphrase),
                None => rotation::Wrap::Hardware,
            };
            let (new, lines) = rotation::Rotation {
                sealed,
                policy,
                held: &hardware,
                old: &unlocked.key,
                ways: &ways,
                wrap,
            }
            .run()?;
            for line in lines {
                println!("keystore: {line}");
            }
            println!("keystore: {}", crate::keystore::rotated_said(&plan.rotate));
            if plan.new_passphrase {
                println!("keystore: the identity wrapped to the new passphrase");
            }
            new
        }
    };
    if plan.recipients {
        let hardware = recipients::load(config, sealed)?;
        let identity = ways_of(&key)?;
        let mut ways: Vec<&dyn writ_platform::KeystoreUnwrap> = vec![&identity];
        if let Some(way) = &unlocked.recovery {
            ways.push(way);
        }
        ways.extend(
            hardware
                .iter()
                .map(|h| &h.way as &dyn writ_platform::KeystoreUnwrap),
        );
        for line in recipients::reconcile(sealed, policy, &hardware, &key, &ways)? {
            println!("keystore: {line}");
        }
        for name in &dropped {
            recipients::forget(sealed, name)?;
        }
    }
    Ok(rotated)
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
