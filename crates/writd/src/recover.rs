//! `writd recover <writd.yaml> <policy|approvers|readers> <file>`: puts a file in force from
//! the daemon host, when no admin change can (every approver or reader key lost), or to apply
//! a file edited there. Run as the daemon's user, with the daemon stopped. It needs the
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
    let key = match &config.keystore {
        KeystoreConfig::Sealed(sealed) => {
            let typed = writ_crypto::passphrase::read("Keystore passphrase: ", None, false)?;
            let passphrase = writ_platform::Passphrase::new(typed.as_str().to_owned());
            drop(typed);
            let data_key = crate::platform::unlock(sealed)
                .unlock(&writ_platform::UnsealRequest::with_passphrase(passphrase))?;
            crate::keystore::sealed_authority_key(sealed, data_key.identity()?)?
        }
        KeystoreConfig::Dev(dir) => crate::keystore::dev_authority_key(dir)?,
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
            crate::keystore::make_missing(&config, &declared)?
        }
        AdminTarget::Approvers | AdminTarget::Readers => Vec::new(),
    };
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
                 on the host with the keystore's passphrase"
            )),
        )
        .context("the audit log can't be written: the version is in force all the same")?;
    let path = crate::authority::path(&config, target);
    crate::authority::write_back(path, &text)?;
    println!("{target}: version {version} in force (recovered on the host). Start the daemon.");
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
