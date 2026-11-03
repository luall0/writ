//! `writd recover <writd.yaml> <policy|approvers|readers> <file>`: puts a file in force from
//! the daemon host, when no admin change can (every approver or reader key lost), or to apply
//! a file edited there. Run as the daemon's user, with the daemon stopped. It needs the
//! keystore's passphrase: with the host, that opens every secret already, so recovery gives
//! nobody anything new. The file is checked like an admin change (with the two others in
//! force), recorded as a new version under the keystore's MAC, logged (`admin`, no approver),
//! and written to the file `writd.yaml` names.

use std::path::Path;

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
    let store = Store::open(&db)?;
    let (old, version, digest) = crate::authority::recover(
        &store,
        &key,
        target,
        text.clone(),
        crate::now()?,
        config.min_ttl,
    )?;
    let mut audit = AuditLog::open(&config.state_dir.join("audit.jsonl"))?;
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
