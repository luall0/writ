//! Auto-unseal (M7.6, `unseal: auto` in the policy): what must hold for the daemon to open
//! itself at start, with no one, and what is still missing, each with the command that fixes
//! it ([`missing`]). Checked when a policy change asks for it (refused while anything is
//! missing), by `writ admin auto-unseal status`, and at each start (refused to start, naming
//! each one, never adjusted).
//!
//! The rule: nothing on the host opens a secret without a human. Every signing key, `ssh`
//! upstream credential and the SSH CA on a hardware backend; the keystore wrapped to hardware
//! recipients and the offline recovery key, never a passphrase (its tokens and identity then
//! wrapped only to them). Exempt: the boot tier's transport keys (the SSH host key, the TLS
//! key), which only identify the daemon, and a notifier's token kept in the boot tier.

use writ_core::config::{Key, PolicyConfig, UpstreamKey};

use crate::config::{Config, KeystoreConfig};

/// What keeps `policy` from starting the daemon on its own, one line each with its fix (none:
/// it can). Files are read only from what a sealed daemon can read: the keystore's identity
/// header, the CA's backend marker.
pub fn missing(config: &Config, policy: &PolicyConfig) -> anyhow::Result<Vec<String>> {
    let mut missing = Vec::new();
    let sealed = match &config.keystore {
        KeystoreConfig::Sealed(sealed) => sealed,
        KeystoreConfig::Dev(_) => {
            missing.push(
                "the development keystore is no keystore: a daemon that starts on its own takes \
                 a sealed one (writd init)"
                    .to_owned(),
            );
            return Ok(missing);
        }
    };
    if !policy.hardware_keystore() {
        missing.push(
            "the keystore opens with a passphrase: make a recovery key (writ recovery new), \
             declare it (writ admin recipient add recovery recipient=<age1…>), then a Secure \
             Enclave key (writ admin recipient add se-01 backend=se-cryptokit)"
                .to_owned(),
        );
    } else if !crate::keystore::hardware_wrapped(sealed)? {
        missing.push(
            "the keystore's identity is still wrapped to the passphrase: the recipients' change \
             hasn't applied yet (unseal once with writ unseal, which finishes it)"
                .to_owned(),
        );
    }
    let ca = crate::keystore::ca::backend(sealed)?;
    if ca == "software" {
        missing.push(
            "the SSH CA's key is in software: writ admin ca rotate --backend se-cryptokit"
                .to_owned(),
        );
    }
    for (id, key) in policy.keys() {
        let (what, in_software) = match key {
            Key::Signing(k) => ("signing key", k.backend.is_default()),
            Key::Upstream(UpstreamKey::Ssh { backend, .. }) => {
                ("upstream credential", backend.is_default())
            }
            // A token is wrapped to the keystore's recipients: hardware with the keystore.
            Key::Upstream(UpstreamKey::Token { .. }) => continue,
        };
        if in_software {
            missing.push(format!(
                "{what} {id} is in software: writ admin key rotate {id} --backend se-cryptokit \
                 (a p256 key; register its new public half where the old one was)"
            ));
        }
    }
    Ok(missing)
}
