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

#[cfg(test)]
mod tests {
    use super::*;

    /// A sealed keystore's directory and its `writd.yaml`, the keystore's identity sealed to a
    /// passphrase or to an X25519 key (standing for the hardware: its header names no scrypt).
    fn sealed(dir: &std::path::Path, hardware: bool, ca: Option<&str>) -> Config {
        use std::io::Write as _;
        let keys = dir.join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        let identity = keys.join("identity.age");
        let encryptor = if hardware {
            let to = age::x25519::Identity::generate().to_public();
            age::Encryptor::with_recipients(std::iter::once(&to as &dyn age::Recipient)).unwrap()
        } else {
            age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(
                "a test passphrase".to_owned(),
            ))
        };
        let mut out = Vec::new();
        let mut writer = encryptor.wrap_output(&mut out).unwrap();
        writer.write_all(b"data key").unwrap();
        writer.finish().unwrap();
        writ_platform::fs::create_new_private_file(&identity)
            .unwrap()
            .write_all(&out)
            .unwrap();
        if let Some(ca) = ca {
            std::fs::write(keys.join("ca.backend"), format!("{ca}\n")).unwrap();
        }
        let path = dir.join("writd.yaml");
        std::fs::write(
            &path,
            "state_dir: data\npolicy: policy.yaml\napprovers: approvers\nreaders: readers\n\
             keystore: { sealed: { dir: keys, boot: boot } }\n\
             transports: { agents: [{ tcp: \"127.0.0.1:0\", allow: [127.0.0.1] }], approvals: \
             { ssh: [{ tcp: \"127.0.0.1:0\" }] } }\nattestor: network\nsession_watcher: none\n",
        )
        .unwrap();
        Config::load(&path).unwrap()
    }

    const HARDWARE: &str = "recipients:\n  recovery: { recipient: \
        age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p }\n  se-01: { backend: \
        se-cryptokit }\n";

    fn policy(agent_backend: &str, recipients: &str) -> PolicyConfig {
        PolicyConfig::from_yaml(&format!(
            "format: 2\nkeys:\n  agent-01:\n    use: signing\n    format: ssh\n    algorithm: p256\n    \
             backend: {agent_backend}\n  upstream-01:\n    use: upstream\n    kind: ssh\n    \
             algorithm: p256\n    backend: se-cryptokit\n{recipients}repos: {{}}\ntemplates: {{}}\n"
        ))
        .unwrap()
    }

    /// The review after M7.6 (T-5): each condition on its own, the others met, says itself
    /// and nothing else; everything met says nothing.
    #[test]
    fn each_thing_left_in_software_is_said_alone() {
        let dir = tempfile::tempdir().unwrap();
        // Everything in hardware: nothing missing.
        let config = sealed(dir.path(), true, Some("se-cryptokit"));
        assert!(
            missing(&config, &policy("se-cryptokit", HARDWARE))
                .unwrap()
                .is_empty()
        );
        // One signing key in software.
        assert_eq!(
            missing(&config, &policy("software", HARDWARE)).unwrap(),
            [
                "signing key agent-01 is in software: writ admin key rotate agent-01 --backend \
              se-cryptokit (a p256 key; register its new public half where the old one was)"
            ]
        );
        // The keystore with no hardware recipient: opens with a passphrase.
        let said = missing(&config, &policy("se-cryptokit", "")).unwrap();
        assert_eq!(said.len(), 1, "{said:?}");
        assert!(
            said[0].starts_with("the keystore opens with a passphrase"),
            "{said:?}"
        );
        // The CA in software.
        let dir = tempfile::tempdir().unwrap();
        let config = sealed(dir.path(), true, None);
        assert_eq!(
            missing(&config, &policy("se-cryptokit", HARDWARE)).unwrap(),
            ["the SSH CA's key is in software: writ admin ca rotate --backend se-cryptokit"]
        );
        // The identity still wrapped to the passphrase.
        let dir = tempfile::tempdir().unwrap();
        let config = sealed(dir.path(), false, Some("se-cryptokit"));
        let said = missing(&config, &policy("se-cryptokit", HARDWARE)).unwrap();
        assert_eq!(said.len(), 1, "{said:?}");
        assert!(
            said[0].starts_with("the keystore's identity is still wrapped to the passphrase"),
            "{said:?}"
        );
    }

    #[test]
    fn the_development_keystore_never_opens_itself() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("writd.yaml");
        std::fs::write(
            &path,
            "state_dir: data\npolicy: policy.yaml\napprovers: approvers\nreaders: readers\n\
             keystore: { dev: keys }\n\
             transports: { agents: [{ tcp: \"127.0.0.1:0\", allow: [127.0.0.1] }], approvals: \
             { ssh: [{ tcp: \"127.0.0.1:0\" }] } }\nattestor: network\nsession_watcher: none\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        let said = missing(&config, &policy("se-cryptokit", HARDWARE)).unwrap();
        assert_eq!(said.len(), 1, "{said:?}");
        assert!(
            said[0].starts_with("the development keystore is no keystore"),
            "{said:?}"
        );
    }
}
