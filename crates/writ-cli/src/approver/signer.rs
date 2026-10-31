//! How the approver signs: `ssh-keygen -Y sign -n writ-approval -f <approval key .pub>` with
//! `SSH_AUTH_SOCK` set to the approver's agent (Secretive). Only the dedicated approval key is
//! ever used, and only its public half is ever handed to ssh-keygen, so the private key stays
//! in the agent (hard rule 8).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command as Process;

use anyhow::{Context, bail};
use writ_core::lease::APPROVAL_NAMESPACE;
use writ_crypto::keys::random_hex;
use writ_proto::{Command, Decisions, Info};

use crate::client::Approvals;

/// The approval key's public half and the agent holding it.
pub struct Signer {
    pub key: PathBuf,
    pub agent: Option<PathBuf>,
}

impl Signer {
    /// An SSHSIG over `message` in the `writ-approval` namespace, made by the agent.
    pub fn sign(&self, message: &[u8]) -> anyhow::Result<String> {
        let dir = std::env::temp_dir().join(format!("writ-sign-{}", random_hex(8)?));
        std::fs::create_dir(&dir).context("cannot create a temporary directory")?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot make {} private", dir.display()))?;
        let result = (|| {
            // ssh-keygen signs with a private key file directly when given one: only ever
            // hand it a public key, checked and copied here, so the private half has to be
            // in the agent.
            let public = approval_public_key(&self.key)?;
            let key = dir.join("approval.pub");
            std::fs::write(&key, public)?;
            let file = dir.join("message");
            std::fs::write(&file, message)?;
            let mut command = Process::new("ssh-keygen");
            command
                .args(["-Y", "sign", "-n", APPROVAL_NAMESPACE, "-f"])
                .arg(&key)
                .arg(&file);
            if let Some(agent) = &self.agent {
                command.env("SSH_AUTH_SOCK", agent);
            }
            // Its chatter ("Signing file …") would clutter the trusted display: shown only on
            // failure. Touch ID is Secretive's own prompt, not a terminal one.
            let output = command
                .stdin(std::process::Stdio::null())
                .output()
                .context("cannot run ssh-keygen")?;
            if !output.status.success() {
                eprint!("{}", String::from_utf8_lossy(&output.stderr));
                bail!("ssh-keygen could not sign (is the approval key in the agent?)");
            }
            let signature = std::fs::read_to_string(dir.join("message.sig"))
                .context("ssh-keygen wrote no signature")?;
            Ok(signature)
        })();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    /// A signature over `document` if the daemon wants one (`decisions: signed`), none if it
    /// takes open decisions (`decisions: open`).
    pub async fn sign_if_required(
        &self,
        session: &Approvals,
        document: &[u8],
    ) -> anyhow::Result<Option<String>> {
        let info: Info = session.call(&Command::Info, b"").await??;
        match info.decisions {
            Decisions::Signed => Ok(Some(self.sign(document)?)),
            Decisions::Open => Ok(None),
        }
    }
}

/// The default approval key path, `<home>/approver.pub`.
pub fn default_key(home: &Path) -> PathBuf {
    home.join("approver.pub")
}

/// The approval key file's public key, re-encoded (one line). Anything else, a private key
/// first of all, is refused.
fn approval_public_key(path: &Path) -> anyhow::Result<String> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read the approval key {}", path.display()))?;
    let key = writ_crypto::ssh_key::PublicKey::from_openssh(text.trim()).map_err(|_| {
        anyhow::anyhow!(
            "{} is not an OpenSSH public key: --key takes the approval key's public half (.pub)",
            path.display()
        )
    })?;
    Ok(key.to_openssh()? + "\n")
}

#[cfg(test)]
mod tests {
    use writ_crypto::keys::{KeyKind, generate};
    use writ_crypto::ssh_key::LineEnding;

    use super::*;

    #[test]
    fn the_approval_key_must_be_a_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate(KeyKind::Ed25519).unwrap();
        let public = dir.path().join("approval.pub");
        let line = key.public_key().to_openssh().unwrap();
        std::fs::write(&public, format!("  {line}  \n")).unwrap();
        assert_eq!(approval_public_key(&public).unwrap(), format!("{line}\n"));

        let private = dir.path().join("approval");
        std::fs::write(&private, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
        let error = approval_public_key(&private).unwrap_err().to_string();
        assert!(error.contains("is not an OpenSSH public key"), "{error}");
        assert!(!error.contains("PRIVATE"), "{error}");

        let garbage = dir.path().join("garbage.pub");
        std::fs::write(&garbage, "ssh-ed25519 not-base64\n").unwrap();
        assert!(approval_public_key(&garbage).is_err());
        assert!(approval_public_key(&dir.path().join("missing.pub")).is_err());
    }
}
