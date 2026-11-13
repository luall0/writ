//! How the approver signs: `ssh-keygen -Y sign -U -n writ-approval -f <approval key .pub>`
//! with `SSH_AUTH_SOCK` set to the approver's agent (Secretive). Only the dedicated approval
//! key is ever used, only its public half is ever handed to ssh-keygen, and `-U` makes
//! ssh-keygen sign with the agent only, never a private key file (hard rule 8). ssh-keygen is
//! run by its absolute path, never looked up in `PATH`.
//!
//! The bytes to sign (a whole ticket, a whole new policy) reach ssh-keygen on its standard
//! input and the signature comes back on its standard output (no file named: `-Y sign` reads
//! the data from stdin): they are never written to a file, which a Ctrl-C at the Touch ID
//! prompt would leave behind (the review after M7.6, U-10). Only the approval key's public
//! half goes through a private temporary directory.

use std::io::Write as _;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};

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
        self.sign_with(&ssh_keygen()?, message)
    }

    /// [`Signer::sign`] with the ssh-keygen at `program`.
    fn sign_with(&self, program: &Path, message: &[u8]) -> anyhow::Result<String> {
        let dir = std::env::temp_dir().join(format!("writ-sign-{}", random_hex(8)?));
        // Made 0700 as it is created: no window where another user could enter it, and it
        // fails if anything already sits at that path.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
        let result = (|| {
            // ssh-keygen signs with a private key file directly when given one: only ever
            // hand it a public key, checked and copied here, so the private half has to be
            // in the agent.
            let public = approval_public_key(&self.key)?;
            let key = dir.join("approval.pub");
            std::fs::write(&key, public)
                .with_context(|| format!("cannot write {}", key.display()))?;
            // No file named: the message on stdin, the signature on stdout.
            let mut command = Process::new(program);
            command
                .env_clear()
                .args(["-Y", "sign", "-U", "-n", APPROVAL_NAMESPACE, "-f"])
                .arg(&key);
            // A clean environment: only the agent socket, the approver's or SSH_AUTH_SOCK.
            let agent = self
                .agent
                .clone()
                .or_else(|| std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no ssh-agent: set WRIT_APPROVAL_AGENT (Secretive's socket) or SSH_AUTH_SOCK"
                    )
                })?;
            command.env("SSH_AUTH_SOCK", agent);
            // Its chatter ("Signing file …") would clutter the trusted display: shown only on
            // failure. Touch ID is Secretive's own prompt, not a terminal one.
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .context("cannot run ssh-keygen")?;
            // Written from a thread while the output is read here: neither side waits on the
            // other's pipe. Closed once written, so ssh-keygen sees the end of the message.
            let mut stdin = child.stdin.take().context("ssh-keygen has no input")?;
            let owned = message.to_vec();
            let writer = std::thread::spawn(move || stdin.write_all(&owned));
            let output = child.wait_with_output().context("cannot run ssh-keygen")?;
            let written = writer
                .join()
                .map_err(|_| anyhow::anyhow!("cannot hand the message to ssh-keygen"))?;
            if !output.status.success() {
                eprintln!(
                    "{}",
                    crate::display::clean_lines(&String::from_utf8_lossy(&output.stderr))
                );
                bail!("ssh-keygen could not sign (is the approval key in the agent?)");
            }
            written.context("cannot hand the message to ssh-keygen")?;
            let signature =
                String::from_utf8(output.stdout).context("ssh-keygen wrote no signature")?;
            if signature.trim().is_empty() {
                bail!("ssh-keygen wrote no signature");
            }
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

/// The ssh-keygen the approver signs with: `WRIT_SSH_KEYGEN` (an absolute path), else the
/// system's, `/usr/bin/ssh-keygen` (OpenSSH ≥ 8.9 for `-U`). Never a `PATH` lookup: whatever
/// sits first in `PATH` would see the approval and choose what gets signed.
fn ssh_keygen() -> anyhow::Result<PathBuf> {
    match std::env::var_os("WRIT_SSH_KEYGEN") {
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                bail!("WRIT_SSH_KEYGEN must be an absolute path");
            }
            Ok(path)
        }
        None => Ok(PathBuf::from("/usr/bin/ssh-keygen")),
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

    /// The review after M7.6 (U-10): the bytes to sign went through `$TMPDIR/writ-sign-…/
    /// message`, left behind by a Ctrl-C at the Touch ID prompt. A fake ssh-keygen (never the
    /// real one, nor an agent) sees no file named after the key, the message on its stdin and
    /// nothing but the public key beside it; what it prints is the signature; the directory
    /// is gone after.
    #[test]
    fn the_message_reaches_ssh_keygen_on_stdin_and_is_never_written_to_a_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let key = generate(KeyKind::Ed25519).unwrap();
        let public = dir.path().join("approval.pub");
        std::fs::write(&public, key.public_key().to_openssh().unwrap()).unwrap();
        // Prints its arguments' count, the files beside the key, then what it read.
        let fake = dir.path().join("ssh-keygen");
        std::fs::write(
            &fake,
            "#!/bin/sh\nfor last; do :; done\necho \"args $#\"\nls \"$(dirname \"$last\")\"\n\
             printf 'read '\ncat\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
        let signer = Signer {
            key: public,
            agent: Some(dir.path().join("agent.sock")),
        };
        let message = "writ-ticket/3 {\"x\":1}\n".repeat(10_000);
        let signature = signer.sign_with(&fake, message.as_bytes()).unwrap();
        // `-Y sign -U -n writ-approval -f <key>`: no message file after the key.
        assert_eq!(signature, format!("args 7\napproval.pub\nread {message}"));
        let left: Vec<_> = std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("writ-sign-"))
            .filter(|e| e.path().join("message").exists())
            .collect();
        assert!(left.is_empty(), "{left:?}");
        // A failing ssh-keygen, which reads nothing: refused, its words shown escaped.
        std::fs::write(&fake, "#!/bin/sh\necho 'agent refused' >&2\nexit 1\n").unwrap();
        assert_eq!(
            crate::error_of(signer.sign_with(&fake, message.as_bytes())),
            "ssh-keygen could not sign (is the approval key in the agent?)"
        );
        // One that signs nothing.
        std::fs::write(&fake, "#!/bin/sh\ncat >/dev/null\n").unwrap();
        assert_eq!(
            crate::error_of(signer.sign_with(&fake, b"x")),
            "ssh-keygen wrote no signature"
        );
    }

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
        let error = crate::error_of(approval_public_key(&garbage));
        assert!(error.contains("is not an OpenSSH public key"), "{error}");
        let error = crate::error_of(approval_public_key(&dir.path().join("missing.pub")));
        assert!(error.starts_with("cannot read the approval key"), "{error}");
    }
}
