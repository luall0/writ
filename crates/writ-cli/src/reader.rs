//! The reader key: the client key this machine uses on the daemon's approval API (SSH
//! authentication, and the HTTPS client certificate). It is generated here, kept in
//! `<home>/reader` (0600, never overwritten), and listed in the daemon's `readers` file.
//! It is never the approver's Secretive key (hard rule 8): it only opens the connection, and
//! approvals stay signed with the approval key.

use std::path::Path;

use anyhow::bail;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{Algorithm, PrivateKey};

use crate::session::write_private;

/// Reads the reader key. Refused if others can read it, or if it isn't Ed25519.
pub fn load(path: &Path) -> anyhow::Result<PrivateKey> {
    if !path.exists() {
        bail!(
            "no reader key at {}: run `writ reader` and add the line it prints to the daemon's \
             readers file",
            path.display()
        );
    }
    let key = crate::session::load_key(path)?;
    if key.algorithm() != Algorithm::Ed25519 {
        bail!("{} is not an ssh-ed25519 key", path.display());
    }
    Ok(key)
}

/// The reader key, generated first if there is none. Returns the line for the daemon's
/// `readers` file: `<name> <public key>`.
pub fn ensure(path: &Path, name: &str) -> anyhow::Result<String> {
    let valid_name = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'));
    if !valid_name {
        bail!("a reader name is up to 64 letters, digits, '-', '_', '.' or '@'");
    }
    if !path.exists() {
        let key = generate(KeyKind::Ed25519)?;
        let text = key.to_openssh(writ_crypto::ssh_key::LineEnding::LF)?;
        write_private(path, text.as_bytes())?;
    }
    let key = load(path)?;
    Ok(format!("{name} {}", key.public_key().to_openssh()?))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn the_reader_key_is_made_once_and_kept_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reader");
        let line = ensure(&path, "mac").unwrap();
        assert!(line.starts_with("mac ssh-ed25519 "), "{line}");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // Kept: the same line the second time.
        assert_eq!(ensure(&path, "mac").unwrap(), line);
        // Readable by others: refused.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = load(&path).unwrap_err().to_string();
        assert!(
            error.contains("can be read by others (mode 644)"),
            "{error}"
        );
        // Missing: says what to do.
        let error = load(&dir.path().join("none")).unwrap_err().to_string();
        assert!(error.contains("run `writ reader`"), "{error}");
        for bad in ["", "a b", "x\u{1b}", &"n".repeat(65)] {
            let error = ensure(&dir.path().join("other"), bad)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("a reader name is up to 64"),
                "{bad:?}: {error}"
            );
        }
        assert!(ensure(&dir.path().join("long"), &"n".repeat(64)).is_ok());
    }

    #[test]
    fn only_an_ed25519_key_is_a_reader() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reader");
        let p256 = generate(KeyKind::P256).unwrap();
        write_private(
            &path,
            p256.to_openssh(writ_crypto::ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let error = load(&path).unwrap_err().to_string();
        assert!(error.contains("is not an ssh-ed25519 key"), "{error}");
    }
}
