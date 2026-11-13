//! A secret sealed on the approver's machine for the daemon's keystore: encrypted to the
//! keystore's public recipient (age X25519), so only the keystore's identity reads it, and
//! carried as standard base64 in a signed document (`writ-token/2`). Sealing needs no secret:
//! the recipient is public, served by `writ info` over the pinned channel.

use base64ct::{Base64, Encoding};
use std::io::Write as _;

/// Why a secret couldn't be sealed or its ciphertext read. Never holds the secret.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    #[error("the daemon's recipient is not an age X25519 recipient (age1…)")]
    Recipient,
    #[error("cannot encrypt to the daemon's recipient")]
    Encrypt,
    #[error("the sealed secret is not standard base64")]
    Base64,
}

/// Encrypts `plaintext` to `recipient` (`age1…`, one line, surrounding blanks ignored): the
/// age file in standard base64. The plaintext is copied nowhere but into the encryptor.
pub fn seal(recipient: &str, plaintext: &[u8]) -> Result<String, SealError> {
    let recipient: age::x25519::Recipient =
        recipient.trim().parse().map_err(|_| SealError::Recipient)?;
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|_| SealError::Encrypt)?;
    let mut sealed = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut sealed)
        .map_err(|_| SealError::Encrypt)?;
    writer
        .write_all(plaintext)
        .and_then(|()| writer.finish().map(|_| ()))
        .map_err(|_| SealError::Encrypt)?;
    Ok(Base64::encode_string(&sealed))
}

/// Encrypts `plaintext` to each of `recipients` (M7.6): an age X25519 recipient (`age1…`) or a
/// hardware one (`age1se1…`, a `piv-p256` stanza); the age file in standard base64.
pub fn seal_to(recipients: &[String], plaintext: &[u8]) -> Result<String, SealError> {
    let mut x25519 = Vec::new();
    let mut hardware = Vec::new();
    for text in recipients {
        let text = text.trim();
        if text.starts_with("age1se1") {
            hardware.push(
                crate::piv_p256::P256Recipient::parse(text, "age1se")
                    .map_err(|_| SealError::Recipient)?,
            );
        } else {
            x25519.push(
                text.parse::<age::x25519::Recipient>()
                    .map_err(|_| SealError::Recipient)?,
            );
        }
    }
    let all = x25519
        .iter()
        .map(|r| r as &dyn age::Recipient)
        .chain(hardware.iter().map(|r| r as &dyn age::Recipient));
    let encryptor = age::Encryptor::with_recipients(all).map_err(|_| SealError::Encrypt)?;
    let mut sealed = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut sealed)
        .map_err(|_| SealError::Encrypt)?;
    writer
        .write_all(plaintext)
        .and_then(|()| writer.finish().map(|_| ()))
        .map_err(|_| SealError::Encrypt)?;
    Ok(Base64::encode_string(&sealed))
}

/// An age file as standard base64, as a sealed secret travels.
pub fn encode(file: &[u8]) -> String {
    Base64::encode_string(file)
}

/// The age file a sealed secret's base64 carries (still encrypted).
pub fn decode(text: &str) -> Result<Vec<u8>, SealError> {
    Base64::decode_vec(text).map_err(|_| SealError::Base64)
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use super::*;

    fn identity() -> age::x25519::Identity {
        age::x25519::Identity::generate()
    }

    #[test]
    fn a_sealed_secret_opens_only_with_its_recipient_s_identity() {
        let mine = identity();
        let text = seal(&format!(" {}\n", mine.to_public()), b"writ-test-token-0123").unwrap();
        let file = decode(&text).unwrap();
        assert!(file.starts_with(b"age-encryption.org/v1\n-> X25519 "));
        let open = |identity: &age::x25519::Identity| {
            let decryptor = age::Decryptor::new_buffered(&file[..]).unwrap();
            let mut plaintext = Vec::new();
            decryptor
                .decrypt(std::iter::once(identity as &dyn age::Identity))
                .map(|mut reader| reader.read_to_end(&mut plaintext).map(|_| plaintext))
        };
        assert_eq!(open(&mine).unwrap().unwrap(), b"writ-test-token-0123");
        assert!(matches!(
            open(&identity()),
            Err(age::DecryptError::NoMatchingKeys)
        ));
        // The base64 never carries the plaintext.
        assert!(!text.contains("writ-test-token"));
    }

    #[test]
    fn a_bad_recipient_or_ciphertext_is_refused() {
        for bad in [
            "",
            "age1",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq",
            "AGE1QL3Z7HJY54PW3HYWW5AYYFG7ZQGVC7W3J2ELW8ZMRJ2KG5SFN9AQMCAC8P x",
        ] {
            assert_eq!(seal(bad, b"x"), Err(SealError::Recipient), "{bad:?}");
        }
        for bad in ["YWd", "Y W d l", "YW-l"] {
            assert_eq!(decode(bad), Err(SealError::Base64), "{bad:?}");
        }
    }
}
