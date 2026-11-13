//! The keystore's offline recovery key (M7.6): made on the approver's machine (`writ recovery
//! new`, best offline: the secret is printed once and written nowhere) and checked against the
//! daemon's challenge without anything secret going back (`writ recovery check`).

use zeroize::Zeroizing;

/// Why a recovery key didn't check. Never holds the key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryError {
    #[error("not an age secret key (one line, as writ recovery new or age-keygen print it)")]
    NotAKey,
    #[error("this key's recipient is {mine}, not the daemon's recovery recipient {theirs}")]
    OtherRecipient { mine: String, theirs: String },
    #[error("the daemon's challenge is not an age file")]
    Challenge,
    #[error("this key doesn't open the daemon's challenge")]
    DoesNotOpen,
    #[error(
        "the challenge opened to something its digest doesn't name: the daemon's files don't match"
    )]
    Digest,
}

/// A new recovery key: its secret (age's secret key text, wiped on drop) and its recipient
/// (`age1…`).
pub fn new_key() -> (Zeroizing<String>, String) {
    use age::secrecy::ExposeSecret as _;
    let identity = age::x25519::Identity::generate();
    let secret = Zeroizing::new(identity.to_string().expose_secret().to_owned());
    (secret, identity.to_public().to_string())
}

/// The recipient of the secret key `text` (one line, surrounding blanks ignored).
pub fn recipient_of(text: &str) -> Result<String, RecoveryError> {
    let identity: age::x25519::Identity =
        text.trim().parse().map_err(|_| RecoveryError::NotAKey)?;
    Ok(identity.to_public().to_string())
}

/// Checks that the secret key `text` is the daemon's recovery key: its recipient is `recipient`,
/// and it opens `challenge` (an age file) to what `digest` (`sha256:<hex>`) names.
pub fn check(
    text: &str,
    recipient: &str,
    challenge: &[u8],
    digest: &str,
) -> Result<(), RecoveryError> {
    use std::io::Read as _;
    let identity: age::x25519::Identity =
        text.trim().parse().map_err(|_| RecoveryError::NotAKey)?;
    let mine = identity.to_public().to_string();
    if mine != recipient.trim() {
        return Err(RecoveryError::OtherRecipient {
            mine,
            theirs: recipient.trim().to_owned(),
        });
    }
    let decryptor =
        age::Decryptor::new_buffered(challenge).map_err(|_| RecoveryError::Challenge)?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| RecoveryError::DoesNotOpen)?;
    let mut value = Zeroizing::new(Vec::with_capacity(64));
    (&mut reader)
        .take(64)
        .read_to_end(&mut value)
        .map_err(|_| RecoveryError::DoesNotOpen)?;
    use sha2::{Digest as _, Sha256};
    let hex: String = Sha256::digest(value.as_slice())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if digest.trim() != format!("sha256:{hex}") {
        return Err(RecoveryError::Digest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge(recipient: &str, value: &[u8]) -> Vec<u8> {
        crate::sealed::decode(&crate::sealed::seal(recipient, value).unwrap()).unwrap()
    }

    fn digest(value: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};
        let hex: String = Sha256::digest(value)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("sha256:{hex}")
    }

    #[test]
    fn a_new_key_checks_against_its_own_challenge_and_no_other() {
        let (secret, recipient) = new_key();
        assert_ne!(secret.as_str(), recipient.as_str());
        assert_eq!(recipient_of(&secret).unwrap(), recipient);
        let value = [7u8; 32];
        let file = challenge(&recipient, &value);
        assert_eq!(
            check(
                &format!("  {}\n", *secret),
                &recipient,
                &file,
                &digest(&value)
            ),
            Ok(())
        );
        // Another key: named by its recipient, before anything is opened.
        let (other, other_recipient) = new_key();
        assert_eq!(
            check(&other, &recipient, &file, &digest(&value)),
            Err(RecoveryError::OtherRecipient {
                mine: other_recipient.clone(),
                theirs: recipient.clone()
            })
        );
        // The right recipient, a challenge sealed to another: it doesn't open.
        let theirs = challenge(&other_recipient, &value);
        assert_eq!(
            check(&secret, &recipient, &theirs, &digest(&value)),
            Err(RecoveryError::DoesNotOpen)
        );
        // A digest that doesn't match, a challenge that isn't one, a key that isn't one.
        assert_eq!(
            check(&secret, &recipient, &file, &digest(&[8; 32])),
            Err(RecoveryError::Digest)
        );
        assert_eq!(
            check(&secret, &recipient, b"garbage", &digest(&value)),
            Err(RecoveryError::Challenge)
        );
        for bad in ["", "age1notakey", "not a key at all"] {
            assert_eq!(
                check(bad, &recipient, &file, &digest(&value)),
                Err(RecoveryError::NotAKey),
                "{bad:?}"
            );
        }
        // No error text holds the secret.
        let error = check(&secret, "age1other", &file, "x")
            .unwrap_err()
            .to_string();
        assert!(!error.contains(secret.as_str()), "{error}");
    }
}
