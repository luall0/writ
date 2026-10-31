//! SSHSIG (OpenSSH `PROTOCOL.sshsig`): the format of git's SSH commit signatures and of
//! Writ approvals (namespace `writ-approval`).

use signature::Signer as _;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, Signature, SshSig};

use crate::{CryptoError, Result};

/// Hash algorithm used for every signature Writ makes (the one `ssh-keygen` uses).
pub const HASH_ALG: HashAlg = HashAlg::Sha512;

/// The exact bytes a key must sign to produce an SSHSIG over `msg` in `namespace`.
pub fn signed_data(namespace: &str, msg: &[u8]) -> Result<Vec<u8>> {
    Ok(SshSig::signed_data(namespace, HASH_ALG, msg)?)
}

/// Wraps a raw signature over [`signed_data`] into an armored SSHSIG.
pub fn assemble(public_key: &KeyData, namespace: &str, signature: Signature) -> Result<String> {
    let sig = SshSig::new(public_key.clone(), namespace, HASH_ALG, signature)?;
    Ok(sig.to_pem(LineEnding::LF)?)
}

/// Signs `msg` with a key held in memory (software backend).
pub fn sign(key: &PrivateKey, namespace: &str, msg: &[u8]) -> Result<String> {
    let data = signed_data(namespace, msg)?;
    let signature = key
        .try_sign(&data)
        .map_err(|_| CryptoError::SigningFailed)?;
    assemble(key.public_key().key_data(), namespace, signature)
}

/// Verifies an armored SSHSIG over `msg` made in `namespace` by one of `allowed` keys, and
/// returns the key that signed it.
pub fn verify<'a>(
    allowed: &'a [PublicKey],
    namespace: &str,
    msg: &[u8],
    armored: &str,
) -> Result<&'a PublicKey> {
    let sig = SshSig::from_pem(armored)?;
    if sig.namespace() != namespace {
        return Err(CryptoError::Namespace {
            expected: namespace.to_owned(),
            found: sig.namespace().to_owned(),
        });
    }
    let signer = allowed
        .iter()
        .find(|key| key.key_data() == sig.public_key())
        .ok_or_else(|| {
            CryptoError::UnknownSigner(
                PublicKey::from(sig.public_key().clone())
                    .fingerprint(HashAlg::Sha256)
                    .to_string(),
            )
        })?;
    signer
        .verify(namespace, msg, &sig)
        .map_err(|_| CryptoError::BadSignature)?;
    require_user_presence(sig.signature())?;
    Ok(signer)
}

/// The user-presence flag of the security key's authenticator data.
const SK_USER_PRESENT: u8 = 0x01;

/// A security-key signature must say the key was touched. ssh-key folds the flags into the
/// signed data but never checks them; sshd refuses a signature without the flag by default,
/// and so does Writ (a credential made `no-touch-required` would sign silently).
fn require_user_presence(signature: &Signature) -> Result<()> {
    if !matches!(
        signature.algorithm(),
        Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256
    ) {
        return Ok(());
    }
    // The signature data ends with the flags byte and a 4-byte counter.
    let bytes = signature.as_bytes();
    let flags = bytes.len().checked_sub(5).and_then(|i| bytes.get(i));
    match flags {
        Some(flags) if flags & SK_USER_PRESENT != 0 => Ok(()),
        _ => Err(CryptoError::NoUserPresence),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyKind, generate};
    use sha2::{Digest, Sha256};
    use ssh_key::public::SkEd25519;

    const NAMESPACE: &str = "writ-approval";

    /// A security-key (sk-ssh-ed25519) SSHSIG over `msg` with these authenticator `flags`,
    /// made in software the way a FIDO key makes it: the key signs
    /// sha256(application) ‖ flags ‖ counter ‖ sha256(message).
    fn sk_signature(msg: &[u8], flags: u8) -> (PublicKey, String) {
        let inner = generate(KeyKind::Ed25519).unwrap();
        let keypair = inner.key_data().ed25519().unwrap();
        let sk = KeyData::SkEd25519(SkEd25519::new(keypair.public, "ssh:"));
        let message = signed_data(NAMESPACE, msg).unwrap();
        let trailer = [flags, 0, 0, 0, 1];
        let mut to_sign = Sha256::digest("ssh:").to_vec();
        to_sign.extend_from_slice(&trailer);
        to_sign.extend(Sha256::digest(&message));
        let raw = inner.try_sign(&to_sign).unwrap();
        let mut data = raw.as_bytes().to_vec();
        data.extend_from_slice(&trailer);
        let signature = Signature::new(Algorithm::SkEd25519, data).unwrap();
        let armored = assemble(&sk, NAMESPACE, signature).unwrap();
        (PublicKey::from(sk), armored)
    }

    #[test]
    fn a_touched_security_key_signs() {
        let (key, armored) = sk_signature(b"ticket", SK_USER_PRESENT);
        let allowed = [key];
        assert!(verify(&allowed, NAMESPACE, b"ticket", &armored).is_ok());
        // The same signature over other bytes: refused as a bad signature, not for presence.
        assert!(matches!(
            verify(&allowed, NAMESPACE, b"other", &armored),
            Err(CryptoError::BadSignature)
        ));
    }

    #[test]
    fn a_security_key_signature_without_a_touch_is_refused() {
        for flags in [0x00, 0x04] {
            let (key, armored) = sk_signature(b"ticket", flags);
            assert!(
                matches!(
                    verify(&[key], NAMESPACE, b"ticket", &armored),
                    Err(CryptoError::NoUserPresence)
                ),
                "flags {flags:#x}"
            );
        }
    }

    #[test]
    fn a_plain_key_needs_no_flags() {
        let key = generate(KeyKind::Ed25519).unwrap();
        let armored = sign(&key, NAMESPACE, b"ticket").unwrap();
        assert!(verify(&[key.public_key().clone()], NAMESPACE, b"ticket", &armored).is_ok());
    }
}
