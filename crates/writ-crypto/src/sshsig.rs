//! SSHSIG (OpenSSH `PROTOCOL.sshsig`): the format of git's SSH commit signatures and of
//! Writ approvals (namespace `writ-approval`).

use signature::Signer as _;
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, Signature, SshSig};

use crate::{Error, Result};

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
    let signature = key.try_sign(&data).map_err(|_| Error::SigningFailed)?;
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
        return Err(Error::Namespace {
            expected: namespace.to_owned(),
            found: sig.namespace().to_owned(),
        });
    }
    let signer = allowed
        .iter()
        .find(|key| key.key_data() == sig.public_key())
        .ok_or_else(|| {
            Error::UnknownSigner(
                PublicKey::from(sig.public_key().clone())
                    .fingerprint(HashAlg::Sha256)
                    .to_string(),
            )
        })?;
    signer
        .verify(namespace, msg, &sig)
        .map_err(|_| Error::BadSignature)?;
    Ok(signer)
}
