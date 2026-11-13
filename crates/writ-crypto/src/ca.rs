//! The daemon's SSH certificate authority: one user certificate per approved lease.

use ssh_key::certificate::{Builder, CertType};
use ssh_key::public::KeyData;
use ssh_key::{Certificate, Fingerprint, HashAlg, PrivateKey, PublicKey};

use crate::Result;

/// Why a certificate was refused. Shown in the audit log, never to the client.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CertificateError {
    #[error("not a user certificate")]
    NotUserCertificate,
    #[error("signed by an unknown certificate authority {0}")]
    UnknownAuthority(String),
    #[error("certificate signature is invalid")]
    BadSignature,
    #[error("certificate is not valid yet")]
    NotYetValid,
    #[error("certificate has expired")]
    Expired,
    #[error("certificate serial {0} is revoked")]
    Revoked(u64),
    #[error("certificate is not valid for user {0:?}")]
    WrongPrincipal(String),
    /// A critical option the gateway doesn't enforce. PROTOCOL.certkeys: a server must refuse
    /// a certificate with one it doesn't recognize; the daemon's CA never sets any.
    #[error("certificate has a critical option the gateway doesn't enforce: {0:?}")]
    CriticalOption(String),
}

/// What a certificate is issued for.
#[derive(Debug, Clone)]
pub struct CertificateRequest<'a> {
    pub subject: &'a PublicKey,
    pub serial: u64,
    /// The lease id.
    pub key_id: &'a str,
    pub principals: &'a [&'a str],
    pub valid_after: u64,
    pub valid_before: u64,
}

/// What signs a session certificate (M7.6): the CA's key, wherever it lives. A software key
/// in memory ([`CertificateAuthority::new`]), or one a `Signer` backend holds (the Secure
/// Enclave), behind this.
pub trait CaSigner: Send + Sync {
    fn public_key(&self) -> &PublicKey;
    /// The signature over `data`, as the CA's algorithm signs a certificate (Ed25519 the bytes
    /// themselves, ECDSA their curve's hash).
    fn sign(&self, data: &[u8]) -> Result<crate::keypair::RawSignature>;
}

/// The CA's key in memory (software).
struct Software {
    key: crate::keypair::KeyPair,
    public: PublicKey,
}

impl CaSigner for Software {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, data: &[u8]) -> Result<crate::keypair::RawSignature> {
        let hash = match self.key.algorithm() {
            crate::algorithm::KeyAlgorithm::Ed25519 => None,
            crate::algorithm::KeyAlgorithm::P256 => Some(crate::algorithm::Hash::Sha256),
            crate::algorithm::KeyAlgorithm::P384 => Some(crate::algorithm::Hash::Sha384),
            other => {
                return Err(crate::CryptoError::Unsupported(format!(
                    "a CA key of {other}"
                )));
            }
        };
        self.key.sign(data, hash)
    }
}

/// A [`CaSigner`] as `ssh-key`'s certificate builder signs with.
struct Through<'a>(&'a dyn CaSigner);

impl signature::Signer<ssh_key::Signature> for Through<'_> {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<ssh_key::Signature, signature::Error> {
        self.0
            .sign(msg)
            .and_then(|raw| raw.to_ssh())
            .map_err(|_| signature::Error::new())
    }
}

impl From<&Through<'_>> for ssh_key::public::KeyData {
    fn from(through: &Through<'_>) -> Self {
        through.0.public_key().key_data().clone()
    }
}

/// Issues and checks session certificates. Its key can be replaced in place (M7.6, a CA
/// rotation): every certificate from then on is the new key's.
pub struct CertificateAuthority {
    key: std::sync::RwLock<std::sync::Arc<dyn CaSigner>>,
}

impl CertificateAuthority {
    /// The CA over a software key.
    pub fn new(key: PrivateKey) -> Self {
        let public = key.public_key().clone();
        match crate::keypair::KeyPair::from_ssh(key) {
            Ok(key) => Self::with_signer(std::sync::Arc::new(Software { key, public })),
            // A key ssh-key reads but Writ doesn't sign with: every certificate refused.
            Err(_) => Self::with_signer(std::sync::Arc::new(Refusing(public))),
        }
    }

    /// The CA over `key`, a key a `Signer` backend holds.
    pub fn with_signer(key: std::sync::Arc<dyn CaSigner>) -> Self {
        Self {
            key: std::sync::RwLock::new(key),
        }
    }

    /// The key in force.
    fn current(&self) -> std::sync::Arc<dyn CaSigner> {
        // poisoned: replaced whole.
        self.key
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Puts `key` in force for every certificate from now on.
    pub fn replace(&self, key: std::sync::Arc<dyn CaSigner>) {
        *self
            .key
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = key;
    }

    pub fn public_key(&self) -> PublicKey {
        self.current().public_key().clone()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key().fingerprint(HashAlg::Sha256)
    }

    pub fn issue(&self, request: &CertificateRequest<'_>) -> Result<Certificate> {
        let nonce: [u8; Builder::RECOMMENDED_NONCE_SIZE] = crate::keys::random_array()?;
        let mut builder = Builder::new(
            nonce.to_vec(),
            request.subject.key_data().clone(),
            request.valid_after,
            request.valid_before,
        )?;
        builder
            .serial(request.serial)?
            .cert_type(CertType::User)?
            .key_id(request.key_id)?;
        for principal in request.principals {
            builder.valid_principal(*principal)?;
        }
        let key = self.current();
        Ok(builder.sign(&Through(&*key))?)
    }
}

/// A CA key Writ can't sign with: refuses every certificate.
struct Refusing(PublicKey);

impl CaSigner for Refusing {
    fn public_key(&self) -> &PublicKey {
        &self.0
    }

    fn sign(&self, _: &[u8]) -> Result<crate::keypair::RawSignature> {
        Err(crate::CryptoError::SigningFailed)
    }
}

/// Checks a user certificate presented to the gateway. Every check must pass; `is_revoked`
/// says whether a serial is on the deny list. The CA that signed it is matched by its whole
/// key against `authorities`, never by a fingerprint (the review after M7.6, K-8).
pub fn validate_user_certificate(
    cert: &Certificate,
    authorities: &[KeyData],
    is_revoked: impl Fn(u64) -> bool,
    user: &str,
    now: u64,
) -> std::result::Result<(), CertificateError> {
    if cert.cert_type() != CertType::User {
        return Err(CertificateError::NotUserCertificate);
    }
    let authority = cert.signature_key();
    if !authorities.contains(authority) {
        return Err(CertificateError::UnknownAuthority(
            authority.fingerprint(HashAlg::Sha256).to_string(),
        ));
    }
    cert.verify_signature()
        .map_err(|_| CertificateError::BadSignature)?;
    if now < cert.valid_after() {
        return Err(CertificateError::NotYetValid);
    }
    if now >= cert.valid_before() {
        return Err(CertificateError::Expired);
    }
    if is_revoked(cert.serial()) {
        return Err(CertificateError::Revoked(cert.serial()));
    }
    if !cert.valid_principals().iter().any(|p| p == user) {
        return Err(CertificateError::WrongPrincipal(user.to_owned()));
    }
    if let Some(name) = cert.critical_options().keys().next() {
        return Err(CertificateError::CriticalOption(name.clone()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyKind, generate};

    #[test]
    fn a_certificate_with_a_critical_option_is_refused() {
        let ca = generate(KeyKind::Ed25519).unwrap();
        let subject = generate(KeyKind::Ed25519).unwrap();
        let issue = |option: Option<(&str, &str)>| {
            let mut builder = Builder::new(
                vec![7; 32],
                subject.public_key().key_data().clone(),
                10,
                100,
            )
            .unwrap();
            builder
                .serial(1)
                .unwrap()
                .cert_type(CertType::User)
                .unwrap();
            builder
                .key_id("wrt_x")
                .unwrap()
                .valid_principal("git")
                .unwrap();
            if let Some((name, value)) = option {
                builder.critical_option(name, value).unwrap();
            }
            builder.sign(&ca).unwrap()
        };
        let authorities = [ca.public_key().key_data().clone()];
        let check = |cert: &Certificate| {
            validate_user_certificate(cert, &authorities, |_| false, "git", 50)
        };
        assert_eq!(check(&issue(None)), Ok(()));
        for name in ["source-address", "force-command", "verify-required"] {
            assert_eq!(
                check(&issue(Some((name, "x")))),
                Err(CertificateError::CriticalOption(name.to_owned()))
            );
        }
    }
}
