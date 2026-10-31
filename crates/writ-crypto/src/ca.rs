//! The daemon's SSH certificate authority: one user certificate per approved lease.

use ssh_key::certificate::{Builder, CertType};
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

/// Issues and checks session certificates.
pub struct CertificateAuthority {
    key: PrivateKey,
}

impl CertificateAuthority {
    pub fn new(key: PrivateKey) -> Self {
        Self { key }
    }

    pub fn public_key(&self) -> &PublicKey {
        self.key.public_key()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.key.public_key().fingerprint(HashAlg::Sha256)
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
        Ok(builder.sign(&self.key)?)
    }
}

/// Checks a user certificate presented to the gateway. Every check must pass; `is_revoked`
/// says whether a serial is on the deny list.
pub fn validate_user_certificate(
    cert: &Certificate,
    authorities: &[Fingerprint],
    is_revoked: impl Fn(u64) -> bool,
    user: &str,
    now: u64,
) -> std::result::Result<(), CertificateError> {
    if cert.cert_type() != CertType::User {
        return Err(CertificateError::NotUserCertificate);
    }
    let authority = cert.signature_key().fingerprint(HashAlg::Sha256);
    if !authorities.contains(&authority) {
        return Err(CertificateError::UnknownAuthority(authority.to_string()));
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
        let authorities = [ca.public_key().fingerprint(HashAlg::Sha256)];
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
