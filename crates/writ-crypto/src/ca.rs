//! The daemon's SSH certificate authority: one user certificate per approved lease.

use std::collections::HashSet;

use ssh_key::certificate::{Builder, CertType};
use ssh_key::getrandom::SysRng;
use ssh_key::rand_core::UnwrapErr;
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
        let mut builder = Builder::new_with_random_nonce(
            &mut UnwrapErr(SysRng),
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

/// Checks a user certificate presented to the gateway. Every check must pass.
pub fn validate_user_certificate(
    cert: &Certificate,
    authorities: &[Fingerprint],
    revoked: &HashSet<u64>,
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
    if revoked.contains(&cert.serial()) {
        return Err(CertificateError::Revoked(cert.serial()));
    }
    if !cert.valid_principals().iter().any(|p| p == user) {
        return Err(CertificateError::WrongPrincipal(user.to_owned()));
    }
    Ok(())
}
