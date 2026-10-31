//! SSH cryptography for Writ: SSHSIG signatures (commit signing, approvals) and the SSH
//! certificate authority that turns an approved lease into a session certificate.
//!
//! Signing is split the way the `Signer` interface needs it: [`sshsig::signed_data`] builds
//! the exact bytes to sign, a key signs them, and [`sshsig::assemble`] wraps the raw
//! signature. Where the key lives is not this crate's business.

pub mod ca;
pub mod keys;
pub mod sshsig;

pub use ssh_key;

/// Errors from this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ssh key error: {0}")]
    Key(#[from] ssh_key::Error),
    #[error("signature namespace is {found:?}, expected {expected:?}")]
    Namespace { expected: String, found: String },
    #[error("signature was made by a key that is not allowed: {0}")]
    UnknownSigner(String),
    #[error("the key failed to sign")]
    SigningFailed,
    #[error("signature does not match the signed data")]
    BadSignature,
    #[error(transparent)]
    Certificate(#[from] ca::CertificateError),
}

pub type Result<T> = std::result::Result<T, Error>;
