//! Cryptography for Writ: SSHSIG signatures (commit signing, approvals), the SSH certificate
//! authority that turns an approved lease into a session certificate, the approvers file,
//! the readers file (who may use the approval API), keys and randomness, the approval API's
//! pinned TLS, reading a passphrase a person types, and sealing a secret to the daemon's
//! keystore.
//!
//! Signing is split the way the `Signer` interface needs it: [`sshsig::signed_data`] builds
//! the exact bytes to sign, a key signs them, and [`sshsig::assemble`] wraps the raw
//! signature. Where the key lives is not this crate's business.

// This crate parses untrusted input and computes limits: every arithmetic operation is
// checked, saturating, or allowed with the reason it can't overflow.
#![deny(clippy::arithmetic_side_effects)]

pub mod allowed_signers;
pub mod authority;
pub mod ca;
pub mod keys;
pub mod passphrase;
pub mod readers;
pub mod sealed;
pub mod sshsig;
pub mod tls;

pub use ssh_key;

/// Errors from this crate. Messages name what failed and never hold key material.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
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
    /// A security-key (`sk-*`) signature made without the user-presence flag: the key was not
    /// touched, so malware could have signed without the approver.
    #[error("the security key signed without user presence (no touch)")]
    NoUserPresence,
    #[error("the system's random source failed")]
    Random,
    /// A line of an `allowed_signers` file that can't be read or honored.
    #[error("line {line}: {why}")]
    AllowedSigners { line: usize, why: String },
    /// A line of a `readers` file that can't be read or honored.
    #[error("line {line}: {why}")]
    Readers { line: usize, why: String },
    /// A PEM block that isn't the expected certificate or key.
    #[error("invalid TLS {0}")]
    Pem(&'static str),
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("cannot generate the TLS certificate: {0}")]
    CertificateGeneration(#[from] rcgen::Error),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
