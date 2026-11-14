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

pub mod algorithm;
pub mod allowed_signers;
pub mod authority;
pub mod ca;
pub mod keyfile;
pub mod keypair;
pub mod keys;
pub mod openpgp;
pub mod passphrase;
pub mod piv_p256;
pub mod readers;
pub mod recovery;
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
    /// The CA's key, refused by its backend when it was opened: no certificate is signed.
    #[error("the CA key is unusable: {0}")]
    CaUnusable(String),
    /// An algorithm, hash or key kind Writ doesn't sign with (named, never replaced).
    #[error("not supported: {0}")]
    Unsupported(String),
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
    /// The authority MAC's key isn't 32 bytes (a damaged `authority.age`).
    #[error("invalid authority key: {0} bytes, not 32")]
    AuthorityKey(usize),
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("cannot generate the TLS certificate: {0}")]
    CertificateGeneration(#[from] rcgen::Error),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
