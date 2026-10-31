//! Key generation for the software backend and tests.

use ssh_key::getrandom::SysRng;
use ssh_key::rand_core::UnwrapErr;
use ssh_key::{Algorithm, EcdsaCurve, PrivateKey};

use crate::Result;

/// Key algorithms Writ generates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Ed25519,
    P256,
}

impl KeyKind {
    fn algorithm(self) -> Algorithm {
        match self {
            KeyKind::Ed25519 => Algorithm::Ed25519,
            KeyKind::P256 => Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        }
    }
}

/// Generates a new private key from the system's random source.
pub fn generate(kind: KeyKind) -> Result<PrivateKey> {
    Ok(PrivateKey::random(
        &mut UnwrapErr(SysRng),
        kind.algorithm(),
    )?)
}

/// Random bytes from the system's random source, as lowercase hex.
pub fn random_hex(bytes: usize) -> String {
    use ssh_key::rand_core::Rng;
    let mut buf = vec![0u8; bytes];
    UnwrapErr(SysRng).fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}
