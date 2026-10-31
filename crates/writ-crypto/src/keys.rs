//! Key generation for the software backend and tests, and the system's random source.
//!
//! Nothing here panics when the system's random source fails: the bytes are fetched fallibly
//! first, and key generation draws only from those bytes ([`FallibleRng`]). A failure is an
//! error, and whatever was generated from it is thrown away.

use ssh_key::getrandom::SysRng;
use ssh_key::rand_core::{TryCryptoRng, TryRng};
use ssh_key::{Algorithm, EcdsaCurve, PrivateKey};

use crate::{CryptoError, Result};

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

/// Fills `buf` from the system's random source.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    SysRng.try_fill_bytes(buf).map_err(|_| CryptoError::Random)
}

/// `N` random bytes from the system's random source.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    fill_random(&mut buf)?;
    Ok(buf)
}

/// A random `u64` below 2^63 and above 0 (fits SQLite's signed integers), e.g. a serial.
pub fn random_serial() -> Result<u64> {
    let value = u64::from_be_bytes(random_array::<8>()?) >> 1;
    Ok(value.max(1))
}

/// Random bytes from the system's random source, as lowercase hex.
pub fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    fill_random(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Generates a new private key from the system's random source.
pub fn generate(kind: KeyKind) -> Result<PrivateKey> {
    with_rng(|rng| PrivateKey::random(rng, kind.algorithm()).map_err(CryptoError::from))
}

/// Runs `f` with a random generator holding bytes already fetched from the system. If `f`
/// draws more than were fetched, its result is discarded and this fails.
pub(crate) fn with_rng<T>(f: impl FnOnce(&mut FallibleRng) -> Result<T>) -> Result<T> {
    let mut rng = FallibleRng::new()?;
    let result = f(&mut rng);
    if rng.exhausted {
        return Err(CryptoError::Random);
    }
    result
}

/// A generator over a buffer filled fallibly from the system's random source. It never
/// fails while drawing: past the end of the buffer it marks itself exhausted (and gives
/// zeros), and [`with_rng`] then throws the result away. Key generation needs far less than
/// the buffer (an ed25519 seed is 32 bytes; P-256 rejection sampling a few times that).
pub(crate) struct FallibleRng {
    buf: zeroize::Zeroizing<[u8; Self::SIZE]>,
    used: usize,
    exhausted: bool,
}

impl FallibleRng {
    const SIZE: usize = 1024;

    fn new() -> Result<Self> {
        let mut buf = zeroize::Zeroizing::new([0u8; Self::SIZE]);
        fill_random(buf.as_mut())?;
        Ok(Self {
            buf,
            used: 0,
            exhausted: false,
        })
    }
}

impl TryRng for FallibleRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        let available = Self::SIZE - self.used;
        if dst.len() > available {
            self.exhausted = true;
            dst.fill(0);
            return Ok(());
        }
        dst.copy_from_slice(&self.buf[self.used..self.used + dst.len()]);
        self.buf[self.used..self.used + dst.len()].fill(0);
        self.used += dst.len();
        Ok(())
    }
}

impl TryCryptoRng for FallibleRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_differ_and_serials_fit() {
        let a = generate(KeyKind::Ed25519).unwrap();
        let b = generate(KeyKind::Ed25519).unwrap();
        assert_ne!(a.public_key(), b.public_key());
        assert!(generate(KeyKind::P256).is_ok());
        for _ in 0..100 {
            let serial = random_serial().unwrap();
            assert!(serial > 0 && i64::try_from(serial).is_ok());
        }
        assert_eq!(random_hex(16).unwrap().len(), 32);
    }

    #[test]
    fn drawing_past_the_buffer_discards_the_result() {
        let result = with_rng(|rng| {
            let mut big = vec![0u8; FallibleRng::SIZE + 1];
            rng.try_fill_bytes(&mut big).ok();
            Ok(big)
        });
        assert!(matches!(result, Err(CryptoError::Random)));
    }
}
