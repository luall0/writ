//! The MAC that binds the authority files in force (the policy, `approvers`, `readers`) to the
//! keystore: an HMAC-SHA-256 over the **head** (each file's version and the digest of its
//! text), keyed by [`AuthorityKey`], a secret of the sealed keystore. At unseal the daemon
//! checks it: a version altered, replaced or swapped for another one without the passphrase
//! is found. (The whole state put back from an older copy carries a valid MAC: that is a
//! restored backup.)

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{CryptoError, Result};

type HmacSha256 = Hmac<Sha256>;

/// The authority MAC's key: 32 random bytes, sealed in the keystore. Wiped on drop, never
/// printed.
pub struct AuthorityKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for AuthorityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthorityKey(<redacted>)")
    }
}

impl AuthorityKey {
    /// A new key from the system's random source.
    pub fn generate() -> Result<Self> {
        Ok(Self(Zeroizing::new(crate::keys::random_array()?)))
    }

    /// The key from its 32 bytes (as the keystore holds them); anything else is refused.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CryptoError::Pem("authority key (not 32 bytes)"))?;
        Ok(Self(Zeroizing::new(array)))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn mac(&self, head: &[HeadEntry<'_>]) -> Result<HmacSha256> {
        // HMAC takes a key of any length: never refused, but never assumed either.
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.0.as_slice())
            .map_err(|_| CryptoError::SigningFailed)?;
        mac.update(b"writ-authority-head/1\n");
        for entry in head {
            mac.update(format!("{} {} {}\n", entry.target, entry.version, entry.digest).as_bytes());
        }
        Ok(mac)
    }

    /// The head's MAC, as lowercase hex.
    pub fn sign_head(&self, head: &[HeadEntry<'_>]) -> Result<String> {
        Ok(self
            .mac(head)?
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }

    /// Whether `mac` (lowercase hex) is the head's, compared in constant time.
    pub fn verify_head(&self, head: &[HeadEntry<'_>], mac: &str) -> bool {
        let Some(bytes) = from_hex(mac) else {
            return false;
        };
        self.mac(head)
            .is_ok_and(|mac| mac.verify_slice(&bytes).is_ok())
    }
}

/// One file of the head: its name, the version in force, the digest of its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadEntry<'a> {
    pub target: &'a str,
    pub version: u64,
    pub digest: &'a str,
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() != 64 {
        return None;
    }
    (0usize..32)
        .map(|i| {
            let pair = text.get(i.checked_mul(2)?..i.checked_mul(2)?.checked_add(2)?)?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head<'a>(version: u64, digest: &'a str) -> Vec<HeadEntry<'a>> {
        vec![
            HeadEntry {
                target: "policy",
                version,
                digest,
            },
            HeadEntry {
                target: "approvers",
                version: 1,
                digest: "aa",
            },
            HeadEntry {
                target: "readers",
                version: 1,
                digest: "bb",
            },
        ]
    }

    #[test]
    fn a_head_verifies_only_with_its_key_and_exactly_its_entries() {
        let key = AuthorityKey::generate().unwrap();
        let mac = key.sign_head(&head(2, "cc")).unwrap();
        assert_eq!(mac.len(), 64);
        assert!(key.verify_head(&head(2, "cc"), &mac));
        // Another version, another text, another key, a cut or garbled MAC: refused.
        assert!(!key.verify_head(&head(1, "cc"), &mac));
        assert!(!key.verify_head(&head(2, "cd"), &mac));
        assert!(
            !AuthorityKey::generate()
                .unwrap()
                .verify_head(&head(2, "cc"), &mac)
        );
        assert!(!key.verify_head(&head(2, "cc"), mac.get(..62).unwrap()));
        assert!(!key.verify_head(&head(2, "cc"), &"zz".repeat(32)));
        // The same key from its bytes gives the same MAC; other lengths are refused.
        let again = AuthorityKey::from_bytes(key.as_bytes()).unwrap();
        assert_eq!(again.sign_head(&head(2, "cc")).unwrap(), mac);
        assert!(matches!(
            AuthorityKey::from_bytes(&[0; 31]),
            Err(CryptoError::Pem("authority key (not 32 bytes)"))
        ));
        assert_eq!(format!("{key:?}"), "AuthorityKey(<redacted>)");
    }
}
