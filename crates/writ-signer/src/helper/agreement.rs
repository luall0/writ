//! [`HelperAgreement`] (M7.6): a P-256 key-agreement key made and used by the helper (the
//! Secure Enclave's, through `writ-se`), for the keystore's hardware recipient: the helper does
//! the ECDH that unwraps a `piv-p256` stanza (`writ_crypto::piv_p256`), the key never leaves
//! the device.
//!
//! The same rules as the helper signer's: **no blob reaches the device unless it is the one
//! the device made for that key**, framed under its own header (`writ-se-agreement/1\n`, then
//! SHA-256 over that header, the key's public point and the blob, then the blob), so a signing
//! key's blob never passes for an agreement key's, nor the other way round; **what the helper
//! answers is untrusted**: a point must be on P-256 and the key's, a shared secret exactly 32
//! bytes. An ECDH can't be checked like a signature, so the key proves its point when it is
//! made and when it is loaded: a probe agreement with an ephemeral point, compared with the
//! one computed from the point answered. A shared secret that is wrong at another time only
//! fails to open its stanza (ChaCha20-Poly1305 refuses it): never another file key.

use p256::elliptic_curve::sec1::ToSec1Point;
use zeroize::Zeroizing;

use super::{DIGEST, Helper, HelperConfig, HelperError, MAX_ANSWER, Op, digest_under};
use crate::Stored;

/// The frame's header of a key-agreement key's blob.
const AGREEMENT_FRAME: &[u8] = b"writ-se-agreement/1\n";
/// An uncompressed SEC1 P-256 point.
pub const POINT: usize = 65;
/// The ECDH shared secret: the shared point's x coordinate.
pub const SHARED: usize = 32;

/// A key-agreement key the helper just made: what the daemon keeps (the blob, framed) and its
/// public point.
pub struct MadeAgreement {
    pub stored: Stored,
    pub point: [u8; POINT],
}

/// A key-agreement key held by the helper's device, its blob checked against its point.
pub struct HelperAgreement {
    helper: Helper,
    blob: Stored,
    point: [u8; POINT],
}

impl std::fmt::Debug for HelperAgreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperAgreement")
            .field("backend", &self.helper.config.backend)
            .finish_non_exhaustive()
    }
}

/// An uncompressed P-256 point on the curve, or why not.
fn checked_point(bytes: &[u8]) -> Result<[u8; POINT], HelperError> {
    let point: [u8; POINT] = bytes
        .try_into()
        .map_err(|_| HelperError::Malformed("not an uncompressed P-256 point"))?;
    if point.first() != Some(&4) {
        return Err(HelperError::Malformed("not an uncompressed P-256 point"));
    }
    p256::PublicKey::from_sec1_bytes(&point)
        .map_err(|_| HelperError::Malformed("not a point on P-256"))?;
    Ok(point)
}

fn frame(point: &[u8; POINT], blob: &[u8]) -> Stored {
    let mut framed = AGREEMENT_FRAME.to_vec();
    framed.extend_from_slice(&digest_under(AGREEMENT_FRAME, point, blob));
    framed.extend_from_slice(blob);
    Stored::new(framed)
}

/// The blob inside `stored`, if it is the frame made for the key-agreement key `point`:
/// checked by the daemon alone, before any helper or device sees it.
pub fn unframe(stored: &Stored, point: &[u8; POINT]) -> Result<Stored, &'static str> {
    let rest = stored
        .as_bytes()
        .strip_prefix(AGREEMENT_FRAME)
        .ok_or("its stored bytes are not a writ-se-agreement/1 frame")?;
    let (kept, blob) = rest
        .split_first_chunk::<DIGEST>()
        .ok_or("its stored bytes are cut")?;
    if blob.is_empty() || blob.len() > MAX_ANSWER {
        return Err("its stored blob's length is out of bounds");
    }
    if &digest_under(AGREEMENT_FRAME, point, blob) != kept {
        return Err("its stored bytes don't match their digest (corrupted, or another key's)");
    }
    Ok(Stored::new(blob.to_vec()))
}

impl HelperAgreement {
    /// Asks the helper for a new key-agreement key: its point checked, then proven by a probe
    /// agreement. The blob comes back framed, for the daemon to keep.
    pub fn create(config: &HelperConfig) -> Result<(Self, MadeAgreement), HelperError> {
        let helper = Helper::new(config.clone());
        let fields = helper.call(Op::CreateAgreement, &[b"p256"], 2)?;
        let [blob, point] = fields.as_slice() else {
            return Err(HelperError::Malformed(
                "not the fields the operation answers",
            ));
        };
        if blob.is_empty() || blob.len() > MAX_ANSWER {
            helper.end();
            return Err(HelperError::Malformed("a blob of no length"));
        }
        let point = checked_point(point).inspect_err(|_| helper.end())?;
        let agreement = Self {
            helper,
            blob: Stored::new(blob.clone()),
            point,
        };
        agreement.probe()?;
        let made = MadeAgreement {
            stored: frame(&point, blob),
            point,
        };
        Ok((agreement, made))
    }

    /// The key the daemon kept (`stored`, framed, and its `point`): the frame checked before
    /// the helper sees the blob, then the point the helper answers for it, then a probe
    /// agreement. Refused with why, never sent to the device otherwise.
    pub fn load(
        config: &HelperConfig,
        stored: &Stored,
        point: &[u8; POINT],
    ) -> Result<Self, String> {
        checked_point(point).map_err(|e| e.to_string())?;
        let blob = unframe(stored, point)?;
        let helper = Helper::new(config.clone());
        let answered = helper
            .call(Op::PublicAgreement, &[blob.as_bytes()], 1)
            .map_err(|e| e.to_string())?;
        let [answered] = answered.as_slice() else {
            return Err("not the fields the operation answers".to_owned());
        };
        let answered = checked_point(answered).map_err(|e| {
            helper.end();
            e.to_string()
        })?;
        if &answered != point {
            helper.end();
            return Err("the helper answers another key for its blob".to_owned());
        }
        let agreement = Self {
            helper,
            blob,
            point: *point,
        };
        agreement.probe().map_err(|e| e.to_string())?;
        Ok(agreement)
    }

    /// The key's public point, uncompressed.
    pub fn point(&self) -> &[u8; POINT] {
        &self.point
    }

    /// The ECDH shared secret with `peer` (an uncompressed P-256 point, checked on the curve
    /// before the helper sees it): exactly 32 bytes, in memory wiped on drop.
    pub fn agree(&self, peer: &[u8]) -> Result<Zeroizing<[u8; SHARED]>, HelperError> {
        // Refused here, never sent: the device sees only a point on the curve.
        let peer = checked_point(peer).map_err(|_| {
            HelperError::Malformed("the peer is not an uncompressed point on P-256")
        })?;
        let fields = self
            .helper
            .call(Op::Agree, &[self.blob.as_bytes(), &peer], 1)?;
        let [shared] = fields.as_slice() else {
            self.helper.end();
            return Err(HelperError::Malformed(
                "not the fields the operation answers",
            ));
        };
        let shared = Zeroizing::new(shared.clone());
        let mut out = Zeroizing::new([0u8; SHARED]);
        if shared.len() != SHARED {
            self.helper.end();
            return Err(HelperError::Malformed("a shared secret of another length"));
        }
        out.copy_from_slice(&shared);
        Ok(out)
    }

    /// Proves the helper's key is the one whose point it answered: an agreement with a fresh
    /// ephemeral point gives what that point and the ephemeral scalar give.
    fn probe(&self) -> Result<(), HelperError> {
        let scalar = loop {
            let bytes = Zeroizing::new(
                writ_crypto::keys::random_array::<32>()
                    .map_err(|_| HelperError::Spawn("no randomness for the probe".to_owned()))?,
            );
            if let Ok(secret) = p256::SecretKey::from_slice(bytes.as_slice()) {
                break secret;
            }
        };
        let peer = scalar.public_key().to_sec1_point(false);
        let answered = self.agree(peer.as_bytes())?;
        let point = p256::PublicKey::from_sec1_bytes(&self.point)
            .map_err(|_| HelperError::Malformed("not a point on P-256"))?;
        let expected = p256::elliptic_curve::ecdh::diffie_hellman(
            scalar.to_nonzero_scalar(),
            point.as_affine(),
        );
        // Not secret once compared (the probe's scalar is dropped): a plain comparison.
        if expected.raw_secret_bytes().as_slice() != answered.as_slice() {
            self.helper.end();
            return Err(HelperError::Malformed(
                "a shared secret its point doesn't give (another key's)",
            ));
        }
        Ok(())
    }
}
