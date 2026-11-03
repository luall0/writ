//! The [`Signer`] interface: where the daemon's keys live and how they sign, so nothing
//! else depends on the backend (`docs/architecture/signer.md`).
//!
//! The daemon asks a signer for raw signatures over bytes it built itself (an SSHSIG's
//! signed data); it never sees a private key. Backends:
//!
//! - [`software`]: keys held in memory, wiped on drop (the sealed keystore that holds them at
//!   rest comes in M5).
//! - [`queue`]: a decorator in front of any backend, so a slow or hung device never holds
//!   up a caller past a deadline (one worker thread, a bounded queue).
//! - Hardware backends (Secure Enclave in `writ-platform-macos`, YubiKey) implement the same
//!   trait and run the same [`contract`] suite.
//!
//! With the `testing` feature: [`testing::FailingSigner`] (a backend that refuses on demand),
//! [`testing::GatedSigner`] (one that blocks until the test releases it) and the [`contract`]
//! suite every backend passes.

pub mod queue;
pub mod software;
pub mod tls;

#[cfg(feature = "testing")]
pub mod contract;
#[cfg(feature = "testing")]
pub mod testing;

use writ_core::names::KeyId;
use writ_crypto::ssh_key::{Algorithm, PrivateKey, PublicKey, Signature};

/// Why a signer didn't sign. Never holds key material.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("the signer has no key {0}")]
    UnknownKey(KeyId),
    #[error("the signer has two keys named {0}")]
    DuplicateKey(KeyId),
    #[error("key {id}: algorithm {algorithm} is not supported by this backend")]
    Unsupported { id: KeyId, algorithm: String },
    /// The backend failed (a device error, a refused operation). The cause stays out of the
    /// message: a backend's error could say more than a client should see.
    #[error("the signer failed to sign with key {0}")]
    Failed(KeyId),
    /// Too many signatures already wait for the device ([`queue::QueuedSigner`]).
    #[error("the signer is busy: too many signatures are waiting")]
    Busy,
    /// The device didn't sign before the deadline ([`queue::QueuedSigner`]).
    #[error("the signer did not sign with key {0} in time")]
    Timeout(KeyId),
    /// The signer can't take a job: its worker couldn't start, or stopped.
    #[error("the signer is unavailable")]
    Unavailable,
    /// The backend takes no key made outside it ([`Signer::add_key`]): a device that makes
    /// its own keys.
    #[error("key {0}: this signer backend takes no key made outside it")]
    CannotTakeKeys(KeyId),
}

/// A key a backend exposes: its id (what templates name in `signing_key`) and its public
/// half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub id: KeyId,
    pub public_key: PublicKey,
}

/// What a backend can do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// The algorithms of the keys it holds.
    pub algorithms: Vec<Algorithm>,
    /// Whether its keys can be read out (software keys can, by whoever holds the daemon's
    /// memory or keystore; a hardware key can't).
    pub exportable: bool,
    /// Whether signing needs someone to touch the device (never for an agent key: signing
    /// happens unattended).
    pub needs_touch: bool,
    /// Whether [`Signer::add_key`] takes a key made outside the backend (a software backend
    /// does; a device that makes its own keys doesn't).
    pub takes_keys: bool,
}

/// Where keys live and how they sign. Used as a trait object (`Arc<dyn Signer>`).
pub trait Signer: Send + Sync {
    /// The keys this backend exposes (public parts only).
    fn list_keys(&self) -> Result<Vec<KeyInfo>, SignerError>;
    /// Signs raw `data` with the key `id`. The caller builds what is signed (an SSHSIG's
    /// signed data) and wraps the signature; the signature is in SSH encoding.
    fn sign(&self, id: &KeyId, data: &[u8]) -> Result<Signature, SignerError>;
    /// What this backend can do.
    fn capabilities(&self) -> Capabilities;
    /// Takes `key`, made outside the backend, under `id` (moved in, never copied), usable at
    /// once; answers its [`KeyInfo`]. An id it holds already is [`SignerError::DuplicateKey`],
    /// an algorithm it doesn't hold [`SignerError::Unsupported`]. A backend that takes no key
    /// from outside (a device makes its own: M7.5 brings that verb) keeps this default,
    /// [`SignerError::CannotTakeKeys`], and says so in [`Capabilities::takes_keys`].
    fn add_key(&self, id: KeyId, key: PrivateKey) -> Result<KeyInfo, SignerError> {
        drop(key);
        Err(SignerError::CannotTakeKeys(id))
    }
}

/// A shared signer is a signer (a decorator can hold one the daemon or a test holds too).
impl<S: Signer + ?Sized> Signer for std::sync::Arc<S> {
    fn list_keys(&self) -> Result<Vec<KeyInfo>, SignerError> {
        (**self).list_keys()
    }

    fn sign(&self, id: &KeyId, data: &[u8]) -> Result<Signature, SignerError> {
        (**self).sign(id, data)
    }

    fn capabilities(&self) -> Capabilities {
        (**self).capabilities()
    }

    fn add_key(&self, id: KeyId, key: PrivateKey) -> Result<KeyInfo, SignerError> {
        (**self).add_key(id, key)
    }
}

/// The public key of `id`, from the signer's list.
pub fn public_key(signer: &dyn Signer, id: &KeyId) -> Result<PublicKey, SignerError> {
    signer
        .list_keys()?
        .into_iter()
        .find(|key| &key.id == id)
        .map(|key| key.public_key)
        .ok_or_else(|| SignerError::UnknownKey(id.clone()))
}

/// An SSHSIG over `msg` in `namespace`, signed by the key `id` through `signer`: the armored
/// text git's `ssh-keygen -Y sign` would write.
pub fn sshsig(
    signer: &dyn Signer,
    id: &KeyId,
    namespace: &str,
    msg: &[u8],
) -> Result<String, SignerError> {
    let public = public_key(signer, id)?;
    let failed = |_| SignerError::Failed(id.clone());
    let data = writ_crypto::sshsig::signed_data(namespace, msg).map_err(failed)?;
    let signature = signer.sign(id, &data)?;
    writ_crypto::sshsig::assemble(public.key_data(), namespace, signature).map_err(failed)
}
