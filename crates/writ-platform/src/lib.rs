//! Platform interfaces: everything that depends on the OS, the hardware or the deployment,
//! behind small traits with implementations picked at startup by `writd/src/platform.rs`.
//!
//! Each interface has its module (the trait and the types it uses), and each implementation a
//! file in that module's directory:
//!
//! | Trait | Portable implementation here |
//! |---|---|
//! | [`Clock`] | [`clock::system::SystemClock`] |
//! | [`Transport`] | [`transport::tcp::TcpTransport`] |
//! | [`CallerAttestor`] | [`attest::network::NetworkAttestor`] |
//! | [`SessionWatcher`] | [`watch::none::NoSessionWatcher`] |
//! | [`KeystoreUnlock`] | [`unlock::passphrase::PassphraseUnlock`] |
//! | [`Notifier`] | [`notify::telegram::TelegramNotifier`] (and [`notify::Notifiers`], a list of them) |
//!
//! Platform-only implementations live in `writ-platform-<os>` crates, laid out the same way.
//!
//! With the `testing` feature: a fake of each trait ([`testing`]) for the core crates' tests,
//! and the contract suite every implementation must pass ([`contract`]).
//!
//! A platform that can't provide a fact leaves it empty or reports
//! [`PlatformError::Unsupported`]; it never invents one. See docs/architecture/platform.md.

pub mod attest;
pub mod clock;
pub mod fs;
pub mod notify;
pub mod transport;
pub mod unlock;
pub mod watch;

#[cfg(feature = "testing")]
pub mod contract;
#[cfg(feature = "testing")]
pub mod testing;

pub use attest::CallerAttestor;
pub use clock::Clock;
pub use notify::{Notification, Notifier, Priority};
pub use transport::{AsyncStream, BoxFuture, Connection, PeerInfo, Transport};
pub use unlock::{DataKey, KeystoreUnlock, Passphrase, UnsealRequest};
pub use watch::{OnExit, SessionWatcher, WatchHandle};

/// Errors from platform implementations. Every caller treats them as a denial (fail closed).
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// This implementation can't do this at all (e.g. watching processes over TCP).
    #[error("{0} is not supported by this implementation")]
    Unsupported(&'static str),
    #[error("cannot attest the caller: {0}")]
    Attestation(String),
    /// Wrong passphrase, unreadable wrapped key, … Never contains the secret itself.
    #[error("cannot unlock the keystore: {0}")]
    Unlock(String),
    #[error("notification failed: {0}")]
    Notify(String),
    #[error("invalid configuration: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, PlatformError>;
