//! The host key scan (`writ admin host add`, on an approver's signed `writ-scan/1`): one SSH
//! handshake to the host per key algorithm Writ verifies (Ed25519, ECDSA P-256 and P-384), each
//! asking for that algorithm alone and dropped once the host proved it holds the key (russh
//! checks the key exchange's signature before it shows the key), before any authentication.
//! Bounded: a deadline for each handshake (`mirrors.scan_timeout`, [`DEFAULT_HANDSHAKE_DEADLINE`]
//! by default: some hosts are slow to answer), the whole scan within [`MAX_HANDSHAKES`] of them,
//! at most [`MAX_KEYS`] keys. What comes back is shown, never pinned: a second signed change
//! pins it, once the approver compared it with what the remote publishes. A host offering only
//! RSA or P-521 keys answers none: its keys are given to `writ admin host add` instead.

use std::borrow::Cow;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ssh_key::{Algorithm, EcdsaCurve, PublicKey};

/// The handshakes one scan makes: one per algorithm.
pub const MAX_HANDSHAKES: usize = 3;

/// The most keys one scan returns.
pub const MAX_KEYS: usize = 3;

/// The longest one handshake takes unless `mirrors.scan_timeout` says otherwise.
pub const DEFAULT_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);

/// The algorithms asked for, one handshake each.
const ALGORITHMS: [Algorithm; MAX_HANDSHAKES] = [
    Algorithm::Ed25519,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
];

/// Why a scan read no key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScanError {
    /// The host can't be reached (refused, unknown, silent past the deadline).
    #[error("cannot reach {target}: {why}")]
    Unreachable { target: String, why: String },
    /// It answered, with no key of an algorithm Writ verifies.
    #[error(
        "{target} offers no Ed25519, P-256 or P-384 host key: give its keys to writ admin host \
         add instead"
    )]
    NoKey { target: String },
}

/// Holds the key the host shows, and refuses to go on: the handshake ends there.
struct Capture(Arc<Mutex<Option<PublicKey>>>);

impl russh::client::Handler for Capture {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        if let russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } = server_public_key {
            *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(key.clone());
        }
        // Never authenticate: the key is all a scan wants.
        Ok(false)
    }
}

/// One handshake asking for `algorithm`: the key the host proved it holds, none when it has
/// no key of it, or why it can't be reached.
async fn handshake(
    host: &str,
    port: u16,
    algorithm: Algorithm,
    deadline: Duration,
) -> Result<Option<PublicKey>, String> {
    let algorithms: Vec<Algorithm> = vec![algorithm];
    let config = Arc::new(russh::client::Config {
        inactivity_timeout: Some(deadline),
        preferred: russh::Preferred {
            key: Cow::Owned(algorithms),
            ..russh::Preferred::DEFAULT
        },
        ..Default::default()
    });
    let seen = Arc::new(Mutex::new(None));
    let handler = Capture(seen.clone());
    let attempt = tokio::time::timeout(
        deadline,
        russh::client::connect(config, (host, port), handler),
    )
    .await;
    let key = seen.lock().unwrap_or_else(PoisonError::into_inner).take();
    match (attempt, key) {
        (_, Some(key)) => Ok(Some(key)),
        (Err(_), None) => Err(format!(
            "no answer within {}s (mirrors.scan_timeout)",
            deadline.as_secs()
        )),
        // Connected, the algorithm not offered: no key of it.
        (Ok(Err(russh::Error::NoCommonAlgo { .. })), None) => Ok(None),
        (Ok(Err(russh::Error::IO(e))), None) => Err(e.kind().to_string()),
        (Ok(Err(e)), None) => Err(crate::shown(e.to_string().as_bytes())),
        (Ok(Ok(_)), None) => Ok(None),
    }
}

/// Scans `host` on `port`, each handshake within `deadline`: the keys it holds of each
/// algorithm Writ verifies, each once.
pub async fn scan(host: &str, port: u16, deadline: Duration) -> Result<Vec<PublicKey>, ScanError> {
    let target = format!("{host}:{port}");
    let mut keys: Vec<PublicKey> = Vec::new();
    for algorithm in ALGORITHMS {
        match handshake(host, port, algorithm, deadline).await {
            Ok(Some(key)) => {
                if keys.len() < MAX_KEYS && !keys.iter().any(|k| k.key_data() == key.key_data()) {
                    keys.push(key);
                }
            }
            Ok(None) => {}
            // Not reached once: the next handshakes would fail the same way.
            Err(why) if keys.is_empty() => {
                return Err(ScanError::Unreachable { target, why });
            }
            Err(_) => {}
        }
    }
    if keys.is_empty() {
        return Err(ScanError::NoKey { target });
    }
    Ok(keys)
}
