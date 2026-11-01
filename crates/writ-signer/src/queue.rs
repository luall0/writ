//! [`QueuedSigner`]: a [`Signer`] in front of another, so a slow, hung or single-session
//! device never holds up its callers past a deadline (`docs/architecture/signer.md`).
//!
//! One worker thread owns the backend and signs one job at a time, in order. Callers put a
//! job in a bounded queue and wait for its answer until a deadline:
//!
//! - a full queue refuses at once ([`SignerError::Busy`]): nothing waits behind a stuck
//!   device without bound;
//! - past its deadline, a job is answered [`SignerError::Timeout`]; the worker skips a job
//!   whose caller already gave up (nothing is signed for nobody), and throws away a late
//!   result;
//! - [`Signer::list_keys`] and [`Signer::capabilities`] answer from what the backend said at
//!   startup, never through the queue: they must never wait behind the device.
//!
//! One queue per use (agent keys, the TLS key, the upstream credential), so a device stuck
//! on one use doesn't take the others down with it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, Instant};

use writ_core::names::KeyId;
use writ_crypto::ssh_key::Signature;

use crate::{Capabilities, KeyInfo, Signer, SignerError};

/// How a queue is sized.
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// The worker thread's name (`writ-sign-<use>`), for the daemon's diagnostics.
    pub name: String,
    /// Jobs that may wait while the worker signs one; past it, [`SignerError::Busy`].
    pub capacity: usize,
    /// How long a caller of [`Signer::sign`] waits for its signature.
    pub deadline: Duration,
}

type Answer = Result<Signature, SignerError>;

struct Job {
    id: KeyId,
    data: Vec<u8>,
    /// Set once its caller stopped waiting: the worker skips it.
    abandoned: Arc<AtomicBool>,
    /// Room for one answer: the worker never blocks on a caller that left.
    answer: SyncSender<Answer>,
}

/// A backend behind a bounded queue and one worker thread. See the module documentation.
pub struct QueuedSigner {
    jobs: SyncSender<Job>,
    keys: Vec<KeyInfo>,
    capabilities: Capabilities,
    deadline: Duration,
}

impl std::fmt::Debug for QueuedSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<&KeyId> = self.keys.iter().map(|k| &k.id).collect();
        f.debug_struct("QueuedSigner")
            .field("keys", &ids)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl QueuedSigner {
    /// Moves `backend` to a new worker thread, after reading its keys and capabilities once
    /// (what [`Signer::list_keys`] and [`Signer::capabilities`] answer from then on).
    pub fn new<S: Signer + 'static>(backend: S, config: QueueConfig) -> Result<Self, SignerError> {
        let keys = backend.list_keys()?;
        let capabilities = backend.capabilities();
        let (jobs, inbox) = std::sync::mpsc::sync_channel(config.capacity);
        std::thread::Builder::new()
            .name(config.name)
            .spawn(move || work(&backend, &inbox))
            .map_err(|_| SignerError::Unavailable)?;
        Ok(Self {
            jobs,
            keys,
            capabilities,
            deadline: config.deadline,
        })
    }

    /// Puts a signature in the queue, to be waited for until `deadline` from now
    /// ([`Pending::wait`]). An unknown key is refused here, and a full queue at once.
    pub fn submit(
        &self,
        id: &KeyId,
        data: &[u8],
        deadline: Duration,
    ) -> Result<Pending, SignerError> {
        if !self.keys.iter().any(|k| &k.id == id) {
            return Err(SignerError::UnknownKey(id.clone()));
        }
        let deadline = Instant::now()
            .checked_add(deadline)
            .ok_or(SignerError::Unavailable)?;
        let (answer, reply) = std::sync::mpsc::sync_channel(1);
        let abandoned = Arc::new(AtomicBool::new(false));
        let job = Job {
            id: id.clone(),
            data: data.to_vec(),
            abandoned: Arc::clone(&abandoned),
            answer,
        };
        match self.jobs.try_send(job) {
            Ok(()) => Ok(Pending {
                id: id.clone(),
                reply,
                deadline,
                abandoned,
            }),
            Err(TrySendError::Full(_)) => Err(SignerError::Busy),
            Err(TrySendError::Disconnected(_)) => Err(SignerError::Unavailable),
        }
    }
}

/// A signature in the queue. Dropping it (or a timed-out [`Pending::wait`]) gives up on it:
/// the worker skips it if it hasn't started it yet.
#[derive(Debug)]
pub struct Pending {
    id: KeyId,
    reply: Receiver<Answer>,
    deadline: Instant,
    abandoned: Arc<AtomicBool>,
}

impl Pending {
    /// Waits for the signature until the deadline: [`SignerError::Timeout`] past it (a result
    /// that comes later is thrown away).
    pub fn wait(self) -> Answer {
        let left = self.deadline.saturating_duration_since(Instant::now());
        match self.reply.recv_timeout(left) {
            Ok(answer) => answer,
            Err(RecvTimeoutError::Timeout) => Err(SignerError::Timeout(self.id.clone())),
            // The worker is gone (the backend panicked): nothing will answer.
            Err(RecvTimeoutError::Disconnected) => Err(SignerError::Unavailable),
        }
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.abandoned.store(true, Ordering::Release);
    }
}

/// The worker: one job at a time, in order, until the queue is dropped. A job whose caller
/// already gave up is skipped: nothing is signed for nobody.
fn work(backend: &dyn Signer, inbox: &Receiver<Job>) {
    for job in inbox {
        if job.abandoned.load(Ordering::Acquire) {
            continue;
        }
        let answer = backend.sign(&job.id, &job.data);
        // The caller may have left (its deadline passed meanwhile): the result is dropped.
        let _ = job.answer.try_send(answer);
    }
}

impl Signer for QueuedSigner {
    fn list_keys(&self) -> Result<Vec<KeyInfo>, SignerError> {
        Ok(self.keys.clone())
    }

    fn sign(&self, id: &KeyId, data: &[u8]) -> Result<Signature, SignerError> {
        self.submit(id, data, self.deadline)?.wait()
    }

    fn capabilities(&self) -> Capabilities {
        self.capabilities.clone()
    }
}
