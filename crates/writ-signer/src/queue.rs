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
//!   startup, never through the queue: they must never wait behind the device;
//! - [`Signer::add_key`] goes through the queue like a signature (in order with the jobs
//!   before it, bounded and with the same deadline); once the backend took the key, the worker
//!   refreshes what `list_keys` and `capabilities` answer from;
//! - a backend that panics is not trusted again: the worker answers that job
//!   [`SignerError::Unavailable`], logs it once, and stops; every later signature is
//!   `Unavailable` until the daemon restarts (fail closed, and said once where it happened).
//!
//! One queue per use (agent keys, the TLS key, the upstream credential), so a device stuck
//! on one use doesn't take the others down with it.

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use writ_core::names::KeyId;
use writ_crypto::algorithm::SignerHash;
use writ_crypto::keypair::{KeyPair, RawSignature};

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

type Answer = Result<RawSignature, SignerError>;

/// What a job asks the backend for.
enum Work {
    Sign {
        data: Vec<u8>,
        hash: SignerHash,
        /// Room for one answer: the worker never blocks on a caller that left.
        answer: SyncSender<Answer>,
    },
    Add {
        /// Boxed: a key is far larger than a signature job.
        key: Box<KeyPair>,
        answer: SyncSender<Result<KeyInfo, SignerError>>,
    },
    Remove {
        answer: SyncSender<Result<(), SignerError>>,
    },
}

struct Job {
    id: KeyId,
    work: Work,
    /// Set once its caller stopped waiting: the worker skips it.
    abandoned: Arc<AtomicBool>,
}

/// What the backend said it holds and can do: read by `list_keys` and `capabilities`, written
/// by the worker when a key is added.
struct Known {
    keys: Vec<KeyInfo>,
    capabilities: Capabilities,
}

/// A backend behind a bounded queue and one worker thread. See the module documentation.
pub struct QueuedSigner {
    jobs: SyncSender<Job>,
    known: Arc<RwLock<Known>>,
    deadline: Duration,
}

impl std::fmt::Debug for QueuedSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let known = self.known();
        let ids: Vec<&KeyId> = known.keys.iter().map(|k| &k.id).collect();
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
        let known = Arc::new(RwLock::new(Known {
            keys: backend.list_keys()?,
            capabilities: backend.capabilities(),
        }));
        let (jobs, inbox) = std::sync::mpsc::sync_channel(config.capacity);
        // The worker logs where its creator does (the daemon's subscriber).
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let name = config.name.clone();
        let refreshed = Arc::clone(&known);
        std::thread::Builder::new()
            .name(config.name)
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    work(&name, &backend, &inbox, &refreshed);
                });
            })
            .map_err(|_| SignerError::Unavailable)?;
        Ok(Self {
            jobs,
            known,
            deadline: config.deadline,
        })
    }

    // poisoned: the worker replaces the whole value at once; the last one written stands.
    fn known(&self) -> std::sync::RwLockReadGuard<'_, Known> {
        self.known.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues `work` for the key `id`: a full queue refuses at once.
    fn queue(&self, id: &KeyId, work: Work) -> Result<Arc<AtomicBool>, SignerError> {
        let abandoned = Arc::new(AtomicBool::new(false));
        let job = Job {
            id: id.clone(),
            work,
            abandoned: Arc::clone(&abandoned),
        };
        match self.jobs.try_send(job) {
            Ok(()) => Ok(abandoned),
            Err(TrySendError::Full(_)) => Err(SignerError::Busy),
            Err(TrySendError::Disconnected(_)) => Err(SignerError::Unavailable),
        }
    }

    /// Puts a signature in the queue, to be waited for until `deadline` from now
    /// ([`Pending::wait`]). An unknown key is refused here, and a full queue at once.
    pub fn submit(
        &self,
        id: &KeyId,
        data: &[u8],
        hash: SignerHash,
        deadline: Duration,
    ) -> Result<Pending, SignerError> {
        if !self.known().keys.iter().any(|k| &k.id == id) {
            return Err(SignerError::UnknownKey(id.clone()));
        }
        let deadline = Instant::now()
            .checked_add(deadline)
            .ok_or(SignerError::Unavailable)?;
        let (answer, reply) = std::sync::mpsc::sync_channel(1);
        let work = Work::Sign {
            data: data.to_vec(),
            hash,
            answer,
        };
        let abandoned = self.queue(id, work)?;
        Ok(Pending {
            id: id.clone(),
            reply,
            deadline,
            abandoned,
        })
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
/// already gave up is skipped: nothing is signed for nobody, and no key is added for nobody
/// (it is dropped, wiped). Once a key is added, `known` is refreshed from the backend. A
/// backend that panics ends it: that job is answered `Unavailable`, the panic logged once,
/// and the jobs still queued are dropped with the inbox (their callers read `Unavailable`, as
/// every later one does).
fn work(name: &str, backend: &dyn Signer, inbox: &Receiver<Job>, known: &RwLock<Known>) {
    for job in inbox {
        if job.abandoned.load(Ordering::Acquire) {
            continue;
        }
        let Job { id, work, .. } = job;
        // Not unwind-safe in general; it doesn't matter: after a panic the backend is never
        // called again.
        // The caller may have left meanwhile (its deadline passed): an answer is then dropped.
        let survived = match work {
            Work::Sign { data, hash, answer } => {
                match std::panic::catch_unwind(AssertUnwindSafe(|| backend.sign(&id, &data, hash)))
                {
                    Ok(signed) => {
                        let _ = answer.try_send(signed);
                        true
                    }
                    Err(_) => {
                        let _ = answer.try_send(Err(SignerError::Unavailable));
                        false
                    }
                }
            }
            Work::Add { key, answer } => {
                let added = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    let added = backend.add_key(id.clone(), *key);
                    if added.is_ok() {
                        refresh(backend, known);
                    }
                    added
                }));
                match added {
                    Ok(added) => {
                        let _ = answer.try_send(added);
                        true
                    }
                    Err(_) => {
                        let _ = answer.try_send(Err(SignerError::Unavailable));
                        false
                    }
                }
            }
            Work::Remove { answer } => {
                let removed = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    let removed = backend.remove_key(&id);
                    if removed.is_ok() {
                        refresh(backend, known);
                    }
                    removed
                }));
                match removed {
                    Ok(removed) => {
                        let _ = answer.try_send(removed);
                        true
                    }
                    Err(_) => {
                        let _ = answer.try_send(Err(SignerError::Unavailable));
                        false
                    }
                }
            }
        };
        if !survived {
            tracing::error!(
                queue = name,
                key = %id,
                "the signer backend panicked: this queue signs nothing more until the daemon \
                 restarts"
            );
            return;
        }
    }
}

/// Reads again what the backend holds and can do, after a key was added. A backend that can't
/// list its keys any more keeps the last list (its signatures then fail on their own).
fn refresh(backend: &dyn Signer, known: &RwLock<Known>) {
    if let Ok(keys) = backend.list_keys() {
        let capabilities = backend.capabilities();
        *known.write().unwrap_or_else(PoisonError::into_inner) = Known { keys, capabilities };
    }
}

impl Signer for QueuedSigner {
    fn list_keys(&self) -> Result<Vec<KeyInfo>, SignerError> {
        Ok(self.known().keys.clone())
    }

    fn sign(&self, id: &KeyId, data: &[u8], hash: SignerHash) -> Answer {
        self.submit(id, data, hash, self.deadline)?.wait()
    }

    fn capabilities(&self) -> Capabilities {
        self.known().capabilities.clone()
    }

    /// Through the queue, in order with the jobs before it, until the deadline. Past it the
    /// caller gets [`SignerError::Timeout`]; the worker skips the key if it hasn't reached it
    /// yet, or adds it all the same if it has (then it is listed, and adding it again is
    /// [`SignerError::DuplicateKey`]).
    fn add_key(&self, id: KeyId, key: KeyPair) -> Result<KeyInfo, SignerError> {
        if !self.known().capabilities.takes_keys {
            drop(key);
            return Err(SignerError::CannotTakeKeys(id));
        }
        let deadline = Instant::now()
            .checked_add(self.deadline)
            .ok_or(SignerError::Unavailable)?;
        let (answer, reply) = std::sync::mpsc::sync_channel(1);
        let abandoned = self.queue(
            &id,
            Work::Add {
                key: Box::new(key),
                answer,
            },
        )?;
        let left = deadline.saturating_duration_since(Instant::now());
        let answer = match reply.recv_timeout(left) {
            Ok(answer) => answer,
            Err(RecvTimeoutError::Timeout) => Err(SignerError::Timeout(id)),
            Err(RecvTimeoutError::Disconnected) => Err(SignerError::Unavailable),
        };
        abandoned.store(true, Ordering::Release);
        answer
    }

    /// Through the queue, in order with the jobs before it (a signature queued before the
    /// removal still signs; none queued after it does), until the deadline. Past it the caller
    /// gets [`SignerError::Timeout`]; the worker skips the removal if it hasn't reached it yet,
    /// or removes the key all the same if it has.
    fn remove_key(&self, id: &KeyId) -> Result<(), SignerError> {
        if !self.known().capabilities.takes_keys {
            return Err(SignerError::CannotTakeKeys(id.clone()));
        }
        let deadline = Instant::now()
            .checked_add(self.deadline)
            .ok_or(SignerError::Unavailable)?;
        let (answer, reply) = std::sync::mpsc::sync_channel(1);
        let abandoned = self.queue(id, Work::Remove { answer })?;
        let left = deadline.saturating_duration_since(Instant::now());
        let answer = match reply.recv_timeout(left) {
            Ok(answer) => answer,
            Err(RecvTimeoutError::Timeout) => Err(SignerError::Timeout(id.clone())),
            Err(RecvTimeoutError::Disconnected) => Err(SignerError::Unavailable),
        };
        abandoned.store(true, Ordering::Release);
        answer
    }
}
