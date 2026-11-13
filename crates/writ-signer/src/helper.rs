//! [`HelperSigner`]: a [`Signer`] over a helper process that makes and uses keys the daemon
//! can't (`docs/architecture/signer.md`): the Secure Enclave's, through CryptoKit, which has
//! no C or Rust API and crashes the process on a corrupted blob. The helper is a separate
//! program (`writ-se` on macOS), so its crash costs one job, never the daemon.
//!
//! The protocol, `writ-se/1`, over the helper's stdin and stdout, one request at a time:
//! frames of a 4-byte big-endian length and a body; a request is an operation byte then its
//! fields, an answer a status byte (0 ok, 1 refused) then its fields, each field a 4-byte
//! length and its bytes.
//!
//! | Operation | Fields | Answer |
//! |---|---|---|
//! | `hello` (1) | none | the protocol's name |
//! | `create` (2) | the algorithm (`p256`) | the key's stored bytes, its public point (SEC1, uncompressed) |
//! | `public` (3) | stored bytes | the public point |
//! | `sign` (4) | stored bytes, the data | the signature over the data's SHA-256, `r ‖ s` |
//! | `create-agreement` (5) | the algorithm (`p256`) | a key-agreement key's stored bytes, its public point (M7.6, [`agreement`]) |
//! | `public-agreement` (6) | stored bytes | its public point |
//! | `agree` (7) | stored bytes, a peer point (SEC1, uncompressed) | the ECDH shared secret (its x coordinate, 32 bytes) |
//! | refused | | a code: at most 64 bytes of `[a-z0-9-]` |
//!
//! The helper keeps no state: each request carries its stored bytes, so a new helper answers
//! as the old one did. **What it answers is untrusted**: an answer past [`MAX_ANSWER`], a
//! field count or length other than the operation's, a point that isn't one, a code outside
//! its alphabet, a public point other than the key's, or a signature that doesn't verify with
//! the key's public half (checked on every signature, before it leaves) is refused and logged.
//! A helper that dies, answers wrong or stays silent past its deadline is killed; the job is
//! refused and the next one starts a new helper. Started with an empty environment, its
//! stderr discarded. P-256 with SHA-256 is the only pair it signs with in this build.
//!
//! **No blob reaches the device unless it is the one the device made for that key.** A
//! malformed blob does more than crash the helper: one made the Secure Enclave's firmware
//! panic and the Mac with it (2026-11-12). So what the daemon keeps for a key ([`Stored`]) is
//! the blob framed with a digest: `writ-se-blob/1\n`, then SHA-256 over that header, the key's
//! public point and the blob, then the blob. When the signer is built, each key's frame is
//! checked against the public half the daemon kept **before** the helper sees its blob: a
//! frame that doesn't check (corrupted, cut, another key's, not a frame) never leaves the
//! daemon. Only then is the helper asked for the blob's point, which must be the key's.
//!
//! A key whose stored bytes are refused when the signer is built stays listed from the public
//! half the daemon kept, and every signature with it is refused ([`SignerError::Unusable`]):
//! the daemon keeps running and its other keys sign. [`HelperSigner::refused`] says which, for
//! the daemon's log and audit log.

pub mod agreement;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Mutex, PoisonError, RwLock};
use std::time::Duration;

use sha2::{Digest, Sha256};
use writ_core::names::KeyId;
use writ_crypto::algorithm::{Hash, KeyAlgorithm, SignerHash};
use writ_crypto::keypair::RawSignature;
use writ_crypto::ssh_key::PublicKey;
use writ_crypto::ssh_key::public::{EcdsaPublicKey, KeyData};

use crate::{Capabilities, Created, KeyInfo, Signer, SignerError, Stored};

/// The protocol's name, what `hello` answers.
pub const PROTOCOL: &str = "writ-se/1";

/// The largest answer read from the helper: far more than a blob, a point or a signature.
pub const MAX_ANSWER: usize = 64 * 1024;

/// The largest data signed through the helper: a sign request's whole body
/// (`writ_proto::sign::MAX_SIGN_INPUT`, 16 MiB) and room for its blob.
pub const MAX_DATA: usize = 16 * 1024 * 1024;

/// The largest request written (the data, its blob and the framing).
const MAX_REQUEST: usize = MAX_DATA + MAX_ANSWER;

/// The longest refusal code.
const MAX_CODE: usize = 64;

/// The pair a helper signs with.
const PAIR: (KeyAlgorithm, SignerHash) = (KeyAlgorithm::P256, Some(Hash::Sha256));

/// What a stored frame starts with ([`frame`]).
const FRAME: &[u8] = b"writ-se-blob/1\n";

/// The length of a frame's digest.
const DIGEST: usize = 32;

/// The digest of `blob` for the key whose public point is `point`.
fn digest(point: &[u8], blob: &[u8]) -> [u8; DIGEST] {
    digest_under(FRAME, point, blob)
}

/// The digest of `blob` for the key whose public point is `point`, framed under `header` (a
/// signing key's, or a key-agreement key's: a blob of one kind never passes for the other).
fn digest_under(header: &[u8], point: &[u8], blob: &[u8]) -> [u8; DIGEST] {
    let mut hash = Sha256::new();
    hash.update(header);
    hash.update(point);
    hash.update(blob);
    hash.finalize().into()
}

/// The public point of a P-256 public key (SEC1, uncompressed), or None for another key.
fn point_of(public: &PublicKey) -> Option<&[u8]> {
    match public.key_data() {
        KeyData::Ecdsa(key @ EcdsaPublicKey::NistP256(_)) => Some(key.as_sec1_bytes()),
        _ => None,
    }
}

/// What the daemon keeps for a key the helper made: the blob framed with its digest.
fn frame(public: &PublicKey, blob: &[u8]) -> Result<Stored, HelperError> {
    let point = point_of(public).ok_or(HelperError::Malformed("not a P-256 point"))?;
    let mut framed = FRAME.to_vec();
    framed.extend_from_slice(&digest(point, blob));
    framed.extend_from_slice(blob);
    Ok(Stored::new(framed))
}

/// The blob inside `stored`, if `stored` is the frame made for the key `public`: checked by
/// the daemon alone, before any helper or device sees it.
fn unframe(stored: &Stored, public: &PublicKey) -> Result<Stored, &'static str> {
    let point = point_of(public).ok_or("the public half kept for it is not a P-256 key")?;
    let rest = stored
        .as_bytes()
        .strip_prefix(FRAME)
        .ok_or("its stored bytes are not a writ-se-blob/1 frame")?;
    let (kept, blob) = rest
        .split_first_chunk::<DIGEST>()
        .ok_or("its stored bytes are cut")?;
    if blob.is_empty() || blob.len() > MAX_ANSWER {
        return Err("its stored blob's length is out of bounds");
    }
    // Not secret (the digest of a blob the daemon holds): a plain comparison.
    if &digest(point, blob) != kept {
        return Err("its stored bytes don't match their digest (corrupted, or another key's)");
    }
    Ok(Stored::new(blob.to_vec()))
}

/// The bytes signed when a key is made, to prove the point answered is the key's.
const PROBE: &[u8] = b"writ-se/1 probe: the key just made signs";

/// The (algorithm, signer hash) pairs a helper signs with: P-256 with SHA-256.
pub fn pairs() -> Vec<(KeyAlgorithm, SignerHash)> {
    vec![PAIR]
}

/// How to start the helper.
#[derive(Debug, Clone)]
pub struct HelperConfig {
    /// The backend's name in the policy (`se-cryptokit`), for the log.
    pub backend: String,
    /// The program, by absolute path.
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// How long one request may take, from its write to its answer.
    pub deadline: Duration,
}

/// A key the daemon gives back to the backend: its id, what it stored, and the public half
/// it kept beside it.
pub struct Load {
    pub id: KeyId,
    pub stored: Stored,
    pub public: PublicKey,
}

/// Why the helper didn't answer what was asked. Says nothing of a key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HelperError {
    #[error("the helper could not start: {0}")]
    Spawn(String),
    #[error("the helper died")]
    Died,
    #[error("the helper did not answer in time")]
    Silent,
    #[error("the helper's answer is larger than {MAX_ANSWER} bytes")]
    Oversized,
    #[error("the helper's answer is malformed: {0}")]
    Malformed(&'static str),
    /// The helper refused, with its code.
    #[error("the helper refused: {0}")]
    Refused(String),
    #[error("the request is larger than the helper takes")]
    TooLarge,
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum Op {
    Hello = 1,
    Create = 2,
    Public = 3,
    Sign = 4,
    CreateAgreement = 5,
    PublicAgreement = 6,
    Agree = 7,
}

/// A running helper: its stdin, and the answers its reader thread reads from its stdout.
struct Process {
    child: Child,
    stdin: ChildStdin,
    answers: Receiver<Result<Vec<u8>, HelperError>>,
}

impl Process {
    fn spawn(config: &HelperConfig) -> Result<Self, HelperError> {
        // By absolute path only: a relative one would be looked up wherever the daemon runs.
        if !config.program.is_absolute() {
            return Err(HelperError::Spawn("its path is not absolute".to_owned()));
        }
        let mut child = Command::new(&config.program)
            .args(&config.args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| HelperError::Spawn(e.kind().to_string()))?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(HelperError::Spawn("no pipe".to_owned()));
        };
        let (send, answers) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name(format!("{}-reader", config.backend))
            .spawn(move || read_answers(stdout, &send))
            .map_err(|e| HelperError::Spawn(e.kind().to_string()))?;
        Ok(Self {
            child,
            stdin,
            answers,
        })
    }

    fn end(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reads frames until the helper's stdout ends or breaks; the last thing sent says why.
fn read_answers(
    mut stdout: ChildStdout,
    send: &std::sync::mpsc::SyncSender<Result<Vec<u8>, HelperError>>,
) {
    loop {
        let frame = read_frame(&mut stdout);
        let stop = frame.is_err();
        if send.send(frame).is_err() || stop {
            return;
        }
    }
}

fn read_frame(from: &mut impl Read) -> Result<Vec<u8>, HelperError> {
    let mut len = [0u8; 4];
    from.read_exact(&mut len).map_err(|_| HelperError::Died)?;
    let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| HelperError::Oversized)?;
    if len > MAX_ANSWER {
        return Err(HelperError::Oversized);
    }
    let mut body = vec![0u8; len];
    from.read_exact(&mut body).map_err(|_| HelperError::Died)?;
    Ok(body)
}

/// A request's body: the operation, then each field with its length.
fn request(op: Op, fields: &[&[u8]]) -> Result<Vec<u8>, HelperError> {
    let mut body = vec![op as u8];
    for field in fields {
        let len = u32::try_from(field.len()).map_err(|_| HelperError::TooLarge)?;
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(field);
    }
    if body.len() > MAX_REQUEST {
        return Err(HelperError::TooLarge);
    }
    let len = u32::try_from(body.len()).map_err(|_| HelperError::TooLarge)?;
    let mut frame = len.to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// An answer's fields, exactly `count` of them, or the helper's refusal.
fn answer(body: &[u8], count: usize) -> Result<Vec<&[u8]>, HelperError> {
    let (&status, mut rest) = body.split_first().ok_or(HelperError::Malformed("empty"))?;
    let mut fields = Vec::new();
    while !rest.is_empty() {
        let (len, after) = rest
            .split_first_chunk::<4>()
            .ok_or(HelperError::Malformed("a field's length is cut"))?;
        let len = usize::try_from(u32::from_be_bytes(*len))
            .map_err(|_| HelperError::Malformed("length"))?;
        if after.len() < len {
            return Err(HelperError::Malformed("a field is cut"));
        }
        let (field, after) = after.split_at(len);
        fields.push(field);
        rest = after;
    }
    match status {
        0 if fields.len() == count => Ok(fields),
        0 => Err(HelperError::Malformed(
            "not the fields the operation answers",
        )),
        1 => match fields.as_slice() {
            [code] if code_is_clean(code) => Err(HelperError::Refused(
                String::from_utf8_lossy(code).into_owned(),
            )),
            _ => Err(HelperError::Malformed("a refusal that isn't one code")),
        },
        _ => Err(HelperError::Malformed("an unknown status")),
    }
}

fn code_is_clean(code: &[u8]) -> bool {
    !code.is_empty()
        && code.len() <= MAX_CODE
        && code
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// A P-256 public point (SEC1, uncompressed) as a public key.
fn point(bytes: &[u8]) -> Result<PublicKey, HelperError> {
    if bytes.len() != 65 || bytes.first() != Some(&4) {
        return Err(HelperError::Malformed("not an uncompressed P-256 point"));
    }
    // On the curve: the encoding alone doesn't say (`EcdsaPublicKey` doesn't check).
    p256::PublicKey::from_sec1_bytes(bytes)
        .map_err(|_| HelperError::Malformed("not a point on P-256"))?;
    let key = EcdsaPublicKey::from_sec1_bytes(bytes)
        .map_err(|_| HelperError::Malformed("not a P-256 point"))?;
    if !matches!(key, EcdsaPublicKey::NistP256(_)) {
        return Err(HelperError::Malformed("not a P-256 point"));
    }
    Ok(PublicKey::new(KeyData::Ecdsa(key), ""))
}

/// The helper itself: started on first use, again after it failed.
struct Helper {
    config: HelperConfig,
    process: Mutex<Option<Process>>,
}

impl Helper {
    /// A helper that starts on its first request.
    fn new(config: HelperConfig) -> Self {
        Self {
            config,
            process: Mutex::new(None),
        }
    }

    /// Sends one request and waits for its answer, until the deadline. Any failure but the
    /// helper's own refusal ends the process: the next request starts a new one.
    fn call(&self, op: Op, fields: &[&[u8]], count: usize) -> Result<Vec<Vec<u8>>, HelperError> {
        let frame = request(op, fields)?;
        let mut held = self.process.lock().unwrap_or_else(PoisonError::into_inner);
        if held.is_none() {
            *held = Some(Process::spawn(&self.config)?);
        }
        let Some(process) = held.as_mut() else {
            return Err(HelperError::Died);
        };
        let answered = (|| {
            process
                .stdin
                .write_all(&frame)
                .and_then(|()| process.stdin.flush())
                .map_err(|_| HelperError::Died)?;
            let body = match process.answers.recv_timeout(self.config.deadline) {
                Ok(body) => body?,
                Err(RecvTimeoutError::Timeout) => return Err(HelperError::Silent),
                Err(RecvTimeoutError::Disconnected) => return Err(HelperError::Died),
            };
            answer(&body, count).map(|fields| fields.into_iter().map(<[u8]>::to_vec).collect())
        })();
        match &answered {
            Ok(_) | Err(HelperError::Refused(_)) => {}
            Err(_) => {
                if let Some(process) = held.take() {
                    process.end();
                }
            }
        }
        answered
    }
}

impl Helper {
    /// Ends the running helper, if any: one whose well-formed answer was wrong (a point that
    /// isn't one, a signature that doesn't verify) is no more trusted than a broken one.
    fn end(&self) {
        if let Some(process) = self
            .process
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            process.end();
        }
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        if let Some(process) = self
            .process
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            process.end();
        }
    }
}

enum Held {
    /// The blob alone, its frame checked.
    Ready { blob: Stored, public: PublicKey },
    /// Refused when the signer was built: listed, never signed with.
    Unusable { public: PublicKey },
}

impl Held {
    fn public(&self) -> &PublicKey {
        match self {
            Held::Ready { public, .. } | Held::Unusable { public } => public,
        }
    }
}

/// Keys a helper process makes and signs with. See the module documentation.
pub struct HelperSigner {
    helper: Helper,
    keys: RwLock<BTreeMap<KeyId, Held>>,
    refused: Vec<(KeyId, String)>,
}

impl std::fmt::Debug for HelperSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys = self.read();
        f.debug_struct("HelperSigner")
            .field("backend", &self.helper.config.backend)
            .field("keys", &keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Starts the helper once and asks `hello`: whether it runs and speaks [`PROTOCOL`] (the
/// daemon's startup check). Its refusal code says why it can't (`no-secure-enclave`).
pub fn check(config: &HelperConfig) -> Result<(), HelperError> {
    let helper = Helper {
        config: config.clone(),
        process: Mutex::new(None),
    };
    let fields = helper.call(Op::Hello, &[], 1)?;
    match fields.as_slice() {
        [name] if name.as_slice() == PROTOCOL.as_bytes() => Ok(()),
        _ => Err(HelperError::Malformed("another protocol")),
    }
}

impl HelperSigner {
    /// A signer over the helper `config` starts, holding the keys `keys` gives back: each
    /// one's frame checked against the public half the daemon kept (before the helper sees
    /// its blob), then the blob's point asked of the helper. One whose frame doesn't check,
    /// or the helper refuses or answers another point for, is held unusable and said in
    /// [`HelperSigner::refused`] (and the daemon's log); two keys with one id are refused.
    pub fn new(
        config: HelperConfig,
        keys: impl IntoIterator<Item = Load>,
    ) -> Result<Self, SignerError> {
        let helper = Helper {
            config,
            process: Mutex::new(None),
        };
        let mut held = BTreeMap::new();
        let mut refused = Vec::new();
        for Load { id, stored, public } in keys {
            if held.contains_key(&id) {
                return Err(SignerError::DuplicateKey(id));
            }
            let checked = match unframe(&stored, &public) {
                Err(why) => Err(why.to_owned()),
                Ok(blob) => {
                    let answered =
                        helper
                            .call(Op::Public, &[blob.as_bytes()], 1)
                            .and_then(|fields| match fields.as_slice() {
                                [answered] => point(answered),
                                _ => Err(HelperError::Malformed(
                                    "not the fields the operation answers",
                                )),
                            });
                    match answered {
                        Ok(answered) if answered.key_data() == public.key_data() => Ok(blob),
                        Ok(_) => Err("the helper answers another key for its blob".to_owned()),
                        Err(e @ HelperError::Malformed(_)) => {
                            helper.end();
                            Err(e.to_string())
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
            };
            let entry = match checked {
                Ok(blob) => Held::Ready { blob, public },
                Err(why) => {
                    tracing::error!(
                        backend = %helper.config.backend,
                        key = %id,
                        why = %why,
                        "a key's stored bytes were refused: it signs nothing until it is replaced"
                    );
                    refused.push((id.clone(), why));
                    Held::Unusable { public }
                }
            };
            held.insert(id, entry);
        }
        Ok(Self {
            helper,
            keys: RwLock::new(held),
            refused,
        })
    }

    /// The keys refused when the signer was built, and why.
    pub fn refused(&self) -> &[(KeyId, String)] {
        &self.refused
    }

    // poisoned: the map is changed by one insert or remove, whole or not at all.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<KeyId, Held>> {
        self.keys.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Ends the helper after an answer that was well formed but wrong, then [`Self::failed`].
    fn lied(&self, id: &KeyId, what: &str, e: &HelperError) -> SignerError {
        self.helper.end();
        self.failed(id, what, e)
    }

    /// Logs what went wrong with the helper for key `id`, and answers the signer's error.
    fn failed(&self, id: &KeyId, what: &str, e: &HelperError) -> SignerError {
        tracing::error!(
            backend = %self.helper.config.backend,
            key = %id,
            error = %e,
            "{what}"
        );
        match e {
            HelperError::Silent => SignerError::Timeout(id.clone()),
            HelperError::Spawn(_) => SignerError::Unavailable,
            _ => SignerError::Failed(id.clone()),
        }
    }

    /// Signs `data` with the key's blob, the signature checked against `public`.
    fn sign_with(
        &self,
        id: &KeyId,
        blob: &Stored,
        public: &PublicKey,
        data: &[u8],
    ) -> Result<RawSignature, SignerError> {
        if data.len() > MAX_DATA {
            return Err(SignerError::Unsupported {
                id: id.clone(),
                what: format!("signing more than {MAX_DATA} bytes"),
            });
        }
        let fields = self
            .helper
            .call(Op::Sign, &[blob.as_bytes(), data], 1)
            .map_err(|e| self.failed(id, "the helper did not sign", &e))?;
        let [signature] = fields.as_slice() else {
            return Err(SignerError::Failed(id.clone()));
        };
        let raw = RawSignature::new(PAIR.0, PAIR.1, signature.clone()).map_err(|_| {
            self.lied(
                id,
                "the helper did not sign",
                &HelperError::Malformed("not a P-256 signature"),
            )
        })?;
        if writ_crypto::keypair::verify(public, data, &raw).is_err() {
            return Err(self.lied(
                id,
                "the helper's signature doesn't verify",
                &HelperError::Malformed("a signature that doesn't verify"),
            ));
        }
        Ok(raw)
    }
}

impl Signer for HelperSigner {
    fn list_keys(&self) -> Result<Vec<KeyInfo>, SignerError> {
        Ok(self
            .read()
            .iter()
            .map(|(id, held)| KeyInfo {
                id: id.clone(),
                public_key: held.public().clone(),
            })
            .collect())
    }

    fn sign(&self, id: &KeyId, data: &[u8], hash: SignerHash) -> Result<RawSignature, SignerError> {
        let keys = self.read();
        let held = keys
            .get(id)
            .ok_or_else(|| SignerError::UnknownKey(id.clone()))?;
        if hash != PAIR.1 {
            return Err(SignerError::Unsupported {
                id: id.clone(),
                what: writ_crypto::keypair::pair(PAIR.0, hash),
            });
        }
        match held {
            Held::Ready { blob, public } => self.sign_with(id, blob, public, data),
            Held::Unusable { .. } => Err(SignerError::Unusable(id.clone())),
        }
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            pairs: vec![PAIR],
            exportable: false,
            needs_touch: false,
            takes_keys: false,
            makes_keys: true,
        }
    }

    fn create_key(&self, id: KeyId, algorithm: KeyAlgorithm) -> Result<Created, SignerError> {
        if algorithm != PAIR.0 {
            return Err(SignerError::Unsupported {
                id,
                what: format!("making a {algorithm} key"),
            });
        }
        if self.read().contains_key(&id) {
            return Err(SignerError::DuplicateKey(id));
        }
        let fields = self
            .helper
            .call(Op::Create, &[algorithm.name().as_bytes()], 2)
            .map_err(|e| self.failed(&id, "the helper did not make a key", &e))?;
        let [blob, answered] = fields.as_slice() else {
            return Err(SignerError::Failed(id));
        };
        if blob.is_empty() || blob.len() > MAX_ANSWER {
            return Err(self.lied(
                &id,
                "the helper did not make a key",
                &HelperError::Malformed("a blob's length out of bounds"),
            ));
        }
        let blob = Stored::new(blob.clone());
        let public =
            point(answered).map_err(|e| self.lied(&id, "the helper did not make a key", &e))?;
        // The key proves the point is its own before it is kept.
        self.sign_with(&id, &blob, &public, PROBE)?;
        let stored = frame(&public, blob.as_bytes())
            .map_err(|e| self.lied(&id, "the helper did not make a key", &e))?;
        let mut keys = self.keys.write().unwrap_or_else(PoisonError::into_inner);
        if keys.contains_key(&id) {
            return Err(SignerError::DuplicateKey(id));
        }
        keys.insert(
            id.clone(),
            Held::Ready {
                blob,
                public: public.clone(),
            },
        );
        Ok(Created {
            info: KeyInfo {
                id,
                public_key: public,
            },
            stored,
        })
    }

    fn remove_key(&self, id: &KeyId) -> Result<(), SignerError> {
        self.keys
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id)
            .map(drop)
            .ok_or_else(|| SignerError::UnknownKey(id.clone()))
    }
}
