//! An ssh-agent socket for one upstream operation: it offers one key (the repo's upstream
//! credential) and signs with it through the [`Signer`], so the daemon's ssh authenticates
//! without the key ever leaving the signer (a hardware backend works the same way).
//!
//! Only what ssh needs is served (the ssh-agent protocol, draft-ietf-sshm-ssh-agent: list the
//! identities, sign with one); everything else is answered with a failure. The socket lives
//! in a private directory, for one operation, and is bounded: a few connections, a few
//! signatures, small messages, a deadline per message. Dropping the [`AgentSocket`] stops it
//! and removes the socket file.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ssh_key::PublicKey;
use ssh_key::encoding::Encode;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use writ_core::names::KeyId;
use writ_signer::Signer;

use crate::{MirrorError, Result};

/// The largest message read (OpenSSH's own agent takes 256 KiB; a sign request from ssh is
/// well under 1 KiB).
pub const MAX_MESSAGE: usize = 256 * 1024;
/// Connections one socket accepts in its life (one ssh connects once).
pub const MAX_CONNECTIONS: usize = 4;
/// Signatures one socket makes in its life (one ssh authentication needs one).
pub const MAX_SIGNATURES: usize = 4;
/// Requests one connection may make.
pub const MAX_REQUESTS: usize = 16;
/// How long a peer may take to send a message.
pub const MESSAGE_DEADLINE: Duration = Duration::from_secs(30);

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;

/// A running agent socket. Dropped: stopped, and its file removed.
pub struct AgentSocket {
    path: PathBuf,
    task: JoinHandle<()>,
    signatures: Arc<AtomicUsize>,
}

impl AgentSocket {
    /// Serves `key` (whose public half is `public`) from `signer` on a new socket in `dir`, a
    /// private directory.
    pub fn start(
        dir: &Path,
        signer: Arc<dyn Signer>,
        key: KeyId,
        public: &PublicKey,
    ) -> Result<Self> {
        let name = writ_crypto::keys::random_hex(8)
            .map_err(|_| MirrorError::Agent("no randomness".to_owned()))?;
        let path = dir.join(format!("{name}.sock"));
        let listener = UnixListener::bind(&path).map_err(|source| MirrorError::Io {
            what: "cannot create the agent socket",
            path: path.clone(),
            source,
        })?;
        let blob = public
            .to_bytes()
            .map_err(|_| MirrorError::Agent("unencodable public key".to_owned()))?;
        let state = Arc::new(Served {
            signer,
            key,
            blob,
            signatures: Arc::new(AtomicUsize::new(0)),
        });
        let signatures = state.signatures.clone();
        let task = tokio::spawn(serve(listener, state));
        Ok(Self {
            path,
            task,
            signatures,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How many signatures it made.
    pub fn signatures(&self) -> usize {
        self.signatures.load(Ordering::Acquire)
    }
}

impl Drop for AgentSocket {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

struct Served {
    signer: Arc<dyn Signer>,
    key: KeyId,
    /// The key's public blob, as ssh names it.
    blob: Vec<u8>,
    signatures: Arc<AtomicUsize>,
}

async fn serve(listener: UnixListener, served: Arc<Served>) {
    let mut connections = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        match listener.accept().await {
            Ok((stream, _)) => connections.push(tokio::spawn(answer(stream, served.clone()))),
            // The socket is private and short-lived: a failure ends it, and ssh then fails.
            Err(e) => {
                tracing::debug!(error = %e, "agent socket accept failed");
                break;
            }
        }
    }
    // Past the cap, nobody else is accepted; the running connections finish.
    drop(listener);
    for connection in connections {
        let _ = connection.await;
    }
}

async fn answer(mut stream: impl AsyncRead + AsyncWrite + Unpin, served: Arc<Served>) {
    for _ in 0..MAX_REQUESTS {
        let message = match tokio::time::timeout(MESSAGE_DEADLINE, read_message(&mut stream)).await
        {
            Ok(Ok(Some(message))) => message,
            _ => return,
        };
        let reply = respond(&served, &message).await;
        if write_message(&mut stream, &reply).await.is_err() {
            return;
        }
    }
}

/// One message: a 4-byte length, then that many bytes. `None` at a clean end.
async fn read_message(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
    if length == 0 || length > MAX_MESSAGE {
        return Err(std::io::Error::other("agent message out of bounds"));
    }
    let mut message = vec![0u8; length];
    stream.read_exact(&mut message).await?;
    Ok(Some(message))
}

async fn write_message(stream: &mut (impl AsyncWrite + Unpin), body: &[u8]) -> std::io::Result<()> {
    let length = u32::try_from(body.len()).map_err(std::io::Error::other)?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

/// The reply to one request: the identity list, a signature, or a failure.
async fn respond(served: &Served, message: &[u8]) -> Vec<u8> {
    match message.split_first() {
        Some((&REQUEST_IDENTITIES, [])) => {
            let mut reply = vec![IDENTITIES_ANSWER];
            reply.extend_from_slice(&1u32.to_be_bytes());
            put_string(&mut reply, &served.blob);
            put_string(
                &mut reply,
                format!("writ upstream {}", served.key).as_bytes(),
            );
            reply
        }
        Some((&SIGN_REQUEST, body)) => sign(served, body).await.unwrap_or_else(|| vec![FAILURE]),
        _ => vec![FAILURE],
    }
}

/// A sign request: `string key, string data, uint32 flags`. Signed only with the served key,
/// at most [`MAX_SIGNATURES`] times.
async fn sign(served: &Served, body: &[u8]) -> Option<Vec<u8>> {
    let (blob, rest) = take_string(body)?;
    let (data, rest) = take_string(rest)?;
    if rest.len() != 4 || blob != served.blob.as_slice() {
        return None;
    }
    let taken = served
        .signatures
        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < MAX_SIGNATURES).then(|| n.saturating_add(1))
        });
    if taken.is_err() {
        tracing::warn!(key = %served.key, "agent socket: signature refused past its cap");
        return None;
    }
    let (signer, key, data) = (served.signer.clone(), served.key.clone(), data.to_vec());
    let signature = tokio::task::spawn_blocking(move || signer.sign(&key, &data))
        .await
        .ok()?
        .map_err(
            |e| tracing::warn!(key = %served.key, error = %e, "upstream credential did not sign"),
        )
        .ok()?;
    let encoded = signature.encode_vec().ok()?;
    let mut reply = vec![SIGN_RESPONSE];
    put_string(&mut reply, &encoded);
    Some(reply)
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A `string` (4-byte length, bytes) from the front of `bytes`, and what follows it.
fn take_string(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (length, rest) = bytes.split_at_checked(4)?;
    let length = usize::try_from(u32::from_be_bytes(length.try_into().ok()?)).ok()?;
    rest.split_at_checked(length)
}

#[cfg(test)]
mod tests {
    use writ_crypto::keys::{KeyKind, generate};
    use writ_signer::software::SoftwareSigner;

    use super::*;

    fn agent(dir: &Path) -> (AgentSocket, PublicKey) {
        let key = generate(KeyKind::Ed25519).unwrap();
        let public = key.public_key().clone();
        let id: KeyId = "upstream-01".parse().unwrap();
        let signer: Arc<dyn Signer> =
            Arc::new(SoftwareSigner::new(vec![(id.clone(), key)]).unwrap());
        (
            AgentSocket::start(dir, signer, id, &public).unwrap(),
            public,
        )
    }

    async fn ask(stream: &mut tokio::net::UnixStream, body: &[u8]) -> Vec<u8> {
        write_message(stream, body).await.unwrap();
        read_message(stream).await.unwrap().unwrap()
    }

    fn sign_request(blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut body = vec![SIGN_REQUEST];
        put_string(&mut body, blob);
        put_string(&mut body, data);
        body.extend_from_slice(&0u32.to_be_bytes());
        body
    }

    #[tokio::test]
    async fn it_offers_one_key_and_signs_with_it_a_bounded_number_of_times() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, public) = agent(dir.path());
        let blob = public.to_bytes().unwrap();
        let mut stream = tokio::net::UnixStream::connect(socket.path())
            .await
            .unwrap();

        let reply = ask(&mut stream, &[REQUEST_IDENTITIES]).await;
        assert_eq!(reply[0], IDENTITIES_ANSWER);
        assert_eq!(&reply[1..5], &1u32.to_be_bytes());
        let (listed, _) = take_string(&reply[5..]).unwrap();
        assert_eq!(listed, blob.as_slice());

        for n in 0..MAX_SIGNATURES {
            let reply = ask(&mut stream, &sign_request(&blob, b"session data")).await;
            assert_eq!(reply[0], SIGN_RESPONSE, "signature {n}");
            let (encoded, rest) = take_string(&reply[1..]).unwrap();
            assert!(rest.is_empty());
            let signature =
                ssh_key::Signature::try_from(encoded).expect("an SSH-encoded signature");
            signature::Verifier::verify(&public, b"session data", &signature)
                .expect("a valid signature by the served key");
        }
        // One past the cap: refused.
        let reply = ask(&mut stream, &sign_request(&blob, b"session data")).await;
        assert_eq!(reply, vec![FAILURE]);
        assert_eq!(socket.signatures(), MAX_SIGNATURES);
    }

    #[tokio::test]
    async fn another_key_or_another_request_gets_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, _) = agent(dir.path());
        let other = generate(KeyKind::Ed25519).unwrap();
        let other_blob = other.public_key().to_bytes().unwrap();
        let mut stream = tokio::net::UnixStream::connect(socket.path())
            .await
            .unwrap();
        assert_eq!(
            ask(&mut stream, &sign_request(&other_blob, b"x")).await,
            vec![FAILURE]
        );
        // Add identity (17), remove all (19), lock (22), extension (27), a cut-short sign request.
        for body in [
            vec![17u8, 0, 0],
            vec![19],
            vec![22, 0, 0, 0, 0],
            vec![27],
            vec![13, 0, 0],
        ] {
            assert_eq!(ask(&mut stream, &body).await, vec![FAILURE], "{body:?}");
        }
        assert_eq!(socket.signatures(), 0);
    }

    #[tokio::test]
    async fn an_oversized_message_ends_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, _) = agent(dir.path());
        let mut stream = tokio::net::UnixStream::connect(socket.path())
            .await
            .unwrap();
        let length = u32::try_from(MAX_MESSAGE + 1).unwrap();
        stream.write_all(&length.to_be_bytes()).await.unwrap();
        let mut rest = Vec::new();
        // The agent hangs up without reading the body.
        stream.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        // At the limit, the message is read (and refused as an unknown request).
        let mut stream = tokio::net::UnixStream::connect(socket.path())
            .await
            .unwrap();
        let mut body = vec![99u8];
        body.resize(MAX_MESSAGE, 0);
        assert_eq!(ask(&mut stream, &body).await, vec![FAILURE]);
    }

    #[tokio::test]
    async fn the_socket_takes_a_bounded_number_of_connections_and_is_removed_when_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, _) = agent(dir.path());
        let path = socket.path().to_owned();
        let mut open = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
            assert_eq!(
                ask(&mut stream, &[REQUEST_IDENTITIES]).await[0],
                IDENTITIES_ANSWER
            );
            open.push(stream);
        }
        // Past the cap nobody accepts: the connection is refused, or (when a process another
        // test spawned inherited the listening socket in the moment before macOS marks it
        // close-on-exec) it waits unanswered until that process ends. Never an answer.
        if let Ok(mut stream) = tokio::net::UnixStream::connect(&path).await {
            let _ = write_message(&mut stream, &[REQUEST_IDENTITIES]).await;
            let mut byte = [0u8; 1];
            let read = stream.read(&mut byte).await;
            assert!(
                matches!(read, Ok(0) | Err(_)),
                "answered past the cap: {read:?}"
            );
        }
        drop(socket);
        assert!(!path.exists(), "the socket file is removed");
    }
}
