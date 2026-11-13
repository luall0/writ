//! The token of an HTTPS upstream, handed to git for one operation.
//!
//! git asks its credential helper for a password; the daemon makes that helper
//! `writd upstream-credential <socket> <operation>` (git starts it, [`helper`]), which asks the
//! daemon on a socket served for this operation alone ([`CredentialSocket`]), in a private
//! directory. The daemon answers only a request for this upstream (`protocol=https`, its host
//! and port), a few times at most, and then removes the socket. The token reaches git through
//! pipes: never a command line, an environment variable, a URL or a file. The helper writes
//! nothing but the answer to git, and never the token to its stderr.
//!
//! The mirrors never hold a token: they hold a [`TokenRef`] (its id, the version of its file
//! in force, where it is unwrapped), unwrapped when an operation starts, dropped and wiped when
//! it ends ([`TokenSource`]: the daemon's keystore, M7.6).

pub mod helper;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use writ_core::names::KeyId;

use crate::upstream::HttpsUrl;
use crate::{MirrorError, Result};

/// The longest token taken (GitHub's fine-grained ones are 93 characters).
pub const MAX_TOKEN_LEN: usize = 1024;
/// The largest token file read.
pub const MAX_TOKEN_FILE: u64 = 4096;
/// The largest request read from git (a few `key=value` lines) and answer read from the
/// daemon.
pub const MAX_MESSAGE: usize = 4096;
/// What is read of a message: one byte past the bound tells a message too long.
pub(crate) const READ_LIMIT: u64 = 4097;
/// Connections one socket accepts in its life.
pub const MAX_CONNECTIONS: usize = 8;
/// Answers holding the token one socket gives in its life (one git process asks once).
pub const MAX_ANSWERS: usize = 4;
/// How long the helper and the socket wait for the other side.
pub const DEADLINE: Duration = Duration::from_secs(30);
/// The user name sent with the token when the URL names none. GitHub, GitLab, Forgejo and
/// Gitea take any name with a token; a remote that wants a given one has it in the URL
/// (`https://x-token-auth@bitbucket.org/…`).
pub const DEFAULT_USER: &str = "writ";

/// Where a token is unwrapped when an operation needs it: the daemon's keystore. Each call
/// unwraps it afresh; the caller drops it, wiped, once the operation is done.
pub trait TokenSource: Send + Sync {
    /// The token `id` whose file in force is `version` (a file changed since is refused).
    /// Why not, never the token.
    fn unwrap(&self, id: &KeyId, version: &str) -> std::result::Result<UpstreamToken, String>;
}

/// A token in force, as the mirrors hold it: its id, the version of its file (a token added or
/// replaced is another [`TokenRef`]), and its source. Holds no secret.
pub struct TokenRef {
    id: KeyId,
    version: String,
    source: Arc<dyn TokenSource>,
}

/// The tokens in force by id.
pub type Tokens = std::collections::BTreeMap<KeyId, Arc<TokenRef>>;

impl TokenRef {
    pub fn new(id: KeyId, version: String, source: Arc<dyn TokenSource>) -> Self {
        Self {
            id,
            version,
            source,
        }
    }

    pub fn id(&self) -> &KeyId {
        &self.id
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    /// The token, unwrapped now, for one operation, on the calling thread: it may block (a
    /// device call since M7.6), so never on an async thread ([`TokenRef::unwrap_off_async`]).
    pub fn unwrap(&self) -> std::result::Result<UpstreamToken, String> {
        self.source.unwrap(&self.id, &self.version)
    }

    /// [`TokenRef::unwrap`] off the async threads (a device call can wait seconds; the review
    /// after M7.6, M-3), as the signer's calls are: what the mirrors use. A caller that gives
    /// up leaves the unwrap to finish on its thread, its token dropped (wiped) there.
    pub async fn unwrap_off_async(&self) -> std::result::Result<UpstreamToken, String> {
        let (source, id, version) = (self.source.clone(), self.id.clone(), self.version.clone());
        tokio::task::spawn_blocking(move || source.unwrap(&id, &version))
            .await
            .map_err(|_| "the unwrap's thread failed".to_owned())?
    }

    /// A token held in memory as it is, for tests: no keystore behind it.
    #[cfg(any(test, feature = "testing"))]
    pub fn held(id: KeyId, token: UpstreamToken) -> Self {
        struct Held(UpstreamToken);
        impl TokenSource for Held {
            fn unwrap(&self, _: &KeyId, _: &str) -> std::result::Result<UpstreamToken, String> {
                UpstreamToken::from_bytes(self.0.expose().as_bytes()).map_err(str::to_owned)
            }
        }
        Self::new(id, "held".to_owned(), Arc::new(Held(token)))
    }
}

impl std::fmt::Debug for TokenRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRef")
            .field("id", &self.id)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// An upstream token, wiped from memory when dropped, never printed.
pub struct UpstreamToken(Zeroizing<String>);

impl UpstreamToken {
    /// A token file's contents, surrounding whitespace trimmed: 1 to [`MAX_TOKEN_LEN`]
    /// printable ASCII characters, no space. Anything else (a newline inside, which would
    /// smuggle a line into git's credential protocol) is refused; the reason never holds the
    /// token.
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, &'static str> {
        let text = bytes.trim_ascii();
        if text.is_empty() {
            return Err("empty");
        }
        if text.len() > MAX_TOKEN_LEN {
            return Err("longer than 1024 characters");
        }
        if !text.iter().all(u8::is_ascii_graphic) {
            return Err("not printable ASCII without spaces");
        }
        let token = std::str::from_utf8(text).map_err(|_| "not printable ASCII without spaces")?;
        Ok(Self(Zeroizing::new(token.to_owned())))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for UpstreamToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UpstreamToken(<redacted>)")
    }
}

/// A running credential socket. Dropped: stopped, every connection ended, its file removed.
pub struct CredentialSocket {
    path: PathBuf,
    task: tokio::task::JoinHandle<()>,
    answers: Arc<AtomicUsize>,
}

struct Served {
    upstream: HttpsUrl,
    token: Arc<UpstreamToken>,
    answers: Arc<AtomicUsize>,
}

impl CredentialSocket {
    /// Serves `token` for `upstream` on a new socket in `dir`, a private directory.
    pub fn start(dir: &Path, upstream: HttpsUrl, token: Arc<UpstreamToken>) -> Result<Self> {
        let name =
            writ_crypto::keys::random_hex(8).map_err(|source| MirrorError::NoRandomness {
                what: "the credential socket",
                source,
            })?;
        let path = dir.join(format!("{name}.cred"));
        let listener = UnixListener::bind(&path).map_err(|source| MirrorError::Io {
            what: "cannot create the credential socket",
            path: path.clone(),
            source,
        })?;
        let answers = Arc::new(AtomicUsize::new(0));
        let served = Arc::new(Served {
            upstream,
            token,
            answers: answers.clone(),
        });
        let task = tokio::spawn(serve(listener, served));
        Ok(Self {
            path,
            task,
            answers,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How many answers holding the token it gave.
    pub fn answers(&self) -> usize {
        self.answers.load(Ordering::Acquire)
    }
}

impl Drop for CredentialSocket {
    fn drop(&mut self) {
        // The serving task owns the connections (a `JoinSet`): aborting it ends them all.
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn serve(listener: UnixListener, served: Arc<Served>) {
    let mut connections = JoinSet::new();
    for _ in 0..MAX_CONNECTIONS {
        match listener.accept().await {
            Ok((stream, _)) => {
                connections.spawn(answer(stream, served.clone()));
            }
            Err(e) => {
                tracing::debug!(error = %e, "credential socket accept failed");
                break;
            }
        }
    }
    drop(listener);
    while connections.join_next().await.is_some() {}
}

/// Reads one request (until the peer stops writing) and answers it with the token if it
/// names this upstream; otherwise closes without a word.
async fn answer(mut stream: UnixStream, served: Arc<Served>) {
    let mut request = Vec::new();
    let read = tokio::time::timeout(DEADLINE, async {
        let mut limited = (&mut stream).take(READ_LIMIT);
        limited.read_to_end(&mut request).await
    })
    .await;
    if !matches!(read, Ok(Ok(_))) || request.len() > MAX_MESSAGE {
        tracing::debug!("credential request unreadable or too long");
        return;
    }
    if !names_upstream(&request, &served.upstream) {
        tracing::warn!(
            upstream = served.upstream.as_str(),
            "git asked for the upstream token for another host or protocol: refused"
        );
        return;
    }
    let taken = served
        .answers
        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < MAX_ANSWERS).then(|| n.saturating_add(1))
        });
    if taken.is_err() {
        tracing::warn!("the upstream token was asked for too many times in one operation");
        return;
    }
    let user = served.upstream.user().unwrap_or(DEFAULT_USER);
    let reply = answer_text(user, served.token.expose());
    let written = tokio::time::timeout(DEADLINE, async {
        stream.write_all(reply.as_bytes()).await?;
        stream.shutdown().await
    })
    .await;
    if !matches!(written, Ok(Ok(()))) {
        tracing::debug!("cannot answer the credential request");
    }
}

/// The answer to git, in a buffer sized up front: one growing as the token is added would
/// leave copies of it behind (the review after M7.6, M-8).
fn answer_text(user: &str, token: &str) -> Zeroizing<String> {
    let parts = ["username=", user, "\npassword=", token, "\n"];
    let capacity = parts
        .iter()
        .map(|part| part.len())
        .fold(0usize, usize::saturating_add);
    let mut reply = Zeroizing::new(String::with_capacity(capacity));
    for part in parts {
        reply.push_str(part);
    }
    reply
}

/// Whether git's request (`key=value` lines) is for this upstream: `protocol=https` and its
/// host, each exactly once. Anything unreadable is not.
fn names_upstream(request: &[u8], upstream: &HttpsUrl) -> bool {
    let Ok(text) = std::str::from_utf8(request) else {
        return false;
    };
    let (mut protocol, mut host) = (Vec::new(), Vec::new());
    for line in text.lines() {
        match line.split_once('=') {
            Some(("protocol", value)) => protocol.push(value),
            Some(("host", value)) => host.push(value),
            _ => {}
        }
    }
    matches!(protocol.as_slice(), ["https"])
        && matches!(host.as_slice(), [one] if upstream.is_host(one))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "writ-test-token-0123456789abcdefABCDEF";

    fn token() -> Arc<UpstreamToken> {
        Arc::new(UpstreamToken::from_bytes(format!("{TOKEN}\n").as_bytes()).unwrap())
    }

    #[test]
    fn a_token_is_one_word_of_printable_ascii_and_never_printed() {
        let parsed = UpstreamToken::from_bytes(format!("  {TOKEN}\r\n").as_bytes()).unwrap();
        assert_eq!(parsed.expose(), TOKEN);
        assert_eq!(format!("{parsed:?}"), "UpstreamToken(<redacted>)");
        let longest = "a".repeat(MAX_TOKEN_LEN);
        assert!(UpstreamToken::from_bytes(longest.as_bytes()).is_ok());
        for (bytes, why) in [
            (b"".to_vec(), "empty"),
            (b" \n".to_vec(), "empty"),
            (
                "a".repeat(MAX_TOKEN_LEN + 1).into_bytes(),
                "longer than 1024 characters",
            ),
            (
                b"abc\nprotocol=http".to_vec(),
                "not printable ASCII without spaces",
            ),
            (b"abc def".to_vec(), "not printable ASCII without spaces"),
            (b"abc\x00def".to_vec(), "not printable ASCII without spaces"),
            (
                "tökén".as_bytes().to_vec(),
                "not printable ASCII without spaces",
            ),
        ] {
            let error = UpstreamToken::from_bytes(&bytes).map(|_| ()).unwrap_err();
            assert_eq!(error, why, "{bytes:?}");
        }
    }

    /// The review after M7.6 (M-3): a token's unwrap (a device call since M7.6) ran on the
    /// async thread, so a device that waits held up everything else on it. On a runtime of one
    /// thread, the source below waits until the runtime itself releases it: it is released
    /// only if the unwrap runs elsewhere. Run on the runtime's thread, it would wait its 10 s
    /// out and fail.
    #[tokio::test(flavor = "current_thread")]
    async fn a_token_is_unwrapped_off_the_async_threads() {
        struct Gated {
            entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
            release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        }
        impl TokenSource for Gated {
            fn unwrap(&self, _: &KeyId, _: &str) -> std::result::Result<UpstreamToken, String> {
                if let Some(entered) = self.entered.lock().unwrap().take() {
                    let _ = entered.send(());
                }
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(|_| "never released: the unwrap held the runtime".to_owned())?;
                UpstreamToken::from_bytes(TOKEN.as_bytes()).map_err(str::to_owned)
            }
        }
        let (entered, is_in) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let token = Arc::new(TokenRef::new(
            "token-01".parse().unwrap(),
            "v1".to_owned(),
            Arc::new(Gated {
                entered: std::sync::Mutex::new(Some(entered)),
                release: std::sync::Mutex::new(released),
            }),
        ));
        let unwrapping = tokio::spawn({
            let token = token.clone();
            async move { token.unwrap_off_async().await }
        });
        // The runtime still runs this task while the unwrap waits.
        is_in.await.unwrap();
        release.send(()).unwrap();
        let unwrapped = unwrapping.await.unwrap().unwrap();
        assert_eq!(unwrapped.expose(), TOKEN);
    }

    /// The review after M7.6 (M-8): the answer was a `format!`, its buffer grown (and copied)
    /// as the token went in. Sized up front: exactly what it holds, never reallocated.
    #[test]
    fn the_answer_holding_the_token_is_sized_up_front() {
        let reply = answer_text("writ", TOKEN);
        assert_eq!(reply.as_str(), format!("username=writ\npassword={TOKEN}\n"));
        assert_eq!(reply.capacity(), reply.len());
    }

    #[test]
    fn only_a_request_for_this_upstream_over_https_is_answered() {
        let upstream = HttpsUrl::parse("https://git.example.org/u/r.git").unwrap();
        let yes = |r: &str| names_upstream(r.as_bytes(), &upstream);
        assert!(yes("protocol=https\nhost=git.example.org\npath=u/r.git\n"));
        assert!(yes(
            "capability[]=authtype\nprotocol=https\nhost=GIT.example.org:443\n"
        ));
        for request in [
            "protocol=http\nhost=git.example.org\n",
            "protocol=https\nhost=evil.example.org\n",
            "protocol=https\nhost=git.example.org:8443\n",
            "protocol=https\n",
            "host=git.example.org\n",
            "protocol=https\nprotocol=http\nhost=git.example.org\n",
            "protocol=https\nhost=git.example.org\nhost=evil.example.org\n",
            "",
        ] {
            assert!(!yes(request), "{request:?}");
        }
        assert!(!names_upstream(b"protocol=https\nhost=\xff\n", &upstream));
    }

    async fn ask(path: &Path, request: &str) -> Vec<u8> {
        let mut stream = UnixStream::connect(path).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        reply
    }

    /// Sends a request the socket refuses unread: it stops reading at its bound and hangs up
    /// with the rest unread, which Linux turns into a reset (macOS closes quietly). Either way
    /// git gets no reply, which is all a refusal is: an empty end, or the reset, nothing else.
    async fn ask_cut_off(path: &Path, request: &str) {
        let cut_off = |e: std::io::Error| {
            assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                ),
                "{e}"
            );
        };
        let mut stream = UnixStream::connect(path).await.unwrap();
        if let Err(e) = stream.write_all(request.as_bytes()).await {
            return cut_off(e);
        }
        if let Err(e) = stream.shutdown().await {
            return cut_off(e);
        }
        let mut reply = Vec::new();
        match stream.read_to_end(&mut reply).await {
            Ok(_) => assert!(reply.is_empty(), "{}", String::from_utf8_lossy(&reply)),
            Err(e) => cut_off(e),
        }
    }

    #[tokio::test]
    async fn the_socket_answers_this_upstream_a_bounded_number_of_times() {
        let dir = tempfile::tempdir().unwrap();
        let upstream = HttpsUrl::parse("https://git.example.org/u/r.git").unwrap();
        let socket = CredentialSocket::start(dir.path(), upstream, token()).unwrap();
        let good = "protocol=https\nhost=git.example.org\n";
        let reply = ask(socket.path(), good).await;
        assert_eq!(
            String::from_utf8(reply).unwrap(),
            format!("username={DEFAULT_USER}\npassword={TOKEN}\n")
        );
        // Another host: closed without a word, and not counted.
        assert!(
            ask(socket.path(), "protocol=https\nhost=evil.example.org\n")
                .await
                .is_empty()
        );
        assert_eq!(socket.answers(), 1);
        for _ in 1..MAX_ANSWERS {
            assert!(!ask(socket.path(), good).await.is_empty());
        }
        assert_eq!(socket.answers(), MAX_ANSWERS);
        // One past the cap: nothing.
        assert!(ask(socket.path(), good).await.is_empty());
        assert_eq!(socket.answers(), MAX_ANSWERS);
    }

    #[tokio::test]
    async fn the_user_in_the_url_is_the_one_sent_and_the_socket_goes_when_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let upstream = HttpsUrl::parse("https://x-token-auth@bitbucket.org/u/r.git").unwrap();
        let socket = CredentialSocket::start(dir.path(), upstream, token()).unwrap();
        let reply = ask(socket.path(), "protocol=https\nhost=bitbucket.org\n").await;
        assert!(
            String::from_utf8(reply)
                .unwrap()
                .starts_with("username=x-token-auth\n")
        );
        let path = socket.path().to_owned();
        drop(socket);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn a_request_longer_than_the_bound_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let upstream = HttpsUrl::parse("https://git.example.org/u/r.git").unwrap();
        let socket = CredentialSocket::start(dir.path(), upstream, token()).unwrap();
        let padding = "x".repeat(MAX_MESSAGE);
        let long = format!("protocol=https\nhost=git.example.org\npath={padding}\n");
        ask_cut_off(socket.path(), &long).await;
        assert_eq!(socket.answers(), 0, "the token was never handed out");
        let fits = format!(
            "protocol=https\nhost=git.example.org\npath={}\n",
            "x".repeat(MAX_MESSAGE - 42)
        );
        assert_eq!(fits.len(), MAX_MESSAGE);
        assert!(!ask(socket.path(), &fits).await.is_empty());
        assert_eq!(socket.answers(), 1);
    }
}
