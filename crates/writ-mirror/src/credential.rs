//! The token of an HTTPS upstream, handed to git for one operation.
//!
//! git asks its credential helper for a password; the daemon makes that helper
//! `writd upstream-credential <socket> <operation>` (git starts it, [`helper`]), which asks the
//! daemon on a socket served for this operation alone ([`CredentialSocket`]), in a private
//! directory. The daemon answers only a request for this upstream (`protocol=https`, its host
//! and port), a few times at most, and then removes the socket. The token reaches git through
//! pipes: never a command line, an environment variable, a URL or a file. The helper writes
//! nothing but the answer to git, and never the token to its stderr.

pub mod helper;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;
use zeroize::Zeroizing;

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
        let name = writ_crypto::keys::random_hex(8)
            .map_err(|_| MirrorError::Agent("no randomness".to_owned()))?;
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
    let reply = Zeroizing::new(format!(
        "username={user}\npassword={}\n",
        served.token.expose()
    ));
    let written = tokio::time::timeout(DEADLINE, async {
        stream.write_all(reply.as_bytes()).await?;
        stream.shutdown().await
    })
    .await;
    if !matches!(written, Ok(Ok(()))) {
        tracing::debug!("cannot answer the credential request");
    }
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
        assert!(ask(socket.path(), &long).await.is_empty());
        let fits = format!(
            "protocol=https\nhost=git.example.org\npath={}\n",
            "x".repeat(MAX_MESSAGE - 42)
        );
        assert_eq!(fits.len(), MAX_MESSAGE);
        assert!(!ask(socket.path(), &fits).await.is_empty());
    }
}
