//! The daemon's repositories: one bare mirror per registered repo, synced from upstream, and
//! the git the daemon runs on them (`docs/architecture/gateway.md`).
//!
//! Upstream is semi-trusted: it is the operator's remote, but a remote can be compromised and
//! a network can be hostile. So everything that comes from it is checked and bounded:
//!
//! - its host key is pinned by the operator ([`known_hosts`]), never learned;
//! - its objects are checked by git's `fsck`, with the checks Writ relies on at error level
//!   ([`git::HARDENING`]); a pack lands only whole (`fetch.unpackLimit = 1`, `--atomic`);
//! - only its branches and tags are mirrored, refs it deleted are pruned;
//! - what it sends is bounded in bytes ([`relay`]: git has no limit of its own on a fetch)
//!   and in time (the whole process group is killed past the deadline: [`process`]);
//! - its object format must be the registry's (a mirror is created in that format, and git
//!   refuses a remote in another);
//! - what it says (an error) is cut and kept as text, never interpreted.
//!
//! The daemon reaches upstream with the system's OpenSSH and a key it never sees: an ssh-agent
//! socket served for one operation ([`agent`]) signs through the [`Signer`], with only that
//! repo's credential, a few signatures at most, in a private directory.
//!
//! git runs with a clean environment and no system or global config ([`git`]); the gateway
//! runs `upload-pack` and `receive-pack` through the same builder.

pub mod agent;
pub mod credential;
pub mod git;
pub mod known_hosts;
mod mirror;
mod process;
pub mod proxy;
pub mod quarantine;
pub mod relay;
#[cfg(feature = "testing")]
pub mod testing;
pub mod upstream;

pub use mirror::{MirrorConfig, MirrorGuard, Mirrors, RefMove, SyncReport, UpstreamUpdate};

use std::path::PathBuf;

use writ_core::names::{KeyId, RepoName};

/// The oldest git the daemon runs with: reftable (2.45), `fetch --porcelain` (2.41).
pub const MIN_GIT: (u32, u32) = (2, 45);
/// The oldest git the daemon runs with for an HTTPS upstream: it reaches upstream through a
/// proxy on a Unix socket, whose path `http.proxy` keeps from 2.47 (older ones drop it, and
/// would ask a proxy on `localhost:1080`).
pub const MIN_GIT_HTTPS: (u32, u32) = (2, 47);

/// Why a mirror couldn't be opened, synced or used. Texts from git or upstream are cut
/// ([`MAX_SHOWN`] characters) and hold no secret: the daemon's key never leaves the signer,
/// and an HTTPS upstream's token is taken out of whatever upstream says.
#[derive(Debug, thiserror::Error)]
pub enum MirrorError {
    #[error("{what} {path}: {source}")]
    Io {
        what: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid mirror configuration: {0}")]
    Config(String),
    #[error("git {found} is too old: the daemon needs git {needed} or newer")]
    GitTooOld { found: String, needed: String },
    #[error("repo {repo}: upstream {upstream}: {why}")]
    Upstream {
        repo: RepoName,
        upstream: String,
        why: String,
    },
    #[error("repo {repo}: upstream credential {key} is not in the upstream signer")]
    UnknownCredential { repo: RepoName, key: KeyId },
    #[error("repo {repo}: upstream credential {key} is not a token the keystore holds")]
    UnknownToken { repo: RepoName, key: KeyId },
    #[error("repo {repo}: no pinned host key for {host} in the upstream known_hosts")]
    HostNotPinned { repo: RepoName, host: String },
    #[error("repo {repo}: {path} is not a mirror made by writd: {why}")]
    NotAMirror {
        repo: RepoName,
        path: PathBuf,
        why: String,
    },
    #[error("unknown repo {0}")]
    UnknownRepo(RepoName),
    #[error("repo {repo}: upstream's object format is not {expected} (the registry's)")]
    ObjectFormat { repo: RepoName, expected: String },
    #[error("repo {repo}: upstream's host key is not the pinned one")]
    HostKey { repo: RepoName },
    #[error("repo {repo}: upstream's certificate does not verify: {why}")]
    Certificate { repo: RepoName, why: String },
    #[error("repo {repo}: upstream sent more than {max} bytes")]
    TooLarge { repo: RepoName, max: u64 },
    #[error("repo {repo}: upstream did not answer within {seconds} s")]
    Timeout { repo: RepoName, seconds: u64 },
    #[error("repo {repo}: upstream refused the push: {reason}")]
    Rejected { repo: RepoName, reason: String },
    #[error("repo {repo}: {what} failed: {stderr}")]
    Git {
        repo: RepoName,
        what: &'static str,
        stderr: String,
    },
    #[error("cannot run git: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("the upstream agent socket failed: {0}")]
    Agent(String),
    #[error("not this push's quarantine: {0}")]
    NotAQuarantine(String),
    #[error("the push brings more than {0} new commits")]
    TooManyCommits(usize),
    #[error("cannot read the push: {0}")]
    Read(String),
}

pub type Result<T> = std::result::Result<T, MirrorError>;

/// How much of a text from git or upstream an error keeps.
pub const MAX_SHOWN: usize = 2_000;

/// `text` made safe for an error: hidden characters dropped (newlines become `; `), at most
/// [`MAX_SHOWN`] characters. Upstream chooses what it prints; it reaches the audit log and an
/// agent's terminal.
pub(crate) fn shown(text: &[u8]) -> String {
    let text = String::from_utf8_lossy(text);
    let lines: Vec<String> = text
        .lines()
        .map(|line| writ_core::text::strip(line, writ_core::text::Newlines::Drop, usize::MAX))
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect();
    writ_core::text::shown(&lines.join("; "), MAX_SHOWN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_text_is_one_bounded_clean_line() {
        assert_eq!(shown(b"error: a\n\nfatal: b\n"), "error: a; fatal: b");
        assert_eq!(shown(b"\x1b[31mred\x1b[0m\r\n"), "[31mred[0m");
        assert_eq!(shown("a\u{202e}b".as_bytes()), "ab");
        let long = vec![b'x'; MAX_SHOWN + 10];
        assert_eq!(shown(&long).chars().count(), MAX_SHOWN + 1);
        assert_eq!(shown(&long[..MAX_SHOWN]).chars().count(), MAX_SHOWN);
    }
}
