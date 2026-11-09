//! How clients reach the daemon: the [`Transport`] interface. Every transport carries the
//! same SSH protocol: only the byte stream and what is known about its peer differ.
//!
//! Portable implementations: [`tcp::TcpTransport`], [`unix::UnixTransport`]. [`accept_retrying`] is the accept loop's
//! rule for every listener the daemon runs, a transport's or its own (the hook socket).

mod retry;
pub mod tcp;
pub mod unix;

pub use retry::accept_retrying;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::Result;

/// A boxed, sendable future (the traits here are used as trait objects).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A bidirectional byte stream.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncStream for T {}

/// One accepted client connection.
pub struct Connection {
    pub stream: Box<dyn AsyncStream>,
    /// Raw peer information from the transport. Never something the client claims about
    /// itself.
    pub peer: PeerInfo,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

/// What the transport knows about the other end, before any attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerInfo {
    /// A TCP peer: its address as seen by the socket.
    Tcp { remote: SocketAddr },
    /// A Unix socket peer: the kernel's peer credentials (local mode).
    Unix {
        uid: u32,
        gid: u32,
        pid: Option<u32>,
        /// The pid's generation when the kernel gives it with the credentials (macOS: the
        /// audit token's pidversion), so a pid reused since the connect is another process.
        generation: Option<u64>,
    },
    /// An in-memory connection made by a test fake. No real transport ever produces it.
    Memory { label: String },
}

/// Waits for client connections.
pub trait Transport: Send + Sync {
    /// Waits for the next client connection. Fails only when the listener itself can't go
    /// on: an error about one connection or a passing shortage (out of file descriptors, a
    /// connection reset before it was accepted) is retried inside, never returned, since the
    /// daemon stops when a listener fails.
    fn accept(&self) -> BoxFuture<'_, Result<Connection>>;
    /// Where it listens, for logs (`tcp 127.0.0.1:2222`).
    fn describe(&self) -> String;
}
