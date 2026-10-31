//! How clients reach the daemon. Every transport carries the same SSH protocol: only the byte
//! stream and what is known about its peer differ.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

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
    /// A Unix socket peer: the kernel's peer credentials (local mode, M7).
    Unix {
        uid: u32,
        gid: u32,
        pid: Option<u32>,
    },
    /// An in-memory connection made by a test fake. No real transport ever produces it.
    Memory { label: String },
}

/// Waits for client connections.
pub trait Transport: Send + Sync {
    /// Waits for the next client connection.
    fn accept(&self) -> BoxFuture<'_, Result<Connection>>;
    /// Where it listens, for logs (`tcp 127.0.0.1:2222`).
    fn describe(&self) -> String;
}

/// TCP: the detached mode's transport.
pub struct TcpTransport {
    listener: TcpListener,
}

impl TcpTransport {
    /// Listens on `addr` (`0.0.0.0:2222`, `127.0.0.1:0`).
    pub async fn bind(addr: &str) -> Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
        })
    }

    pub fn from_listener(listener: TcpListener) -> Self {
        Self { listener }
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
}

impl Transport for TcpTransport {
    fn accept(&self) -> BoxFuture<'_, Result<Connection>> {
        Box::pin(async move {
            let (stream, remote) = self.listener.accept().await?;
            // Small request/response exchanges: don't wait to fill packets.
            let _ = stream.set_nodelay(true);
            Ok(Connection {
                stream: Box::new(stream),
                peer: PeerInfo::Tcp { remote },
            })
        })
    }

    fn describe(&self) -> String {
        match self.listener.local_addr() {
            Ok(addr) => format!("tcp {addr}"),
            Err(_) => "tcp".to_owned(),
        }
    }
}
