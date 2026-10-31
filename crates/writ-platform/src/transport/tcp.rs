//! [`TcpTransport`]: TCP, the detached mode's transport.

use std::net::SocketAddr;

use tokio::net::TcpListener;

use super::{BoxFuture, Connection, PeerInfo, Transport};
use crate::Result;

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
