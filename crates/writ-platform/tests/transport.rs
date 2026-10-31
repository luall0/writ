//! Every transport, real and fake, through the transport contract.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::net::TcpStream;
use writ_platform::contract::{self, Connected};
use writ_platform::testing::FakeTransport;
use writ_platform::transport::tcp::TcpTransport;
use writ_platform::{AsyncStream, BoxFuture, PeerInfo, Transport};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_transport_passes_the_contract() {
    let transport = TcpTransport::bind("127.0.0.1:0").await.unwrap();
    let addr = transport.local_addr().unwrap();
    assert!(transport.describe().contains(&addr.to_string()));
    contract::transport(transport, move || -> BoxFuture<'static, Connected> {
        Box::pin(async move {
            let stream = TcpStream::connect(addr).await?;
            let local = stream.local_addr()?;
            Ok((
                Box::new(stream) as Box<dyn AsyncStream>,
                Some(PeerInfo::Tcp { remote: local }),
            ))
        })
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fake_transport_passes_the_contract() {
    let (transport, connector) = FakeTransport::new();
    let counter = Arc::new(AtomicUsize::new(0));
    contract::transport(transport, move || -> BoxFuture<'static, Connected> {
        let connector = connector.clone();
        let peer = PeerInfo::Memory {
            label: format!("client-{}", counter.fetch_add(1, Ordering::Relaxed)),
        };
        Box::pin(async move {
            let stream = connector.connect(peer.clone()).await?;
            Ok((Box::new(stream) as Box<dyn AsyncStream>, Some(peer)))
        })
    })
    .await;
}

#[tokio::test]
async fn fake_transport_reports_any_peer_given() {
    let (transport, connector) = FakeTransport::new();
    let peer = PeerInfo::Tcp {
        remote: "192.0.2.7:51000".parse().unwrap(),
    };
    let _client = connector.connect(peer.clone()).await.unwrap();
    let connection = transport.accept().await.unwrap();
    assert_eq!(connection.peer, peer);
}

#[tokio::test]
async fn fake_accept_fails_once_every_connector_is_dropped() {
    let (transport, connector) = FakeTransport::new();
    let second = connector.clone();
    drop(connector);
    let _client = second
        .connect(PeerInfo::Memory {
            label: "last".to_owned(),
        })
        .await
        .unwrap();
    drop(second);
    // A connection made before the drop is still delivered, then accept fails.
    assert!(transport.accept().await.is_ok());
    assert!(transport.accept().await.is_err());
}

#[tokio::test]
async fn fake_connect_fails_once_the_transport_is_dropped() {
    let (transport, connector) = FakeTransport::new();
    drop(transport);
    let result = connector
        .connect(PeerInfo::Memory {
            label: "late".to_owned(),
        })
        .await;
    assert!(result.is_err());
}
