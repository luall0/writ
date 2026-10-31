//! The approval API over HTTPS: the same commands, bodies and replies as over SSH
//! (`writ_proto`), for approvers that speak HTTP (approver apps). Agent commands don't exist
//! here.
//!
//! Connections come from a [`Transport`] and their callers are attested, like the SSH
//! listeners. TLS 1.3 only, with the daemon's self-signed certificate
//! ([`writ_crypto::tls::TlsIdentity`]), which clients pin by its SHA-256 fingerprint; no client authentication, since the connection grants nothing
//! (approvals are SSHSIGs checked by the approval service). Routes: see
//! [`writ_proto::Command::http_route`].

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use writ_core::caller::CallerFacts;
use writ_crypto::tls::TlsIdentity;
use writ_platform::{CallerAttestor, Transport};
use writ_proto::{ApiError, MAX_BODY};

use crate::api::{approval_has_body, approval_reply, encoded};
use crate::{Gateway, Result};

/// How long a client has to finish the TLS handshake, and to send its request headers.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

impl Gateway {
    /// Serves the approval API over HTTPS from a transport, until the transport fails.
    pub async fn serve_https(
        &self,
        transport: Arc<dyn Transport>,
        attestor: Arc<dyn CallerAttestor>,
        identity: Arc<TlsIdentity>,
    ) -> Result<()> {
        let acceptor = tokio_rustls::TlsAcceptor::from(identity.server_config());
        loop {
            let (connection, facts) = self.accept_attested(&*transport, &*attestor).await?;
            let (gateway, acceptor) = (self.clone(), acceptor.clone());
            tokio::spawn(async move {
                let tls = match tokio::time::timeout(
                    HANDSHAKE_TIMEOUT,
                    acceptor.accept(connection.stream),
                )
                .await
                {
                    Ok(Ok(tls)) => tls,
                    _ => return,
                };
                let service = hyper::service::service_fn(move |request| {
                    let (gateway, facts) = (gateway.clone(), facts.clone());
                    async move {
                        Ok::<_, std::convert::Infallible>(handle(gateway, facts, request).await)
                    }
                });
                let served = hyper::server::conn::http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(HANDSHAKE_TIMEOUT)
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
                if let Err(e) = served {
                    eprintln!("writ gateway: HTTPS connection ended with an error: {e}");
                }
            });
        }
    }
}

fn respond(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    response
}

fn error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    respond(status, encoded::<()>(Err(ApiError::new(message))).0)
}

async fn handle(
    gateway: Gateway,
    facts: CallerFacts,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    let Some(command) = writ_proto::Command::from_http(request.method().as_str(), &path) else {
        return error(StatusCode::NOT_FOUND, "no such endpoint");
    };
    let body = if approval_has_body(&command) {
        match Limited::new(request.into_body(), MAX_BODY).collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(_) => {
                return error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &format!("the request is larger than {MAX_BODY} bytes"),
                );
            }
        }
    } else {
        Vec::new()
    };
    let (reply, failure) = approval_reply(gateway.service().clone(), facts, command, body).await;
    let status = if failure.is_some() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    respond(status, reply)
}
