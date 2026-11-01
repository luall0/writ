//! The `writ` commands, over SSH and HTTPS alike: the agent's (submit a ticket, wait for the
//! decision) and the approval API's. Replies are one JSON line (`writ_proto`), with the
//! reason as the failure when they fail.

use std::sync::Arc;

use russh::server::Msg;
use russh::{Channel, ChannelReadHalf};
use serde::Serialize;
use writ_approval::{Service, ServiceError};
use writ_core::caller::CallerFacts;
use writ_crypto::ssh_key::PublicKey;
use writ_proto::{ApiError, Command, MAX_BODY};

use crate::channel::reply;
use crate::{Gateway, limits};

/// Runs an agent command (`writ request`, `writ wait`) for the session key the client
/// authenticated with.
pub(crate) async fn run_agent(
    gateway: Gateway,
    key: PublicKey,
    facts: CallerFacts,
    command: Command,
    channel: Channel<Msg>,
) {
    let (mut rx, tx) = channel.split();
    let service = gateway.service().clone();
    let result = match command {
        Command::Request => match read_body(&mut rx).await {
            Ok(body) => encoded(blocking(move || service.submit(&key, &body, &facts)).await),
            Err(e) => encoded::<()>(Err(e)),
        },
        Command::Wait { id } => encoded(served(service.wait(&id, &key).await)),
        // The handler routes only agent commands here.
        _ => encoded::<()>(Err(ApiError::new("command not allowed here"))),
    };
    reply(tx, result).await;
}

/// Runs an approval command over SSH: its body (if it has one) from stdin.
pub(crate) async fn run_approval(
    gateway: Gateway,
    facts: CallerFacts,
    command: Command,
    channel: Channel<Msg>,
) {
    let (mut rx, tx) = channel.split();
    let body = if approval_has_body(&command) {
        match read_body(&mut rx).await {
            Ok(body) => body,
            Err(e) => return reply(tx, encoded::<()>(Err(e))).await,
        }
    } else {
        Vec::new()
    };
    let result = approval_reply(gateway.service().clone(), facts, command, body).await;
    reply(tx, result).await;
}

/// Whether an approval command reads a JSON body.
pub(crate) fn approval_has_body(command: &Command) -> bool {
    matches!(
        command,
        Command::Approve { .. } | Command::Refuse { .. } | Command::Revoke { .. }
    )
}

/// Runs an approval command, the same over SSH and HTTPS: the reply bytes, and the failure
/// to report. `body` is the command's JSON body (empty when it has none).
pub(crate) async fn approval_reply(
    service: Arc<Service>,
    facts: CallerFacts,
    command: Command,
    body: Vec<u8>,
) -> (Vec<u8>, Option<String>) {
    let empty = body.iter().all(u8::is_ascii_whitespace);
    match command {
        Command::Info => encoded(Ok(service.info())),
        Command::List { all } => encoded(blocking(move || service.list(all)).await),
        Command::Show { id } => encoded(blocking(move || service.show(&id)).await),
        Command::Approve { id } => match writ_proto::decode_body(&body) {
            Ok(request) => encoded(blocking(move || service.approve(&id, &request, &facts)).await),
            Err(e) => encoded::<()>(Err(e)),
        },
        Command::Refuse { id } => match writ_proto::decode_body(&body) {
            Ok(request) => encoded(blocking(move || service.refuse(&id, &request, &facts)).await),
            Err(e) => encoded::<()>(Err(e)),
        },
        Command::Revoke { id } => {
            let request = if empty {
                Ok(writ_proto::RevokeRequest::default())
            } else {
                writ_proto::decode_body(&body)
            };
            match request {
                Ok(request) => {
                    encoded(blocking(move || service.revoke(&id, &request, &facts)).await)
                }
                Err(e) => encoded::<()>(Err(e)),
            }
        }
        Command::Request | Command::Wait { .. } => {
            encoded::<()>(Err(ApiError::new("command not allowed here")))
        }
    }
}

/// The reply bytes, and the failure to show on stderr.
pub(crate) fn encoded<T: Serialize>(result: Result<T, ApiError>) -> (Vec<u8>, Option<String>) {
    let failure = result.as_ref().err().map(ToString::to_string);
    (writ_proto::encode_reply(&result), failure)
}

/// Runs a service call (SQLite, fsync) off the async threads.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, ServiceError> + Send + 'static,
) -> Result<T, ApiError> {
    let result = tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|e| Err(ServiceError::internal(e)));
    served(result)
}

/// What the client sees of a service result. An internal cause is logged here, the client
/// gets only "internal error".
fn served<T>(result: Result<T, ServiceError>) -> Result<T, ApiError> {
    result.map_err(|error| {
        if matches!(error, ServiceError::Internal(_) | ServiceError::AuditLog(_)) {
            tracing::error!(error = %error.detail(), "request failed inside the daemon");
        }
        ApiError::from(error)
    })
}

/// Reads the command's body (stdin, until EOF), at most [`MAX_BODY`] bytes, within
/// [`limits::BODY_DEADLINE`].
async fn read_body(rx: &mut ChannelReadHalf) -> Result<Vec<u8>, ApiError> {
    let body = limits::read_within(rx.make_reader(), MAX_BODY, limits::BODY_DEADLINE)
        .await
        .map_err(ApiError::new)?;
    if body.len() > MAX_BODY {
        return Err(ApiError::new(format!(
            "the request is larger than {MAX_BODY} bytes"
        )));
    }
    Ok(body)
}
