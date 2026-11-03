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
use writ_proto::{
    AdminRequest, ApiError, Command, MAX_BODY, TokenRequest, UnsealRequest, Unsealed,
};
use zeroize::Zeroizing;

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
    if gateway.service().is_sealed() {
        gateway.refused_sealed(facts).await;
        return reply(tx, sealed()).await;
    }
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
    let result = approval_reply(gateway, facts, command, body).await;
    reply(tx, result).await;
}

/// What every request but `info` and `unseal` gets while the daemon is sealed.
fn sealed() -> (Vec<u8>, Option<String>) {
    encoded::<()>(Err(ApiError::new(writ_core::policy::SEALED)))
}

/// Whether an approval command reads a JSON body.
pub(crate) fn approval_has_body(command: &Command) -> bool {
    matches!(
        command,
        Command::Approve { .. }
            | Command::Refuse { .. }
            | Command::Revoke { .. }
            | Command::Prove
            | Command::Unseal
            | Command::AdminApply
            | Command::TokenApply
    )
}

/// Runs an approval command, the same over SSH and HTTPS: the reply bytes, and the failure
/// to report. `body` is the command's JSON body (empty when it has none).
pub(crate) async fn approval_reply(
    gateway: Gateway,
    facts: CallerFacts,
    command: Command,
    body: Vec<u8>,
) -> (Vec<u8>, Option<String>) {
    // An unseal's body holds the passphrase: wiped once read.
    let body = Zeroizing::new(body);
    let service: Arc<Service> = gateway.service().clone();
    if service.is_sealed() && !matches!(command, Command::Info | Command::Unseal) {
        gateway.refused_sealed(facts).await;
        return sealed();
    }
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
        Command::Prove => match writ_proto::decode_body(&body) {
            Ok(request) => encoded(blocking(move || service.prove(&request, &facts)).await),
            Err(e) => encoded::<()>(Err(e)),
        },
        Command::Unseal => unseal(gateway, facts, &body).await,
        Command::AdminShow { target } => {
            encoded(blocking(move || service.admin_show(target)).await)
        }
        Command::AdminApply => admin_apply(gateway, facts, &body).await,
        Command::TokenShow { id } => match gateway.shared.config.admin.clone() {
            Some(applier) => match applier.token_show(id).await {
                Ok(shown) => encoded(Ok(shown)),
                Err(reason) => encoded::<()>(Err(ApiError::new(reason))),
            },
            None => encoded::<()>(Err(ApiError::new("this daemon takes no admin change"))),
        },
        Command::TokenApply => token_apply(gateway, facts, &body).await,
        Command::Request | Command::Wait { .. } => {
            encoded::<()>(Err(ApiError::new("command not allowed here")))
        }
    }
}

/// `writ admin apply`: the service checks the document and the approver's signature against
/// the version in force; then the daemon's [`crate::AdminApplier`] checks the new text, has it
/// recorded and swaps it in. One change at a time; refusals are logged by the service or the
/// applier, once.
async fn admin_apply(
    gateway: Gateway,
    facts: CallerFacts,
    body: &[u8],
) -> (Vec<u8>, Option<String>) {
    let request: AdminRequest = match writ_proto::decode_body(body) {
        Ok(request) => request,
        Err(e) => return encoded::<()>(Err(e)),
    };
    let Some(applier) = gateway.shared.config.admin.clone() else {
        return encoded::<()>(Err(ApiError::new("this daemon takes no admin change")));
    };
    let _one = gateway.shared.administering.lock().await;
    let (service, caller) = (gateway.service().clone(), facts.clone());
    let checked = match blocking(move || service.check_admin(&request, &caller)).await {
        Ok(checked) => checked,
        Err(e) => return encoded::<()>(Err(e)),
    };
    match applier.apply(checked, facts).await {
        Ok(applied) => encoded(Ok(applied)),
        Err(reason) => encoded::<()>(Err(ApiError::new(format!("not applied: {reason}")))),
    }
}

/// `writ admin token`: the service checks the document and the approver's signature; then the
/// daemon's [`crate::AdminApplier`] opens the token, has the change logged against the file in
/// force, writes it and uses it. One change at a time (admin changes included); refusals are
/// logged by the service or the applier, once.
async fn token_apply(
    gateway: Gateway,
    facts: CallerFacts,
    body: &[u8],
) -> (Vec<u8>, Option<String>) {
    let request: TokenRequest = match writ_proto::decode_body(body) {
        Ok(request) => request,
        Err(e) => return encoded::<()>(Err(e)),
    };
    let Some(applier) = gateway.shared.config.admin.clone() else {
        return encoded::<()>(Err(ApiError::new("this daemon takes no admin change")));
    };
    let _one = gateway.shared.administering.lock().await;
    let (service, caller) = (gateway.service().clone(), facts.clone());
    let checked = match blocking(move || service.check_token(&request, &caller)).await {
        Ok(checked) => checked,
        Err(e) => return encoded::<()>(Err(e)),
    };
    match applier.apply_token(checked, facts).await {
        Ok(applied) => encoded(Ok(applied)),
        Err(reason) => encoded::<()>(Err(ApiError::new(format!("not applied: {reason}")))),
    }
}

/// `writ unseal`: the service checks the document and the approver's signature (this daemon,
/// this boot) before the passphrase is tried; then the daemon's [`crate::Unsealer`] opens
/// the keystore. One unseal at a time; a refusal after the check is logged here, once.
async fn unseal(gateway: Gateway, facts: CallerFacts, body: &[u8]) -> (Vec<u8>, Option<String>) {
    let request: UnsealRequest = match writ_proto::decode_body(body) {
        Ok(request) => request,
        Err(e) => return encoded::<()>(Err(e)),
    };
    let Some(unsealer) = gateway.shared.config.unsealer.clone() else {
        return encoded::<()>(Err(ApiError::new(
            "this daemon has no sealed keystore: there is nothing to unseal",
        )));
    };
    let Ok(_one) = gateway.shared.unsealing.try_lock() else {
        return encoded::<()>(Err(ApiError::new(
            "an unseal is already in progress: wait for it",
        )));
    };
    let (service, caller) = (gateway.service().clone(), facts.clone());
    let checked = blocking(move || {
        service
            .check_unseal(&request, &caller)
            .map(|approver| (approver, request))
    })
    .await;
    let (approver, request) = match checked {
        Ok(checked) => checked,
        Err(e) => return encoded::<()>(Err(e)),
    };
    match unsealer
        .unseal(request.passphrase, approver.clone(), facts.clone())
        .await
    {
        Ok(()) => encoded(Ok(Unsealed {
            signed_by: approver,
        })),
        Err(reason) => {
            let (service, logged) = (gateway.service().clone(), reason.clone());
            let _ = tokio::task::spawn_blocking(move || {
                service.unseal_failed(Some(&approver), &logged, &facts);
            })
            .await;
            encoded::<()>(Err(ApiError::new(format!("not unsealed: {reason}"))))
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
