//! The `writ` commands, over SSH and HTTPS alike: the agent's (submit a ticket, wait for the
//! decision) and the approval API's. Replies are one JSON line (`writ_proto`), with the
//! reason as the failure when they fail.

use std::sync::Arc;

use russh::server::Msg;
use russh::{Channel, ChannelMsg, ChannelReadHalf};
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

/// Runs an agent command (`writ request`, its dry run, `writ policy`, `writ wait`, `writ
/// close`) for the session key the client authenticated with.
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
        Command::DryRun => match read_body(&mut rx).await {
            Ok(body) => encoded(blocking(move || service.dry_run(&key, &body, &facts)).await),
            Err(e) => encoded::<()>(Err(e)),
        },
        Command::Policy { repo } => {
            encoded(blocking(move || service.repo_policy(&repo, &facts)).await)
        }
        Command::Close { id } => match read_body(&mut rx).await {
            Ok(body) => match writ_proto::decode_body::<writ_proto::CloseRequest>(&body) {
                Ok(request) => {
                    encoded(blocking(move || service.close(&id, &key, &request, &facts)).await)
                }
                Err(e) => encoded::<()>(Err(e)),
            },
            Err(e) => encoded::<()>(Err(e)),
        },
        // Raced against the channel: a client gone (its channel closed or the connection
        // lost) ends the wait, so waits never outlive their connection and pile up (the
        // review after M5.5, S11). The client's EOF (it has nothing to send) is not an end.
        Command::Wait { id } => {
            let waited = service.wait(&id, &key);
            tokio::pin!(waited);
            loop {
                tokio::select! {
                    result = &mut waited => break encoded(served(result)),
                    message = rx.wait() => match message {
                        None | Some(ChannelMsg::Close) => return,
                        Some(_) => {}
                    },
                }
            }
        }
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
        Zeroizing::new(Vec::new())
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
            | Command::Scan
            | Command::TlsRotate
    )
}

/// Runs an approval command, the same over SSH and HTTPS: the reply bytes, and the failure
/// to report. `body` is the command's JSON body (empty when it has none).
pub(crate) async fn approval_reply(
    gateway: Gateway,
    facts: CallerFacts,
    command: Command,
    // An unseal's body holds the passphrase: wiped once read, by every path that read it.
    body: Zeroizing<Vec<u8>>,
) -> (Vec<u8>, Option<String>) {
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
        Command::Report { id } => encoded(blocking(move || service.report(&id)).await),
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
        Command::TlsShow => match gateway.shared.config.admin.clone() {
            Some(applier) => match applier.tls_show().await {
                Ok(shown) => encoded(Ok(shown)),
                Err(reason) => encoded::<()>(Err(ApiError::new(reason))),
            },
            None => encoded::<()>(Err(ApiError::new("this daemon takes no admin change"))),
        },
        Command::TlsRotate => tls_rotate(gateway, facts, &body).await,
        Command::ScanNonce => encoded(blocking(move || service.scan_nonce()).await),
        Command::Scan => scan(gateway, facts, &body).await,
        Command::RepoCheck { repo } => check(gateway, facts, repo).await,
        Command::AdminKeys => match gateway.shared.config.admin.clone() {
            Some(applier) => match applier.keys_show().await {
                Ok(shown) => encoded(Ok(shown)),
                Err(reason) => encoded::<()>(Err(ApiError::new(reason))),
            },
            None => encoded::<()>(Err(ApiError::new("this daemon takes no admin change"))),
        },
        Command::Request
        | Command::DryRun
        | Command::Policy { .. }
        | Command::Wait { .. }
        | Command::Close { .. } => encoded::<()>(Err(ApiError::new("command not allowed here"))),
    }
}

/// `writ admin host add`'s scan: the service checks the `writ-scan/1` and its signature (its
/// nonce used); the host's keys read ([`writ_mirror::scan`]), logged with their fingerprints,
/// and shown, never pinned.
async fn scan(gateway: Gateway, facts: CallerFacts, body: &[u8]) -> (Vec<u8>, Option<String>) {
    let request: writ_proto::ScanRequest = match writ_proto::decode_body(body) {
        Ok(request) => request,
        Err(e) => return encoded::<()>(Err(e)),
    };
    let (service, caller) = (gateway.service().clone(), facts.clone());
    let checked = match blocking(move || service.check_scan(&request, &caller)).await {
        Ok(checked) => checked,
        Err(e) => return encoded::<()>(Err(e)),
    };
    let (host, port) = (checked.scan().host.clone(), checked.scan().port);
    let deadline = gateway
        .mirrors()
        .map(|m| m.scan_timeout())
        .unwrap_or(writ_mirror::scan::DEFAULT_HANDSHAKE_DEADLINE);
    // Through the proxy the signed scan names, as the policy in force declares it.
    let proxy = checked.scan().proxy.clone();
    let dialer = match proxy.as_ref() {
        None => Ok(writ_mirror::dial::Dialer::Direct),
        Some(_) => gateway
            .mirrors()
            .map_err(|e| e.to_string())
            .and_then(|m| m.dialer(proxy.as_ref())),
    };
    let scanned = match dialer {
        Ok(dialer) => writ_mirror::scan::scan(host.as_str(), port, &dialer, deadline)
            .await
            .map_err(|e| e.to_string()),
        Err(why) => Err(why),
    };
    let service = gateway.service().clone();
    match scanned {
        Ok(keys) => {
            let shown: Vec<writ_proto::ScannedKey> = keys
                .iter()
                .filter_map(|key| {
                    let line = key.to_openssh().ok()?;
                    let key_line = line.split(' ').take(2).collect::<Vec<_>>().join(" ");
                    Some(writ_proto::ScannedKey {
                        key: key_line,
                        fingerprint: key
                            .fingerprint(writ_crypto::ssh_key::HashAlg::Sha256)
                            .to_string(),
                    })
                })
                .collect();
            let fingerprints: Vec<String> = shown.iter().map(|k| k.fingerprint.clone()).collect();
            let pin = match writ_core::config::UpstreamHost::of(host.as_str(), port) {
                Ok(pin) => pin.to_string(),
                Err(e) => return encoded::<()>(Err(ApiError::new(e.to_string()))),
            };
            let logged = checked.clone();
            blocking(move || {
                service.scan_logged(Some(&logged), Ok(&fingerprints), &facts);
                Ok::<(), writ_approval::ServiceError>(())
            })
            .await
            .ok();
            encoded(Ok(writ_proto::Scanned {
                host: pin,
                keys: shown,
            }))
        }
        Err(why) => {
            let logged = (checked.clone(), why.clone());
            blocking(move || {
                service.scan_logged(Some(&logged.0), Err(&logged.1), &facts);
                Ok::<(), writ_approval::ServiceError>(())
            })
            .await
            .ok();
            encoded::<()>(Err(ApiError::new(why)))
        }
    }
}

/// `writ admin repo check <repo>`: allowed by the service (in the registry, within the
/// rate), then run by the mirrors (read, sync, write with nothing pushed), logged.
async fn check(
    gateway: Gateway,
    facts: CallerFacts,
    repo: writ_core::names::RepoName,
) -> (Vec<u8>, Option<String>) {
    let (service, caller, asked) = (gateway.service().clone(), facts.clone(), repo.clone());
    if let Err(e) = blocking(move || service.check_allowed(&asked, &caller)).await {
        return encoded::<()>(Err(e));
    }
    let mirrors = match gateway.mirrors() {
        Ok(mirrors) => mirrors,
        Err(reason) => return encoded::<()>(Err(ApiError::new(reason))),
    };
    let checked = mirrors.check(&repo).await;
    let service = gateway.service().clone();
    let (steps, refused) = match checked {
        Ok(steps) => (
            steps
                .into_iter()
                .map(|s| writ_proto::CheckStep {
                    what: s.what.to_owned(),
                    ok: s.ok,
                    said: s.said,
                })
                .collect::<Vec<_>>(),
            None,
        ),
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    let logged = (repo.clone(), steps.clone(), refused.clone());
    blocking(move || {
        service.check_logged(&logged.0, &logged.1, logged.2.as_deref(), &facts);
        Ok::<(), writ_approval::ServiceError>(())
    })
    .await
    .ok();
    match refused {
        Some(why) => encoded::<()>(Err(ApiError::new(why))),
        None => encoded(Ok(writ_proto::UpstreamChecked { repo, steps })),
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

/// `writ admin tls rotate` (M7.5): the service checks the `writ-tls/1` and its signature; the
/// daemon checks it names the certificate in force and makes the new key and certificate, put
/// in force at once (this connection keeps the one it was opened with). One admin change at a
/// time; the outcome logged once, here (`admin`).
async fn tls_rotate(
    gateway: Gateway,
    facts: CallerFacts,
    body: &[u8],
) -> (Vec<u8>, Option<String>) {
    let request: writ_proto::TlsRequest = match writ_proto::decode_body(body) {
        Ok(request) => request,
        Err(e) => return encoded::<()>(Err(e)),
    };
    let Some(applier) = gateway.shared.config.admin.clone() else {
        return encoded::<()>(Err(ApiError::new("this daemon takes no admin change")));
    };
    let _one = gateway.shared.administering.lock().await;
    let (service, caller) = (gateway.service().clone(), facts.clone());
    let checked = match blocking(move || service.check_tls(&request, &caller)).await {
        Ok(checked) => checked,
        Err(e) => return encoded::<()>(Err(e)),
    };
    let done = applier.rotate_tls(checked.clone(), facts.clone()).await;
    let service = gateway.service().clone();
    let logged = done.clone();
    blocking(move || {
        match &logged {
            Ok(rotated) => service.tls_logged(Some(&checked), Ok(&rotated.fingerprint), &facts),
            Err(why) => service.tls_logged(Some(&checked), Err(why), &facts),
        }
        Ok::<(), writ_approval::ServiceError>(())
    })
    .await
    .ok();
    match done {
        Ok(rotated) => encoded(Ok(rotated)),
        Err(reason) => encoded::<()>(Err(ApiError::new(format!("not rotated: {reason}")))),
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
async fn read_body(rx: &mut ChannelReadHalf) -> Result<Zeroizing<Vec<u8>>, ApiError> {
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
