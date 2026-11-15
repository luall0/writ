//! `writ git fetch` and `writ git pull` with no lease (M7.9.7): when one of the repository's
//! templates has `unsigned_fetch` on (the first `writ policy` lists), `writ` asks the daemon
//! for a fetch-only lease under it (granted with no signature, for that time), runs git under that lease, then closes it and removes its
//! session files, whatever git's exit. Nothing points `current` at it and no run goes in the
//! timings file: the agent sees a fetch, not a lease.
//!
//! A convenience: the daemon decides the grant, as for any ticket. With no lease named and
//! no such template, git runs as before and the daemon refuses it.

use std::path::Path;
use std::process::Command;

use anyhow::Context;
use writ_core::canonical::Canonical;
use writ_core::names::TicketId;
use writ_core::ticket::Ticket;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{LineEnding, PrivateKey};
use writ_proto::{CLIENT_USER, CloseRequest, Command as Call, Decision, RepoPolicy, Submitted};

use crate::client::{Endpoint, Session};
use crate::session::{create_private_dir, session_dir, write_file, write_private};
use crate::wiring::{self, Mode, SessionRef, Wiring};
use crate::{Exit, Paths, display};

/// The git commands a lease granted with no signature serves: they only fetch (a `pull` that
/// would make a merge commit fails at its signature: the lease has no `commit_sign`).
const FETCHING: [&str; 2] = ["fetch", "pull"];

/// The summary an unsigned lease is closed with.
const SUMMARY: &str =
    "Fetched by writ git with no lease (unsigned_fetch); closed when git returned.";

/// Whether `writ git <command>` in a repository wired as `wired` fetches with no lease: a
/// fetching command, and no lease named or running (`WRIT_SESSION` unset, the repo pinned to
/// none, `current` pointing at no lease still running). A lease named but ended, or one
/// without `fetch`, is never replaced: the command runs under it and the daemon decides.
pub fn applies(home: &Path, wired: &Wiring, command: Option<&str>) -> anyhow::Result<bool> {
    if !command.is_some_and(|c| FETCHING.contains(&c)) {
        return Ok(false);
    }
    if std::env::var("WRIT_SESSION").is_ok_and(|v| !v.is_empty()) || wired.lease.is_some() {
        return Ok(false);
    }
    Ok(match SessionRef::Current.resolved(home)? {
        SessionRef::Current => true,
        SessionRef::Lease(id) => wiring::check_session(home, &id).is_err(),
    })
}

/// The daemon's agents listener for the repository `wired`.
fn endpoint(wired: &Wiring) -> anyhow::Result<Endpoint> {
    match &wired.socket {
        Some(socket) => Endpoint::parse(&format!("unix:{}", socket.display())),
        None => Endpoint::parse(&wired.base_url),
    }
}

/// The first of the repository's templates whose `unsigned_fetch` is on, as `writ policy`
/// lists them; none when it has none (or the daemon refuses the read).
async fn template(
    paths: &Paths,
    endpoint: &Endpoint,
    wired: &Wiring,
) -> anyhow::Result<Option<writ_proto::TemplateView>> {
    let key = generate(KeyKind::Ed25519)?;
    let reply = Session::connect(endpoint, &paths.known_hosts, CLIENT_USER, key)
        .await?
        .run(async |session| {
            session
                .call::<RepoPolicy>(
                    &Call::Policy {
                        repo: wired.repo.clone(),
                    },
                    b"",
                )
                .await
        })
        .await?;
    Ok(match reply {
        Ok(policy) => policy
            .templates
            .into_iter()
            .find(|t| t.unsigned_fetch.is_some()),
        Err(_) => None,
    })
}

/// The fetch-only ticket `writ` writes for `wired`'s repository under `template`, for its
/// `unsigned_fetch` time.
fn ticket(wired: &Wiring, template: &writ_proto::TemplateView) -> anyhow::Result<String> {
    let ttl = template
        .unsigned_fetch
        .context("the template grants no fetch with no signature")?;
    let text = format!(
        "repos:\n  {repo}:\n    template: {template}\n    operations: [fetch]\n\
         ticket:\n  title: \"Fetch {repo} with no lease (writ git)\"\n  task: \"Fetched by writ \
         git before a ticket: fetch only, closed when git returns.\"\nlimits:\n  ttl: \"{ttl}\"\n",
        repo = wired.repo,
        template = template.name,
        ttl = ttl,
    );
    // Under `writ run`: bound to its session, as `writ request` binds a ticket.
    Ok(match crate::run::session()? {
        Some(pid) => crate::run::bind(&text, pid),
        None => text,
    })
}

/// Runs `command` (git, with its arguments) under a lease granted with no signature, if the
/// repository's policy has a template for it: `None` when it hasn't (the caller runs git as
/// before). The lease is closed and its session removed once git returns.
pub async fn fetch(
    paths: &Paths,
    wired: &Wiring,
    mut command: Command,
) -> anyhow::Result<Option<i32>> {
    let endpoint = endpoint(wired)?;
    let Some(template) = template(paths, &endpoint, wired).await? else {
        return Ok(None);
    };
    let key = generate(KeyKind::Ed25519)?;
    let text = ticket(wired, &template)?;
    let granted = Session::connect(&endpoint, &paths.known_hosts, CLIENT_USER, key.clone())
        .await?
        .run(async |session| request(session, &text).await)
        .await?;
    let (id, lease, certificate) = match granted {
        Ok(granted) => granted,
        Err(exit) => return Ok(Some(exit as i32)),
    };
    let dir = session_dir(paths, &id);
    let ran = run(
        paths,
        wired,
        &key,
        &dir,
        &id,
        &lease,
        &certificate,
        &mut command,
    );
    let closed = close(paths, &endpoint, &key, &id).await;
    if let Err(e) = std::fs::remove_dir_all(&dir)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("writ: cannot remove {}: {e}", dir.display());
    }
    if let Err(e) = closed {
        eprintln!(
            "writ: lease {id} was not closed ({e:#}); it ends by itself at {}",
            lease.limits.expires_at
        );
    }
    ran.map(Some)
}

/// Submits `text` and waits for its grant: the lease, its terms and its certificate, or the
/// exit after printing the daemon's reasons.
async fn request(
    session: &Session,
    text: &str,
) -> anyhow::Result<Result<(TicketId, Ticket, String), Exit>> {
    let submitted: Submitted = match session.call(&Call::Request, text.as_bytes()).await? {
        Ok(submitted) => submitted,
        Err(error) => {
            eprintln!(
                "writ: a fetch with no lease was refused: {}",
                display::clean(&error.message)
            );
            for reason in &error.reasons {
                eprintln!("  - {}", display::clean(reason));
            }
            return Ok(Err(Exit::Rejected));
        }
    };
    let decision: Decision = session
        .call(
            &Call::Wait {
                id: submitted.id.clone(),
            },
            b"",
        )
        .await??;
    match decision {
        Decision::Active {
            lease, certificate, ..
        } => {
            let terms = Ticket::from_canonical(lease.as_bytes())
                .context("the daemon sent a lease that isn't canonical")?;
            Ok(Ok((submitted.id, terms, certificate)))
        }
        // Never pending: anything else is the daemon's answer, said as it is.
        other => {
            eprintln!(
                "writ: a fetch with no lease wasn't granted: ticket {} is {}",
                submitted.id,
                match other {
                    Decision::Applied { .. } => "applied".to_owned(),
                    Decision::Refused { .. } => "refused".to_owned(),
                    Decision::Expired => "expired".to_owned(),
                    Decision::Revoked => "revoked".to_owned(),
                    Decision::Ended { state } => state.to_string(),
                    Decision::Active { .. } => "active".to_owned(),
                }
            );
            Ok(Err(Exit::Ended))
        }
    }
}

/// git under the lease `id`: its session written in `dir` (the key, the certificate, the
/// terms), git's settings and SSH command pointing at it.
#[allow(clippy::too_many_arguments)] // one lease's parts, taken apart once
fn run(
    paths: &Paths,
    wired: &Wiring,
    key: &PrivateKey,
    dir: &Path,
    id: &TicketId,
    lease: &Ticket,
    certificate: &str,
    command: &mut Command,
) -> anyhow::Result<i32> {
    create_private_dir(dir)?;
    write_private(&dir.join("key"), key.to_openssh(LineEnding::LF)?.as_bytes())?;
    write_file(&dir.join("key.pub"), key.public_key().to_openssh()? + "\n")?;
    write_file(
        &dir.join("key-cert.pub"),
        certificate.trim_end().to_owned() + "\n",
    )?;
    write_file(&dir.join("lease.json"), lease.canonical_bytes()?)?;
    eprintln!(
        "writ: no lease: fetching under lease {id}, granted with no signature ({}), closed \
         when git returns",
        display::templates(lease)
    );
    let session = SessionRef::Lease(id.clone());
    if wired.mode == Mode::Wrapper {
        let settings = wiring::settings_with(paths, wired, &session)?;
        let existing = std::env::var("GIT_CONFIG_COUNT").ok();
        command.envs(wiring::config_env(existing.as_deref(), &settings)?);
    }
    // A whole-repo clone's own settings point at `current`: the SSH command, over them, at
    // this lease's session.
    let home = std::path::absolute(&paths.home).context("cannot resolve WRIT_HOME")?;
    let known_hosts =
        std::path::absolute(&paths.known_hosts).context("cannot resolve the known_hosts path")?;
    command.env(
        "GIT_SSH_COMMAND",
        wiring::ssh_command(&session.dir(&home), &known_hosts, wired.socket.as_deref()),
    );
    command.env("WRIT_SESSION", id.as_str());
    let status = command.status().context("cannot run git")?;
    // git's own exit, as `writ git` gives it otherwise (a signal: 128 and its number).
    Ok(status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        128_i32.saturating_add(status.signal().unwrap_or(0))
    }))
}

/// Closes the lease `id` with [`SUMMARY`]; its report isn't printed or recorded.
async fn close(
    paths: &Paths,
    endpoint: &Endpoint,
    key: &PrivateKey,
    id: &TicketId,
) -> anyhow::Result<()> {
    let body = writ_proto::encode_body(&CloseRequest {
        summary: SUMMARY.to_owned(),
    })?;
    let _: writ_proto::Report =
        Session::connect(endpoint, &paths.known_hosts, CLIENT_USER, key.clone())
            .await?
            .run(async |session| {
                Ok(session
                    .call(&Call::Close { id: id.clone() }, &body)
                    .await??)
            })
            .await?;
    Ok(())
}
