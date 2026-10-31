//! The agent's side: `writ request` and `writ wait`.
//!
//! `writ request` generates a session key, submits the ticket file over the agents' listener
//! authenticated with that key (so the daemon knows the submitter holds it), and waits for
//! the decision. Once signed, the session lives in `<home>/sessions/<lease>/`: `key`,
//! `key.pub`, `key-cert.pub` (the certificate, valid until the lease expires), `ticket.json`
//! (as submitted) and `lease.json` (as signed: narrowed if the approver narrowed it);
//! `<home>/sessions/current` points at it.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use writ_core::names::TicketId;
use writ_core::ticket::{Ticket, TicketRequest};
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{LineEnding, PrivateKey};
use writ_proto::{Command, Decision, Submitted};

use crate::client::{Endpoint, Session};
use crate::display;
use crate::{Exit, Paths};

/// The SSH user for ticket submission (a plain key, no certificate).
const CLIENT_USER: &str = "writ";

fn session_dir(paths: &Paths, id: &TicketId) -> PathBuf {
    paths.home.join("sessions").join(id.as_str())
}

fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(bytes)?;
    Ok(())
}

fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path).with_context(|| format!("cannot create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn load_key(path: &Path) -> anyhow::Result<PrivateKey> {
    let text =
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(PrivateKey::from_openssh(text)?)
}

/// Submits a ticket file and, unless `no_wait`, waits for the decision.
pub async fn request(paths: &Paths, url: &str, file: &Path, no_wait: bool) -> anyhow::Result<Exit> {
    let text = if file == Path::new("-") {
        std::io::read_to_string(std::io::stdin()).context("cannot read the ticket from stdin")?
    } else {
        fs::read_to_string(file).with_context(|| format!("cannot read {}", file.display()))?
    };
    // A convenience check; the daemon checks again (with the templates).
    let parsed = match TicketRequest::from_yaml(&text) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("writ: the ticket file is invalid: {e}");
            return Ok(Exit::Rejected);
        }
    };
    // An amendment comes from the lease's own session (same key).
    let (key, new_session) = match &parsed.ticket.amends {
        Some(lease) => (load_key(&session_dir(paths, lease).join("key"))?, false),
        None => (generate(KeyKind::Ed25519)?, true),
    };
    let endpoint = Endpoint::parse(url)?;
    let session = Session::connect(&endpoint, &paths.known_hosts, CLIENT_USER, key.clone()).await?;
    let result: anyhow::Result<Exit> = async {
        let submitted: Submitted = match session.call(&Command::Request, text.as_bytes()).await? {
            Ok(submitted) => submitted,
            Err(error) => {
                eprintln!("writ: {}", error.message);
                for reason in &error.reasons {
                    eprintln!("  - {reason}");
                }
                return Ok(Exit::Rejected);
            }
        };
        let ticket = Ticket::from_canonical(submitted.canonical.as_bytes())
            .context("the daemon sent a ticket that isn't canonical")?;
        let dir = match &ticket.ticket.amends {
            Some(lease) => session_dir(paths, lease),
            None => session_dir(paths, &submitted.id),
        };
        if new_session {
            create_private_dir(&dir)?;
            write_private(&dir.join("key"), key.to_openssh(LineEnding::LF)?.as_bytes())?;
            fs::write(dir.join("key.pub"), key.public_key().to_openssh()? + "\n")?;
        }
        fs::write(
            dir.join(format!("{}.json", submitted.id)),
            &submitted.canonical,
        )?;
        if new_session {
            fs::write(dir.join("ticket.json"), &submitted.canonical)?;
        }
        println!(
            "Ticket {} submitted (template {}, revision {}, expires {}).",
            submitted.id, ticket.template, ticket.ticket.revision, ticket.limits.expires_at
        );
        println!(
            "Waiting for the approver: `writ sign {}` on the approver's machine.",
            submitted.id
        );
        if no_wait {
            return Ok(Exit::Ok);
        }
        decide(paths, &session, &submitted.id, &dir, Some(&ticket)).await
    }
    .await;
    session.close().await;
    result
}

/// Waits for a ticket submitted earlier from this host.
pub async fn wait(
    paths: &Paths,
    url: &str,
    id: &TicketId,
    lease: Option<&TicketId>,
) -> anyhow::Result<Exit> {
    let dir = session_dir(paths, lease.unwrap_or(id));
    let key = load_key(&dir.join("key")).with_context(|| {
        format!(
            "no session for {id} on this host (looked in {})",
            dir.display()
        )
    })?;
    let submitted = fs::read(dir.join(format!("{id}.json")))
        .ok()
        .and_then(|bytes| Ticket::from_canonical(&bytes).ok());
    let endpoint = Endpoint::parse(url)?;
    let session = Session::connect(&endpoint, &paths.known_hosts, CLIENT_USER, key).await?;
    let result: anyhow::Result<Exit> =
        async { decide(paths, &session, id, &dir, submitted.as_ref()).await }.await;
    session.close().await;
    result
}

async fn decide(
    paths: &Paths,
    session: &Session,
    id: &TicketId,
    dir: &Path,
    submitted: Option<&Ticket>,
) -> anyhow::Result<Exit> {
    let decision: Decision = match session.call(&Command::Wait { id: id.clone() }, b"").await? {
        Ok(decision) => decision,
        Err(error) => bail!("{error}"),
    };
    match decision {
        Decision::Active { lease, certificate } => {
            let terms = Ticket::from_canonical(lease.as_bytes())
                .context("the daemon sent a lease that isn't canonical")?;
            fs::write(
                dir.join("key-cert.pub"),
                certificate.trim_end().to_owned() + "\n",
            )?;
            fs::write(dir.join("lease.json"), &lease)?;
            point_current(paths, id)?;
            println!(
                "Lease {id} granted until {}: {} on {}, branches {}.",
                terms.limits.expires_at,
                display::fields(&terms)
                    .into_iter()
                    .find(|(l, _)| *l == "operations")
                    .map(|(_, v)| v)
                    .unwrap_or_default(),
                terms
                    .scope
                    .repos
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                terms
                    .scope
                    .branches
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            print_narrowing(submitted, &terms);
            println!("Session files: {}", dir.display());
            Ok(Exit::Ok)
        }
        Decision::Applied { lease } => {
            let terms = Ticket::from_canonical(lease.as_bytes())
                .context("the daemon sent a lease that isn't canonical")?;
            fs::write(dir.join("lease.json"), &lease)?;
            println!(
                "Amendment {id} signed: lease {} now runs under its terms (until {}).",
                terms.lease_id(),
                terms.limits.expires_at
            );
            print_narrowing(submitted, &terms);
            Ok(Exit::Ok)
        }
        Decision::Refused { feedback } => {
            println!("Ticket {id} was refused. The approver's feedback:");
            print!("{}", display::block(&feedback, "  "));
            println!("Revise the ticket and submit it again with `ticket.revises: {id}`.");
            Ok(Exit::Refused)
        }
        Decision::Expired => {
            println!("Ticket {id} expired before it was signed.");
            Ok(Exit::Ended)
        }
        Decision::Revoked => {
            println!("Ticket {id} was withdrawn or its lease revoked.");
            Ok(Exit::Ended)
        }
        Decision::Ended { state } => {
            println!("Lease {id} is {state}.");
            Ok(Exit::Ended)
        }
    }
}

fn print_narrowing(submitted: Option<&Ticket>, terms: &Ticket) {
    let Some(submitted) = submitted else { return };
    let changes = display::diff(submitted, terms);
    if !changes.is_empty() {
        print!(
            "{}",
            display::changes("The approver narrowed the ticket:", &changes)
        );
    }
}

/// Points `<home>/sessions/current` at a lease's session, replacing the link atomically.
fn point_current(paths: &Paths, id: &TicketId) -> anyhow::Result<()> {
    let sessions = paths.home.join("sessions");
    let temporary = sessions.join(format!(".current-{id}"));
    let _ = fs::remove_file(&temporary);
    std::os::unix::fs::symlink(id.as_str(), &temporary)?;
    fs::rename(&temporary, sessions.join("current"))?;
    Ok(())
}
