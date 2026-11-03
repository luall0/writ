//! The agent's side: `writ request` and `writ wait`.
//!
//! `writ request` generates a session key (or reuses the session's: an amendment's lease, a
//! revision's refused ticket), submits the ticket file over the agents' listener
//! authenticated with that key (so the daemon knows the submitter holds it), and waits for
//! the decision. Once signed, the session lives in `<home>/sessions/<lease>/`: `key`,
//! `key.pub`, `key-cert.pub` (the certificate, valid until the lease expires), `ticket.json`
//! (as submitted), `lease.json` (as signed: narrowed if the approver narrowed it) and
//! `signing_key.pub` (the daemon's key for the lease's commits, when it signs);
//! `<home>/sessions/current` points at it.

use std::fs;
use std::path::Path;

use anyhow::Context;
use writ_core::names::TicketId;
use writ_core::ticket::{Ticket, TicketRequest};
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::LineEnding;
use writ_proto::{CLIENT_USER, Command, Decision, Submitted};

use crate::client::{Endpoint, Session};
use crate::display;
use crate::session::{
    create_private_dir, load_key, point_current, session_dir, write_file, write_private,
};
use crate::{Exit, Paths};
use writ_core::canonical::Canonical;

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
    // An amendment comes from the lease's own session, a revision from the refused ticket's
    // (same key): the daemon refuses either from another session. A revision is a new ticket,
    // so it gets its own session directory, with that same key.
    let (key, new_session) = match (&parsed.ticket.amends, &parsed.ticket.revises) {
        (Some(lease), _) => (load_key(&session_dir(paths, lease).join("key"))?, false),
        (None, Some(refused)) => {
            let path = session_dir(paths, refused).join("key");
            let key = load_key(&path).with_context(|| {
                format!(
                    "a revision of {refused} comes from the session that submitted it, and \
                     it isn't on this host (looked in {})",
                    path.display()
                )
            })?;
            (key, true)
        }
        (None, None) => (generate(KeyKind::Ed25519)?, true),
    };
    let endpoint = Endpoint::parse(url)?;
    let session = Session::connect(&endpoint, &paths.known_hosts, CLIENT_USER, key.clone()).await?;
    session
        .run(async |session| {
            let submitted: Submitted =
                match session.call(&Command::Request, text.as_bytes()).await? {
                    Ok(submitted) => submitted,
                    Err(error) => {
                        eprintln!("writ: {}", display::clean(&error.message));
                        for reason in &error.reasons {
                            eprintln!("  - {}", display::clean(reason));
                        }
                        return Ok(Exit::Rejected);
                    }
                };
            let ticket = Ticket::from_canonical(submitted.canonical.as_bytes())
                .context("the daemon sent a ticket that isn't canonical")?;
            let dir = match &ticket.text.amends {
                Some(lease) => session_dir(paths, lease),
                None => session_dir(paths, &submitted.id),
            };
            if new_session {
                create_private_dir(&dir)?;
                write_private(&dir.join("key"), key.to_openssh(LineEnding::LF)?.as_bytes())?;
                write_file(&dir.join("key.pub"), key.public_key().to_openssh()? + "\n")?;
            }
            write_file(
                &dir.join(format!("{}.json", submitted.id)),
                &submitted.canonical,
            )?;
            if new_session {
                write_file(&dir.join("ticket.json"), &submitted.canonical)?;
            }
            println!(
                "Ticket {} submitted (template {}, revision {}, expires {}).",
                submitted.id, ticket.template, ticket.text.revision, ticket.limits.expires_at
            );
            println!(
                "Waiting for the approver: `writ sign {}` on the approver's machine.",
                submitted.id
            );
            if no_wait {
                return Ok(Exit::Ok);
            }
            decide(paths, session, &submitted.id, &dir, Some(&ticket)).await
        })
        .await
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
    Session::connect(&endpoint, &paths.known_hosts, CLIENT_USER, key)
        .await?
        .run(async |session| decide(paths, session, id, &dir, submitted.as_ref()).await)
        .await
}

async fn decide(
    paths: &Paths,
    session: &Session,
    id: &TicketId,
    dir: &Path,
    submitted: Option<&Ticket>,
) -> anyhow::Result<Exit> {
    let decision: Decision = session
        .call(&Command::Wait { id: id.clone() }, b"")
        .await??;
    match decision {
        Decision::Active {
            lease,
            certificate,
            signing_key,
            signing_certificate,
        } => {
            let terms = Ticket::from_canonical(lease.as_bytes())
                .context("the daemon sent a lease that isn't canonical")?;
            write_file(
                &dir.join("key-cert.pub"),
                certificate.trim_end().to_owned() + "\n",
            )?;
            write_file(&dir.join("lease.json"), &lease)?;
            write_signing_key(dir, signing_key.as_deref())?;
            write_signing_certificate(dir, signing_certificate.as_deref())?;
            point_current(paths, id)?;
            println!(
                "Lease {id} granted until {}: {} on {}, branches {}.",
                terms.limits.expires_at,
                display::list(&terms.scope.operations),
                display::list(&terms.scope.repos),
                display::list(&terms.scope.branches),
            );
            print_narrowing(submitted, &terms);
            println!("Session files: {}", dir.display());
            Ok(Exit::Ok)
        }
        Decision::Applied {
            lease,
            signing_key,
            signing_certificate,
        } => {
            let terms = Ticket::from_canonical(lease.as_bytes())
                .context("the daemon sent a lease that isn't canonical")?;
            write_file(&dir.join("lease.json"), &lease)?;
            write_signing_key(dir, signing_key.as_deref())?;
            write_signing_certificate(dir, signing_certificate.as_deref())?;
            println!(
                "Amendment {id} signed: lease {} now runs under its terms (until {}).",
                terms.lease_id(),
                terms.limits.expires_at
            );
            print_narrowing(submitted, &terms);
            Ok(Exit::Ok)
        }
        Decision::Refused {
            feedback,
            signed_by,
        } => {
            match signed_by {
                Some(approver) => println!(
                    "Ticket {id} was refused. The approver's feedback (signed by {approver}):"
                ),
                // `decisions: open`: anyone the daemon lets read could have written it.
                None => println!(
                    "Ticket {id} was refused without an approver's signature: the feedback below \
                     may not be the approver's words."
                ),
            }
            print!("{}", display::block(&feedback, "  ", true));
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

/// `signing_key.pub`: the public key the daemon signs the lease's commits with (git's
/// `user.signingkey`, and what `allowed_signers` lists to verify them). A key that doesn't
/// parse is refused rather than written.
fn write_signing_key(dir: &Path, key: Option<&str>) -> anyhow::Result<()> {
    let Some(key) = key else { return Ok(()) };
    let key = writ_crypto::ssh_key::PublicKey::from_openssh(key)
        .context("the daemon sent a signing key that isn't an SSH public key")?;
    write_file(&dir.join("signing_key.pub"), key.to_openssh()? + "\n")
}

/// The largest OpenPGP certificate written to a session (a key and 16 user ids are a few
/// KiB).
const MAX_CERTIFICATE: usize = 64 * 1024;

/// `signing_key.asc`: the armored OpenPGP certificate the daemon signs the lease's commits
/// with, when its key signs in OpenPGP (git verifies with it; `writ init` names its
/// fingerprint). Written only if it is one armored public key block of printable ASCII.
fn write_signing_certificate(dir: &Path, certificate: Option<&str>) -> anyhow::Result<()> {
    let Some(certificate) = certificate else {
        return Ok(());
    };
    let armored = certificate.len() <= MAX_CERTIFICATE
        && certificate.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
        && certificate.ends_with("-----END PGP PUBLIC KEY BLOCK-----\n")
        && certificate
            .bytes()
            .all(|b| b == b'\n' || b.is_ascii_graphic() || b == b' ');
    if !armored {
        anyhow::bail!("the daemon sent a signing certificate that isn't an armored OpenPGP key");
    }
    write_file(&dir.join("signing_key.asc"), certificate)
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
