//! The approver's side: `writ ls`, `writ sign`, `writ refuse`, `writ revoke`, `writ
//! prove-key`, `writ unseal`, over the approval listener.
//!
//! Signatures are made by the approver's agent ([`signer`]): only the dedicated approval key
//! is ever used, and the private key never leaves the agent. Connections to the approval API
//! authenticate with a throwaway key: the connection grants nothing, signatures do.

mod admin;
mod guided;
mod manage;
mod narrowing;
mod prove;
mod signer;

pub use admin::{
    apply as admin_apply, recovery_check, recovery_new, show as admin_show, target as admin_target,
    tls_rotate as admin_tls_rotate, token as admin_token,
};
pub use guided::{
    add as guided_add, check as guided_check, edit_entry as guided_edit, rescan as guided_rescan,
    rotate as guided_rotate,
};
pub use manage::{
    list as manage_list, remove as manage_remove, set as manage_set, show as manage_show,
};
pub use narrowing::Narrowing;
pub use prove::{ProveKey, prove_key};
pub use signer::{Signer, default_key};

use std::io::{BufRead, Write as _};

use anyhow::{Context, bail};
use writ_core::lease::State;
use writ_core::names::TicketId;
use writ_core::signed::{Refusal, Revocation, Unseal};
use writ_core::ticket::Ticket;
use writ_core::units::Timestamp;
use writ_proto::{
    Ack, ApproveRequest, Command, Info, Listing, PassphraseText, RefuseRequest, Relation,
    RevokeRequest, Shown, UnsealRequest, Unsealed,
};

use crate::client::Approvals;
use crate::display;
use crate::{Exit, Paths};
use writ_core::canonical::Canonical;

async fn connect(paths: &Paths, url: &str) -> anyhow::Result<Approvals> {
    Approvals::connect(paths, url).await
}

fn now() -> anyhow::Result<Timestamp> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(Timestamp::from_unix(i64::try_from(seconds)?)?)
}

/// `writ ls`.
pub async fn list(paths: &Paths, url: &str, all: bool) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let listing: Listing = session.call(&Command::List { all }, b"").await??;
            if listing.tickets.is_empty() {
                println!("Nothing waiting and no active lease.");
                return Ok(Exit::Ok);
            }
            print!("{}", display::listing(&listing, now()?));
            Ok(Exit::Ok)
        })
        .await
}

fn read_line() -> anyhow::Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("cannot read the answer")?;
    Ok(line.trim().to_owned())
}

/// Feedback typed by the approver, ended by an empty line or end of input.
fn read_feedback() -> anyhow::Result<String> {
    println!("Feedback for the agent (end with an empty line):");
    let mut lines = Vec::new();
    for line in std::io::stdin().lock().lines() {
        let line = line.context("cannot read the feedback")?;
        if line.trim().is_empty() {
            break;
        }
        lines.push(line);
    }
    Ok(lines.join("\n"))
}

/// The ticket to sign: the one named, or the only one waiting.
async fn pick_pending(session: &Approvals, id: Option<TicketId>) -> anyhow::Result<TicketId> {
    if let Some(id) = id {
        return Ok(id);
    }
    let listing: Listing = session.call(&Command::List { all: false }, b"").await??;
    let pending: Vec<_> = listing
        .tickets
        .iter()
        .filter(|t| t.state == State::Pending)
        .collect();
    match pending.as_slice() {
        [one] => Ok(one.id.clone()),
        [] => bail!("no ticket is waiting"),
        _ => bail!("several tickets are waiting: name one (writ ls)"),
    }
}

/// A pending ticket as the daemon shows it, decoded strictly, what it follows, the chain a
/// renewal continues (with its original ticket), and the other leases of its source.
struct Reviewed {
    submitted: Ticket,
    state: State,
    previous: Option<(Relation, Ticket)>,
    renewal: Option<(writ_proto::Renewal, Ticket)>,
    others: writ_proto::Others,
}

/// Fetches ticket `id` and checks it is the one asked for, canonical, and waiting.
async fn fetch_reviewed(session: &Approvals, id: &TicketId) -> anyhow::Result<Reviewed> {
    let shown: Shown = session
        .call(&Command::Show { id: id.clone() }, b"")
        .await??;
    // Decoded strictly: only canonical bytes, re-encoded to exactly themselves.
    let submitted = Ticket::from_canonical(shown.canonical.as_bytes())
        .context("the daemon sent a ticket that isn't canonical: not signing it")?;
    if &submitted.id != id {
        bail!(
            "the daemon sent ticket {} instead of {id}: not signing it",
            submitted.id
        );
    }
    if shown.state != State::Pending {
        bail!(
            "ticket {id} is {}, not waiting for a signature",
            shown.state
        );
    }
    let previous = match &shown.previous {
        Some(previous) => Some((
            previous.relation,
            Ticket::from_canonical(previous.canonical.as_bytes())
                .context("the daemon sent a previous ticket that isn't canonical")?,
        )),
        None => None,
    };
    let renewal = match shown.renewal {
        Some(view) => {
            let original = Ticket::from_canonical(view.original.as_bytes())
                .context("the daemon sent an original ticket that isn't canonical")?;
            Some((view, original))
        }
        None => None,
    };
    Ok(Reviewed {
        submitted,
        state: shown.state,
        previous,
        renewal,
        others: shown.others,
    })
}

/// The trusted display of what is about to be signed: the ticket (narrowed), what changed
/// since the ticket it follows, and what the approver narrowed.
fn render(reviewed: &Reviewed, signed: &Ticket, now: Timestamp, full: bool) -> String {
    let mut out = display::ticket(signed, reviewed.state, now, full);
    if let Some((view, original)) = &reviewed.renewal {
        out.push_str(&display::renewal_section(view, original, full));
    }
    if let Some((relation, previous)) = &reviewed.previous {
        let title = match relation {
            Relation::Revises => format!(
                "Changes since revision {} (the refused ticket {})",
                previous.text.revision, previous.id
            ),
            Relation::Amends => format!("Changes from the terms in force of lease {}", previous.id),
            Relation::Renews => format!("Changes from the terms of lease {}, renewed", previous.id),
        };
        out.push_str(&display::changes(
            &title,
            &display::diff(previous, &reviewed.submitted),
        ));
    }
    out.push_str(&display::others(&reviewed.others, now));
    let narrowed = display::diff(&reviewed.submitted, signed);
    if !narrowed.is_empty() {
        out.push_str(&display::changes(
            "Narrowed by you (this is what gets signed)",
            &narrowed,
        ));
    }
    // Last, right above the prompt: the terms that get signed, whatever the agent wrote.
    out.push_str(&display::summary(signed, !narrowed.is_empty()));
    out
}

/// Signs `signed` and sends the approval.
async fn approve(
    session: &Approvals,
    signer: &Signer,
    id: &TicketId,
    signed: &Ticket,
) -> anyhow::Result<Exit> {
    let bytes = signed.canonical_bytes()?;
    // Sign exactly what was displayed: the bytes must decode back to it.
    if &Ticket::from_canonical(&bytes)? != signed {
        bail!("the ticket doesn't re-encode to itself: not signing it");
    }
    let signature = signer.sign(&bytes)?;
    let request = ApproveRequest {
        signed: String::from_utf8(bytes)?,
        signature,
    };
    let ack: Ack = session
        .call(
            &Command::Approve { id: id.clone() },
            &writ_proto::encode_body(&request)?,
        )
        .await??;
    match ack.state {
        State::Applied => println!("Signed: amendment {id} now applies to its lease."),
        _ => println!("Signed: lease {id} is active."),
    }
    Ok(Exit::Ok)
}

/// `writ sign`: shows the ticket, then signs it (narrowed if asked), refuses it, or not.
/// How `writ sign` reviews: `yes` signs without asking (only with a named ticket), `full`
/// shows every line of agent text.
pub struct Review {
    pub yes: bool,
    pub full: bool,
}

pub async fn sign(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    id: Option<TicketId>,
    narrowing: &Narrowing,
    review: &Review,
) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let id = pick_pending(session, id).await?;
            let reviewed = fetch_reviewed(session, &id).await?;
            let signed = narrowing.apply(&reviewed.submitted)?;
            println!("{}", render(&reviewed, &signed, now()?, review.full));
            let answer = if review.yes {
                "y".to_owned()
            } else {
                // The key on a row of its own (a path of any length, cut to fit), the prompt
                // one short row.
                let mut key = String::new();
                display::rows_after(
                    &mut key,
                    "Approval key: ",
                    &display::clean(&signer.key.display().to_string()),
                );
                print!("{key}Sign this ticket? [y]es / [n]o / [r]efuse: ");
                std::io::stdout()
                    .flush()
                    .context("cannot write to the terminal")?;
                read_line()?.to_ascii_lowercase()
            };
            match answer.as_str() {
                "y" | "yes" => approve(session, signer, &id, &signed).await,
                "r" | "refuse" => refuse_with(session, signer, &id, read_feedback()?).await,
                _ => {
                    println!("Nothing signed.");
                    Ok(Exit::NotSigned)
                }
            }
        })
        .await
}

async fn refuse_with(
    session: &Approvals,
    signer: &Signer,
    id: &TicketId,
    feedback: String,
) -> anyhow::Result<Exit> {
    if feedback.trim().is_empty() {
        bail!("a refusal needs feedback for the agent");
    }
    let document = Refusal::new(id.clone(), feedback.clone()).canonical_bytes()?;
    let request = RefuseRequest {
        feedback,
        signature: signer.sign_if_required(session, &document).await?,
    };
    let _: Ack = session
        .call(
            &Command::Refuse { id: id.clone() },
            &writ_proto::encode_body(&request)?,
        )
        .await??;
    println!("Refused: ticket {id}. The agent gets your feedback.");
    Ok(Exit::Ok)
}

/// `writ refuse`.
pub async fn refuse(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    id: &TicketId,
    message: Option<String>,
) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let feedback = match message {
                Some(message) => message,
                None => read_feedback()?,
            };
            refuse_with(session, signer, id, feedback).await
        })
        .await
}

/// `writ unseal`: the boot to unseal from `writ info` (this daemon's host key, this start's
/// nonce), the keystore's passphrase, then one signature with the approval key over that
/// `writ-unseal/1` document. The daemon checks the signature before it tries the passphrase.
pub async fn unseal(paths: &Paths, url: &str, signer: &Signer) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let info: Info = session.call(&Command::Info, b"").await??;
            let Some(boot) = info.sealed else {
                bail!("the daemon is not sealed: there is nothing to unseal");
            };
            println!(
                "Daemon {} is sealed (start {}).",
                boot.daemon,
                boot.nonce.as_str()
            );
            let typed = writ_crypto::passphrase::read("Keystore passphrase: ", None, false)?;
            let document = Unseal::new(boot.daemon, boot.nonce).canonical_bytes()?;
            let signature = signer.sign(&document)?;
            let request = UnsealRequest {
                passphrase: PassphraseText::new(typed.as_str().to_owned()),
                unseal: String::from_utf8(document)?,
                signature,
            };
            drop(typed);
            let body = zeroize::Zeroizing::new(writ_proto::encode_body(&request)?);
            drop(request);
            let unsealed: Unsealed = session.call(&Command::Unseal, &body).await??;
            println!("Unsealed (signed by {}).", unsealed.signed_by);
            Ok(Exit::Ok)
        })
        .await
}

/// `writ report`: a lease's activity report, as the daemon builds it.
pub async fn report(paths: &Paths, url: &str, id: &TicketId) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let report: writ_proto::Report = session
                .call(&Command::Report { id: id.clone() }, b"")
                .await??;
            print!("{}", display::report(&report, &[], false));
            Ok(Exit::Ok)
        })
        .await
}

/// `writ revoke`.
pub async fn revoke(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    id: &TicketId,
) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let document = Revocation::new(id.clone()).canonical_bytes()?;
            let request = RevokeRequest {
                signature: signer.sign_if_required(session, &document).await?,
            };
            let ack: Ack = session
                .call(
                    &Command::Revoke { id: id.clone() },
                    &writ_proto::encode_body(&request)?,
                )
                .await??;
            println!("Revoked: {} is {}.", ack.id, ack.state);
            Ok(Exit::Ok)
        })
        .await
}
