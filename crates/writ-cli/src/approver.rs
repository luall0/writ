//! The approver's side: `writ ls`, `writ sign`, `writ refuse`, `writ revoke`, `writ
//! prove-key`, `writ unseal`, over the approval listener.
//!
//! Signatures are made by the approver's agent ([`signer`]): only the dedicated approval key
//! is ever used, and the private key never leaves the agent. Connections to the approval API
//! authenticate with the reader key (`~/.writ/reader`): it lets this machine read and ask,
//! and grants nothing; signatures do.
//!
//! Every "Sign …?" question goes through [`confirm`] (the same answers sign everywhere), and
//! a command the approver answered no to ends with [`Exit::NotSigned`] (6), whatever it was
//! about to sign (the review after M7.6, U-8).

mod admin;
pub(crate) mod dispatch;
mod guided;
mod manage;
mod narrowing;
mod prove;
mod signer;
pub mod ui;

pub use admin::{
    apply as admin_apply, ca_rotate as admin_ca_rotate, ca_show as admin_ca_show, recovery_check,
    recovery_new, show as admin_show, target as admin_target, tls_rotate as admin_tls_rotate,
    token as admin_token,
};
pub use guided::{
    add as guided_add, check as guided_check, edit_entry as guided_edit, rescan as guided_rescan,
    rotate as guided_rotate,
};
pub use manage::{
    auto_unseal_set, auto_unseal_status, list as manage_list, remove as manage_remove,
    set as manage_set, show as manage_show,
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

/// Whether an answer to a "Sign …?" question signs: `y` or `yes`, in any case, the spaces
/// around it ignored. Anything else, an empty line or the end of the input, signs nothing.
fn signs(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Asks `question` (`Sign this change?`) on `output` and reads the answer on `input`: whether
/// it signs ([`signs`]). The one way every "Sign …?" is asked.
fn confirm_on(
    question: &str,
    mut input: impl BufRead,
    mut output: impl std::io::Write,
) -> anyhow::Result<bool> {
    write!(output, "{question} [y/N] ").context("cannot write to the terminal")?;
    output.flush().context("cannot write to the terminal")?;
    let mut answer = String::new();
    input
        .read_line(&mut answer)
        .context("cannot read the answer")?;
    Ok(signs(&answer))
}

/// [`confirm_on`] on the standard streams.
pub(crate) fn confirm(question: &str) -> anyhow::Result<bool> {
    confirm_on(question, std::io::stdin().lock(), std::io::stdout())
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
    if let Some((relation, previous)) = &previous {
        follows(&submitted, *relation, previous)?;
    }
    if let Some((_, original)) = &renewal
        && (submitted.text.renews.is_none() || original.text.renews.is_some())
    {
        bail!(
            "the daemon sent ticket {} as the original of a chain ticket {id} doesn't continue: \
             not signing it",
            original.id
        );
    }
    Ok(Reviewed {
        submitted,
        state: shown.state,
        previous,
        renewal,
        others: shown.others,
    })
}

/// Refuses a ticket shown as the one `submitted` follows when it isn't (the review after
/// M7.6, L-1: what the screen compares the ticket with comes from the reply, so it must be the
/// ticket the submitted one names). An amendment or a renewal follows the terms in force of
/// the lease it names: that lease's own ticket, or an amendment of it; a revision follows the
/// refused ticket it names.
fn follows(submitted: &Ticket, relation: Relation, previous: &Ticket) -> anyhow::Result<()> {
    let lease_terms =
        |lease: &TicketId| &previous.id == lease || previous.text.amends.as_ref() == Some(lease);
    let ok = match (
        relation,
        &submitted.text.amends,
        &submitted.text.renews,
        &submitted.text.revises,
    ) {
        (Relation::Amends, Some(lease), _, _) => lease_terms(lease),
        (Relation::Renews, None, Some(lease), _) => lease_terms(lease),
        // The daemon's fallback when the lease named isn't found: the refused ticket.
        (Relation::Revises, _, _, Some(refused)) => &previous.id == refused,
        _ => false,
    };
    if !ok {
        bail!(
            "the daemon sent ticket {} as the one {} follows, which it doesn't: not signing it",
            previous.id,
            submitted.id
        );
    }
    Ok(())
}

/// The trusted display of what is about to be signed: the ticket (narrowed), what changed
/// since the ticket it follows, and what the approver narrowed.
fn render(reviewed: &Reviewed, signed: &Ticket, now: Timestamp, shown: display::Rows) -> String {
    render_out(reviewed, signed, now, shown).text
}

/// [`render`]'s text and its structure (the approval popup's), written by the same calls.
fn render_out(
    reviewed: &Reviewed,
    signed: &Ticket,
    now: Timestamp,
    shown: display::Rows,
) -> display::Out {
    let mut out = display::Out::default();
    display::ticket_into(&mut out, signed, reviewed.state, now, shown);
    if let Some((view, original)) = &reviewed.renewal {
        display::renewal_into(&mut out, view, original, shown);
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
        display::changes_into(
            &mut out,
            &title,
            &display::diff(previous, &reviewed.submitted),
            shown,
        );
    }
    display::others_into(&mut out, &reviewed.others, now);
    let narrowed = display::diff(&reviewed.submitted, signed);
    if !narrowed.is_empty() {
        display::changes_into(
            &mut out,
            "Narrowed by you (this is what gets signed)",
            &narrowed,
            display::Rows::All,
        );
    }
    // Last, right above the prompt: the terms that get signed, whatever the agent wrote.
    display::summary_into(&mut out, signed, !narrowed.is_empty());
    out
}

/// Signs `signed` and sends the approval: what it did, in a line.
async fn approve(
    session: &Approvals,
    signer: &Signer,
    id: &TicketId,
    signed: &Ticket,
) -> anyhow::Result<String> {
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
    Ok(match ack.state {
        State::Applied => format!("Signed: amendment {id} now applies to its lease."),
        _ => format!("Signed: lease {id} is active."),
    })
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
            let command = format!("writ sign {id} --full");
            let shown = display::Rows::new(review.full, &command);
            println!("{}", render(&reviewed, &signed, now()?, shown));
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
                read_line()?
            };
            // `y` signs as at every other "Sign …?" ([`signs`]); `r` is this one's own.
            let done = match answer.to_ascii_lowercase().as_str() {
                _ if signs(&answer) => approve(session, signer, &id, &signed).await?,
                "r" | "refuse" => refuse_with(session, signer, &id, read_feedback()?).await?,
                _ => {
                    println!("Nothing signed.");
                    return Ok(Exit::NotSigned);
                }
            };
            println!("{done}");
            Ok(Exit::Ok)
        })
        .await
}

/// Refuses `id` with `feedback`, signed when the daemon wants it: what it did, in a line.
async fn refuse_with(
    session: &Approvals,
    signer: &Signer,
    id: &TicketId,
    feedback: String,
) -> anyhow::Result<String> {
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
    Ok(format!(
        "Refused: ticket {id}. The agent gets your feedback."
    ))
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
            println!("{}", refuse_with(session, signer, id, feedback).await?);
            Ok(Exit::Ok)
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
            // Before the passphrase is asked: it goes to the daemon this one authenticated.
            session.authenticated()?.check_daemon(&boot.daemon)?;
            println!(
                "Daemon {} is sealed (start {}).",
                boot.daemon,
                boot.nonce.as_str()
            );
            // A rotation of the data key the keystore owes (the review after M7.6, S-8): this
            // unseal does it.
            if !info.rotation_owed.is_empty() {
                println!(
                    "This unseal rotates the keystore's data key first ({}): until it does, \
                     what was taken out still opens the keystore with a copy of its files.",
                    display::clean(&info.rotation_owed.join("; "))
                );
            }
            // A keystore its hardware opens (M7.6) takes no passphrase: none is asked.
            let typed = match info.unseal {
                Some(writ_proto::UnsealWay::Hardware) => {
                    println!("Its keystore opens with the daemon's hardware: no passphrase.");
                    zeroize::Zeroizing::new(String::new())
                }
                _ => writ_crypto::passphrase::read("Keystore passphrase: ", None, false)?,
            };
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

/// `writ report`: a lease's activity report, as the daemon builds it (`full`: every line of
/// the agent's text and of the warnings).
pub async fn report(paths: &Paths, url: &str, id: &TicketId, full: bool) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let report: writ_proto::Report = session
                .call(&Command::Report { id: id.clone() }, b"")
                .await??;
            let command = format!("writ report {id} --full");
            print!(
                "{}",
                display::report(&report, &[], display::Rows::new(full, &command))
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A ticket of the shared fixture, with the links given.
    fn ticket(
        id: &str,
        amends: Option<&str>,
        renews: Option<&str>,
        revises: Option<&str>,
    ) -> Ticket {
        const FULL: &[u8] = include_bytes!("../../writ-core/tests/fixtures/ticket-full.json");
        let mut ticket = Ticket::from_canonical(FULL).unwrap();
        ticket.id = id.parse().unwrap();
        ticket.text.amends = amends.map(|i| i.parse().unwrap());
        ticket.text.renews = renews.map(|i| i.parse().unwrap());
        ticket.text.revises = revises.map(|i| i.parse().unwrap());
        ticket
    }

    /// The review after M7.6 (L-1): what `writ sign` compares a ticket with must be the
    /// ticket it names, by the daemon's own rule; any other is refused before anything shows.
    #[test]
    fn a_ticket_shown_as_the_one_followed_must_be_the_one_named() {
        const LEASE: &str = "wrt_01JD8X0000000000000000000A";
        const OTHER: &str = "wrt_01JD8X0000000000000000000B";
        const NEW: &str = "wrt_01JD8X0000000000000000000C";
        const AMENDMENT: &str = "wrt_01JD8X0000000000000000000D";
        let lease = ticket(LEASE, None, None, None);
        let amended = ticket(AMENDMENT, Some(LEASE), None, None);
        let other = ticket(OTHER, None, None, None);
        let amends = ticket(NEW, Some(LEASE), None, None);
        let renews = ticket(NEW, None, Some(LEASE), None);
        let revises = ticket(NEW, None, None, Some(LEASE));
        for (submitted, relation, previous) in [
            (&amends, Relation::Amends, &lease),
            (&amends, Relation::Amends, &amended),
            (&renews, Relation::Renews, &lease),
            (&renews, Relation::Renews, &amended),
            (&revises, Relation::Revises, &lease),
        ] {
            follows(submitted, relation, previous).unwrap();
        }
        for (submitted, relation, previous) in [
            (&amends, Relation::Amends, &other),
            (&amends, Relation::Renews, &lease),
            (&renews, Relation::Amends, &lease),
            (&renews, Relation::Renews, &other),
            (&revises, Relation::Revises, &other),
            (&revises, Relation::Revises, &amended),
            (&other, Relation::Revises, &lease),
        ] {
            assert_eq!(
                crate::error_of(follows(submitted, relation, previous)),
                format!(
                    "the daemon sent ticket {} as the one {} follows, which it doesn't: not \
                     signing it",
                    previous.id, submitted.id
                ),
                "{relation:?}"
            );
        }
    }

    /// The review after M7.6 (U-2): the diff sections printed the agent's task, plan and
    /// paths whole on both sides, the enforced changes first, so an amendment's widening
    /// scrolled far above the prompt. An amendment that adds a branch and rewrites task, plan
    /// and paths at their largest: the agent's words cut on each side, the paths and the
    /// branches whole and last in the section, every row within the width, and the display
    /// still ending on the summary.
    #[test]
    fn an_amendment_s_widening_comes_last_and_whole_after_the_agent_s_words_cut() {
        const LEASE: &str = "wrt_01JD8X0000000000000000000A";
        const NEW: &str = "wrt_01JD8X0000000000000000000C";
        let lease = ticket(LEASE, None, None, None);
        let mut amendment = ticket(NEW, Some(LEASE), None, None);
        let forged = format!("{}  branches           main", " ".repeat(57));
        amendment.text.task = forged.repeat(46);
        amendment.text.plan = vec![forged.repeat(5); 50];
        let terms = amendment
            .repos
            .get_mut(&"omega-code".parse().unwrap())
            .unwrap();
        terms.branches.insert("release/*".parse().unwrap());
        terms.expected_paths = (0..100)
            .map(|i| {
                format!("src/{i:02}/{}.rs", "p".repeat(150))
                    .parse()
                    .unwrap()
            })
            .collect();
        let reviewed = Reviewed {
            submitted: amendment.clone(),
            state: State::Pending,
            previous: Some((Relation::Amends, lease)),
            renewal: None,
            others: writ_proto::Others {
                shown: Vec::new(),
                more: 0,
            },
        };
        let command = format!("writ sign {NEW} --full");
        let shown = render(
            &reviewed,
            &amendment,
            amendment.created_at,
            display::Rows::new(false, &command),
        );
        let section = shown
            .split(&format!(
                "Changes from the terms in force of lease {LEASE}\n"
            ))
            .nth(1)
            .unwrap();
        let section = format!(
            "\n{}",
            section.split("\nOther active leases").next().unwrap()
        );
        let at = |label: &str| {
            section
                .find(&format!("\n  {label}\n"))
                .unwrap_or_else(|| panic!("{label}: {section}"))
        };
        // The agent's words first, the enforced terms last, nearest the prompt.
        assert!(at("task") < at("plan"), "{section}");
        assert!(at("plan") < at("branches"), "{section}");
        assert!(at("plan") < at("expected paths"), "{section}");
        assert!(
            section.contains("    + agent/oauth-*, release/*\n"),
            "{section}"
        );
        // The task's and the plan's new sides cut, saying how to see the rest.
        assert_eq!(
            section
                .matches(&format!(
                    " more lines not shown\n      ({command} shows them)\n"
                ))
                .count(),
            2,
            "{section}"
        );
        // The paths' new side whole.
        let paths = section.split("\n  expected paths\n").nth(1).unwrap();
        let added: String = paths
            .lines()
            .skip_while(|l| !l.starts_with("    + "))
            .take_while(|l| l.starts_with("    + ") || l.starts_with("    │ "))
            .map(|l| {
                l.strip_prefix("    + ")
                    .or_else(|| l.strip_prefix("    │ "))
                    .unwrap()
            })
            .collect();
        assert_eq!(
            added.replace(' ', ""),
            display::field(
                &amendment,
                display::Field::Repo(display::RepoField::ExpectedPaths)
            )
            .replace(' ', "")
        );
        for line in shown.lines() {
            assert!(
                display::width(line) <= display::WIDTH,
                "{} columns: {line:?}",
                display::width(line)
            );
            assert!(
                !(line.starts_with("  branches") && line.contains("main")),
                "a forged row at column 0: {line:?}"
            );
        }
        let lines: Vec<&str> = shown.lines().collect();
        let start = lines
            .iter()
            .rposition(|l| *l == "You are signing (enforced):")
            .unwrap();
        assert_eq!(lines.len() - start, 14, "{:#?}", &lines[start..]);
        // With --full, every row of the agent's words too.
        let full = render(
            &reviewed,
            &amendment,
            amendment.created_at,
            display::Rows::All,
        );
        assert!(!full.contains("more lines not shown"));
        // A title with the largest revision fits the width too.
        let title = format!(
            "Changes since revision {} (the refused ticket {LEASE})",
            u32::MAX
        );
        for line in display::changes(&title, &[], display::Rows::All).lines() {
            assert!(display::width(line) <= display::WIDTH, "{line:?}");
        }
    }

    /// The review after M7.6 (U-8): each "Sign …?" took its own answers (`Yes` signed a
    /// ticket, not an admin change). One rule now: `y` or `yes` in any case signs, nothing
    /// else does, the end of the input included.
    #[test]
    fn every_sign_question_takes_the_same_answers() {
        for yes in ["y", "Y", "yes", "YES", "Yes", " y ", "yes\n"] {
            assert!(signs(yes), "{yes:?}");
        }
        for no in [
            "",
            "n",
            "N",
            "no",
            "ye",
            "yess",
            "y es",
            "yes please",
            "\u{1b}y",
            "oui",
            "1",
        ] {
            assert!(!signs(no), "{no:?}");
        }
        let mut asked = Vec::new();
        assert!(confirm_on("Sign this change?", &b"Yes\n"[..], &mut asked).unwrap());
        assert_eq!(asked, b"Sign this change? [y/N] ");
        let mut asked = Vec::new();
        assert!(!confirm_on("Sign this change?", &b""[..], &mut asked).unwrap());
        assert!(!confirm_on("Sign this change?", &b"n\n"[..], &mut asked).unwrap());
        assert_eq!(crate::Exit::NotSigned as i32, 6);
    }
}
