//! The approver's side: `writ ls`, `writ sign`, `writ refuse`, `writ revoke`, over the
//! approval listener.
//!
//! Signatures are made by `ssh-keygen -Y sign -n writ-approval -f <approval key .pub>` with
//! `SSH_AUTH_SOCK` set to the approver's agent (Secretive): only the dedicated approval key
//! is ever used, and the private key never leaves the agent. Connections to the approval API
//! authenticate with a throwaway key: the connection grants nothing, signatures do.

use std::collections::BTreeSet;
use std::io::{BufRead, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command as Process;

use anyhow::{Context, bail};
use writ_core::config::Operation;
use writ_core::lease::{APPROVAL_NAMESPACE, State};
use writ_core::names::{Email, RepoName, TicketId};
use writ_core::narrow;
use writ_core::pattern::BranchPattern;
use writ_core::signed::{Refusal, Revocation};
use writ_core::ticket::{OnViolation, Ticket};
use writ_core::units::{ByteSize, Duration, Timestamp};
use writ_crypto::keys::random_hex;
use writ_proto::{
    Ack, ApproveRequest, Command, Decisions, Info, Listing, RefuseRequest, RevokeRequest, Shown,
};

use crate::client::Approvals;
use crate::display;
use crate::{Exit, Paths};

/// How the approver signs: the approval key's public half and the agent holding it.
pub struct Signer {
    pub key: PathBuf,
    pub agent: Option<PathBuf>,
}

impl Signer {
    /// An SSHSIG over `message` in the `writ-approval` namespace, made by the agent.
    fn sign(&self, message: &[u8]) -> anyhow::Result<String> {
        let dir = std::env::temp_dir().join(format!("writ-sign-{}", random_hex(8)?));
        std::fs::create_dir(&dir).context("cannot create a temporary directory")?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let result = (|| {
            let file = dir.join("message");
            std::fs::write(&file, message)?;
            let mut command = Process::new("ssh-keygen");
            command
                .args(["-Y", "sign", "-n", APPROVAL_NAMESPACE, "-f"])
                .arg(&self.key)
                .arg(&file);
            if let Some(agent) = &self.agent {
                command.env("SSH_AUTH_SOCK", agent);
            }
            // Its chatter ("Signing file …") would clutter the trusted display: shown only on
            // failure. Touch ID is Secretive's own prompt, not a terminal one.
            let output = command
                .stdin(std::process::Stdio::null())
                .output()
                .context("cannot run ssh-keygen")?;
            if !output.status.success() {
                eprint!("{}", String::from_utf8_lossy(&output.stderr));
                bail!("ssh-keygen could not sign (is the approval key in the agent?)");
            }
            let signature = std::fs::read_to_string(dir.join("message.sig"))
                .context("ssh-keygen wrote no signature")?;
            Ok(signature)
        })();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }
}

async fn connect(paths: &Paths, url: &str) -> anyhow::Result<Approvals> {
    Approvals::connect(url, &paths.known_hosts, &paths.tls_pins).await
}

fn now() -> anyhow::Result<Timestamp> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(Timestamp::from_unix(i64::try_from(seconds)?)?)
}

/// `writ ls`.
pub async fn list(paths: &Paths, url: &str, all: bool) -> anyhow::Result<Exit> {
    let session = connect(paths, url).await?;
    let result: anyhow::Result<Exit> = async {
        let listing: Listing = session.call(&Command::List { all }, b"").await??;
        if listing.tickets.is_empty() {
            println!("Nothing waiting and no active lease.");
            return Ok(Exit::Ok);
        }
        let now = now()?;
        for t in &listing.tickets {
            let left = match t.state {
                State::Pending | State::Active => {
                    format!(
                        "{} left",
                        display::duration(now.seconds_until(t.expires_at))
                    )
                }
                _ => String::new(),
            };
            let lease = if t.lease != t.id {
                format!(" (amends {})", t.lease)
            } else {
                String::new()
            };
            println!(
                "{}  {:<9} r{}  {:<14} {:<10} {}{lease}",
                t.id,
                t.state.to_string(),
                t.revision,
                t.template.to_string(),
                left,
                t.repos
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
            println!("    {}{}", display::GUTTER, display::clean(&t.title));
        }
        Ok(Exit::Ok)
    }
    .await;
    session.close().await;
    result
}

/// What `writ sign` may narrow before signing. Each flag only narrows.
#[derive(Debug, Default, Clone, clap::Args)]
pub struct Narrowing {
    /// Shorter lease: it ends at most this long after the ticket was created (e.g. 2h).
    #[arg(long)]
    pub ttl: Option<Duration>,
    /// Drop a repo (repeatable).
    #[arg(long = "drop-repo", value_name = "REPO")]
    pub drop_repos: Vec<RepoName>,
    /// Drop an operation: fetch, commit_sign or push (repeatable).
    #[arg(long = "drop-op", value_name = "OP", value_parser = parse_operation)]
    pub drop_ops: Vec<Operation>,
    /// Replace the branches; each must be within a submitted one (repeatable).
    #[arg(long = "branch", value_name = "PATTERN")]
    pub branches: Vec<BranchPattern>,
    /// Drop a committer email (repeatable).
    #[arg(long = "drop-email", value_name = "EMAIL")]
    pub drop_emails: Vec<Email>,
    #[arg(long)]
    pub max_signatures: Option<u32>,
    #[arg(long)]
    pub max_pushes: Option<u32>,
    #[arg(long)]
    pub max_ops_per_minute: Option<u32>,
    #[arg(long)]
    pub max_push_size: Option<ByteSize>,
    /// Turn force push off.
    #[arg(long)]
    pub no_force_push: bool,
    /// Revoke the lease on the first out-of-scope request.
    #[arg(long)]
    pub revoke_on_violation: bool,
}

fn parse_operation(text: &str) -> Result<Operation, String> {
    match text {
        "fetch" => Ok(Operation::Fetch),
        "commit_sign" => Ok(Operation::CommitSign),
        "push" => Ok(Operation::Push),
        _ => Err(format!(
            "unknown operation {text:?} (fetch, commit_sign, push)"
        )),
    }
}

impl Narrowing {
    /// The ticket narrowed by these flags. Refuses a flag that would widen anything.
    pub fn apply(&self, submitted: &Ticket) -> anyhow::Result<Ticket> {
        let mut t = submitted.clone();
        if let Some(ttl) = self.ttl {
            let end = t.created_at.checked_add(ttl).context("--ttl is too long")?;
            if end > t.limits.expires_at {
                bail!("--ttl {ttl} would extend the lease; it can only shorten it");
            }
            t.limits.expires_at = end;
        }
        for repo in &self.drop_repos {
            if !t.scope.repos.remove(repo) {
                bail!("--drop-repo {repo}: the ticket doesn't ask for it");
            }
        }
        for op in &self.drop_ops {
            if !t.scope.operations.remove(op) {
                bail!("--drop-op {op}: the ticket doesn't ask for it");
            }
        }
        if !self.branches.is_empty() {
            t.scope.branches = self.branches.iter().cloned().collect::<BTreeSet<_>>();
        }
        for email in &self.drop_emails {
            if !t.scope.committer_emails.remove(email) {
                bail!("--drop-email {email}: the ticket doesn't ask for it");
            }
        }
        let lower = |name: &str, value: Option<u32>, current: &mut u32| -> anyhow::Result<()> {
            if let Some(value) = value {
                if value > *current {
                    bail!("--{name} {value} is above the ticket's {current}; it can only lower it");
                }
                *current = value;
            }
            Ok(())
        };
        lower(
            "max-signatures",
            self.max_signatures,
            &mut t.limits.max_signatures,
        )?;
        lower("max-pushes", self.max_pushes, &mut t.limits.max_pushes)?;
        lower(
            "max-ops-per-minute",
            self.max_ops_per_minute,
            &mut t.limits.max_ops_per_minute,
        )?;
        if let Some(size) = self.max_push_size {
            if size > t.limits.max_push_size {
                bail!("--max-push-size {size} is above the ticket's; it can only lower it");
            }
            t.limits.max_push_size = size;
        }
        if self.no_force_push {
            t.scope.force_push = false;
        }
        if self.revoke_on_violation {
            t.on_violation = OnViolation::RevokeLease;
        }
        // Convenience: the daemon checks this again.
        narrow::check(submitted, &t).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(t)
    }
}

fn read_line() -> anyhow::Result<String> {
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

/// Feedback typed by the approver, ended by an empty line or end of input.
fn read_feedback() -> anyhow::Result<String> {
    println!("Feedback for the agent (end with an empty line):");
    let mut lines = Vec::new();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            break;
        }
        lines.push(line);
    }
    Ok(lines.join("\n"))
}

/// `writ sign`: shows the ticket, then signs it (narrowed if asked), refuses it, or not.
pub async fn sign(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    id: Option<TicketId>,
    narrowing: &Narrowing,
    yes: bool,
) -> anyhow::Result<Exit> {
    let session = connect(paths, url).await?;
    let result: anyhow::Result<Exit> = async {
        let id = match id {
            Some(id) => id,
            None => {
                let listing: Listing = session.call(&Command::List { all: false }, b"").await??;
                let pending: Vec<_> = listing
                    .tickets
                    .iter()
                    .filter(|t| t.state == State::Pending)
                    .collect();
                match pending.as_slice() {
                    [one] => one.id.clone(),
                    [] => bail!("no ticket is waiting"),
                    _ => bail!("several tickets are waiting: name one (writ ls)"),
                }
            }
        };
        let shown: Shown = session
            .call(&Command::Show { id: id.clone() }, b"")
            .await??;
        // Decoded strictly: only canonical bytes, re-encoded to exactly themselves.
        let submitted = Ticket::from_canonical(shown.canonical.as_bytes())
            .context("the daemon sent a ticket that isn't canonical: not signing it")?;
        if submitted.id != id {
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
        let signed = narrowing.apply(&submitted)?;

        let now = now()?;
        print!("{}", display::ticket(&signed, shown.state, now));
        if let Some((relation, previous)) = &previous {
            let title = match relation {
                writ_proto::Relation::Revises => format!(
                    "Changes since revision {} (the refused ticket {})",
                    previous.ticket.revision, previous.id
                ),
                writ_proto::Relation::Amends => {
                    format!("Changes from the terms in force of lease {}", previous.id)
                }
            };
            print!(
                "{}",
                display::changes(&title, &display::diff(previous, &submitted))
            );
        }
        let narrowed = display::diff(&submitted, &signed);
        if !narrowed.is_empty() {
            print!(
                "{}",
                display::changes("Narrowed by you (this is what gets signed)", &narrowed)
            );
        }
        println!();

        let answer = if yes {
            "y".to_owned()
        } else {
            print!(
                "Sign this ticket with {}? [y]es / [n]o / [r]efuse: ",
                signer.key.display()
            );
            std::io::stdout().flush()?;
            read_line()?.to_ascii_lowercase()
        };
        match answer.as_str() {
            "y" | "yes" => {
                let bytes = signed.canonical_bytes()?;
                // Sign exactly what was displayed: the bytes must decode back to it.
                if Ticket::from_canonical(&bytes)? != signed {
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
            "r" | "refuse" => {
                let feedback = read_feedback()?;
                refuse_with(&session, signer, &id, feedback).await
            }
            _ => {
                println!("Nothing signed.");
                Ok(Exit::NotSigned)
            }
        }
    }
    .await;
    session.close().await;
    result
}

async fn decisions(session: &Approvals) -> anyhow::Result<Decisions> {
    let info: Info = session.call(&Command::Info, b"").await??;
    Ok(info.decisions)
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
    let signature = match decisions(session).await? {
        Decisions::Signed => {
            Some(signer.sign(&Refusal::new(id.clone(), feedback.clone()).canonical_bytes()?)?)
        }
        Decisions::Open => None,
    };
    let request = RefuseRequest {
        feedback,
        signature,
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
    let session = connect(paths, url).await?;
    let result: anyhow::Result<Exit> = async {
        let feedback = match message {
            Some(message) => message,
            None => read_feedback()?,
        };
        refuse_with(&session, signer, id, feedback).await
    }
    .await;
    session.close().await;
    result
}

/// `writ revoke`.
pub async fn revoke(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    id: &TicketId,
) -> anyhow::Result<Exit> {
    let session = connect(paths, url).await?;
    let result: anyhow::Result<Exit> = async {
        let signature = match decisions(&session).await? {
            Decisions::Signed => {
                Some(signer.sign(&Revocation::new(id.clone()).canonical_bytes()?)?)
            }
            Decisions::Open => None,
        };
        let request = RevokeRequest { signature };
        let ack: Ack = session
            .call(
                &Command::Revoke { id: id.clone() },
                &writ_proto::encode_body(&request)?,
            )
            .await??;
        println!("Revoked: {} is {}.", ack.id, ack.state);
        Ok(Exit::Ok)
    }
    .await;
    session.close().await;
    result
}

/// The default approval key path, `<home>/approver.pub`.
pub fn default_key(home: &Path) -> PathBuf {
    home.join("approver.pub")
}
