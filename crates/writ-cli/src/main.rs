//! `writ`, the Writ CLI.
//!
//! Agent side: `writ request <ticket.yaml>` (submit and wait), `writ wait <id>`.
//! Approver side: `writ reader` (the key this machine uses on the approval API), `writ ls`,
//! `writ sign [<id>]` (the trusted display, then an SSHSIG through the approver's
//! ssh-agent), `writ refuse <id>`, `writ revoke <id>`.
//!
//! The client is untrusted: every check it makes is a convenience, the daemon checks again.
//! It never reads the user's `~/.ssh`: the daemon's host key is pinned in
//! `<home>/known_hosts` (`<home>` is `$WRIT_HOME`, or `~/.writ`).

mod agent;
mod approver;
mod client;
mod display;
mod https;
mod reader;
mod session;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use writ_core::names::TicketId;

/// How a command ended, as the exit status (stable: the agent skill and harnesses read it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Ok = 0,
    /// Something failed (connection, daemon error, bad arguments).
    Error = 1,
    /// The ticket was rejected by policy (fits no template) or is invalid.
    Rejected = 3,
    /// The approver refused the ticket.
    Refused = 4,
    /// The ticket expired or was withdrawn, or the lease ended, before a decision.
    Ended = 5,
    /// `writ sign`: the approver answered no.
    NotSigned = 6,
}

/// Where the client keeps its files.
pub struct Paths {
    pub home: PathBuf,
    pub known_hosts: PathBuf,
    /// Pins of the daemon's TLS certificate (HTTPS approval API).
    pub tls_pins: PathBuf,
    /// The reader key, for the approval API.
    pub reader: PathBuf,
}

#[derive(Parser)]
#[command(
    name = "writ",
    version,
    about = "Writ: signed, scoped, time-boxed leases for AI agents"
)]
struct Cli {
    /// Writ's directory on this host (sessions, known_hosts, approver.pub).
    #[arg(long, env = "WRIT_HOME", global = true)]
    home: Option<PathBuf>,
    /// The file pinning the daemon's host key (default: <home>/known_hosts).
    #[arg(long, env = "WRIT_KNOWN_HOSTS", global = true)]
    known_hosts: Option<PathBuf>,
    /// The file pinning the daemon's TLS certificate, for an https:// approval URL
    /// (default: <home>/tls_pins).
    #[arg(long, env = "WRIT_TLS_PINS", global = true)]
    tls_pins: Option<PathBuf>,
    /// The reader key used on the approval API (default: <home>/reader).
    #[arg(long, env = "WRIT_READER", global = true)]
    reader: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Args)]
struct AgentUrl {
    /// The daemon's agents listener, ssh://host:port or unix:<path>.
    #[arg(long, env = "WRIT_URL")]
    url: String,
}

#[derive(clap::Args)]
struct ApprovalUrl {
    /// The daemon's approval listener: https://host:port, ssh://host:port or unix:<path>.
    #[arg(long = "approval-url", env = "WRIT_APPROVAL_URL")]
    url: String,
}

#[derive(clap::Args)]
struct SignerArgs {
    /// The approval key's public half (default: <home>/approver.pub).
    #[arg(long = "key", env = "WRIT_APPROVAL_KEY")]
    key: Option<PathBuf>,
    /// The ssh-agent socket holding the approval key (default: $SSH_AUTH_SOCK).
    #[arg(long = "agent", env = "WRIT_APPROVAL_AGENT")]
    agent: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Submit a ticket file (YAML, `-` for stdin) and wait for the approver's decision.
    Request {
        file: PathBuf,
        /// Return once submitted; `writ wait <id>` later.
        #[arg(long)]
        no_wait: bool,
        #[command(flatten)]
        url: AgentUrl,
    },
    /// Wait for the decision on a ticket submitted from this host.
    Wait {
        id: TicketId,
        /// The lease the ticket amends, for an amendment.
        #[arg(long)]
        lease: Option<TicketId>,
        #[command(flatten)]
        url: AgentUrl,
    },
    /// Print this machine's reader key line for the daemon's `readers` file (the key is made
    /// on first use).
    Reader {
        /// The name the daemon logs for this reader.
        #[arg(default_value = "approver")]
        name: String,
    },
    /// List tickets waiting and active leases.
    Ls {
        /// Every ticket, ended ones included.
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        url: ApprovalUrl,
    },
    /// Review a waiting ticket and sign it (narrowed if asked), refuse it, or leave it.
    Sign {
        /// The ticket (default: the only one waiting).
        id: Option<TicketId>,
        #[command(flatten)]
        narrowing: approver::Narrowing,
        /// Sign without asking (the ticket is still shown first). Only with a named ticket:
        /// never whichever happens to be waiting.
        #[arg(long, requires = "id")]
        yes: bool,
        /// Show every line of the agent's text (by default, 40 lines per field).
        #[arg(long)]
        full: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
    /// Refuse a waiting ticket, with feedback for the agent.
    Refuse {
        id: TicketId,
        /// The feedback (default: read from stdin).
        #[arg(short, long)]
        message: Option<String>,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
    /// Revoke a lease (its sessions are dropped at once), or withdraw a waiting ticket.
    Revoke {
        id: TicketId,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
}

fn paths(cli: &Cli) -> anyhow::Result<Paths> {
    let home = match &cli.home {
        Some(home) => home.clone(),
        None => PathBuf::from(
            std::env::var_os("HOME").ok_or_else(|| anyhow::anyhow!("HOME is not set"))?,
        )
        .join(".writ"),
    };
    let known_hosts = cli
        .known_hosts
        .clone()
        .unwrap_or_else(|| home.join("known_hosts"));
    let tls_pins = cli
        .tls_pins
        .clone()
        .unwrap_or_else(|| home.join("tls_pins"));
    let reader = cli.reader.clone().unwrap_or_else(|| home.join("reader"));
    Ok(Paths {
        home,
        known_hosts,
        tls_pins,
        reader,
    })
}

fn signer(paths: &Paths, args: &SignerArgs) -> approver::Signer {
    approver::Signer {
        key: args
            .key
            .clone()
            .unwrap_or_else(|| approver::default_key(&paths.home)),
        agent: args.agent.clone(),
    }
}

async fn run(cli: Cli) -> anyhow::Result<Exit> {
    let paths = paths(&cli)?;
    match &cli.command {
        Commands::Request { file, no_wait, url } => {
            agent::request(&paths, &url.url, file, *no_wait).await
        }
        Commands::Wait { id, lease, url } => {
            agent::wait(&paths, &url.url, id, lease.as_ref()).await
        }
        Commands::Reader { name } => {
            session::create_private_dir(&paths.home)?;
            println!("{}", reader::ensure(&paths.reader, name)?);
            Ok(Exit::Ok)
        }
        Commands::Ls { all, url } => approver::list(&paths, &url.url, *all).await,
        Commands::Sign {
            id,
            narrowing,
            yes,
            full,
            url,
            signer: args,
        } => {
            let review = approver::Review {
                yes: *yes,
                full: *full,
            };
            approver::sign(
                &paths,
                &url.url,
                &signer(&paths, args),
                id.clone(),
                narrowing,
                &review,
            )
            .await
        }
        Commands::Refuse {
            id,
            message,
            url,
            signer: args,
        } => approver::refuse(&paths, &url.url, &signer(&paths, args), id, message.clone()).await,
        Commands::Revoke {
            id,
            url,
            signer: args,
        } => approver::revoke(&paths, &url.url, &signer(&paths, args), id).await,
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("writ: cannot start: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(exit) => ExitCode::from(exit as u8),
        Err(e) => {
            // The chain may hold the daemon's words: shown escaped, like any outside text.
            eprintln!("writ: {}", display::clean_lines(&format!("{e:#}")));
            ExitCode::from(Exit::Error as u8)
        }
    }
}

/// The message chain of an error a test expects; a success fails the test.
#[cfg(test)]
pub(crate) fn error_of<T>(result: anyhow::Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected an error, got a success"),
        Err(e) => format!("{e:#}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_yes_needs_a_named_ticket() {
        // Never "whichever ticket happens to be waiting" without a look.
        let error =
            match Cli::try_parse_from(["writ", "sign", "--yes", "--approval-url", "ssh://h:1"]) {
                Ok(_) => panic!("--yes without an id was accepted"),
                Err(error) => error,
            };
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        let named = Cli::try_parse_from([
            "writ",
            "sign",
            "wrt_01JD8X0000000000000000000A",
            "--yes",
            "--approval-url",
            "ssh://h:1",
        ]);
        assert!(named.is_ok());
        // Without --yes, no id is fine: the prompt asks.
        assert!(Cli::try_parse_from(["writ", "sign", "--approval-url", "ssh://h:1"]).is_ok());
    }
}
