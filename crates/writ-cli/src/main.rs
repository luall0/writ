//! `writ`, the Writ CLI.
//!
//! Agent side: `writ request <ticket.yaml>` (submit and wait), `writ wait <id>`, `writ init
//! <repo>` (wire a repository; `--whole-repo` for a clone dedicated to an agent, `--undo`),
//! `writ git <args>` and `writ exec -- <program>` (git, or a program, with the wiring).
//! Approver side: `writ reader` (the key this machine uses on the approval API), `writ ls`,
//! `writ sign [<id>]` (the trusted display, then an SSHSIG through the approver's
//! ssh-agent), `writ refuse <id>`, `writ revoke <id>`, `writ prove-key <key id> --namespace
//! <ns>` (an agent signing key's proof for a remote, the message on stdin).
//!
//! The client is untrusted: every check it makes is a convenience, the daemon checks again.
//! It never reads the user's `~/.ssh`: the daemon's host key is pinned in
//! `<home>/known_hosts` (`<home>` is `$WRIT_HOME`, or `~/.writ`).

mod agent;
mod approver;
mod client;
mod display;
mod https;
mod init;
mod reader;
mod session;
mod wiring;
mod wrap;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use writ_core::names::{Email, KeyId, ProofNamespace, RepoName, TicketId};

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
    /// Wire the git repository in the current directory for Writ. By default nothing in its
    /// git config changes: run git through `writ git` to work under the lease (good practice:
    /// docs/operators/good-practice.md).
    Init {
        /// The repo's name in the daemon's registry.
        #[arg(required_unless_present = "undo")]
        repo: Option<RepoName>,
        /// Write the settings in the repo's git config: for a clone dedicated to an agent.
        #[arg(long, conflicts_with = "undo")]
        whole_repo: bool,
        /// The committer email (default: the current lease's, if it allows exactly one).
        #[arg(long, conflicts_with = "undo")]
        email: Option<Email>,
        /// Take the repo back to before `writ init`.
        #[arg(long, conflicts_with = "repo")]
        undo: bool,
        /// The daemon's agents listener, ssh://host:port.
        #[arg(long, env = "WRIT_URL")]
        url: Option<String>,
    },
    /// Run any git command with the repo's Writ wiring (signing by the daemon, the session's
    /// SSH command, the `writ` remote), without changing its git config.
    Git {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run a program (that runs git) with the repo's Writ wiring: writ exec -- <program> [args].
    Exec {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<OsString>,
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
    /// Prove an agent signing key to a remote that asks (Forgejo, Gitea): sign the message on
    /// stdin with it, in place of `ssh-keygen -Y sign -n <namespace>`. An approval: one
    /// signature with your approval key.
    ProveKey {
        /// The key, by its id in the daemon (`writd signing-keys` lists them).
        #[arg(value_name = "KEY_ID")]
        key_id: KeyId,
        /// The namespace the remote asks for (Forgejo and Gitea: gitea). Never git, nor
        /// anything starting with writ.
        #[arg(long, short = 'n')]
        namespace: ProofNamespace,
        /// Sign without asking (the proof is still shown first).
        #[arg(long)]
        yes: bool,
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
        Commands::Init { undo: true, .. } => init::undo(),
        Commands::Init {
            repo,
            whole_repo,
            email,
            url,
            ..
        } => {
            let repo = repo
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("writ init needs the repo's registry name"))?;
            let url = url
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("writ init needs WRIT_URL (or --url)"))?;
            let mode = if *whole_repo {
                wiring::Mode::WholeRepo
            } else {
                wiring::Mode::Wrapper
            };
            init::init(
                &paths,
                &init::Init {
                    url,
                    repo,
                    mode,
                    email: email.as_ref(),
                },
            )
        }
        Commands::Git { args } => wrap::git(&paths, args),
        Commands::Exec { command } => wrap::exec(&paths, command),
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
        Commands::ProveKey {
            key_id,
            namespace,
            yes,
            url,
            signer: args,
        } => {
            let asked = approver::ProveKey {
                key: key_id.clone(),
                namespace: namespace.clone(),
                yes: *yes,
            };
            approver::prove_key(&paths, &url.url, &signer(&paths, args), asked).await
        }
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

    /// The features `docs/end-to-end.md`'s coverage registry lists (first cell of each row,
    /// up to its first parenthesis), for one binary.
    pub(crate) fn registry(binary: &str) -> std::collections::BTreeSet<String> {
        let doc = include_str!("../../../docs/end-to-end.md");
        let (_, section) = doc
            .split_once("## Coverage: every command and flag")
            .expect("the registry section");
        let section = section
            .split_once("\n## ")
            .map_or(section, |(body, _)| body);
        section
            .lines()
            .filter_map(|line| line.strip_prefix("| `"))
            .filter_map(|rest| rest.split('`').next())
            .filter(|feature| feature.split(' ').next() == Some(binary))
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn every_command_and_flag_is_in_the_end_to_end_registry() {
        // Every subcommand and every long flag (global ones too) is used for real by an
        // end-to-end scenario (AGENTS.md rule 18): its row names it (`tool/check-e2e.py`
        // checks the scenarios exist).
        let cli = <Cli as clap::CommandFactory>::command();
        let mut features = Vec::new();
        let flags = |command: &clap::Command| -> Vec<String> {
            command
                .get_arguments()
                .filter_map(|arg| arg.get_long())
                .filter(|long| !matches!(*long, "help" | "version"))
                .map(|long| format!("--{long}"))
                .collect()
        };
        features.extend(flags(&cli).into_iter().map(|flag| format!("writ {flag}")));
        for sub in cli.get_subcommands() {
            let name = sub.get_name();
            features.push(format!("writ {name}"));
            features.extend(
                flags(sub)
                    .into_iter()
                    .map(|flag| format!("writ {name} {flag}")),
            );
        }
        assert!(features.len() > 40, "{features:?}");
        let registry = registry("writ");
        let missing: Vec<&String> = features.iter().filter(|f| !registry.contains(*f)).collect();
        assert!(
            missing.is_empty(),
            "not in docs/end-to-end.md's coverage registry (add a scenario and its row): {missing:?}"
        );
    }

    #[test]
    fn the_command_line_is_well_formed() {
        // clap checks its definition only when a command is parsed: every subcommand here.
        <Cli as clap::CommandFactory>::command().debug_assert();
    }

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
