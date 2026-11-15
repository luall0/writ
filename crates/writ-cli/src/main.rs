//! `writ`, the Writ CLI.
//!
//! Agent side: `writ policy` (what a ticket for the repo may ask), `writ request
//! <ticket.yaml>` (submit and wait; `--dry-run` checks it only), `writ wait <id>`, `writ init
//! <repo>` (wire a repository and install the agent skill; `--whole-repo` for a clone
//! dedicated to an agent, `--undo`; with no repo named, a folder of repositories: a
//! workspace), `writ git <args>` and `writ exec [-C <dir>] -- <program>` (git, or a program,
//! with the wiring), `writ close` (end the lease: its report, recorded in the timings file),
//! `writ mark <phase>`, `writ timings`.
//! Approver side: `writ reader` (the key this machine uses on the approval API), `writ ls`,
//! `writ report <lease>`,
//! `writ sign [<id>]` (the trusted display, then an SSHSIG through the approver's
//! ssh-agent), `writ refuse <id>`, `writ revoke <id>`, `writ prove-key <key id> --namespace
//! <ns>` (an agent signing key's proof for a remote, the message on stdin).
//!
//! The client is untrusted: every check it makes is a convenience, the daemon checks again.
//! It never reads the user's `~/.ssh`: the daemon's host key is pinned in
//! `<home>/known_hosts` (`<home>` is `$WRIT_HOME`, or `~/.writ`).
//!
//! The command line is [`cli`]'s; `writ admin`'s subcommands are dispatched by
//! [`approver::dispatch`].

mod agent;
mod approver;
mod cli;
mod client;
mod close;
mod display;
mod gitopts;
mod https;
mod init;
mod policy;
mod prompt;
mod reader;
mod repos;
mod run;
mod session;
mod settings;
mod skill;
mod timings;
mod unsigned;
mod version;
mod wiring;
mod workspace;
mod wrap;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Commands, RecoveryCommand, SignerArgs, SkillCommand};

/// Every block is zeroed when it is freed, whatever code freed it: a library's copy of a
/// secret too (age's, sealing a token; docs/security.md#secrets).
#[global_allocator]
static ALLOCATOR: writ_alloc::Wiping = writ_alloc::Wiping::system();

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
    /// The approver answered no to a "Sign …?" question (`writ sign`, `writ prove-key`, every
    /// `writ admin` change, a scan's keys not matching): nothing was signed.
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

pub(crate) fn signer(paths: &Paths, args: &SignerArgs) -> approver::Signer {
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
        Commands::Request {
            file,
            no_wait,
            dry_run,
            url,
        } => {
            let mode = if *dry_run {
                agent::Mode::DryRun
            } else if *no_wait {
                agent::Mode::NoWait
            } else {
                agent::Mode::Wait
            };
            agent::request(&paths, &url.get(&paths)?, file, mode).await
        }
        Commands::Policy { repos, url } => policy::policy(&paths, &url.get(&paths)?, repos).await,
        Commands::Wait { id, lease, url } => {
            agent::wait(&paths, &url.get(&paths)?, id, lease.as_ref()).await
        }
        Commands::Init { list: true, .. } => init::list(&paths),
        Commands::Init {
            undo: true,
            all: true,
            ..
        } => init::undo_all(&paths),
        Commands::Init { undo: true, .. } => init::undo(&paths),
        Commands::Prompt { command } => prompt::command(command),
        Commands::Skill {
            command: SkillCommand::Update { all: true },
        } => init::update_skills_all(&paths),
        Commands::Skill {
            command: SkillCommand::Update { all: false },
        } => init::update_skills(),
        Commands::Init {
            repo,
            members,
            whole_repo,
            email,
            url,
            lease,
            agents,
            skill_dir,
            global,
            agents_md,
            ..
        } => {
            let url = &url.get(&paths)?;
            let mode = if *whole_repo {
                wiring::Mode::WholeRepo
            } else {
                wiring::Mode::Wrapper
            };
            let skill = init::SkillChoice {
                agents: agents.clone(),
                skill_dir: skill_dir.clone(),
                global: *global,
                agents_md: *agents_md,
            };
            match repo {
                Some(repo) => init::init(
                    &paths,
                    &init::Init {
                        url,
                        repo,
                        mode,
                        email: email.as_ref(),
                        lease: lease.as_ref(),
                        skill,
                    },
                ),
                None => init::init_workspace(
                    &paths,
                    &init::WorkspaceInit {
                        url,
                        mode,
                        email: email.as_ref(),
                        lease: lease.as_ref(),
                        skill,
                        answers: members,
                    },
                ),
            }
        }
        Commands::Close {
            lease,
            summary,
            full,
            url,
        } => close::close(&paths, &url.get(&paths)?, lease.as_ref(), summary, *full).await,
        Commands::Mark { phase } => close::mark(&paths, *phase),
        Commands::Check { file } => close::check(file),
        Commands::Timings {
            max_lines,
            max_bytes,
            keep_runs,
            max_notes,
        } => close::timings(&[
            ("max_lines", *max_lines),
            ("max_bytes", *max_bytes),
            ("keep_runs", *keep_runs),
            ("max_notes", *max_notes),
        ]),
        Commands::Report { id, full, url } => {
            approver::report(&paths, &url.get(&paths)?, id, *full).await
        }
        Commands::Git { args } => wrap::git(&paths, args).await,
        Commands::Exec { dir, command } => wrap::exec(&paths, dir.as_deref(), command),
        // Handled by `main` before any runtime starts.
        Commands::Run { .. } => anyhow::bail!("writ run runs on its own"),
        Commands::Reader { name } => {
            session::create_private_dir(&paths.home)?;
            println!("{}", reader::ensure(&paths.reader, name)?);
            Ok(Exit::Ok)
        }
        Commands::Ls { all, url } => approver::list(&paths, &url.get(&paths)?, *all).await,
        Commands::Sign {
            ui: true,
            url,
            signer: args,
            ..
        } => approver::ui::run(&paths, &url.get(&paths)?, &signer(&paths, args)).await,
        Commands::Sign {
            id,
            narrowing,
            yes,
            full,
            ui: false,
            url,
            signer: args,
        } => {
            let review = approver::Review {
                yes: *yes,
                full: *full,
            };
            approver::sign(
                &paths,
                &url.get(&paths)?,
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
        } => {
            approver::refuse(
                &paths,
                &url.get(&paths)?,
                &signer(&paths, args),
                id,
                message.clone(),
            )
            .await
        }
        Commands::Revoke {
            id,
            url,
            signer: args,
        } => approver::revoke(&paths, &url.get(&paths)?, &signer(&paths, args), id).await,
        Commands::Recovery {
            command: RecoveryCommand::New,
        } => approver::recovery_new(),
        Commands::Recovery {
            command: RecoveryCommand::Check { url },
        } => approver::recovery_check(&paths, &url.get(&paths)?).await,
        Commands::Admin { command } => approver::dispatch::admin(&paths, command).await,
        Commands::Unseal { url, signer: args } => {
            approver::unseal(&paths, &url.get(&paths)?, &signer(&paths, args)).await
        }
        Commands::Migrate {
            file,
            yes,
            url,
            signer: args,
        } => {
            approver::migrate(
                &paths,
                &url.get(&paths)?,
                &signer(&paths, args),
                file.as_deref(),
                *yes,
            )
            .await
        }
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
            approver::prove_key(&paths, &url.get(&paths)?, &signer(&paths, args), asked).await
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // Its own runtime and exit status: the harness's.
    if let Commands::Run { command } = &cli.command {
        return run::run(command);
    }
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
    fn the_global_allocator_wipes_every_block_freed() {
        // Only a wiping allocator counts: with any other, the count never moves.
        let before = writ_alloc::testing::wiped_blocks();
        drop(std::hint::black_box(vec![0x5au8; 4096]));
        assert!(writ_alloc::testing::wiped_blocks() > before);
    }

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
            // A flag by its long name, or its short one when it has no long one (`-C`).
            command
                .get_arguments()
                .filter_map(|arg| {
                    arg.get_long()
                        .map(|long| format!("--{long}"))
                        .or_else(|| arg.get_short().map(|short| format!("-{short}")))
                })
                .filter(|flag| !matches!(flag.as_str(), "--help" | "--version"))
                .collect()
        };
        features.extend(flags(&cli).into_iter().map(|flag| format!("writ {flag}")));
        // clap's own `--version` (M7.9.8), on `writ` alone (no `propagate_version`).
        assert!(cli.get_version().is_some(), "writ has its version");
        features.push("writ --version".to_owned());
        // A group (`writ admin`, `writ admin repo`) is its subcommands, each a command of its
        // own, however deep.
        let mut groups: Vec<(String, &clap::Command)> = cli
            .get_subcommands()
            .map(|sub| (sub.get_name().to_owned(), sub))
            .collect();
        while let Some((name, command)) = groups.pop() {
            let nested: Vec<_> = command.get_subcommands().collect();
            if nested.is_empty() {
                features.push(format!("writ {name}"));
                features.extend(
                    flags(command)
                        .into_iter()
                        .map(|flag| format!("writ {name} {flag}")),
                );
            }
            for inner in nested {
                groups.push((format!("{name} {}", inner.get_name()), inner));
            }
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
