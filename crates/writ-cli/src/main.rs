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

mod agent;
mod approver;
mod client;
mod close;
mod display;
mod gitopts;
mod https;
mod init;
mod policy;
mod reader;
mod repos;
mod run;
mod session;
mod settings;
mod skill;
mod timings;
mod wiring;
mod workspace;
mod wrap;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use writ_core::names::{Email, KeyId, ProofNamespace, RepoName, TicketId};

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
    /// The daemon's agents listener, ssh://host:port or unix:<path> (default: `url` in
    /// <home>/config).
    #[arg(long, env = "WRIT_URL")]
    url: Option<String>,
}

impl AgentUrl {
    /// The flag's or the variable's, or the settings file's.
    fn get(&self, paths: &Paths) -> anyhow::Result<String> {
        resolve(
            self.url.as_ref(),
            paths,
            |s| s.url,
            "WRIT_URL (or --url, or url",
        )
    }
}

#[derive(clap::Args, Clone)]
struct ApprovalUrl {
    /// The daemon's approval listener: https://host:port, ssh://host:port or unix:<path>
    /// (default: `approval_url` in <home>/config).
    #[arg(long = "approval-url", env = "WRIT_APPROVAL_URL")]
    url: Option<String>,
}

impl ApprovalUrl {
    /// The flag's or the variable's, or the settings file's.
    fn get(&self, paths: &Paths) -> anyhow::Result<String> {
        resolve(
            self.url.as_ref(),
            paths,
            |s| s.approval_url,
            "WRIT_APPROVAL_URL (or --approval-url, or approval_url",
        )
    }
}

/// `given` (a flag or its variable), or what `<home>/config` sets (`pick`), or an error
/// naming where it can come from.
fn resolve(
    given: Option<&String>,
    paths: &Paths,
    pick: fn(settings::Settings) -> Option<String>,
    from: &str,
) -> anyhow::Result<String> {
    if let Some(given) = given {
        return Ok(given.clone());
    }
    pick(settings::load(&paths.home)?).ok_or_else(|| {
        anyhow::anyhow!(
            "no daemon to reach: set {from} in {})",
            paths.home.join(settings::FILE).display()
        )
    })
}

#[derive(clap::Args, Clone)]
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
        /// Check the ticket as the daemon would on submission (templates, limits, the lease it
        /// amends or renews), without submitting it: nothing stored, nobody asked.
        #[arg(long, conflicts_with = "no_wait")]
        dry_run: bool,
        #[command(flatten)]
        url: AgentUrl,
    },
    /// What a ticket for a repo may ask (templates, branches, committer emails, limits,
    /// protected refs), from the daemon's policy: the repo named, or this wired repository's.
    Policy {
        /// The repos' names in the daemon's registry (default: the wired repository's); for
        /// several, whether one ticket can cover them.
        repos: Vec<RepoName>,
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
    /// docs/operators/good-practice.md). With no repo named, at a folder of repositories:
    /// each one level down is wired, for one agent at the folder (a workspace).
    Init {
        /// The repo's name in the daemon's registry (none: the folder is a workspace).
        repo: Option<RepoName>,
        /// At a workspace root: the registry name of the repository in <dir> (`-` leaves it
        /// out; `.` is the folder's own repository). Repeatable; on a terminal, the others
        /// are asked.
        #[arg(
            long = "repo",
            id = "members",
            value_name = "DIR=NAME",
            value_parser = parse_member,
            conflicts_with_all = ["undo", "repo"],
        )]
        members: Vec<(String, Option<RepoName>)>,
        /// Write the settings in the repo's git config: for a clone dedicated to an agent.
        #[arg(long, conflicts_with = "undo")]
        whole_repo: bool,
        /// The committer email (default: the current lease's, if it allows exactly one).
        #[arg(long, conflicts_with = "undo")]
        email: Option<Email>,
        /// Take the repo back to before `writ init`.
        #[arg(long, conflicts_with = "repo")]
        undo: bool,
        /// With --undo: every repository and workspace `writ init` wired on this host (its
        /// list, <home>/repos), each said.
        #[arg(long, requires = "undo")]
        all: bool,
        /// The repositories and workspaces `writ init` wired on this host (<home>/repos), each
        /// checked: what an uninstall or `--undo --all` would take back.
        #[arg(long, conflicts_with_all = ["repo", "undo"])]
        list: bool,
        /// The daemon's agents listener, ssh://host:port or unix:<path> (default: `url` in
        /// <home>/config).
        #[arg(long, env = "WRIT_URL")]
        url: Option<String>,
        /// Pin the repo to this lease: its session, never `current` (WRIT_SESSION still
        /// comes first).
        #[arg(long, conflicts_with = "undo")]
        lease: Option<TicketId>,
        /// The agents the skill is installed for, without asking: claude, agents (Codex,
        /// Gemini CLI, Copilot, Amp…), opencode, cursor, comma-separated; or none.
        #[arg(long, conflicts_with = "undo", value_parser = parse_agents)]
        agents: Option<std::collections::BTreeSet<skill::Agent>>,
        /// Also install the skill in this skills folder (<path>/writ/SKILL.md).
        #[arg(long, conflicts_with = "undo")]
        skill_dir: Option<PathBuf>,
        /// Install in your own folders (~/.claude/skills…) instead of the repo's.
        #[arg(long, conflicts_with = "undo")]
        global: bool,
        /// Add a line pointing at the skill to AGENTS.md / CLAUDE.md.
        #[arg(long, conflicts_with = "undo")]
        agents_md: bool,
    },
    /// The agent skill writ init installed here.
    Skill {
        #[command(subcommand)]
        command: SkillCommand,
    },
    /// Run any git command with the repo's Writ wiring (signing by the daemon, the session's
    /// SSH command, the `writ` remote), without changing its git config.
    Git {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run a program (that runs git) with the repo's Writ wiring: writ exec [-C <dir>] --
    /// <program> [args].
    Exec {
        /// Run it in <dir>, under the wiring of the repository there (one repository per
        /// process).
        #[arg(short = 'C', value_name = "DIR")]
        dir: Option<PathBuf>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<OsString>,
    },
    /// Run an agent harness as the root of its session: every `writ request` under it binds
    /// its lease to the session, refused outside it and revoked when it ends. writ run --
    /// <program> [args]; its exit status is the harness's.
    Run {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<OsString>,
    },
    /// End a lease with a summary: prints its activity report and records the run in the
    /// timings file. The lease: the one named, WRIT_SESSION, or the current one.
    Close {
        lease: Option<TicketId>,
        /// What was done, what is left (shown to the approver as written).
        #[arg(long, short = 'm')]
        summary: String,
        #[command(flatten)]
        url: AgentUrl,
    },
    /// Check a ticket file (as far as can be without the daemon), or the timings file (what
    /// `writ close` would drop or rewrite). Sends nothing; exit 3 with every problem.
    Check {
        /// The file (`-` for stdin).
        file: PathBuf,
    },
    /// Mark the end of a phase (coding, checks, ci) the daemon can't see: shown as yours in
    /// the activity report.
    Mark {
        #[arg(value_parser = parse_phase)]
        phase: timings::Phase,
    },
    /// The timings file's limits (the repo here): change them, then the file is compacted.
    Timings {
        /// The most lines the file keeps.
        #[arg(long)]
        max_lines: Option<usize>,
        /// The most bytes the file keeps.
        #[arg(long)]
        max_bytes: Option<usize>,
        /// The runs listed per repository (every run stays in its summary).
        #[arg(long)]
        keep_runs: Option<usize>,
        /// The notes kept per repository.
        #[arg(long)]
        max_notes: Option<usize>,
    },
    /// Print this machine's reader key line for the daemon's `readers` file (the key is made
    /// on first use).
    Reader {
        /// The name the daemon logs for this reader.
        #[arg(default_value = "approver")]
        name: String,
    },
    /// A lease's activity report (commits, pushes, denials, time used).
    Report {
        id: TicketId,
        #[command(flatten)]
        url: ApprovalUrl,
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
    /// The policy, approvers or readers in force, and signed changes of them.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// The daemon keystore's offline recovery key (M7.6): it opens every secret when the
    /// daemon's hardware is lost.
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommand,
    },
    /// Unseal a daemon that started sealed: the keystore's passphrase (asked for, or one
    /// line of stdin), and one signature with your approval key over this start of this
    /// daemon.
    Unseal {
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
}

#[derive(Subcommand)]
enum RecoveryCommand {
    /// Make a recovery key, best on a machine that isn't online: its secret is printed once
    /// (write it down; nothing is saved) with its recipient, to declare with `writ admin
    /// recipient add <name> recipient=<age1…>`.
    New,
    /// Check that you hold the daemon's recovery key: it is read (no echo, or one line of
    /// stdin) and opens the daemon's challenge here; nothing secret is sent.
    Check {
        #[command(flatten)]
        url: ApprovalUrl,
    },
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Print the file in force (policy, approvers or readers) on stdout, to edit and apply.
    Show {
        /// policy, approvers or readers.
        target: String,
        #[command(flatten)]
        url: ApprovalUrl,
    },
    /// Replace the file in force with FILE: shows what changes, then one signature with your
    /// approval key. It applies at once.
    Apply {
        /// policy, approvers or readers.
        target: String,
        file: PathBuf,
        /// Sign without asking (what changes is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
    /// The repos of the registry in force.
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
    },
    /// The templates in force.
    Template {
        #[command(subcommand)]
        command: TemplateCommand,
    },
    /// The keys the policy in force declares: signing keys and upstream credentials.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// The upstream host keys pinned in the policy in force.
    Host {
        #[command(subcommand)]
        command: HostCommand,
    },
    /// The proxies in the policy in force, which repos reach their upstream through (SOCKS5,
    /// Tor included, or HTTP CONNECT).
    Proxy {
        #[command(subcommand)]
        command: EntryCommand,
    },
    /// The keystore's recipients in the policy in force (M7.6): a hardware key the daemon
    /// makes (the Secure Enclave), and the offline recovery key.
    Recipient {
        #[command(subcommand)]
        command: EntryCommand,
    },
    /// The HTTPS approval API's TLS key (M7.5).
    Tls {
        #[command(subcommand)]
        command: TlsCommand,
    },
    /// The daemon's SSH certificate authority (M7.6): it signs each lease's certificate.
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    /// Whether the daemon opens itself at start, with no one (M7.6): only with every key and
    /// secret in hardware. `status` says what is missing.
    #[command(name = "auto-unseal")]
    AutoUnseal {
        #[command(subcommand)]
        command: AutoUnsealCommand,
    },
    /// Add or replace the token ID (a token the policy declares, or a notifier's sealed
    /// token): asked for with no echo (or one line of stdin), encrypted here to the daemon's
    /// keystore, then one signature with your approval key. It is used at once.
    Token {
        /// The credential id.
        id: String,
        /// Sign without asking (what is replaced is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
}

/// `writ admin tls <verb>`.
#[derive(Subcommand)]
enum TlsCommand {
    /// A new key for the HTTPS approval API, on BACKEND (the current one by default: the
    /// same command rotates it), and its certificate, in force at once: one signature. Reached
    /// over HTTPS, your pin is replaced; every other approver re-pins.
    Rotate {
        /// The backend the new key is made on (software, se-cryptokit: the daemon's).
        #[arg(long)]
        backend: Option<String>,
        /// Sign without asking (what is replaced is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
}

#[derive(Subcommand)]
enum AutoUnsealCommand {
    /// How the daemon unseals at start, and what keeps it from opening itself, each with the
    /// command that fixes it.
    Status {
        #[command(flatten)]
        url: ApprovalUrl,
    },
    /// The daemon opens itself after every start, through its hardware: refused, with what is
    /// missing, until every key and secret is in hardware. One signature.
    On {
        /// Sign without asking (what changes is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
    /// The daemon waits for `writ unseal` after every start again. One signature.
    Off {
        /// Sign without asking (what changes is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
}

#[derive(Subcommand)]
enum CaCommand {
    /// The CA in force, its key's backend, and the CA it replaced while its leases last.
    Show {
        #[command(flatten)]
        url: ApprovalUrl,
    },
    /// A new key for the CA, on BACKEND (the current one by default: the same command rotates
    /// it), in force at once: one signature. Leases certified by the old CA keep working until
    /// they end, and no longer.
    Rotate {
        /// The backend the new key is made on (software, se-cryptokit: the daemon's).
        #[arg(long)]
        backend: Option<String>,
        /// Sign without asking (what is replaced is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
}

/// `writ admin repo|host <verb>`.
#[derive(Subcommand)]
enum EntryCommand {
    /// One line per entry.
    List {
        #[command(flatten)]
        url: ApprovalUrl,
    },
    /// One entry, as the policy writes it, and what uses it.
    Show {
        name: String,
        #[command(flatten)]
        url: ApprovalUrl,
    },
    /// Add one, step by step: each field asked in order with its bounds and default, the
    /// ones given as field=value not asked. Without a terminal nothing is asked: every
    /// required field must be given. One signature with your approval key.
    Add {
        name: String,
        /// field=value for the fields not to ask.
        #[arg(value_name = "FIELD=VALUE")]
        given: Vec<String>,
        /// Sign without asking (the diff is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
    /// Edit one, step by step on a terminal: each field asked, Enter keeping its value. One
    /// signature with your approval key.
    Edit {
        name: String,
        /// Sign without asking (the diff is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
    /// Change only the fields named: field=value replaces, field+=value and field-=value add
    /// to and take from a list, field! unsets an optional field, field= empties a list. Shown
    /// as a diff, then one signature with your approval key.
    Set {
        name: String,
        /// field=value, field+=value, field-=value or field!.
        #[arg(value_name = "FIELD=VALUE")]
        edits: Vec<String>,
        /// Sign without asking (the diff is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
    /// Remove it: what it affects shown first, then confirmed and signed. Refused while
    /// something uses it.
    Remove {
        name: String,
        /// Answer the questions (without a terminal too); the signature is still asked for.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
}

/// `writ admin host <verb>`.
#[derive(Subcommand)]
enum HostCommand {
    #[command(flatten)]
    Entry(EntryCommand),
    /// Scan a pinned host again from the daemon (its keys changed, or to see whether they
    /// did): each key shown against the pin, compared by you, then one signed change
    /// replacing the pin. On a terminal.
    Rescan {
        host: String,
        /// Scan through this proxy of the policy (default: the one every repo on the host is
        /// reached through, when they share one).
        #[arg(long, value_name = "NAME")]
        proxy: Option<String>,
        /// Sign without asking (the diff is still shown first; the keys are still compared).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
}

/// `writ skill <verb>`.
#[derive(Subcommand)]
enum SkillCommand {
    /// Rewrite the skills writ init installed in this repository or workspace from the one
    /// built into this writ (after upgrading it). A file that isn't Writ's skill any more is
    /// left as it is.
    Update {
        /// In every repository and workspace `writ init` wired on this host (its list,
        /// <home>/repos), each said.
        #[arg(long)]
        all: bool,
    },
}

/// `writ admin repo <verb>`.
#[derive(Subcommand)]
enum RepoCommand {
    #[command(flatten)]
    Entry(EntryCommand),
    /// Reach the repo's upstream from the daemon with its credential: read and write access
    /// proven with nothing pushed, its mirror synced.
    Check {
        repo: String,
        #[command(flatten)]
        url: ApprovalUrl,
    },
}

/// `writ admin template <verb>`.
#[derive(Subcommand)]
enum TemplateCommand {
    /// One line per entry.
    List {
        #[command(flatten)]
        url: ApprovalUrl,
    },
    /// One entry, as the policy writes it, and what uses it.
    Show {
        name: String,
        #[command(flatten)]
        url: ApprovalUrl,
    },
    /// Add one, step by step: each field asked in order with its bounds and default, the
    /// ones given as field=value not asked. Without a terminal nothing is asked: every
    /// required field must be given. One signature with your approval key.
    Add {
        name: String,
        /// field=value for the fields not to ask.
        #[arg(value_name = "FIELD=VALUE")]
        given: Vec<String>,
        /// Start from this template's values (each still asked, Enter keeping it).
        #[arg(long, value_name = "TEMPLATE")]
        from: Option<String>,
        /// Sign without asking (the diff is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
    /// Edit one, step by step on a terminal: each field asked, Enter keeping its value. One
    /// signature with your approval key.
    Edit {
        name: String,
        /// Sign without asking (the diff is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
    /// Change only the fields named: field=value replaces, field+=value and field-=value add
    /// to and take from a list, field! unsets an optional field, field= empties a list. Shown
    /// as a diff, then one signature with your approval key.
    Set {
        name: String,
        /// field=value, field+=value, field-=value or field!.
        #[arg(value_name = "FIELD=VALUE")]
        edits: Vec<String>,
        /// Sign without asking (the diff is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
    /// Remove it: what it affects shown first, then confirmed and signed. Refused while
    /// something uses it.
    Remove {
        name: String,
        /// Answer the questions (without a terminal too); the signature is still asked for.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
}

/// `writ admin key <verb>`.
#[derive(Subcommand)]
enum KeyCommand {
    /// One line per key: what it is, its fingerprint (or whether a token was added), what
    /// uses it.
    List {
        #[command(flatten)]
        url: ApprovalUrl,
    },
    /// One key: its declaration, public half, fingerprint, OpenPGP certificate, users.
    Show {
        id: String,
        /// Only the public half (an OpenPGP key's certificate), for a pipe or pbcopy.
        #[arg(long)]
        public: bool,
        #[command(flatten)]
        url: ApprovalUrl,
    },
    /// Add one, step by step: each field asked in order with its bounds and default, the
    /// ones given as field=value not asked. Without a terminal nothing is asked: every
    /// required field must be given. One signature with your approval key.
    Add {
        name: String,
        /// field=value for the fields not to ask.
        #[arg(value_name = "FIELD=VALUE")]
        given: Vec<String>,
        /// Sign without asking (the diff is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
    /// Edit one, step by step on a terminal: each field asked, Enter keeping its value. One
    /// signature with your approval key.
    Edit {
        name: String,
        /// Sign without asking (the diff is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
    /// Change only the fields named: field=value replaces, field+=value and field-=value add
    /// to and take from a list, field! unsets an optional field, field= empties a list. Shown
    /// as a diff, then one signature with your approval key.
    Set {
        name: String,
        /// field=value, field+=value, field-=value or field!.
        #[arg(value_name = "FIELD=VALUE")]
        edits: Vec<String>,
        /// Sign without asking (the diff is still shown first).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
    /// Remove it: deleted from the keystore for good once the change applies, after its id is
    /// typed again. Refused while a repo or a template uses it.
    Remove {
        name: String,
        /// Answer the questions (without a terminal too); the signature is still asked for.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
    /// A new key declared like ID (ID-2, the next number, or --name), its public half printed
    /// to register; then every repo and template that used ID switched to it, a second
    /// signature; then ID offered for removal.
    Rotate {
        id: String,
        /// The new key's id.
        #[arg(long)]
        name: Option<String>,
        /// The backend the new key is made on (software, se-cryptokit: the daemon's, as
        /// `writ admin key list` says); the old key's by default.
        #[arg(long)]
        backend: Option<String>,
        /// Answer the question between the two changes (without a terminal too); the old key
        /// is then left declared, unused. The signatures are still asked for.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        url: ApprovalUrl,
        #[command(flatten)]
        signer: SignerArgs,
    },
}

impl TemplateCommand {
    /// The command as a repo's or a host's would be, and `add`'s `--from`.
    fn split(&self) -> (EntryCommand, Option<String>) {
        match self {
            Self::List { url } => (EntryCommand::List { url: url.clone() }, None),
            Self::Show { name, url } => (
                EntryCommand::Show {
                    name: name.clone(),
                    url: url.clone(),
                },
                None,
            ),
            Self::Add {
                name,
                given,
                from,
                yes,
                url,
                signer,
            } => (
                EntryCommand::Add {
                    name: name.clone(),
                    given: given.clone(),
                    yes: *yes,
                    url: url.clone(),
                    signer: signer.clone(),
                },
                from.clone(),
            ),
            Self::Edit {
                name,
                yes,
                url,
                signer,
            } => (
                EntryCommand::Edit {
                    name: name.clone(),
                    yes: *yes,
                    url: url.clone(),
                    signer: signer.clone(),
                },
                None,
            ),
            Self::Set {
                name,
                edits,
                yes,
                url,
                signer,
            } => (
                EntryCommand::Set {
                    name: name.clone(),
                    edits: edits.clone(),
                    yes: *yes,
                    url: url.clone(),
                    signer: signer.clone(),
                },
                None,
            ),
            Self::Remove {
                name,
                yes,
                url,
                signer,
            } => (
                EntryCommand::Remove {
                    name: name.clone(),
                    yes: *yes,
                    url: url.clone(),
                    signer: signer.clone(),
                },
                None,
            ),
        }
    }
}

/// `writ admin repo|template|host <verb>`, for `section` (`from`: a template's `add --from`).
async fn entry_command(
    paths: &Paths,
    section: writ_core::config::Section,
    command: &EntryCommand,
    from: Option<&str>,
) -> anyhow::Result<Exit> {
    match command {
        EntryCommand::List { url } => approver::manage_list(paths, &url.get(paths)?, section).await,
        EntryCommand::Show { name, url } => {
            approver::manage_show(paths, &url.get(paths)?, section, name, false).await
        }
        EntryCommand::Add {
            name,
            given,
            yes,
            url,
            signer: args,
        } => {
            let signer = signer(paths, args);
            approver::guided_add(
                paths,
                &url.get(paths)?,
                &signer,
                section,
                name,
                given,
                from,
                *yes,
            )
            .await
        }
        EntryCommand::Edit {
            name,
            yes,
            url,
            signer: args,
        } => {
            let signer = signer(paths, args);
            approver::guided_edit(paths, &url.get(paths)?, &signer, section, name, *yes).await
        }
        EntryCommand::Set {
            name,
            edits,
            yes,
            url,
            signer: args,
        } => {
            let signer = signer(paths, args);
            approver::manage_set(paths, &url.get(paths)?, &signer, section, name, edits, *yes).await
        }
        EntryCommand::Remove {
            name,
            yes,
            url,
            signer: args,
        } => {
            let signer = signer(paths, args);
            approver::manage_remove(paths, &url.get(paths)?, &signer, section, name, *yes).await
        }
    }
}

fn parse_agents(text: &str) -> Result<std::collections::BTreeSet<skill::Agent>, String> {
    skill::parse_agents(text)
}

fn parse_member(text: &str) -> Result<(String, Option<RepoName>), String> {
    workspace::parse_answer(text)
}

fn parse_phase(text: &str) -> Result<timings::Phase, String> {
    text.parse()
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
            let url = &resolve(
                url.as_ref(),
                &paths,
                |s| s.url,
                "WRIT_URL (or --url, or url",
            )?;
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
            url,
        } => close::close(&paths, &url.get(&paths)?, lease.as_ref(), summary).await,
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
        Commands::Report { id, url } => approver::report(&paths, &url.get(&paths)?, id).await,
        Commands::Git { args } => wrap::git(&paths, args),
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
        Commands::Admin {
            command: AdminCommand::Show { target, url },
        } => approver::admin_show(&paths, &url.get(&paths)?, approver::admin_target(target)?).await,
        Commands::Admin {
            command: AdminCommand::Repo { command },
        } => match command {
            RepoCommand::Entry(command) => {
                entry_command(&paths, writ_core::config::Section::Repos, command, None).await
            }
            RepoCommand::Check { repo, url } => {
                approver::guided_check(&paths, &url.get(&paths)?, repo).await
            }
        },
        Commands::Admin {
            command: AdminCommand::Host { command },
        } => match command {
            HostCommand::Entry(command) => {
                entry_command(
                    &paths,
                    writ_core::config::Section::UpstreamHosts,
                    command,
                    None,
                )
                .await
            }
            HostCommand::Rescan {
                host,
                proxy,
                yes,
                url,
                signer: args,
            } => {
                let signer = signer(&paths, args);
                approver::guided_rescan(
                    &paths,
                    &url.get(&paths)?,
                    &signer,
                    host,
                    proxy.as_deref(),
                    *yes,
                )
                .await
            }
        },
        Commands::Admin {
            command: AdminCommand::Proxy { command },
        } => entry_command(&paths, writ_core::config::Section::Proxies, command, None).await,
        Commands::Admin {
            command: AdminCommand::Recipient { command },
        } => {
            entry_command(
                &paths,
                writ_core::config::Section::Recipients,
                command,
                None,
            )
            .await
        }
        Commands::Admin {
            command: AdminCommand::Template { command },
        } => {
            use writ_core::config::Section;
            let (command, from) = command.split();
            entry_command(&paths, Section::Templates, &command, from.as_deref()).await
        }
        Commands::Admin {
            command: AdminCommand::Key { command },
        } => {
            use writ_core::config::Section;
            match command {
                KeyCommand::List { url } => {
                    approver::manage_list(&paths, &url.get(&paths)?, Section::Keys).await
                }
                KeyCommand::Show { id, public, url } => {
                    approver::manage_show(&paths, &url.get(&paths)?, Section::Keys, id, *public)
                        .await
                }
                KeyCommand::Add {
                    name,
                    given,
                    yes,
                    url,
                    signer: args,
                } => {
                    let signer = signer(&paths, args);
                    approver::guided_add(
                        &paths,
                        &url.get(&paths)?,
                        &signer,
                        Section::Keys,
                        name,
                        given,
                        None,
                        *yes,
                    )
                    .await
                }
                KeyCommand::Edit {
                    name,
                    yes,
                    url,
                    signer: args,
                } => {
                    let signer = signer(&paths, args);
                    approver::guided_edit(
                        &paths,
                        &url.get(&paths)?,
                        &signer,
                        Section::Keys,
                        name,
                        *yes,
                    )
                    .await
                }
                KeyCommand::Set {
                    name,
                    edits,
                    yes,
                    url,
                    signer: args,
                } => {
                    let signer = signer(&paths, args);
                    approver::manage_set(
                        &paths,
                        &url.get(&paths)?,
                        &signer,
                        Section::Keys,
                        name,
                        edits,
                        *yes,
                    )
                    .await
                }
                KeyCommand::Remove {
                    name,
                    yes,
                    url,
                    signer: args,
                } => {
                    let signer = signer(&paths, args);
                    approver::manage_remove(
                        &paths,
                        &url.get(&paths)?,
                        &signer,
                        Section::Keys,
                        name,
                        *yes,
                    )
                    .await
                }
                KeyCommand::Rotate {
                    id,
                    name,
                    backend,
                    yes,
                    url,
                    signer: args,
                } => {
                    let signer = signer(&paths, args);
                    approver::guided_rotate(
                        &paths,
                        &url.get(&paths)?,
                        &signer,
                        id,
                        name.as_deref(),
                        backend.as_deref(),
                        *yes,
                    )
                    .await
                }
            }
        }
        Commands::Admin {
            command:
                AdminCommand::Apply {
                    target,
                    file,
                    yes,
                    url,
                    signer: args,
                },
        } => {
            approver::admin_apply(
                &paths,
                &url.get(&paths)?,
                &signer(&paths, args),
                approver::admin_target(target)?,
                file,
                *yes,
            )
            .await
        }
        Commands::Admin {
            command:
                AdminCommand::Token {
                    id,
                    yes,
                    url,
                    signer: args,
                },
        } => {
            let id: writ_core::names::KeyId = id
                .parse()
                .map_err(|e| anyhow::anyhow!("token id {id:?}: {e}"))?;
            approver::admin_token(&paths, &url.get(&paths)?, &signer(&paths, args), &id, *yes).await
        }
        Commands::Admin {
            command:
                AdminCommand::Tls {
                    command:
                        TlsCommand::Rotate {
                            backend,
                            yes,
                            url,
                            signer: args,
                        },
                },
        } => {
            approver::admin_tls_rotate(
                &paths,
                &url.get(&paths)?,
                &signer(&paths, args),
                backend.as_deref(),
                *yes,
            )
            .await
        }
        Commands::Admin {
            command:
                AdminCommand::Ca {
                    command: CaCommand::Show { url },
                },
        } => approver::admin_ca_show(&paths, &url.get(&paths)?).await,
        Commands::Admin {
            command:
                AdminCommand::Ca {
                    command:
                        CaCommand::Rotate {
                            backend,
                            yes,
                            url,
                            signer: args,
                        },
                },
        } => {
            approver::admin_ca_rotate(
                &paths,
                &url.get(&paths)?,
                &signer(&paths, args),
                backend.as_deref(),
                *yes,
            )
            .await
        }
        Commands::Admin {
            command:
                AdminCommand::AutoUnseal {
                    command: AutoUnsealCommand::Status { url },
                },
        } => approver::auto_unseal_status(&paths, &url.get(&paths)?).await,
        Commands::Admin {
            command:
                AdminCommand::AutoUnseal {
                    command:
                        AutoUnsealCommand::On {
                            yes,
                            url,
                            signer: args,
                        },
                },
        } => {
            approver::auto_unseal_set(&paths, &url.get(&paths)?, &signer(&paths, args), true, *yes)
                .await
        }
        Commands::Admin {
            command:
                AdminCommand::AutoUnseal {
                    command:
                        AutoUnsealCommand::Off {
                            yes,
                            url,
                            signer: args,
                        },
                },
        } => {
            approver::auto_unseal_set(
                &paths,
                &url.get(&paths)?,
                &signer(&paths, args),
                false,
                *yes,
            )
            .await
        }
        Commands::Unseal { url, signer: args } => {
            approver::unseal(&paths, &url.get(&paths)?, &signer(&paths, args)).await
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
