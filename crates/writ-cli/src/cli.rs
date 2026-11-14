//! `writ`'s command line, as clap reads it: every command, subcommand and flag, with the
//! help each shows (the review after M7.6, W-13: out of `main.rs`, which runs them). The
//! end-to-end coverage registry is checked against it (`main.rs`'s tests).

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use writ_core::names::{Email, KeyId, ProofNamespace, RepoName, TicketId};

use crate::{Paths, approver, settings, skill, timings, workspace};

#[derive(Parser)]
#[command(
    name = "writ",
    version,
    about = "Writ: signed, scoped, time-boxed leases for AI agents"
)]
pub(crate) struct Cli {
    /// Writ's directory on this host (sessions, known_hosts, approver.pub).
    #[arg(long, env = "WRIT_HOME", global = true)]
    pub(crate) home: Option<PathBuf>,
    /// The file pinning the daemon's host key (default: <home>/known_hosts).
    #[arg(long, env = "WRIT_KNOWN_HOSTS", global = true)]
    pub(crate) known_hosts: Option<PathBuf>,
    /// The file pinning the daemon's TLS certificate, for an https:// approval URL
    /// (default: <home>/tls_pins).
    #[arg(long, env = "WRIT_TLS_PINS", global = true)]
    pub(crate) tls_pins: Option<PathBuf>,
    /// The reader key used on the approval API (default: <home>/reader).
    #[arg(long, env = "WRIT_READER", global = true)]
    pub(crate) reader: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(clap::Args)]
pub(crate) struct AgentUrl {
    /// The daemon's agents listener, ssh://host:port or unix:<path> (default: `url` in
    /// <home>/config).
    #[arg(long, env = "WRIT_URL")]
    pub(crate) url: Option<String>,
}

impl AgentUrl {
    /// The flag's or the variable's, or the settings file's.
    pub(crate) fn get(&self, paths: &Paths) -> anyhow::Result<String> {
        resolve(
            self.url.as_ref(),
            paths,
            |s| s.url,
            "WRIT_URL (or --url, or url",
        )
    }
}

#[derive(clap::Args, Clone)]
pub(crate) struct ApprovalUrl {
    /// The daemon's approval listener: https://host:port, ssh://host:port or unix:<path>
    /// (default: `approval_url` in <home>/config).
    #[arg(long = "approval-url", env = "WRIT_APPROVAL_URL")]
    pub(crate) url: Option<String>,
}

impl ApprovalUrl {
    /// The flag's or the variable's, or the settings file's.
    pub(crate) fn get(&self, paths: &Paths) -> anyhow::Result<String> {
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
pub(crate) fn resolve(
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
pub(crate) struct SignerArgs {
    /// The approval key's public half (default: <home>/approver.pub).
    #[arg(long = "key", env = "WRIT_APPROVAL_KEY")]
    pub(crate) key: Option<PathBuf>,
    /// The ssh-agent socket holding the approval key (default: $SSH_AUTH_SOCK).
    #[arg(long = "agent", env = "WRIT_APPROVAL_AGENT")]
    pub(crate) agent: Option<PathBuf>,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
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
        #[command(flatten)]
        url: AgentUrl,
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
        /// Show every line of the report's agent text and warnings (by default, 40 lines
        /// each).
        #[arg(long)]
        full: bool,
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
        /// Show every line of the agent's text and of the warnings (by default, 40 lines
        /// each).
        #[arg(long)]
        full: bool,
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
        /// For the approval popup (writ-popup, M7.8): watch for waiting tickets, show each
        /// one through the app (one JSON line each way on stdin and stdout), sign or refuse
        /// it on its answer. Runs until stdin ends. No narrowing: the terminal's `writ sign`.
        #[arg(long, conflicts_with_all = [
            "id", "yes", "full", "ttl", "drop_repos", "drop_ops", "branches", "drop_emails",
            "max_signatures", "max_pushes", "max_ops_per_minute", "max_push_size",
            "no_force_push", "revoke_on_violation",
        ])]
        ui: bool,
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
pub(crate) enum RecoveryCommand {
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
pub(crate) enum AdminCommand {
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
pub(crate) enum TlsCommand {
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
pub(crate) enum AutoUnsealCommand {
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
pub(crate) enum CaCommand {
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
pub(crate) enum EntryCommand {
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
pub(crate) enum HostCommand {
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
pub(crate) enum SkillCommand {
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
pub(crate) enum RepoCommand {
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
pub(crate) enum TemplateCommand {
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
pub(crate) enum KeyCommand {
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
    pub(crate) fn split(&self) -> (EntryCommand, Option<String>) {
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

pub(crate) fn parse_agents(text: &str) -> Result<std::collections::BTreeSet<skill::Agent>, String> {
    skill::parse_agents(text)
}

pub(crate) fn parse_member(text: &str) -> Result<(String, Option<RepoName>), String> {
    workspace::parse_answer(text)
}

pub(crate) fn parse_phase(text: &str) -> Result<timings::Phase, String> {
    text.parse()
}
