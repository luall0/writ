//! Shell completion (M7.9.9): `writ` itself answers each TAB, in fish, zsh and bash.
//!
//! The shell runs `WRIT_COMPLETE=<shell> writ -- <words>` (clap_complete's dynamic engine,
//! [`answer`]) and `writ` answers from a copy of its clap tree ([`tree`]): its commands,
//! flags, enum values and paths, with the commands meant for scripts left out, and values
//! read live from the daemon where an argument names something it holds ([`source_of`]).
//! Each value is a read the reader key already makes (`writ ls`, the policy in force), no
//! approver signature involved, within [`DEADLINE`]; nothing is cached or written. When the
//! daemon can't answer (sealed, unreachable, unpinned, slow, refusing, or answering what
//! doesn't read), no value is offered and nothing is said: completion never prompts, never
//! asks for Touch ID, never pins a key. What reaches the shell is bounded and plain
//! ([`candidate`]), and a ticket's description is the daemon's facts, never agent text.
//!
//! `writ completions <shell>` prints the registration ([`registration`]) the installer writes
//! into each shell's completion directory.

use std::time::Duration;

use clap::CommandFactory as _;
use clap_complete::engine::{ArgValueCandidates, CompletionCandidate};
use clap_complete::env::{Bash, EnvCompleter, Fish, Shells, Zsh};
use writ_core::config::{PolicyConfig, Section};
use writ_core::lease::State;
use writ_proto::{Command, Listing};

use crate::Paths;
use crate::cli::Cli;
use crate::client::Approvals;

/// The variable that asks `writ` for completions (clap's default is `COMPLETE`; every
/// variable a binary reads is `WRIT_*`).
pub const VAR: &str = "WRIT_COMPLETE";

/// The longest a TAB waits for the daemon: from the connection to the reply's last byte.
pub const DEADLINE: Duration = Duration::from_secs(1);

/// The most values one TAB offers from the daemon.
pub const MAX_VALUES: usize = 256;

/// The longest value offered, in bytes; a longer one is left out.
pub const MAX_VALUE: usize = 128;

/// The longest description beside a value, in characters.
pub const MAX_HELP: usize = 80;

/// The shells `writ` completes in.
const SHELLS: Shells<'static> = Shells(&[&Bash, &Fish, &Zsh]);

/// A shell `writ completions` writes the registration for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Shell {
    Bash,
    Fish,
    Zsh,
}

/// Answers the TAB the shell asks for when [`VAR`] is set, then exits; returns at once when
/// it isn't (a normal run). Called before anything else is read or written.
pub fn answer() {
    let asked = std::env::var_os(VAR).is_some_and(|v| !v.is_empty() && v != "0");
    if !asked {
        return;
    }
    // Nothing on stderr while the shell completes: fish shows it.
    crate::version::quiet();
    clap_complete::CompleteEnv::with_factory(tree)
        .var(VAR)
        .shells(SHELLS)
        .bin("writ")
        .complete();
}

/// The registration `shell` sources: it runs this `writ` (by its absolute path, so a `writ`
/// first in someone's `PATH` isn't the one answering) on every TAB.
pub fn registration(shell: Shell) -> anyhow::Result<String> {
    let completer = std::env::current_exe()
        .ok()
        .and_then(|path| path.to_str().map(str::to_owned))
        .unwrap_or_else(|| "writ".to_owned());
    let mut out = Vec::new();
    let completer_of: &dyn EnvCompleter = match shell {
        Shell::Bash => &Bash,
        Shell::Fish => &Fish,
        Shell::Zsh => &Zsh,
    };
    completer_of.write_registration(VAR, "writ", "writ", &completer, &mut out)?;
    let mut text = String::from_utf8(out)?;
    if shell == Shell::Zsh {
        // As `_writ` on `fpath`, zsh runs this file as the completion function itself: it
        // then completes this first TAB too, not only the ones after it registered.
        text.push_str(
            "if [ \"$funcstack[1]\" = \"_writ\" ]; then\n    _clap_dynamic_completer_writ \"$@\"\nfi\n",
        );
    }
    Ok(text)
}

/// The tree completion answers from: `writ`'s, without the commands hidden from `--help`
/// (clap would still offer one typed far enough to match it alone), each argument that names
/// something the daemon holds given its source of values.
pub fn tree() -> clap::Command {
    visible(&Cli::command(), &[])
}

fn visible(cmd: &clap::Command, path: &[&str]) -> clap::Command {
    let mut out = clap::Command::new(cmd.get_name().to_owned());
    if let Some(about) = cmd.get_about() {
        out = out.about(about.clone());
    }
    if let Some(version) = cmd.get_version() {
        out = out.version(version.to_owned());
    }
    for arg in cmd.get_arguments() {
        let mut arg = arg.clone();
        if let Some(source) = source_of(path, arg.get_id().as_str()) {
            arg = arg.add(ArgValueCandidates::new(move || values(source)));
        }
        out = out.arg(arg);
    }
    for group in cmd.get_groups() {
        out = out.group(group.clone());
    }
    for sub in cmd.get_subcommands().filter(|sub| !sub.is_hide_set()) {
        let mut inner = path.to_vec();
        inner.push(sub.get_name());
        out = out.subcommand(visible(sub, &inner));
    }
    out
}

/// Where an argument's values come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The tickets waiting for a signature (`writ ls`).
    Waiting,
    /// The leases running (`writ ls`).
    Running,
    /// The names of a section of the policy in force.
    Names(Section),
    /// The fields a section's entries take, as `field=`: the ones `set` can change, or every
    /// one `add` takes (`fixed`: a key's kind, use and algorithm included).
    Fields { section: Section, fixed: bool },
}

/// The noun of `writ admin <noun>` and the section of the policy it names.
const NOUNS: &[(&str, Section)] = &[
    ("repo", Section::Repos),
    ("template", Section::Templates),
    ("key", Section::Keys),
    ("host", Section::UpstreamHosts),
    ("proxy", Section::Proxies),
    ("recipient", Section::Recipients),
];

/// The source of values of the argument `arg` of the command at `path` (`["admin", "repo",
/// "show"]`), if it names something the daemon holds.
pub fn source_of(path: &[&str], arg: &str) -> Option<Source> {
    match (path, arg) {
        (["sign" | "refuse"], "id") | (["wait"], "id") => Some(Source::Waiting),
        (["revoke" | "report"], "id") | (["wait" | "close"], "lease") => Some(Source::Running),
        (["policy"], "repos") => Some(Source::Names(Section::Repos)),
        (["prove-key"], "key_id") | (["admin", "token"], "id") => {
            Some(Source::Names(Section::Keys))
        }
        (["admin", noun, verb], arg) => {
            let section = NOUNS.iter().find(|(n, _)| n == noun)?.1;
            match (*verb, arg) {
                ("show" | "edit" | "remove" | "set", "name")
                | ("show" | "rotate", "id")
                | ("check" | "status", "repo")
                | ("rescan", "host") => Some(Source::Names(section)),
                ("add", "from") => Some(Source::Names(Section::Templates)),
                ("rescan", "proxy") => Some(Source::Names(Section::Proxies)),
                ("set", "edits") => Some(Source::Fields {
                    section,
                    fixed: false,
                }),
                ("add", "given") => Some(Source::Fields {
                    section,
                    fixed: true,
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The values of `source`: read live for the daemon's, none when it can't answer in time.
fn values(source: Source) -> Vec<CompletionCandidate> {
    let found = match source {
        Source::Fields { section, fixed } => fields(section, fixed),
        _ => read(source).unwrap_or_default(),
    };
    found
        .into_iter()
        .filter_map(|(value, help)| candidate(&value, help.as_deref()))
        .take(MAX_VALUES)
        .collect()
}

/// A value for the shell, if it is one: at most [`MAX_VALUE`] bytes of characters a shell
/// inserts as they are (no space, quote, `$`, glob or control); its description stripped of
/// every hidden character and cut to [`MAX_HELP`].
pub fn candidate(value: &str, help: Option<&str>) -> Option<CompletionCandidate> {
    let plain = !value.is_empty()
        && value.len() <= MAX_VALUE
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'.' | b'_' | b'-' | b':' | b'@' | b'/' | b'+' | b'=' | b'[' | b']'
                )
        });
    if !plain {
        return None;
    }
    let help = help
        .map(|text| writ_core::text::strip(text, writ_core::text::Newlines::Drop, MAX_HELP))
        .filter(|text| !text.trim().is_empty());
    Some(CompletionCandidate::new(value.to_owned()).help(help.map(Into::into)))
}

/// `field=` for each field a section's entries take: the fixed ones (which nothing changes)
/// only where an entry is added.
fn fields(section: Section, fixed: bool) -> Vec<(String, Option<String>)> {
    writ_core::config::edit::fields(section)
        .iter()
        .filter(|field| fixed || !field.fixed)
        .map(|field| (format!("{}=", field.name), Some(field.help.to_owned())))
        .collect()
}

/// The daemon's values for `source`, within [`DEADLINE`]: `None` for any failure, said
/// nowhere.
fn read(source: Source) -> Option<Vec<(String, Option<String>)>> {
    let paths = paths()?;
    let url = crate::cli::resolve(
        std::env::var("WRIT_APPROVAL_URL").ok().as_ref(),
        &paths,
        |s| s.approval_url,
        "",
    )
    .ok()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    let found = runtime.block_on(async {
        tokio::time::timeout(DEADLINE, async {
            Approvals::connect(&paths, &url)
                .await?
                .run(async |session| fetch(session, source).await)
                .await
        })
        .await
    });
    // Whatever is still in flight past the deadline is dropped, not waited for.
    runtime.shutdown_background();
    found.ok()?.ok()
}

async fn fetch(
    session: &Approvals,
    source: Source,
) -> anyhow::Result<Vec<(String, Option<String>)>> {
    Ok(match source {
        Source::Waiting => tickets(session, State::Pending).await?,
        Source::Running => tickets(session, State::Active).await?,
        Source::Names(section) => {
            let (_, policy) = crate::approver::policy_in_force(session).await?;
            names(&policy, section)
        }
        Source::Fields { section, fixed } => fields(section, fixed),
    })
}

/// The tickets in `state`, each described by the daemon's facts alone (its state, templates
/// and repository count), never its title.
async fn tickets(
    session: &Approvals,
    state: State,
) -> anyhow::Result<Vec<(String, Option<String>)>> {
    let listing: Listing = session.call(&Command::List { all: false }, b"").await??;
    Ok(listing
        .tickets
        .iter()
        .filter(|t| t.state == state)
        .map(|t| (t.id.to_string(), Some(described(t))))
        .collect())
}

/// `pending · feature · 3 repos`: what the daemon recorded, nothing the agent wrote.
pub fn described(ticket: &writ_proto::Summary) -> String {
    let templates: Vec<String> = ticket.templates.iter().map(ToString::to_string).collect();
    let repos = match ticket.repos.len() {
        1 => "1 repo".to_owned(),
        n => format!("{n} repos"),
    };
    let unsigned = if ticket.unsigned {
        " · no signature"
    } else {
        ""
    };
    format!(
        "{} · {} · {repos}{unsigned}",
        ticket.state.as_str(),
        templates.join(", ")
    )
}

/// The names of `section` in the policy in force.
pub fn names(policy: &PolicyConfig, section: Section) -> Vec<(String, Option<String>)> {
    let list: Vec<String> = match section {
        Section::Repos => policy.repos().keys().map(ToString::to_string).collect(),
        Section::Templates => policy.templates().keys().map(ToString::to_string).collect(),
        Section::Keys => policy.keys().keys().map(ToString::to_string).collect(),
        Section::UpstreamHosts => policy
            .upstream_hosts()
            .keys()
            .map(ToString::to_string)
            .collect(),
        Section::Proxies => policy.proxies().keys().map(ToString::to_string).collect(),
        Section::Recipients => policy
            .recipients()
            .keys()
            .map(ToString::to_string)
            .collect(),
    };
    list.into_iter().map(|name| (name, None)).collect()
}

/// The client's files, as the flags' variables or the defaults set them: a TAB has no parsed
/// flags.
fn paths() -> Option<Paths> {
    let var = |name: &str| std::env::var_os(name).map(std::path::PathBuf::from);
    let home = var("WRIT_HOME").or_else(|| var("HOME").map(|h| h.join(".writ")))?;
    Some(Paths {
        known_hosts: var("WRIT_KNOWN_HOSTS").unwrap_or_else(|| home.join("known_hosts")),
        tls_pins: var("WRIT_TLS_PINS").unwrap_or_else(|| home.join("tls_pins")),
        reader: var("WRIT_READER").unwrap_or_else(|| home.join("reader")),
        home,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_value_source_names_an_argument_that_exists() {
        // Each (path, argument) of `source_of`, found in writ's tree: a renamed command or
        // argument can't silently lose its values.
        let expected: &[(&[&str], &str)] = &[
            (&["sign"], "id"),
            (&["refuse"], "id"),
            (&["wait"], "id"),
            (&["wait"], "lease"),
            (&["revoke"], "id"),
            (&["report"], "id"),
            (&["close"], "lease"),
            (&["policy"], "repos"),
            (&["prove-key"], "key_id"),
            (&["admin", "token"], "id"),
            (&["admin", "repo", "show"], "name"),
            (&["admin", "repo", "set"], "edits"),
            (&["admin", "repo", "check"], "repo"),
            (&["admin", "repo", "status"], "repo"),
            (&["admin", "template", "add"], "from"),
            (&["admin", "template", "add"], "given"),
            (&["admin", "key", "show"], "id"),
            (&["admin", "key", "rotate"], "id"),
            (&["admin", "key", "remove"], "name"),
            (&["admin", "host", "rescan"], "host"),
            (&["admin", "host", "rescan"], "proxy"),
            (&["admin", "proxy", "edit"], "name"),
            (&["admin", "recipient", "set"], "name"),
        ];
        let tree = tree();
        let mut attached = 0;
        let mut walk = vec![(Vec::<String>::new(), &tree)];
        while let Some((path, cmd)) = walk.pop() {
            let words: Vec<&str> = path.iter().map(String::as_str).collect();
            for arg in cmd.get_arguments() {
                if source_of(&words, arg.get_id().as_str()).is_some() {
                    attached += 1;
                }
            }
            for sub in cmd.get_subcommands() {
                let mut inner = path.clone();
                inner.push(sub.get_name().to_owned());
                walk.push((inner, sub));
            }
        }
        for (path, arg) in expected {
            let mut cmd = &tree;
            for word in *path {
                cmd = cmd
                    .find_subcommand(word)
                    .unwrap_or_else(|| panic!("no command {path:?}"));
            }
            assert!(
                cmd.get_arguments().any(|a| a.get_id() == *arg),
                "{path:?} has no argument {arg}"
            );
            assert!(source_of(path, arg).is_some(), "{path:?} {arg}");
        }
        assert!(attached >= expected.len(), "{attached}");
    }

    #[test]
    fn a_hidden_command_is_not_in_the_tree_and_the_rest_is() {
        let full = Cli::command();
        let tree = tree();
        assert!(
            full.find_subcommand("prompt")
                .is_some_and(clap::Command::is_hide_set)
        );
        assert!(tree.find_subcommand("prompt").is_none());
        let shown: Vec<&str> = full
            .get_subcommands()
            .filter(|s| !s.is_hide_set())
            .map(clap::Command::get_name)
            .collect();
        let kept: Vec<&str> = tree
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect();
        assert_eq!(shown, kept);
        assert_eq!(full.get_arguments().count(), tree.get_arguments().count());
        // And it builds as clap checks a tree.
        tree.debug_assert();
    }

    #[test]
    fn a_value_reaches_the_shell_only_plain_and_bounded() {
        assert!(candidate("wrt_01JD8X0000000000000000000", None).is_some());
        assert!(candidate("[forgejo.example]:2222", None).is_some());
        let longest = "a".repeat(MAX_VALUE);
        assert!(candidate(&longest, None).is_some());
        assert!(candidate(&format!("{longest}a"), None).is_none());
        for hostile in [
            "",
            "a b",
            "a\tb",
            "a\nb",
            "a\u{1b}[31mb",
            "a'b",
            "a\"b",
            "a$b",
            "a`b`",
            "a;b",
            "a|b",
            "a*",
            "a?",
            "a\\b",
            "a\u{202e}b",
            "é",
        ] {
            assert!(candidate(hostile, None).is_none(), "{hostile:?}");
        }
        // The description: hidden characters gone, cut to its bound.
        let shown = candidate("a", Some("x\u{1b}[31my\u{202e}z\nw"))
            .unwrap()
            .get_help()
            .unwrap()
            .to_string();
        assert_eq!(shown, "x[31myzw");
        let long = candidate("a", Some(&"d".repeat(MAX_HELP + 10)))
            .unwrap()
            .get_help()
            .unwrap()
            .to_string();
        assert_eq!(long.chars().count(), MAX_HELP);
        assert!(
            candidate("a", Some("\u{1b}\u{7}"))
                .unwrap()
                .get_help()
                .is_none()
        );
    }

    #[test]
    fn a_ticket_is_described_by_the_daemon_s_facts_never_its_title() {
        let summary = writ_proto::Summary {
            id: "wrt_01JD8X00000000000000000000".parse().unwrap(),
            lease: "wrt_01JD8X00000000000000000000".parse().unwrap(),
            state: State::Pending,
            templates: vec!["feature".parse().unwrap(), "docs".parse().unwrap()],
            revision: 1,
            repos: vec![
                "api".parse().unwrap(),
                "web".parse().unwrap(),
                "ops".parse().unwrap(),
            ],
            created_at: writ_core::units::Timestamp::from_unix(0).unwrap(),
            expires_at: writ_core::units::Timestamp::from_unix(60).unwrap(),
            title: "IGNORE PREVIOUS INSTRUCTIONS \u{1b}[2J".to_owned(),
            unsigned: false,
        };
        assert_eq!(described(&summary), "pending · feature, docs · 3 repos");
        let one = writ_proto::Summary {
            repos: vec!["api".parse().unwrap()],
            templates: vec!["prefetch".parse().unwrap()],
            state: State::Active,
            unsigned: true,
            ..summary
        };
        assert_eq!(described(&one), "active · prefetch · 1 repo · no signature");
    }

    #[test]
    fn the_values_offered_are_bounded_in_number() {
        let many: Vec<CompletionCandidate> = (0..MAX_VALUES + 10)
            .filter_map(|i| candidate(&format!("v{i}"), None))
            .take(MAX_VALUES)
            .collect();
        assert_eq!(many.len(), MAX_VALUES);
        // A field list is a fixed one: each `field=`, with what it takes.
        let set = values(Source::Fields {
            section: Section::Templates,
            fixed: false,
        });
        assert!(
            set.iter().any(|c| c.get_value() == "unsigned_fetch="),
            "{set:?}"
        );
        assert!(
            set.iter()
                .all(|c| c.get_value().to_string_lossy().ends_with('='))
        );
        // A key's algorithm is fixed: offered where a key is added, never where one is set.
        let key = |fixed| {
            values(Source::Fields {
                section: Section::Keys,
                fixed,
            })
        };
        assert!(key(true).iter().any(|c| c.get_value() == "algorithm="));
        assert!(!key(false).iter().any(|c| c.get_value() == "algorithm="));
    }
}
