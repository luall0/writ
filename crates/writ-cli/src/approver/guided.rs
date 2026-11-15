//! The guided flows of `writ admin <noun>`: `add` and `edit` ask each field in order (its
//! bounds and default, or its current value), the ones given on the command line not asked;
//! `template add --from` starts from another template; `key rotate` declares a new key like
//! the old one, then switches what used it. Each change is one signed change, built as `set`
//! builds one ([`writ_core::config::edit`]) and checked by the daemon whole.
//!
//! The prompts are a convenience: nothing typed here is trusted by the daemon.

use std::collections::BTreeMap;
use std::io::IsTerminal as _;

use anyhow::bail;
use writ_core::authority::AdminText;
use writ_core::canonical::Canonical;
use writ_core::config::edit::{self, Change, FieldEdit, FieldKind};
use writ_core::config::hosts::HostName;
use writ_core::config::{Key, PolicyConfig, Section, UpstreamHost, UpstreamKey};
use writ_core::names::ProxyName;
use writ_core::signed::Scan;
use writ_core::upstream::Upstream;
use writ_proto::{BackendShown, Command, ScanNonce, ScanRequest, Scanned, UpstreamChecked};

use super::admin::{Signing, sign_applied};
use super::manage::policy_in_force;
use super::{Signer, confirm, connect};
use crate::display::clean;
use crate::prompt::{self, Answer, Choice};
use crate::{Exit, Paths};

/// The lowest `min_ttl` any daemon takes: the daemon checks against its own.
const MIN_TTL: writ_core::units::Duration = writ_core::fit::MIN_TTL_FLOOR;

/// Whether stdin is a terminal: only then are questions asked.
fn terminal() -> bool {
    std::io::stdin().is_terminal()
}

/// Asks one value as text, showing `label`, `help` and what Enter keeps (`keeps`): the answer
/// as typed (empty: Enter). On a terminal a text field ([`prompt::text`]), else the plain line.
fn ask(label: &str, help: &str, keeps: Option<&str>) -> anyhow::Result<String> {
    ask_checked(label, help, keeps, FieldKind::Text)
}

/// [`ask`], a count checked as it is typed (a whole number, or Enter, or `!`).
fn ask_checked(
    label: &str,
    help: &str,
    keeps: Option<&str>,
    kind: FieldKind,
) -> anyhow::Result<String> {
    let check = move |typed: &str| match kind {
        FieldKind::Count
            if !typed.is_empty() && typed != "!" && !typed.chars().all(|c| c.is_ascii_digit()) =>
        {
            Err("a whole number (Enter keeps it)".to_owned())
        }
        _ => Ok(()),
    };
    match prompt::text(label, help, keeps, check)? {
        Answer::Given(answer) => Ok(answer.trim().to_owned()),
        Answer::Cancelled => bail!("stopped: nothing was changed or signed"),
    }
}

/// One value among `options` (what it gives, how it is shown), asked as the answer [`asked`]
/// reads: empty keeps `keeps` (Enter), `!` leaves an optional field out. On a terminal a select
/// whose first option keeps; typing filters (the value typed picks it). Plainly: [`ask`].
fn choose(
    label: &str,
    help: &str,
    keeps: Option<&str>,
    options: &[(String, String)],
    optional: bool,
) -> anyhow::Result<String> {
    if !prompt::widgets() || options.is_empty() {
        return ask(label, help, keeps);
    }
    let mut choices = Vec::new();
    if let Some(keeps) = keeps {
        choices.push(Choice::new("", format!("{keeps} (Enter keeps it)")));
    }
    choices.extend(
        options
            .iter()
            .filter(|(value, _)| Some(value.as_str()) != keeps)
            .map(|(value, shown)| Choice::new(value.clone(), shown.clone())),
    );
    if optional && keeps.is_some() {
        choices.push(Choice::new("!", "! leave it out"));
    }
    match prompt::select(label, help, &choices, 0)? {
        Answer::Given(answer) => Ok(answer),
        Answer::Cancelled => bail!("stopped: nothing was changed or signed"),
    }
}

/// Some values among `options`, asked as the answer [`asked`] reads: empty keeps `keeps` (the
/// ticked ones unchanged), `none` an empty list, else the values ticked, joined by commas. On a
/// terminal a multi-select, `keeps`'s values ticked at first. Plainly: [`ask`].
fn choose_many(
    label: &str,
    help: &str,
    keeps: Option<&str>,
    options: &[(String, String)],
) -> anyhow::Result<String> {
    if !prompt::widgets() || options.is_empty() {
        return ask(label, help, keeps);
    }
    let current: Vec<String> = keeps
        .unwrap_or_default()
        .split(',')
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .collect();
    let mut all: Vec<(String, String)> = options.to_vec();
    // A value in force the options don't name stays in sight, ticked.
    for value in &current {
        if !all.iter().any(|(v, _)| v == value) {
            all.push((value.clone(), value.clone()));
        }
    }
    let chosen: Vec<usize> = all
        .iter()
        .enumerate()
        .filter(|(_, (value, _))| current.contains(value))
        .map(|(i, _)| i)
        .collect();
    let choices: Vec<Choice> = all
        .iter()
        .map(|(value, shown)| Choice::new(value.clone(), shown.clone()))
        .collect();
    match prompt::multi(label, help, &choices, &chosen)? {
        Answer::Given(picked) => Ok(many_answer(&current, &picked)),
        Answer::Cancelled => bail!("stopped: nothing was changed or signed"),
    }
}

/// The answer a multi-select gives, as the plain prompt's: empty when the ticked values are
/// the ones in force (Enter keeps), `none` when none is ticked, else them, joined by commas.
fn many_answer(current: &[String], picked: &[String]) -> String {
    let same = picked.len() == current.len() && picked.iter().all(|v| current.contains(v));
    match () {
        _ if same => String::new(),
        _ if picked.is_empty() => "none".to_owned(),
        _ => picked.join(","),
    }
}

/// The values a field takes, when they are few and known (a select, or a multi-select for a
/// list): fixed by the policy's format, or the names in force. None: typed as text.
fn options(
    policy: &PolicyConfig,
    section: Section,
    name: &str,
    kind: FieldKind,
    makes: Option<&BackendShown>,
    backends: &[BackendShown],
) -> Option<(Vec<(String, String)>, bool)> {
    let plain = |values: &[&str]| -> Vec<(String, String)> {
        values
            .iter()
            .map(|v| ((*v).to_owned(), (*v).to_owned()))
            .collect()
    };
    let named = |names: Vec<String>| -> Option<Vec<(String, String)>> {
        (!names.is_empty()).then(|| names.into_iter().map(|n| (n.clone(), n)).collect())
    };
    let one = match (section, name) {
        _ if kind == FieldKind::Flag => Some(plain(&["true", "false"])),
        (Section::Keys, "use") => Some(plain(&["signing", "upstream"])),
        (Section::Keys, "kind") => Some(plain(&["ssh", "token"])),
        (Section::Keys, "format") => Some(plain(&["ssh", "openpgp"])),
        (Section::Keys, "hash") => Some(plain(&["sha256", "sha384", "sha512"])),
        (Section::Keys, "algorithm") => Some(match makes {
            Some(shown) => shown
                .algorithms
                .iter()
                .map(|a| (a.clone(), a.clone()))
                .collect(),
            None => plain(&["ed25519", "p256", "p384", "rsa3072", "rsa4096"]),
        }),
        (Section::Keys, "backend") => Some(
            backends
                .iter()
                .map(|b| (b.name.clone(), backend_choice(b)))
                .collect(),
        ),
        (Section::Repos, "ticket_link") => Some(plain(&["ledger_only", "trailer", "notes"])),
        (Section::Repos, "notes_ref") => Some(plain(&["commits", "writ"])),
        (Section::Repos, "object_format") => Some(plain(&["sha1", "sha256"])),
        (Section::Repos, "proxy") => named(policy.entry_names(Section::Proxies)),
        (Section::Repos, "upstream_credential") => named(
            policy
                .upstream_keys()
                .map(|(id, _)| id.to_string())
                .collect(),
        ),
        (Section::Proxies, "credential") => named(
            policy
                .upstream_keys()
                .filter(|(_, k)| matches!(k, writ_core::config::UpstreamKey::Token { .. }))
                .map(|(id, _)| id.to_string())
                .collect(),
        ),
        (Section::Templates, "signing_key") => named(
            policy
                .signing_keys()
                .map(|(id, _)| id.to_string())
                .collect(),
        ),
        (Section::Templates, "paths_check") => Some(plain(&["warn", "deny"])),
        _ => None,
    };
    if let Some(values) = one {
        return Some((values, false));
    }
    let many = match (section, name) {
        (Section::Templates, "operations") => Some(plain(&["fetch", "commit_sign", "push"])),
        (Section::Repos, "templates") => named(policy.entry_names(Section::Templates)),
        _ => None,
    };
    many.map(|values| (values, true))
}

/// Whether the field `name` of `section` is asked, given the answers so far: only the fields
/// the entry's other values need (a template's branches with commit_sign or push, a key's
/// fields for its use and kind, a repo's notes ref with notes).
fn relevant(
    section: Section,
    name: &str,
    values: &BTreeMap<String, String>,
    backends: &[BackendShown],
) -> bool {
    let value = |field: &str| values.get(field).map(String::as_str).unwrap_or_default();
    let has = |field: &str, item: &str| value(field).split(',').any(|v| v.trim() == item);
    match section {
        Section::Keys => {
            let signing = value("use") == "signing";
            match name {
                "use" => true,
                "kind" => !signing,
                "format" | "hash" => signing,
                "uids" => signing && value("format") == "openpgp",
                "algorithm" => signing || value("kind") == "ssh",
                "host" => !signing && value("kind") == "token",
                // Asked for a key (a token has no backend) once the daemon has a choice.
                "backend" => (signing || value("kind") == "ssh") && backends.len() > 1,
                _ => false,
            }
        }
        Section::Templates => {
            let signs = has("operations", "commit_sign");
            let pushes = has("operations", "push");
            match name {
                "branches" => signs || pushes,
                "force_push" => pushes,
                "committer_emails"
                | "committer_name"
                | "signing_key"
                | "paths_check"
                | "require_expected_paths" => signs,
                _ => true,
            }
        }
        Section::Repos => match name {
            "notes_ref" => value("ticket_link") == "notes",
            _ => true,
        },
        // A password goes with a user: asked only when the URL names one.
        Section::Proxies => name != "credential" || value("url").contains('@'),
        Section::UpstreamHosts => true,
        // A hardware key (backend) or the recovery key (recipient): one or the other.
        Section::Recipients => match name {
            "backend" => value("recipient").is_empty(),
            "recipient" => value("backend").is_empty(),
            _ => true,
        },
    }
}

/// What the prompt for the field `name` adds to its help: the names it may take from the
/// policy in force (templates, keys of the right use).
fn choices(
    policy: &PolicyConfig,
    section: Section,
    name: &str,
    backends: &[BackendShown],
) -> Option<String> {
    let join = |names: Vec<String>| match names.is_empty() {
        true => None,
        false => Some(names.join(", ")),
    };
    match (section, name) {
        (Section::Repos, "templates") => join(policy.entry_names(Section::Templates)),
        (Section::Repos, "proxy") => join(policy.entry_names(Section::Proxies)),
        (Section::Proxies, "credential") => join(
            policy
                .upstream_keys()
                .filter(|(_, k)| matches!(k, writ_core::config::UpstreamKey::Token { .. }))
                .map(|(id, _)| id.to_string())
                .collect(),
        ),
        (Section::Keys, "backend") => join(backends.iter().map(backend_choice).collect()),
        (Section::Templates, "signing_key") => join(
            policy
                .signing_keys()
                .map(|(id, _)| id.to_string())
                .collect(),
        ),
        _ => None,
    }
}

/// A backend as a prompt offers it: its name and the algorithms it makes.
fn backend_choice(backend: &BackendShown) -> String {
    format!(
        "{} ({})",
        clean(&backend.name),
        backend
            .algorithms
            .iter()
            .map(|a| clean(a))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// The backend a key being declared lives on, as the daemon described it: the one answered,
/// `software` when none was (the daemon has one backend, or it was kept); none when the
/// daemon named no such backend (it refuses that change whole).
fn backend_makes<'a>(
    values: &BTreeMap<String, String>,
    backends: &'a [BackendShown],
) -> Option<&'a BackendShown> {
    let named = values
        .get("backend")
        .map(String::as_str)
        .filter(|b| !b.is_empty())
        .unwrap_or("software");
    backends.iter().find(|b| b.name == named)
}

/// What a backend makes, as a prompt shows it.
fn makes_list(shown: &BackendShown) -> String {
    shown
        .algorithms
        .iter()
        .map(|a| clean(a))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The algorithm Enter takes on `shown`: `ed25519` when it makes one, else the first it makes.
fn default_algorithm(shown: &BackendShown) -> Option<&str> {
    shown
        .algorithms
        .iter()
        .find(|a| *a == "ed25519")
        .or_else(|| shown.algorithms.first())
        .map(String::as_str)
}

/// Why `answer` (an algorithm typed, Enter taking the default) can't be made on `shown`.
fn unmade(shown: &BackendShown, answer: &str) -> Option<String> {
    (!answer.is_empty() && !shown.algorithms.iter().any(|a| a == answer)).then(|| {
        format!(
            "{} makes {} keys only.",
            clean(&shown.name),
            makes_list(shown)
        )
    })
}

/// The key backends the daemon has, from `writ admin key list`'s reply.
async fn daemon_backends(session: &super::Approvals) -> anyhow::Result<Vec<BackendShown>> {
    let keys: writ_proto::KeysShown = session.call(&Command::AdminKeys, b"").await??;
    Ok(keys.backends)
}

/// The edits the answers give, asked field by field: `given` not asked, the others asked when
/// relevant (`current` the values Enter keeps: an edit's, or `--from`'s). Enter keeps (or
/// leaves a field to its default), `!` leaves an optional field out, `none` empties a list.
fn asked(
    policy: &PolicyConfig,
    section: Section,
    given: &[FieldEdit],
    current: &BTreeMap<&'static str, String>,
    adding: bool,
    backends: &[BackendShown],
) -> anyhow::Result<Vec<FieldEdit>> {
    let mut values: BTreeMap<String, String> = current
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    for one in given {
        if let Change::Set(value) = &one.change {
            values.insert(one.field.clone(), value.clone());
        }
    }
    let mut edits: Vec<FieldEdit> = Vec::new();
    for field in edit::fields(section) {
        if given.iter().any(|g| g.field == field.name)
            || !relevant(section, field.name, &values, backends)
        {
            continue;
        }
        // What an existing key is never changes: not asked in an edit.
        if field.fixed && !adding {
            continue;
        }
        // A key's algorithm: among what its backend makes (asked before it), when it is known.
        let makes = match (section, field.name) {
            (Section::Keys, "algorithm") => backend_makes(&values, backends),
            _ => None,
        };
        let help = match (makes, choices(policy, section, field.name, backends)) {
            (Some(shown), _) => format!("what {} makes: {}", clean(&shown.name), makes_list(shown)),
            (None, Some(names)) => format!("{}; in force: {names}", field.help),
            (None, None) => field.help.to_owned(),
        };
        let made_default = makes.and_then(default_algorithm);
        let keeps = current
            .get(field.name)
            .map(String::as_str)
            .or(made_default)
            .or(field.default);
        loop {
            let answer = match options(policy, section, field.name, field.kind, makes, backends) {
                Some((values, true)) => choose_many(field.name, &help, keeps, &values)?,
                Some((values, false)) => {
                    choose(field.name, &help, keeps, &values, !field.required)?
                }
                None => ask_checked(field.name, &help, keeps, field.kind)?,
            };
            if let Some(why) = makes.and_then(|shown| unmade(shown, &answer)) {
                println!("  {why}");
                continue;
            }
            let change = match answer.as_str() {
                "" if current.contains_key(field.name) => None,
                "" if made_default.is_some() => made_default.map(|a| Change::Set(a.to_owned())),
                "" if field.required => {
                    println!("  {} is required.", field.name);
                    continue;
                }
                "" => None,
                "!" if field.required => {
                    println!("  {} is required: it can't be left out.", field.name);
                    continue;
                }
                "!" => Some(Change::Unset),
                "none" if field.kind == FieldKind::List => Some(Change::Set(String::new())),
                other => Some(Change::Set(other.to_owned())),
            };
            if let Some(change) = change {
                if let Change::Set(value) = &change {
                    values.insert(field.name.to_owned(), value.clone());
                }
                if change == Change::Unset {
                    values.remove(field.name);
                }
                edits.push(FieldEdit {
                    field: field.name.to_owned(),
                    change,
                });
            }
            break;
        }
    }
    Ok(edits)
}

/// Parses the edits given on the command line.
fn parsed(given: &[String]) -> anyhow::Result<Vec<FieldEdit>> {
    given
        .iter()
        .map(|e| FieldEdit::parse(e).map_err(|why| anyhow::anyhow!(why)))
        .collect()
}

/// A key declared in the same change as the repo that uses it: its id and its fields.
type NewKey = (String, Vec<FieldEdit>);

/// A repo's credential, asked with the upstream's kind: one the policy declares, or a new key
/// declared in the same change (`new`: its id and, for an SSH key, its algorithm). The edit
/// of the repo, and the new key's edits if any.
fn credential(
    policy: &PolicyConfig,
    repo: &str,
    upstream: &str,
    backends: &[BackendShown],
) -> anyhow::Result<(FieldEdit, Option<NewKey>)> {
    let parsed = Upstream::parse(upstream).map_err(|why| anyhow::anyhow!("upstream: {why}"))?;
    let token_host = match &parsed {
        Upstream::Https(url) => Some(url.host().to_owned()),
        Upstream::Ssh(_) => None,
    };
    let fitting: Vec<String> = policy
        .upstream_keys()
        .filter(|(_, key)| match (key, &token_host) {
            (UpstreamKey::Ssh { .. }, None) => true,
            (UpstreamKey::Token { host, .. }, Some(url)) => host.is(url),
            _ => false,
        })
        .map(|(id, _)| id.to_string())
        .collect();
    let help = match fitting.is_empty() {
        true => "new: a key declared now".to_owned(),
        false => format!("one of {}, or new: a key declared now", fitting.join(", ")),
    };
    loop {
        let offered: Vec<(String, String)> =
            fitting.iter().map(|k| (k.clone(), k.clone())).collect();
        let answer = choose("upstream_credential", &help, Some("new"), &offered, false)?;
        let answer = if answer.is_empty() {
            "new".to_owned()
        } else {
            answer
        };
        if answer != "new" {
            if !fitting.contains(&answer) {
                println!("  {} is not one of these.", clean(&answer));
                continue;
            }
            return Ok((
                FieldEdit::parse(&format!("upstream_credential={answer}"))
                    .map_err(anyhow::Error::msg)?,
                None,
            ));
        }
        let default_id = format!("{repo}-upstream");
        let id = ask("new key id", "a plain name", Some(&default_id))?;
        let id = if id.is_empty() { default_id } else { id };
        let mut key = vec![FieldEdit::parse("use=upstream").map_err(anyhow::Error::msg)?];
        match &token_host {
            Some(host) => {
                key.push(FieldEdit::parse("kind=token").map_err(anyhow::Error::msg)?);
                key.push(FieldEdit::parse(&format!("host={host}")).map_err(anyhow::Error::msg)?);
            }
            None => {
                key.push(FieldEdit::parse("kind=ssh").map_err(anyhow::Error::msg)?);
                // The backend first: it limits the algorithms.
                let mut values = BTreeMap::new();
                if backends.len() > 1 {
                    let offered: Vec<String> = backends.iter().map(backend_choice).collect();
                    let named: Vec<(String, String)> = backends
                        .iter()
                        .map(|b| (b.name.clone(), backend_choice(b)))
                        .collect();
                    let backend = choose(
                        "backend",
                        &format!("where the key lives: {}", offered.join(", ")),
                        Some("software"),
                        &named,
                        false,
                    )?;
                    if !backend.is_empty() && backend != "software" {
                        key.push(
                            FieldEdit::parse(&format!("backend={backend}"))
                                .map_err(anyhow::Error::msg)?,
                        );
                        values.insert("backend".to_owned(), backend);
                    }
                }
                let makes = backend_makes(&values, backends);
                let help = match makes {
                    Some(shown) => format!(
                        "what {} makes: {} (some remotes take RSA only)",
                        clean(&shown.name),
                        makes_list(shown)
                    ),
                    None => "ed25519, p256, p384, rsa3072 or rsa4096 (some remotes take RSA only)"
                        .to_owned(),
                };
                let default = makes.and_then(default_algorithm).unwrap_or("ed25519");
                let algorithm = loop {
                    let made: Vec<(String, String)> = match makes {
                        Some(shown) => shown
                            .algorithms
                            .iter()
                            .map(|a| (a.clone(), a.clone()))
                            .collect(),
                        None => ["ed25519", "p256", "p384", "rsa3072", "rsa4096"]
                            .iter()
                            .map(|a| ((*a).to_owned(), (*a).to_owned()))
                            .collect(),
                    };
                    let answer = choose("algorithm", &help, Some(default), &made, false)?;
                    match makes.and_then(|shown| unmade(shown, &answer)) {
                        Some(why) => println!("  {why}"),
                        None if answer.is_empty() => break default.to_owned(),
                        None => break answer,
                    }
                };
                key.push(
                    FieldEdit::parse(&format!("algorithm={algorithm}"))
                        .map_err(anyhow::Error::msg)?,
                );
            }
        }
        return Ok((
            FieldEdit::parse(&format!("upstream_credential={id}")).map_err(anyhow::Error::msg)?,
            Some((id, key)),
        ));
    }
}

/// A host as `writ admin host add` takes it (`host`, `host:port` or `[host]:port`): the host,
/// its port, and the `upstream_hosts` entry it is pinned under.
pub fn host_and_port(name: &str) -> anyhow::Result<(HostName, u16, String)> {
    let (host, port) = match name.strip_prefix('[') {
        Some(rest) => {
            let (host, port) = rest
                .split_once("]:")
                .ok_or_else(|| anyhow::anyhow!("{}: write [host]:port", clean(name)))?;
            (host, port)
        }
        None => match name.split_once(':') {
            Some((host, port)) if !port.contains(':') => (host, port),
            _ => (name, "22"),
        },
    };
    let port: u16 = port
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| anyhow::anyhow!("{}: not a port", clean(port)))?;
    let host = HostName::try_from(host.to_owned()).map_err(|e| anyhow::anyhow!("{e}"))?;
    let pin = UpstreamHost::of(host.as_str(), port)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .to_string();
    Ok((host, port, pin))
}

/// Has the daemon scan `host` on `port` on the approver's signature (a `writ-scan/1` naming a
/// nonce it handed out), shows the keys with their fingerprints, and asks whether they are the
/// ones the remote publishes: the keys to pin when they are, none when they aren't. The scan
/// pins nothing. A direct scan the daemon answers with a failure adds `hint` (how to go
/// through a proxy: [`direct_hint`]).
async fn scanned(
    session: &crate::client::Approvals,
    signer: &Signer,
    host: &HostName,
    port: u16,
    proxy: Option<&ProxyName>,
    pinned: &[String],
    hint: &str,
) -> anyhow::Result<Option<Vec<String>>> {
    let nonce: ScanNonce = session.call(&Command::ScanNonce, b"").await??;
    session.authenticated()?.check_daemon(&nonce.daemon)?;
    let document = Scan::new(nonce.daemon, host.clone(), port, nonce.nonce)
        .through(proxy.cloned())
        .canonical_bytes()?;
    let through = proxy
        .map(|p| format!(" through proxy {}", clean(p.as_str())))
        .unwrap_or_default();
    println!(
        "Scanning {}:{port} from the daemon{through}: one signature with your approval key.",
        clean(host.as_str())
    );
    let request = ScanRequest {
        signature: signer.sign(&document)?,
        document: String::from_utf8(document)?,
    };
    let found: Scanned = match session
        .call(&Command::Scan, &writ_proto::encode_body(&request)?)
        .await?
    {
        Ok(found) => found,
        Err(why) if proxy.is_none() => bail!("{why}\n{hint}"),
        Err(why) => return Err(why.into()),
    };
    let found = checked_scan(host, port, found)?;
    println!(
        "{} offered these keys: compare each fingerprint with the one the remote publishes \
         (never trust a scan alone).",
        clean(&found.host)
    );
    for key in &found.keys {
        let kind = key.key.split(' ').next().unwrap_or_default();
        // On a rescan, each against the pin.
        let mark = match (
            pinned.is_empty(),
            pinned.iter().any(|p| same_key(p, &key.key)),
        ) {
            (true, _) => "",
            (false, true) => "  (pinned)",
            (false, false) => "  (new: not in the pin)",
        };
        println!("  {} {}{mark}", clean(kind), clean(&key.fingerprint));
    }
    for gone in pinned
        .iter()
        .filter(|p| scannable(p) && !found.keys.iter().any(|k| same_key(p, &k.key)))
    {
        println!(
            "  {} (pinned, no longer offered: it goes)",
            clean(gone.split(' ').next().unwrap_or_default())
        );
    }
    if !confirm("Do they match what the remote publishes?")? {
        println!("Nothing pinned.");
        return Ok(None);
    }
    Ok(Some(found.keys.into_iter().map(|k| k.key).collect()))
}

/// A scan's answer as the approver compares it (the review after M7.6, U-7): for the host and
/// port asked, each fingerprint computed here from the key that gets pinned, never taken from
/// the reply; a reply whose host or fingerprints say otherwise is refused, nothing pinned.
fn checked_scan(host: &HostName, port: u16, found: Scanned) -> anyhow::Result<Scanned> {
    let asked = UpstreamHost::of(host.as_str(), port)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .to_string();
    if found.host != asked {
        bail!(
            "asked to scan {}, the daemon answered for {}: nothing pinned",
            clean(&asked),
            clean(&found.host)
        );
    }
    let mut keys = Vec::with_capacity(found.keys.len());
    for key in found.keys {
        let public = writ_crypto::ssh_key::PublicKey::from_openssh(&key.key).map_err(|_| {
            anyhow::anyhow!(
                "the scan sent a key that doesn't read ({}): nothing pinned",
                clean(&key.key)
            )
        })?;
        let fingerprint = writ_crypto::keys::fingerprint(&public);
        if fingerprint != key.fingerprint {
            bail!(
                "the scan names a key {} whose fingerprint is {fingerprint}: nothing pinned",
                clean(&key.fingerprint)
            );
        }
        keys.push(writ_proto::ScannedKey {
            key: key.key,
            fingerprint,
        });
    }
    Ok(Scanned { host: asked, keys })
}

/// The keys to pin for `host` on `port`, as `keys=…`: scanned (on a terminal) and compared.
async fn pin_edit(
    session: &crate::client::Approvals,
    signer: &Signer,
    host: &HostName,
    port: u16,
    proxy: Option<&ProxyName>,
    hint: &str,
) -> anyhow::Result<Option<FieldEdit>> {
    match scanned(session, signer, host, port, proxy, &[], hint).await? {
        Some(keys) => Ok(Some(
            FieldEdit::parse(&format!("keys={}", keys.join(","))).map_err(anyhow::Error::msg)?,
        )),
        None => Ok(None),
    }
}

/// The proxy every repo reached through the pin `entry` names, when they all name the same
/// one (none: some reach it directly, or there is no repo on it).
fn shared_proxy(policy: &PolicyConfig, entry: &str) -> Option<ProxyName> {
    let host = UpstreamHost::try_from(entry.to_owned()).ok()?;
    let proxies: Vec<Option<ProxyName>> = policy
        .host_users(&host)
        .iter()
        .filter_map(|repo| policy.repo(repo))
        .map(|r| r.proxy.clone())
        .collect();
    match proxies.split_first() {
        Some((first @ Some(_), rest)) if rest.iter().all(|p| p == first) => first.clone(),
        _ => None,
    }
}

/// The proxy a guided scan goes through when none was given: asked when the policy in force
/// declares some (Enter: none, the host reached directly), never otherwise.
fn asked_scan_proxy(policy: &PolicyConfig) -> anyhow::Result<Option<ProxyName>> {
    let names = policy.entry_names(Section::Proxies);
    if names.is_empty() {
        return Ok(None);
    }
    let help = format!(
        "the proxy the scan goes through, Enter for none (reached directly); in force: {}",
        names.join(", ")
    );
    loop {
        let mut offered = vec![(String::new(), "none: the host reached directly".to_owned())];
        offered.extend(names.iter().map(|n| (n.clone(), n.clone())));
        match scan_proxy_answer(&names, &choose("proxy", &help, None, &offered, false)?) {
            Ok(proxy) => return Ok(proxy),
            Err(why) => println!("  {why}"),
        }
    }
}

/// An answer to the scan's proxy question: none (Enter), or one of the proxies in force.
fn scan_proxy_answer(names: &[String], answer: &str) -> Result<Option<ProxyName>, String> {
    if answer.is_empty() {
        return Ok(None);
    }
    if !names.iter().any(|name| name == answer) {
        return Err(format!(
            "{} is not a proxy in force (in force: {}).",
            clean(answer),
            names.join(", ")
        ));
    }
    answer
        .parse()
        .map(Some)
        .map_err(|e: writ_core::names::NameError| e.to_string())
}

/// What a direct scan that failed adds: how to scan through a proxy (`how`: `proxy=<name>`, or
/// `--proxy <name>` for a rescan), with the proxies in force, or declaring one first when there
/// is none (the daemon dials only a proxy the policy in force declares).
fn direct_hint(policy: &PolicyConfig, how: &str) -> String {
    let names = policy.entry_names(Section::Proxies);
    match names.is_empty() {
        true => format!(
            "If the host is reachable only through a proxy: declare it first (writ admin proxy \
             add <name>), then give {how} to this command."
        ),
        false => format!(
            "If the host is reachable only through a proxy: scan through one in force ({}) \
             with {how}.",
            names.join(", ")
        ),
    }
}

/// The key types a scan reads (the others' pins are kept by a rescan as they are).
const SCANNED_TYPES: [&str; 3] = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384"];

fn scannable(key: &str) -> bool {
    SCANNED_TYPES.contains(&key.split(' ').next().unwrap_or_default())
}

/// The same key: its type and base64, whatever follows.
fn same_key(a: &str, b: &str) -> bool {
    a.split(' ').take(2).eq(b.split(' ').take(2))
}

/// `writ admin host rescan <host>`: the pinned host scanned again (its keys changed, or to
/// see whether they did), each key shown against the pin (pinned, new, gone), compared by
/// the approver, then one signed change replacing the pin. A pinned key of a type the scan
/// doesn't read (RSA, P-521) is kept, said. Through `proxy`, or the proxy every repo on the
/// host is reached through when they share one. Only on a terminal.
pub async fn rescan(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    name: &str,
    proxy: Option<&str>,
    yes: bool,
) -> anyhow::Result<Exit> {
    let proxy: Option<ProxyName> = proxy.map(str::parse).transpose()?;
    let (host, port, entry) = host_and_port(name)?;
    if !terminal() {
        bail!(
            "rescan compares the host's keys on a terminal: without one, writ admin host set {} \
             keys=<type> <base64>,… replaces them",
            clean(&entry)
        );
    }
    connect(paths, url)
        .await?
        .run(async |session| {
            let (shown, policy) = policy_in_force(session).await?;
            let Some(pinned) = policy
                .upstream_hosts()
                .iter()
                .find(|(h, _)| h.as_str() == entry)
                .map(|(_, keys)| keys.iter().map(ToString::to_string).collect::<Vec<_>>())
            else {
                bail!(
                    "no host {} in the policy in force (writ admin host add {} scans and pins \
                     it)",
                    clean(&entry),
                    clean(&entry)
                );
            };
            let proxy = proxy.or_else(|| shared_proxy(&policy, &entry));
            let hint = direct_hint(&policy, "--proxy <name>");
            let Some(mut keys) =
                scanned(session, signer, &host, port, proxy.as_ref(), &pinned, &hint).await?
            else {
                return Ok(Exit::NotSigned);
            };
            for kept in pinned.iter().filter(|p| !scannable(p)) {
                let kind = clean(kept.split(' ').next().unwrap_or_default());
                println!(
                    "Kept the pinned {kind} key (a scan reads no {kind} key: writ admin host set \
                     {} keys-=… removes it).",
                    clean(&entry)
                );
                keys.push(kept.clone());
            }
            let unchanged = keys.len() == pinned.len()
                && keys.iter().all(|k| pinned.iter().any(|p| same_key(p, k)));
            if unchanged {
                println!("The pin already holds these keys: nothing changed.");
                return Ok(Exit::Ok);
            }
            let keys_edit = FieldEdit::parse(&format!("keys={}", keys.join(",")))
                .map_err(anyhow::Error::msg)?;
            let next = edit::edit(
                &policy,
                Section::UpstreamHosts,
                &entry,
                std::slice::from_ref(&keys_edit),
                MIN_TTL,
            )
            .map_err(|e| anyhow::anyhow!("not changed: {}", clean(&e.to_string())))?;
            let text = AdminText::try_from(next.to_yaml())?;
            let what = format!("with host {} rescanned", clean(&entry));
            Ok(sign_applied(session, signer, &shown, &text, &what, yes)
                .await?
                .exit())
        })
        .await
}

/// `writ admin repo check <repo>`: the repo's upstream reached with its credential, each step
/// printed; failed when one is.
pub async fn check(paths: &Paths, url: &str, repo: &str) -> anyhow::Result<Exit> {
    let repo: writ_core::names::RepoName = repo.parse()?;
    connect(paths, url)
        .await?
        .run(async |session| run_check(session, &repo).await)
        .await
}

async fn run_check(
    session: &crate::client::Approvals,
    repo: &writ_core::names::RepoName,
) -> anyhow::Result<Exit> {
    println!("Checking {repo}'s upstream from the daemon (nothing is pushed)…");
    let asked = Command::RepoCheck { repo: repo.clone() };
    let check = session.call(&asked, b"");
    let checked: UpstreamChecked =
        super::sync_status::while_syncing(session, repo, check).await??;
    for step in &checked.steps {
        let mark = if step.ok { "ok" } else { "failed" };
        println!("  {}: {mark}: {}", clean(&step.what), clean(&step.said));
    }
    if checked.steps.iter().all(|s| s.ok) && checked.steps.len() == 3 {
        println!("{repo} is ready: read and write access proven, its mirror synced.");
        Ok(Exit::Ok)
    } else {
        Ok(Exit::Error)
    }
}

/// What to do once a change made `section`'s entry: a new key's public half is to register,
/// a token to add.
fn next_steps(policy: &PolicyConfig, keys: &[String]) {
    for id in keys {
        let Some(key) = id.parse().ok().and_then(|id| policy.key(&id).cloned()) else {
            continue;
        };
        match key {
            Key::Upstream(UpstreamKey::Token { host, .. }) => println!(
                "Next: add a token made on {}: writ admin token {}",
                clean(host.as_str()),
                clean(id)
            ),
            Key::Upstream(UpstreamKey::Ssh { .. }) => println!(
                "Next: add {} (printed above) on the remote as a deploy key with write access \
                 (on GitHub, Codeberg or Forgejo: the repository's settings, Deploy keys).",
                clean(id)
            ),
            Key::Signing(_) => println!(
                "Next: register {} (printed above) on the account the commits show under, so a \
                 remote shows them as verified (writ prove-key proves it where asked).",
                clean(id)
            ),
        }
    }
}

/// The proxy a scan made while adding to `section` goes through: for a host, the `proxy=`
/// given (taken out of `given`: a pin has no such field); for a repo, its `proxy` field given.
fn scan_proxy(section: Section, given: &mut Vec<FieldEdit>) -> anyhow::Result<Option<ProxyName>> {
    let named = |edit: &FieldEdit| match &edit.change {
        Change::Set(value) => value.parse::<ProxyName>().map_err(anyhow::Error::from),
        _ => Err(anyhow::anyhow!(
            "proxy=<name> names the proxy to scan through"
        )),
    };
    match section {
        Section::UpstreamHosts => match given.iter().position(|g| g.field == "proxy") {
            Some(at) => named(&given.remove(at)).map(Some),
            None => Ok(None),
        },
        Section::Repos => given
            .iter()
            .find(|g| g.field == "proxy")
            .map(named)
            .transpose(),
        _ => Ok(None),
    }
}

/// `writ admin <noun> add <name> [<field>=<value>…]`: each field asked in order (the ones
/// given not asked); with no terminal nothing is asked, and every required field must be
/// given. `from` (a template) starts from that template's values.
#[allow(clippy::too_many_arguments)]
pub async fn add(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    section: Section,
    name: &str,
    given: &[String],
    from: Option<&str>,
    yes: bool,
) -> anyhow::Result<Exit> {
    let mut given = parsed(given)?;
    let interactive = terminal();
    // A host by the entry it is pinned under (`[host]:port` off port 22).
    let host = match section {
        Section::UpstreamHosts => Some(host_and_port(name)?),
        _ => None,
    };
    // The proxy its scan goes through: a host's `proxy=<name>` (not a field of the pin: taken
    // out), a repo's own `proxy` field.
    let proxy = scan_proxy(section, &mut given)?;
    let name = host.as_ref().map_or(name, |(_, _, pin)| pin.as_str());
    if section == Section::UpstreamHosts && !interactive && !given.iter().any(|g| g.field == "keys")
    {
        bail!(
            "host add scans the host on a terminal, where you compare its keys: without one, \
             give keys=<type> <base64>,…"
        );
    }
    let checked_repo = connect(paths, url)
        .await?
        .run(async |session| {
            let (shown, policy) = policy_in_force(session).await?;
            // Before anything is asked or scanned.
            if edit::current(&policy, section, name).is_some() {
                bail!(
                    "there is a {} {} already (writ admin {} edit {} changes it)",
                    section.noun(),
                    clean(name),
                    section.noun(),
                    clean(name)
                );
            }
            // The daemon's key backends: offered where a key is declared.
            let backends = match (section, interactive) {
                (Section::Keys | Section::Repos, true) => daemon_backends(session).await?,
                _ => Vec::new(),
            };
            let start: BTreeMap<&'static str, String> = match from {
                Some(other) => edit::current(&policy, Section::Templates, other)
                    .ok_or_else(|| anyhow::anyhow!("no template {} to start from", clean(other)))?,
                None => BTreeMap::new(),
            };
            let mut edits: Vec<FieldEdit> = start
                .iter()
                .filter(|(field, _)| !given.iter().any(|g| g.field == **field))
                .map(|(field, value)| FieldEdit {
                    field: (*field).to_owned(),
                    change: Change::Set(value.clone()),
                })
                .collect();
            let mut new_key: Option<NewKey> = None;
            let mut pin: Option<(String, FieldEdit)> = None;
            // The unsigned_fetch template a repo's yes makes, when the policy has none.
            let mut unsigned: Option<(String, Vec<FieldEdit>)> = None;
            if let (Some((host, port, _)), true) = (&host, interactive)
                && !given.iter().any(|g| g.field == "keys")
            {
                // Asked before the scan when none was given and the policy declares some.
                let proxy = match &proxy {
                    Some(given) => Some(given.clone()),
                    None => asked_scan_proxy(&policy)?,
                };
                let hint = direct_hint(&policy, "proxy=<name>");
                match pin_edit(session, signer, host, *port, proxy.as_ref(), &hint).await? {
                    Some(keys) => edits.push(keys),
                    None => return Ok(Err(Exit::NotSigned)),
                }
            }
            if interactive && section != Section::UpstreamHosts {
                println!(
                    "Adding {} {}: Enter keeps what [] shows, ! leaves an optional field out, \
                     none empties a list.",
                    section.noun(),
                    clean(name)
                );
                let mut asked_given = given.clone();
                if section == Section::Repos
                    && !given.iter().any(|g| g.field == "upstream_credential")
                {
                    let upstream = match given.iter().find(|g| g.field == "upstream") {
                        Some(FieldEdit {
                            change: Change::Set(url),
                            ..
                        }) => url.clone(),
                        _ => {
                            let url = ask(
                                "upstream",
                                edit::field_of(section, "upstream")
                                    .map(|f| f.help)
                                    .unwrap_or_default(),
                                None,
                            )?;
                            asked_given.push(
                                FieldEdit::parse(&format!("upstream={url}"))
                                    .map_err(anyhow::Error::msg)?,
                            );
                            url
                        }
                    };
                    // A host with no pin: scanned now, its pin in the same change.
                    if let Ok(Upstream::Ssh(ssh)) = Upstream::parse(&upstream) {
                        let wanted = ssh.known_hosts_name();
                        if !policy.upstream_hosts().keys().any(|h| h.as_str() == wanted) {
                            println!("Its host {} has no pin: it is scanned now.", clean(&wanted));
                            let (host, port, entry) = host_and_port(&wanted)?;
                            // Asked before the scan when none was given and the policy
                            // declares some: the repo's own proxy, not asked again.
                            let proxy = match &proxy {
                                Some(given) => Some(given.clone()),
                                None if policy.entry_names(Section::Proxies).is_empty() => None,
                                None => {
                                    let answered = asked_scan_proxy(&policy)?;
                                    asked_given.push(FieldEdit {
                                        field: "proxy".to_owned(),
                                        change: match &answered {
                                            Some(name) => Change::Set(name.to_string()),
                                            None => Change::Unset,
                                        },
                                    });
                                    answered
                                }
                            };
                            let hint = direct_hint(&policy, "proxy=<name>");
                            match pin_edit(session, signer, &host, port, proxy.as_ref(), &hint)
                                .await?
                            {
                                Some(keys) => pin = Some((entry, keys)),
                                None => return Ok(Err(Exit::NotSigned)),
                            }
                        }
                    }
                    let (repo_edit, key) = credential(&policy, name, &upstream, &backends)?;
                    asked_given.push(repo_edit);
                    new_key = key;
                }
                let more = asked(&policy, section, &asked_given, &start, true, &backends)?;
                edits.extend(asked_given);
                edits.extend(more);
                if section == Section::Repos {
                    unsigned = asked_unsigned_fetch(&policy, &mut edits)?;
                }
            } else {
                edits.extend(given.clone());
                let missing = edit::missing(section, &edits);
                if !missing.is_empty() {
                    bail!(
                        "add asks nothing without a terminal: give every required field \
                         (missing: {})",
                        missing.join(", ")
                    );
                }
            }
            let mut next = policy.clone();
            let mut made = Vec::new();
            if let Some((entry, keys)) = &pin {
                next = edit::add(
                    &next,
                    Section::UpstreamHosts,
                    entry,
                    std::slice::from_ref(keys),
                    MIN_TTL,
                )
                .map_err(|e| anyhow::anyhow!("not added: {}", clean(&e.to_string())))?;
            }
            if let Some((id, key)) = &new_key {
                next = edit::add(&next, Section::Keys, id, key, MIN_TTL)
                    .map_err(|e| anyhow::anyhow!("not added: {}", clean(&e.to_string())))?;
                made.push(id.clone());
            }
            if let Some((template, fields)) = &unsigned {
                next = edit::add(&next, Section::Templates, template, fields, MIN_TTL)
                    .map_err(|e| anyhow::anyhow!("not added: {}", clean(&e.to_string())))?;
            }
            let next = edit::add(&next, section, name, &edits, MIN_TTL)
                .map_err(|e| anyhow::anyhow!("not added: {}", clean(&e.to_string())))?;
            if section == Section::Keys {
                made.push(name.to_owned());
            }
            let text = AdminText::try_from(next.to_yaml())?;
            let what = match &unsigned {
                Some((template, _)) => format!(
                    "with {} {} and template {} added",
                    section.noun(),
                    clean(name),
                    clean(template)
                ),
                None => format!("with {} {} added", section.noun(), clean(name)),
            };
            match sign_applied(session, signer, &shown, &text, &what, yes).await? {
                Signing::Applied => {}
                other => return Ok(Err(other.exit())),
            }
            next_steps(&next, &made);
            Ok(Ok(section == Section::Repos))
        })
        .await?;
    let checked_repo = match checked_repo {
        Ok(checked) => checked,
        Err(exit) => return Ok(exit),
    };
    // A repo added: its upstream checked once its credential is registered.
    if checked_repo {
        let repo: writ_core::names::RepoName = name.parse()?;
        if !interactive {
            println!("Once its credential is registered: writ admin repo check {repo}");
            return Ok(Exit::Ok);
        }
        if !prompt::pause("Press Enter once its credential is registered, to check its upstream:")?
        {
            println!("Not checked: writ admin repo check {repo} once it is registered.");
            return Ok(Exit::Ok);
        }
        return connect(paths, url)
            .await?
            .run(async |session| run_check(session, &repo).await)
            .await;
    }
    Ok(Exit::Ok)
}

/// The template a repo's `unsigned_fetch` yes makes when the policy has none.
const UNSIGNED_FETCH_TEMPLATE: &str = "fetch_unsigned";

/// The fields of the template [`asked_unsigned_fetch`] makes: fetch only, 15 minutes.
const UNSIGNED_FETCH_FIELDS: [&str; 7] = [
    "unsigned_fetch=true",
    "operations=fetch",
    "max_ttl=15m",
    "max_signatures=0",
    "max_pushes=0",
    "max_ops_per_minute=20",
    "max_push_size=0",
];

/// The templates a repo names once `edits` are applied to a new one.
fn named_templates(edits: &[FieldEdit]) -> Vec<String> {
    let mut named: Vec<String> = Vec::new();
    for one in edits.iter().filter(|e| e.field == "templates") {
        match &one.change {
            Change::Set(list) => {
                named = list
                    .split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            Change::Add(t) => named.push(t.trim().to_owned()),
            Change::Remove(t) => named.retain(|n| n != t.trim()),
            Change::Unset => named.clear(),
        }
    }
    named
}

/// The `unsigned_fetch` template a repo would name: the policy's own (none made), or a new
/// one under a free name, with its fields.
fn unsigned_fetch_template(
    policy: &PolicyConfig,
) -> anyhow::Result<(String, Option<Vec<FieldEdit>>)> {
    if let Some((name, _)) = policy.templates().iter().find(|(_, t)| t.unsigned_fetch) {
        return Ok((name.to_string(), None));
    }
    let taken = policy.entry_names(Section::Templates);
    let name = (1..=10_000u32)
        .map(|n| match n {
            1 => UNSIGNED_FETCH_TEMPLATE.to_owned(),
            n => format!("{UNSIGNED_FETCH_TEMPLATE}_{n}"),
        })
        .find(|candidate| !taken.contains(candidate))
        .ok_or_else(|| anyhow::anyhow!("no free template name"))?;
    let fields = UNSIGNED_FETCH_FIELDS
        .iter()
        .map(|arg| FieldEdit::parse(arg).map_err(anyhow::Error::msg))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok((name, Some(fields)))
}

/// A repo being added (on a terminal): whether agents may fetch it with no signature, unless
/// a template it names already lets them. On yes, the policy's `unsigned_fetch` template is
/// added to its templates, and returned with its fields when it is to be made (M7.9.7).
fn asked_unsigned_fetch(
    policy: &PolicyConfig,
    edits: &mut Vec<FieldEdit>,
) -> anyhow::Result<Option<(String, Vec<FieldEdit>)>> {
    let named = named_templates(edits);
    let lets_already = named.iter().any(|name| {
        name.parse()
            .ok()
            .and_then(|name| policy.template(&name))
            .is_some_and(|t| t.unsigned_fetch)
    });
    if lets_already {
        return Ok(None);
    }
    let answer = choose(
        "unsigned fetch",
        "let agents fetch this repo with no signature from you, to plan before their ticket \
         (fetch only: no commit, no push)",
        Some("no"),
        &[("yes".to_owned(), "yes".to_owned())],
        false,
    )?;
    if !matches!(answer.trim(), "yes" | "y") {
        return Ok(None);
    }
    let (name, fields) = unsigned_fetch_template(policy)?;
    edits.push(FieldEdit {
        field: "templates".to_owned(),
        change: Change::Add(name.clone()),
    });
    Ok(fields.map(|fields| (name, fields)))
}

/// `writ admin <noun> edit <name>`: each field asked, Enter keeping its current value; only
/// on a terminal (`set` changes fields without one).
pub async fn edit_entry(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    section: Section,
    name: &str,
    yes: bool,
) -> anyhow::Result<Exit> {
    if !terminal() {
        bail!(
            "edit asks each field on a terminal: without one, writ admin {} set {} \
             <field>=<value> changes the fields named",
            section.noun(),
            clean(name)
        );
    }
    connect(paths, url)
        .await?
        .run(async |session| {
            let (shown, policy) = policy_in_force(session).await?;
            let Some(current) = edit::current(&policy, section, name) else {
                bail!(
                    "no {} {} in the policy in force (writ admin {} list)",
                    section.noun(),
                    clean(name),
                    section.noun()
                );
            };
            println!(
                "Editing {} {}: Enter keeps the value [] shows, ! leaves an optional field out, \
                 none empties a list.",
                section.noun(),
                clean(name)
            );
            let edits = asked(&policy, section, &[], &current, false, &[])?;
            if edits.is_empty() {
                println!("Nothing changed.");
                return Ok(Exit::Ok);
            }
            let next = edit::edit(&policy, section, name, &edits, MIN_TTL)
                .map_err(|e| anyhow::anyhow!("not changed: {}", clean(&e.to_string())))?;
            let text = AdminText::try_from(next.to_yaml())?;
            let typed: Vec<String> = edits.iter().map(|e| clean(&e.to_string())).collect();
            let what = format!(
                "with {} {} edited: {}",
                section.noun(),
                clean(name),
                typed.join(" ")
            );
            Ok(sign_applied(session, signer, &shown, &text, &what, yes)
                .await?
                .exit())
        })
        .await
}

/// The id a rotated key gets when none is given: `<id>-2`, or the next number after a
/// trailing `-<n>`, the first the policy doesn't declare.
pub fn next_id(policy: &PolicyConfig, id: &str) -> String {
    let (stem, number) = match id.rsplit_once('-') {
        Some((stem, digits))
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) =>
        {
            (stem.to_owned(), digits.parse::<u64>().unwrap_or(1))
        }
        _ => (id.to_owned(), 1),
    };
    let mut n = number.saturating_add(1);
    loop {
        let candidate = format!("{stem}-{n}");
        let taken = candidate
            .parse()
            .ok()
            .is_some_and(|key| policy.key(&key).is_some());
        if !taken {
            return candidate;
        }
        n = n.saturating_add(1);
    }
}

/// `writ admin key rotate <id> [--backend <name>] [--name <new>]`: a new key declared like the
/// old one, on the backend named (the old one's by default: moving a key between software and
/// the Secure Enclave is a rotation) (one signed change: its public half printed, to
/// register); once it is registered, every repo, proxy and template that used the old one
/// switched to it (a second signed change); then, if nothing uses the old one any more, it is
/// offered for removal. `--yes` answers the question between the two, on a terminal or not
/// (the old key is then left declared, unused). The closing words come from what still uses
/// the old key, never assumed.
pub async fn rotate(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    id: &str,
    name: Option<&str>,
    backend: Option<&str>,
    yes: bool,
) -> anyhow::Result<Exit> {
    let interactive = terminal();
    if !interactive && !yes {
        bail!("key rotate asks before switching to the new key: without a terminal, give --yes");
    }
    let session = connect(paths, url).await?;
    let fresh = session
        .run(async |session| {
            let (shown, policy) = policy_in_force(session).await?;
            let Some(values) = edit::current(&policy, Section::Keys, id) else {
                bail!(
                    "no key {} in the policy in force (writ admin key list)",
                    clean(id)
                );
            };
            let fresh = match name {
                Some(name) => name.to_owned(),
                None => next_id(&policy, id),
            };
            let mut edits: Vec<FieldEdit> = values
                .iter()
                .filter(|(field, _)| backend.is_none() || **field != "backend")
                .map(|(field, value)| FieldEdit {
                    field: (*field).to_owned(),
                    change: Change::Set(value.clone()),
                })
                .collect();
            if let Some(backend) = backend {
                let backends = daemon_backends(session).await?;
                let algorithm = values.get("algorithm").map(String::as_str);
                check_backend(&backends, backend, algorithm, id)?;
                edits.push(FieldEdit {
                    field: "backend".to_owned(),
                    change: Change::Set(backend.to_owned()),
                });
            }
            let next = edit::add(&policy, Section::Keys, &fresh, &edits, MIN_TTL)
                .map_err(|e| anyhow::anyhow!("not rotated: {}", clean(&e.to_string())))?;
            let text = AdminText::try_from(next.to_yaml())?;
            let what = match backend {
                Some(backend) => format!(
                    "with key {} declared like {}, on backend {}",
                    clean(&fresh),
                    clean(id),
                    clean(backend)
                ),
                None => format!("with key {} declared like {}", clean(&fresh), clean(id)),
            };
            match sign_applied(session, signer, &shown, &text, &what, yes).await? {
                Signing::Applied => {}
                other => return Ok(Err(other.exit())),
            }
            next_steps(&next, std::slice::from_ref(&fresh));
            Ok(Ok(fresh))
        })
        .await?;
    let fresh = match fresh {
        Ok(fresh) => fresh,
        Err(exit) => return Ok(exit),
    };
    if interactive && !yes {
        let message = format!(
            "Once {} is registered (or added), press Enter to switch what uses {} to it \
             (Esc stops here; {} stays in use):",
            clean(&fresh),
            clean(id),
            clean(id)
        );
        if !prompt::pause(&message)? {
            println!("Stopped: {} stays in use.", clean(id));
            return Ok(Exit::NotSigned);
        }
    }
    let old: writ_core::names::KeyId = id.parse()?;
    let session = connect(paths, url).await?;
    let (exit, still) = session
        .run(async |session| {
            let (shown, policy) = policy_in_force(session).await?;
            let next = switched(&policy, &old, &fresh)?;
            if !policy.key_users(&old).templates.is_empty() {
                println!(
                    "The leases signing with {} stop fitting their template once it switches: \
                     their agents amend them. Keep {}'s public key registered on the remote, \
                     or the commits it signed stop showing as verified.",
                    clean(id),
                    clean(id)
                );
            }
            let text = AdminText::try_from(next.to_yaml())?;
            let what = format!("with what used {} switched to {}", clean(id), clean(&fresh));
            let signing = sign_applied(session, signer, &shown, &text, &what, yes).await?;
            // What uses the old key now: the policy signed, or the one still in force.
            let still = match signing {
                Signing::Applied | Signing::Unchanged => next.key_users(&old),
                Signing::NotSigned => policy.key_users(&old),
            };
            Ok((signing.exit(), still))
        })
        .await?;
    if !still.is_empty() {
        println!("{}", still_used(id, &fresh, &still));
        return Ok(exit);
    }
    if interactive
        && !yes
        && confirm(&format!(
            "Remove {} now? It is deleted for good.",
            clean(id)
        ))?
    {
        return super::manage::remove(paths, url, signer, Section::Keys, id, false).await;
    }
    println!(
        "{} stays declared, unused: writ admin key remove {} deletes it.",
        clean(id),
        clean(id)
    );
    Ok(exit)
}

/// `policy` with every repo, proxy and template that uses the key `old` switched to `fresh`
/// (the review after M7.6, U-3: the proxies were forgotten, a proxy's password left on the old
/// token and the new one used by nothing).
fn switched(
    policy: &PolicyConfig,
    old: &writ_core::names::KeyId,
    fresh: &str,
) -> anyhow::Result<PolicyConfig> {
    let users = policy.key_users(old);
    let mut next = policy.clone();
    let mut switch = |section: Section, name: &str, field: &str| -> anyhow::Result<()> {
        let set = FieldEdit::parse(&format!("{field}={fresh}")).map_err(anyhow::Error::msg)?;
        next = edit::edit(&next, section, name, &[set], MIN_TTL)
            .map_err(|e| anyhow::anyhow!("not switched: {}", clean(&e.to_string())))?;
        Ok(())
    };
    for repo in &users.repos {
        switch(Section::Repos, repo.as_str(), "upstream_credential")?;
    }
    for proxy in &users.proxies {
        switch(Section::Proxies, proxy.as_str(), "credential")?;
    }
    for template in &users.templates {
        switch(Section::Templates, template.as_str(), "signing_key")?;
    }
    Ok(next)
}

/// The closing words of a rotation the old key `id` is still used after: by whom, and what to
/// do.
fn still_used(id: &str, fresh: &str, users: &writ_core::config::KeyUsers) -> String {
    format!(
        "{} is still used by {}: point them at {} (writ admin <noun> set), then writ admin \
         key remove {} deletes it.",
        clean(id),
        clean(&users.to_string()),
        clean(fresh),
        clean(id)
    )
}

/// Refuses `--backend <backend>` for the key `id` of `algorithm` unless the daemon has it and
/// it makes keys of that algorithm (a token, with no algorithm, lives on no device): what the
/// daemon would refuse after the signature, said before it is asked for.
fn check_backend(
    backends: &[BackendShown],
    backend: &str,
    algorithm: Option<&str>,
    id: &str,
) -> anyhow::Result<()> {
    let Some(shown) = backends.iter().find(|b| b.name == backend) else {
        let names: Vec<String> = backends.iter().map(|b| clean(&b.name)).collect();
        bail!(
            "the daemon has no backend {} (it has: {})",
            clean(backend),
            names.join(", ")
        );
    };
    let Some(algorithm) = algorithm else {
        bail!(
            "{} is a token: it is sealed in the keystore, on no backend",
            clean(id)
        );
    };
    if !shown.algorithms.iter().any(|a| a == algorithm) {
        bail!(
            "{} makes {} keys only: {} is {} (declare a new key of one of these with writ \
             admin key add, then point what uses {id} at it)",
            clean(backend),
            shown
                .algorithms
                .iter()
                .map(|a| clean(a))
                .collect::<Vec<_>>()
                .join(", "),
            clean(id),
            clean(algorithm)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(templates: &str, repo_templates: &str) -> PolicyConfig {
        PolicyConfig::from_yaml(&format!(
            "format: 2\nkeys:\n  up: {{ use: upstream, kind: token, host: example.org }}\n\
             repos:\n  r:\n    upstream: https://example.org/r.git\n    \
             upstream_credential: up\n    templates: [{repo_templates}]\n\
             templates:\n  feature:\n    operations: [fetch]\n    max_ttl: 1h\n    \
             max_signatures: 0\n    max_pushes: 0\n    max_ops_per_minute: 1\n    \
             max_push_size: 0\n{templates}"
        ))
        .unwrap()
    }

    /// M7.9.7: a yes adds the policy's unsigned_fetch template to the repo, or makes one under
    /// a free name; the template made is one the policy reads, fetch only.
    #[test]
    fn a_yes_names_the_unsigned_fetch_template_or_makes_one() {
        let edits = |args: &[&str]| -> Vec<FieldEdit> {
            args.iter().map(|a| FieldEdit::parse(a).unwrap()).collect()
        };
        assert_eq!(
            named_templates(&edits(&["templates=a, b", "templates+=c", "templates-=a"])),
            ["b", "c"]
        );
        assert!(named_templates(&edits(&["upstream=x"])).is_empty());
        // None in the policy: made as fetch_unsigned, read back as unsigned fetch only.
        let plain = policy("", "feature");
        let (name, fields) = unsigned_fetch_template(&plain).unwrap();
        assert_eq!(name, "fetch_unsigned");
        let fields = fields.unwrap();
        let made = edit::add(&plain, Section::Templates, &name, &fields, MIN_TTL).unwrap();
        let template = made.template(&name.parse().unwrap()).unwrap();
        assert!(template.unsigned_fetch);
        assert_eq!(
            template
                .operations
                .iter()
                .map(|o| o.to_string())
                .collect::<Vec<_>>(),
            ["fetch"]
        );
        // The name taken by another template: the next free one.
        let taken = policy(
            "  fetch_unsigned:\n    operations: [fetch]\n    max_ttl: 1h\n    \
             max_signatures: 0\n    max_pushes: 0\n    max_ops_per_minute: 1\n    \
             max_push_size: 0\n",
            "feature",
        );
        assert_eq!(
            unsigned_fetch_template(&taken).unwrap().0,
            "fetch_unsigned_2"
        );
        // One in the policy: named, nothing made.
        let has = policy(
            "  open:\n    unsigned_fetch: true\n    operations: [fetch]\n    max_ttl: 15m\n    \
             max_signatures: 0\n    max_pushes: 0\n    max_ops_per_minute: 1\n    \
             max_push_size: 0\n",
            "feature",
        );
        assert_eq!(
            unsigned_fetch_template(&has).unwrap(),
            ("open".to_owned(), None)
        );
    }

    /// The review after M7.6 (U-7): what the approver compares is computed here from the keys
    /// that get pinned, for the host asked; a reply that says otherwise is refused.
    #[test]
    fn a_scan_is_shown_by_fingerprints_of_the_keys_pinned_for_the_host_asked() {
        let key = writ_crypto::keys::generate(writ_crypto::keys::KeyKind::Ed25519).unwrap();
        let line = key.public_key().to_openssh().unwrap();
        let line: String = line.split(' ').take(2).collect::<Vec<_>>().join(" ");
        let fingerprint = writ_crypto::keys::fingerprint(key.public_key());
        let other = writ_crypto::keys::generate(writ_crypto::keys::KeyKind::Ed25519).unwrap();
        let wrong = writ_crypto::keys::fingerprint(other.public_key());
        let host = HostName::try_from("git.example".to_owned()).unwrap();
        let reply = |host: &str, fingerprint: &str| Scanned {
            host: host.to_owned(),
            keys: vec![writ_proto::ScannedKey {
                key: line.clone(),
                fingerprint: fingerprint.to_owned(),
            }],
        };
        let checked = checked_scan(&host, 2222, reply("[git.example]:2222", &fingerprint)).unwrap();
        assert_eq!(checked.host, "[git.example]:2222");
        assert_eq!(checked.keys[0].fingerprint, fingerprint);
        assert_eq!(
            crate::error_of(checked_scan(
                &host,
                2222,
                reply("git.example", &fingerprint)
            )),
            "asked to scan [git.example]:2222, the daemon answered for git.example: nothing pinned"
        );
        assert_eq!(
            crate::error_of(checked_scan(&host, 22, reply("git.example", &wrong))),
            format!(
                "the scan names a key {wrong} whose fingerprint is {fingerprint}: nothing pinned"
            )
        );
        let mut unreadable = reply("git.example", &fingerprint);
        unreadable.keys[0].key = "ssh-ed25519 !!!".to_owned();
        assert_eq!(
            crate::error_of(checked_scan(&host, 22, unreadable)),
            "the scan sent a key that doesn't read (ssh-ed25519 !!!): nothing pinned"
        );
    }

    #[test]
    fn a_backend_is_checked_against_what_the_daemon_has_and_makes() {
        let backends = [
            BackendShown {
                name: "software".to_owned(),
                algorithms: vec!["ed25519".to_owned(), "p256".to_owned()],
            },
            BackendShown {
                name: "se-cryptokit".to_owned(),
                algorithms: vec!["p256".to_owned()],
            },
        ];
        check_backend(&backends, "se-cryptokit", Some("p256"), "k").unwrap();
        check_backend(&backends, "software", Some("ed25519"), "k").unwrap();
        for (backend, algorithm, why) in [
            (
                "yubikey",
                Some("p256"),
                "the daemon has no backend yubikey (it has: software, se-cryptokit)",
            ),
            (
                "se-cryptokit",
                Some("ed25519"),
                "se-cryptokit makes p256 keys only: k is ed25519",
            ),
            (
                "se-cryptokit",
                None,
                "k is a token: it is sealed in the keystore, on no backend",
            ),
        ] {
            let error = check_backend(&backends, backend, algorithm, "k")
                .unwrap_err()
                .to_string();
            assert!(error.starts_with(why), "{error}");
        }
        // What the daemon sends is shown escaped.
        let hostile = [BackendShown {
            name: "x\u{1b}[2J".to_owned(),
            algorithms: vec![],
        }];
        let error = check_backend(&hostile, "y", Some("p256"), "k")
            .unwrap_err()
            .to_string();
        assert!(!error.contains('\u{1b}'), "{error:?}");
    }

    /// The review after M7.6 (U-3): rotating a proxy's password switched nothing (proxies
    /// were forgotten), then said the old key was unused. Every repo, proxy and template that
    /// used the old key is switched, and what still uses it is said from the policy.
    #[test]
    fn a_rotation_switches_every_repo_proxy_and_template_that_used_the_key() {
        let policy = PolicyConfig::from_yaml(
            "format: 2\nkeys:\n  proxy-pass: { use: upstream, kind: token, host: \"127.0.0.1\" }\n  \
             proxy-pass-2: { use: upstream, kind: token, host: \"127.0.0.1\" }\n  \
             token-01: { use: upstream, kind: token, host: localhost }\n  \
             token-01-2: { use: upstream, kind: token, host: localhost }\n\
             proxies:\n  p: { url: \"http://u@127.0.0.1:3128\", credential: proxy-pass }\n  \
             q: { url: \"http://u@127.0.0.1:3129\", credential: proxy-pass }\n\
             repos:\n  demo:\n    upstream: https://localhost/demo.git\n    \
             upstream_credential: token-01\n    proxy: p\n    templates: [t]\n\
             templates:\n  t:\n    operations: [fetch]\n    branches: [\"*\"]\n    \
             committer_emails: [\"a@b\"]\n    max_ttl: 1h\n    max_signatures: 1\n    \
             max_pushes: 1\n    max_ops_per_minute: 10\n    max_push_size: 1MB\n",
        )
        .unwrap();
        let old: writ_core::names::KeyId = "proxy-pass".parse().unwrap();
        let fresh: writ_core::names::KeyId = "proxy-pass-2".parse().unwrap();
        assert_eq!(policy.key_users(&old).proxies.len(), 2);
        let next = switched(&policy, &old, fresh.as_str()).unwrap();
        assert!(next.key_users(&old).is_empty(), "{}", next.key_users(&old));
        assert_eq!(
            next.key_users(&fresh).to_string(),
            "proxies p, q",
            "both proxies' password is the new token"
        );
        // A repo's credential the same way, the proxies untouched.
        let token: writ_core::names::KeyId = "token-01".parse().unwrap();
        let next = switched(&policy, &token, "token-01-2").unwrap();
        assert!(next.key_users(&token).is_empty());
        assert_eq!(next.key_users(&old).to_string(), "proxies p, q");
        // Still used (the switch not signed): said, with whom.
        assert_eq!(
            still_used("proxy-pass", "proxy-pass-2", &policy.key_users(&old)),
            "proxy-pass is still used by proxies p, q: point them at proxy-pass-2 (writ admin \
             <noun> set), then writ admin key remove proxy-pass deletes it."
        );
    }

    #[test]
    fn a_rotated_key_takes_the_next_free_id() {
        let policy = PolicyConfig::from_yaml(
            "format: 2\nkeys:\n  forgejo-home: { use: upstream, kind: ssh, algorithm: ed25519 }\n  \
             forgejo-home-2: { use: upstream, kind: ssh, algorithm: ed25519 }\n  \
             agent-01: { use: signing, format: ssh, algorithm: ed25519 }\nrepos: {}\n\
             templates: {}\n",
        )
        .unwrap();
        assert_eq!(next_id(&policy, "forgejo-home"), "forgejo-home-3");
        assert_eq!(next_id(&policy, "agent-01"), "agent-2");
        assert_eq!(next_id(&policy, "token"), "token-2");
    }

    /// Found on a real setup: `repo add` scanned an unpinned host before asking the repo's
    /// proxy, so a remote reachable only through one failed at the scan. The question comes
    /// first; an answer is a proxy in force or none, never another name.
    #[test]
    fn a_scan_s_proxy_is_one_in_force_or_none() {
        let names = vec!["socks".to_owned(), "office".to_owned()];
        assert_eq!(scan_proxy_answer(&names, ""), Ok(None));
        assert_eq!(
            scan_proxy_answer(&names, "office"),
            Ok(Some("office".parse().unwrap()))
        );
        assert_eq!(
            scan_proxy_answer(&names, "tor"),
            Err("tor is not a proxy in force (in force: socks, office).".to_owned())
        );
        // Not a prefix, not another case.
        for typed in ["sock", "Socks"] {
            assert_eq!(
                scan_proxy_answer(&names, typed),
                Err(format!(
                    "{typed} is not a proxy in force (in force: socks, office)."
                ))
            );
        }
        // What was typed is shown escaped.
        let error = scan_proxy_answer(&names, "x\u{1b}[2J").unwrap_err();
        assert!(!error.contains('\u{1b}'), "{error:?}");
    }

    #[test]
    fn a_failed_direct_scan_says_how_to_go_through_a_proxy() {
        let none =
            PolicyConfig::from_yaml("format: 2\nkeys: {}\nrepos: {}\ntemplates: {}\n").unwrap();
        assert_eq!(
            direct_hint(&none, "proxy=<name>"),
            "If the host is reachable only through a proxy: declare it first (writ admin proxy \
             add <name>), then give proxy=<name> to this command."
        );
        let some = PolicyConfig::from_yaml(
            "format: 2\nkeys: {}\nrepos: {}\ntemplates: {}\nproxies:\n  \
             socks: { url: \"socks5://127.0.0.1:1080\" }\n  \
             office: { url: \"http://127.0.0.1:3128\" }\n",
        )
        .unwrap();
        let hint = direct_hint(&some, "--proxy <name>");
        assert!(
            hint.ends_with("scan through one in force (office, socks) with --proxy <name>."),
            "{hint}"
        );
    }

    /// A key's backend is asked before its algorithm, which is then one the backend makes
    /// (the Secure Enclave makes p256 only): Enter takes ed25519 when it can, else the first.
    #[test]
    fn a_key_s_algorithm_is_asked_among_what_its_backend_makes() {
        let names: Vec<&str> = edit::fields(Section::Keys).iter().map(|f| f.name).collect();
        let at = |name: &str| names.iter().position(|n| *n == name).unwrap();
        assert!(at("backend") < at("algorithm"), "{names:?}");
        let backends = [
            BackendShown {
                name: "software".to_owned(),
                algorithms: vec!["p256".to_owned(), "ed25519".to_owned()],
            },
            BackendShown {
                name: "se-cryptokit".to_owned(),
                algorithms: vec!["p256".to_owned()],
            },
        ];
        let with = |backend: Option<&str>| -> BTreeMap<String, String> {
            backend
                .map(|b| ("backend".to_owned(), b.to_owned()))
                .into_iter()
                .collect()
        };
        let software = backend_makes(&with(None), &backends).unwrap();
        assert_eq!(software.name, "software");
        assert_eq!(default_algorithm(software), Some("ed25519"));
        let se = backend_makes(&with(Some("se-cryptokit")), &backends).unwrap();
        assert_eq!(default_algorithm(se), Some("p256"));
        assert_eq!(unmade(se, "p256"), None);
        assert_eq!(unmade(se, ""), None);
        assert_eq!(
            unmade(se, "ed25519"),
            Some("se-cryptokit makes p256 keys only.".to_owned())
        );
        // A backend the daemon didn't name: nothing assumed of it (the daemon refuses it).
        assert!(backend_makes(&with(Some("yubikey")), &backends).is_none());
        let nothing = BackendShown {
            name: "empty".to_owned(),
            algorithms: vec![],
        };
        assert_eq!(default_algorithm(&nothing), None);
    }

    #[test]
    fn only_the_fields_the_entry_needs_are_asked() {
        let values = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        let fetch = values(&[("operations", "fetch")]);
        assert!(!relevant(Section::Templates, "branches", &fetch, &[]));
        assert!(!relevant(Section::Templates, "signing_key", &fetch, &[]));
        assert!(relevant(Section::Templates, "max_ttl", &fetch, &[]));
        let signs = values(&[("operations", "fetch, commit_sign")]);
        assert!(relevant(Section::Templates, "signing_key", &signs, &[]));
        assert!(!relevant(Section::Templates, "force_push", &signs, &[]));
        let token = values(&[("use", "upstream"), ("kind", "token")]);
        assert!(relevant(Section::Keys, "host", &token, &[]));
        assert!(!relevant(Section::Keys, "algorithm", &token, &[]));
        let pgp = values(&[("use", "signing"), ("format", "openpgp")]);
        assert!(
            relevant(Section::Keys, "uids", &pgp, &[])
                && !relevant(Section::Keys, "kind", &pgp, &[])
        );
        // A key's backend: asked once the daemon has a choice, never for a token.
        let backend = |name: &str, algorithms: &[&str]| BackendShown {
            name: name.to_owned(),
            algorithms: algorithms.iter().map(|a| (*a).to_owned()).collect(),
        };
        let both = [
            backend("software", &["ed25519", "p256"]),
            backend("se-cryptokit", &["p256"]),
        ];
        let ssh = values(&[("use", "upstream"), ("kind", "ssh")]);
        let signing = values(&[("use", "signing")]);
        assert!(relevant(Section::Keys, "backend", &ssh, &both));
        assert!(relevant(Section::Keys, "backend", &signing, &both));
        assert!(!relevant(Section::Keys, "backend", &token, &both));
        assert!(!relevant(Section::Keys, "backend", &signing, &both[..1]));
        let notes = values(&[("ticket_link", "notes")]);
        assert!(relevant(Section::Repos, "notes_ref", &notes, &[]));
        assert!(!relevant(Section::Repos, "notes_ref", &values(&[]), &[]));
    }

    /// M7.9.5: a select offers only values the policy takes. Each fixed option of a field is
    /// one the core's own help for that field names, so the two can't drift apart.
    #[test]
    fn every_fixed_option_is_one_the_field_s_help_names() {
        let policy =
            PolicyConfig::from_yaml("format: 2\nkeys: {}\nrepos: {}\ntemplates: {}\n").unwrap();
        for section in [
            Section::Keys,
            Section::Repos,
            Section::Templates,
            Section::Proxies,
            Section::Recipients,
            Section::UpstreamHosts,
        ] {
            for field in edit::fields(section) {
                let Some((values, _)) =
                    options(&policy, section, field.name, field.kind, None, &[])
                else {
                    continue;
                };
                for (value, _) in values {
                    assert!(
                        field.help.contains(&value) || field.kind == FieldKind::Flag,
                        "{}.{} offers {value}, which its help doesn't name: {}",
                        section.noun(),
                        field.name,
                        field.help
                    );
                }
            }
        }
    }

    #[test]
    fn a_multi_select_answers_as_the_plain_prompt_did() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            many_answer(&s(&["fetch", "push"]), &s(&["push", "fetch"])),
            ""
        );
        assert_eq!(many_answer(&s(&["fetch"]), &s(&[])), "none");
        assert_eq!(
            many_answer(&s(&["fetch"]), &s(&["fetch", "push"])),
            "fetch,push"
        );
        assert_eq!(many_answer(&s(&[]), &s(&[])), "");
    }
}
