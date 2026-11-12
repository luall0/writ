//! The guided flows of `writ admin <noun>`: `add` and `edit` ask each field in order (its
//! bounds and default, or its current value), the ones given on the command line not asked;
//! `template add --from` starts from another template; `key rotate` declares a new key like
//! the old one, then switches what used it. Each change is one signed change, built as `set`
//! builds one ([`writ_core::config::edit`]) and checked by the daemon whole.
//!
//! The prompts are a convenience: nothing typed here is trusted by the daemon.

use std::collections::BTreeMap;
use std::io::{IsTerminal as _, Write as _};

use anyhow::bail;
use writ_core::authority::AdminText;
use writ_core::canonical::Canonical;
use writ_core::config::edit::{self, Change, FieldEdit, FieldKind};
use writ_core::config::hosts::HostName;
use writ_core::config::{Key, PolicyConfig, Section, UpstreamHost, UpstreamKey};
use writ_core::names::ProxyName;
use writ_core::signed::Scan;
use writ_core::upstream::Upstream;
use writ_proto::{Command, ScanNonce, ScanRequest, Scanned, UpstreamChecked};

use super::admin::sign_applied;
use super::manage::policy_in_force;
use super::{Signer, connect, read_line};
use crate::display::clean;
use crate::{Exit, Paths};

/// The lowest `min_ttl` any daemon takes: the daemon checks against its own.
const MIN_TTL: writ_core::units::Duration = writ_core::fit::MIN_TTL_FLOOR;

/// Whether stdin is a terminal: only then are questions asked.
fn terminal() -> bool {
    std::io::stdin().is_terminal()
}

/// Asks one line, showing `label`, `help` and what Enter keeps (`keeps`).
fn ask(label: &str, help: &str, keeps: Option<&str>) -> anyhow::Result<String> {
    match keeps {
        Some(keeps) => print!("{label} ({help}) [{}]: ", clean(keeps)),
        None => print!("{label} ({help}): "),
    }
    std::io::stdout().flush()?;
    read_line()
}

/// Whether the field `name` of `section` is asked, given the answers so far: only the fields
/// the entry's other values need (a template's branches with commit_sign or push, a key's
/// fields for its use and kind, a repo's notes ref with notes).
fn relevant(section: Section, name: &str, values: &BTreeMap<String, String>) -> bool {
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
                // One backend today: asked only once there is a choice.
                _ => false,
            }
        }
        Section::Templates => {
            let signs = has("operations", "commit_sign");
            let pushes = has("operations", "push");
            match name {
                "branches" => signs || pushes,
                "push_modes" | "force_push" => pushes,
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
            "direct_ssh.hosts" | "direct_ssh.allow_account_wide" => has("push_modes", "direct_ssh"),
            _ => true,
        },
        // A password goes with a user: asked only when the URL names one.
        Section::Proxies => name != "credential" || value("url").contains('@'),
        Section::UpstreamHosts => true,
    }
}

/// What the prompt for the field `name` adds to its help: the names it may take from the
/// policy in force (templates, keys of the right use).
fn choices(policy: &PolicyConfig, section: Section, name: &str) -> Option<String> {
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
        (Section::Templates, "signing_key") => join(
            policy
                .signing_keys()
                .map(|(id, _)| id.to_string())
                .collect(),
        ),
        _ => None,
    }
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
        if given.iter().any(|g| g.field == field.name) || !relevant(section, field.name, &values) {
            continue;
        }
        // What an existing key is never changes: not asked in an edit.
        if field.fixed && !adding {
            continue;
        }
        let help = match choices(policy, section, field.name) {
            Some(names) => format!("{}; in force: {names}", field.help),
            None => field.help.to_owned(),
        };
        let keeps = current
            .get(field.name)
            .map(String::as_str)
            .or(field.default);
        loop {
            let answer = ask(field.name, &help, keeps)?;
            let change = match answer.as_str() {
                "" if current.contains_key(field.name) => None,
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
        let answer = ask("upstream_credential", &help, Some("new"))?;
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
                let algorithm = ask(
                    "algorithm",
                    "ed25519, p256, p384, rsa3072 or rsa4096 (some remotes take RSA only)",
                    Some("ed25519"),
                )?;
                let algorithm = if algorithm.is_empty() {
                    "ed25519".to_owned()
                } else {
                    algorithm
                };
                key.push(FieldEdit::parse("kind=ssh").map_err(anyhow::Error::msg)?);
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
/// pins nothing.
async fn scanned(
    session: &crate::client::Approvals,
    signer: &Signer,
    host: &HostName,
    port: u16,
    proxy: Option<&ProxyName>,
    pinned: &[String],
) -> anyhow::Result<Option<Vec<String>>> {
    let nonce: ScanNonce = session.call(&Command::ScanNonce, b"").await??;
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
    let found: Scanned = session
        .call(&Command::Scan, &writ_proto::encode_body(&request)?)
        .await??;
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
    print!("Do they match what the remote publishes? [y/N] ");
    std::io::stdout().flush()?;
    if !matches!(read_line()?.as_str(), "y" | "Y" | "yes") {
        println!("Nothing pinned.");
        return Ok(None);
    }
    Ok(Some(found.keys.into_iter().map(|k| k.key).collect()))
}

/// The keys to pin for `host` on `port`, as `keys=…`: scanned (on a terminal) and compared.
async fn pin_edit(
    session: &crate::client::Approvals,
    signer: &Signer,
    host: &HostName,
    port: u16,
    proxy: Option<&ProxyName>,
) -> anyhow::Result<Option<FieldEdit>> {
    match scanned(session, signer, host, port, proxy, &[]).await? {
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
            let Some(mut keys) =
                scanned(session, signer, &host, port, proxy.as_ref(), &pinned).await?
            else {
                return Ok(Exit::Ok);
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
            sign_applied(session, signer, &shown, &text, &what, yes).await?;
            Ok(Exit::Ok)
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
    let checked: UpstreamChecked = session
        .call(&Command::RepoCheck { repo: repo.clone() }, b"")
        .await??;
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
                "Next: add the token for {} from {}: writ admin token {}",
                clean(host.as_str()),
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
            if let (Some((host, port, _)), true) = (&host, interactive)
                && !given.iter().any(|g| g.field == "keys")
            {
                match pin_edit(session, signer, host, *port, proxy.as_ref()).await? {
                    Some(keys) => edits.push(keys),
                    None => return Ok(None),
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
                            match pin_edit(session, signer, &host, port, proxy.as_ref()).await? {
                                Some(keys) => pin = Some((entry, keys)),
                                None => return Ok(None),
                            }
                        }
                    }
                    let (repo_edit, key) = credential(&policy, name, &upstream)?;
                    asked_given.push(repo_edit);
                    new_key = key;
                }
                let more = asked(&policy, section, &asked_given, &start, true)?;
                edits.extend(asked_given);
                edits.extend(more);
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
            let next = edit::add(&next, section, name, &edits, MIN_TTL)
                .map_err(|e| anyhow::anyhow!("not added: {}", clean(&e.to_string())))?;
            if section == Section::Keys {
                made.push(name.to_owned());
            }
            let text = AdminText::try_from(next.to_yaml())?;
            let what = format!("with {} {} added", section.noun(), clean(name));
            if sign_applied(session, signer, &shown, &text, &what, yes)
                .await?
                .is_none()
            {
                return Ok(None);
            }
            next_steps(&next, &made);
            Ok((section == Section::Repos).then_some(()))
        })
        .await?;
    // A repo added: its upstream checked once its credential is registered.
    if checked_repo.is_some() {
        let repo: writ_core::names::RepoName = name.parse()?;
        if !interactive {
            println!("Once its credential is registered: writ admin repo check {repo}");
            return Ok(Exit::Ok);
        }
        print!("Press Enter once its credential is registered, to check its upstream: ");
        std::io::stdout().flush()?;
        read_line()?;
        return connect(paths, url)
            .await?
            .run(async |session| run_check(session, &repo).await)
            .await;
    }
    Ok(Exit::Ok)
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
            let edits = asked(&policy, section, &[], &current, false)?;
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
            sign_applied(session, signer, &shown, &text, &what, yes).await?;
            Ok(Exit::Ok)
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

/// `writ admin key rotate <id> [--name <new>]`: a new key declared like the old one (one
/// signed change: its public half printed, to register); once it is registered, every repo
/// and template that used the old one switched to it (a second signed change); then the old
/// one offered for removal. Without a terminal, `--yes` answers the question between the
/// two (the old key is then left declared, unused).
pub async fn rotate(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    id: &str,
    name: Option<&str>,
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
            let edits: Vec<FieldEdit> = values
                .iter()
                .map(|(field, value)| FieldEdit {
                    field: (*field).to_owned(),
                    change: Change::Set(value.clone()),
                })
                .collect();
            let next = edit::add(&policy, Section::Keys, &fresh, &edits, MIN_TTL)
                .map_err(|e| anyhow::anyhow!("not rotated: {}", clean(&e.to_string())))?;
            let text = AdminText::try_from(next.to_yaml())?;
            let what = format!("with key {} declared like {}", clean(&fresh), clean(id));
            let applied = sign_applied(session, signer, &shown, &text, &what, yes).await?;
            if applied.is_none() {
                return Ok(None);
            }
            next_steps(&next, std::slice::from_ref(&fresh));
            Ok(Some(fresh))
        })
        .await?;
    let Some(fresh) = fresh else {
        return Ok(Exit::Ok);
    };
    if interactive && !yes {
        print!(
            "Once {} is registered (or added), press Enter to switch what uses {} to it \
             (Ctrl-C stops here; {} stays in use): ",
            clean(&fresh),
            clean(id),
            clean(id)
        );
        std::io::stdout().flush()?;
        read_line()?;
    }
    let session = connect(paths, url).await?;
    session
        .run(async |session| {
            let (shown, policy) = policy_in_force(session).await?;
            let old: writ_core::names::KeyId = id.parse()?;
            let users = policy.key_users(&old);
            let mut next = policy.clone();
            for repo in &users.repos {
                let set = FieldEdit::parse(&format!("upstream_credential={fresh}"))
                    .map_err(anyhow::Error::msg)?;
                next = edit::edit(&next, Section::Repos, repo.as_str(), &[set], MIN_TTL)
                    .map_err(|e| anyhow::anyhow!("not switched: {}", clean(&e.to_string())))?;
            }
            for template in &users.templates {
                let set = FieldEdit::parse(&format!("signing_key={fresh}"))
                    .map_err(anyhow::Error::msg)?;
                next = edit::edit(
                    &next,
                    Section::Templates,
                    template.as_str(),
                    &[set],
                    MIN_TTL,
                )
                .map_err(|e| anyhow::anyhow!("not switched: {}", clean(&e.to_string())))?;
            }
            if !users.templates.is_empty() {
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
            sign_applied(session, signer, &shown, &text, &what, yes).await?;
            Ok(())
        })
        .await?;
    if interactive && !yes {
        print!("Remove {} now? It is deleted for good. [y/N] ", clean(id));
        std::io::stdout().flush()?;
        if matches!(read_line()?.as_str(), "y" | "Y" | "yes") {
            return super::manage::remove(paths, url, signer, Section::Keys, id, false).await;
        }
    }
    println!(
        "{} stays declared, unused: writ admin key remove {} deletes it.",
        clean(id),
        clean(id)
    );
    Ok(Exit::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rotated_key_takes_the_next_free_id() {
        let policy = PolicyConfig::from_yaml(
            "keys:\n  forgejo-home: { use: upstream, kind: ssh, algorithm: ed25519 }\n  \
             forgejo-home-2: { use: upstream, kind: ssh, algorithm: ed25519 }\n  \
             agent-01: { use: signing, format: ssh, algorithm: ed25519 }\nrepos: {}\n\
             templates: {}\n",
        )
        .unwrap();
        assert_eq!(next_id(&policy, "forgejo-home"), "forgejo-home-3");
        assert_eq!(next_id(&policy, "agent-01"), "agent-2");
        assert_eq!(next_id(&policy, "token"), "token-2");
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
        assert!(!relevant(Section::Templates, "branches", &fetch));
        assert!(!relevant(Section::Templates, "signing_key", &fetch));
        assert!(relevant(Section::Templates, "max_ttl", &fetch));
        let signs = values(&[("operations", "fetch, commit_sign")]);
        assert!(relevant(Section::Templates, "signing_key", &signs));
        assert!(!relevant(Section::Templates, "force_push", &signs));
        let token = values(&[("use", "upstream"), ("kind", "token")]);
        assert!(relevant(Section::Keys, "host", &token));
        assert!(!relevant(Section::Keys, "algorithm", &token));
        let pgp = values(&[("use", "signing"), ("format", "openpgp")]);
        assert!(relevant(Section::Keys, "uids", &pgp) && !relevant(Section::Keys, "kind", &pgp));
        let notes = values(&[("ticket_link", "notes")]);
        assert!(relevant(Section::Repos, "notes_ref", &notes));
        assert!(!relevant(Section::Repos, "direct_ssh.hosts", &notes));
    }
}
