//! `writ admin repo|template|key|host`: the policy in force, entry by entry. `list` and
//! `show` read it with the reader key (the policy's text from `writ admin show policy`, the
//! keys' public halves from the daemon's signers); nothing here grants anything, and what the
//! daemon sends is shown escaped.
//!
//! The policy is parsed here only to show it: the daemon is the one that checks it.

use anyhow::{Context, bail};
use writ_core::config::{PolicyConfig, Section};
use writ_core::upstream::Upstream;
use writ_proto::{AdminShown, Command, KeyShown, KeysShown};

use super::connect;
use crate::client::Approvals;
use crate::display::clean;
use crate::{Exit, Paths};

/// The policy in force, as the daemon holds it, and parsed for showing.
async fn policy_in_force(session: &Approvals) -> anyhow::Result<(AdminShown, PolicyConfig)> {
    let shown: AdminShown = session
        .call(
            &Command::AdminShow {
                target: writ_core::authority::AdminTarget::Policy,
            },
            b"",
        )
        .await??;
    // The daemon's own `min_ttl` isn't known here: the lowest any daemon takes, so a policy
    // in force always reads (the daemon checked it against its own).
    let policy = PolicyConfig::from_yaml_with_min_ttl(&shown.text, writ_core::fit::MIN_TTL_FLOOR)
        .with_context(|| {
        format!(
            "the policy in force (version {}) doesn't read here: is this writ older than \
                 the daemon?",
            shown.version
        )
    })?;
    Ok((shown, policy))
}

/// Names, joined, or `none`.
fn names<T: ToString>(items: &[T]) -> String {
    match items.is_empty() {
        true => "none".to_owned(),
        false => items
            .iter()
            .map(|i| clean(&i.to_string()))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

/// `writ admin <noun> list`: one line per entry.
pub async fn list(paths: &Paths, url: &str, section: Section) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let (shown, policy) = policy_in_force(session).await?;
            let keys: Option<KeysShown> = match section {
                Section::Keys => Some(session.call(&Command::AdminKeys, b"").await??),
                _ => None,
            };
            eprintln!(
                "policy: version {} (sha256 {})",
                shown.version, shown.digest
            );
            let lines = lines(&policy, section, keys.as_ref());
            if lines.is_empty() {
                println!("No {} in the policy in force.", section.noun());
            }
            for line in lines {
                println!("{line}");
            }
            Ok(Exit::Ok)
        })
        .await
}

/// The lines of `list` for `section`.
fn lines(policy: &PolicyConfig, section: Section, keys: Option<&KeysShown>) -> Vec<String> {
    match section {
        Section::Repos => policy
            .repos()
            .iter()
            .map(|(name, repo)| {
                let templates = match repo.templates.is_empty() {
                    true => "closed (no template)".to_owned(),
                    false => format!(
                        "templates {}",
                        names(&repo.templates.iter().collect::<Vec<_>>())
                    ),
                };
                format!(
                    "{}  {}  credential {}  {templates}",
                    clean(name.as_str()),
                    clean(&repo.upstream),
                    clean(repo.upstream_credential.as_str())
                )
            })
            .collect(),
        Section::Templates => policy
            .templates()
            .iter()
            .map(|(name, template)| {
                let operations: Vec<String> =
                    template.operations.iter().map(|o| o.to_string()).collect();
                format!(
                    "{}  {}  max_ttl {}  repos {}",
                    clean(name.as_str()),
                    operations.join(", "),
                    template.max_ttl,
                    names(&policy.template_users(name))
                )
            })
            .collect(),
        Section::UpstreamHosts => policy
            .upstream_hosts()
            .iter()
            .map(|(host, pinned)| {
                let count = match pinned.len() {
                    1 => "1 key".to_owned(),
                    n => format!("{n} keys"),
                };
                format!(
                    "{}  {count}  repos {}",
                    clean(host.as_str()),
                    names(&policy.host_users(host))
                )
            })
            .collect(),
        Section::Keys => keys
            .map(|keys| keys.keys.iter().map(key_line).collect())
            .unwrap_or_default(),
    }
}

/// A key's line in `key list`: its id, what it is, its fingerprint (or whether a token was
/// added), what uses it.
fn key_line(key: &KeyShown) -> String {
    let state = match (&key.fingerprint, key.token_added) {
        (Some(fingerprint), _) => clean(fingerprint),
        (None, Some(true)) => "added".to_owned(),
        (None, Some(false)) => "not added yet (writ admin token)".to_owned(),
        (None, None) => "no public half".to_owned(),
    };
    format!(
        "{}  {}  {state}  {}",
        clean(key.id.as_str()),
        clean(&key.description),
        used_by(key)
    )
}

fn used_by(key: &KeyShown) -> String {
    match (key.repos.is_empty(), key.templates.is_empty()) {
        (true, true) => "unused".to_owned(),
        (false, true) => format!("repos {}", names(&key.repos)),
        (true, false) => format!("templates {}", names(&key.templates)),
        (false, false) => format!(
            "repos {}; templates {}",
            names(&key.repos),
            names(&key.templates)
        ),
    }
}

/// `writ admin <noun> show <name>`: the entry as the policy writes it, then what the daemon
/// knows of it (a key's public half, a host's fingerprints, what uses it).
pub async fn show(
    paths: &Paths,
    url: &str,
    section: Section,
    name: &str,
    public: bool,
) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let (shown, policy) = policy_in_force(session).await?;
            let Some(entry) = policy.entry_yaml(section, name) else {
                bail!(
                    "no {} {} in the policy in force (writ admin {} list)",
                    section.noun(),
                    clean(name),
                    section.noun()
                );
            };
            let key: Option<KeyShown> = match section {
                Section::Keys => {
                    let keys: KeysShown = session.call(&Command::AdminKeys, b"").await??;
                    keys.keys.into_iter().find(|k| k.id.as_str() == name)
                }
                _ => None,
            };
            if public {
                print!("{}", public_half(name, key.as_ref())?);
                return Ok(Exit::Ok);
            }
            eprintln!(
                "policy: version {} (sha256 {})",
                shown.version, shown.digest
            );
            print!("{}", clean_text(&entry));
            print!("{}", details(&policy, section, name, key.as_ref()));
            Ok(Exit::Ok)
        })
        .await
}

/// Policy text, each line escaped (it may hold anything an approver signed).
fn clean_text(text: &str) -> String {
    text.lines().map(|l| format!("{}\n", clean(l))).collect()
}

/// `key show <id> --public`: the public half alone (an OpenSSH line, or an OpenPGP key's
/// certificate), for a pipe.
fn public_half(id: &str, key: Option<&KeyShown>) -> anyhow::Result<String> {
    let Some(key) = key else {
        bail!("the daemon lists no key {}", clean(id));
    };
    if let Some(openpgp) = &key.openpgp {
        return Ok(clean_text(&openpgp.certificate));
    }
    match (&key.public_key, key.token_added) {
        (Some(line), _) => Ok(format!("{}\n", clean(line))),
        (None, Some(_)) => bail!(
            "{} is a token: it has no public half (the remote made it)",
            clean(id)
        ),
        (None, None) => bail!("the daemon gave no public half for {}", clean(id)),
    }
}

/// What `show` prints after the entry.
fn details(policy: &PolicyConfig, section: Section, name: &str, key: Option<&KeyShown>) -> String {
    let mut out = String::new();
    match section {
        Section::Keys => {
            if let Some(key) = key {
                if let Some(line) = &key.public_key {
                    out.push_str(&format!("public key: {}\n", clean(line)));
                }
                if let Some(fingerprint) = &key.fingerprint {
                    out.push_str(&format!("fingerprint: {}\n", clean(fingerprint)));
                }
                match key.token_added {
                    Some(true) => out.push_str("token: added\n"),
                    Some(false) => out.push_str(&format!(
                        "token: not added yet (writ admin token {})\n",
                        clean(key.id.as_str())
                    )),
                    None => {}
                }
                out.push_str(&format!("used by: {}\n", used_by(key)));
                if let Some(openpgp) = &key.openpgp {
                    out.push_str(&format!(
                        "OpenPGP fingerprint: {}\n",
                        clean(&openpgp.fingerprint)
                    ));
                    out.push_str(&clean_text(&openpgp.certificate));
                }
            }
        }
        Section::UpstreamHosts => {
            if let Some((host, pinned)) = policy
                .upstream_hosts()
                .iter()
                .find(|(host, _)| host.as_str() == name)
            {
                for key in pinned {
                    let fingerprint = writ_crypto::ssh_key::PublicKey::from_openssh(key.as_str())
                        .map(|k| {
                            k.fingerprint(writ_crypto::ssh_key::HashAlg::Sha256)
                                .to_string()
                        })
                        .unwrap_or_else(|_| "(not a key)".to_owned());
                    out.push_str(&format!(
                        "fingerprint: {} {}\n",
                        clean(key.key_type()),
                        clean(&fingerprint)
                    ));
                }
                out.push_str(&format!("repos: {}\n", names(&policy.host_users(host))));
            }
        }
        Section::Repos => {
            if let Some((_, repo)) = policy.repos().iter().find(|(r, _)| r.as_str() == name) {
                if let Ok(Upstream::Ssh(url)) = Upstream::parse(&repo.upstream) {
                    out.push_str(&format!("host pin: {}\n", clean(&url.known_hosts_name())));
                }
                if let Some(key) = policy.key(&repo.upstream_credential) {
                    out.push_str(&format!(
                        "credential: {} ({})\n",
                        clean(repo.upstream_credential.as_str()),
                        clean(&key.describe())
                    ));
                }
                if repo.templates.is_empty() {
                    out.push_str("closed: no template allows tickets for it\n");
                }
            }
        }
        Section::Templates => {
            if let Some((template, _)) = policy.templates().iter().find(|(t, _)| t.as_str() == name)
            {
                out.push_str(&format!(
                    "repos: {}\n",
                    names(&policy.template_users(template))
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(id: &str, fingerprint: Option<&str>, token: Option<bool>) -> KeyShown {
        KeyShown {
            id: id.parse().unwrap(),
            description: "upstream ssh ed25519".to_owned(),
            public_key: fingerprint.map(|_| "ssh-ed25519 AAAA\u{1b}[2J".to_owned()),
            fingerprint: fingerprint.map(str::to_owned),
            openpgp: None,
            token_added: token,
            repos: vec!["demo".parse().unwrap()],
            templates: vec![],
        }
    }

    #[test]
    fn what_the_daemon_sends_is_shown_escaped_and_a_token_has_no_public_half() {
        let key = shown("k", Some("SHA256:x\u{7}"), None);
        let line = key_line(&key);
        assert!(
            !line.contains('\u{7}') && !line.contains('\u{1b}'),
            "{line:?}"
        );
        assert!(line.ends_with("repos demo"), "{line}");
        assert!(!public_half("k", Some(&key)).unwrap().contains('\u{1b}'));
        let token = shown("t", None, Some(false));
        assert!(key_line(&token).contains("not added yet (writ admin token)"));
        assert_eq!(
            public_half("t", Some(&token)).unwrap_err().to_string(),
            "t is a token: it has no public half (the remote made it)"
        );
        assert_eq!(
            public_half("nope", None).unwrap_err().to_string(),
            "the daemon lists no key nope"
        );
    }
}
