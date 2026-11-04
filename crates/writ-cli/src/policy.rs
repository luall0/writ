//! `writ policy [<repo>]`: what a ticket for a repo may ask, read from the daemon (the policy
//! in force), so the agent writes a ticket that fits before it sends one. The repo is the one
//! named, or the wired repository's. A read: the daemon checks every ticket again.

use std::fmt::Write as _;

use writ_core::config::{PathsCheck, TicketLink};
use writ_core::names::RepoName;
use writ_crypto::keys::{KeyKind, generate};
use writ_proto::{CLIENT_USER, Command, RepoPolicy, TemplateView};

use crate::client::{Endpoint, Session};
use crate::{Exit, Paths, display, wiring, workspace};

/// Prints the policy for each of `repos`, or for the wired repository here; for several,
/// whether one ticket can cover them ([`together`]).
pub async fn policy(paths: &Paths, url: &str, repos: &[RepoName]) -> anyhow::Result<Exit> {
    let repos: Vec<RepoName> = if repos.is_empty() {
        let dir = std::env::current_dir()?;
        if let Some(wired) = wiring::load(&dir).ok().flatten() {
            vec![wired.repo]
        } else if let Ok(Some(found)) = workspace::load(&dir) {
            anyhow::bail!(
                "this folder is a Writ workspace: name the repos (`writ policy <repo>…`), of:\n{}",
                found.listing()
            );
        } else {
            anyhow::bail!(
                "this directory isn't a repository wired for Writ: name the repo \
                 (`writ policy <repo>`)"
            );
        }
    } else {
        repos.to_vec()
    };
    let endpoint = Endpoint::parse(url)?;
    let mut read = Vec::new();
    for (i, repo) in repos.iter().enumerate() {
        // Any key reaches the agents' listener for a read; this one is never kept.
        let key = generate(KeyKind::Ed25519)?;
        let reply = Session::connect(&endpoint, &paths.known_hosts, CLIENT_USER, key)
            .await?
            .run(async |session| {
                session
                    .call::<RepoPolicy>(&Command::Policy { repo: repo.clone() }, b"")
                    .await
            })
            .await?;
        match reply {
            Ok(policy) => {
                if i > 0 {
                    println!();
                }
                print!("{}", render(&policy));
                read.push(policy);
            }
            Err(error) => {
                eprintln!("writ: {}", display::clean(&error.message));
                return Ok(Exit::Rejected);
            }
        }
    }
    if read.len() > 1 {
        print!("\n{}", together(&read));
    }
    Ok(Exit::Ok)
}

/// Whether one ticket can cover every repository of `policies`: some template of each
/// repository, all naming one signing key (or none, for repositories that don't sign), and
/// the lease's terms the strictest of them. Otherwise, one lease per repository.
pub fn together(policies: &[RepoPolicy]) -> String {
    let mut out = String::from("Together:\n");
    let keys: Vec<std::collections::BTreeSet<Option<&writ_core::names::KeyId>>> = policies
        .iter()
        .map(|p| p.templates.iter().map(|t| t.signing_key.as_ref()).collect())
        .collect();
    let shared: Vec<Option<&writ_core::names::KeyId>> = match keys.split_first() {
        Some((first, rest)) => first
            .iter()
            .filter(|k| rest.iter().all(|set| set.contains(*k)))
            .copied()
            .collect(),
        None => Vec::new(),
    };
    if shared.is_empty() {
        out.push_str(
            "  No signing key is shared by a template of every repository: one ticket can't \
             cover them. Ask one lease per repository (each with its own WRIT_SESSION).\n",
        );
        return out;
    }
    for key in shared {
        let shown = key.map_or("no signing key".to_owned(), |k| {
            format!("signing key {}", display::clean(k.as_str()))
        });
        let picks: Vec<String> = policies
            .iter()
            .map(|p| {
                let names: Vec<String> = p
                    .templates
                    .iter()
                    .filter(|t| t.signing_key.as_ref() == key)
                    .map(|t| display::clean(t.name.as_str()))
                    .collect();
                format!(
                    "{}: {}",
                    display::clean(p.repo.as_str()),
                    names.join(" or ")
                )
            })
            .collect();
        let chosen: Vec<&TemplateView> = policies
            .iter()
            .flat_map(|p| p.templates.iter().filter(|t| t.signing_key.as_ref() == key))
            .collect();
        let ttl = chosen.iter().map(|t| t.max_ttl).min();
        let rate = chosen.iter().map(|t| t.max_ops_per_minute).min();
        let _ = writeln!(
            out,
            "  One ticket can cover them with {shown}: {}.",
            picks.join("; ")
        );
        if let (Some(ttl), Some(rate)) = (ttl, rate) {
            let _ = writeln!(
                out,
                "  Its ttl at most {ttl} and its rate at most {rate}/min (the strictest of \
                 these templates; the one each repository fits decides)."
            );
        }
    }
    out.push_str(
        "  Name each repository's template in its block (`repos.<repo>.template`) when several \
         could; if these terms are too tight for the task, ask one lease per repository.\n",
    );
    out
}

/// The policy as the agent reads it. Everything from the daemon is escaped.
pub fn render(policy: &RepoPolicy) -> String {
    let mut out = format!(
        "What a ticket for repo {} may ask (the daemon's policy in force; every ticket is \
         checked again):\n",
        display::clean(policy.repo.as_str())
    );
    let row = |out: &mut String, name: &str, value: &str| {
        out.push_str(&format!("  {name:<20}{value}\n"));
    };
    row(
        &mut out,
        "protected refs",
        &format!(
            "{} (never pushed: work on a branch of your own)",
            display::list(&policy.protected_refs)
        ),
    );
    row(
        &mut out,
        "ticket link",
        match policy.ticket_link {
            TicketLink::Trailer => "every commit message needs the trailer `Writ: <lease id>`",
            TicketLink::Notes => "a git note the daemon writes after each push (nothing to add)",
            TicketLink::LedgerOnly => "the daemon's ledger only (nothing to add to commits)",
        },
    );
    row(&mut out, "shortest ttl", &policy.min_ttl.to_string());
    row(
        &mut out,
        "renew within",
        &format!("{} after a lease ends", policy.renew_grace),
    );
    if let Some(max) = policy.max_active_per_source {
        row(
            &mut out,
            "active leases",
            &format!("at most {max} at once from one host"),
        );
    }
    if policy.templates.is_empty() {
        out.push_str("\nNo template allows tickets for this repo: ask the operator.\n");
        return out;
    }
    for template in &policy.templates {
        out.push('\n');
        out.push_str(&template_rows(template));
    }
    if policy.templates.len() > 1 {
        out.push_str(
            "\nThe repo's block must fit one template: name it (`repos.<repo>.template: <name>`) \
             when several could.\n",
        );
    } else {
        out.push_str(
            "\nThe repo's block must fit this template: ask for what the task needs, within it.\n",
        );
    }
    out
}

fn template_rows(template: &TemplateView) -> String {
    let mut out = format!("Template {}:\n", display::clean(template.name.as_str()));
    let row = |out: &mut String, name: &str, value: String| {
        out.push_str(&format!("  {name:<20}{value}\n"));
    };
    let count = |n: u32| n.to_string();
    row(&mut out, "operations", display::list(&template.operations));
    row(&mut out, "branches", display::list(&template.branches));
    row(
        &mut out,
        "committer emails",
        display::list(&template.committer_emails),
    );
    row(
        &mut out,
        "committer name",
        template.committer_name.as_ref().map_or_else(
            || "not checked".to_owned(),
            |name| {
                format!(
                    "{} (every commit, as author and committer; `writ git` sets it)",
                    display::clean(name.as_str())
                )
            },
        ),
    );
    row(
        &mut out,
        "force push",
        if template.force_push {
            "may be asked for"
        } else {
            "never"
        }
        .to_owned(),
    );
    row(&mut out, "max ttl", template.max_ttl.to_string());
    row(&mut out, "max signatures", count(template.max_signatures));
    row(&mut out, "max pushes", count(template.max_pushes));
    row(
        &mut out,
        "ops per minute",
        count(template.max_ops_per_minute),
    );
    row(
        &mut out,
        "max push size",
        template.max_push_size.to_string(),
    );
    let paths = match template.paths_check {
        PathsCheck::Off => "not checked",
        PathsCheck::Warn => "files outside them are signed, with a warning",
        PathsCheck::Deny => "files outside them are refused",
    };
    let required = if template.require_expected_paths {
        "required"
    } else {
        "optional"
    };
    row(&mut out, "expected_paths", format!("{required}; {paths}"));
    row(
        &mut out,
        "renewals",
        template.max_renewals.map_or_else(
            || "no limit".to_owned(),
            |n| format!("at most {n} per lease"),
        ),
    );
    out
}

#[cfg(test)]
mod tests {
    use writ_core::ticket::Operation;
    use writ_core::units::{ByteSize, Duration};

    use super::*;

    fn template(name: &str) -> TemplateView {
        TemplateView {
            name: name.parse().unwrap(),
            operations: vec![Operation::Fetch, Operation::CommitSign, Operation::Push],
            branches: vec!["agent/*".to_owned()],
            committer_emails: vec!["agent@writ.invalid".parse().unwrap()],
            committer_name: Some("Writ agent".parse().unwrap()),
            force_push: false,
            max_ttl: Duration::from_seconds(4 * 3600),
            max_signatures: 50,
            max_pushes: 30,
            max_ops_per_minute: 20,
            max_push_size: ByteSize::from_bytes(50_000_000),
            paths_check: PathsCheck::Deny,
            require_expected_paths: true,
            max_renewals: Some(2),
        }
    }

    fn policy(templates: Vec<TemplateView>) -> RepoPolicy {
        RepoPolicy {
            repo: "demo".parse().unwrap(),
            protected_refs: vec!["refs/heads/main".to_owned(), "refs/tags/*".to_owned()],
            ticket_link: TicketLink::Trailer,
            templates,
            min_ttl: Duration::from_seconds(300),
            renew_grace: Duration::from_seconds(86_400),
            max_active_per_source: Some(1),
        }
    }

    #[test]
    fn the_policy_reads_as_what_a_ticket_may_ask() {
        let shown = render(&policy(vec![template("feature-branch")]));
        for words in [
            "What a ticket for repo demo may ask",
            "protected refs      refs/heads/main, refs/tags/* (never pushed",
            "ticket link         every commit message needs the trailer `Writ: <lease id>`",
            "shortest ttl        5m",
            "renew within        1d after a lease ends",
            "active leases       at most 1 at once from one host",
            "Template feature-branch:",
            "operations          fetch, commit_sign, push",
            "branches            agent/*",
            "committer emails    agent@writ.invalid",
            "committer name      Writ agent (every commit, as author and committer",
            "force push          never",
            "max ttl             4h",
            "max push size       50000000 bytes",
            "expected_paths      required; files outside them are refused",
            "renewals            at most 2 per lease",
            "A ticket must fit this template",
        ] {
            assert!(shown.contains(words), "{words:?} not in:\n{shown}");
        }
        let two = render(&policy(vec![template("a"), template("b")]));
        assert!(
            two.contains("Template a:") && two.contains("Template b:"),
            "{two}"
        );
        assert!(two.contains("name it (`template: <name>`)"), "{two}");
        let mut unnamed = template("c");
        unnamed.committer_name = None;
        let unnamed = render(&policy(vec![unnamed]));
        assert!(
            unnamed.contains("committer name      not checked"),
            "{unnamed}"
        );
        let none = render(&policy(Vec::new()));
        assert!(
            none.contains("No template allows tickets for this repo"),
            "{none}"
        );
    }

    #[test]
    fn the_daemon_s_words_are_escaped() {
        let mut hostile = policy(vec![template("feature-branch")]);
        hostile.protected_refs = vec!["refs/heads/\u{1b}[2Jmain".to_owned()];
        hostile.templates[0].branches = vec!["agent/\u{1b}]8;;x\u{7}*".to_owned()];
        let shown = render(&hostile);
        assert!(
            !shown.contains('\u{1b}') && !shown.contains('\u{7}'),
            "{shown:?}"
        );
    }
}
