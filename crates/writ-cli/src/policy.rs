//! `writ policy [<repo>]`: what a ticket for a repo may ask, read from the daemon (the policy
//! in force), so the agent writes a ticket that fits before it sends one. The repo is the one
//! named, or the wired repository's. A read: the daemon checks every ticket again.

use writ_core::config::{PathsCheck, TicketLink};
use writ_core::names::RepoName;
use writ_crypto::keys::{KeyKind, generate};
use writ_proto::{CLIENT_USER, Command, RepoPolicy, TemplateView};

use crate::client::{Endpoint, Session};
use crate::{Exit, Paths, display, wiring};

/// Prints the policy for `repo`, or for the wired repository here.
pub async fn policy(paths: &Paths, url: &str, repo: Option<&RepoName>) -> anyhow::Result<Exit> {
    let repo = match repo {
        Some(repo) => repo.clone(),
        None => {
            let dir = std::env::current_dir()?;
            let wired = wiring::load(&dir).ok().flatten().ok_or_else(|| {
                anyhow::anyhow!(
                    "this directory isn't a repository wired for Writ: name the repo \
                     (`writ policy <repo>`)"
                )
            })?;
            wired.repo
        }
    };
    // Any key reaches the agents' listener for a read; this one is never kept.
    let key = generate(KeyKind::Ed25519)?;
    let endpoint = Endpoint::parse(url)?;
    Session::connect(&endpoint, &paths.known_hosts, CLIENT_USER, key)
        .await?
        .run(async |session| {
            let reply = session
                .call::<RepoPolicy>(&Command::Policy { repo: repo.clone() }, b"")
                .await?;
            match reply {
                Ok(policy) => {
                    print!("{}", render(&policy));
                    Ok(Exit::Ok)
                }
                Err(error) => {
                    eprintln!("writ: {}", display::clean(&error.message));
                    Ok(Exit::Rejected)
                }
            }
        })
        .await
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
            "\nA ticket must fit one template: name it (`template: <name>`) when several could.\n",
        );
    } else {
        out.push_str(
            "\nA ticket must fit this template: ask for what the task needs, within it.\n",
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
