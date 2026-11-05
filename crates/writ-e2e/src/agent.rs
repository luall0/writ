//! Agents and the approver. Each scenario makes its own agent ([`Stack::agent`]): its own
//! directory on the agents' host and its own `WRIT_HOME` (a session's files, and
//! `sessions/current` the wiring follows, are per agent), as if each ran on a host of its
//! own. The approver is shared: one machine, one approval key.
//!
//! Tickets are YAML as an agent writes them ([`ticket`]); [`Agent::lease`] goes through the
//! whole flow (submitted, signed by the approver, the decision received) and returns the
//! lease id.

use std::process::Output;

use crate::docker::{Host, Running, stderr, stdout};
use crate::forgejo::{BASE, OWNER};
use crate::setup::AGENTS_URL;
use crate::stack::Stack;

/// An agent, in its directory on the agents' host, with its `client.env` sourced.
pub struct Agent {
    pub host: Host,
    pub name: String,
}

impl std::ops::Deref for Agent {
    type Target = Host;

    fn deref(&self) -> &Host {
        &self.host
    }
}

/// A ticket for `repos` and `branches` from the `feature` template, one committer email,
/// `ttl`, and `extra` lines (YAML, at the top level) appended.
pub fn ticket(repos: &[&str], branches: &[&str], ttl: &str, extra: &str) -> String {
    ticket_with(repos, branches, ttl, "", extra)
}

/// [`ticket`], with `in_each` lines (YAML, indented four spaces) in each repository's block.
pub fn ticket_with(
    repos: &[&str],
    branches: &[&str],
    ttl: &str,
    in_each: &str,
    extra: &str,
) -> String {
    let quoted = |items: &[&str]| {
        items
            .iter()
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let blocks: String = repos
        .iter()
        .map(|repo| {
            format!(
                "  {repo}:\n    template: feature\n    operations: [fetch, commit_sign, push]\n    \
                 branches: [{}]\n{in_each}",
                quoted(branches)
            )
        })
        .collect();
    format!(
        "common:\n  committer_emails: [\"agent@writ.invalid\"]\n\
         repos:\n{blocks}\
         ticket:\n  title: \"e2e: {}\"\n  task: \"An end-to-end scenario's work\"\n\
         limits:\n  ttl: {ttl}\n{extra}",
        repos.join(", ")
    )
}

/// The ticket id in `writ request`'s first line (`Ticket wrt_… submitted …`).
pub fn submitted_id(first_line: &str) -> String {
    first_line
        .strip_prefix("Ticket ")
        .and_then(|rest| rest.split_whitespace().next())
        .filter(|id| id.starts_with("wrt_"))
        .unwrap_or_else(|| panic!("writ request didn't submit: {first_line:?}"))
        .to_owned()
}

/// Asserts a command's exit code, showing both its streams if it differs; its stdout and
/// stderr.
pub fn expect(out: &Output, code: i32, what: &str) -> (String, String) {
    assert_eq!(
        out.status.code(),
        Some(code),
        "{what}\n--- stdout\n{}--- stderr\n{}",
        stdout(out),
        stderr(out)
    );
    (stdout(out), stderr(out))
}

impl Stack {
    /// A new agent named `name` (one per scenario): its directory, its `WRIT_HOME` with the
    /// daemon's host key pinned, and its `client.env`.
    pub fn agent(&self, name: &str) -> Agent {
        let dir = format!("{}/agents/{name}", self.agents_home.dir);
        self.agents_home.ok(&format!(
            "mkdir -p {dir} && mkdir -m 700 {dir}/.writ && cp .writ/known_hosts {dir}/.writ/"
        ));
        let host = self.agents_home.with(&dir, None);
        host.write(
            "client.env",
            &format!("export WRIT_HOME={dir}/.writ\nexport WRIT_URL={AGENTS_URL}\n"),
            "0644",
        );
        Agent {
            host: host.with(&dir, Some("client.env")),
            name: name.to_owned(),
        }
    }

    /// The approver signs `id` as submitted (`writ sign <id> --yes`, over HTTPS).
    pub fn approve(&self, id: &str) {
        self.approve_with(id, "");
    }

    /// The approver signs `id` with more arguments (narrowing flags, another approval URL).
    pub fn approve_with(&self, id: &str, args: &str) {
        let out = self.approver.run(&format!("writ sign {id} --yes {args}"));
        let (out, _) = expect(&out, 0, &format!("writ sign {id} --yes {args}"));
        assert!(
            out.contains(&format!("Signed: lease {id} is active.")),
            "{out}"
        );
    }
}

impl Agent {
    /// Writes `ticket` to `<file>.yaml` in the agent's directory; the file's name.
    pub fn ticket_file(&self, file: &str, ticket: &str) -> String {
        let path = format!("{file}.yaml");
        self.write(&path, ticket, "0644");
        path
    }

    /// Submits a ticket without waiting (`writ request --no-wait`): its id.
    pub fn submit(&self, file: &str, ticket: &str) -> String {
        let path = self.ticket_file(file, ticket);
        let out = self.run(&format!("writ request --no-wait {path}"));
        let (out, _) = expect(&out, 0, "writ request --no-wait");
        submitted_id(&out)
    }

    /// `writ request <file>`, waiting for the decision, in the background: returns once the
    /// ticket is submitted.
    pub fn request(&self, file: &str, ticket: &str) -> (String, Running) {
        let path = self.ticket_file(file, ticket);
        let running = self.start(&format!("writ request {path}"));
        (submitted_id(&running.first), running)
    }

    /// A lease, through the whole flow: submitted, signed by the approver, received.
    pub fn lease(&self, stack: &Stack, ticket: &str) -> String {
        let id = self.submit("ticket", ticket);
        stack.approve(&id);
        let out = self.run(&format!("writ wait {id}"));
        let (out, _) = expect(&out, 0, "writ wait");
        assert!(out.contains(&format!("Lease {id} granted")), "{out}");
        id
    }

    /// A file of a lease's session on the agent's host.
    pub fn session_file(&self, lease: &str, file: &str) -> String {
        self.read(&format!(".writ/sessions/{lease}/{file}"))
    }

    /// Clones `repo` from Forgejo into `dir`, with the operator's own access (an HTTP URL
    /// with the operator's token): the clone a person has before wiring it.
    pub fn clone_from_forgejo(&self, stack: &Stack, repo: &str, dir: &str) {
        let url = format!(
            "{}/{OWNER}/{repo}.git",
            BASE.replace(
                "http://",
                &format!("http://{OWNER}:{}@", stack.forgejo.token)
            )
        );
        self.ok(&format!("git clone -q {url} {dir}"));
    }

    /// Runs `script` in `dir` (a clone in the agent's directory).
    pub fn in_dir(&self, dir: &str, script: &str) -> Output {
        self.run(&format!("cd {dir} && {script}"))
    }

    /// The same, which must exit 0; its stdout.
    pub fn ok_in(&self, dir: &str, script: &str) -> String {
        let out = self.in_dir(dir, script);
        expect(&out, 0, &format!("in {dir}: {script}")).0
    }

    /// A signed commit through `writ git` in `dir`, changing `file`: its id.
    pub fn commit(&self, dir: &str, lease: &str, file: &str, content: &str) -> String {
        self.ok_in(
            dir,
            &format!(
                "printf '%s\\n' '{content}' > {file} && writ git add {file} && \
                 writ git commit -q -m 'Change {file}' --trailer 'Writ: {lease}' && \
                 git rev-parse HEAD"
            ),
        )
        .trim()
        .to_owned()
    }
}
