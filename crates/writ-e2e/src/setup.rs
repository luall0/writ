//! The operator setup, from nothing, in the order the operator guide gives it
//! (docs/guides/operator.md#setting-up-the-daemon): the daemon's files with relative paths,
//! the upstream credentials added on Forgejo as deploy keys (and the HTTPS repo's token in the
//! keystore, its front's certificate trusted), Forgejo's host key pinned and
//! checked against the one it publishes, the signing keys listed, the daemon's host key and
//! TLS fingerprint pinned on the clients, the reader and the approver listed, and
//! `writd run writd.yaml` started from the daemon's directory, on a relative path.
//!
//! Every command the guide shows runs through [`doc_step`], with its text exactly as the
//! guide writes it (placeholders such as `<host>` filled in): `tool/check-e2e.py` checks that
//! each command in the guide's marked blocks is run here and each one run here is in the
//! guide, so a step changed in one is changed in the other. The setup runs once per stack
//! ([`crate::stack`]); what it saw is the [`Report`] the `operator_setup` scenario checks.

use std::time::Duration;

use crate::docker::{Container, Host, eventually, stderr, stdout};
use crate::forgejo::Forgejo;
use crate::stack::Stack;

/// The daemon's configuration and registry, as the operator writes them (`e2e/config/`).
pub const WRITD_YAML: &str = include_str!("../../../e2e/config/writd.yaml");
pub const POLICY_YAML: &str = include_str!("../../../e2e/config/policy.yaml");

/// The daemon's name on the project's network, and its listeners.
pub const DAEMON: &str = "writd";
pub const AGENTS_URL: &str = "ssh://writd:2222";
pub const APPROVALS_SSH: &str = "ssh://writd:2223";
pub const APPROVALS_HTTPS: &str = "https://writd:8443";

/// The repository reached over HTTPS with a token (`https://forgejo-https:3443`), and its
/// credential's id.
pub const HTTPS_REPO: &str = "https";
pub const HTTPS_CREDENTIAL: &str = "token-https";

/// The reader's name in the daemon's `readers` file.
pub const READER: &str = "e2e-approver";

/// What the setup saw: the `operator_setup` scenario checks it.
#[derive(Debug, Clone)]
pub struct Report {
    /// The configuration path `writd` was started on (relative, from its directory).
    pub config_path: String,
    /// The commands that print a key, and what each printed, all run while no approvers
    /// (and no readers) file existed yet.
    pub before_approvers: Vec<(String, String)>,
    /// `<id> <key> (repos: …)` lines of `writd upstream-keys`.
    pub upstream_keys: Vec<String>,
    /// `<id> <key> (templates: …)` lines of `writd signing-keys`.
    pub signing_keys: Vec<String>,
    pub host_key: String,
    pub tls_fingerprint: String,
    /// The line pinning Forgejo in `upstream_known_hosts`, and what Forgejo publishes.
    pub pinned_upstream: String,
    pub published_upstream: String,
    /// What `ssh-keygen -lf upstream_known_hosts` printed (the fingerprint to compare).
    pub upstream_fingerprint: String,
    /// The line `writ reader` printed.
    pub reader_line: String,
}

/// Runs a command the operator guide shows, exactly as written there (`command` is checked
/// against the guide by `tool/check-e2e.py`), with its placeholders filled in. It must exit
/// 0; its stdout.
pub fn doc_step(host: &Host, command: &'static str, fill: &[(&str, &str)]) -> String {
    host.ok(&filled(command, fill))
}

/// The same, with `stdin` written to it (what the operator pastes).
pub fn doc_step_with(
    host: &Host,
    command: &'static str,
    fill: &[(&str, &str)],
    stdin: &[u8],
) -> String {
    let out = host.run_with(&filled(command, fill), stdin);
    assert_eq!(out.status.code(), Some(0), "{command}: {}", stderr(&out));
    stdout(&out)
}

/// The same, for a step the guide shows failing (a refused push): it must exit `code`; its
/// output.
pub fn doc_step_fails(
    host: &Host,
    command: &'static str,
    fill: &[(&str, &str)],
    code: i32,
) -> std::process::Output {
    let out = host.run(&filled(command, fill));
    assert_eq!(
        out.status.code(),
        Some(code),
        "{command}\n--- stdout\n{}--- stderr\n{}",
        stdout(&out),
        stderr(&out)
    );
    out
}

/// The same, started in the background (the daemon), its stderr appended to `log`.
pub fn doc_step_detached(host: &Host, command: &'static str, fill: &[(&str, &str)], log: &str) {
    let script = format!("{} 2>>{log} >/dev/null", filled(command, fill));
    let out = std::process::Command::new("docker")
        .args(["exec", "-d", "-u", &host.user, "-w", &host.dir])
        .arg(host.container.name())
        .args(["sh", "-c", &script])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{script}: {}", stderr(&out));
}

fn filled(command: &str, fill: &[(&str, &str)]) -> String {
    let mut text = command.to_owned();
    for (placeholder, value) in fill {
        assert!(text.contains(placeholder), "{command} has no {placeholder}");
        text = text.replace(placeholder, value);
    }
    text
}

/// Waits until the daemon announced its listeners `times` times in `writd.log` (once per
/// start: the first start, then each restart).
pub fn wait_started(operator: &Host, times: usize) {
    eventually("writd's listeners", Duration::from_secs(90), || {
        let log = operator.run("cat writd.log 2>/dev/null");
        let log = stdout(&log);
        let count = |needle: &str| log.lines().filter(|l| l.contains(needle)).count();
        // `writd: <reason>` is how it exits on a fatal error: no need to wait any longer.
        if log.lines().any(|l| l.starts_with("writd: ")) {
            panic!("writd did not start:\n{log}");
        }
        count("approval API (HTTPS)") >= times
            && count("role=Agents") >= times
            && count("role=Approvals") >= times
    });
}

/// The whole setup, from nothing; the stack ready for the scenarios.
pub fn run() -> Stack {
    let forgejo = Forgejo::create_accounts();
    let operator = Host::new("writd", "writ", "/home/writ");
    let approver_home = Host::new("agent", "approver", "/home/approver");
    let agents_home = Host::new("agent", "agent", "/home/agent");
    let nothing_yet = || {
        let out = operator.run("test ! -e approvers && test ! -e readers");
        assert_eq!(
            out.status.code(),
            Some(0),
            "approvers or readers exist already"
        );
    };

    // 1. The daemon's files, with paths relative to its configuration.
    nothing_yet();
    operator.write("writd.yaml", WRITD_YAML, "0644");
    operator.write("policy.yaml", POLICY_YAML, "0644");
    let mut before_approvers = Vec::new();

    // 2. The upstream credentials, each added on its repository as a deploy key.
    let upstream = doc_step(&operator, "writd upstream-keys writd.yaml", &[]);
    before_approvers.push((
        "writd upstream-keys writd.yaml".to_owned(),
        upstream.clone(),
    ));
    let upstream_keys: Vec<String> = upstream.lines().map(str::to_owned).collect();
    for line in &upstream_keys {
        let (key, repos) = split_key_line(line, "repos");
        for repo in repos {
            forgejo.create_repo(&repo);
            forgejo.add_deploy_key(&repo, &key);
        }
    }

    // The HTTPS upstream's token: one made on the account for repositories, alone in its file
    // in the keystore (pasted, as the guide says); the HTTPS front's certificate is the
    // daemon's `mirrors.ca_certs` (no system CA signed it).
    forgejo.create_repo(HTTPS_REPO);
    let token = forgejo.repository_token("writd-https-upstream");
    doc_step_with(
        &operator,
        "(umask 077 && mkdir -p data/keys/tokens && cat > data/keys/tokens/<id>)",
        &[("<id>", HTTPS_CREDENTIAL)],
        format!("{token}\n").as_bytes(),
    );
    let front = Container::of("forgejo-https").run_as("front", "cat /tls/cert.pem");
    assert_eq!(front.status.code(), Some(0), "{}", stderr(&front));
    operator.write("upstream_ca.pem", &stdout(&front), "0644");

    // 3. Forgejo's host key, pinned, and checked against the one it publishes.
    doc_step(
        &operator,
        "ssh-keyscan -t ed25519 <host> >> upstream_known_hosts",
        &[("<host>", "forgejo")],
    );
    let upstream_fingerprint = doc_step(&operator, "ssh-keygen -lf upstream_known_hosts", &[]);
    // The key line (ssh-keyscan also writes a `# host:port SSH-2.0-…` comment, which the
    // daemon drops).
    let pinned_upstream = pinned_line(&operator.read("upstream_known_hosts"));
    let published_upstream = forgejo.published_host_key();
    assert_eq!(
        pinned_upstream,
        format!("forgejo {published_upstream}"),
        "the scan is not the key Forgejo publishes"
    );

    // 4. The agent signing keys (to register on an account, for verified commits).
    let signing = doc_step(&operator, "writd signing-keys writd.yaml", &[]);
    before_approvers.push(("writd signing-keys writd.yaml".to_owned(), signing.clone()));
    let signing_keys: Vec<String> = signing.lines().map(str::to_owned).collect();

    // 5. The daemon's identity, pinned on the clients.
    let host_key = doc_step(&operator, "writd host-key writd.yaml", &[])
        .trim()
        .to_owned();
    before_approvers.push(("writd host-key writd.yaml".to_owned(), host_key.clone()));
    let tls_fingerprint = doc_step(&operator, "writd tls-fingerprint writd.yaml", &[])
        .trim()
        .to_owned();
    before_approvers.push((
        "writd tls-fingerprint writd.yaml".to_owned(),
        tls_fingerprint.clone(),
    ));
    nothing_yet();
    agents_home.ok("mkdir -m 700 -p .writ agents");
    agents_home.write(
        ".writ/known_hosts",
        &format!("[{DAEMON}]:2222 {host_key}\n"),
        "0644",
    );
    agents_home.ok("git config --global user.name Operator && \
         git config --global user.email operator@writ.invalid && \
         git config --global init.defaultBranch main");
    approver_home.ok("mkdir -m 700 -p .writ");
    approver_home.write(
        ".writ/known_hosts",
        &format!("[{DAEMON}]:2223 {host_key}\n"),
        "0644",
    );
    approver_home.write(
        ".writ/tls_pins",
        &format!("[{DAEMON}]:8443 {tls_fingerprint}\n"),
        "0644",
    );
    approver_home.write(
        "client.env",
        &format!(
            "export WRIT_HOME=\"$HOME/.writ\"\n\
             export WRIT_APPROVAL_URL={APPROVALS_HTTPS}\n\
             export WRIT_APPROVAL_AGENT=\"$HOME/agent.sock\"\n"
        ),
        "0644",
    );
    let approver = approver_home.with("/home/approver", Some("client.env"));

    // 6. The reader (the approver's machine's key for the approval API) and the approver
    // (the approval key, in a throwaway ssh-agent standing in for Secretive).
    let reader_line = doc_step(&approver, "writ reader <name>", &[("<name>", READER)])
        .trim()
        .to_owned();
    operator.write("readers", &format!("{reader_line}\n"), "0644");
    approver.ok("ssh-agent -a \"$WRIT_APPROVAL_AGENT\" >/dev/null && \
         ssh-keygen -q -t ed25519 -N '' -C approval -f .writ/approval && \
         SSH_AUTH_SOCK=\"$WRIT_APPROVAL_AGENT\" ssh-add -q .writ/approval && \
         rm .writ/approval && mv .writ/approval.pub .writ/approver.pub");
    let approval_key = approver.read(".writ/approver.pub");
    operator.write(
        "approvers",
        &format!("{READER} {}\n", approval_key.trim()),
        "0644",
    );

    // 7. The daemon, started from its directory on a relative path.
    doc_step_detached(&operator, "writd run writd.yaml", &[], "writd.log");
    wait_started(&operator, 1);

    Stack {
        operator,
        approver,
        agents_home,
        forgejo,
        report: Report {
            config_path: "writd.yaml".to_owned(),
            before_approvers,
            upstream_keys,
            signing_keys,
            host_key,
            tls_fingerprint,
            pinned_upstream,
            published_upstream,
            upstream_fingerprint,
            reader_line,
        },
    }
}

/// The one line of a `known_hosts` file that isn't a comment.
pub fn pinned_line(text: &str) -> String {
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(lines.len(), 1, "one pinned key: {text}");
    lines[0].trim().to_owned()
}

/// `<id> <type> <base64> (<what>: a, b)` → the key (`<type> <base64>`) and the names.
pub fn split_key_line(line: &str, what: &str) -> (String, Vec<String>) {
    let mut words = line.splitn(4, ' ');
    let (_id, kind, data) = (words.next(), words.next().unwrap(), words.next().unwrap());
    let names = words
        .next()
        .and_then(|rest| rest.strip_prefix(&format!("({what}: ")))
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or_else(|| panic!("unreadable line: {line}"));
    (
        format!("{kind} {data}"),
        names.split(", ").map(str::to_owned).collect(),
    )
}
