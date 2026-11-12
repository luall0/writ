//! The operator setup, from nothing, in the order the operator guide gives it
//! (docs/operators/setup.md): the daemon's files with relative paths, the approver's machine
//! (the reader and the approval key listed), the sealed keystore made by `writd init` (the
//! passphrase on stdin), the upstream credentials added on Forgejo as deploy keys (the HTTPS
//! front's certificate trusted), Forgejo's host key pinned and checked against the one it
//! publishes, the signing keys listed, the daemon's host key and TLS fingerprint pinned on the
//! clients, `writd run writd.yaml` started from the daemon's directory on a relative path,
//! `writ unseal` from the approver's machine; then from there, with `writ admin` only, a repo
//! on a new host (Forgejo under another name, scanned by the daemon on a terminal), with a new
//! template and a new upstream key (registered on Forgejo as the change printed it), checked
//! once registered; and the HTTPS repo's token added with `writ admin token`.
//!
//! Every command the guide shows runs through [`doc_step`], with its text exactly as the
//! guide writes it (placeholders such as `<host>` filled in): `tool/check-e2e.py` checks that
//! each command of the guide's `sh` blocks is run here (or by the `notes` scenario) and each
//! one run here is in the guide, so a step changed in one is changed in the other. The setup runs once per stack
//! ([`crate::stack`]); what it saw is the [`Report`] the `operator_setup` scenario checks.

use std::time::Duration;

use crate::docker::{Container, Host, eventually, stderr, stdout};
use crate::forgejo::Forgejo;
use crate::stack::Stack;

/// The daemon's configuration and registry, as the operator writes them (`e2e/config/`).
pub const WRITD_YAML: &str = include_str!("../../../e2e/config/writd.yaml");
pub const POLICY_YAML: &str = include_str!("../../../e2e/config/policy.yaml");

/// The key `POLICY_YAML` pins Forgejo's host to until the setup puts the scanned one there.
pub const PLACEHOLDER_HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

/// The daemon's name on the project's network, and its listeners.
pub const DAEMON: &str = "writd";
pub const AGENTS_URL: &str = "ssh://writd:2222";
pub const APPROVALS_SSH: &str = "ssh://writd:2223";
pub const APPROVALS_HTTPS: &str = "https://writd:8443";

/// The repository reached over HTTPS with a token (`https://forgejo-https:3443`), and its
/// credential's id.
pub const HTTPS_REPO: &str = "https";
pub const HTTPS_CREDENTIAL: &str = "token-https";
/// A second front for the same repository, with a certificate only the daemon container's
/// system store trusts (not `mirrors.ca_certs`), and the registry's repository behind it: every
/// sync of it refused.
pub const SYSTEM_FRONT: &str = "forgejo-https-system";
pub const SYSTEM_REPO: &str = "https-system";
/// Its token's id: the same Forgejo token, declared for that front's host (a token is sent to
/// its declared host only), so what refuses the sync is the certificate, not a missing token.
pub const SYSTEM_CREDENTIAL: &str = "token-https-system";

/// The repositories behind the proxies (scenario 25): Forgejo under names only the proxies
/// resolve (`forgejo-behind`, `forgejo-https-behind`), the HTTPS one's token (the same Forgejo
/// token, declared for that host), and each proxy's password, as its container sets it
/// (e2e/Dockerfile, e2e/proxy/tinyproxy.conf): a throwaway stack's.
pub const SOCKS_REPO: &str = "behind-socks";
pub const HTTP_REPO: &str = "behind-http";
pub const BEHIND_CREDENTIAL: &str = "token-https-behind";
pub const SOCKS_PASSWORD_ID: &str = "proxy-socks-password";
pub const HTTP_PASSWORD_ID: &str = "proxy-http-password";
pub const SOCKS_PASSWORD: &str = "e2e-socks-proxy-password";
pub const HTTP_PASSWORD: &str = "e2e-http-proxy-password";

/// The reader's name in the daemon's `readers` file.
pub const READER: &str = "e2e-approver";

/// The keystore's passphrase, as the operator types it at `writd init` and the approver at
/// each `writ unseal` (a throwaway stack's).
pub const PASSPHRASE: &str = "the end-to-end stack's passphrase";

/// What the setup saw: the `operator_setup` scenario checks it.
#[derive(Debug, Clone)]
pub struct Report {
    /// The configuration path `writd` was started on (relative, from its directory).
    pub config_path: String,
    /// What `writd init` printed (the recipient, the keys to register).
    pub init_printed: String,
    /// The commands that print a key, and what each printed, all run before the daemon
    /// started: no passphrase.
    pub printed: Vec<(String, String)>,
    /// `<id> <key> (repos: …)` lines of `writd upstream-keys`.
    pub upstream_keys: Vec<String>,
    /// `<id> <key> (templates: …)` lines of `writd signing-keys`.
    pub signing_keys: Vec<String>,
    pub host_key: String,
    pub tls_fingerprint: String,
    /// The key line the scan of Forgejo gave (pinned in the policy), and what Forgejo publishes.
    pub pinned_upstream: String,
    pub published_upstream: String,
    /// What `ssh-keygen -lf forgejo.keys` printed (the fingerprint to compare).
    pub upstream_fingerprint: String,
    /// The line `writ reader` printed.
    pub reader_line: String,
    /// The `https` repo's Forgejo token, as the approver pasted it into `writ admin token`
    /// (the scenarios check it is in clear nowhere on the daemon's host).
    pub https_token: String,
    /// What `writ admin host add` showed for the new host (the daemon's scan), and what
    /// `writ admin repo check` said of the repo added on it.
    pub added_host: String,
    pub added_check: String,
}

/// The repo the setup adds from the approver's machine, on Forgejo under another name, with
/// its own template and upstream key.
pub const ADDED_REPO: &str = "added";
pub const ADDED_HOST: &str = "forgejo-added";
pub const ADDED_TEMPLATE: &str = "added";
pub const ADDED_CREDENTIAL: &str = "upstream-added";

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

/// The same, on a terminal (`script`), `answers` typed one per line: what it showed (the
/// streams merged, rows ending in `\r\n`). It must exit 0.
pub fn doc_step_on_terminal(
    host: &Host,
    command: &'static str,
    fill: &[(&str, &str)],
    answers: &[&str],
) -> String {
    let typed: String = answers.iter().map(|a| format!("{a}\n")).collect();
    let filled = filled(command, fill);
    assert!(!filled.contains('\''), "{filled}");
    let out = host.run_with(
        &format!("script -qec '{filled}' /dev/null"),
        typed.as_bytes(),
    );
    assert_eq!(out.status.code(), Some(0), "{command}: {}", stdout(&out));
    stdout(&out)
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

/// `writ unseal` on the approver's machine, the passphrase typed: after the setup's start and
/// after each restart of the daemon.
pub fn unseal(approver: &Host) {
    let said = doc_step_with(
        approver,
        "writ unseal",
        &[],
        format!("{PASSPHRASE}\n").as_bytes(),
    );
    assert!(said.contains("Unsealed (signed by SHA256:"), "{said}");
}

/// The whole setup, from nothing; the stack ready for the scenarios.
pub fn run() -> Stack {
    let forgejo = Forgejo::create_accounts();
    let operator = Host::new("writd", "writ", "/home/writ");
    let approver_home = Host::new("agent", "approver", "/home/approver");
    let agents_home = Host::new("agent", "agent", "/home/agent");
    let nothing_yet = || {
        let out = operator.run("test ! -e approvers && test ! -e readers && test ! -e data");
        assert_eq!(out.status.code(), Some(0), "a daemon's files exist already");
    };

    // 1. The daemon's files, with paths relative to its configuration.
    nothing_yet();
    operator.write("writd.yaml", WRITD_YAML, "0644");
    operator.write("policy.yaml", POLICY_YAML, "0644");

    // 2. The approver's machine: its reader key (in `readers`) and its approval key (in
    // `approvers`, held by a throwaway ssh-agent standing in for Secretive). `writd init`
    // records both files as their first versions in force.
    approver_home.ok("mkdir -m 700 -p .writ");
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

    // 3. Forgejo's host key, scanned, checked against the one it publishes, and pinned in the
    // policy (the line's last two fields, under `upstream_hosts`).
    doc_step(
        &operator,
        "ssh-keyscan -t ed25519 <host> > <host>.keys",
        &[("<host>", "forgejo")],
    );
    let upstream_fingerprint = doc_step(
        &operator,
        "ssh-keygen -lf <host>.keys",
        &[("<host>", "forgejo")],
    );
    // The key line (ssh-keyscan also writes a `# host:port SSH-2.0-…` comment).
    let pinned_upstream = pinned_line(&operator.read("forgejo.keys"));
    let published_upstream = forgejo.published_host_key();
    assert_eq!(
        pinned_upstream,
        format!("forgejo {published_upstream}"),
        "the scan is not the key Forgejo publishes"
    );
    let pinned_policy = POLICY_YAML.replace(PLACEHOLDER_HOST_KEY, &published_upstream);
    assert_ne!(
        pinned_policy, POLICY_YAML,
        "the policy pins no placeholder key"
    );
    operator.ok("rm policy.yaml");
    operator.write("policy.yaml", &pinned_policy, "0644");

    // 4. The sealed keystore, the passphrase typed once (on stdin, one line).
    let init_printed = doc_step_with(
        &operator,
        "writd init writd.yaml",
        &[],
        format!("{PASSPHRASE}\n").as_bytes(),
    );
    let mut printed = Vec::new();

    // 5. The upstream credentials, each added on its repository as a deploy key.
    let upstream = doc_step(&operator, "writd upstream-keys writd.yaml", &[]);
    printed.push((
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
    // The HTTPS repository, and its token made on the account for repositories (the approver
    // adds it once the daemon is unsealed, step 10); the HTTPS front's certificate is the
    // daemon's `mirrors.ca_certs` (no system CA signed it).
    forgejo.create_repo(HTTPS_REPO);
    forgejo.create_repo(HTTP_REPO);
    let https_token = forgejo.repository_token("writd-https-upstream");
    let front = Container::of("forgejo-https").run_as("front", "cat /tls/cert.pem");
    assert_eq!(front.status.code(), Some(0), "{}", stderr(&front));
    operator.write("upstream_ca.pem", &stdout(&front), "0644");
    // Not the operator's: the test machine's system store trusts the second front (as root),
    // so the daemon is shown to trust `mirrors.ca_certs` alone.
    let system = Container::of(SYSTEM_FRONT).run_as("front", "cat /tls/cert.pem");
    assert_eq!(system.status.code(), Some(0), "{}", stderr(&system));
    let installed = Container::of(DAEMON).run_as(
        "root",
        &format!(
            "cat > /usr/local/share/ca-certificates/{SYSTEM_FRONT}.crt <<'PEM'\n{}PEM\n\
             update-ca-certificates >/dev/null",
            stdout(&system)
        ),
    );
    assert_eq!(installed.status.code(), Some(0), "{}", stderr(&installed));

    // 6. The agent signing keys (to register on an account, for verified commits).
    let signing = doc_step(&operator, "writd signing-keys writd.yaml", &[]);
    printed.push(("writd signing-keys writd.yaml".to_owned(), signing.clone()));
    // One line per key (`<id> <key> (templates: …)`); an OpenPGP key's certificate follows
    // its line, kept apart.
    let signing_keys: Vec<String> = signing
        .lines()
        .filter(|l| l.contains(" (templates: "))
        .map(str::to_owned)
        .collect();

    // 7. The daemon's identity, pinned on the clients.
    let host_key = doc_step(&operator, "writd host-key writd.yaml", &[])
        .trim()
        .to_owned();
    printed.push(("writd host-key writd.yaml".to_owned(), host_key.clone()));
    let tls_fingerprint = doc_step(&operator, "writd tls-fingerprint writd.yaml", &[])
        .trim()
        .to_owned();
    printed.push((
        "writd tls-fingerprint writd.yaml".to_owned(),
        tls_fingerprint.clone(),
    ));
    agents_home.ok("mkdir -m 700 -p .writ agents");
    agents_home.write(
        ".writ/known_hosts",
        &format!("[{DAEMON}]:2222 {host_key}\n"),
        "0644",
    );
    agents_home.ok("git config --global user.name Operator && \
         git config --global user.email operator@writ.invalid && \
         git config --global init.defaultBranch main");
    approver.write(
        ".writ/known_hosts",
        &format!("[{DAEMON}]:2223 {host_key}\n"),
        "0644",
    );
    approver.write(
        ".writ/tls_pins",
        &format!("[{DAEMON}]:8443 {tls_fingerprint}\n"),
        "0644",
    );

    // 8. The daemon, started from its directory on a relative path: sealed.
    doc_step_detached(&operator, "writd run writd.yaml", &[], "writd.log");
    wait_started(&operator, 1);

    // 9. Unsealed from the approver's machine.
    unseal(&approver);

    // 10. A new host, scanned by the daemon on the approver's signature, its key compared with
    // the one Forgejo publishes, then pinned (the second signature).
    let added_host = doc_step_on_terminal(
        &approver,
        "writ admin host add <host>",
        &[("<host>", ADDED_HOST)],
        &["y", "y"],
    );
    assert!(
        added_host.contains(&format!(
            "  ssh-ed25519 {}\r\n",
            upstream_fingerprint.split(' ').nth(1).unwrap_or_default()
        )),
        "{added_host}"
    );
    // 11. Its template, each field asked (fetch only: the fields of signing and pushing not
    // asked).
    let said = doc_step_on_terminal(
        &approver,
        "writ admin template add <template>",
        &[("<template>", ADDED_TEMPLATE)],
        &["fetch", "1h", "0", "0", "10", "0", "", "", "y"],
    );
    assert!(said.contains("Applied: policy is version "), "{said}");
    // 12. Its upstream key, made by the change that declares it, registered on Forgejo as a
    // deploy key with write access from the public half it printed.
    let said = doc_step_with(
        &approver,
        "writ admin key add <id> use=upstream kind=ssh algorithm=ed25519",
        &[("<id>", ADDED_CREDENTIAL)],
        b"y\n",
    );
    let public = said
        .lines()
        .find_map(|l| {
            l.split_once("(register it on the remote): ")
                .map(|(_, key)| key)
        })
        .unwrap_or_else(|| panic!("no public half printed: {said}"));
    let public: Vec<&str> = public.split(' ').take(2).collect();
    forgejo.create_repo(ADDED_REPO);
    forgejo.add_deploy_key(ADDED_REPO, &public.join(" "));
    // 13. The repo, every field given.
    let said = doc_step_with(
        &approver,
        "writ admin repo add <repo> upstream=ssh://git@<host>/<path>.git upstream_credential=<id> templates=<template>",
        &[
            ("<repo>", ADDED_REPO),
            ("<host>", ADDED_HOST),
            ("<path>", &format!("writ/{ADDED_REPO}")),
            ("<id>", ADDED_CREDENTIAL),
            ("<template>", ADDED_TEMPLATE),
        ],
        b"y\n",
    );
    assert!(
        said.contains(&format!("with repo {ADDED_REPO} added")),
        "{said}"
    );
    // 14. Checked: read, synced, written with nothing pushed.
    let added_check = doc_step(
        &approver,
        "writ admin repo check <repo>",
        &[("<repo>", ADDED_REPO)],
    );

    // 15. The HTTPS upstream's token, added from the approver's machine (pasted, then the
    // change signed): encrypted there, sealed on the daemon's host.
    let said = doc_step_with(
        &approver,
        "writ admin token <id>",
        &[("<id>", HTTPS_CREDENTIAL)],
        format!("{https_token}\ny\n").as_bytes(),
    );
    assert!(
        said.contains(&format!("Token {HTTPS_CREDENTIAL} in force (file sha256 ")),
        "{said}"
    );
    let said = doc_step_with(
        &approver,
        "writ admin token <id>",
        &[("<id>", SYSTEM_CREDENTIAL)],
        format!("{https_token}\ny\n").as_bytes(),
    );
    assert!(
        said.contains(&format!("Token {SYSTEM_CREDENTIAL} in force (file sha256 ")),
        "{said}"
    );
    // The repositories behind the proxies: the HTTPS one's token, then each proxy's password.
    for (id, secret) in [
        (BEHIND_CREDENTIAL, https_token.as_str()),
        (SOCKS_PASSWORD_ID, SOCKS_PASSWORD),
        (HTTP_PASSWORD_ID, HTTP_PASSWORD),
    ] {
        let said = doc_step_with(
            &approver,
            "writ admin token <id>",
            &[("<id>", id)],
            format!("{secret}\ny\n").as_bytes(),
        );
        assert!(
            said.contains(&format!("Token {id} in force (file sha256 ")),
            "{said}"
        );
    }

    Stack {
        operator,
        approver,
        agents_home,
        forgejo,
        report: Report {
            config_path: "writd.yaml".to_owned(),
            init_printed,
            printed,
            upstream_keys,
            signing_keys,
            host_key,
            tls_fingerprint,
            pinned_upstream,
            published_upstream,
            upstream_fingerprint,
            reader_line,
            https_token,
            added_host,
            added_check,
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
