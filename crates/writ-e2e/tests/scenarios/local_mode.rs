//! Scenario 24, local mode on Linux (M7.1): one machine (the `local` container), the daemon as
//! the system user `writd`, started as its systemd unit starts it (`setpriv`: the ambient
//! `CAP_SYS_PTRACE` its process reader alone keeps, the bounding set that one only, no new
//! privileges), its files as `make install` lays them out (`/etc/writ/writd.yaml` root's,
//! `/var/lib/writ` its own, the sockets in `/run/writ` through the `writ` group); the agent and
//! the approver as `dev`, in that group, over the Unix sockets; the upstream on Forgejo.
//!
//! What it proves, which the Mac can only check by hand: the daemon holds no capability once
//! started and its process reader `CAP_SYS_PTRACE` alone; `dev` can't read the daemon's files
//! or attach to it or its reader (`cat`, `strace -p`, `gdb -p`); the M6 workflow under
//! `writ run` (a ticket bound to the session by the daemon from the kernel, a commit signed,
//! pushed to Forgejo, the chain of each operation in its audit line, read by the reader across
//! users); the same lease refused outside the session (`caller`); the lease revoked when the
//! session's root ends; and SIGTERM, what systemd's stop sends, an orderly stop that takes the
//! reader with it.

use std::time::Duration;

use serde_json::Value;
use writ_e2e::agent::{expect, submitted_id};
use writ_e2e::docker::eventually;
use writ_e2e::forgejo::{BASE, OWNER};
use writ_e2e::setup::split_key_line;
use writ_e2e::{Host, Stack, stdout};

const REPO: &str = "local";
const PASSPHRASE: &str = "the local scenario's passphrase";
const LOG: &str = "/var/log/writd.log";
const AUDIT: &str = "/var/lib/writ/state/audit.jsonl";

/// The daemon's configuration, as `make install`'s `local` setup writes it on Linux
/// (`deploy/setups/local-linux.sh`), and `fresh_for: 0s` (every fetch asks Forgejo first).
const WRITD_YAML: &str = "\
state_dir: /var/lib/writ/state
policy: /var/lib/writ/policy.yaml
approvers: /var/lib/writ/approvers
readers: /var/lib/writ/readers
keystore: { sealed: { dir: /var/lib/writ/keys, boot: /var/lib/writ/boot } }
mirrors: { fresh_for: 0s }
transports:
  agents: [{ unix: /run/writ/agents.sock }]
  approvals:
    ssh: [{ unix: /run/writ/approvals.sock }]
    https: []
attestor: linux_process_chain
session_watcher: linux
notifiers: []
";

/// The policy: one repository, under a template that requires a session binding.
fn policy(forgejo_key: &str) -> String {
    format!(
        "keys:
  agent-local: {{ use: signing, format: ssh, algorithm: ed25519 }}
  upstream-local: {{ use: upstream, kind: ssh, algorithm: ed25519 }}
upstream_hosts:
  forgejo: [\"{forgejo_key}\"]
repos:
  {REPO}: {{ upstream: \"ssh://git@forgejo/{OWNER}/{REPO}.git\", upstream_credential: upstream-local, templates: [local], protected_refs: [\"refs/heads/main\"] }}
templates:
  local:
    operations: [fetch, commit_sign, push]
    branches: [\"agent/*\"]
    committer_emails: [\"agent@writ.invalid\"]
    signing_key: agent-local
    max_ttl: 2h
    max_signatures: 40
    max_pushes: 20
    max_ops_per_minute: 100
    max_push_size: 10MB
    require_session: true
"
    )
}

/// The ticket the agent writes: no `caller`, `writ request` under `writ run` binds it.
const TICKET: &str = "repos:
  local:
    operations: [fetch, commit_sign, push]
    branches: [\"agent/*\"]
common:
  committer_emails: [\"agent@writ.invalid\"]
ticket:
  title: \"e2e: local mode on Linux\"
  task: \"Commit and push from a session\"
limits:
  ttl: 1h
";

/// The harness `writ run` starts: the M6 workflow, then it waits on a FIFO the scenario
/// writes to end the session.
const HARNESS: &str = "set -e
cd ~/work
writ request ~/ticket.yaml
writ init local --agents none
echo work > f && git add f
writ git commit -q -m work
writ git push -q origin HEAD:refs/heads/agent/local
touch ~/pushed
cat ~/go >/dev/null
";

/// The audit lines with `event` and `result` about `lease`.
fn audited(root: &Host, lease: &str, event: &str, result: &str) -> Vec<Value> {
    root.read(AUDIT)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|e| e["event"] == event && e["result"] == result)
        .filter(|e| e["lease"] == lease || e["ticket"] == lease)
        .collect()
}

/// A process's capability sets (`CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb`), as root
/// reads them.
fn capabilities(root: &Host, pid: &str) -> Vec<String> {
    root.ok(&format!("grep ^Cap /proc/{pid}/status"))
        .lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

/// The pid of the one process whose command line is exactly `command`.
fn pid_of(root: &Host, command: &str) -> String {
    let pid = root.ok(&format!("pgrep -x -f '{command}'"));
    assert_eq!(pid.lines().count(), 1, "{command}: {pid}");
    pid.trim().to_owned()
}

#[test]
#[ignore = "end to end: make e2e"]
fn local_mode_on_linux_binds_a_lease_to_its_session_and_keeps_the_daemon_out_of_reach() {
    let stack = Stack::shared();
    let root = Host::new("local", "root", "/root");
    let daemon = Host::new("local", "writd", "/var/lib/writ");
    let dev = Host::new("local", "dev", "/home/dev");

    // The daemon's files, as the installer lays them out.
    let forgejo_key = stack.forgejo.published_host_key();
    root.write("/etc/writ/writd.yaml", WRITD_YAML, "0644");
    daemon.write("policy.yaml", &policy(forgejo_key.trim()), "0644");
    dev.ok("mkdir -m 700 .writ");
    let reader = dev.ok("writ reader dev-local");
    daemon.write("readers", &reader, "0644");
    dev.ok("ssh-agent -a \"$HOME/agent.sock\" >/dev/null && \
         ssh-keygen -q -t ed25519 -N '' -C approval -f .writ/approval && \
         SSH_AUTH_SOCK=\"$HOME/agent.sock\" ssh-add -q .writ/approval && \
         rm .writ/approval && mv .writ/approval.pub .writ/approver.pub");
    let approval = dev.read(".writ/approver.pub");
    // The approver's agent, standing in for the hardware key that asks for a touch.
    dev.write(
        "approver.env",
        "export WRIT_APPROVAL_AGENT=\"$HOME/agent.sock\"\n",
        "0644",
    );
    let approver = dev.with("/home/dev", Some("approver.env"));
    daemon.write("approvers", &format!("dev {}", approval.trim()), "0644");
    let made = daemon.run_with(
        "writd init /etc/writ/writd.yaml",
        format!("{PASSPHRASE}\n").as_bytes(),
    );
    assert!(
        expect(&made, 0, "writd init")
            .0
            .starts_with("keystore made: ")
    );
    for line in daemon
        .ok("writd upstream-keys /etc/writ/writd.yaml")
        .lines()
    {
        let (key, repos) = split_key_line(line, "repos");
        assert_eq!(repos, [REPO]);
        stack.forgejo.create_repo(REPO);
        stack.forgejo.add_deploy_key(REPO, &key);
    }
    let host_key = daemon.ok("writd host-key /etc/writ/writd.yaml");
    dev.write(
        ".writ/known_hosts",
        &format!("writ-local {host_key}"),
        "0600",
    );
    dev.write(
        ".writ/config",
        "url = unix:/run/writ/agents.sock\napproval_url = unix:/run/writ/approvals.sock\n",
        "0600",
    );

    // Started as the unit starts it: systemd's RuntimeDirectory, then writd as `writd` with
    // CAP_SYS_PTRACE ambient and bounding, nothing else.
    root.ok(&format!(
        "install -d -m 0750 -o writd -g writ /run/writ && \
         ( setpriv --reuid=writd --regid=writ --clear-groups --inh-caps=+sys_ptrace \
           --ambient-caps=+sys_ptrace --bounding-set=-all,+sys_ptrace --no-new-privs \
           env WRIT_LOG=info /usr/local/bin/writd run /etc/writ/writd.yaml \
           >>{LOG} 2>&1 </dev/null & )"
    ));
    eventually(
        "the local daemon's sockets",
        Duration::from_secs(60),
        || {
            let log = stdout(&root.run(&format!("cat {LOG}")));
            assert!(
                !log.lines().any(|l| l.starts_with("writd: ")),
                "writd did not start:\n{log}"
            );
            log.contains("listener=unix /run/writ/agents.sock role=Agents")
                && log.contains("listener=unix /run/writ/approvals.sock role=Approvals")
        },
    );
    let log = root.read(LOG);
    assert!(
        log.contains("the process reader started: it alone keeps CAP_SYS_PTRACE")
            && log.contains("every capability dropped"),
        "{log}"
    );
    let unsealed = approver.run_with("writ unseal", format!("{PASSPHRASE}\n").as_bytes());
    assert!(
        expect(&unsealed, 0, "writ unseal")
            .0
            .contains("Unsealed (signed by SHA256:")
    );

    // The daemon holds no capability; its reader CAP_SYS_PTRACE alone (bit 19), nothing it
    // could pass on.
    let writd = pid_of(&root, "/usr/local/bin/writd run /etc/writ/writd.yaml");
    let reader = pid_of(&root, "/usr/local/bin/writd proc-reader");
    let none = "0000000000000000";
    let ptrace = "0000000000080000";
    assert_eq!(
        capabilities(&root, &writd),
        [
            format!("CapInh: {none}"),
            format!("CapPrm: {none}"),
            format!("CapEff: {none}"),
            format!("CapBnd: {ptrace}"),
            format!("CapAmb: {none}"),
        ]
    );
    assert_eq!(
        capabilities(&root, &reader),
        [
            format!("CapInh: {none}"),
            format!("CapPrm: {ptrace}"),
            format!("CapEff: {ptrace}"),
            format!("CapBnd: {ptrace}"),
            format!("CapAmb: {none}"),
        ]
    );
    assert_eq!(root.ok(&format!("ps -o ppid= -p {reader}")).trim(), writd);

    // `dev` (so any agent) can't read the daemon's files, nor attach to it or its reader.
    for (what, script) in [
        ("its directory", "ls /var/lib/writ".to_owned()),
        (
            "the keystore",
            "cat /var/lib/writ/keys/identity.age".to_owned(),
        ),
        ("its memory", format!("cat /proc/{writd}/mem")),
    ] {
        let out = dev.run(&script);
        assert_ne!(out.status.code(), Some(0), "{what}: {}", stdout(&out));
        assert!(
            writ_e2e::stderr(&out).contains("Permission denied"),
            "{what}: {}",
            writ_e2e::stderr(&out)
        );
    }
    for pid in [&writd, &reader] {
        let traced = dev.run(&format!("timeout 10 strace -p {pid} -e trace=none"));
        assert_ne!(traced.status.code(), Some(0));
        assert!(
            writ_e2e::stderr(&traced).contains("Operation not permitted"),
            "{}",
            writ_e2e::stderr(&traced)
        );
        let debugged = dev.run(&format!("timeout 30 gdb -batch -nx -p {pid} 2>&1"));
        assert!(
            stdout(&debugged).contains("ptrace: Operation not permitted"),
            "{}",
            stdout(&debugged)
        );
    }

    // The M6 workflow under `writ run`: the ticket bound to the session by the daemon.
    let clone = format!(
        "{}/{OWNER}/{REPO}.git",
        BASE.replace(
            "http://",
            &format!("http://{OWNER}:{}@", stack.forgejo.token)
        )
    );
    dev.ok(&format!(
        "git clone -q {clone} work && git -C work config user.name Agent && \
         git -C work config user.email agent@writ.invalid && mkfifo go"
    ));
    dev.write("ticket.yaml", TICKET, "0644");
    dev.write("harness.sh", HARNESS, "0644");
    let session = dev.start("writ run -- sh ~/harness.sh");
    let lease = submitted_id(&session.first);
    let signed = approver.run(&format!("writ sign {lease} --yes"));
    let (shown, _) = expect(&signed, 0, "writ sign");
    assert!(
        shown.contains("caller             descends from /usr/local/bin/writ (pid ")
            // Linux has no code signature to show.
            && !shown.contains(", signed "),
        "{shown}"
    );
    eventually("the session's push", Duration::from_secs(60), || {
        dev.run("test -e pushed").status.code() == Some(0)
    });
    let head = dev.ok("git -C work rev-parse HEAD");
    assert_eq!(
        stack.forgejo.branch(REPO, "agent/local").as_deref(),
        Some(head.trim())
    );
    // Each operation's chain, read across users by the reader: the agent's tools, then the
    // session's root (`writ run`, its executable /usr/local/bin/writ), then its ancestors.
    let pushes = audited(&root, &lease, "push", "allowed");
    assert_eq!(pushes.len(), 1, "{pushes:?}");
    let chain: Vec<&str> = pushes[0]["process_chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert!(chain.contains(&"/usr/local/bin/writ"), "{chain:?}");
    assert!(chain.contains(&"/usr/bin/git"), "{chain:?}");
    assert!(!chain.iter().any(|p| p.contains("unbindable")), "{chain:?}");

    // Outside the session (another login of `dev`): the same lease refused, the caller's
    // chain not the session's.
    let outside = dev.run("cd work && writ git fetch -q origin");
    assert_eq!(
        outside.status.code(),
        Some(128),
        "{}",
        writ_e2e::stderr(&outside)
    );
    eventually("the refusal's audit line", Duration::from_secs(30), || {
        audited(&root, &lease, "connect", "denied")
            .iter()
            .any(|e| e["code"] == "caller")
    });

    // The session ends: writ run exits with its harness, the lease is revoked.
    dev.ok("echo > go");
    let (status, said, err) = session.finish();
    assert!(status.success(), "{said}{err}");
    eventually(
        "the session's lease revoked",
        Duration::from_secs(30),
        || !audited(&root, &lease, "revoke", "done").is_empty(),
    );

    // SIGTERM (systemd's stop): an orderly stop, the reader gone with it.
    root.ok(&format!("kill -TERM {writd}"));
    eventually(
        "writd and its reader ended",
        Duration::from_secs(60),
        || root.run("pgrep -f 'writd (run|proc-reader)'").status.code() == Some(1),
    );
    let log = root.read(LOG);
    assert!(log.contains("stopping"), "{log}");
}
