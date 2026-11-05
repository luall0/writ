//! Scenario 11, a broken or hostile upstream, for real: Forgejo stopped (fetch and push
//! refused, working again once it is back), its host key changed (refused, nothing learned;
//! working again on the pinned key), its deploy key removed (refused with Forgejo's reason).
//! Each restores what it broke, so the stack is left working.

use std::time::Duration;

use writ_e2e::Stack;
use writ_e2e::agent::expect;
use writ_e2e::docker::eventually;
use writ_e2e::forgejo;
use writ_e2e::setup::split_key_line;
use writ_e2e::stderr;

use crate::wired;

/// Waits until Forgejo answers again: its API, and its SSH server as the daemon sees it.
fn wait_forgejo(stack: &Stack) {
    forgejo::wait_ready();
    eventually("Forgejo's SSH server", Duration::from_secs(120), || {
        let out = stack
            .operator
            .run("ssh-keyscan -t ed25519 forgejo 2>/dev/null");
        writ_e2e::stdout(&out).contains("ssh-ed25519")
    });
}

/// Puts Forgejo back as the setup left it when the scenario ends, passed or failed: its
/// pinned host key, started, answering. A scenario that fails halfway must not leave the
/// others without their remote.
struct Restore<'a>(&'a Stack);

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        // Never a panic here: during a failure's unwinding it would abort every scenario.
        let stack = self.0;
        let name = stack.forgejo.container.name();
        let docker = |verb: &str| {
            let _ = std::process::Command::new("docker")
                .args([verb, name])
                .output();
        };
        docker("start");
        let keys = "/data/ssh/ssh_host_ed25519_key";
        let _ = stack.forgejo.container.run_as(
            "root",
            &format!(
                "if [ -f /data/ssh/pinned ]; then mv /data/ssh/pinned {keys} && \
                 mv /data/ssh/pinned.pub {keys}.pub; fi"
            ),
        );
        docker("restart");
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wait_forgejo(stack);
            // Its deploy key, if a failure left it removed.
            if stack.forgejo.deploy_keys("hostile").is_empty() {
                let line = stack
                    .report
                    .upstream_keys
                    .iter()
                    .find(|l| l.starts_with("upstream-hostile "))
                    .unwrap();
                stack
                    .forgejo
                    .add_deploy_key("hostile", &split_key_line(line, "repos").0);
            }
        }));
    }
}

#[test]
#[ignore = "end to end: make e2e"]
fn a_stopped_a_changed_and_a_closed_upstream_are_refused_with_their_reasons() {
    let stack = Stack::exclusive();
    let _restore = Restore(&stack);
    let agent = stack.agent("hostile");
    let (lease, w) = wired(&stack, &agent, "hostile");
    agent.ok_in(&w, "git checkout -q -b agent/hostile");
    agent.commit(&w, &lease, "a.txt", "a");
    expect(
        &agent.in_dir(&w, "writ git push -q origin HEAD"),
        0,
        "the first push",
    );

    // Stopped: refused, with the reason; working again once it is back.
    stack.forgejo.container.lifecycle("stop");
    let out = agent.in_dir(&w, "writ git fetch origin");
    expect(&out, 128, "a fetch with Forgejo stopped");
    assert!(
        stderr(&out).contains("cannot sync from upstream"),
        "{}",
        stderr(&out)
    );
    let pending = agent.commit(&w, &lease, "b.txt", "b");
    let out = agent.in_dir(&w, "writ git push origin HEAD");
    // Refused before git's receive-pack starts (the daemon syncs first): git's exit 128.
    expect(&out, 128, "a push with Forgejo stopped");
    assert!(
        stderr(&out).contains("cannot sync from upstream"),
        "{}",
        stderr(&out)
    );
    assert!(!stack.audited(&lease, "fetch", "denied").is_empty());
    stack.forgejo.container.lifecycle("start");
    wait_forgejo(&stack);
    expect(
        &agent.in_dir(&w, "writ git fetch -q origin"),
        0,
        "a fetch once it is back",
    );
    expect(
        &agent.in_dir(&w, "writ git push -q origin HEAD"),
        0,
        "the push once it is back",
    );
    assert_eq!(
        stack.forgejo.branch("hostile", "agent/hostile").as_deref(),
        Some(pending.as_str())
    );

    // Another host key: refused, the pin unchanged; back on the pinned key, working again.
    let keys = "/data/ssh/ssh_host_ed25519_key";
    let out = stack.forgejo.container.run_as(
        "root",
        &format!(
            "cp -p {keys} /data/ssh/pinned && cp -p {keys}.pub /data/ssh/pinned.pub && \
             rm {keys} {keys}.pub && ssh-keygen -q -t ed25519 -N '' -f {keys}"
        ),
    );
    expect(&out, 0, "a new host key for Forgejo");
    stack.forgejo.container.lifecycle("restart");
    wait_forgejo(&stack);
    let new_key = stack.forgejo.published_host_key();
    assert_ne!(new_key, stack.report.published_upstream);
    let out = agent.in_dir(&w, "writ git fetch origin");
    expect(&out, 128, "a fetch from a host with another key");
    assert!(
        stderr(&out).contains("cannot sync from upstream"),
        "{}",
        stderr(&out)
    );
    // The policy in force (written back to the daemon's file) still pins the old key alone.
    let policy = stack.operator.read("policy.yaml");
    assert!(
        policy.contains(&stack.report.published_upstream) && !policy.contains(&new_key),
        "the daemon learned the new key"
    );
    let out = stack.forgejo.container.run_as(
        "root",
        &format!("mv /data/ssh/pinned {keys} && mv /data/ssh/pinned.pub {keys}.pub"),
    );
    expect(&out, 0, "the pinned key back");
    stack.forgejo.container.lifecycle("restart");
    wait_forgejo(&stack);
    assert_eq!(
        stack.forgejo.published_host_key(),
        stack.report.published_upstream
    );
    expect(
        &agent.in_dir(&w, "writ git fetch -q origin"),
        0,
        "a fetch on the pinned key",
    );

    // The deploy key removed: refused with Forgejo's reason; added back, through again.
    for id in stack.forgejo.deploy_keys("hostile") {
        stack.forgejo.api_ok(
            "DELETE",
            &format!("/repos/{}/hostile/keys/{id}", forgejo::OWNER),
            None,
            204,
        );
    }
    let closed = agent.commit(&w, &lease, "c.txt", "c");
    let out = agent.in_dir(&w, "writ git push origin HEAD");
    expect(&out, 128, "a push without the deploy key");
    let err = stderr(&out);
    assert!(
        err.contains("cannot sync from upstream") && err.contains("Permission denied"),
        "Forgejo's reason: {err}"
    );
    assert_eq!(
        stack.forgejo.branch("hostile", "agent/hostile").as_deref(),
        Some(pending.as_str())
    );
    let line = stack
        .report
        .upstream_keys
        .iter()
        .find(|l| l.starts_with("upstream-hostile "))
        .unwrap();
    stack
        .forgejo
        .add_deploy_key("hostile", &split_key_line(line, "repos").0);
    expect(
        &agent.in_dir(&w, "writ git push -q origin HEAD"),
        0,
        "the push with the key back",
    );
    assert_eq!(
        stack.forgejo.branch("hostile", "agent/hostile").as_deref(),
        Some(closed.as_str())
    );
}
