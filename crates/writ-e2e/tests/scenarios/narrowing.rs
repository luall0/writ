//! Scenario 2b, narrowing at signature: the approver narrows every term of a ticket with
//! `writ sign`'s flags, the agent is told what changed, and the lease holds to the narrowed
//! terms (a second push past `--max-pushes 1`, a fetch after `--drop-op fetch`, which revokes
//! the lease under `--revoke-on-violation`).

use writ_e2e::Stack;
use writ_e2e::agent::expect;
use writ_e2e::stderr;

const TICKET: &str = "template: feature
scope:
  repos: [narrowing, lifecycle]
  operations: [fetch, commit_sign, push]
  branches: [\"agent/*\"]
  force_push: true
  committer_emails: [\"agent@writ.invalid\", \"second@writ.invalid\"]
ticket:
  title: \"Narrow me\"
  task: \"A ticket the approver narrows\"
limits:
  ttl: 2h
  max_signatures: 10
  max_pushes: 5
  max_ops_per_minute: 100
  max_push_size: 10MB
";

#[test]
#[ignore = "end to end: make e2e"]
fn the_approver_narrows_every_term_and_the_lease_holds_to_them() {
    let stack = Stack::shared();
    let agent = stack.agent("narrowing");
    let id = agent.submit("ticket", TICKET);
    let out = stack.approver.run(&format!(
        "writ sign {id} --yes --ttl 30m --drop-repo lifecycle --drop-op fetch \
         --branch agent/narrow --drop-email second@writ.invalid --max-signatures 3 \
         --max-pushes 1 --max-ops-per-minute 50 --max-push-size 1MB --no-force-push \
         --revoke-on-violation"
    ));
    let (out, _) = expect(&out, 0, "writ sign with every narrowing flag");
    assert!(
        out.contains("Narrowed by you (this is what gets signed)"),
        "{out}"
    );
    let out = agent.run(&format!("writ wait {id}"));
    let (out, _) = expect(&out, 0, "the narrowed lease");
    assert!(out.contains("The approver narrowed the ticket:"), "{out}");

    // The lease's terms, as the agent received them.
    let lease: serde_json::Value =
        serde_json::from_str(&agent.session_file(&id, "lease.json")).unwrap();
    let scope = &lease["scope"];
    assert_eq!(scope["repos"], serde_json::json!(["narrowing"]), "{lease}");
    assert_eq!(
        scope["operations"],
        serde_json::json!(["commit_sign", "push"]),
        "{lease}"
    );
    assert_eq!(
        scope["branches"],
        serde_json::json!(["agent/narrow"]),
        "{lease}"
    );
    assert_eq!(
        scope["committer_emails"],
        serde_json::json!(["agent@writ.invalid"]),
        "{lease}"
    );
    assert_eq!(scope["force_push"], false, "{lease}");
    let limits = &lease["limits"];
    assert_eq!(limits["max_signatures"], 3, "{lease}");
    assert_eq!(limits["max_pushes"], 1, "{lease}");
    assert_eq!(limits["max_ops_per_minute"], 50, "{lease}");
    assert_eq!(limits["max_push_size"], 1_000_000, "{lease}");
    assert_eq!(lease["on_violation"], "revoke_lease", "{lease}");
    let created = lease["created_at"].as_str().unwrap();
    let expires = limits["expires_at"].as_str().unwrap();
    let seconds = |stamp: &str| {
        agent
            .ok(&format!("date -u -d '{stamp}' +%s"))
            .trim()
            .parse::<i64>()
            .unwrap()
    };
    assert_eq!(seconds(expires) - seconds(created), 30 * 60, "{lease}");

    // The lease holds to them: one push, then the next refused for the count.
    agent.clone_from_forgejo(&stack, "narrowing", "work");
    agent.ok_in("work", "writ init narrowing");
    agent.ok_in("work", "git checkout -q -b agent/narrow");
    let first = agent.commit("work", &id, "a.txt", "one");
    expect(
        &agent.in_dir("work", "writ git push origin HEAD"),
        0,
        "the one push",
    );
    assert_eq!(
        stack.forgejo.branch("narrowing", "agent/narrow").as_deref(),
        Some(first.as_str())
    );
    agent.commit("work", &id, "b.txt", "two");
    let out = agent.in_dir("work", "writ git push origin HEAD");
    expect(&out, 1, "a push past --max-pushes");
    assert!(stderr(&out).contains("push"), "{}", stderr(&out));
    assert_eq!(
        stack.forgejo.branch("narrowing", "agent/narrow").as_deref(),
        Some(first.as_str())
    );
    let denied = stack.audited(&id, "push", "denied");
    assert_eq!(denied.last().unwrap()["code"], "limit", "{denied:?}");

    // A fetch, dropped from the lease: a violation, and the lease revoked for it.
    let out = agent.in_dir("work", "writ git fetch origin");
    expect(&out, 128, "a fetch without fetch");
    assert!(
        stderr(&out).contains("fetch not allowed"),
        "{}",
        stderr(&out)
    );
    let denied = stack.audited(&id, "fetch", "denied");
    assert_eq!(denied.last().unwrap()["code"], "operation", "{denied:?}");
    assert_eq!(
        stack.audited(&id, "revoke", "done").len(),
        1,
        "revoked on the violation"
    );
    let all = stack.approver.ok("writ ls --all");
    assert!(
        all.lines()
            .any(|l| l.starts_with(&id) && l.contains("revoked")),
        "{all}"
    );
}
