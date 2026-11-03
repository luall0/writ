//! Scenario 2, the ticket lifecycle: a ticket outside every template rejected; requested and
//! waited for, listed and signed over SSH; submitted from stdin without waiting, refused with
//! signed feedback, revised and signed at the prompt over HTTPS; refused at the prompt, its
//! long text cut unless `--full`; left unsigned (`n`) and withdrawn; an amendment signed and
//! waited for with `--lease`; a lease revoked; a ticket left unsigned until it expires; and
//! every client setting given as a flag instead of the environment.

use std::time::Duration;

use writ_e2e::Stack;
use writ_e2e::agent::{expect, submitted_id, ticket};
use writ_e2e::setup::{AGENTS_URL, APPROVALS_HTTPS, APPROVALS_SSH};

/// A ticket for the `lifecycle` repo with this title, `ticket:` lines and TTL.
fn lifecycle(title: &str, ticket_lines: &str, ttl: &str) -> String {
    format!(
        "template: feature\n\
         scope:\n  repos: [lifecycle]\n  operations: [fetch, commit_sign, push]\n  \
         branches: [\"agent/lifecycle\"]\n  committer_emails: [\"agent@writ.invalid\"]\n\
         ticket:\n  title: \"{title}\"\n{ticket_lines}\
         limits:\n  ttl: {ttl}\n"
    )
}

const TASK: &str = "  task: \"Exercise the ticket lifecycle\"\n";

#[test]
#[ignore = "end to end: make e2e"]
fn tickets_are_requested_signed_refused_revised_amended_and_revoked() {
    let stack = Stack::shared();
    let agent = stack.agent("lifecycle");

    // Outside every template: rejected before it reaches the approver, with the reason.
    let file = agent.ticket_file("outside", &ticket(&["lifecycle"], &["feature/x"], "1h", ""));
    let out = agent.run(&format!("writ request {file}"));
    let (_, err) = expect(&out, 3, "a ticket outside every template");
    assert!(err.contains("feature/x"), "{err}");
    assert!(
        stack.audit().iter().any(|e| e["event"] == "submit"
            && e["result"] == "denied"
            && e["reason"]
                .as_str()
                .is_some_and(|r| r.contains("feature/x"))),
        "no submit denied line"
    );

    // Requested and waited for; the approver lists it and signs it over SSH.
    let (first, running) = agent.request("first", &lifecycle("First", TASK, "1h"));
    let listing = stack.approver.ok("writ ls");
    let line = listing
        .lines()
        .find(|l| l.starts_with(&first))
        .unwrap_or_else(|| panic!("{listing}"));
    assert!(
        line.contains("pending") && line.contains("r1") && line.contains("lifecycle"),
        "{line}"
    );
    assert!(listing.contains("│ First"), "{listing}");
    let out = stack.approver.run(&format!(
        "WRIT_APPROVAL_URL={APPROVALS_SSH} writ sign {first} --yes"
    ));
    let (out, _) = expect(&out, 0, "writ sign over SSH");
    assert!(
        out.contains(&format!("Signed: lease {first} is active.")),
        "{out}"
    );
    let (status, out, err) = running.finish();
    assert_eq!(status.code(), Some(0), "{out}{err}");
    assert!(
        out.contains(&format!("Lease {first} granted until ")),
        "{out}"
    );
    agent.ok(&format!(
        "cd .writ/sessions/{first} && test -s key && test -s key-cert.pub && test -s lease.json \
         && test -s signing_key.pub && test \"$(readlink ../current)\" != ''"
    ));
    let granted = stack.audited(&first, "grant", "allowed");
    assert_eq!(granted.len(), 1);
    assert!(
        granted[0]["approver"]
            .as_str()
            .unwrap()
            .starts_with("SHA256:")
    );

    // From stdin, without waiting; refused with signed feedback.
    let out = agent.run_with(
        "writ request --no-wait -",
        lifecycle("Second", TASK, "1h").as_bytes(),
    );
    let (out, _) = expect(&out, 0, "writ request --no-wait -");
    let second = submitted_id(&out);
    let out = stack.approver.ok(&format!(
        "writ refuse {second} -m 'Too broad: say which files'"
    ));
    assert!(out.contains(&format!("Refused: ticket {second}.")), "{out}");
    let out = agent.run(&format!("writ wait {second}"));
    let (out, _) = expect(&out, 4, "writ wait on a refused ticket");
    assert!(
        out.contains("was refused. The approver's feedback (signed by SHA256:"),
        "{out}"
    );
    assert!(out.contains("Too broad: say which files"), "{out}");
    assert_eq!(stack.audited(&second, "refuse", "done").len(), 1);

    // The revision, from the refused ticket's session: the approver sees what changed and
    // signs at the prompt (over HTTPS).
    let revision = agent.submit(
        "third",
        &lifecycle(
            "Third",
            &format!("{TASK}  expected_paths: [\"notes/**\"]\n  revises: {second}\n"),
            "1h",
        ),
    );
    let out = stack
        .approver
        .run_with(&format!("writ sign {revision}"), b"y\n");
    let (out, _) = expect(&out, 0, "writ sign at the prompt");
    assert!(
        out.contains(&format!(
            "Changes since revision 1 (the refused ticket {second})"
        )),
        "{out}"
    );
    assert!(out.contains("[y]es / [n]o / [r]efuse"), "{out}");
    assert!(
        out.contains(&format!("Signed: lease {revision} is active.")),
        "{out}"
    );
    expect(
        &agent.run(&format!("writ wait {revision}")),
        0,
        "the revision granted",
    );

    // Refused at the prompt, with typed feedback; a long task is cut on screen.
    let long: String = (1..=45).map(|i| format!("    step {i}\n")).collect();
    let long_task = format!("  task: |\n{long}");
    let fourth = agent.submit("fourth", &lifecycle("Fourth", &long_task, "1h"));
    let out = stack
        .approver
        .run_with(&format!("writ sign {fourth}"), b"r\nNot this one\n\n");
    let (out, _) = expect(&out, 0, "a refusal at the prompt");
    assert!(
        out.contains("more lines not shown (writ sign --full shows them)"),
        "{out}"
    );
    assert!(out.contains("step 40") && !out.contains("step 45"), "{out}");
    assert!(out.contains(&format!("Refused: ticket {fourth}.")), "{out}");
    let out = agent.run(&format!("writ wait {fourth}"));
    let (out, _) = expect(&out, 4, "refused at the prompt");
    assert!(out.contains("Not this one"), "{out}");

    // Shown whole with --full; left unsigned (`n`), then withdrawn.
    let fifth = agent.submit("fifth", &lifecycle("Fifth", &long_task, "1h"));
    let out = stack
        .approver
        .run_with(&format!("writ sign {fifth} --full"), b"n\n");
    let (out, _) = expect(&out, 6, "answered no");
    assert!(
        out.contains("step 45") && out.contains("Nothing signed."),
        "{out}"
    );
    let all = stack.approver.ok("writ ls");
    assert!(
        all.lines()
            .any(|l| l.starts_with(&fifth) && l.contains("pending")),
        "{all}"
    );
    let out = stack.approver.ok(&format!("writ revoke {fifth}"));
    assert!(
        out.contains(&format!("Revoked: {fifth} is revoked.")),
        "{out}"
    );
    let out = agent.run(&format!("writ wait {fifth}"));
    let (out, _) = expect(&out, 5, "withdrawn");
    assert!(out.contains("was withdrawn or its lease revoked"), "{out}");

    // An amendment of the revised lease: submitted without waiting, signed, then waited for
    // with --lease (its session is the lease's).
    let amendment = agent.submit(
        "amend",
        &lifecycle(
            "Amend",
            &format!("{TASK}  expected_paths: [\"notes/**\", \"docs/**\"]\n  amends: {revision}\n"),
            "30m",
        ),
    );
    let out = stack.approver.run(&format!("writ sign {amendment} --yes"));
    let (out, _) = expect(&out, 0, "signing the amendment");
    assert!(
        out.contains(&format!(
            "Signed: amendment {amendment} now applies to its lease."
        )),
        "{out}"
    );
    let out = agent.run(&format!("writ wait {amendment} --lease {revision}"));
    let (out, _) = expect(&out, 0, "writ wait --lease");
    assert!(
        out.contains(&format!(
            "Amendment {amendment} signed: lease {revision} now runs under its terms"
        )),
        "{out}"
    );
    assert_eq!(stack.audited(&revision, "amend", "allowed").len(), 1);

    // A lease revoked: listed as such, logged.
    let out = stack.approver.ok(&format!("writ revoke {first}"));
    assert!(
        out.contains(&format!("Revoked: {first} is revoked.")),
        "{out}"
    );
    let all = stack.approver.ok("writ ls --all");
    assert!(
        all.lines()
            .any(|l| l.starts_with(&first) && l.contains("revoked")),
        "{all}"
    );
    assert!(
        all.lines()
            .any(|l| l.starts_with(&second) && l.contains("refused")),
        "{all}"
    );
    assert!(all.contains(&format!("(amends {revision})")), "{all}");
    let active = stack.approver.ok("writ ls");
    assert!(!active.contains(&first), "{active}");
    assert!(
        active
            .lines()
            .any(|l| l.starts_with(&revision) && l.contains("active")),
        "{active}"
    );
    assert_eq!(stack.audited(&first, "revoke", "done").len(), 1);
}

#[test]
#[ignore = "end to end: make e2e"]
fn a_ticket_left_unsigned_expires() {
    // A ticket asks for at least the daemon's `min_ttl`, 30 seconds here
    // (e2e/config/writd.yaml): one second under it is refused, naming it.
    let stack = Stack::shared();
    let agent = stack.agent("lifecycle-expiry");
    let file = agent.ticket_file("too-short", &lifecycle("Too short", TASK, "29s"));
    let out = agent.run(&format!("writ request {file}"));
    let (_, err) = expect(&out, 3, "a ticket under the daemon's min_ttl");
    assert!(
        err.contains("limits.ttl is 29s, under the minimum of 30s"),
        "{err}"
    );
    // Exactly the minimum is taken, and left unsigned, it expires.
    let id = agent.submit("unsigned", &lifecycle("Never signed", TASK, "30s"));
    // `writ wait` returns when the daemon decides: here, its sweep expiring the ticket.
    let out = agent.run_within(&format!("writ wait {id}"), b"", Duration::from_secs(90));
    let (out, _) = expect(&out, 5, "an unsigned ticket's wait");
    assert!(
        out.contains(&format!("Ticket {id} expired before it was signed.")),
        "{out}"
    );
    assert_eq!(stack.audited(&id, "expire", "done").len(), 1);
    let out = stack.approver.run(&format!("writ sign {id} --yes"));
    let (_, err) = expect(&out, 1, "signing an expired ticket");
    assert!(
        err.contains("is expired, not waiting for a signature"),
        "{err}"
    );
}

#[test]
#[ignore = "end to end: make e2e"]
fn every_client_setting_works_as_a_flag() {
    // No WRIT_* in the environment: every setting on the command line.
    let stack = Stack::shared();
    let agent = stack.agent("lifecycle-flags");
    let path = "PATH=/usr/local/bin:/usr/bin:/bin";
    let home = &agent.dir;
    let agent_writ = format!(
        "env -i {path} HOME=/home/agent writ --home {home}/.writ --known-hosts {home}/.writ/known_hosts"
    );
    // `$HOME` is the approver's: the outer shell expands it before `env -i`.
    let dot = "$HOME/.writ";
    let approver_writ = format!(
        "env -i {path} HOME=\"$HOME\" writ --home \"$HOME\"/nowhere \
         --known-hosts {dot}/known_hosts --tls-pins {dot}/tls_pins --reader {dot}/reader"
    );
    let signer = format!("--key {dot}/approver.pub --agent $HOME/agent.sock");

    let file = agent.ticket_file("flags", &lifecycle("Flags", TASK, "1h"));
    let out = agent.run(&format!(
        "{agent_writ} request --url {AGENTS_URL} --no-wait {file}"
    ));
    let id = submitted_id(&expect(&out, 0, "writ request --url").0);
    let out = stack.approver.run(&format!(
        "{approver_writ} ls --approval-url {APPROVALS_SSH}"
    ));
    assert!(expect(&out, 0, "writ ls --approval-url").0.contains(&id));
    let out = stack.approver.run(&format!(
        "{approver_writ} sign {id} --yes --approval-url {APPROVALS_HTTPS} {signer}"
    ));
    expect(&out, 0, "writ sign with flags");
    let out = agent.run(&format!("{agent_writ} wait {id} --url {AGENTS_URL}"));
    assert!(
        expect(&out, 0, "writ wait --url")
            .0
            .contains(&format!("Lease {id} granted"))
    );

    let refused = submitted_id(
        &expect(
            &agent.run(&format!(
                "{agent_writ} request --url {AGENTS_URL} --no-wait {}",
                agent.ticket_file("flags-2", &lifecycle("Flags 2", TASK, "1h"))
            )),
            0,
            "a second ticket",
        )
        .0,
    );
    let out = stack.approver.run(&format!(
        "{approver_writ} refuse {refused} --message 'No' --approval-url {APPROVALS_SSH} {signer}"
    ));
    expect(&out, 0, "writ refuse with flags");
    let out = stack.approver.run(&format!(
        "{approver_writ} revoke {id} --approval-url {APPROVALS_HTTPS} {signer}"
    ));
    assert!(
        expect(&out, 0, "writ revoke with flags")
            .0
            .contains("is revoked")
    );
    let out = stack.approver.run_with(
        &format!(
            "{approver_writ} prove-key agent-e2e --namespace gitea --yes \
             --approval-url {APPROVALS_SSH} {signer}"
        ),
        b"flags",
    );
    assert!(
        expect(&out, 0, "writ prove-key with flags")
            .0
            .starts_with("-----BEGIN SSH SIGNATURE-----")
    );
    assert_eq!(stack.audited(&id, "revoke", "done").len(), 1);
    assert_eq!(stack.audited(&refused, "refuse", "done").len(), 1);
}
