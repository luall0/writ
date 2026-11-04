//! Scenario 20, a lease's whole life as M6 gives it: a ticket file checked before it is sent
//! (`writ check`), with an estimate; a clone pinned to the lease and the skill installed for
//! several agents (`writ init --lease --agents --skill-dir --agents-md`), excluded from git; a
//! phase marked (`writ mark`); a renewal, which the approver reviews with the original ticket
//! and the chain, after which the pinned lease is refused and the renewal (`WRIT_SESSION`)
//! pushes what the renewed lease signed; `writ close` with its report, recorded in the
//! timings file; the timings file checked and its limits changed (`writ check`, `writ
//! timings`); the approver's `writ report`; the skill installed in the agent's own folders
//! (`--global`); everything undone, the timings kept.

use writ_e2e::Stack;
use writ_e2e::agent::{expect, submitted_id};

const REPO: &str = "sessions";

/// A ticket for `sessions` on `branch`, with an estimate, and `more` lines in its `ticket:`
/// section.
fn ticket(branch: &str, more: &str) -> String {
    format!(
        "template: feature\n\
         scope:\n  repos: [{REPO}]\n  operations: [fetch, commit_sign, push]\n  branches: [\"{branch}\"]\n  \
         committer_emails: [\"agent@writ.invalid\"]\n\
         ticket:\n  title: \"e2e: renew and close\"\n  task: \"An end-to-end scenario's work\"\n  \
         estimate: {{ coding: 20m, checks: 5m, ci: 10m }}\n{more}\
         limits:\n  ttl: 1h\n"
    )
}

#[test]
#[ignore = "end to end: make e2e"]
fn a_lease_is_renewed_closed_and_learned_from() {
    let stack = Stack::shared();
    let agent = stack.agent("sessions");

    // Checked before it is sent: a ticket with a problem, then the real one.
    agent.write(
        "bad.yaml",
        &ticket("agent/s", "").replace("e2e: renew and close", "  "),
        "0644",
    );
    let (out, _) = expect(
        &agent.run("writ check bad.yaml"),
        3,
        "writ check on a bad ticket",
    );
    assert!(out.contains("ticket.title is empty"), "{out}");
    agent.write("ticket.yaml", &ticket("agent/s", ""), "0644");
    let (out, _) = expect(&agent.run("writ check ticket.yaml"), 0, "writ check");
    assert!(out.contains("a well-formed ticket file"), "{out}");
    let lease = agent.lease(&stack, &ticket("agent/s", ""));

    // Pinned to the lease, the skill for Claude Code and Cursor, one more folder, a pointer.
    agent.clone_from_forgejo(&stack, REPO, "work");
    let out = agent.ok_in(
        "work",
        &format!(
            "writ init {REPO} --lease {lease} --agents claude,cursor --skill-dir ../skills \
             --agents-md"
        ),
    );
    assert!(out.contains(&format!("Pinned to lease {lease}")), "{out}");
    agent.ok_in(
        "work",
        "test -f .claude/skills/writ/SKILL.md && test -f .cursor/skills/writ/SKILL.md && \
         test -f .claude/skills/writ/timings.md && test -f ../skills/writ/SKILL.md",
    );
    let status = agent.ok_in("work", "git status --porcelain");
    assert_eq!(
        status.trim(),
        "?? AGENTS.md",
        "only the pointer shows: {status}"
    );

    // Work under the pinned lease (no WRIT_SESSION), a phase marked.
    let first = agent.commit("work", &lease, "a.txt", "a");
    let out = agent.ok_in("work", "writ mark checks");
    assert!(
        out.contains(&format!("Marked the end of checks under lease {lease}")),
        "{out}"
    );

    // A renewal: the approver sees the original ticket and the chain.
    let renewal = ticket("agent/s", &format!("  renews: {lease}\n"));
    let path = agent.ticket_file("renew", &renewal);
    let running = agent.start(&format!("writ request {path}"));
    let renewed = submitted_id(&running.first);
    let out = stack.approver.run(&format!("writ sign {renewed} --yes"));
    let (shown, _) = expect(&out, 0, "writ sign on a renewal");
    for words in [
        format!("Renewal {renewed}"),
        format!("renews lease {lease}"),
        format!("Renewal 1 of the work started as lease {lease}"),
        "The original ticket, as you signed it".to_owned(),
        "estimate".to_owned(),
        "35m00s in all (coding 20m, checks 5m, ci 10m)".to_owned(),
    ] {
        assert!(shown.contains(&words), "{words:?} not in:\n{shown}");
    }
    let (status, out, err) = running.finish();
    assert_eq!(status.code(), Some(0), "{out}{err}");
    assert!(
        out.contains(&format!("export WRIT_SESSION={renewed}")),
        "{out}"
    );

    // The pinned lease ended: refused, never replaced by another.
    let out = agent.in_dir("work", "writ git commit -q --allow-empty -m x");
    let (_, err) = expect(&out, 1, "a commit under a renewed lease");
    assert!(
        err.contains(&format!(
            "the lease this repository is pinned to names lease {lease}: it ended (renewed by lease {renewed})"
        )),
        "{err}"
    );
    // The renewal pushes what the renewed lease signed.
    agent.ok_in(
        "work",
        &format!("WRIT_SESSION={renewed} writ git push -q origin HEAD:refs/heads/agent/s"),
    );
    assert_eq!(
        stack.forgejo.branch(REPO, "agent/s").as_deref(),
        Some(first.as_str())
    );
    assert_eq!(
        stack.mirror_ref(REPO, "refs/heads/agent/s").as_deref(),
        Some(first.as_str())
    );

    // Closed: the report, and the run recorded in the timings file.
    let out = agent.in_dir(
        "work",
        &format!(
            "WRIT_SESSION={renewed} writ close --summary 'Renewed once, pushed' --url \"$WRIT_URL\""
        ),
    );
    let (report, _) = expect(&out, 0, "writ close");
    for words in [
        format!("Activity report of lease {renewed} (closed)"),
        format!("renewal chain      {lease} →"),
        "agent's marks".to_owned(),
        "Renewed once, pushed".to_owned(),
        "Recorded in".to_owned(),
    ] {
        assert!(report.contains(&words), "{words:?} not in:\n{report}");
    }
    assert_eq!(stack.audited(&renewed, "close", "done").len(), 1);
    let timings = agent.read("work/.claude/skills/writ/timings.md");
    for words in [
        "## sessions",
        "summary: runs=1 ",
        "renewals=1",
        "estimate_runs=1",
        "marked checks",
    ] {
        assert!(timings.contains(words), "{words:?} not in:\n{timings}");
    }

    // The timings file checked, an edit outside the notes named, the limits changed.
    let file = ".claude/skills/writ/timings.md";
    let out = agent.ok_in("work", &format!("writ check {file}"));
    assert!(out.contains("a well-formed timings file"), "{out}");
    agent.ok_in("work", &format!("printf 'not a note\\n' >> {file}"));
    let (out, _) = expect(
        &agent.in_dir("work", &format!("writ check {file}")),
        3,
        "writ check",
    );
    assert!(
        out.contains("writ close would drop or rewrite it: not a note"),
        "{out}"
    );
    let out = agent.ok_in(
        "work",
        "writ timings --max-lines 60 --max-bytes 5000 --keep-runs 3 --max-notes 2",
    );
    assert!(
        out.contains("max_lines 60, max_bytes 5000, keep_runs 3, max_notes 2"),
        "{out}"
    );
    agent.ok_in("work", &format!("writ check {file}"));

    // The approver reads the same report.
    let out = stack.approver.run(&format!(
        "writ report {renewed} --approval-url \"$WRIT_APPROVAL_URL\""
    ));
    let (shown, _) = expect(&out, 0, "writ report");
    assert!(
        shown.contains(&format!("Activity report of lease {renewed} (closed)")),
        "{shown}"
    );
    assert!(shown.contains("Renewed once, pushed"), "{shown}");

    // In the agent's own folders.
    agent.clone_from_forgejo(&stack, REPO, "global");
    agent.ok_in(
        "global",
        &format!("writ init {REPO} --agents agents --global"),
    );
    agent.ok_in(
        "global",
        "test -f \"$HOME/.agents/skills/writ/SKILL.md\" && test ! -e .agents",
    );
    agent.ok_in(
        "global",
        "writ init --undo && test ! -e \"$HOME/.agents/skills/writ/SKILL.md\"",
    );

    // Undone: the skill, the exclude lines and the pointer gone, the timings kept.
    let out = agent.ok_in("work", "writ init --undo");
    assert!(out.contains("Kept"), "{out}");
    agent.ok_in(
        "work",
        "test ! -e .cursor/skills/writ && test ! -e .claude/skills/writ/SKILL.md && \
         test -f .claude/skills/writ/timings.md && test ! -e AGENTS.md && test ! -e ../skills/writ && \
         ! grep -q writ .git/info/exclude",
    );
}
