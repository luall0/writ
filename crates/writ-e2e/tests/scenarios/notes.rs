//! Scenario 14, notes under heavy concurrency (asked by the user): a repo with
//! `ticket_link: notes` (`notes_ref` at its default, `refs/notes/commits`), several agents
//! pushing to it at once while a person writes notes on the same ref directly.
//!
//! - [`AGENTS`] agents, each its own lease and branch of the repo `notes`, commit without a
//!   `Writ:` trailer and push [`ROUNDS`] rounds at once: every push starts a notes job, all
//!   of them on the one notes ref, through the one mirror.
//! - Meanwhile the contributor (a second Forgejo account) reviews on Forgejo with plain git
//!   over HTTP, writing [`REVIEWS`] notes on `main`'s tip under the same `refs/notes/commits`:
//!   the daemon's notes pushes meet a ref that moved under them (fetched, merged, pushed once
//!   more; moved again: left waiting for the next push), and the contributor's meet the
//!   daemon's (fetched, appended, pushed again, as a person would).
//! - Then each agent pushes once more, the contributor done: every note still waiting goes.
//!
//! What is checked, whatever the interleaving: every agent commit has exactly its lease's note
//! on Forgejo (its notes API, and its commit page), the contributor's notes are all there too,
//! the commits are on Forgejo as the agents made them (same ids, still signed), the audit log
//! counts each lease's notes once, the only notes refusals are a ref that moved again, the
//! mirror's notes ref is Forgejo's, an agent can't push a notes ref, and the commands the
//! operator guide gives to read the notes show them. It holds the stack alone, like
//! scenario 12: the agents' container is one source address, with its own budget.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use writ_e2e::Stack;
use writ_e2e::agent::{Agent, expect, ticket};
use writ_e2e::setup::doc_step;
use writ_e2e::stderr;

use super::assert_push_refused;

const REPO: &str = "notes";
/// Agents pushing at once.
const AGENTS: usize = 8;
/// Rounds of commit and push each, while the contributor writes notes.
const ROUNDS: usize = 5;
/// The contributor's notes on `main`.
const REVIEWS: usize = 20;
/// Pushes one of the contributor's notes may take when the ref keeps moving.
const ATTEMPTS: usize = 20;
/// How long the last notes jobs may take to land.
const NOTES_WITHIN: Duration = Duration::from_secs(180);

/// A commit through `writ git`, without a trailer (the repo links commits by notes): its id.
fn commit_plain(agent: &Agent, file: &str, content: &str) -> String {
    agent
        .ok_in(
            "work",
            &format!(
                "printf '%s\\n' '{content}' > {file} && writ git add {file} && \
                 writ git commit -q -m 'Change {file}' && git rev-parse HEAD"
            ),
        )
        .trim()
        .to_owned()
}

/// Commit and push on the agent's own branch (nobody else moves it): the commit.
fn round(agent: &Agent, branch: &str, round: usize) -> String {
    let sha = commit_plain(
        agent,
        &format!("{}-{round}.txt", agent.name),
        &format!("round {round}"),
    );
    let out = agent.in_dir(
        "work",
        &format!("writ git push -q origin HEAD:refs/heads/{branch}"),
    );
    expect(&out, 0, "a push among many");
    sha
}

/// The contributor's reviews: notes on `main`'s tip, appended under `refs/notes/commits` and
/// pushed with plain git; a push the daemon's notes beat is fetched again and retried. The
/// lines it wrote.
fn contributor_reviews(stack: &Stack, done: &AtomicBool) -> Vec<String> {
    let mut written = Vec::new();
    // The first went before the storm (`first_review`).
    for n in 1..REVIEWS {
        written.push(review(stack, n));
        if done.load(Ordering::Acquire) && n >= REVIEWS / 2 {
            break;
        }
    }
    written
}

/// The contributor's clone, and its first note on Forgejo, before any agent pushes: the
/// daemon's first notes push then always meets a ref it doesn't have (fetched, merged, pushed
/// once more), whatever the timing of the rest. The line written.
fn first_review(stack: &Stack) -> String {
    let me = stack.agents_home.with("/home/agent", None);
    let url = stack.forgejo.contributor_url(REPO);
    me.ok(&format!("rm -rf reviewer && git clone -q {url} reviewer"));
    review(stack, 0)
}

/// One review: a note appended on `main`'s tip and pushed, fetched again and retried while the
/// daemon's notes beat it. The line written.
fn review(stack: &Stack, n: usize) -> String {
    let me = stack.agents_home.with("/home/agent", None);
    let git = "git -c user.name=Contributor -c user.email=contributor@writ.invalid";
    let line = format!("Reviewed-by: Contributor ({n})");
    for _ in 0..ATTEMPTS {
        // The notes ref may not exist yet: a pattern takes it if it does.
        let out = me.run(&format!(
            "cd reviewer && git fetch -q origin '+refs/notes/*:refs/notes/*' && \
             {git} notes append -m '{line}' origin/main && \
             git push -q origin refs/notes/commits:refs/notes/commits"
        ));
        if out.status.code() == Some(0) {
            return line;
        }
        // Only a push behind the remote is tried again (fetched again above).
        assert!(
            stderr(&out).contains("rejected"),
            "the contributor's notes push: {}",
            stderr(&out)
        );
    }
    panic!("{line}: not pushed in {ATTEMPTS} attempts");
}

#[test]
#[ignore = "end to end: make e2e"]
fn many_agents_and_a_person_write_notes_on_one_ref_and_none_is_lost() {
    let stack = Stack::exclusive();
    let stack: &Stack = &stack;

    // Every lease, and a wired clone each.
    let agents: Vec<(Agent, String, String)> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..AGENTS)
            .map(|i| {
                s.spawn(move || {
                    let agent = stack.agent(&format!("notes-{i}"));
                    let branch = format!("agent/n{i}");
                    let lease = agent.lease(stack, &ticket(&[REPO], &[branch.as_str()], "1h", ""));
                    agent.clone_from_forgejo(stack, REPO, "work");
                    agent.ok_in("work", &format!("writ init {REPO}"));
                    (agent, lease, branch)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    // The storm: every agent's rounds at once, the contributor writing notes under them (its
    // first one before any push).
    let first = first_review(stack);
    let done = AtomicBool::new(false);
    let (signed, mut reviews) = std::thread::scope(|s| {
        let reviewer = s.spawn(|| contributor_reviews(stack, &done));
        let workers: Vec<_> = agents
            .iter()
            .map(|(agent, lease, branch)| {
                s.spawn(move || {
                    let shas: Vec<String> = (0..ROUNDS).map(|r| round(agent, branch, r)).collect();
                    (lease.clone(), shas)
                })
            })
            .collect();
        let signed: Vec<(String, Vec<String>)> =
            workers.into_iter().map(|h| h.join().unwrap()).collect();
        done.store(true, Ordering::Release);
        (signed, reviewer.join().unwrap())
    });
    reviews.insert(0, first);
    assert!(reviews.len() > REVIEWS / 2, "{reviews:?}");

    // The contributor done, one more push each: whatever waits goes with it.
    let mut by_lease: BTreeMap<String, Vec<String>> = signed.into_iter().collect();
    for (agent, lease, branch) in &agents {
        let last = round(agent, branch, ROUNDS);
        by_lease.get_mut(lease).unwrap().push(last);
    }

    // Every agent commit gets its lease's note on Forgejo (the jobs run after the pushes).
    let deadline = Instant::now() + NOTES_WITHIN;
    for (lease, shas) in &by_lease {
        for sha in shas {
            let note = loop {
                match stack.forgejo.note(REPO, sha) {
                    Some(note) => break note,
                    None => {
                        assert!(Instant::now() < deadline, "no note for {sha} of {lease}");
                        // poll: the notes job runs on its own after the push; Forgejo gives
                        // no signal. Bounded by `deadline`.
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
            };
            assert_eq!(note, format!("Writ: {lease}\n"), "{sha}");
        }
    }
    // The contributor's notes are all there, beside the daemon's.
    let main = stack.forgejo.branch(REPO, "main").unwrap();
    let reviewed = stack
        .forgejo
        .note(REPO, &main)
        .expect("the contributor's notes");
    for line in &reviews {
        assert!(reviewed.contains(line.as_str()), "{line} in {reviewed}");
    }

    // Shown on the commit's page, where a person looks.
    let (lease, shas) = by_lease.iter().next().unwrap();
    let page = stack.forgejo.commit_page(REPO, &shas[0]);
    assert!(
        page.contains(&format!("Writ: {lease}")),
        "the note on the page"
    );

    // The commits as the agents made them: the same ids on their branches, still signed.
    for (agent, lease, branch) in &agents {
        let shas = &by_lease[lease];
        let head = agent.ok_in("work", "git rev-parse HEAD").trim().to_owned();
        assert_eq!(
            stack.forgejo.branch(REPO, branch).as_deref(),
            Some(head.as_str())
        );
        assert_eq!(shas.last(), Some(&head));
        let (_, verification) = stack.forgejo.verification(REPO, &shas[0]);
        assert_ne!(
            verification["reason"], "gpg.error.not_signed_commit",
            "{verification}"
        );
    }

    // Each lease's notes counted once; refused only for a ref that moved again.
    for (lease, shas) in &by_lease {
        let pushed: u64 = stack
            .audited(lease, "notes", "allowed")
            .iter()
            .map(|l| l["count"].as_u64().unwrap())
            .sum();
        assert_eq!(pushed, shas.len() as u64, "{lease}");
        for line in stack.audited(lease, "notes", "allowed") {
            assert_eq!(line["refs"][0], "refs/notes/commits", "{line}");
        }
        for denied in stack.audited(lease, "notes", "denied") {
            let reason = denied["reason"].as_str().unwrap_or_default();
            assert!(
                reason.contains("refs/notes/commits moved again while the notes were merged"),
                "{denied}"
            );
        }
    }
    // The mirror's notes ref is Forgejo's: the last job pushed it.
    assert_eq!(
        stack.mirror_ref(REPO, "refs/notes/commits"),
        stack.forgejo.git_ref(REPO, "refs/notes/commits")
    );

    // An agent never pushes a notes ref.
    let (agent, lease, _) = &agents[0];
    // A line of its own on top of the daemon's notes (or the push would carry no update).
    agent.ok_in(
        "work",
        "writ git fetch -q origin refs/notes/commits:refs/notes/commits && \
         git notes append -m 'Writ: wrt_forged' HEAD",
    );
    let out = agent.in_dir(
        "work",
        "writ git push origin refs/notes/commits:refs/notes/commits",
    );
    assert_push_refused(
        stack,
        lease,
        &out,
        "refs/notes/commits is not a branch",
        "ref",
    );
    let head = agent.ok_in("work", "git rev-parse HEAD").trim().to_owned();
    assert_eq!(
        stack.forgejo.note(REPO, &head),
        Some(format!("Writ: {lease}\n")),
        "the forged line never reached Forgejo"
    );

    // The operator guide's way to read them, from a clone of the remote.
    let reader = stack.agent("notes-reader");
    reader.clone_from_forgejo(stack, REPO, "clone");
    reader.ok_in("clone", "git checkout -q agent/n0");
    let clone = reader
        .host
        .with(&format!("{}/clone", reader.host.dir), None);
    doc_step(
        &clone,
        "git fetch origin refs/notes/commits:refs/notes/commits",
        &[],
    );
    let log = doc_step(&clone, "git log", &[]);
    let first = &agents[0].1;
    assert!(log.contains(&format!("Notes:\n    Writ: {first}")), "{log}");

    // The daemon met a notes ref that had moved, at least for its first push, and merged it.
    let log = stack.operator.read("writd.log");
    let merged = log
        .lines()
        .filter(|l| l.contains("notes pushed upstream") && l.contains("how=Merged"))
        .count();
    assert!(merged >= 1, "no notes push met a moved ref:\n{log}");
    // Nothing went wrong inside the daemon.
    assert!(!log.contains("internal error"), "{log}");
    assert!(!log.contains(" ERROR "), "{log}");
}
