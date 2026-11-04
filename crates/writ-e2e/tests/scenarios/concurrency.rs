//! Scenario 12, heavy concurrency (asked by the user): one daemon, several users at once,
//! and a remote that keeps changing under them.
//!
//! - [`AGENTS`] agents (each its own host directory, `WRIT_HOME`, session key and lease)
//!   submit their tickets at the same moment; the approver lists and signs them all in
//!   parallel, over HTTPS and SSH.
//! - Each agent then works [`ROUNDS`] rounds on its own branch of the same repository: fetch
//!   (every fetch syncs the one mirror they share), sign a commit, push; when upstream moved
//!   under it, fetch, rebase (signed again) and push again, as an agent would.
//! - Meanwhile another contributor of the repository (a second Forgejo account, a write
//!   collaborator) works on Forgejo directly, without Writ, in two ways at once: through the
//!   API (commits on `main`, on the agents' branches: a reviewer's commits, the agent's next
//!   push refused until it rebases; new branches) and with plain git over HTTP from its own
//!   clone ([`CONTRIBUTOR_PUSHES`] pushes: to `main`, onto the agents' branches, new branches;
//!   fetch and rebase when the remote moved under it, as a person would).
//!
//! What is checked holds whatever the interleaving: every agent's branch ends where the agent
//! says (its work and the contributor's), the mirror ends exactly as Forgejo (every branch,
//! the contributor's too), the audit log has one allowed push per push that went through and no other
//! kind of refusal, every lease is still active, and the daemon logged no internal error. It
//! holds the stack alone: the agents' container is one source address, with its own budget
//! of connections.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use writ_e2e::Stack;
use writ_e2e::agent::{Agent, expect, ticket};
use writ_e2e::setup::APPROVALS_SSH;
use writ_e2e::stderr;

/// Agents working at once.
const AGENTS: usize = 8;
/// Rounds of fetch, commit, push each.
const ROUNDS: usize = 4;
/// Pushes one round may take when upstream keeps moving under it.
const ATTEMPTS: usize = 12;
/// The contributor's changes through Forgejo's API.
const WRITES: usize = 30;
/// The contributor's pushes with plain git.
const CONTRIBUTOR_PUSHES: usize = 12;

/// The contributor's plain git, in its own clone on the agents' host (another person's
/// machine: its own credentials in the clone's URL, its own identity).
fn contributor_git(stack: &Stack) -> usize {
    let me = stack.agents_home.with("/home/agent", None);
    let url = stack.forgejo.contributor_url("busy");
    me.ok(&format!(
        "rm -rf contributor && git clone -q {url} contributor"
    ));
    let git = "git -c user.name=Contributor -c user.email=contributor@writ.invalid";
    let mut pushed = 0;
    for n in 0..CONTRIBUTOR_PUSHES {
        // Where it pushes: main, an agent's branch (if it exists yet), or a new branch.
        let (base, target) = match n % 3 {
            0 => ("main".to_owned(), "main".to_owned()),
            1 => {
                let branch = format!("agent/u{}", (n / 3) % AGENTS);
                let exists = me.run(&format!(
                    "cd contributor && git ls-remote --exit-code -q origin {branch}"
                ));
                if exists.status.code() == Some(0) {
                    (branch.clone(), branch)
                } else {
                    ("main".to_owned(), format!("contrib/b{n}"))
                }
            }
            _ => ("main".to_owned(), format!("contrib/b{n}")),
        };
        for attempt in 0..ATTEMPTS {
            let out = me.run(&format!(
                "cd contributor && git fetch -q origin {base} && git checkout -q -B work FETCH_HEAD && \
                 echo {n}-{attempt} > contrib-{n}.txt && git add contrib-{n}.txt && \
                 {git} commit -q -m 'Contributor {n}' && git push -q origin HEAD:refs/heads/{target}"
            ));
            if out.status.code() == Some(0) {
                pushed += 1;
                break;
            }
            // Only a push behind the remote is retried (fetched again above).
            assert!(
                stderr(&out).contains("rejected"),
                "the contributor's push: {}",
                stderr(&out)
            );
        }
    }
    pushed
}

/// One agent's work: its lease, and how many pushes went through.
struct Worker {
    agent: Agent,
    lease: String,
    branch: String,
}

/// Fetch, commit, push; on a push refused because upstream moved, fetch, rebase, push again.
/// The pushes that went through.
fn work(worker: &Worker, round: usize) -> usize {
    let Worker {
        agent,
        lease,
        branch,
    } = worker;
    expect(
        &agent.in_dir("work", "writ git fetch -q origin"),
        0,
        "a fetch in the storm",
    );
    agent.commit(
        "work",
        lease,
        &format!("{}-{round}.txt", agent.name),
        &format!("round {round}"),
    );
    for _ in 0..ATTEMPTS {
        let out = agent.in_dir(
            "work",
            &format!("writ git push -q origin HEAD:refs/heads/{branch}"),
        );
        match out.status.code() {
            Some(0) => return 1,
            Some(1) if stderr(&out).contains("rejected") => {
                // Upstream moved (the writer's commit on this branch): catch up, signed again.
                agent.ok_in(
                    "work",
                    &format!("writ git fetch -q origin && writ git rebase -q origin/{branch}"),
                );
            }
            _ => {
                expect(&out, 0, "a push in the storm");
            }
        }
    }
    panic!("{branch}: no push went through in {ATTEMPTS} attempts");
}

#[test]
#[ignore = "end to end: make e2e"]
fn many_agents_and_a_busy_remote_share_one_daemon() {
    let stack = Stack::exclusive();
    let stack: &Stack = &stack;

    // Every ticket at once, every signature at once.
    let workers: Vec<Worker> = std::thread::scope(|s| {
        let submitted: Vec<_> = (0..AGENTS)
            .map(|i| {
                s.spawn(move || {
                    let agent = stack.agent(&format!("busy-{i}"));
                    let id = agent.submit(
                        "ticket",
                        &ticket(&["busy"], &[&format!("agent/u{i}")], "1h", ""),
                    );
                    (agent, id)
                })
            })
            .collect();
        let submitted: Vec<(Agent, String)> =
            submitted.into_iter().map(|h| h.join().unwrap()).collect();
        let listing = stack.approver.ok("writ ls");
        for (_, id) in &submitted {
            assert!(
                listing
                    .lines()
                    .any(|l| l.starts_with(id.as_str()) && l.contains("pending")),
                "{listing}"
            );
        }
        let ids: Vec<String> = submitted.iter().map(|(_, id)| id.clone()).collect();
        let signed: Vec<_> = ids
            .into_iter()
            .enumerate()
            .map(|(i, id)| {
                s.spawn(move || {
                    // Half over SSH, half over HTTPS.
                    let url = if i % 2 == 0 {
                        format!("WRIT_APPROVAL_URL={APPROVALS_SSH} ")
                    } else {
                        String::new()
                    };
                    let out = stack.approver.run(&format!("{url}writ sign {id} --yes"));
                    expect(&out, 0, "a signature among many");
                })
            })
            .collect();
        signed.into_iter().for_each(|h| h.join().unwrap());
        submitted
            .into_iter()
            .enumerate()
            .map(|(i, (agent, lease))| {
                expect(
                    &agent.run(&format!("writ wait {lease}")),
                    0,
                    "a lease among many",
                );
                agent.clone_from_forgejo(stack, "busy", "work");
                agent.ok_in("work", "writ init busy --agents none");
                Worker {
                    agent,
                    lease,
                    branch: format!("agent/u{i}"),
                }
            })
            .collect()
    });

    // The storm: the agents at work, the writer changing Forgejo under them.
    let done = AtomicBool::new(false);
    let pushed = AtomicUsize::new(0);
    let written = std::thread::scope(|s| {
        let writer = s.spawn(|| {
            let mut writes = 0;
            for n in 0..WRITES {
                match n % 3 {
                    0 => {
                        stack.forgejo.commit_file(
                            "busy",
                            "main",
                            &format!("upstream/{n}.txt"),
                            "upstream",
                        );
                    }
                    1 => {
                        let branch = format!("agent/u{}", n % AGENTS);
                        if stack.forgejo.branch("busy", &branch).is_some() {
                            stack.forgejo.commit_file(
                                "busy",
                                &branch,
                                &format!("review-{n}.txt"),
                                "review",
                            );
                        }
                    }
                    _ => stack
                        .forgejo
                        .create_branch("busy", &format!("upstream/b{n}"), "main"),
                }
                writes += 1;
                if done.load(Ordering::Acquire) && n >= WRITES / 2 {
                    break;
                }
            }
            writes
        });
        let contributor = s.spawn(|| contributor_git(stack));
        let agents: Vec<_> = workers
            .iter()
            .map(|worker| {
                let pushed = &pushed;
                s.spawn(move || {
                    for round in 0..ROUNDS {
                        pushed.fetch_add(work(worker, round), Ordering::AcqRel);
                    }
                })
            })
            .collect();
        agents.into_iter().for_each(|h| h.join().unwrap());
        done.store(true, Ordering::Release);
        (writer.join().unwrap(), contributor.join().unwrap())
    });
    let (written, contributed) = written;
    assert!(
        written >= WRITES / 2,
        "the contributor made {written} changes through the API"
    );
    assert_eq!(
        contributed, CONTRIBUTOR_PUSHES,
        "the contributor's git pushes"
    );

    // Every agent's work is on its branch on Forgejo, all of its rounds in it (the contributor
    // may have pushed on top since: its commits come after, never instead).
    for worker in &workers {
        let branch = &worker.branch;
        worker.agent.ok_in("work", "writ git fetch -q origin");
        let contained = worker.agent.in_dir(
            "work",
            &format!("git merge-base --is-ancestor HEAD origin/{branch}"),
        );
        expect(&contained, 0, "the agent's last push is in its branch");
        let tip = worker
            .agent
            .ok_in("work", &format!("git rev-parse origin/{branch}"))
            .trim()
            .to_owned();
        assert_eq!(
            stack.forgejo.branch("busy", branch).as_deref(),
            Some(tip.as_str())
        );
        let files = worker
            .agent
            .ok_in("work", &format!("git ls-tree --name-only origin/{branch}"));
        for round in 0..ROUNDS {
            assert!(
                files.contains(&format!("{}-{round}.txt", worker.agent.name)),
                "{files}"
            );
        }
        assert_eq!(
            stack.audited(&worker.lease, "push", "allowed").len(),
            ROUNDS
        );
        // Refused only because upstream had moved: never for another reason.
        for denied in stack.audited(&worker.lease, "push", "denied") {
            assert!(denied["code"].is_null(), "{denied}");
        }
    }
    assert_eq!(pushed.load(Ordering::Acquire), AGENTS * ROUNDS);

    // One more fetch syncs the mirror: then it is exactly Forgejo, the writer's branches too.
    expect(
        &workers[0].agent.in_dir("work", "writ git fetch -q origin"),
        0,
        "the last fetch",
    );
    let forgejo = stack.forgejo.branches("busy");
    let mirror: BTreeMap<String, String> = stack
        .operator
        .ok("git -C data/repos/busy.git for-each-ref --format='%(refname:strip=2) %(objectname)' refs/heads")
        .lines()
        .map(|l| {
            let (name, sha) = l.split_once(' ').unwrap();
            (name.to_owned(), sha.to_owned())
        })
        .collect();
    assert_eq!(mirror, forgejo);
    assert!(
        forgejo.keys().any(|b| b.starts_with("upstream/b")),
        "{forgejo:?}"
    );

    // Every lease still active; nothing went wrong inside the daemon.
    let active = stack.approver.ok("writ ls");
    for worker in &workers {
        assert!(
            active
                .lines()
                .any(|l| l.starts_with(&worker.lease) && l.contains("active")),
            "{active}"
        );
    }
    let log = stack.operator.read("writd.log");
    assert!(!log.contains("internal error"), "{log}");
    assert!(!log.contains(" ERROR "), "{log}");
}
