//! M5.7's benchmark: what the wiping allocator costs (docs/history/m5.7-memory-wiped-on-free.md).
//! Run by `make bench-alloc` (`tool/bench-alloc.py`, which builds `writd` with and without the
//! wiping allocator and alternates them), never by `make test`: both tests are ignored.
//!
//! - [`allocation_heavy_paths`]: the daemon's allocation-heavy paths in this process (a ticket
//!   parsed and decoded, an audit line, a commit's touched paths from its evidence, buffers
//!   growing, a large buffer, small blocks), on `writ_alloc::testing::Switch`: the same work
//!   with and without wiping, interleaved, so both see the same machine.
//! - [`writd_under_heavy_load`]: the real `writd` named by `WRIT_BIN_DIR`, sealed then
//!   unsealed, under many agents at once: tickets submitted and signed in bursts (over SSH and
//!   HTTPS), each agent fetching (every fetch syncs the mirror), signing commits and pushing
//!   upstream on its own branch, more tickets and a signed policy change in the middle of it,
//!   then a large push and every agent fetching it at once. Measured: each operation's
//!   latency, the daemon's CPU time and its peak memory, the wall time.
//!
//! Each writes its numbers as JSON to `WRIT_BENCH_OUT`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use writ_alloc::testing::Switch;
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::{stderr, stdout};

/// Every allocation of this test binary: wiping or not, as each measurement asks.
#[global_allocator]
static ALLOCATOR: Switch = Switch::new();

/// Where the numbers go.
fn output() -> PathBuf {
    PathBuf::from(std::env::var_os("WRIT_BENCH_OUT").expect("WRIT_BENCH_OUT is not set"))
}

// ---------------------------------------------------------------------------------------------
// The allocation-heavy paths, in process.

/// Samples per workload and mode.
const ROUNDS: usize = 21;

/// A ticket as an agent writes one, with a long task and plan.
fn ticket_text() -> String {
    let plan: String = (0..40)
        .map(|i| format!("    - \"Step {i}: change the module, add its tests, run them\"\n"))
        .collect();
    format!(
        "repos:\n  demo:\n    operations: [fetch, commit_sign, push]\n    \
         branches: [\"agent/oauth\", \"agent/oauth-*\"]\n    \
         expected_paths: [\"src/**\", \"tests/**\", \"docs/*.md\"]\n    limits:\n      \
         max_signatures: 30\nticket:\n  title: \"Add OAuth login\"\n  \
         task: {}\n  plan:\n{plan}limits:\n  ttl: 1h\n",
        "Add GitHub OAuth login behind a feature flag. ".repeat(20)
    )
}

/// A root commit over `dirs` directories of `files` files each, and its trees: what
/// `writ-sign` sends with it.
fn commit_and_trees(dirs: usize, files: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
    use writ_git::HashAlgo;
    use writ_git::object::ObjectType;
    let raw = |hex: &str| -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    };
    let mut trees = Vec::new();
    let mut root = Vec::new();
    for d in 0..dirs {
        let mut tree = Vec::new();
        for f in 0..files {
            let blob = HashAlgo::Sha1
                .hash(ObjectType::Blob, format!("{d}-{f}").as_bytes())
                .unwrap();
            tree.extend_from_slice(format!("100644 file-{f:04}.rs\0").as_bytes());
            tree.extend_from_slice(&raw(blob.as_str()));
        }
        let id = HashAlgo::Sha1.hash(ObjectType::Tree, &tree).unwrap();
        root.extend_from_slice(format!("40000 dir-{d:03}\0").as_bytes());
        root.extend_from_slice(&raw(id.as_str()));
        trees.push(tree);
    }
    let id = HashAlgo::Sha1.hash(ObjectType::Tree, &root).unwrap();
    trees.push(root);
    let commit = format!(
        "tree {id}\nauthor Agent <agent@writ> 1700000000 +0000\n\
         committer Agent <agent@writ> 1700000000 +0000\n\nA large first commit\n"
    );
    (commit.into_bytes(), trees)
}

/// One workload: its name, how many times one sample runs it, and the work.
struct Workload {
    name: &'static str,
    iterations: usize,
    run: Box<dyn Fn()>,
}

fn workloads() -> Vec<Workload> {
    use std::hint::black_box;
    use writ_core::canonical::Canonical;
    use writ_core::names::{RepoName, TicketId};
    use writ_core::ticket::{Ticket, TicketRequest};
    use writ_core::units::Timestamp;
    use writ_git::object::ObjectType;
    use writ_git::paths::{self, Evidence};
    use writ_git::{Commit, HashAlgo};
    use writ_store::{AuditEvent, EventKind, Outcome};

    let text = ticket_text();
    let canonical: &[u8] = include_bytes!("../../writ-core/tests/fixtures/ticket-full.json");
    let (commit, trees) = commit_and_trees(40, 50);
    let lease: TicketId = "wrt_01JD8X3K5Q7R9T1V3W5X7Y9Z0A".parse().unwrap();
    let repo: RepoName = "demo".parse().unwrap();
    vec![
        Workload {
            name: "ticket parse (YAML)",
            iterations: 2_000,
            run: Box::new(move || {
                black_box(TicketRequest::from_yaml(black_box(&text)).unwrap());
            }),
        },
        Workload {
            name: "ticket decode (canonical)",
            iterations: 5_000,
            run: Box::new(move || {
                black_box(Ticket::from_canonical(black_box(canonical)).unwrap());
            }),
        },
        Workload {
            name: "audit line",
            iterations: 50_000,
            run: Box::new(move || {
                let event = AuditEvent::new(
                    Timestamp::from_unix(1_700_000_000).unwrap(),
                    EventKind::Push,
                    Outcome::Allowed,
                )
                .lease(&lease)
                .repo(&repo)
                .refs(["refs/heads/agent/oauth".to_owned()])
                .reason("pushed upstream");
                black_box(serde_json::to_string(&event).unwrap());
            }),
        },
        Workload {
            name: "touched paths (2,000 files)",
            iterations: 20,
            run: Box::new(move || {
                let evidence = Evidence::new(
                    HashAlgo::Sha1,
                    trees.iter().map(|t| (ObjectType::Tree, t.clone())),
                );
                let commit = Commit::parse(commit.clone()).unwrap();
                let touched = paths::touched(&commit, &evidence).unwrap();
                assert_eq!(touched.len(), 2_000);
                black_box(paths::digest(&touched));
            }),
        },
        Workload {
            name: "buffer grown to 1 MiB",
            iterations: 50,
            run: Box::new(|| {
                let mut buffer = Vec::new();
                for i in 0..(1usize << 20) {
                    buffer.push(i as u8);
                }
                black_box(buffer);
            }),
        },
        Workload {
            name: "16 MiB buffer",
            iterations: 10,
            run: Box::new(|| {
                let mut buffer = vec![0u8; 16 << 20];
                buffer.fill(1);
                black_box(buffer);
            }),
        },
        Workload {
            name: "small blocks (1,000 strings)",
            iterations: 500,
            run: Box::new(|| {
                let strings: Vec<String> = (0..1000).map(|i| format!("{i:>24}-{i:x}")).collect();
                black_box(strings);
            }),
        },
    ]
}

/// Nanoseconds per run of `work`, over `iterations` runs.
fn nanos_per_run(work: &dyn Fn(), iterations: usize) -> f64 {
    let start = Instant::now();
    for _ in 0..iterations {
        work();
    }
    start.elapsed().as_nanos() as f64 / iterations as f64
}

#[test]
#[ignore = "benchmark: make bench-alloc"]
fn allocation_heavy_paths() {
    let workloads = workloads();
    // Once each way first: caches, page faults, the allocator's own warm-up.
    for workload in &workloads {
        for wiping in [false, true] {
            ALLOCATOR.set_wiping(wiping);
            nanos_per_run(&*workload.run, 1);
        }
    }
    let mut samples: BTreeMap<&str, BTreeMap<&str, Vec<f64>>> = BTreeMap::new();
    for round in 0..ROUNDS {
        for workload in &workloads {
            // Each way first in turn, so neither always runs on the other's leftovers.
            let order = if round % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            };
            for wiping in order {
                ALLOCATOR.set_wiping(wiping);
                let nanos = nanos_per_run(&*workload.run, workload.iterations);
                ALLOCATOR.set_wiping(false);
                samples
                    .entry(workload.name)
                    .or_default()
                    .entry(if wiping { "wiping" } else { "system" })
                    .or_default()
                    .push(nanos);
            }
        }
    }
    let json = serde_json::json!({ "micro": samples });
    fs::write(output(), serde_json::to_string_pretty(&json).unwrap()).unwrap();
}

// ---------------------------------------------------------------------------------------------
// The real daemon under heavy load.

/// Agents working at once (each one connection at a time: the gateway takes 16 per source).
const AGENTS: usize = 8;
/// Rounds of fetch, signed commit, push, each.
const STORM_ROUNDS: usize = 12;
/// Tickets submitted and signed in the middle of the storm.
const EXTRA_TICKETS: usize = 8;
/// The large push: files of random bytes (incompressible), and their size.
const LARGE_FILES: usize = 4;
const LARGE_FILE_BYTES: usize = 6 << 20;

const POLICY: &str = r#"
keys:
  agent-01:
    use: signing
    format: ssh
    algorithm: ed25519
  upstream-01:
    use: upstream
    kind: ssh
    algorithm: ed25519
upstream_hosts:
  remote.invalid:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    templates: [feature]
    protected_refs: ["refs/heads/main"]
templates:
  feature:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-01
    max_ttl: 2h
    max_signatures: 200
    max_pushes: 200
    max_ops_per_minute: 1000
    max_push_size: 64MB
    paths_check: warn
"#;

/// The template the signed policy change adds, under load.
const EXTRA_TEMPLATE: &str = "  docs:\n    repos: [demo]\n    operations: [fetch, commit_sign, push]\n    \
     branches: [\"docs/*\"]\n    committer_emails: [\"agent@writ\"]\n    signing_key: agent-01\n    \
     max_ttl: 1h\n    max_signatures: 10\n    max_pushes: 10\n    max_ops_per_minute: 30\n    \
     max_push_size: 1MB\n";

fn ticket(branch: &str) -> String {
    format!(
        "repos:\n  demo:\n    operations: [fetch, commit_sign, push]\n    \
         branches: [\"{branch}\"]\nticket:\n  title: \"Benchmark work on {branch}\"\n  \
         task: Change files on {branch} and push them\nlimits:\n  ttl: 1h\n"
    )
}

/// Latencies of each kind of operation, in milliseconds, from every thread.
#[derive(Default)]
struct Latencies(Mutex<BTreeMap<&'static str, Vec<f64>>>);

impl Latencies {
    /// Runs `work`, records how long it took under `kind`, returns what it returned.
    fn time<T>(&self, kind: &'static str, work: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let result = work();
        let millis = start.elapsed().as_secs_f64() * 1000.0;
        self.0.lock().unwrap().entry(kind).or_default().push(millis);
        result
    }
}

/// One agent: its own home (its `~/.writ`, git identity), its clone, its lease.
struct Agent<'a> {
    daemon: &'a Daemon,
    home: PathBuf,
    work: PathBuf,
    branch: String,
}

impl<'a> Agent<'a> {
    fn new(daemon: &'a Daemon, name: &str, branch: &str) -> Self {
        let home = daemon.root().join("agents").join(name);
        fs::create_dir_all(&home).unwrap();
        fs::write(
            home.join(".gitconfig"),
            "[user]\n\tname = Agent\n\temail = agent@writ\n[init]\n\tdefaultBranch = main\n",
        )
        .unwrap();
        Self {
            daemon,
            work: home.join("work"),
            home,
            branch: branch.to_owned(),
        }
    }

    /// `writ <args>` as this agent, in `cwd`.
    fn writ(&self, cwd: &Path, args: &[&str]) -> Output {
        self.daemon
            .writ(args)
            .env("HOME", &self.home)
            .env("WRIT_HOME", self.home.join(".writ"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .current_dir(cwd)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn writ_ok(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.writ(cwd, args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "writ {args:?}: {}{}",
            stdout(&out),
            stderr(&out)
        );
        stdout(&out)
    }

    /// Plain git as this agent, in `cwd`.
    fn git_ok(&self, cwd: &Path, args: &[&str]) {
        let out = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "git {args:?}: {}", stderr(&out));
    }

    /// Submits its ticket without waiting: the ticket's id.
    fn submit(&self) -> String {
        let file = self.home.join("ticket.yaml");
        fs::write(&file, ticket(&self.branch)).unwrap();
        let out = self.writ_ok(
            &self.home,
            &["request", file.to_str().unwrap(), "--no-wait"],
        );
        out.strip_prefix("Ticket ")
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or_else(|| panic!("no ticket id in {out:?}"))
            .to_owned()
    }

    /// One round: fetch, a signed commit of a few files, a push.
    fn round(&self, round: usize, latencies: &Latencies) {
        latencies.time("fetch", || {
            self.writ_ok(&self.work, &["git", "fetch", "-q", "origin"])
        });
        let dir = self.work.join("src").join(self.branch.replace('/', "-"));
        fs::create_dir_all(&dir).unwrap();
        for file in 0..3 {
            let line = format!("round {round} file {file} of {}\n", self.branch);
            fs::write(dir.join(format!("f{file}.rs")), line.repeat(50)).unwrap();
        }
        self.writ_ok(&self.work, &["git", "add", "-A"]);
        let message = format!("Round {round}");
        latencies.time("commit (signed)", || {
            self.writ_ok(&self.work, &["git", "commit", "-q", "-m", &message])
        });
        let target = format!("HEAD:refs/heads/{}", self.branch);
        latencies.time("push", || {
            self.writ_ok(&self.work, &["git", "push", "-q", "origin", &target])
        });
    }
}

/// The approver signs `id`, over SSH or HTTPS: how long it took.
fn sign(daemon: &Daemon, id: &str, https: bool, latencies: &Latencies) {
    let url = if https {
        format!("https://127.0.0.1:{}", daemon.https_port)
    } else {
        format!("ssh://127.0.0.1:{}", daemon.approvals_port)
    };
    let out = latencies.time("ticket signed", || {
        daemon
            .writ(&["sign", id, "--yes"])
            .env("WRIT_APPROVAL_URL", &url)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    });
    assert_eq!(
        out.status.code(),
        Some(0),
        "writ sign {id}: {}",
        stderr(&out)
    );
}

/// Incompressible bytes, the same on every run (xorshift).
fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(len);
    bytes
}

/// A process's own CPU time so far (user and system, its threads, not its children), in
/// seconds: from `/proc` where there is one, from `ps` otherwise.
fn cpu_seconds(pid: u32) -> f64 {
    if let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) {
        // After the command's closing parenthesis: field 3 first; utime is 14, stime 15.
        let fields: Vec<&str> = stat
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        let ticks: f64 = fields[11].parse::<f64>().unwrap() + fields[12].parse::<f64>().unwrap();
        let hz = Command::new("getconf").arg("CLK_TCK").output().unwrap();
        return ticks / stdout(&hz).trim().parse::<f64>().unwrap();
    }
    // `[[dd-]hh:]mm:ss.cc`
    let out = Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    let text = stdout(&out);
    let text = text.trim();
    let (days, rest) = text.split_once('-').unwrap_or(("0", text));
    let seconds = rest.split(':').fold(0.0, |total, part| {
        total * 60.0 + part.parse::<f64>().unwrap()
    });
    days.parse::<f64>().unwrap() * 86_400.0 + seconds
}

/// A process's resident memory now, in KiB. (Not its lifetime peak, Linux's `VmHWM`: the
/// unseal's key derivation sets it before the run.)
fn memory_kib(pid: u32) -> u64 {
    if let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) {
        let field = |name: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
        };
        return field("VmRSS:").unwrap();
    }
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    stdout(&out).trim().parse().unwrap()
}

/// The phases of the run under load, in order: the sampler keeps a peak for each.
const PHASES: [&str; 4] = ["tickets", "setup", "storm", "large"];

/// Samples the daemon's resident memory until `phase` is past the last one: the highest seen
/// in each phase, in KiB.
fn sample_memory(pid: u32, phase: &AtomicUsize) -> Vec<u64> {
    let mut highest = vec![0; PHASES.len()];
    loop {
        let now = phase.load(Ordering::Acquire);
        let Some(peak) = highest.get_mut(now) else {
            return highest;
        };
        *peak = (*peak).max(memory_kib(pid));
        // poll: resident memory gives no signal when it changes; sampled until the run ends.
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
#[ignore = "benchmark: make bench-alloc"]
fn writd_under_heavy_load() {
    let started = Instant::now();
    let daemon = Daemon::start_sealed_with(POLICY, Approvals::Ssh, |yaml| {
        format!("{yaml}max_pending: 100\nsubmissions: {{ per_source: 1000, in_all: 10000 }}\n")
    });
    let latencies = Latencies::default();
    // The keystore's key derivation (scrypt, 1 GiB) is the largest block the daemon frees.
    let out = latencies.time("unseal", || daemon.unseal());
    assert_eq!(out.status.code(), Some(0), "writ unseal: {}", stderr(&out));
    daemon.upstream_commit("main", "seed");
    let pid = daemon.pid();
    let cpu_at_start = cpu_seconds(pid);
    let phase = AtomicUsize::new(0);
    let mut phases = BTreeMap::new();

    let peaks = std::thread::scope(|s| {
        let sampler = s.spawn(|| sample_memory(pid, &phase));
        let mut next = |name: &'static str, started: Instant| {
            phases.insert(name, started.elapsed().as_secs_f64());
            phase.fetch_add(1, Ordering::AcqRel);
        };

        // Every ticket at once, every signature at once (half over HTTPS), every wait.
        let started = Instant::now();
        let agents: Vec<Agent> = (0..AGENTS)
            .map(|i| Agent::new(&daemon, &format!("a{i}"), &format!("agent/u{i}")))
            .collect();
        let ids: Vec<String> = std::thread::scope(|s| {
            let submitted: Vec<_> = agents
                .iter()
                .map(|agent| s.spawn(|| latencies.time("ticket submitted", || agent.submit())))
                .collect();
            submitted.into_iter().map(|h| h.join().unwrap()).collect()
        });
        std::thread::scope(|s| {
            for (i, id) in ids.iter().enumerate() {
                let (daemon, latencies) = (&daemon, &latencies);
                s.spawn(move || sign(daemon, id, i % 2 == 1, latencies));
            }
        });
        std::thread::scope(|s| {
            for (agent, id) in agents.iter().zip(&ids) {
                s.spawn(move || agent.writ_ok(&agent.home, &["wait", id]));
            }
        });
        next("tickets", started);

        // Each agent's clone of upstream, wired (no daemon in it but `writ init`'s reads).
        let started = Instant::now();
        let upstream = daemon.remote.repo("demo");
        for agent in &agents {
            agent.git_ok(
                &agent.home,
                &["clone", "-q", upstream.to_str().unwrap(), "work"],
            );
            agent.writ_ok(&agent.work, &["init", "demo", "--agents", "none"]);
        }
        next("setup", started);

        // The storm: every agent at work; in the middle, more tickets and a policy change.
        let started = Instant::now();
        std::thread::scope(|s| {
            for agent in &agents {
                let latencies = &latencies;
                s.spawn(move || {
                    for round in 0..STORM_ROUNDS {
                        agent.round(round, latencies);
                    }
                });
            }
            let (daemon, latencies) = (&daemon, &latencies);
            s.spawn(move || {
                let extra: Vec<Agent> = (0..EXTRA_TICKETS)
                    .map(|i| Agent::new(daemon, &format!("x{i}"), &format!("agent/x{i}")))
                    .collect();
                // Four at a time: the agents hold up to eight of the source's 16 connections.
                for wave in extra.chunks(4) {
                    let ids: Vec<String> = std::thread::scope(|s| {
                        let handles: Vec<_> = wave
                            .iter()
                            .map(|a| s.spawn(|| latencies.time("ticket submitted", || a.submit())))
                            .collect();
                        handles.into_iter().map(|h| h.join().unwrap()).collect()
                    });
                    std::thread::scope(|s| {
                        for (i, id) in ids.iter().enumerate() {
                            s.spawn(move || sign(daemon, id, i % 2 == 0, latencies));
                        }
                    });
                }
                let shown = daemon.run(&["admin", "show", "policy"], "");
                assert_eq!(shown.status.code(), Some(0), "{}", stderr(&shown));
                let file = daemon.root().join("new-policy.yaml");
                fs::write(&file, stdout(&shown) + EXTRA_TEMPLATE).unwrap();
                let applied = latencies.time("policy change", || {
                    daemon.run(
                        &["admin", "apply", "policy", file.to_str().unwrap(), "--yes"],
                        "",
                    )
                });
                assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
            });
        });
        next("storm", started);

        // A large push, then every agent fetching it at once.
        let started = Instant::now();
        let first = &agents[0];
        let large = first.work.join("assets");
        fs::create_dir_all(&large).unwrap();
        for file in 0..LARGE_FILES {
            fs::write(
                large.join(format!("blob-{file}.bin")),
                random_bytes(file as u64 + 1, LARGE_FILE_BYTES),
            )
            .unwrap();
        }
        first.writ_ok(&first.work, &["git", "add", "-A"]);
        latencies.time("large commit (signed)", || {
            first.writ_ok(&first.work, &["git", "commit", "-q", "-m", "Large assets"])
        });
        let target = format!("HEAD:refs/heads/{}", first.branch);
        latencies.time("large push", || {
            first.writ_ok(&first.work, &["git", "push", "-q", "origin", &target])
        });
        std::thread::scope(|s| {
            for agent in &agents {
                let latencies = &latencies;
                s.spawn(move || {
                    latencies.time("large fetch", || {
                        agent.writ_ok(&agent.work, &["git", "fetch", "-q", "origin"])
                    })
                });
            }
        });
        next("large", started);
        sampler.join().unwrap()
    });

    let cpu = cpu_seconds(pid) - cpu_at_start;
    // Every push went through, the daemon logged no internal error.
    assert_eq!(
        daemon.audited("push", "allowed"),
        AGENTS * STORM_ROUNDS + 1,
        "{}",
        daemon.log()
    );
    let log = daemon.log();
    assert!(!log.contains("internal error"), "{log}");
    let peaks: BTreeMap<&str, u64> = PHASES.into_iter().zip(peaks).collect();
    let json = serde_json::json!({
        "build": std::env::var("WRIT_BENCH_BUILD").unwrap_or_default(),
        "wall_s": started.elapsed().as_secs_f64(),
        "phases_s": phases,
        "cpu_s": cpu,
        "peak_rss_kib": peaks,
        "operations_ms": latencies.0.into_inner().unwrap(),
    });
    fs::write(output(), serde_json::to_string_pretty(&json).unwrap()).unwrap();
}
