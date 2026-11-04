//! M6 with the real binaries: each agent on its own lease (`WRIT_SESSION`, a repo pinned with
//! `writ init --lease`), `max_active_per_source` at submission and at signing, renewals (the
//! commits of the renewed lease pushed under the renewal, `max_renewals`, `renew_grace`), a
//! whole-repo clone following its lease's format, the skill `writ init` installs, and what an
//! agent reads and checks before it asks (`writ policy`, `writ request --dry-run`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;
use std::path::Path;

use writ_integration::clone::{clone, git_ok, ledger, writ, writ_ok};
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::{audit_events, eventually, stderr, stdout};

const POLICY: &str = r#"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    protected_refs: ["refs/heads/main"]
templates:
  feature:
    repos: [demo]
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-01
    max_ttl: 2h
    max_signatures: 40
    max_pushes: 20
    max_ops_per_minute: 100
    max_push_size: 10MB
    max_renewals: 1
"#;

/// A ticket for `branch`, `more` lines in its `ticket:` section.
fn ticket(branch: &str, more: &str) -> String {
    format!(
        "scope:\n  repos: [demo]\n  operations: [fetch, commit_sign, push]\n  branches: [\"{branch}\"]\n\
         ticket:\n  title: \"Add OAuth login\"\n  task: Add GitHub OAuth login\n{more}limits:\n  ttl: 1h\n"
    )
}

/// A ticket submitted, signed (with `flags`) and granted: its id, and what `writ request`
/// printed (stdout, stderr).
fn granted(daemon: &Daemon, name: &str, yaml: &str, flags: &[&str]) -> (String, String, String) {
    let request = daemon.request(name, yaml);
    let id = request.id.clone();
    let mut args = vec!["sign", id.as_str(), "--yes"];
    args.extend_from_slice(flags);
    let out = daemon.run(&args, "");
    assert!(
        out.status.success(),
        "writ sign: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let (status, out, err) = request.finish();
    assert_eq!(status.code(), Some(0), "{out}{err}");
    (id, out, err)
}

/// A commit of `file` in `repo` through `writ git`, under `session` (none: the default).
fn commit(daemon: &Daemon, repo: &Path, file: &str, session: Option<&str>) -> std::process::Output {
    fs::write(repo.join(file), format!("{file}\n")).unwrap();
    git_ok(daemon, repo, &["add", file]);
    let env: Vec<(&str, &str)> = session.map(|s| ("WRIT_SESSION", s)).into_iter().collect();
    writ(daemon, repo, &["git", "commit", "-q", "-m", file], &env)
}

fn head(daemon: &Daemon, repo: &Path) -> String {
    git_ok(daemon, repo, &["rev-parse", "HEAD"])
        .trim()
        .to_owned()
}

#[test]
fn two_agents_in_one_home_each_keep_their_own_lease() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let (a, out, _) = granted(&daemon, "a", &ticket("agent/a", ""), &[]);
    assert!(out.contains(&format!("export WRIT_SESSION={a}")), "{out}");
    // The second grant moves `current` away from a lease still running: said.
    let (b, _, err) = granted(&daemon, "b", &ticket("agent/b", ""), &[]);
    assert!(
        err.contains(&format!(
            "warning: `current` now points at {b}, and this home has other active leases ({a})"
        )),
        "{err}"
    );
    let repo = clone(&daemon, "two");
    writ_ok(&daemon, &repo, &["init", "demo", "--agents", "none"], &[]);

    // Each agent's commits and pushes under its own lease, whatever `current` says (b).
    let out = commit(&daemon, &repo, "a1", Some(&a));
    assert!(out.status.success(), "{}", stderr(&out));
    let a1 = head(&daemon, &repo);
    writ_ok(
        &daemon,
        &repo,
        &["git", "push", "-q", "origin", "HEAD:refs/heads/agent/a"],
        &[("WRIT_SESSION", &a)],
    );
    let out = commit(&daemon, &repo, "b1", Some(&b));
    assert!(out.status.success(), "{}", stderr(&out));
    let b1 = head(&daemon, &repo);
    assert_eq!(ledger(&daemon, &a), vec![a1.clone()]);
    assert_eq!(ledger(&daemon, &b), vec![b1.clone()]);
    let pushes = audit_events(&daemon.audit(), "push", "allowed");
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0]["lease"], a.as_str());

    // A lease this host doesn't have: refused with the reason, nothing signed.
    let unknown = "wrt_01JD8X0000000000000000000Z";
    let out = commit(&daemon, &repo, "x1", Some(unknown));
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(&format!(
            "WRIT_SESSION names lease {unknown}: no granted session for it on this host"
        )),
        "{}",
        stderr(&out)
    );
    assert_eq!(head(&daemon, &repo), b1, "nothing went out under current");
    // A lease that ended (closed): refused too.
    writ_ok(&daemon, &repo, &["close", &a, "--summary", "done"], &[]);
    let out = commit(&daemon, &repo, "x2", Some(&a));
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(&format!("WRIT_SESSION names lease {a}: it ended (closed)")),
        "{}",
        stderr(&out)
    );
    assert_eq!(ledger(&daemon, &b), [b1]);
}

#[test]
fn a_pinned_repo_uses_its_lease_in_both_wirings() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let (a, _, _) = granted(&daemon, "a", &ticket("agent/a", ""), &[]);
    let wrapper = clone(&daemon, "pinned");
    let out = writ_ok(
        &daemon,
        &wrapper,
        &["init", "demo", "--lease", &a, "--agents", "none"],
        &[],
    );
    assert!(out.contains(&format!("Pinned to lease {a}")), "{out}");
    let whole = clone(&daemon, "pinned-whole");
    writ_ok(
        &daemon,
        &whole,
        &[
            "init",
            "demo",
            "--whole-repo",
            "--lease",
            &a,
            "--agents",
            "none",
        ],
        &[],
    );
    // Another lease becomes current: the pinned repos stay on theirs.
    let (b, _, _) = granted(&daemon, "b", &ticket("agent/b", ""), &[]);
    assert!(commit(&daemon, &wrapper, "w1", None).status.success());
    fs::write(whole.join("p1"), "p1\n").unwrap();
    git_ok(&daemon, &whole, &["add", "p1"]);
    git_ok(&daemon, &whole, &["commit", "-q", "-m", "p1"]);
    assert_eq!(
        ledger(&daemon, &a),
        [head(&daemon, &wrapper), head(&daemon, &whole)]
    );
    assert!(ledger(&daemon, &b).is_empty());
    // WRIT_SESSION naming another lease than the clone is pinned to: writ-sign refuses.
    fs::write(whole.join("p2"), "p2\n").unwrap();
    git_ok(&daemon, &whole, &["add", "p2"]);
    let out = writ(
        &daemon,
        &whole,
        &["git", "commit", "-q", "-m", "p2"],
        &[("WRIT_SESSION", &b)],
    );
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(&format!(
            "WRIT_SESSION names lease {b}, but this repository's Writ settings are for {a}"
        )),
        "{}",
        stderr(&out)
    );
    assert!(ledger(&daemon, &b).is_empty());
    // A pin on a lease this host doesn't have is refused, and nothing is wired.
    let other = clone(&daemon, "pin-nothing");
    let out = writ(
        &daemon,
        &other,
        &[
            "init",
            "demo",
            "--lease",
            "wrt_01JD8X0000000000000000000Z",
            "--agents",
            "none",
        ],
        &[],
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("--lease wrt_01JD8X0000000000000000000Z: no granted session"),
        "{}",
        stderr(&out)
    );
    assert!(!other.join(".git/writ").exists());
}

#[test]
fn max_active_per_source_holds_at_submission_and_at_signing() {
    let daemon = Daemon::start_with(POLICY, Approvals::Ssh, |config| {
        format!("{config}max_active_per_source: 1\n")
    });
    let (a, _, _) = granted(&daemon, "a", &ticket("agent/a", ""), &[]);
    // At the limit: refused at submission, with the limit named.
    let file = daemon.root().join("over.yaml");
    fs::write(&file, ticket("agent/b", "")).unwrap();
    let out = daemon.run(&["request", file.to_str().unwrap()], "");
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("already holds 1 active leases (max_active_per_source: 1)"),
        "{}",
        stderr(&out)
    );
    // An amendment adds no lease.
    granted(
        &daemon,
        "amend",
        &ticket("agent/a", &format!("  amends: {a}\n")),
        &[],
    );
    // The lease ends: two tickets wait at once, the first signed takes the slot.
    let repo = clone(&daemon, "active");
    writ_ok(&daemon, &repo, &["close", &a, "--summary", "done"], &[]);
    let first = daemon.request("first", &ticket("agent/c", ""));
    let second = daemon.request("second", &ticket("agent/d", ""));
    assert!(
        daemon
            .run(&["sign", &first.id, "--yes"], "")
            .status
            .success()
    );
    let out = daemon.run(&["sign", &second.id, "--yes"], "");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("max_active_per_source: 1"),
        "{}",
        stderr(&out)
    );
    let denied = audit_events(&daemon.audit(), "grant", "denied");
    assert_eq!(denied.last().unwrap()["ticket"], second.id.as_str());
    let (status, _, _) = first.finish();
    assert_eq!(status.code(), Some(0));
    assert!(daemon.run(&["revoke", &second.id], "").status.success());
    let (status, _, _) = second.finish();
    assert_eq!(status.code(), Some(5), "withdrawn");
    // A renewal replaces its lease: it doesn't count twice.
    let renewed = first_lease(&daemon);
    granted(
        &daemon,
        "renew",
        &ticket("agent/c", &format!("  renews: {renewed}\n")),
        &[],
    );
}

/// The one active lease `writ ls` lists.
fn first_lease(daemon: &Daemon) -> String {
    let out = daemon.run(&["ls"], "");
    let listed = stdout(&out);
    listed
        .lines()
        .find(|l| l.contains(" active "))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("no active lease: {listed}"))
        .to_owned()
}

#[test]
fn a_renewal_pushes_what_its_lease_signed_and_holds_to_every_bound() {
    let daemon = Daemon::start_with(POLICY, Approvals::Ssh, |config| {
        format!("{config}renew_grace: 0s\n")
    });
    let (a, _, _) = granted(&daemon, "a", &ticket("agent/oauth", ""), &[]);
    let repo = clone(&daemon, "renew");
    writ_ok(&daemon, &repo, &["init", "demo", "--agents", "none"], &[]);
    // A commit signed, not pushed, when the lease is renewed.
    assert!(commit(&daemon, &repo, "c1", Some(&a)).status.success());
    let c1 = head(&daemon, &repo);
    let (b, out, _) = granted(
        &daemon,
        "b",
        &ticket("agent/oauth", &format!("  renews: {a}\n")),
        &[],
    );
    assert!(out.contains(&format!("export WRIT_SESSION={b}")), "{out}");
    assert_eq!(
        fs::read_to_string(daemon.session(&a).join("ended"))
            .unwrap()
            .trim(),
        format!("renewed by lease {b}")
    );
    // The renewed lease: its session refused here, its certificate refused by the daemon.
    let out = commit(&daemon, &repo, "c2", Some(&a));
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains(&format!("it ended (renewed by lease {b})")),
        "{}",
        stderr(&out)
    );
    let out = daemon.ls_remote(&daemon.session(&a));
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("Permission denied (publickey)"),
        "{}",
        stderr(&out)
    );
    // The renewal pushes the renewed lease's commit.
    writ_ok(
        &daemon,
        &repo,
        &["git", "push", "-q", "origin", "HEAD:refs/heads/agent/oauth"],
        &[("WRIT_SESSION", &b)],
    );
    let upstream = daemon.remote.repo("demo");
    let pushed = git_ok(&daemon, &upstream, &["rev-parse", "refs/heads/agent/oauth"]);
    assert_eq!(pushed.trim(), c1);
    // `max_renewals: 1`: the renewal can't be renewed again.
    let file = daemon.root().join("again.yaml");
    fs::write(&file, ticket("agent/oauth", &format!("  renews: {b}\n"))).unwrap();
    let out = daemon.run(&["request", file.to_str().unwrap()], "");
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("template feature allows 1 renewals of a lease"),
        "{}",
        stderr(&out)
    );
    // `renew_grace: 0s`: a lease that ran out can't be renewed (narrowed to 5 seconds here).
    let (short, _, _) = granted(
        &daemon,
        "short",
        &ticket("agent/short", ""),
        &["--ttl", "5s"],
    );
    eventually("the short lease to expire", || {
        stdout(&daemon.run(&["ls", "--all"], ""))
            .lines()
            .any(|l| l.starts_with(&short) && l.contains(" expired "))
    });
    fs::write(
        &file,
        ticket("agent/short", &format!("  renews: {short}\n")),
    )
    .unwrap();
    let out = daemon.run(&["request", file.to_str().unwrap()], "");
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("more than renew_grace (0s) ago"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn writ_init_installs_the_skill_where_each_agent_looks_and_undo_removes_it() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let repo = clone(&daemon, "skill");
    fs::write(repo.join("AGENTS.md"), "# Agents\n").unwrap();
    git_ok(&daemon, &repo, &["add", "AGENTS.md"]);
    git_ok(&daemon, &repo, &["commit", "-q", "-m", "agents"]);
    // Without a terminal and without --agents or --skill-dir: refused, nothing wired.
    let out = writ(&daemon, &repo, &["init", "demo"], &[]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("no terminal to ask which agents get the Writ skill: pass --agents"),
        "{}",
        stderr(&out)
    );
    assert!(!repo.join(".git/writ").exists());
    let extra = daemon.root().join("my-skills");
    let out = writ_ok(
        &daemon,
        &repo,
        &[
            "init",
            "demo",
            "--agents",
            "claude,opencode,cursor",
            "--skill-dir",
            extra.to_str().unwrap(),
            "--agents-md",
        ],
        &[],
    );
    // OpenCode reads .claude/skills: no folder of its own.
    for path in [
        ".claude/skills/writ/SKILL.md",
        ".cursor/skills/writ/SKILL.md",
        ".claude/skills/writ/timings.md",
    ] {
        assert!(repo.join(path).is_file(), "{path}: {out}");
    }
    assert!(!repo.join(".opencode").exists());
    assert!(extra.join("writ/SKILL.md").is_file());
    let skill = fs::read_to_string(repo.join(".cursor/skills/writ/SKILL.md")).unwrap();
    assert!(
        skill.contains("`.claude/skills/writ/timings.md`"),
        "{skill}"
    );
    // Excluded from git: the status shows only the pointer in AGENTS.md.
    let status = git_ok(&daemon, &repo, &["status", "--porcelain"]);
    assert_eq!(status.trim(), "M AGENTS.md", "{status}");
    assert!(
        fs::read_to_string(repo.join("AGENTS.md"))
            .unwrap()
            .contains("read the `writ` skill")
    );
    // `writ check` on the timings file as installed: clean.
    let timings = repo.join(".claude/skills/writ/timings.md");
    let out = writ_ok(&daemon, &repo, &["check", timings.to_str().unwrap()], &[]);
    assert!(out.contains("a well-formed timings file"), "{out}");
    // Undone: every file it made and every line it added, the timings kept.
    let out = writ_ok(&daemon, &repo, &["init", "--undo"], &[]);
    assert!(out.contains("Kept"), "{out}");
    assert!(!repo.join(".cursor/skills/writ").exists());
    assert!(!repo.join(".claude/skills/writ/SKILL.md").exists());
    assert!(timings.is_file());
    assert!(!extra.join("writ").exists());
    assert_eq!(
        fs::read_to_string(repo.join("AGENTS.md")).unwrap(),
        "# Agents\n"
    );
    let exclude = fs::read_to_string(repo.join(".git/info/exclude")).unwrap();
    assert!(!exclude.contains("writ"), "{exclude}");
    // --global: the user's folders, nothing in the repo or its exclude file.
    writ_ok(
        &daemon,
        &repo,
        &["init", "demo", "--agents", "agents", "--global"],
        &[],
    );
    assert!(
        daemon
            .root()
            .join("home/.agents/skills/writ/SKILL.md")
            .is_file()
    );
    assert!(!repo.join(".agents").exists());
    writ_ok(&daemon, &repo, &["init", "--undo"], &[]);
    assert!(
        !daemon
            .root()
            .join("home/.agents/skills/writ/SKILL.md")
            .exists()
    );
}

#[test]
fn a_whole_repo_clone_follows_its_lease_s_format_and_undo_is_exact() {
    let policy = POLICY.replace("    max_renewals: 1\n", "")
        + "  pgp:\n    repos: [demo]\n    operations: [fetch, commit_sign, push]\n    branches: [\"agent/*\"]\n    committer_emails: [\"agent@writ\"]\n    signing_key: agent-pgp\n    max_ttl: 2h\n    max_signatures: 40\n    max_pushes: 20\n    max_ops_per_minute: 100\n    max_push_size: 10MB\nsigning_keys:\n  agent-pgp:\n    uids: [\"Agent <agent@writ>\"]\n";
    let daemon = Daemon::start(&policy, Approvals::Ssh);
    let (ssh_lease, _, _) = granted(
        &daemon,
        "ssh",
        &format!("template: feature\n{}", ticket("agent/a", "")),
        &[],
    );
    let repo = clone(&daemon, "follow");
    // A value over two lines, which --undo must put back whole.
    git_ok(
        &daemon,
        &repo,
        &["config", "--local", "user.email", "first\nsecond"],
    );
    let before = git_ok(&daemon, &repo, &["config", "--local", "--list", "-z"]);
    writ_ok(
        &daemon,
        &repo,
        &["init", "demo", "--whole-repo", "--agents", "none"],
        &[],
    );
    let commit_plain = |file: &str| {
        fs::write(repo.join(file), "x\n").unwrap();
        git_ok(&daemon, &repo, &["add", file]);
        git_ok(&daemon, &repo, &["commit", "-q", "-m", file]);
        git_ok(&daemon, &repo, &["cat-file", "commit", "HEAD"])
    };
    assert!(commit_plain("s1").contains("-----BEGIN SSH SIGNATURE-----"));
    assert_eq!(ledger(&daemon, &ssh_lease).len(), 1);
    // Another lease, whose key signs in OpenPGP, becomes current: the same clone's commits are
    // signed in its format, with no change to the clone's config.
    let (pgp_lease, _, _) = granted(
        &daemon,
        "pgp",
        &format!("template: pgp\n{}", ticket("agent/b", "")),
        &[],
    );
    let body = commit_plain("p1");
    assert!(body.contains("-----BEGIN PGP SIGNATURE-----"), "{body}");
    assert_eq!(ledger(&daemon, &pgp_lease).len(), 1);
    writ_ok(&daemon, &repo, &["init", "--undo"], &[]);
    assert_eq!(
        git_ok(&daemon, &repo, &["config", "--local", "--list", "-z"]),
        before
    );
}

#[test]
fn writ_policy_and_a_dry_run_tell_the_agent_what_fits_before_it_asks() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let repo = clone(&daemon, "policy");
    // Before any lease, the committer email is the coming lease's: no hint to set one.
    let out = writ_ok(&daemon, &repo, &["init", "demo", "--agents", "none"], &[]);
    assert!(
        out.contains("Committer email: the lease's, once one is granted (`writ policy` lists"),
        "{out}"
    );
    assert!(!out.contains("use --email"), "{out}");
    // What a ticket may ask, for the wired repo.
    let out = writ_ok(&daemon, &repo, &["policy"], &[]);
    for words in [
        "What a ticket for repo demo may ask",
        "protected refs      refs/heads/main (never pushed",
        "ticket link         the daemon's ledger only",
        "Template feature:",
        "branches            agent/*",
        "committer emails    agent@writ",
        "max ttl             2h",
        "renewals            at most 1 per lease",
    ] {
        assert!(out.contains(words), "{words:?} not in:\n{out}");
    }
    assert!(
        !out.contains("remote.invalid") && !out.contains("upstream-01"),
        "{out}"
    );
    let out = writ(&daemon, &repo, &["policy", "elsewhere"], &[]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("writ: repo elsewhere is not in the registry"),
        "{}",
        stderr(&out)
    );
    // A dry run: on main, rejected with the daemon's reason; on a branch of its own, accepted.
    let main = daemon.root().join("main.yaml");
    fs::write(&main, ticket("main", "")).unwrap();
    let out = writ(
        &daemon,
        &repo,
        &["request", "--dry-run", main.to_str().unwrap()],
        &[],
    );
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("branch main is not within the template's branches (agent/*)"),
        "{}",
        stderr(&out)
    );
    let good = daemon.root().join("good.yaml");
    fs::write(&good, ticket("agent/oauth", "")).unwrap();
    let out = writ_ok(
        &daemon,
        &repo,
        &["request", "--dry-run", good.to_str().unwrap()],
        &[],
    );
    assert!(
        out.contains("The daemon would accept this ticket (template feature): fetch, commit_sign, push on demo, branches agent/oauth"),
        "{out}"
    );
    // Nothing submitted, no session on this host; the lines in the audit log.
    let listed = stdout(&daemon.run(&["ls", "--all"], ""));
    assert!(!listed.contains("wrt_"), "{listed}");
    let sessions = daemon.root().join("writ/sessions");
    assert!(
        !sessions.exists() || fs::read_dir(&sessions).unwrap().next().is_none(),
        "a dry run keeps no session"
    );
    assert_eq!(audit_events(&daemon.audit(), "dry_run", "denied").len(), 1);
    assert_eq!(audit_events(&daemon.audit(), "dry_run", "allowed").len(), 1);
    assert_eq!(audit_events(&daemon.audit(), "policy", "allowed").len(), 1);
    assert_eq!(audit_events(&daemon.audit(), "policy", "denied").len(), 1);
    assert!(audit_events(&daemon.audit(), "submit", "allowed").is_empty());
}

#[test]
fn a_template_s_committer_name_is_set_on_commits_and_any_other_refused() {
    let policy = POLICY.replace(
        "    committer_emails: [\"agent@writ\"]\n",
        "    committer_emails: [\"agent@writ\"]\n    committer_name: \"Writ agent\"\n",
    );
    let daemon = Daemon::start(&policy, Approvals::Ssh);
    let (a, out, _) = granted(&daemon, "a", &ticket("agent/a", ""), &[]);
    assert!(
        out.contains("Commits must carry the name Writ agent as author and committer"),
        "{out}"
    );
    let repo = clone(&daemon, "named");
    // The operator's own name, in the clone's config: plain git keeps it.
    git_ok(
        &daemon,
        &repo,
        &["config", "--local", "user.name", "Pat Operator"],
    );
    let out = writ_ok(&daemon, &repo, &["init", "demo", "--agents", "none"], &[]);
    assert!(
        out.contains("Committer name: Writ agent (the lease's)."),
        "{out}"
    );
    let out = writ_ok(&daemon, &repo, &["policy"], &[]);
    assert!(
        out.contains("committer name      Writ agent (every commit"),
        "{out}"
    );

    // Through `writ git`, the lease's name, as author and committer.
    assert!(commit(&daemon, &repo, "n1", Some(&a)).status.success());
    let idents = git_ok(&daemon, &repo, &["log", "-1", "--format=%an|%cn|%ae|%ce"]);
    assert_eq!(idents.trim(), "Writ agent|Writ agent|agent@writ|agent@writ");
    assert_eq!(
        git_ok(&daemon, &repo, &["config", "user.name"]).trim(),
        "Pat Operator"
    );

    // Any other name, as committer or as author: refused, with the reason and its code.
    fs::write(repo.join("n2"), "n2\n").unwrap();
    git_ok(&daemon, &repo, &["add", "n2"]);
    for (variable, who, code) in [
        ("GIT_COMMITTER_NAME", "committer", "committer_name"),
        ("GIT_AUTHOR_NAME", "author", "author_name"),
    ] {
        let out = writ(
            &daemon,
            &repo,
            &["git", "commit", "-q", "-m", "n2"],
            &[("WRIT_SESSION", &a), (variable, "Pat Operator")],
        );
        assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
        assert!(
            stderr(&out).contains(&format!(
                "{who} name \"Pat Operator\" is not the lease's committer_name \"Writ agent\""
            )),
            "{}",
            stderr(&out)
        );
        let denied = audit_events(&daemon.audit(), "sign", "denied");
        assert_eq!(denied.last().unwrap()["code"], code);
    }
    assert_eq!(
        ledger(&daemon, &a).len(),
        1,
        "nothing signed under another name"
    );
}
