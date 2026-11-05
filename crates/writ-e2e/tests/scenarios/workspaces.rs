//! Scenario 21, multi-repo workspaces: a folder holding two clones, wired at once by `writ
//! init` with no repo named (each repository's registry name given with `--repo`, required
//! without a terminal), the `writ-workspace` skill at the folder only; one agent at the folder
//! working on both under one lease through `writ git -C` and `writ exec -C` (the folder
//! itself listing them), both branches on Forgejo and in the mirrors; the run closed at the
//! folder, recorded under both repositories; and `writ init --undo` at the folder taking every
//! repository and the folder back (the timings kept).

use std::collections::BTreeSet;

use writ_e2e::Stack;
use writ_e2e::agent::{expect, ticket};

/// The folder's files, git's own left out.
const FILES: &str = "find . -path '*/.git' -prune -o -print";

/// Each clone's own config.
const CONFIGS: &str = "git -C api config --local --list && git -C web config --local --list";

#[test]
#[ignore = "end to end: make e2e"]
fn one_agent_at_a_workspace_root_works_on_two_repositories_under_one_lease() {
    let stack = Stack::shared();
    let agent = stack.agent("workspace");
    agent.ok("mkdir ws");
    agent.clone_from_forgejo(&stack, "ws-api", "ws/api");
    agent.clone_from_forgejo(&stack, "ws-web", "ws/web");
    let files = || -> BTreeSet<String> {
        agent
            .ok_in("ws", FILES)
            .lines()
            .map(str::to_owned)
            .collect()
    };
    let before = (files(), agent.ok_in("ws", CONFIGS));

    // Without a terminal, every repository's registry name must be given: nothing wired.
    let out = agent.in_dir("ws", "writ init --agents claude");
    let (_, err) = expect(&out, 1, "writ init at a workspace, no names");
    assert!(
        err.contains(
            "no terminal to confirm the registry names: pass --repo <dir>=<name> (or <dir>=- to \
             leave it out) for each of: api (by default ws-api), web (by default ws-web) \
             (nothing was wired)"
        ),
        "{err}"
    );
    assert_eq!((files(), agent.ok_in("ws", CONFIGS)), before);

    // Wired: both clones under their names, the skill at the folder only.
    let out = agent.in_dir(
        "ws",
        "writ init --agents claude --repo api=ws-api --repo web/=ws-web",
    );
    let (out, _) = expect(&out, 0, "writ init --repo");
    assert!(out.starts_with("Workspace wired for Writ at "), "{out}");
    assert!(out.contains("\n  api  repo ws-api, origin "), "{out}");
    assert!(out.contains("\n  web  repo ws-web, origin "), "{out}");
    let skill = agent.read("ws/.claude/skills/writ-workspace/SKILL.md");
    assert!(skill.starts_with("---\nname: writ-workspace\n"), "{skill}");
    assert!(
        skill.contains("- `api`: repo `ws-api`\n- `web`: repo `ws-web`"),
        "{skill}"
    );
    agent.ok("test ! -e ws/api/.claude && test ! -e ws/web/.claude");
    // `writ skill update` at the folder: the workspace's skill, its repositories listed again;
    // in one of its repositories, refused, naming the folder.
    agent
        .ok("sed -i 's/repo `ws-web`/repo `elsewhere`/' ws/.claude/skills/writ-workspace/SKILL.md");
    let out = agent.ok_in("ws", "writ skill update");
    assert!(
        out.contains("The writ-workspace skill, from this writ:\n  .claude/skills/writ-workspace/SKILL.md: updated\n"),
        "{out}"
    );
    assert_eq!(
        agent.read("ws/.claude/skills/writ-workspace/SKILL.md"),
        skill
    );
    let out = agent.in_dir("ws/api", "writ skill update");
    let (_, err) = expect(&out, 1, "writ skill update in a workspace repository");
    assert!(err.contains("run `writ skill update` there"), "{err}");

    // The folder is no repository: `writ git` there lists the workspace's.
    let out = agent.in_dir("ws", "writ git status");
    let (_, err) = expect(&out, 1, "writ git at the workspace root");
    assert!(
        err.contains("is a Writ workspace, not a repository wired for Writ"),
        "{err}"
    );
    assert!(
        err.contains("  api  repo ws-api  (writ git -C api …)"),
        "{err}"
    );

    // One lease for both, asked for after reading each repository's policy.
    let (out, _) = expect(&agent.in_dir("ws", "writ policy ws-web"), 0, "writ policy");
    assert!(
        out.contains("What a ticket for repo ws-web may ask"),
        "{out}"
    );
    let lease = agent.lease(
        &stack,
        &ticket(&["ws-api", "ws-web"], &["agent/*"], "1h", ""),
    );

    // A commit in each, through `writ git -C` from the folder; both pushed by `origin`.
    let mut heads = Vec::new();
    for (dir, repo) in [("api", "ws-api"), ("web", "ws-web")] {
        let head = agent.ok_in(
            "ws",
            &format!(
                "writ git -C {dir} switch -q -c agent/login && echo login > {dir}/login.txt && \
                 writ git -C {dir} add login.txt && \
                 writ git -C {dir} commit -q -m 'Login in {repo}' && \
                 git -C {dir} rev-parse HEAD"
            ),
        );
        let head = head.trim().to_owned();
        agent.ok_in("ws", &format!("writ git -C {dir} push -q origin HEAD"));
        assert_eq!(
            stack.forgejo.branch(repo, "agent/login").as_deref(),
            Some(head.as_str()),
            "{repo}"
        );
        assert_eq!(
            stack.mirror_ref(repo, "refs/heads/agent/login").as_deref(),
            Some(head.as_str()),
            "{repo}"
        );
        heads.push(head);
    }
    let signed = stack.audited(&lease, "sign", "allowed");
    assert_eq!(signed.len(), 2, "{signed:?}");
    assert_eq!(stack.audited(&lease, "push", "allowed").len(), 2);

    // A program that runs git, in one repository: `writ exec -C`.
    let out = agent.ok_in("ws", "writ exec -C web -- sh -c 'git config writ.repo'");
    assert_eq!(out.trim(), "ws-web");

    // Closed at the folder: the run recorded under both repositories.
    agent.ok_in("ws", "writ mark checks");
    let (out, _) = expect(
        &agent.in_dir(
            "ws",
            "writ close --summary 'Login in the API and the web app'",
        ),
        0,
        "writ close at the workspace root",
    );
    assert!(out.contains("Recorded in "), "{out}");
    let timings = agent.read("ws/.claude/skills/writ-workspace/timings.md");
    assert!(timings.contains("\n## ws-api + ws-web\n"), "{timings}");
    assert!(timings.contains(&format!(" {lease}: used ")), "{timings}");

    // Undone in one repository: refused; at the folder: everything back, the timings kept.
    let out = agent.in_dir("ws/api", "writ init --undo");
    let (_, err) = expect(&out, 1, "writ init --undo in a workspace repository");
    assert!(err.contains("run `writ init --undo` there"), "{err}");
    let (out, _) = expect(
        &agent.in_dir("ws", "writ init --undo"),
        0,
        "writ init --undo",
    );
    assert!(
        out.contains("  api: wiring removed (wrapper mode)."),
        "{out}"
    );
    assert!(
        out.contains("  web: wiring removed (wrapper mode)."),
        "{out}"
    );
    assert_eq!(agent.ok_in("ws", CONFIGS), before.1, "every clone's config");
    let after = files();
    assert!(before.0.is_subset(&after), "nothing of before removed");
    let added: Vec<&str> = after.difference(&before.0).map(String::as_str).collect();
    assert_eq!(
        added,
        [
            "./.claude",
            "./.claude/skills",
            "./.claude/skills/writ-workspace",
            "./.claude/skills/writ-workspace/timings.md",
            "./api/login.txt",
            "./web/login.txt",
        ],
        "only the timings file and the agent's work stay"
    );
}
