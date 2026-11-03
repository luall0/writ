//! Scenario 19, every protocol version a client asks for: the daemon's `upload-pack` speaks
//! protocol v0 only (in v2, git ignores `uploadpack.allow*SHA1InWant` and would serve any
//! object the mirror holds by its id), and nothing an agent does with git notices: clones and
//! fetches with git's default (it asks for v2), v2, v1 and v0 asked, all with the same refs;
//! `ls-remote` with v2 asked; a shallow clone deepened; a `--filter=blob:none` clone falling
//! back to a full one; a reachable commit that isn't a tip fetched by its id; a commit no ref
//! reaches (its branch deleted on Forgejo after the mirror synced) refused by its id with v2
//! asked; a push right after a v2 fetch. (No repository of the stack is in SHA-256.)

use writ_e2e::Stack;
use writ_e2e::agent::{Agent, expect};
use writ_e2e::forgejo::OWNER;

use crate::wired;

/// Runs `script` (no single quote in it) in the agent's directory `dir`, with the wiring of
/// the clone `w` (`writ exec`): how the clones made here, not wired themselves, reach the
/// daemon. Its output.
fn in_with_wiring(agent: &Agent, w: &str, dir: &str, script: &str) -> std::process::Output {
    agent.in_dir(w, &format!("writ exec -- sh -c 'cd ../{dir} && {script}'"))
}

/// Every object reachable in the clone `dir` is there (none missing, as in a partial clone).
fn nothing_missing(agent: &Agent, dir: &str) {
    let missing = agent.ok_in(
        dir,
        "git rev-list --objects --missing=print --all | grep '^?' || true",
    );
    assert_eq!(missing.trim(), "", "{dir}: missing objects");
}

#[test]
#[ignore = "end to end: make e2e"]
fn every_protocol_version_fetches_and_only_what_refs_reach_is_served() {
    let stack = Stack::shared();
    let agent = stack.agent("protocols");
    // On Forgejo: main one commit past its first, and a branch `gone`.
    let first = stack.forgejo.branch("protocols", "main").unwrap();
    let second = stack
        .forgejo
        .commit_file("protocols", "main", "second.txt", "second\n");
    stack.forgejo.create_branch("protocols", "gone", "main");
    let gone = stack
        .forgejo
        .commit_file("protocols", "gone", "gone.txt", "gone\n");
    let (lease, w) = wired(&stack, &agent, "protocols");
    let url = agent
        .ok_in(&w, "writ git remote get-url origin")
        .trim()
        .to_owned();
    assert!(url.starts_with("ssh://"), "origin is the daemon's: {url}");

    // (1) Clones with git's default and with each version asked: the same refs and content;
    // a fetch with each in the wired clone.
    let mut listings = Vec::new();
    for (name, config) in [
        ("default", ""),
        ("v2", "-c protocol.version=2"),
        ("v1", "-c protocol.version=1"),
        ("v0", "-c protocol.version=0"),
    ] {
        let clone = format!("clone-{name}");
        agent.ok_in(&w, &format!("writ git {config} clone -q {url} ../{clone}"));
        assert_eq!(agent.ok_in(&clone, "cat second.txt"), "second\n", "{name}");
        nothing_missing(&agent, &clone);
        listings.push((
            name,
            agent.ok_in(
                &clone,
                "git for-each-ref --format='%(refname) %(objectname)' refs/remotes",
            ),
        ));
        agent.ok_in(&w, &format!("writ git {config} fetch -q origin"));
    }
    for (name, listed) in &listings {
        assert_eq!(listed, &listings[0].1, "{name}'s refs");
        assert!(
            listed.contains(&format!("refs/remotes/origin/main {second}")),
            "{name}: {listed}"
        );
        assert!(
            listed.contains(&format!("refs/remotes/origin/gone {gone}")),
            "{name}: {listed}"
        );
    }

    // (2) ls-remote with v2 asked: the mirror's branches.
    let listed = agent.ok_in(&w, "writ git -c protocol.version=2 ls-remote origin");
    assert!(
        listed.contains(&format!("{second}\trefs/heads/main")),
        "{listed}"
    );
    assert!(
        listed.contains(&format!("{gone}\trefs/heads/gone")),
        "{listed}"
    );

    // (3) A shallow clone, then deepened by one commit.
    agent.ok_in(&w, &format!("writ git clone -q --depth 1 {url} ../shallow"));
    assert_eq!(
        agent.ok_in("shallow", "git rev-list --count HEAD").trim(),
        "1"
    );
    let out = in_with_wiring(&agent, &w, "shallow", "git fetch -q --deepen 1 origin");
    expect(&out, 0, "git fetch --deepen 1");
    assert_eq!(
        agent.ok_in("shallow", "git rev-list --count HEAD").trim(),
        "2"
    );

    // (6) A partial clone: the daemon advertises no filter; git says so and clones it whole.
    let out = agent.in_dir(
        &w,
        &format!("writ git clone --filter=blob:none {url} ../filtered"),
    );
    let (_, err) = expect(&out, 0, "a --filter=blob:none clone");
    assert!(err.contains("filtering not recognized by server"), "{err}");
    assert_eq!(agent.ok_in("filtered", "cat second.txt"), "second\n");
    nothing_missing(&agent, "filtered");

    // (4) A reachable commit that isn't a tip, by its id, with v2 asked: served.
    agent.ok("git init -q reachable");
    let out = in_with_wiring(
        &agent,
        &w,
        "reachable",
        &format!("git -c protocol.version=2 fetch -q {url} {first}"),
    );
    expect(&out, 0, "a reachable commit by its id");
    agent.ok_in("reachable", &format!("git cat-file -e {first}"));

    // (5) `gone` deleted on Forgejo; the next fetch syncs the mirror, which prunes the ref
    // and keeps the commit, reached by no ref. Asked for by its id with v2: refused.
    stack.forgejo.api_ok(
        "DELETE",
        &format!("/repos/{OWNER}/protocols/branches/gone"),
        None,
        204,
    );
    agent.ok_in(&w, "writ git fetch -q --prune origin");
    assert_eq!(stack.mirror_ref("protocols", "refs/heads/gone"), None);
    assert!(stack.mirror_has("protocols", &gone), "the commit stays");
    agent.ok("git init -q unreachable");
    let out = in_with_wiring(
        &agent,
        &w,
        "unreachable",
        &format!("git -c protocol.version=2 fetch -q {url} {gone}"),
    );
    let (_, err) = expect(&out, 128, "a commit no ref reaches, by its id");
    assert!(
        err.contains(&format!("upload-pack: not our ref {gone}")),
        "{err}"
    );
    let missing = agent.in_dir("unreachable", &format!("git cat-file -e {gone}"));
    expect(&missing, 1, "the commit never came");

    // (7) A push right after a v2 fetch.
    agent.ok_in(&w, "writ git -c protocol.version=2 fetch -q origin");
    agent.ok_in(&w, "git checkout -q -b agent/protocols origin/main");
    let mine = agent.commit(&w, &lease, "mine.txt", "mine");
    expect(
        &agent.in_dir(&w, "writ git -c protocol.version=2 push -q origin HEAD"),
        0,
        "a push after a v2 fetch",
    );
    assert_eq!(
        stack
            .forgejo
            .branch("protocols", "agent/protocols")
            .as_deref(),
        Some(mine.as_str())
    );
    assert_eq!(
        stack
            .mirror_ref("protocols", "refs/heads/agent/protocols")
            .as_deref(),
        Some(mine.as_str())
    );
    // None of the fetches was refused by the policy (the unreachable id is git's refusal,
    // once the policy allowed the fetch).
    assert!(stack.audited(&lease, "fetch", "denied").is_empty());
}
