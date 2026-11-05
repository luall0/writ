//! Scenario 22, per-repository tickets (M6.1.5): one ticket for `pr-api` and `pr-web` under
//! two templates, its template named where two fit, granted with one signature, the lease as
//! long as the stricter template allows; each repository held to its own part (a branch, a
//! path, a count allowed in one and refused in the other, with its code); a ticket whose
//! repositories sign with different keys rejected naming each; and the same work as one lease
//! per repository, each repository's commands under its own `WRIT_SESSION`.

use writ_e2e::Stack;
use writ_e2e::agent::expect;

/// Both repositories; pr-api's template left to the daemon unless `api_template` names one.
fn both(api_template: &str) -> String {
    format!(
        "common:\n  committer_emails: [\"agent@writ.invalid\"]\n\
         repos:\n  pr-api:\n{api_template}    operations: [fetch, commit_sign, push]\n    \
         branches: [\"agent/split\"]\n  pr-web:\n    operations: [fetch, commit_sign, push]\n    \
         branches: [\"review/split\"]\n    expected_paths: [\"app/**\"]\n    \
         limits: {{ max_pushes: 1 }}\n\
         ticket:\n  title: \"e2e: per-repository\"\n  task: \"One ticket, two templates\"\n"
    )
}

/// One repository's own ticket (the one-lease-per-repository way).
fn one(repo: &str, template: &str, branch: &str) -> String {
    format!(
        "common:\n  committer_emails: [\"agent@writ.invalid\"]\n\
         repos:\n  {repo}:\n    template: {template}\n    operations: [fetch, commit_sign, push]\n    \
         branches: [\"{branch}\"]\n\
         ticket:\n  title: \"e2e: {repo} alone\"\n  task: \"One lease per repository\"\n\
         limits:\n  ttl: 30m\n"
    )
}

#[test]
#[ignore = "end to end: make e2e"]
fn one_ticket_holds_each_repository_to_its_own_template() {
    let stack = Stack::shared();
    let agent = stack.agent("per-repo");

    // What each repository allows, and whether one ticket covers both.
    let policy = agent.ok("writ policy pr-api pr-web");
    assert!(
        policy.contains(
            "With signing key agent-e2e, commit_sign in every repository: pr-api: feature or \
             pr-backend; pr-web: pr-frontend."
        ),
        "{policy}"
    );

    // pr-api fits two templates: the daemon never guesses.
    agent.write("unnamed.yaml", &both(""), "0644");
    let out = agent.run("writ request --dry-run unnamed.yaml");
    let (_, err) = expect(&out, 3, "a repository two templates fit");
    assert!(
        err.contains(
            "repos.pr-api fits several templates (feature, pr-backend): name one in \
             repos.pr-api.template"
        ),
        "{err}"
    );
    // Repositories whose templates sign with different keys: rejected, each one named.
    agent.write(
        "keys.yaml",
        &both("    template: pr-backend\n").replace(
            "  pr-web:\n",
            "  verified:\n    operations: [fetch, commit_sign]\n    branches: [\"agent/x\"]\n  pr-web:\n",
        ),
        "0644",
    );
    let out = agent.run("writ request --dry-run keys.yaml");
    let (_, err) = expect(&out, 3, "two signing keys");
    assert!(
        err.contains(
            "the repositories sign with different keys: pr-api (template pr-backend, key \
             agent-e2e), pr-web (template pr-frontend, key agent-e2e), verified (template \
             verified, key agent-e2e-verify)"
        ),
        "{err}"
    );

    // Named: one signature, one lease, each repository's template, the stricter's time.
    let id = agent.lease(&stack, &both("    template: pr-backend\n"));
    let lease: serde_json::Value =
        serde_json::from_str(&agent.session_file(&id, "lease.json")).unwrap();
    assert_eq!(
        lease["repos"]["pr-api"]["template"], "pr-backend",
        "{lease}"
    );
    assert_eq!(
        lease["repos"]["pr-web"]["template"], "pr-frontend",
        "{lease}"
    );
    assert_eq!(lease["common"]["signing_key"], "agent-e2e", "{lease}");
    assert_eq!(stack.audited(&id, "grant", "allowed").len(), 1);

    for repo in ["pr-api", "pr-web"] {
        agent.clone_from_forgejo(&stack, repo, repo);
        agent.ok_in(repo, &format!("writ init {repo} --agents none"));
    }
    // pr-api: its branch, any path.
    agent.ok_in("pr-api", "git checkout -q -b agent/split");
    let api = agent.commit("pr-api", &id, "server.txt", "route");
    expect(
        &agent.in_dir("pr-api", "writ git push -q origin HEAD"),
        0,
        "a push on pr-api's branch",
    );
    assert_eq!(
        stack.forgejo.branch("pr-api", "agent/split").as_deref(),
        Some(api.as_str())
    );
    // pr-web: a path outside its expected_paths refused at signing (pr-frontend denies).
    agent.ok_in("pr-web", "git checkout -q -b agent/split");
    let out = agent.in_dir(
        "pr-web",
        &format!(
            "echo x > server.txt && writ git add server.txt && \
             writ git commit -q -m Outside --trailer 'Writ: {id}'"
        ),
    );
    expect(
        &out,
        128,
        "a commit outside app/** (git: the signing failed)",
    );
    let denied = stack.audited(&id, "sign", "denied");
    assert_eq!(denied.last().unwrap()["code"], "paths", "{denied:?}");
    agent.ok_in("pr-web", "git reset -q --hard && git clean -qfd");
    // Inside: signed; pushed to pr-api's branch name, refused (pr-web's is review/split).
    agent.ok_in("pr-web", "mkdir -p app");
    let web = agent.commit("pr-web", &id, "app/button.txt", "button");
    let out = agent.in_dir("pr-web", "writ git push origin HEAD:refs/heads/agent/split");
    expect(&out, 1, "pr-api's branch in pr-web");
    let denied = stack.audited(&id, "push", "denied");
    assert_eq!(denied.last().unwrap()["code"], "ref", "{denied:?}");
    assert_eq!(stack.forgejo.branch("pr-web", "agent/split"), None);
    // Its own branch: once (its one push), then refused for the count; pr-api still pushes.
    expect(
        &agent.in_dir(
            "pr-web",
            "writ git push -q origin HEAD:refs/heads/review/split",
        ),
        0,
        "pr-web's one push",
    );
    assert_eq!(
        stack.forgejo.branch("pr-web", "review/split").as_deref(),
        Some(web.as_str())
    );
    agent.commit("pr-web", &id, "app/second.txt", "two");
    let out = agent.in_dir(
        "pr-web",
        "writ git push origin HEAD:refs/heads/review/split",
    );
    expect(&out, 1, "a second push in pr-web");
    let denied = stack.audited(&id, "push", "denied");
    assert_eq!(denied.last().unwrap()["code"], "limit", "{denied:?}");
    let api2 = agent.commit("pr-api", &id, "server2.txt", "more");
    expect(
        &agent.in_dir("pr-api", "writ git push -q origin HEAD"),
        0,
        "pr-api keeps its own pushes",
    );
    assert_eq!(
        stack.forgejo.branch("pr-api", "agent/split").as_deref(),
        Some(api2.as_str())
    );
    let out = agent.run(&format!(
        "WRIT_SESSION={id} writ close --summary 'Two templates, one lease'"
    ));
    expect(&out, 0, "writ close");
}

#[test]
#[ignore = "end to end: make e2e"]
fn the_same_work_as_one_lease_per_repository() {
    let stack = Stack::shared();
    let agent = stack.agent("per-repo-split");
    let api = agent.lease(&stack, &one("pr-api", "pr-backend", "agent/alone"));
    let web = agent.lease(&stack, &one("pr-web", "pr-frontend", "review/alone"));
    for repo in ["pr-api", "pr-web"] {
        agent.clone_from_forgejo(&stack, repo, repo);
        agent.ok_in(repo, &format!("writ init {repo} --agents none"));
    }
    // Each repository's commands under its own lease.
    let pushed = |repo: &str, lease: &str, branch: &str, file: &str| {
        agent
            .ok_in(
                repo,
                &format!(
                    "export WRIT_SESSION={lease} && git checkout -q -b {branch} && mkdir -p app && \
                 echo x > {file} && writ git add {file} && \
                 writ git commit -q -m 'Change {file}' --trailer 'Writ: {lease}' && \
                 writ git push -q origin HEAD && git rev-parse HEAD"
                ),
            )
            .trim()
            .to_owned()
    };
    let api_commit = pushed("pr-api", &api, "agent/alone", "server.txt");
    let web_commit = pushed("pr-web", &web, "review/alone", "app/a.txt");
    assert_eq!(
        stack.forgejo.branch("pr-api", "agent/alone").as_deref(),
        Some(api_commit.as_str())
    );
    assert_eq!(
        stack.forgejo.branch("pr-web", "review/alone").as_deref(),
        Some(web_commit.as_str())
    );
    assert_eq!(stack.audited(&api, "push", "allowed").len(), 1);
    assert_eq!(stack.audited(&web, "push", "allowed").len(), 1);
    // The other lease's repository: refused, with its code.
    let out = agent.in_dir(
        "pr-web",
        &format!("WRIT_SESSION={api} writ git fetch origin"),
    );
    expect(&out, 128, "pr-web under pr-api's lease");
    let denied = stack.audited(&api, "fetch", "denied");
    assert_eq!(denied.last().unwrap()["code"], "repo", "{denied:?}");
    for lease in [&api, &web] {
        let out = agent.run(&format!(
            "WRIT_SESSION={lease} writ close --summary 'One of two'"
        ));
        expect(&out, 0, "writ close");
    }
}
