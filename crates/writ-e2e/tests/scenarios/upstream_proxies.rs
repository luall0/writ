//! Scenario 25, upstreams behind a proxy (M7.2): Forgejo on a network the daemon isn't on
//! (`behind`), as `forgejo-behind` and `forgejo-https-behind`, which only two real proxies
//! reach, each asking for a password: microsocks (SOCKS5) for the `behind-socks` repository
//! over ssh, tinyproxy (HTTP CONNECT) for `behind-http` over HTTPS. The daemon can't even
//! resolve those names: the proxy does. The agent fetches, commits and pushes through the
//! daemon as with any repository; each push lands on Forgejo and in the mirror, the registry's
//! protection still holds, each proxy's log shows the tunnels it opened by name, and neither
//! password is in clear on the daemon's host, the agent's side or the audit log. ssh ran the
//! daemon's tunnel (`writd upstream-tunnel`) as its `ProxyCommand`.

use writ_e2e::Stack;
use writ_e2e::agent::expect;
use writ_e2e::docker::Container;
use writ_e2e::setup::{HTTP_PASSWORD, HTTP_REPO, SOCKS_PASSWORD, SOCKS_REPO};
use writ_e2e::stdout;

use crate::{assert_push_refused, wired};

#[test]
#[ignore = "end to end: make e2e"]
fn repos_behind_a_socks5_and_an_http_proxy_are_reached_through_them_alone() {
    let stack = Stack::shared();

    // The daemon's host knows neither name: only the proxies' network does.
    for name in ["forgejo-behind", "forgejo-https-behind"] {
        let out = stack.operator.run(&format!("getent hosts {name}"));
        assert_eq!(out.status.code(), Some(2), "{name}: {}", stdout(&out));
    }

    for (repo, proxy, tunnel) in [
        (SOCKS_REPO, "socks-proxy", "connected to forgejo-behind:22"),
        (
            HTTP_REPO,
            "http-proxy",
            "CONNECT forgejo-https-behind:3443 HTTP/1.1",
        ),
    ] {
        let agent = stack.agent(repo);
        let (lease, w) = wired(&stack, &agent, repo);
        let main = stack.forgejo.branch(repo, "main").unwrap();

        // A fetch through the daemon: the mirror synced through the proxy.
        agent.ok_in(&w, "writ git fetch -q origin");
        assert_eq!(
            stack.mirror_ref(repo, "refs/heads/main").as_deref(),
            Some(main.as_str()),
            "{repo}"
        );
        // A signed commit, pushed: on Forgejo and in the mirror.
        agent.ok_in(&w, "git checkout -q -b agent/proxied");
        let commit = agent.commit(&w, &lease, "notes.txt", "through a proxy");
        expect(
            &agent.in_dir(&w, "writ git push origin HEAD"),
            0,
            "the push through the proxy",
        );
        assert_eq!(
            stack.forgejo.branch(repo, "agent/proxied").as_deref(),
            Some(commit.as_str()),
            "{repo}"
        );
        assert_eq!(
            stack
                .mirror_ref(repo, "refs/heads/agent/proxied")
                .as_deref(),
            Some(commit.as_str()),
            "{repo}"
        );
        assert_eq!(stack.audited(&lease, "push", "allowed").len(), 1, "{repo}");
        // The registry's protection holds behind a proxy too: main refused, Forgejo unchanged.
        let out = agent.in_dir(&w, "writ git push origin HEAD:refs/heads/main");
        assert_push_refused(
            &stack,
            &lease,
            &out,
            "refs/heads/main is protected",
            "protected_ref",
        );
        assert_eq!(
            stack.forgejo.branch(repo, "main").as_deref(),
            Some(main.as_str())
        );
        // The proxy opened the tunnels, to the name it alone resolves.
        let logs = Container::of(proxy).logs();
        assert!(logs.contains(tunnel), "{proxy}'s log:\n{logs}");
    }

    // The passwords: sealed in the keystore, in clear nowhere on the daemon's host, on the
    // agents' side or in the audit log.
    for password in [SOCKS_PASSWORD, HTTP_PASSWORD] {
        let grep = format!("grep -rlF -e '{password}' .");
        let found = stack.operator.run(&grep);
        assert_eq!(
            found.status.code(),
            Some(1),
            "the password on the daemon's host: {}",
            stdout(&found)
        );
        // Every agent's directory, and the operator's own git there.
        let found = stack.agents_home.run(&grep);
        assert_eq!(
            found.status.code(),
            Some(1),
            "the password on the agent's side: {}",
            stdout(&found)
        );
        assert!(!stack.operator.read("data/audit.jsonl").contains(password));
    }
}

/// The approval flags, given explicitly, and `--yes`.
const FLAGS: &str = "--yes --approval-url \"$WRIT_APPROVAL_URL\" --key \
                     \"$HOME/.writ/approver.pub\" --agent \"$WRIT_APPROVAL_AGENT\"";

fn on_terminal(approver: &writ_e2e::Host, command: &str, answers: &[&str]) -> String {
    approver.on_terminal(command, answers)
}

fn exits_on_terminal(
    approver: &writ_e2e::Host,
    command: &str,
    answers: &[&str],
    code: i32,
) -> String {
    approver.exits_on_terminal(command, answers, code)
}

#[test]
#[ignore = "end to end: make e2e"]
fn proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them() {
    // It changes the policy every scenario runs under: alone, and put back at the end.
    let stack = Stack::exclusive();
    let approver = &stack.approver;
    approver.ok("writ admin show policy > policy-before-proxies.yaml");

    // Read: each proxy, what it is and the repos behind it, through the URL flag too.
    let url = approver.ok("printf %s \"$WRIT_APPROVAL_URL\"");
    let listed = approver.ok(&format!("writ admin proxy list --approval-url {url}"));
    assert!(
        listed.contains(
            "socks  socks5://writ@socks-proxy:1080  credential proxy-socks-password  repos \
             behind-socks"
        ),
        "{listed}"
    );
    let shown = approver.ok(&format!("writ admin proxy show http --approval-url {url}"));
    assert!(
        shown.starts_with("http:\n  url: \"http://writ@http-proxy:8888\"\n"),
        "{shown}"
    );
    for line in [
        "protocol: http, the upstream's name resolved by the proxy",
        "connect timeout: 20s",
        "repos: behind-http",
    ] {
        assert!(shown.contains(line), "{line}: {shown}");
    }
    // Its password, a token on the proxy's host, used by the proxy (never shown).
    let keys = approver.ok("writ admin key list");
    assert!(
        keys.contains("proxy-socks-password  upstream token for socks-proxy  added  proxies socks"),
        "{keys}"
    );
    let repo = approver.ok("writ admin repo show behind-socks");
    assert!(
        repo.contains("reached through: proxy socks (socks5://writ@socks-proxy:1080)"),
        "{repo}"
    );

    // Added, every field given; set; edited on a terminal (the credential not asked: its URL
    // names no user).
    let said = approver.ok(&format!(
        "writ admin proxy add bare url=socks5://socks-proxy:1080 {FLAGS}"
    ));
    assert!(said.contains("with proxy bare added"), "{said}");
    approver.ok(&format!(
        "writ admin proxy set bare connect_timeout=45s {FLAGS}"
    ));
    let said = on_terminal(
        approver,
        &format!("writ admin proxy edit bare {FLAGS}"),
        &["", "1m"],
    );
    assert!(!said.contains("credential ("), "{said}");
    assert!(
        approver
            .ok("writ admin proxy show bare")
            .contains("connect_timeout: 1m"),
        "edited"
    );
    // A proxy a repo is behind: never removed.
    let (_, err) = expect(
        &approver.run(&format!("writ admin proxy remove socks {FLAGS}")),
        1,
        "removing a proxy in use",
    );
    assert!(
        err.contains("proxy socks is in use by repos behind-socks"),
        "{err}"
    );

    // The repo moved behind a proxy that asks for a password it isn't given: refused with the
    // proxy's reason. Then reached directly: its name resolves nowhere, refused, never a
    // fallback. Then back behind its own proxy: reached.
    let agent = stack.agent("behind-socks-moved");
    let (lease, w) = wired(&stack, &agent, SOCKS_REPO);
    approver.ok(&format!(
        "writ admin repo set {SOCKS_REPO} proxy=bare {FLAGS}"
    ));
    let out = agent.in_dir(&w, "writ git fetch origin");
    let (_, err) = expect(&out, 128, "a fetch through a proxy without its password");
    // The agent is told upstream can't be reached, never the proxy's name or words (the
    // review after M7.6, M-5); the proxy's reason is in the audit line.
    assert!(
        err.contains("cannot sync from upstream")
            && err.contains("upstream can't be reached as configured")
            && !err.contains("proxy bare"),
        "{err}"
    );
    assert!(
        stack.audited(&lease, "fetch", "denied").iter().any(|line| {
            line["reason"].as_str().is_some_and(|r| {
                r.contains(
                    "proxy bare: it asks for a password, and none is configured (credential)",
                )
            })
        }),
        "the proxy's reason, in the audit line"
    );
    approver.ok(&format!("writ admin repo set {SOCKS_REPO} proxy! {FLAGS}"));
    let out = agent.in_dir(&w, "writ git fetch origin");
    let (_, err) = expect(&out, 128, "a fetch with no proxy");
    // The name that resolves nowhere is in the audit line, not in what the agent is told.
    assert!(!err.contains("forgejo-behind"), "{err}");
    assert!(
        stack.audited(&lease, "fetch", "denied").iter().any(|line| {
            line["reason"]
                .as_str()
                .is_some_and(|r| r.contains("forgejo-behind"))
        }),
        "the failure, with upstream's name, in the audit line"
    );
    approver.ok(&format!(
        "writ admin repo set {SOCKS_REPO} proxy=socks {FLAGS}"
    ));
    agent.ok_in(&w, "writ git fetch -q origin");
    approver.ok(&format!("writ admin proxy remove bare {FLAGS}"));
    assert!(!approver.ok("writ admin proxy list").contains("bare  "));

    // Hosts behind a proxy scanned through it: a rescan through the proxy its repos share (and
    // named), and a new name pinned through it.
    // The setup pinned Forgejo's Ed25519 key only: the rescan shows it pinned, and its ECDSA
    // key new. Declined first (nothing signed), then pinned through `--proxy`.
    let said = exits_on_terminal(
        approver,
        "writ admin host rescan forgejo-behind",
        &["y", "n"],
        6,
    );
    assert!(
        said.contains("Scanning forgejo-behind:22 from the daemon through proxy socks"),
        "{said}"
    );
    assert!(said.contains("  (pinned)"), "{said}");
    assert!(said.contains("Not signed."), "{said}");
    let said = on_terminal(
        approver,
        &format!("writ admin host rescan forgejo-behind --proxy socks {FLAGS}"),
        &["y"],
    );
    assert!(
        said.contains("with host forgejo-behind rescanned"),
        "{said}"
    );
    assert_eq!(
        approver
            .ok("writ admin host show forgejo-behind")
            .matches("\n  - ")
            .count(),
        2
    );
    let said = on_terminal(
        approver,
        "writ admin host add forgejo-behind-scan proxy=socks",
        &["y", "y"],
    );
    assert!(
        said.contains("Scanning forgejo-behind-scan:22 from the daemon through proxy socks"),
        "{said}"
    );
    assert!(
        said.contains("with host forgejo-behind-scan added"),
        "{said}"
    );
    let scans = stack
        .audit()
        .into_iter()
        .filter(|l| l["event"] == "scan" && l["result"] == "done")
        .filter(|l| {
            l["reason"]
                .as_str()
                .is_some_and(|r| r.starts_with("forgejo-behind-scan:22 through proxy socks: "))
        })
        .count();
    assert_eq!(scans, 1);
    let logs = Container::of("socks-proxy").logs();
    assert!(
        logs.contains("connected to forgejo-behind-scan:22"),
        "{logs}"
    );

    // Found on a real setup: a guided scan with no proxy named went direct. It asks which one
    // first. Direct, a name only the proxies resolve fails, saying how to go through one.
    // A select (M7.9.5): none first, then the proxies in force.
    let asked = "[the proxy the scan goes through, Enter for none (reached directly); in force: \
                 http, socks]";
    let said = exits_on_terminal(approver, "writ admin host add forgejo-behind-new", &[""], 1);
    assert!(said.contains(asked), "{said}");
    assert!(
        said.contains("> proxy none: the host reached directly"),
        "{said}"
    );
    assert!(
        said.contains("Scanning forgejo-behind-new:22 from the daemon: one signature"),
        "{said}"
    );
    assert!(
        said.contains(
            "If the host is reachable only through a proxy: scan through one in force (http, \
             socks) with proxy=<name>."
        ),
        "{said}"
    );
    // A guided `repo add` on that host: the proxy asked before the scan (a select of the ones
    // in force: a name not in force can't be picked, and the plain prompt's refusal of one is
    // `scan_proxy_answer`'s unit test), the scan through it, the answer the repo's own proxy
    // (never asked again), then the repo checked through it.
    let said = on_terminal(
        approver,
        "writ admin repo add behind-asked",
        &[
            "ssh://git@forgejo-behind-new/writ/behind-socks.git",
            "socks",
            "y",
            "upstream-behind-socks",
            // templates, a multi-select: feature ticked.
            "feature ",
            "",
            "",
            "",
            "y",
            "",
        ],
    );
    // Asked once, answered once: socks.
    assert_eq!(said.matches("> proxy ").count(), 1, "{said}");
    assert!(said.contains("> proxy socks"), "{said}");
    assert!(
        said.contains("Scanning forgejo-behind-new:22 from the daemon through proxy socks"),
        "{said}"
    );
    assert!(
        !said.contains("a proxy in proxies, to reach upstream through"),
        "{said}"
    );
    assert!(said.contains("with repo behind-asked added"), "{said}");
    assert!(said.contains("behind-asked is ready"), "{said}");
    assert!(
        approver
            .ok("writ admin repo show behind-asked")
            .contains("proxy: socks"),
        "the repo behind the proxy answered"
    );

    // Put back as it was.
    approver.ok("writ admin apply policy policy-before-proxies.yaml --yes");
    assert_eq!(
        approver.ok("writ admin show policy"),
        approver.ok("cat policy-before-proxies.yaml")
    );
}
