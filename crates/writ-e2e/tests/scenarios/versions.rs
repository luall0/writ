//! Scenario 29, versions (M7.9.8): each binary in its own container says its version, the
//! workspace's (`writd` on the operator's host, `writ` on the approver's and the agents',
//! `writ-sign` on the agents'); the daemon names it in every reply; and `writ`, of the same
//! version, says nothing about it (`writ ls` over the approval API, `writ policy` over the
//! agents' listener).

use writ_e2e::Stack;
use writ_e2e::agent::expect;

/// The workspace's version, which every binary takes.
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[test]
#[ignore = "end to end: make e2e"]
fn every_binary_says_its_version_and_writ_says_nothing_of_the_daemon_s_own() {
    let stack = Stack::shared();
    let agent = stack.agent("versions");
    for (host, binary) in [
        (&stack.operator, "writd"),
        (&stack.approver, "writ"),
        (&agent.host, "writ"),
        (&agent.host, "writ-sign"),
    ] {
        let (out, err) = expect(&host.run(&format!("{binary} --version")), 0, binary);
        assert_eq!(out, format!("{binary} {VERSION}\n"), "{binary}");
        assert_eq!(err, "", "{binary}");
    }

    // The same version on both sides: nothing said, on either listener.
    let (_, err) = expect(&stack.approver.run("writ ls"), 0, "writ ls");
    assert!(!err.contains("install the same version"), "{err}");
    let (_, err) = expect(&agent.run("writ policy setup"), 0, "writ policy");
    assert!(!err.contains("install the same version"), "{err}");
}
