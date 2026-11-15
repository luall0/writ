//! A policy of an older format rewritten to the current one (M7.9.6): the format read from
//! the text alone; format 1's push modes dropped where the policy means the same without
//! them, a reason naming the key where it doesn't; the rewrite the canonical layout of a
//! format 2 policy, checked as the daemon checks one; any other format refused with its
//! error.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use writ_core::config::migrate::{self, MigrateError, Proposal};
use writ_core::config::{POLICY_FORMAT, PolicyConfig};
use writ_core::fit::DEFAULT_MIN_TTL;
use writ_core::units::Duration;

/// The writ-core fixture as format 1 wrote it: no `format`, push modes on its repos and
/// templates (gateway in each but one), a `direct_ssh` section.
fn format_1() -> String {
    include_str!("fixtures/policy.yaml")
        .replacen("format: 2\n", "", 1)
        .replacen(
            "    ticket_link: trailer\n",
            "    push_modes: [gateway]\n    ticket_link: trailer\n",
            1,
        )
        .replacen(
            "    ticket_link: ledger_only\n",
            "    push_modes: [gateway, proxy]\n    ticket_link: ledger_only\n",
            1,
        )
        .replacen(
            "    templates: [quick-fix]\n",
            "    templates: [quick-fix]\n    push_modes: [gateway, direct_ssh]\n    direct_ssh:\n      \
             hosts: [github.com]\n      allow_account_wide: true\n",
            1,
        )
        .replacen(
            "    branches: [\"agent/*\"]\n",
            "    branches: [\"agent/*\"]\n    push_modes: [gateway, proxy]\n",
            1,
        )
}

fn propose(text: &str) -> Result<Proposal, MigrateError> {
    migrate::propose(text, DEFAULT_MIN_TTL)
}

/// The reasons a rewrite gave, as text.
fn reasons(result: Result<Proposal, MigrateError>) -> Vec<String> {
    match result {
        Err(MigrateError::Reasons(reasons)) => reasons.iter().map(ToString::to_string).collect(),
        other => panic!("not reasons: {other:?}"),
    }
}

#[test]
fn the_format_is_read_from_the_text_alone() {
    assert_eq!(migrate::format_of(&format_1()).unwrap(), 1);
    assert_eq!(
        migrate::format_of("format: 2\nanything: [else]\n").unwrap(),
        2
    );
    assert_eq!(migrate::format_of("format: 7\n").unwrap(), 7);
    assert_eq!(
        migrate::format_of("repos: {}\n").unwrap(),
        1,
        "none: format 1"
    );
    // Not a number, or not YAML: an error naming where, never a format.
    let error = |text| migrate::format_of(text).unwrap_err().to_string();
    assert_eq!(
        error("format: two\n"),
        "format: line 1 column 9: invalid u32"
    );
    assert_eq!(
        error("format: -1\n"),
        "format: line 1 column 9: invalid u32"
    );
    assert_eq!(
        error("format: [2]\n"),
        "format: line 1 column 9: expected string scalar"
    );
    assert_eq!(
        error("repos: [unclosed"),
        "repos: line 1 column 8: unclosed bracket '['"
    );
    // A key twice is refused as by every parse of a policy.
    assert!(
        error("format: 2\nformat: 2\n")
            .starts_with("?: line 2 column 1: duplicate mapping key: format"),
        "{}",
        error("format: 2\nformat: 2\n")
    );
}

#[test]
fn a_format_1_policy_is_rewritten_with_its_push_modes_dropped() {
    let old = format_1();
    // Format 1 is refused by the reader: only the rewrite reads it.
    assert!(
        PolicyConfig::from_yaml(&old)
            .unwrap_err()
            .to_string()
            .starts_with("format: missing")
    );
    let proposal = propose(&old).unwrap();
    assert_eq!((proposal.from, proposal.to), (1, POLICY_FORMAT));
    assert!(
        proposal.text.starts_with("format: 2\n"),
        "{}",
        proposal.text
    );
    assert!(!proposal.text.contains("push_modes"), "{}", proposal.text);
    assert!(!proposal.text.contains("direct_ssh"), "{}", proposal.text);
    // The rewrite is the format 2 policy that means the same: the fixture, in the canonical
    // layout, which reads back as itself.
    let fixture = PolicyConfig::from_yaml(include_str!("fixtures/policy.yaml")).unwrap();
    let read = PolicyConfig::from_yaml(&proposal.text).unwrap();
    assert_eq!(read, fixture);
    assert_eq!(proposal.text, fixture.to_yaml());
    // A format 1 text written with `format: 1` reads the same.
    let named = propose(&format!("format: 1\n{old}")).unwrap();
    assert_eq!(named.text, proposal.text);
}

#[test]
fn a_push_mode_list_without_gateway_is_a_reason_naming_its_key() {
    for (old, new, at) in [
        (
            "push_modes: [gateway]\n    ticket_link: trailer",
            "push_modes: [proxy]\n    ticket_link: trailer",
            "repos.omega-code.push_modes: [proxy] has no gateway, so no push was accepted",
        ),
        (
            "push_modes: [gateway, direct_ssh]",
            "push_modes: [direct_ssh]",
            "repos.dotfiles.push_modes: [direct_ssh] has no gateway",
        ),
        (
            "    branches: [\"agent/*\"]\n    push_modes: [gateway, proxy]",
            "    branches: [\"agent/*\"]\n    push_modes: [proxy]",
            "templates.feature-branch.push_modes: [proxy] has no gateway",
        ),
        (
            "push_modes: [gateway]\n    ticket_link: trailer",
            "push_modes: []\n    ticket_link: trailer",
            "repos.omega-code.push_modes: [] has no gateway",
        ),
        (
            "push_modes: [gateway]\n    ticket_link: trailer",
            "push_modes: [gateway, ftp]\n    ticket_link: trailer",
            "repos.omega-code.push_modes: \"ftp\" is not a push mode",
        ),
    ] {
        let text = format_1().replacen(old, new, 1);
        assert_ne!(text, format_1(), "{old}");
        let got = reasons(propose(&text));
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].starts_with(at), "{got:?} should start with {at:?}");
    }
    // Every key it can't carry over is named at once, not the first only.
    let both = format_1()
        .replacen(
            "push_modes: [gateway]\n    ticket_link: trailer",
            "push_modes: [proxy]\n    ticket_link: trailer",
            1,
        )
        .replacen(
            "push_modes: [gateway, direct_ssh]",
            "push_modes: [direct_ssh]",
            1,
        );
    assert_eq!(reasons(propose(&both)).len(), 2);
    // The reason says how to settle it.
    assert!(
        reasons(propose(&both))[0].ends_with("write the policy you want (writ migrate --file)")
    );
}

#[test]
fn a_rewrite_is_checked_as_the_daemon_checks_a_policy() {
    // A template's max_ttl under the daemon's min_ttl: the rewrite doesn't pass, a reason.
    let short = format_1().replacen("max_ttl: 1h", "max_ttl: 1m", 1);
    let got = reasons(propose(&short));
    assert!(
        got[0].starts_with("templates.quick-fix.max_ttl: "),
        "{got:?}"
    );
    // With the daemon's own min_ttl.
    let long = migrate::propose(&format_1(), Duration::from_seconds(5 * 3600));
    assert!(matches!(long, Err(MigrateError::Reasons(_))), "{long:?}");
    // Not YAML, or keys twice: unreadable, never rewritten.
    assert!(matches!(
        propose("repos: [unclosed"),
        Err(MigrateError::Unreadable(_))
    ));
    assert!(matches!(
        propose(&format!("{}\nrepos: {{}}\n", format_1())),
        Err(MigrateError::Unreadable(_))
    ));
    // An unknown key in format 1 is unknown in the rewrite too.
    assert!(matches!(
        propose(&format!("{}\napprovers: []\n", format_1())),
        Err(MigrateError::Unreadable(_))
    ));
}

#[test]
fn only_an_older_format_is_rewritten() {
    let current = include_str!("fixtures/policy.yaml");
    assert_eq!(propose(current), Err(MigrateError::Current));
    let newer = current.replacen("format: 2\n", "format: 3\n", 1);
    assert_eq!(propose(&newer), Err(MigrateError::Newer { found: 3 }));
    let zero = current.replacen("format: 2\n", "format: 0\n", 1);
    assert_eq!(propose(&zero), Err(MigrateError::Unknown { found: 0 }));
    assert!(matches!(
        propose("format: two\n"),
        Err(MigrateError::Unreadable(_))
    ));
    // The errors say so.
    assert_eq!(
        MigrateError::Current.to_string(),
        "the policy is format 2, the current one: nothing to migrate"
    );
    assert_eq!(
        MigrateError::Newer { found: 3 }.to_string(),
        "the policy is format 3, newer than the format 2 this Writ reads"
    );
}
