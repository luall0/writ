//! A template's `committer_name`: the name every commit under its leases carries as author and
//! committer. It goes into the lease's terms at submission, is checked on every signature
//! (exactly), can't be changed by a narrowing or a renewal, and an OpenPGP key's user ids must
//! carry it. Without it, the name isn't checked.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

mod common;

use common::*;
use writ_core::config::PolicyConfig;
use writ_core::fit;
use writ_core::lease::{self, TicketRecord, Usage};
use writ_core::names::{CommitterName, KeyId};
use writ_core::narrow;
use writ_core::policy::{self, Context, Denial, DenyCode};
use writ_core::ticket::Ticket;

const NAME: &str = "Writ agent";

/// The fixture policy, the feature-branch template with `committer_name: <name>`.
fn named_policy(name: &str) -> String {
    POLICY.replacen(
        "    committer_emails: [\"user+agent@example.org\"]\n",
        &format!(
            "    committer_emails: [\"user+agent@example.org\"]\n    committer_name: {name:?}\n"
        ),
        1,
    )
}

fn named_config() -> PolicyConfig {
    PolicyConfig::from_yaml(&named_policy(NAME)).unwrap()
}

fn submitted_under(config: &PolicyConfig, yaml: &str) -> Ticket {
    fit::submit(config, &request(yaml), &submission(1)).unwrap()
}

fn code<T: std::fmt::Debug>(decision: Result<T, Denial>) -> DenyCode {
    match decision {
        Ok(allowed) => panic!("allowed: {allowed:?}"),
        Err(denial) => denial.code,
    }
}

#[test]
fn a_name_is_one_git_writes_as_it_is() {
    for good in [
        "Writ agent",
        "L",
        "Zoë Ñúñez",
        "李小龍",
        "agent (bot)",
        "a.b",
        "O'Brien",
        &"n".repeat(100),
    ] {
        assert!(good.parse::<CommitterName>().is_ok(), "{good:?}");
    }
    for (bad, why) in [
        ("", "must be 1 to 100 characters"),
        (&"n".repeat(101), "must be 1 to 100 characters"),
        (
            "Writ\nagent",
            "no control, newline, bidi or invisible characters",
        ),
        (
            "Writ\u{202e}agent",
            "no control, newline, bidi or invisible characters",
        ),
        (
            "Writ\u{200b}agent",
            "no control, newline, bidi or invisible characters",
        ),
        (
            "Writ\u{1b}[2Jagent",
            "no control, newline, bidi or invisible characters",
        ),
        ("Writ <agent>", "no '<' or '>'"),
        (" Writ", "(git strips them)"),
        ("Writ ", "(git strips them)"),
        ("Writ.", "(git strips them)"),
        (".Writ", "(git strips them)"),
        ("Writ,", "(git strips them)"),
        ("\"Writ\"", "(git strips them)"),
        ("Writ;", "(git strips them)"),
    ] {
        let error = bad.parse::<CommitterName>().unwrap_err();
        assert!(error.why.contains(why), "{bad:?}: {}", error.why);
    }
    // In the policy, a bad one names its field.
    let error = PolicyConfig::from_yaml(&named_policy("Writ <agent>")).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("templates.feature-branch.committer_name"),
        "{error}"
    );
}

#[test]
fn the_template_s_name_goes_into_a_lease_that_signs_and_only_there() {
    let config = named_config();
    let ticket = submitted_under(&config, REQUEST);
    assert_eq!(
        ticket.common.committer_name.as_ref().unwrap().as_str(),
        NAME
    );
    // A ticket that doesn't sign carries no name.
    let fetch = submitted_under(
        &config,
        &REQUEST.replace("[fetch, commit_sign, push]", "[fetch]"),
    );
    assert_eq!(fetch.common.committer_name, None);
    // Without the key, no name.
    assert_eq!(submitted(REQUEST).common.committer_name, None);
    // A ticket can't ask for one: there is no such field in the request.
    let asked = REQUEST.replace(
        "    branches: [\"agent/oauth-*\"]\n",
        "    branches: [\"agent/oauth-*\"]\n    committer_name: Someone\n",
    );
    let error = writ_core::ticket::TicketRequest::from_yaml(&asked).unwrap_err();
    assert!(
        error.to_string().contains("unknown field `committer_name`"),
        "{error}"
    );
}

#[test]
fn a_lease_fits_only_with_the_template_s_name() {
    let config = named_config();
    let ticket = submitted_under(&config, REQUEST);
    assert!(fit::fits(&config, &ticket).is_ok());
    let reason = "common.committer_name must be the template's committer_name";
    for (what, name) in [("another name", Some("Someone")), ("no name", None)] {
        let mut changed = ticket.clone();
        changed.common.committer_name = name.map(|n| n.parse().unwrap());
        let error = fit::fits(&config, &changed).unwrap_err();
        assert!(error.reasons.iter().any(|r| r == reason), "{what}: {error}");
    }
    // A template whose name changed, or was removed, no longer fits the lease: fail closed.
    let renamed = PolicyConfig::from_yaml(&named_policy("Another agent")).unwrap();
    let unnamed = common::config();
    let unnamed_lease = submitted(REQUEST);
    // A lease without a name under a template that now sets one: no longer fits either.
    for (config, ticket) in [
        (&renamed, &ticket),
        (&unnamed, &ticket),
        (&config, &unnamed_lease),
    ] {
        let error = fit::fits(config, ticket).unwrap_err();
        assert_eq!(error.reasons, [reason], "{error}");
    }
}

#[test]
fn a_narrowing_or_a_renewal_never_changes_the_name() {
    let config = named_config();
    let ticket = submitted_under(&config, REQUEST);
    let mut renamed = ticket.clone();
    renamed.common.committer_name = Some("Someone".parse().unwrap());
    let mut dropped = ticket.clone();
    dropped.common.committer_name = None;
    for changed in [&renamed, &dropped] {
        assert!(
            narrow::widenings(&ticket, changed)
                .iter()
                .any(|r| r == "common.committer_name changed"),
            "{changed:?}"
        );
        let error = narrow::check(&ticket, changed).unwrap_err();
        assert!(
            error
                .reasons
                .iter()
                .any(|r| r == "common.committer_name changed"),
            "{error:?}"
        );
    }
    assert!(narrow::widenings(&ticket, &ticket).is_empty());
}

/// A lease under the named template, and a context around it.
struct Named {
    config: PolicyConfig,
    lease: lease::Lease,
    usage: Usage,
    caller: writ_core::caller::CallerFacts,
}

impl Named {
    fn new(config: PolicyConfig) -> Self {
        let ticket = submitted_under(&config, REQUEST);
        let record = TicketRecord::pending(ticket.clone());
        let lease = lease::activate(&config, &record, ticket, approval(), 7, later(30)).unwrap();
        Self {
            config,
            lease,
            usage: Usage::default(),
            caller: Default::default(),
        }
    }

    fn ctx(&self) -> Context<'_> {
        Context {
            config: &self.config,
            lease: &self.lease,
            usage: &self.usage,
            caller: &self.caller,
            now: later(60),
        }
    }
}

#[test]
fn every_signature_carries_the_name_as_author_and_committer() {
    let world = Named::new(named_config());
    let mut request = sign_request(&world.lease);
    request.committer_name = Some(NAME.to_owned());
    request.author_name = Some(NAME.to_owned());
    assert!(policy::decide_sign(&world.ctx(), &request).is_ok());
    for name in [
        Some("L"),
        Some("writ agent"),
        Some("Writ agent "),
        Some("Writ  agent"),
        Some("Writ agent\u{200b}"),
        Some(""),
        None,
    ] {
        let mut committer = request.clone();
        committer.committer_name = name.map(str::to_owned);
        let denial = policy::decide_sign(&world.ctx(), &committer).unwrap_err();
        assert_eq!(denial.code, DenyCode::CommitterName, "{name:?}");
        assert!(
            denial
                .reason
                .contains("is not the lease's committer_name \"Writ agent\""),
            "{}",
            denial.reason
        );
        assert!(
            denial.hint.as_deref().unwrap_or("").contains("user.name"),
            "{denial:?}"
        );
        let mut author = request.clone();
        author.author_name = name.map(str::to_owned);
        assert_eq!(
            code(policy::decide_sign(&world.ctx(), &author)),
            DenyCode::AuthorName,
            "author {name:?}"
        );
    }
    // A name that isn't UTF-8 is said so, never shown raw.
    let mut raw = request.clone();
    raw.author_name = None;
    let denial = policy::decide_sign(&world.ctx(), &raw).unwrap_err();
    assert!(
        denial.reason.starts_with("author name not UTF-8"),
        "{}",
        denial.reason
    );
    // Both are violations: the lease's on_violation applies.
    assert!(DenyCode::CommitterName.is_violation() && DenyCode::AuthorName.is_violation());
    assert_eq!(DenyCode::CommitterName.as_str(), "committer_name");
    assert_eq!(DenyCode::AuthorName.as_str(), "author_name");
}

#[test]
fn without_a_name_in_the_template_any_name_is_signed() {
    let world = World::new(lease());
    for name in [Some("L"), Some("Someone else"), Some(""), None] {
        let mut request = sign_request(&world.lease);
        request.committer_name = name.map(str::to_owned);
        request.author_name = name.map(str::to_owned);
        assert!(
            policy::decide_sign(&world.ctx(), &request).is_ok(),
            "{name:?}"
        );
    }
}

#[test]
fn an_openpgp_key_must_carry_the_name_in_its_user_ids() {
    let with_uids = |uid: &str| {
        named_policy(NAME).replacen(
            "  agent-ed25519-01: { use: signing, format: ssh, algorithm: ed25519 }\n",
            &format!(
                "  agent-ed25519-01:\n    use: signing\n    format: openpgp\n    algorithm: \
                 ed25519\n    uids: [\"{uid}\", \"Fix <user+fix@example.org>\"]\n"
            ),
            1,
        )
    };
    let good = PolicyConfig::from_yaml(&with_uids("Writ agent <user+agent@example.org>"));
    assert!(good.is_ok(), "{good:?}");
    // The email alone isn't enough: the key would carry another name than the commits.
    let error = PolicyConfig::from_yaml(&with_uids("Someone <user+agent@example.org>"))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("templates.feature-branch.committer_name")
            && error.contains("no user id \"Writ agent <user+agent@example.org>\""),
        "{error}"
    );
    // An SSH key has no user ids: nothing to check.
    assert!(
        named_config()
            .key(&"agent-ed25519-01".parse::<KeyId>().unwrap())
            .is_some()
    );
}

/// The review after M7.6 (C-3): a renewal that drops `commit_sign` has no committer name (no
/// commit is signed), which was refused as "another identity" under a template that sets one.
/// It isn't: only a ticket that signs names someone.
#[test]
fn a_renewal_that_signs_nothing_names_no_other_identity() {
    use writ_core::canonical::Canonical;
    const FULL: &[u8] = include_bytes!("fixtures/ticket-full.json");
    let signing = Ticket::from_canonical(FULL).unwrap();
    assert!(signing.common.committer_name.is_some());
    let mut push_only = signing.clone();
    push_only.common.committer_name = None;
    for terms in push_only.repos.values_mut() {
        terms
            .operations
            .remove(&writ_core::ticket::Operation::CommitSign);
    }
    assert_eq!(
        narrow::widenings(&signing, &push_only),
        Vec::<String>::new()
    );
    // Still signing, without the name: another identity.
    let mut unnamed = signing.clone();
    unnamed.common.committer_name = None;
    assert_eq!(
        narrow::widenings(&signing, &unnamed),
        ["common.committer_name changed".to_owned()]
    );
}
