//! M7.9.7: a new fetch-only ticket under templates whose `unsigned_fetch` is on is granted
//! with no signature, for that time at most; every other ticket under the same templates is
//! signed as before. These tests try to get more out of an unsigned lease, or one by chance.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

mod common;

use common::*;
use writ_core::config::PolicyConfig;
use writ_core::fit::{self, Submission};
use writ_core::lease::{self, GrantedBy, Lease, LifecycleError, Renewed, State, TicketRecord};
use writ_core::policy::{self, DenyCode, FetchRequest};
use writ_core::ticket::Ticket;
use writ_core::units::Duration;

/// The test policy with `unsigned_fetch: <switch>` on feature-branch (fetch, commit_sign,
/// push), which omega-code and homelab-scripts name; dotfiles names quick-fix only (no switch).
fn text_with(switch: &str) -> String {
    POLICY.replacen(
        "    max_ttl: 4h\n",
        &format!("    max_ttl: 4h\n    unsigned_fetch: {switch}\n"),
        1,
    )
}

fn switched() -> PolicyConfig {
    PolicyConfig::from_yaml(&text_with("15m")).unwrap()
}

/// A fetch of each of `repos` under feature-branch, for `ttl`.
fn fetch_ticket(repos: &[&str], ttl: &str) -> String {
    let blocks: String = repos
        .iter()
        .map(|repo| format!("  {repo}:\n    template: feature-branch\n    operations: [fetch]\n"))
        .collect();
    format!(
        "repos:\n{blocks}ticket:\n  title: Fetch\n  task: Fetch before planning\nlimits:\n  ttl: {ttl}\n"
    )
}

fn submit_to(
    config: &PolicyConfig,
    yaml: &str,
    submission: &Submission<'_>,
) -> Result<Ticket, Vec<String>> {
    fit::submit(config, &request(yaml), submission).map_err(|r| r.reasons)
}

fn unsigned_lease() -> Lease {
    let config = switched();
    let ticket = submit_to(
        &config,
        &fetch_ticket(&["omega-code"], "10m"),
        &submission(1),
    )
    .unwrap();
    lease::activate_unsigned(&config, &TicketRecord::pending(ticket), 7, later(1)).unwrap()
}

fn world(config: PolicyConfig, lease: Lease) -> World {
    World {
        config,
        ..World::new(lease)
    }
}

fn fetch(repo_name: &str) -> FetchRequest {
    FetchRequest {
        repo: repo(repo_name),
    }
}

#[test]
fn a_fetch_only_ticket_under_the_switch_is_granted_with_no_signature_and_only_fetches() {
    let config = switched();
    let lease = unsigned_lease();
    assert_eq!(lease.granted_by, GrantedBy::Policy);
    assert_eq!(lease.granted_by.approver(), None);
    assert!(fit::unsigned(&config, &lease.ticket));
    let world = world(config, lease.clone());
    assert!(policy::decide_fetch(&world.ctx(), &fetch("omega-code")).is_ok());
    // The template signs and pushes; this lease's terms don't: both refused for the
    // operation, the hint a ticket of its own (never an amendment, which is refused).
    assert_eq!(
        policy::decide_sign(&world.ctx(), &sign_request(&lease))
            .unwrap_err()
            .code,
        DenyCode::Operation
    );
    let denial = policy::decide_push(&world.ctx(), &push_request(&lease)).unwrap_err();
    assert_eq!(denial.code, DenyCode::Operation);
    assert_eq!(
        denial.hint.as_deref(),
        Some(
            "This lease was granted with no signature (unsigned_fetch) and only fetches: for \
             more, submit a ticket of its own"
        )
    );
    assert_eq!(
        policy::decide_fetch(&world.ctx(), &fetch("homelab-scripts"))
            .unwrap_err()
            .code,
        DenyCode::Repo
    );
}

#[test]
fn every_other_ticket_under_the_same_template_is_signed_as_before() {
    let config = switched();
    // Asking more than fetch: signed, never through the unsigned grant.
    let full = submit_to(&config, REQUEST, &submission(1)).unwrap();
    assert!(!fit::unsigned(&config, &full));
    assert!(matches!(
        lease::activate_unsigned(&config, &TicketRecord::pending(full.clone()), 8, later(1)),
        Err(LifecycleError::NotUnsigned)
    ));
    let signed = lease::activate(
        &config,
        &TicketRecord::pending(full.clone()),
        full.clone(),
        approval(),
        8,
        later(1),
    )
    .unwrap();
    assert_eq!(signed.granted_by, GrantedBy::Approver(approval()));
    // Every repository fetch-only, every template with the switch: unsigned, for the
    // smallest switch.
    let both = submit_to(
        &config,
        &fetch_ticket(&["omega-code", "homelab-scripts"], "10m"),
        &submission(2),
    )
    .unwrap();
    assert_eq!(
        fit::unsigned_bound(&config, &both).map(|d| d.seconds()),
        Some(15 * 60)
    );
    // One repository under a template without it: signed.
    let mixed = fetch_ticket(&["omega-code"], "10m").replacen(
        "ticket:",
        "  dotfiles:\n    template: quick-fix\n    operations: [fetch]\nticket:",
        1,
    );
    let mixed = submit_to(&config, &mixed, &submission(3)).unwrap();
    assert!(!fit::unsigned(&config, &mixed));
    // The switch off: the same fetch-only ticket is signed.
    let off = PolicyConfig::from_yaml(POLICY).unwrap();
    let plain = submit_to(&off, &fetch_ticket(&["omega-code"], "10m"), &submission(4)).unwrap();
    assert!(!fit::unsigned(&off, &plain));
    // An approver who narrows a signed ticket to fetch only signs it: a signed lease, for its
    // own time (2h), never held to the switch's.
    let mut narrowed = full.clone();
    omega(&mut narrowed).operations = [writ_core::ticket::Operation::Fetch].into();
    omega(&mut narrowed).branches.clear();
    let lease = lease::activate(
        &config,
        &TicketRecord::pending(full),
        narrowed,
        approval(),
        9,
        later(1),
    )
    .unwrap();
    assert_eq!(lease.granted_by, GrantedBy::Approver(approval()));
    let world = world(config, lease);
    assert!(policy::decide_fetch(&world.ctx(), &fetch("omega-code")).is_ok());
}

#[test]
fn an_unsigned_lease_lasts_its_switch_s_time_at_most_on_both_sides() {
    let config = switched();
    assert!(
        submit_to(
            &config,
            &fetch_ticket(&["omega-code"], "15m"),
            &submission(1)
        )
        .is_ok()
    );
    let reasons = submit_to(
        &config,
        &fetch_ticket(&["omega-code"], "901s"),
        &submission(1),
    )
    .unwrap_err();
    assert_eq!(
        reasons,
        [
            "the lease would last 901s: a fetch-only ticket under these templates is granted with \
          no signature, for at most 15m (unsigned_fetch)"
        ]
    );
    // Its grant checks it again, against the policy in force then.
    let ticket = submit_to(
        &config,
        &fetch_ticket(&["omega-code"], "15m"),
        &submission(2),
    )
    .unwrap();
    let shorter = PolicyConfig::from_yaml(&text_with("10m")).unwrap();
    assert!(matches!(
        lease::activate_unsigned(&shorter, &TicketRecord::pending(ticket), 7, later(1)),
        Err(LifecycleError::Fit(_))
    ));
}

#[test]
fn an_unsigned_lease_ends_when_its_switch_is_turned_off_or_shortened_below_it() {
    let lease = unsigned_lease();
    for (config, why) in [
        (
            PolicyConfig::from_yaml(POLICY).unwrap(),
            "its templates no longer grant that (unsigned_fetch)",
        ),
        (
            PolicyConfig::from_yaml(&text_with("5m")).unwrap(),
            "for at most 5m (unsigned_fetch)",
        ),
    ] {
        let unsigned = world(config.clone(), lease.clone());
        let denial = policy::decide_fetch(&unsigned.ctx(), &fetch("omega-code")).unwrap_err();
        assert_eq!(denial.code, DenyCode::Config);
        assert!(
            denial.reason.contains("was granted with no signature") && denial.reason.contains(why),
            "{}",
            denial.reason
        );
        // The same terms signed by an approver keep fetching under that policy.
        let signed = Lease {
            granted_by: GrantedBy::Approver(approval()),
            ..lease.clone()
        };
        let signed = world(config, signed);
        assert!(policy::decide_fetch(&signed.ctx(), &fetch("omega-code")).is_ok());
    }
}

#[test]
fn an_unsigned_lease_is_never_amended_or_renewed_and_a_new_fetch_alone_is_the_only_one() {
    let config = switched();
    let lease = unsigned_lease();
    let base = fetch_ticket(&["omega-code"], "10m").replacen("limits:\n  ttl: 10m\n", "", 1);
    // An amendment of it, at submission.
    let amends = Submission {
        amends: Some(&lease),
        ..submission(2)
    };
    let reasons =
        submit_to(&config, &format!("{base}  amends: {}\n", lease.id), &amends).unwrap_err();
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("never amended or renewed")),
        "{reasons:?}"
    );
    // A renewal of it, at submission.
    let expired = Lease {
        state: State::Expired,
        ..lease.clone()
    };
    let renews = Submission {
        renews: Some(Renewed {
            lease: &expired,
            renewals: 0,
            grace: Duration::from_seconds(86_400),
        }),
        ..submission(3)
    };
    let reasons = submit_to(
        &config,
        &format!("{base}  renews: {}\nlimits:\n  ttl: 10m\n", lease.id),
        &renews,
    )
    .unwrap_err();
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("never amended or renewed")),
        "{reasons:?}"
    );
    // At signing too.
    let signed_ticket = submitted(REQUEST);
    let with = |amends: bool| TicketRecord {
        ticket: Ticket {
            text: writ_core::ticket::TicketText {
                amends: amends.then(|| lease.id.clone()),
                renews: (!amends).then(|| lease.id.clone()),
                ..signed_ticket.text.clone()
            },
            ..signed_ticket.clone()
        },
        ..TicketRecord::pending(signed_ticket.clone())
    };
    let amendment = with(true);
    assert!(matches!(
        lease::apply_amendment(
            &config,
            &lease,
            &amendment,
            amendment.ticket.clone(),
            approval(),
            later(2)
        ),
        Err(LifecycleError::Unsigned(_))
    ));
    let renewal = with(false);
    assert!(matches!(
        lease::activate_renewal(
            &config,
            &renewal,
            renewal.ticket.clone(),
            approval(),
            8,
            Renewed {
                lease: &expired,
                renewals: 0,
                grace: Duration::from_seconds(86_400),
            },
            later(2)
        ),
        Err(LifecycleError::Unsigned(_))
    ));
    // A fetch-only amendment of a signed lease: not unsigned, signed as any amendment.
    let signed = lease_of(submitted(REQUEST));
    let fetch_amendment = submit_to(
        &config,
        &format!("{base}  amends: {}\n", signed.id),
        &Submission {
            amends: Some(&signed),
            ..submission(4)
        },
    )
    .unwrap();
    assert!(!fit::unsigned(&config, &fetch_amendment));
    // An unsigned grant past its end.
    let ticket = submit_to(
        &config,
        &fetch_ticket(&["omega-code"], "10m"),
        &submission(5),
    )
    .unwrap();
    assert!(matches!(
        lease::activate_unsigned(&config, &TicketRecord::pending(ticket), 11, later(11 * 60)),
        Err(LifecycleError::ExpiredBeforeApproval)
    ));
}
