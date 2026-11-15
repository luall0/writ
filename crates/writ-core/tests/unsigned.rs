//! M7.9.7: a fetch-only ticket under `unsigned_fetch` templates is granted with no signature,
//! and nothing else is: these tests try to get more out of one, or to get one by chance.

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
use writ_core::units::Duration;

/// The test policy with omega-code naming `fetch_unsigned` beside its signed templates, and
/// dotfiles naming it alone.
fn unsigned_text() -> String {
    POLICY
        .replacen(
            "templates: [feature-branch, quick-fix, read-only]",
            "templates: [feature-branch, quick-fix, read-only, fetch_unsigned]",
            1,
        )
        .replacen(
            "    templates: [quick-fix]\n",
            "    templates: [fetch_unsigned]\n",
            1,
        )
        .replacen(
            "templates:\n  feature-branch:",
            "templates:\n  fetch_unsigned:\n    unsigned_fetch: true\n    operations: [fetch]\n    \
             max_ttl: 1h\n    max_signatures: 0\n    max_pushes: 0\n    max_ops_per_minute: 20\n    \
             max_push_size: 0\n  feature-branch:",
            1,
        )
}

fn unsigned_config() -> PolicyConfig {
    PolicyConfig::from_yaml(&unsigned_text()).unwrap()
}

/// A fetch of omega-code under `fetch_unsigned`, for `ttl`.
fn fetch_ticket(ttl: &str) -> String {
    format!(
        "repos:\n  omega-code:\n    template: fetch_unsigned\n    operations: [fetch]\n\
         ticket:\n  title: Fetch omega-code\n  task: Fetch before planning\nlimits:\n  ttl: {ttl}\n"
    )
}

fn submit(
    yaml: &str,
    submission: &Submission<'_>,
) -> Result<writ_core::ticket::Ticket, Vec<String>> {
    fit::submit(&unsigned_config(), &request(yaml), submission).map_err(|r| r.reasons)
}

fn unsigned_lease() -> Lease {
    let ticket = submit(&fetch_ticket("10m"), &submission(1)).unwrap();
    lease::activate_unsigned(
        &unsigned_config(),
        &TicketRecord::pending(ticket),
        7,
        later(1),
    )
    .unwrap()
}

fn world(lease: Lease) -> World {
    World {
        config: unsigned_config(),
        ..World::new(lease)
    }
}

#[test]
fn a_fetch_named_under_an_unsigned_template_is_granted_with_no_signature_and_only_fetches() {
    let config = unsigned_config();
    let lease = unsigned_lease();
    assert_eq!(lease.granted_by, GrantedBy::Policy);
    assert_eq!(lease.granted_by.approver(), None);
    assert!(fit::unsigned(&config, &lease.ticket));
    let world = world(lease.clone());
    let fetch = FetchRequest {
        repo: repo("omega-code"),
    };
    assert!(policy::decide_fetch(&world.ctx(), &fetch).is_ok());
    // Its terms allow nothing else: a signature and a push are refused for the operation.
    assert_eq!(
        policy::decide_sign(&world.ctx(), &sign_request(&lease))
            .unwrap_err()
            .code,
        DenyCode::Operation
    );
    let denial = policy::decide_push(&world.ctx(), &push_request(&lease)).unwrap_err();
    assert_eq!(denial.code, DenyCode::Operation);
    // Never told to amend it: that is refused.
    assert_eq!(
        denial.hint.as_deref(),
        Some(
            "This lease was granted with no signature (unsigned_fetch) and only fetches: for \
             more, submit a ticket of its own"
        )
    );
    // A repo it doesn't name.
    assert_eq!(
        policy::decide_fetch(
            &world.ctx(),
            &FetchRequest {
                repo: repo("homelab-scripts")
            }
        )
        .unwrap_err()
        .code,
        DenyCode::Repo
    );
}

#[test]
fn an_unsigned_lease_ends_when_its_template_stops_granting_without_a_signature() {
    let lease = unsigned_lease();
    let fetch = FetchRequest {
        repo: repo("omega-code"),
    };
    // unsigned_fetch turned off (the template otherwise the same): every fetch denied.
    let off = unsigned_text().replacen("    unsigned_fetch: true\n", "", 1);
    let world = World {
        config: PolicyConfig::from_yaml(&off).unwrap(),
        ..World::new(lease.clone())
    };
    let denial = policy::decide_fetch(&world.ctx(), &fetch).unwrap_err();
    assert_eq!(denial.code, DenyCode::Config);
    assert!(
        denial.reason.contains("granted with no signature"),
        "{}",
        denial.reason
    );
    // The same terms signed by an approver keep fetching under that policy.
    let signed = Lease {
        granted_by: GrantedBy::Approver(approval()),
        ..lease
    };
    let world = World {
        config: PolicyConfig::from_yaml(&off).unwrap(),
        ..World::new(signed)
    };
    assert!(policy::decide_fetch(&world.ctx(), &fetch).is_ok());
}

#[test]
fn an_unsigned_template_is_used_only_when_a_ticket_names_it() {
    // Not named: only the signed templates are candidates, never the unsigned one.
    let unnamed = fetch_ticket("10m").replacen("    template: fetch_unsigned\n", "", 1);
    assert_eq!(
        submit(&unnamed, &submission(1)).unwrap_err(),
        [
            "repos.omega-code fits several templates (feature-branch, quick-fix, read-only): name \
          one in repos.omega-code.template"
        ]
    );
    let signed = unnamed.replacen("operations:", "template: read-only\n    operations:", 1);
    let ticket = submit(&signed, &submission(1)).unwrap();
    assert_eq!(
        ticket.templates().into_iter().cloned().collect::<Vec<_>>(),
        [ticket_template("read-only")]
    );
    assert!(!fit::unsigned(&unsigned_config(), &ticket));
    // A repo whose only template is the unsigned one: refused, saying how to name it.
    let only = unnamed.replace("omega-code", "dotfiles");
    let reasons = submit(&only, &submission(1)).unwrap_err();
    assert_eq!(
        reasons,
        [
            "repos.dotfiles: its only template, fetch_unsigned, grants fetches with no signature \
          (unsigned_fetch) and is used only when the ticket names it (repos.dotfiles.template: \
          fetch_unsigned)"
        ]
    );
    // Named there: granted unsigned.
    let named = fetch_ticket("10m").replace("omega-code", "dotfiles");
    assert!(fit::unsigned(
        &unsigned_config(),
        &submit(&named, &submission(1)).unwrap()
    ));
}

fn ticket_template(name: &str) -> writ_core::names::TemplateName {
    name.parse().unwrap()
}

#[test]
fn an_unsigned_ticket_lasts_at_most_its_template_s_hour_and_never_mixes_with_a_signed_one() {
    // At the template's max_ttl, read; a second past, refused.
    assert!(submit(&fetch_ticket("1h"), &submission(1)).is_ok());
    let reasons = submit(&fetch_ticket("3601s"), &submission(1)).unwrap_err();
    assert!(reasons.iter().any(|r| r.contains("max_ttl")), "{reasons:?}");
    // A second repo under a signed template: refused, naming both.
    let mixed = fetch_ticket("10m").replacen(
        "ticket:",
        "  homelab-scripts:\n    template: feature-branch\n    operations: [fetch]\nticket:",
        1,
    );
    let reasons = submit(&mixed, &submission(1)).unwrap_err();
    assert!(
        reasons.iter().any(|r| r
            == "repos.omega-code: template fetch_unsigned grants fetches with no signature \
                (unsigned_fetch): it can't share a ticket with templates you sign (feature-branch)"),
        "{reasons:?}"
    );
    // Asking for more than fetch under it.
    let more =
        fetch_ticket("10m").replacen("[fetch]", "[fetch, push]\n    branches: [\"agent/x\"]", 1);
    assert_eq!(
        submit(&more, &submission(1)).unwrap_err(),
        [
            "repos.omega-code: operation push is not allowed by the template",
            "repos.omega-code: branch agent/x is not within the template's branches ()",
            "repos.omega-code.limits.max_push_size must be at least 1 byte",
        ]
    );
}

#[test]
fn an_unsigned_lease_is_never_amended_renewed_or_signed() {
    let config = unsigned_config();
    let lease = unsigned_lease();
    // An amendment of it, at submission.
    let amendment = format!(
        "{}  amends: {}\n",
        fetch_ticket("10m").replacen("limits:\n  ttl: 10m\n", "", 1),
        lease.id
    );
    let amends = Submission {
        amends: Some(&lease),
        ..submission(2)
    };
    let reasons = submit(&amendment, &amends).unwrap_err();
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
    let renewal = format!(
        "{}  renews: {}\n",
        fetch_ticket("10m").replacen("limits:\n  ttl: 10m\n", "", 1),
        lease.id
    );
    let renews = Submission {
        renews: Some(Renewed {
            lease: &expired,
            renewals: 0,
            grace: Duration::from_seconds(86_400),
        }),
        ..submission(3)
    };
    let reasons = submit(&format!("{renewal}limits:\n  ttl: 10m\n"), &renews).unwrap_err();
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("never amended or renewed")),
        "{reasons:?}"
    );
    // At signing too: an amendment applied to it, a renewal activated from it.
    let signed_ticket = submitted(REQUEST);
    let record = TicketRecord::pending(signed_ticket.clone());
    let with_amends = TicketRecord {
        ticket: writ_core::ticket::Ticket {
            text: writ_core::ticket::TicketText {
                amends: Some(lease.id.clone()),
                ..signed_ticket.text.clone()
            },
            ..signed_ticket.clone()
        },
        ..record.clone()
    };
    assert!(matches!(
        lease::apply_amendment(
            &config,
            &lease,
            &with_amends,
            with_amends.ticket.clone(),
            approval(),
            later(2)
        ),
        Err(LifecycleError::Unsigned(_))
    ));
    let with_renews = TicketRecord {
        ticket: writ_core::ticket::Ticket {
            text: writ_core::ticket::TicketText {
                renews: Some(lease.id.clone()),
                ..signed_ticket.text.clone()
            },
            ..signed_ticket.clone()
        },
        ..record
    };
    assert!(matches!(
        lease::activate_renewal(
            &config,
            &with_renews,
            with_renews.ticket.clone(),
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
    // A ticket under unsigned_fetch templates, signed by an approver: refused, never a second
    // path to the grant.
    let unsigned_ticket = lease.ticket.clone();
    assert!(matches!(
        lease::activate(
            &config,
            &TicketRecord::pending(unsigned_ticket.clone()),
            unsigned_ticket,
            approval(),
            9,
            later(2)
        ),
        Err(LifecycleError::Fit(_))
    ));
    // And a signed ticket through the unsigned grant.
    assert!(matches!(
        lease::activate_unsigned(
            &config,
            &TicketRecord::pending(submitted(REQUEST)),
            10,
            later(2)
        ),
        Err(LifecycleError::NotUnsigned)
    ));
    // Nor once expired.
    let ticket = submit(&fetch_ticket("10m"), &submission(4)).unwrap();
    assert!(matches!(
        lease::activate_unsigned(&config, &TicketRecord::pending(ticket), 11, later(11 * 60)),
        Err(LifecycleError::ExpiredBeforeApproval)
    ));
}
