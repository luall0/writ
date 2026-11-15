//! A policy of an older format rewritten to the current one ([`POLICY_FORMAT`], M7.9.6): what
//! the daemon proposes when a migration is owed, and the approver signs (`writ migrate`). The
//! daemon never reads an older format: it only rewrites it, one step per format, or says why
//! it can't, each reason naming its key. The rewrite is the policy in Writ's canonical layout
//! ([`PolicyConfig::to_yaml`]), checked as the daemon checks any policy.
//!
//! Format 1 → 2 removes the push modes. A `push_modes` that lists `gateway` is dropped: only
//! gateway pushes ever ran, so the policy means the same. One without `gateway` accepted no
//! push at all, and format 2 can't say that: the operator writes the policy they want (a
//! reason). `direct_ssh` settings applied to a mode that never pushed: dropped.

use serde::Deserialize;

use super::{POLICY_FORMAT, PolicyConfig, RawPolicyConfig};
use crate::units::Duration;
use crate::yaml::{FieldError, parse_yaml};

/// The push modes format 1 took.
const FORMAT_1_PUSH_MODES: [&str; 3] = ["gateway", "proxy", "direct_ssh"];

/// The policy in force rewritten to the current format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub from: u32,
    pub to: u32,
    /// The rewritten policy, in the canonical layout.
    pub text: String,
}

/// Why there is no rewrite.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MigrateError {
    /// Already the current format: nothing to migrate.
    #[error("the policy is format {POLICY_FORMAT}, the current one: nothing to migrate")]
    Current,
    /// A format newer than this build reads.
    #[error("the policy is format {found}, newer than the format {POLICY_FORMAT} this Writ reads")]
    Newer { found: u32 },
    /// A format no Writ wrote (0).
    #[error("format {found} is not one Writ wrote")]
    Unknown { found: u32 },
    /// The text can't be read, or its `format` isn't a number.
    #[error("the policy can't be read: {0}")]
    Unreadable(FieldError),
    /// What the rewrite can't carry over, each naming its key: the operator writes the policy
    /// (`writ migrate --file`).
    #[error("the policy can't be rewritten: {}", reasons(.0))]
    Reasons(Vec<FieldError>),
}

fn reasons(list: &[FieldError]) -> String {
    list.iter()
        .map(FieldError::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Only the `format` key of a policy, every other key left unread.
#[derive(Deserialize)]
struct FormatOnly {
    #[serde(default)]
    format: Option<u32>,
}

/// The format `text` is written in: its `format`, or 1 when it has none (every policy before
/// M7.9.6). Nothing else of the text is checked.
pub fn format_of(text: &str) -> Result<u32, FieldError> {
    Ok(parse_yaml::<FormatOnly>(text)?.format.unwrap_or(1))
}

/// What a daemon holds while a migration is owed: the policy in force, of an older format, read
/// through its rewrite with what the rewrite can't carry over dropped (a `push_modes` without
/// gateway too). Only its keys, recipients and `unseal` are used, to unseal and to check the
/// migration against; every request is refused meanwhile, so nothing else in it decides
/// anything. The current format is read as it is.
pub fn baseline(text: &str, min_ttl: Duration) -> Result<PolicyConfig, MigrateError> {
    match format_of(text).map_err(MigrateError::Unreadable)? {
        POLICY_FORMAT => {
            PolicyConfig::from_yaml_with_min_ttl(text, min_ttl).map_err(MigrateError::Unreadable)
        }
        1 => from_1(text, min_ttl, Reasons::Drop),
        found if found > POLICY_FORMAT => Err(MigrateError::Newer { found }),
        found => Err(MigrateError::Unknown { found }),
    }
}

/// What a rewrite does with what it can't carry over.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reasons {
    /// Refuses the rewrite, naming each: a proposal.
    Refuse,
    /// Drops it: a [`baseline`].
    Drop,
}

/// `text` rewritten to the current format, step by step, checked with `min_ttl` as the
/// daemon checks a policy; or why not.
pub fn propose(text: &str, min_ttl: Duration) -> Result<Proposal, MigrateError> {
    let from = format_of(text).map_err(MigrateError::Unreadable)?;
    match from {
        POLICY_FORMAT => Err(MigrateError::Current),
        1 => Ok(Proposal {
            from,
            to: POLICY_FORMAT,
            text: from_1(text, min_ttl, Reasons::Refuse)?.to_yaml(),
        }),
        found if found > POLICY_FORMAT => Err(MigrateError::Newer { found }),
        found => Err(MigrateError::Unknown { found }),
    }
}

/// Format 1 → 2: the push modes removed, where the policy means the same without them.
fn from_1(text: &str, min_ttl: Duration, what: Reasons) -> Result<PolicyConfig, MigrateError> {
    let mut raw: RawPolicyConfig = parse_yaml(text).map_err(MigrateError::Unreadable)?;
    let mut reasons = Vec::new();
    for (name, repo) in &mut raw.repos {
        if let Some(modes) = repo.push_modes.take() {
            push_modes(&format!("repos.{name}.push_modes"), &modes, &mut reasons);
        }
        repo.direct_ssh = None;
    }
    for (name, template) in &mut raw.templates {
        if let Some(modes) = template.push_modes.take() {
            push_modes(
                &format!("templates.{name}.push_modes"),
                &modes,
                &mut reasons,
            );
        }
    }
    if !reasons.is_empty() && what == Reasons::Refuse {
        return Err(MigrateError::Reasons(reasons));
    }
    raw.format = Some(POLICY_FORMAT);
    PolicyConfig::validate(raw, min_ttl).map_err(|e| MigrateError::Reasons(vec![e]))
}

/// A format 1 `push_modes`: dropped when it lists `gateway`, a reason otherwise.
fn push_modes(at: &str, modes: &[String], reasons: &mut Vec<FieldError>) {
    if let Some(unknown) = modes
        .iter()
        .find(|m| !FORMAT_1_PUSH_MODES.contains(&m.as_str()))
    {
        reasons.push(FieldError::at(
            at,
            format!("{unknown:?} is not a push mode"),
        ));
    } else if !modes.iter().any(|m| m == "gateway") {
        reasons.push(FieldError::at(
            at,
            format!(
                "[{}] has no gateway, so no push was accepted; format 2 has no push modes, and \
                 dropping it would let gateway pushes in: write the policy you want (writ \
                 migrate --file)",
                modes.join(", ")
            ),
        ));
    }
}
