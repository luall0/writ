//! The repo registry and the templates: the admin-approved policy configuration.
//!
//! Parsed from YAML text (reading the file is the daemon's job). Every error names the field
//! it is about, e.g. `templates.quick-fix.max_ttl: invalid duration "1 hour"`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::names::{Email, KeyId, RepoName, TemplateName};
use crate::pattern::{BranchPattern, RefPattern};
use crate::ticket::Operation;
use crate::units::{ByteSize, Duration};
use crate::yaml::{FieldError, parse_yaml};

/// How pushes to a repo reach upstream ([gateway.md](../../docs/architecture/gateway.md)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushMode {
    Gateway,
    Proxy,
    DirectSsh,
}

impl fmt::Display for PushMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Gateway => "gateway",
            Self::Proxy => "proxy",
            Self::DirectSsh => "direct_ssh",
        })
    }
}

/// How a commit is linked to its ticket on the forge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketLink {
    /// Every commit carries `Writ: <lease id>`, checked before signing.
    Trailer,
    /// A git note under `refs/notes/writ`.
    Notes,
    /// Only the daemon's ledger.
    LedgerOnly,
}

/// What to do when a commit touches files outside `expected_paths`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathsCheck {
    Off,
    Warn,
    Deny,
}

/// Settings for `direct_ssh` pushes (checked from M10).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSsh {
    pub hosts: Vec<String>,
    #[serde(default)]
    pub allow_account_wide: bool,
}

/// A repo in the registry: hard limits no lease can exceed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoEntry {
    pub upstream: String,
    pub upstream_credential: KeyId,
    #[serde(default)]
    pub protected_refs: BTreeSet<RefPattern>,
    #[serde(default = "default_push_modes")]
    pub push_modes: BTreeSet<PushMode>,
    #[serde(default = "default_ticket_link")]
    pub ticket_link: TicketLink,
    #[serde(default)]
    pub direct_ssh: Option<DirectSsh>,
}

/// A template: the largest ticket it accepts. Every limit is required.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub repos: BTreeSet<RepoName>,
    pub operations: BTreeSet<Operation>,
    #[serde(default)]
    pub branches: BTreeSet<BranchPattern>,
    #[serde(default = "default_push_modes")]
    pub push_modes: BTreeSet<PushMode>,
    /// Whether a ticket under this template may ask for force pushes.
    #[serde(default)]
    pub force_push: bool,
    /// Committer emails a ticket may use (required with `commit_sign`).
    #[serde(default)]
    pub committer_emails: BTreeSet<Email>,
    /// The signer key that signs commits under this template (required with `commit_sign`).
    #[serde(default)]
    pub signing_key: Option<KeyId>,
    pub max_ttl: Duration,
    pub max_signatures: u32,
    pub max_pushes: u32,
    pub max_ops_per_minute: u32,
    pub max_push_size: ByteSize,
    #[serde(default = "default_paths_check")]
    pub paths_check: PathsCheck,
    #[serde(default)]
    pub require_expected_paths: bool,
}

fn default_push_modes() -> BTreeSet<PushMode> {
    BTreeSet::from([PushMode::Gateway])
}

fn default_ticket_link() -> TicketLink {
    TicketLink::Trailer
}

fn default_paths_check() -> PathsCheck {
    PathsCheck::Warn
}

/// The registry and the templates, as written by the admin, before cross-checks.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicyConfig {
    pub repos: BTreeMap<RepoName, RepoEntry>,
    pub templates: BTreeMap<TemplateName, Template>,
}

/// The registry and the templates, cross-checked: every template only names registered
/// repos and carries what its operations need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConfig {
    repos: BTreeMap<RepoName, RepoEntry>,
    templates: BTreeMap<TemplateName, Template>,
}

impl PolicyConfig {
    /// Parses and checks a policy document (`repos:` and `templates:`).
    pub fn from_yaml(text: &str) -> Result<Self, FieldError> {
        Self::validate(parse_yaml::<RawPolicyConfig>(text)?)
    }

    /// Cross-checks a parsed document.
    fn validate(raw: RawPolicyConfig) -> Result<Self, FieldError> {
        for (name, repo) in &raw.repos {
            validate_repo(name, repo)?;
        }
        for (name, template) in &raw.templates {
            validate_template(name, template, &raw.repos)?;
        }
        Ok(Self {
            repos: raw.repos,
            templates: raw.templates,
        })
    }

    pub fn repo(&self, name: &RepoName) -> Option<&RepoEntry> {
        self.repos.get(name)
    }

    pub fn template(&self, name: &TemplateName) -> Option<&Template> {
        self.templates.get(name)
    }

    pub fn repos(&self) -> &BTreeMap<RepoName, RepoEntry> {
        &self.repos
    }

    pub fn templates(&self) -> &BTreeMap<TemplateName, Template> {
        &self.templates
    }
}

fn validate_repo(name: &RepoName, repo: &RepoEntry) -> Result<(), FieldError> {
    let at = |field: &str| format!("repos.{name}.{field}");
    let upstream = repo.upstream.as_str();
    let scheme_ok = upstream.starts_with("ssh://") || upstream.starts_with("https://");
    if !scheme_ok
        || upstream
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(FieldError::at(
            at("upstream"),
            "must be an ssh:// or https:// URL, with no spaces",
        ));
    }
    if repo.push_modes.is_empty() {
        return Err(FieldError::at(
            at("push_modes"),
            "must list at least one push mode",
        ));
    }
    let wants_direct = repo.push_modes.contains(&PushMode::DirectSsh);
    match &repo.direct_ssh {
        None if wants_direct => Err(FieldError::at(
            at("direct_ssh"),
            "required when push_modes has direct_ssh",
        )),
        Some(_) if !wants_direct => Err(FieldError::at(
            at("direct_ssh"),
            "only allowed when push_modes has direct_ssh",
        )),
        Some(direct) if direct.hosts.is_empty() => Err(FieldError::at(
            at("direct_ssh.hosts"),
            "must list at least one host",
        )),
        _ => Ok(()),
    }
}

fn validate_template(
    name: &TemplateName,
    template: &Template,
    repos: &BTreeMap<RepoName, RepoEntry>,
) -> Result<(), FieldError> {
    let at = |field: &str| format!("templates.{name}.{field}");
    if template.repos.is_empty() {
        return Err(FieldError::at(at("repos"), "must list at least one repo"));
    }
    if let Some(unknown) = template.repos.iter().find(|r| !repos.contains_key(*r)) {
        return Err(FieldError::at(
            at("repos"),
            format!("{unknown} is not in the repo registry"),
        ));
    }
    if template.operations.is_empty() {
        return Err(FieldError::at(
            at("operations"),
            "must list at least one operation",
        ));
    }
    let signs = template.operations.contains(&Operation::CommitSign);
    let pushes = template.operations.contains(&Operation::Push);
    if (signs || pushes) && template.branches.is_empty() {
        return Err(FieldError::at(
            at("branches"),
            "required with commit_sign or push",
        ));
    }
    if template.push_modes.is_empty() {
        return Err(FieldError::at(
            at("push_modes"),
            "must list at least one push mode",
        ));
    }
    if signs && template.committer_emails.is_empty() {
        return Err(FieldError::at(
            at("committer_emails"),
            "required with commit_sign",
        ));
    }
    if signs && template.signing_key.is_none() {
        return Err(FieldError::at(
            at("signing_key"),
            "required with commit_sign",
        ));
    }
    if template.max_ttl.seconds() == 0 {
        return Err(FieldError::at(at("max_ttl"), "must be longer than 0s"));
    }
    if template.max_ops_per_minute == 0 {
        return Err(FieldError::at(
            at("max_ops_per_minute"),
            "must be at least 1",
        ));
    }
    Ok(())
}
