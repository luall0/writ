//! The repo registry and the templates: the admin-approved policy configuration.
//!
//! Parsed from YAML text (reading the file is the daemon's job). Every error names the field
//! it is about, e.g. `templates.quick-fix.max_ttl: invalid duration "1 hour"`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::names::{Email, KeyId, RepoName, TemplateName, Uid};
use crate::pattern::{BranchPattern, RefPattern};
use crate::ticket::Operation;
use crate::units::{ByteSize, Duration};
use crate::yaml::{FieldError, parse_yaml};

/// How pushes to a repo reach upstream (`docs/architecture/gateway.md`).
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

/// How a commit is linked to its ticket on the remote. `ledger_only` by default: many
/// projects' commit conventions don't allow an extra trailer, and the ledger links every
/// commit to its lease whatever this says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketLink {
    /// Every commit carries `Writ: <lease id>`, checked before signing.
    Trailer,
    /// A git note (`Writ: <lease id>`) under the repo's `notes_ref`, written by the daemon from
    /// its ledger and pushed upstream after the branch; the commit untouched.
    Notes,
    /// Only the daemon's ledger.
    #[default]
    LedgerOnly,
}

/// The ref a repo's notes are written under (`ticket_link: notes`). `commits` by default:
/// git's own notes ref, the one `git log` shows and the only one Forgejo and Gitea show on a
/// commit's page; `writ` keeps Writ's notes apart from anyone else's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotesRef {
    /// `refs/notes/commits`.
    #[default]
    Commits,
    /// `refs/notes/writ`.
    Writ,
}

impl NotesRef {
    /// The full ref name.
    pub fn as_ref_name(self) -> &'static str {
        match self {
            NotesRef::Commits => "refs/notes/commits",
            NotesRef::Writ => "refs/notes/writ",
        }
    }
}

impl fmt::Display for NotesRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref_name())
    }
}

/// The hash a repository names its objects with. A repository's commits are signed only in
/// its own format; SHA-1 is the default, since most remotes (GitHub among them) have only
/// SHA-1 repositories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectFormat {
    /// SHA-1 ids (40 hex characters), computed with collision detection.
    #[default]
    Sha1,
    /// SHA-256 ids (64 hex characters).
    Sha256,
}

impl ObjectFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            ObjectFormat::Sha1 => "sha1",
            ObjectFormat::Sha256 => "sha256",
        }
    }
}

impl fmt::Display for ObjectFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
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
    #[serde(default)]
    pub ticket_link: TicketLink,
    /// Where notes go with `ticket_link: notes` ([`RepoEntry::notes_ref`]); only allowed then.
    #[serde(default)]
    pub notes_ref: Option<NotesRef>,
    /// The repository's object format (`sha1`, the default, or `sha256`).
    #[serde(default)]
    pub object_format: ObjectFormat,
    #[serde(default)]
    pub direct_ssh: Option<DirectSsh>,
}

impl RepoEntry {
    /// The ref this repo's notes are written under: `notes_ref`, `refs/notes/commits` unless
    /// it says otherwise.
    pub fn notes_ref(&self) -> NotesRef {
        self.notes_ref.unwrap_or_default()
    }
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

fn default_paths_check() -> PathsCheck {
    PathsCheck::Warn
}

/// What the policy says about an agent signing key: the OpenPGP user ids it is certified
/// with. Binding an identity to a key is an admin change, so it lives here, never in
/// `writd.yaml` (which declares the key's format, algorithm and backend).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyPolicy {
    pub uids: Vec<Uid>,
}

/// The most user ids one key carries.
pub const MAX_UIDS: usize = 16;

/// The registry and the templates, as written by the admin, before cross-checks.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicyConfig {
    pub repos: BTreeMap<RepoName, RepoEntry>,
    pub templates: BTreeMap<TemplateName, Template>,
    #[serde(default)]
    pub signing_keys: BTreeMap<KeyId, SigningKeyPolicy>,
}

/// The registry and the templates, cross-checked: every template only names registered
/// repos and carries what its operations need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConfig {
    repos: BTreeMap<RepoName, RepoEntry>,
    templates: BTreeMap<TemplateName, Template>,
    signing_keys: BTreeMap<KeyId, SigningKeyPolicy>,
}

/// The format a key is declared with in `writd.yaml`, as far as the policy cares: an
/// OpenPGP key needs a user id for each committer email its templates allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclaredFormat {
    Ssh,
    Openpgp,
}

impl PolicyConfig {
    /// Parses and checks a policy document (`repos:` and `templates:`), with the default
    /// minimum TTL ([`DEFAULT_MIN_TTL`](crate::fit::DEFAULT_MIN_TTL)).
    pub fn from_yaml(text: &str) -> Result<Self, FieldError> {
        Self::from_yaml_with_min_ttl(text, crate::fit::DEFAULT_MIN_TTL)
    }

    /// [`Self::from_yaml`] for a daemon whose `min_ttl` is `min_ttl`: every template's
    /// `max_ttl` is at least it.
    pub fn from_yaml_with_min_ttl(text: &str, min_ttl: Duration) -> Result<Self, FieldError> {
        Self::validate(parse_yaml::<RawPolicyConfig>(text)?, min_ttl)
    }

    /// Cross-checks a parsed document.
    fn validate(raw: RawPolicyConfig, min_ttl: Duration) -> Result<Self, FieldError> {
        // A repo's mirror is `<name>.git`: on a case-insensitive file system (APFS, local
        // mode's mirrors) `Demo` and `demo` would be one directory under two entries, each
        // with its own protected refs and upstream. Names are unique ignoring ASCII case
        // (repo names are ASCII).
        let mut folded = std::collections::BTreeSet::new();
        for name in raw.repos.keys() {
            if !folded.insert(name.as_str().to_ascii_lowercase()) {
                return Err(FieldError::at(
                    format!("repos.{name}"),
                    "another repo has the same name ignoring case (their mirrors would be one \
                     directory on a case-insensitive file system)",
                ));
            }
        }
        for (name, repo) in &raw.repos {
            validate_repo(name, repo)?;
        }
        for (name, template) in &raw.templates {
            validate_template(name, template, &raw.repos, min_ttl)?;
        }
        for (id, key) in &raw.signing_keys {
            let at = format!("signing_keys.{id}.uids");
            if key.uids.is_empty() || key.uids.len() > MAX_UIDS {
                return Err(FieldError::at(
                    at,
                    format!("must list 1 to {MAX_UIDS} user ids"),
                ));
            }
            let distinct: BTreeSet<&Uid> = key.uids.iter().collect();
            if distinct.len() != key.uids.len() {
                return Err(FieldError::at(at, "a user id is listed twice"));
            }
        }
        Ok(Self {
            repos: raw.repos,
            templates: raw.templates,
            signing_keys: raw.signing_keys,
        })
    }

    /// The OpenPGP user ids of the key `id`, none when the policy names none.
    pub fn uids(&self, id: &KeyId) -> &[Uid] {
        self.signing_keys
            .get(id)
            .map_or(&[], |key| key.uids.as_slice())
    }

    /// The keys the policy gives user ids to.
    pub fn signing_keys(&self) -> &BTreeMap<KeyId, SigningKeyPolicy> {
        &self.signing_keys
    }

    /// Checks the policy against the keys `writd.yaml` declares (by id, with their format):
    /// every template's `signing_key` is declared; user ids are given only to declared
    /// OpenPGP keys; and every committer email a template allows has a user id on the
    /// OpenPGP key it signs with (a remote shows a commit whose committer the key doesn't
    /// carry as unverified). The first problem is the error, naming its field.
    pub fn check_signing_keys(
        &self,
        declared: &BTreeMap<KeyId, DeclaredFormat>,
    ) -> Result<(), FieldError> {
        for (name, template) in &self.templates {
            let Some(id) = &template.signing_key else {
                continue;
            };
            let Some(format) = declared.get(id) else {
                return Err(FieldError::at(
                    format!("templates.{name}.signing_key"),
                    format!("{id} is not declared in writd.yaml's signing_keys"),
                ));
            };
            if *format != DeclaredFormat::Openpgp {
                continue;
            }
            let uids = self.uids(id);
            for email in &template.committer_emails {
                if !uids.iter().any(|uid| &uid.email() == email) {
                    return Err(FieldError::at(
                        format!("templates.{name}.committer_emails"),
                        format!(
                            "{email} has no user id in signing_keys.{id}.uids (the OpenPGP key \
                             would sign commits a remote shows as unverified)"
                        ),
                    ));
                }
            }
        }
        for id in self.signing_keys.keys() {
            match declared.get(id) {
                Some(DeclaredFormat::Openpgp) => {}
                Some(DeclaredFormat::Ssh) => {
                    return Err(FieldError::at(
                        format!("signing_keys.{id}"),
                        "user ids are for OpenPGP keys; writd.yaml declares this one ssh",
                    ));
                }
                None => {
                    return Err(FieldError::at(
                        format!("signing_keys.{id}"),
                        "not declared in writd.yaml's signing_keys",
                    ));
                }
            }
        }
        Ok(())
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

/// Checks an upstream URL: `ssh://` or `https://`, printable ASCII, a host, no password in
/// it (credentials live in the keystore, never in a URL that ends up in logs), and no user or
/// host starting with `-` (which `ssh` would read as an option).
fn check_upstream(upstream: &str) -> Result<(), &'static str> {
    let rest = upstream
        .strip_prefix("ssh://")
        .or_else(|| upstream.strip_prefix("https://"))
        .ok_or("must be an ssh:// or https:// URL")?;
    if !upstream.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("printable ASCII only, no spaces");
    }
    let authority = rest.split('/').next().unwrap_or_default();
    let (userinfo, host) = match authority.rsplit_once('@') {
        Some((userinfo, host)) => (Some(userinfo), host),
        None => (None, authority),
    };
    if let Some(userinfo) = userinfo {
        if userinfo.contains(':') {
            return Err("must not hold a password (credentials go in the keystore)");
        }
        if userinfo.is_empty() || userinfo.starts_with('-') {
            return Err("the user must not be empty or start with '-'");
        }
    }
    let hostname = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => host.split(':').next().unwrap_or_default(),
    };
    if hostname.is_empty() || hostname.starts_with('-') {
        return Err("the host must not be empty or start with '-'");
    }
    Ok(())
}

fn validate_repo(name: &RepoName, repo: &RepoEntry) -> Result<(), FieldError> {
    let at = |field: &str| format!("repos.{name}.{field}");
    check_upstream(repo.upstream.as_str()).map_err(|why| FieldError::at(at("upstream"), why))?;
    if repo.push_modes.is_empty() {
        return Err(FieldError::at(
            at("push_modes"),
            "must list at least one push mode",
        ));
    }
    if repo.notes_ref.is_some() && repo.ticket_link != TicketLink::Notes {
        return Err(FieldError::at(
            at("notes_ref"),
            "only allowed when ticket_link is notes",
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
        Some(direct)
            if direct.hosts.iter().any(|h| {
                h.is_empty() || h.starts_with('-') || !h.bytes().all(|b| b.is_ascii_graphic())
            }) =>
        {
            Err(FieldError::at(
                at("direct_ssh.hosts"),
                "each host is printable ASCII, not empty, not starting with '-'",
            ))
        }
        _ => Ok(()),
    }
}

fn validate_template(
    name: &TemplateName,
    template: &Template,
    repos: &BTreeMap<RepoName, RepoEntry>,
    min_ttl: Duration,
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
    if template.max_ttl < min_ttl {
        return Err(FieldError::at(
            at("max_ttl"),
            format!("must be at least {min_ttl} (the daemon's min_ttl)"),
        ));
    }
    if template.max_ops_per_minute == 0 {
        return Err(FieldError::at(
            at("max_ops_per_minute"),
            "must be at least 1",
        ));
    }
    // git reads a `receive.maxInputSize` of 0 as no limit: never one where pushes are allowed.
    if template.operations.contains(&Operation::Push) && template.max_push_size.bytes() == 0 {
        return Err(FieldError::at(
            at("max_push_size"),
            "must be at least 1 byte",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_upstream;

    #[test]
    fn upstream_urls_with_and_without_a_user_and_port() {
        for good in [
            "ssh://git@github.com/user/repo.git",
            "ssh://git@[2001:db8::1]:2222/repo.git",
            "ssh://remote.lan:2222/repo.git",
            "https://github.com/user/repo.git",
            "https://bot@codeberg.org/user/repo.git",
        ] {
            assert_eq!(check_upstream(good), Ok(()), "{good}");
        }
        assert_eq!(
            check_upstream("ssh://[-x]/repo.git"),
            Err("the host must not be empty or start with '-'")
        );
        assert_eq!(
            check_upstream("https://@github.com/x.git"),
            Err("the user must not be empty or start with '-'")
        );
    }
}
