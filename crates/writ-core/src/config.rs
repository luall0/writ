//! The policy: the keys, the upstream host pins, the proxies, the repo registry and the
//! templates, as an approver signed them.
//!
//! Parsed from YAML text (reading the file is the daemon's job), and written back in Writ's
//! canonical layout ([`PolicyConfig::to_yaml`]). Every error names the field it is about,
//! e.g. `templates.quick-fix.max_ttl: invalid duration "1 hour"`.
//!
//! - [`keys`]: `keys.<id>`, every key the policy names, declared with its use.
//! - [`hosts`]: `upstream_hosts`, the pinned upstream host keys.
//! - [`proxies`]: `proxies.<name>`, the proxies a repo's upstream may be reached through.
//! - [`edit`]: one entry's fields edited, as `writ admin <noun> set` and `remove` do.
//! - `write`: the canonical layout.

pub mod edit;
pub mod hosts;
pub mod keys;
pub mod proxies;
mod write;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

pub use hosts::{HostKey, UpstreamHost};
pub use keys::{
    BackendName, HashName, Key, KeyAlgorithm, KeyFormat, KeyUse, MAX_UIDS, SigningKey, TokenHost,
    UpstreamKey, UpstreamKind,
};
pub use proxies::{Proxy, ProxyScheme, ProxyUrl};

use crate::names::{CommitterName, Email, KeyId, ProxyName, RepoName, TemplateName, Uid};
use crate::pattern::{BranchPattern, RefPattern};
use crate::ticket::Operation;
use crate::units::{ByteSize, Duration};
use crate::upstream::Upstream;
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

impl PathsCheck {
    pub fn as_str(self) -> &'static str {
        match self {
            PathsCheck::Off => "off",
            PathsCheck::Warn => "warn",
            PathsCheck::Deny => "deny",
        }
    }
}

impl TicketLink {
    pub fn as_str(self) -> &'static str {
        match self {
            TicketLink::Trailer => "trailer",
            TicketLink::Notes => "notes",
            TicketLink::LedgerOnly => "ledger_only",
        }
    }
}

impl NotesRef {
    /// Its name in the policy (`commits`, `writ`).
    pub fn as_str(self) -> &'static str {
        match self {
            NotesRef::Commits => "commits",
            NotesRef::Writ => "writ",
        }
    }
}

/// A field that moved in M6.2: read so its refusal can name its new place, never kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Moved;

impl<'de> Deserialize<'de> for Moved {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        serde::de::IgnoredAny::deserialize(d).map(|_| Moved)
    }
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
    /// The declared upstream credential (`keys.<id>`, `use: upstream`) that reaches it.
    pub upstream_credential: KeyId,
    /// The proxy (`proxies.<name>`) upstream is reached through; none: directly.
    #[serde(default)]
    pub proxy: Option<ProxyName>,
    /// The templates whose tickets may reach the repo; empty: the repo is paused (registered,
    /// with its mirror and credential, while no ticket fits it).
    pub templates: BTreeSet<TemplateName>,
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

/// A template: the largest ticket it accepts in a repo that names it. Every limit is
/// required.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    /// Before M6.2, the repos a template allowed: refused, naming `repos.<name>.templates`.
    #[serde(default)]
    repos: Option<Moved>,
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
    /// The name every commit's author and committer must carry (none: not checked). It goes
    /// into each lease's terms, and the agent's git is set to it.
    #[serde(default)]
    pub committer_name: Option<CommitterName>,
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
    /// Whether a ticket must be bound to a session (`caller`, local mode: `writ run`).
    #[serde(default)]
    pub require_session: bool,
    /// How many renewals one lease's chain may have (none: no limit). Each is signed anyway;
    /// this caps how long one task can run under the template.
    #[serde(default)]
    pub max_renewals: Option<u32>,
}

fn default_push_modes() -> BTreeSet<PushMode> {
    BTreeSet::from([PushMode::Gateway])
}

fn default_paths_check() -> PathsCheck {
    PathsCheck::Warn
}

/// The policy as written, before cross-checks.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicyConfig {
    keys: BTreeMap<KeyId, keys::RawKey>,
    #[serde(default)]
    upstream_hosts: BTreeMap<UpstreamHost, Vec<HostKey>>,
    #[serde(default)]
    proxies: BTreeMap<ProxyName, Proxy>,
    repos: BTreeMap<RepoName, RepoEntry>,
    templates: BTreeMap<TemplateName, Template>,
    /// Before M6.2, the OpenPGP user ids: refused, naming `keys.<id>.uids`.
    #[serde(default)]
    signing_keys: Option<Moved>,
}

/// The policy, cross-checked: every key named is declared for its use, every `ssh://`
/// upstream's host pinned, every proxy and template a repo names defined, and each template
/// carrying what its operations need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConfig {
    keys: BTreeMap<KeyId, Key>,
    upstream_hosts: BTreeMap<UpstreamHost, Vec<HostKey>>,
    proxies: BTreeMap<ProxyName, Proxy>,
    repos: BTreeMap<RepoName, RepoEntry>,
    templates: BTreeMap<TemplateName, Template>,
}

/// A section of the policy, as `writ admin <noun>` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Section {
    Keys,
    UpstreamHosts,
    Proxies,
    Repos,
    Templates,
}

impl Section {
    pub const ALL: [Section; 5] = [
        Section::Keys,
        Section::UpstreamHosts,
        Section::Proxies,
        Section::Repos,
        Section::Templates,
    ];

    /// Its key in the policy (`keys`, `upstream_hosts`, `proxies`, `repos`, `templates`).
    pub fn as_str(self) -> &'static str {
        match self {
            Section::Keys => "keys",
            Section::UpstreamHosts => "upstream_hosts",
            Section::Proxies => "proxies",
            Section::Repos => "repos",
            Section::Templates => "templates",
        }
    }

    /// The noun `writ admin` names one entry of it by (`key`, `host`, `proxy`, `repo`,
    /// `template`).
    pub fn noun(self) -> &'static str {
        match self {
            Section::Keys => "key",
            Section::UpstreamHosts => "host",
            Section::Proxies => "proxy",
            Section::Repos => "repo",
            Section::Templates => "template",
        }
    }
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What uses a key: the repos it reaches upstream for, the proxies it is the password of,
/// the templates that sign with it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyUsers {
    pub repos: Vec<RepoName>,
    pub proxies: Vec<ProxyName>,
    pub templates: Vec<TemplateName>,
}

impl KeyUsers {
    pub fn is_empty(&self) -> bool {
        self.repos.is_empty() && self.proxies.is_empty() && self.templates.is_empty()
    }
}

impl fmt::Display for KeyUsers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let join = |names: Vec<&str>| names.join(", ");
        let mut parts = Vec::new();
        if !self.repos.is_empty() {
            parts.push(format!(
                "repos {}",
                join(self.repos.iter().map(RepoName::as_str).collect())
            ));
        }
        if !self.proxies.is_empty() {
            parts.push(format!(
                "proxies {}",
                join(self.proxies.iter().map(ProxyName::as_str).collect())
            ));
        }
        if !self.templates.is_empty() {
            parts.push(format!(
                "templates {}",
                join(self.templates.iter().map(TemplateName::as_str).collect())
            ));
        }
        match parts.is_empty() {
            true => f.write_str("nothing"),
            false => f.write_str(&parts.join("; ")),
        }
    }
}

impl PolicyConfig {
    /// Parses and checks a policy document, with the default minimum TTL
    /// ([`DEFAULT_MIN_TTL`](crate::fit::DEFAULT_MIN_TTL)).
    pub fn from_yaml(text: &str) -> Result<Self, FieldError> {
        Self::from_yaml_with_min_ttl(text, crate::fit::DEFAULT_MIN_TTL)
    }

    /// [`Self::from_yaml`] for a daemon whose `min_ttl` is `min_ttl`: every template's
    /// `max_ttl` is at least it.
    pub fn from_yaml_with_min_ttl(text: &str, min_ttl: Duration) -> Result<Self, FieldError> {
        Self::validate(parse_yaml::<RawPolicyConfig>(text)?, min_ttl)
    }

    /// Cross-checks a parsed document. The first problem is the error, naming its field.
    fn validate(raw: RawPolicyConfig, min_ttl: Duration) -> Result<Self, FieldError> {
        if raw.signing_keys.is_some() {
            return Err(FieldError::at(
                "signing_keys",
                "moved in M6.2: declare each signing key under keys.<id> (use: signing, its \
                 format and algorithm, and its uids there)",
            ));
        }
        if let Some(name) = raw
            .templates
            .iter()
            .find_map(|(name, t)| t.repos.map(|_| name))
        {
            return Err(FieldError::at(
                format!("templates.{name}.repos"),
                "moved in M6.2: templates no longer list repos; name the template in each \
                 repo's repos.<name>.templates",
            ));
        }
        let mut keys = BTreeMap::new();
        for (id, raw_key) in raw.keys {
            let key = raw_key.check(&format!("keys.{id}"))?;
            keys.insert(id, key);
        }
        if raw.upstream_hosts.len() > hosts::MAX_HOSTS {
            return Err(FieldError::at(
                "upstream_hosts",
                format!("at most {} hosts are pinned", hosts::MAX_HOSTS),
            ));
        }
        for (host, pinned) in &raw.upstream_hosts {
            let at = format!("upstream_hosts.{host}");
            if pinned.is_empty() || pinned.len() > hosts::MAX_HOST_KEYS {
                return Err(FieldError::at(
                    at,
                    format!("must pin 1 to {} keys", hosts::MAX_HOST_KEYS),
                ));
            }
            let distinct: BTreeSet<&HostKey> = pinned.iter().collect();
            if distinct.len() != pinned.len() {
                return Err(FieldError::at(at, "a key is pinned twice"));
            }
        }
        // A repo's mirror is `<name>.git`: on a case-insensitive file system (APFS, local
        // mode's mirrors) `Demo` and `demo` would be one directory under two entries, each
        // with its own protected refs and upstream. Names are unique ignoring ASCII case
        // (repo names are ASCII).
        let mut folded = BTreeSet::new();
        for name in raw.repos.keys() {
            if !folded.insert(name.as_str().to_ascii_lowercase()) {
                return Err(FieldError::at(
                    format!("repos.{name}"),
                    "another repo has the same name ignoring case (their mirrors would be one \
                     directory on a case-insensitive file system)",
                ));
            }
        }
        if raw.proxies.len() > proxies::MAX_PROXIES {
            return Err(FieldError::at(
                "proxies",
                format!("at most {} proxies are declared", proxies::MAX_PROXIES),
            ));
        }
        for (name, proxy) in &raw.proxies {
            validate_proxy(name, proxy, &keys)?;
        }
        for (name, repo) in &raw.repos {
            validate_repo(
                name,
                repo,
                &keys,
                &raw.upstream_hosts,
                &raw.proxies,
                &raw.templates,
            )?;
        }
        for (name, template) in &raw.templates {
            validate_template(name, template, &keys, min_ttl)?;
        }
        Ok(Self {
            keys,
            upstream_hosts: raw.upstream_hosts,
            proxies: raw.proxies,
            repos: raw.repos,
            templates: raw.templates,
        })
    }

    /// The policy in Writ's canonical layout: what `writ admin` signs once it changed a
    /// field. Read back, it is this policy.
    pub fn to_yaml(&self) -> String {
        write::policy(self)
    }

    /// The entry `name` of `section`, as [`Self::to_yaml`] writes it, unindented; none when
    /// there is no such entry.
    pub fn entry_yaml(&self, section: Section, name: &str) -> Option<String> {
        write::one_entry(self, section, name)
    }

    /// The names of `section`'s entries, in order.
    pub fn entry_names(&self, section: Section) -> Vec<String> {
        match section {
            Section::Keys => self.keys.keys().map(|k| k.to_string()).collect(),
            Section::UpstreamHosts => self.upstream_hosts.keys().map(|h| h.to_string()).collect(),
            Section::Proxies => self.proxies.keys().map(|p| p.to_string()).collect(),
            Section::Repos => self.repos.keys().map(|r| r.to_string()).collect(),
            Section::Templates => self.templates.keys().map(|t| t.to_string()).collect(),
        }
    }

    /// Every declared key.
    pub fn keys(&self) -> &BTreeMap<KeyId, Key> {
        &self.keys
    }

    pub fn key(&self, id: &KeyId) -> Option<&Key> {
        self.keys.get(id)
    }

    /// The declared signing keys.
    pub fn signing_keys(&self) -> impl Iterator<Item = (&KeyId, &SigningKey)> {
        self.keys.iter().filter_map(|(id, key)| match key {
            Key::Signing(k) => Some((id, k)),
            Key::Upstream(_) => None,
        })
    }

    /// The declared upstream credentials.
    pub fn upstream_keys(&self) -> impl Iterator<Item = (&KeyId, &UpstreamKey)> {
        self.keys.iter().filter_map(|(id, key)| match key {
            Key::Upstream(k) => Some((id, k)),
            Key::Signing(_) => None,
        })
    }

    /// The OpenPGP user ids of the signing key `id`, none when it has none.
    pub fn uids(&self, id: &KeyId) -> &[Uid] {
        match self.keys.get(id) {
            Some(Key::Signing(k)) => k.uids.as_slice(),
            _ => &[],
        }
    }

    /// What uses the key `id`.
    pub fn key_users(&self, id: &KeyId) -> KeyUsers {
        KeyUsers {
            repos: self
                .repos
                .iter()
                .filter(|(_, r)| r.upstream_credential == *id)
                .map(|(name, _)| name.clone())
                .collect(),
            proxies: self
                .proxies
                .iter()
                .filter(|(_, p)| p.credential.as_ref() == Some(id))
                .map(|(name, _)| name.clone())
                .collect(),
            templates: self
                .templates
                .iter()
                .filter(|(_, t)| t.signing_key.as_ref() == Some(id))
                .map(|(name, _)| name.clone())
                .collect(),
        }
    }

    /// The pinned upstream host keys.
    pub fn upstream_hosts(&self) -> &BTreeMap<UpstreamHost, Vec<HostKey>> {
        &self.upstream_hosts
    }

    /// The repos whose `ssh://` upstream is reached through the pin `host`.
    pub fn host_users(&self, host: &UpstreamHost) -> Vec<RepoName> {
        self.repos
            .iter()
            .filter(|(_, r)| match Upstream::parse(&r.upstream) {
                Ok(Upstream::Ssh(url)) => url.known_hosts_name() == host.as_str(),
                _ => false,
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// The declared proxies.
    pub fn proxies(&self) -> &BTreeMap<ProxyName, Proxy> {
        &self.proxies
    }

    pub fn proxy(&self, name: &ProxyName) -> Option<&Proxy> {
        self.proxies.get(name)
    }

    /// The repos reached through the proxy `name`.
    pub fn proxy_users(&self, name: &ProxyName) -> Vec<RepoName> {
        self.repos
            .iter()
            .filter(|(_, r)| r.proxy.as_ref() == Some(name))
            .map(|(repo, _)| repo.clone())
            .collect()
    }

    /// The repos that name the template `name`.
    pub fn template_users(&self, name: &TemplateName) -> Vec<RepoName> {
        self.repos
            .iter()
            .filter(|(_, r)| r.templates.contains(name))
            .map(|(repo, _)| repo.clone())
            .collect()
    }

    /// Whether a ticket under the template `template` may reach `repo`: the repo is
    /// registered and names the template.
    pub fn allows(&self, repo: &RepoName, template: &TemplateName) -> bool {
        self.repos
            .get(repo)
            .is_some_and(|entry| entry.templates.contains(template))
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

fn validate_repo(
    name: &RepoName,
    repo: &RepoEntry,
    keys: &BTreeMap<KeyId, Key>,
    pins: &BTreeMap<UpstreamHost, Vec<HostKey>>,
    proxies: &BTreeMap<ProxyName, Proxy>,
    templates: &BTreeMap<TemplateName, Template>,
) -> Result<(), FieldError> {
    let at = |field: &str| format!("repos.{name}.{field}");
    let upstream = Upstream::parse(repo.upstream.as_str())
        .map_err(|why| FieldError::at(at("upstream"), why))?;
    let id = &repo.upstream_credential;
    let credential = match keys.get(id) {
        None => {
            return Err(FieldError::at(
                at("upstream_credential"),
                format!("{id} is not declared in keys"),
            ));
        }
        Some(Key::Signing(_)) => {
            return Err(FieldError::at(
                at("upstream_credential"),
                format!("keys.{id} is a signing key (use: signing), not an upstream credential"),
            ));
        }
        Some(Key::Upstream(credential)) => credential,
    };
    match (&upstream, credential) {
        (Upstream::Ssh(url), UpstreamKey::Ssh { .. }) => {
            let host = url.known_hosts_name();
            if !pins.keys().any(|pin| pin.as_str() == host) {
                return Err(FieldError::at(
                    at("upstream"),
                    format!(
                        "its host {host} has no pin in upstream_hosts (writ admin host add scans \
                         it, and pins its keys once you compared them)"
                    ),
                ));
            }
        }
        (Upstream::Https(url), UpstreamKey::Token { host, .. }) => {
            if !host.is(url.host()) {
                return Err(FieldError::at(
                    at("upstream_credential"),
                    format!(
                        "keys.{id} is a token for {host}, not for this upstream's host {}",
                        url.host()
                    ),
                ));
            }
        }
        (Upstream::Ssh(_), UpstreamKey::Token { .. }) => {
            return Err(FieldError::at(
                at("upstream_credential"),
                format!("keys.{id} is a token (kind: token): an ssh:// upstream needs kind: ssh"),
            ));
        }
        (Upstream::Https(_), UpstreamKey::Ssh { .. }) => {
            return Err(FieldError::at(
                at("upstream_credential"),
                format!(
                    "keys.{id} is an SSH key (kind: ssh): an https:// upstream needs kind: token"
                ),
            ));
        }
    }
    if let Some(proxy) = &repo.proxy
        && !proxies.contains_key(proxy)
    {
        return Err(FieldError::at(
            at("proxy"),
            format!("{proxy} is not declared in proxies"),
        ));
    }
    if let Some((proxy, _)) = proxies
        .iter()
        .find(|(_, p)| p.credential.as_ref() == Some(id))
    {
        return Err(FieldError::at(
            at("upstream_credential"),
            format!(
                "keys.{id} is the password of proxies.{proxy}: a key is a repo's credential or \
                 a proxy's, never both"
            ),
        ));
    }
    if let Some(unknown) = repo.templates.iter().find(|t| !templates.contains_key(*t)) {
        return Err(FieldError::at(
            at("templates"),
            format!("{unknown} is not a template"),
        ));
    }
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

/// A proxy: a credential exactly when the URL names a user, a token on the proxy's host; a
/// connect timeout within its bounds.
fn validate_proxy(
    name: &ProxyName,
    proxy: &Proxy,
    keys: &BTreeMap<KeyId, Key>,
) -> Result<(), FieldError> {
    let at = |field: &str| format!("proxies.{name}.{field}");
    match (proxy.url.user(), &proxy.credential) {
        (None, None) => {}
        (Some(_), None) => {
            return Err(FieldError::at(
                at("credential"),
                "required with a user in the URL: the key that holds its password",
            ));
        }
        (None, Some(_)) => {
            return Err(FieldError::at(
                at("credential"),
                "only with a user in the URL (socks5://user@host:port): the password goes with it",
            ));
        }
        (Some(_), Some(id)) => match keys.get(id) {
            None => {
                return Err(FieldError::at(
                    at("credential"),
                    format!("{id} is not declared in keys"),
                ));
            }
            Some(Key::Upstream(UpstreamKey::Token { host, .. })) => {
                if !host.is(proxy.url.host()) {
                    return Err(FieldError::at(
                        at("credential"),
                        format!(
                            "keys.{id} is a token for {host}, not for this proxy's host {}",
                            proxy.url.host()
                        ),
                    ));
                }
            }
            Some(_) => {
                return Err(FieldError::at(
                    at("credential"),
                    format!(
                        "keys.{id} is not a token: a proxy's password is declared with use: \
                         upstream, kind: token, host: {}",
                        proxy.url.host()
                    ),
                ));
            }
        },
    }
    if let Some(timeout) = proxy.connect_timeout
        && !(proxies::MIN_CONNECT_TIMEOUT..=proxies::MAX_CONNECT_TIMEOUT).contains(&timeout)
    {
        return Err(FieldError::at(
            at("connect_timeout"),
            format!(
                "{timeout}, must be from {} to {}",
                proxies::MIN_CONNECT_TIMEOUT,
                proxies::MAX_CONNECT_TIMEOUT
            ),
        ));
    }
    Ok(())
}

fn validate_template(
    name: &TemplateName,
    template: &Template,
    keys: &BTreeMap<KeyId, Key>,
    min_ttl: Duration,
) -> Result<(), FieldError> {
    let at = |field: &str| format!("templates.{name}.{field}");
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
    if let Some(id) = &template.signing_key {
        validate_signing_key(name, template, id, keys)?;
    }
    Ok(())
}
/// A template's `signing_key` is a declared signing key, and an OpenPGP one carries a user id
/// for every committer email the template allows (a remote shows a commit whose committer
/// the key doesn't carry as unverified), as `<committer_name> <email>` when the template sets
/// a name.
fn validate_signing_key(
    name: &TemplateName,
    template: &Template,
    id: &KeyId,
    keys: &BTreeMap<KeyId, Key>,
) -> Result<(), FieldError> {
    let key = match keys.get(id) {
        None => {
            return Err(FieldError::at(
                format!("templates.{name}.signing_key"),
                format!("{id} is not declared in keys"),
            ));
        }
        Some(Key::Upstream(_)) => {
            return Err(FieldError::at(
                format!("templates.{name}.signing_key"),
                format!("keys.{id} is an upstream credential (use: upstream), not a signing key"),
            ));
        }
        Some(Key::Signing(key)) => key,
    };
    if key.format != KeyFormat::Openpgp {
        return Ok(());
    }
    for email in &template.committer_emails {
        if !key.uids.iter().any(|uid| &uid.email() == email) {
            return Err(FieldError::at(
                format!("templates.{name}.committer_emails"),
                format!(
                    "{email} has no user id in keys.{id}.uids (the OpenPGP key would sign \
                     commits a remote shows as unverified)"
                ),
            ));
        }
        // The commits carry the template's name: the key's user id for each email must be
        // that identity, so the certificate and the commits agree.
        if let Some(committer) = &template.committer_name {
            let wanted = format!("{committer} <{email}>");
            if !key.uids.iter().any(|uid| uid.as_str() == wanted) {
                return Err(FieldError::at(
                    format!("templates.{name}.committer_name"),
                    format!(
                        "keys.{id}.uids has no user id {wanted:?}: the OpenPGP key must carry \
                         the name the commits do"
                    ),
                ));
            }
        }
    }
    Ok(())
}
