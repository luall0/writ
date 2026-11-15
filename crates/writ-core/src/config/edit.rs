//! Field edits of one policy entry, as `writ admin <noun> set` and `remove` make them: the
//! fields each section takes ([`fields`]), the `field=value` syntax ([`FieldEdit`]), and the
//! edit applied to the policy in force, read back whole ([`edit`], [`remove`]). Only the
//! fields named change. What comes out is a policy text in the canonical layout that the
//! daemon parses and checks again, exactly as it checks `writ admin apply`: a convenience,
//! never the boundary (hard rule 1).

use std::fmt;

use serde_json::{Map, Value};

use super::{PolicyConfig, Section};
use crate::units::Duration;
use crate::yaml::{FieldError, parse_yaml};

/// What a field holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// A name, a duration, a size, a URL: one value.
    Text,
    /// A count (a whole number).
    Count,
    /// `true` or `false`.
    Flag,
    /// A list of values.
    List,
}

/// A field of a section's entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// Its name, as the policy writes it (`max_ttl`, `upstream_credential`).
    pub name: &'static str,
    pub kind: FieldKind,
    /// Required: never unset.
    pub required: bool,
    /// What the entry is (a key's use, kind, format, algorithm, backend): never changed.
    pub fixed: bool,
    /// What it takes, in a few words.
    pub help: &'static str,
    /// What it is when left out, as a prompt shows it (none: required, or nothing).
    pub default: Option<&'static str>,
}

const fn field(name: &'static str, kind: FieldKind, help: &'static str) -> Field {
    Field {
        name,
        kind,
        required: false,
        fixed: false,
        help,
        default: None,
    }
}

const fn required(name: &'static str, kind: FieldKind, help: &'static str) -> Field {
    Field {
        name,
        kind,
        required: true,
        fixed: false,
        help,
        default: None,
    }
}

const fn fixed(name: &'static str, required: bool, help: &'static str) -> Field {
    Field {
        name,
        kind: FieldKind::Text,
        required,
        fixed: true,
        help,
        default: None,
    }
}

/// `field` with what it is when left out.
const fn or(field: Field, default: &'static str) -> Field {
    Field {
        default: Some(default),
        ..field
    }
}

use FieldKind::{Count, Flag, List, Text};

const KEY_FIELDS: &[Field] = &[
    fixed("use", true, "signing or upstream"),
    fixed("kind", false, "an upstream credential's: ssh or token"),
    fixed("format", false, "a signing key's: ssh or openpgp"),
    // Before the algorithm: a backend makes some algorithms only (the Secure Enclave, p256).
    or(
        fixed("backend", false, "where the key lives: software"),
        "software",
    ),
    fixed(
        "algorithm",
        false,
        "ed25519, p256, p384, rsa3072 or rsa4096 (a token has none)",
    ),
    or(
        field("hash", Text, "a signing key's: sha256, sha384 or sha512"),
        "the strongest allowed",
    ),
    field(
        "uids",
        List,
        "an OpenPGP key's user ids: `Name <local@domain>`, 1 to 16",
    ),
    field("host", Text, "a token's: the one host it is sent to"),
];

/// A host's entry is its list of pinned keys: written `keys` here.
const HOST_FIELDS: &[Field] = &[required(
    "keys",
    List,
    "the host keys, `<type> <base64>` as OpenSSH writes them, 1 to 16",
)];

const PROXY_FIELDS: &[Field] = &[
    required(
        "url",
        Text,
        "socks5://[user@]host:port or http://[user@]host:port (Tor: socks5://127.0.0.1:9050)",
    ),
    field(
        "credential",
        Text,
        "with a user in the URL: a token key on the proxy's host, holding the password",
    ),
    or(
        field(
            "connect_timeout",
            Text,
            "how long reaching upstream through it may take, 1s to 5m",
        ),
        "30s",
    ),
];

const RECIPIENT_FIELDS: &[Field] = &[
    fixed(
        "backend",
        false,
        "a hardware key the daemon makes: se-cryptokit (the Mac's Secure Enclave)",
    ),
    field(
        "recipient",
        Text,
        "the recovery key, age1… (writ recovery new, or age-keygen): with backend left out",
    ),
];

const REPO_FIELDS: &[Field] = &[
    required(
        "upstream",
        Text,
        "ssh://[user@]host[:port]/path or https://[user@]host[:port]/path",
    ),
    required(
        "upstream_credential",
        Text,
        "a key declared with use: upstream, of the kind the URL takes",
    ),
    or(
        field(
            "proxy",
            Text,
            "a proxy in proxies, to reach upstream through",
        ),
        "none: upstream reached directly",
    ),
    required(
        "templates",
        List,
        "the templates its tickets may use; empty: the repo is closed",
    ),
    field(
        "protected_refs",
        List,
        "full refs no lease may push (refs/heads/main, refs/tags/*)",
    ),
    or(
        field("ticket_link", Text, "ledger_only, trailer or notes"),
        "ledger_only",
    ),
    or(
        field("notes_ref", Text, "with ticket_link notes: commits or writ"),
        "commits",
    ),
    or(field("object_format", Text, "sha1 or sha256"), "sha1"),
];

const TEMPLATE_FIELDS: &[Field] = &[
    required("operations", List, "fetch, commit_sign, push"),
    field(
        "branches",
        List,
        "branch patterns, one trailing * at most (required with commit_sign or push)",
    ),
    or(
        field(
            "force_push",
            Flag,
            "whether a ticket may ask for force pushes",
        ),
        "false",
    ),
    field(
        "committer_emails",
        List,
        "the emails commits may carry (required with commit_sign)",
    ),
    or(
        field("committer_name", Text, "the name every commit must carry"),
        "not checked",
    ),
    field(
        "signing_key",
        Text,
        "a key declared with use: signing (required with commit_sign)",
    ),
    required(
        "max_ttl",
        Text,
        "the longest lease (2h, 1d), at least the daemon's min_ttl",
    ),
    or(
        field(
            "unsigned_fetch",
            Text,
            "a fetch-only ticket needs no signature, its lease this long at most (15m; 1h at most)",
        ),
        "off",
    ),
    required(
        "max_signatures",
        Count,
        "commits one lease signs in each repo",
    ),
    required("max_pushes", Count, "pushes one lease makes in each repo"),
    required(
        "max_ops_per_minute",
        Count,
        "signatures, pushes and fetches a minute, at least 1",
    ),
    required(
        "max_push_size",
        Text,
        "the largest pack one push sends (50MB; at least 1 byte with push)",
    ),
    or(field("paths_check", Text, "off, warn or deny"), "warn"),
    or(
        field(
            "require_expected_paths",
            Flag,
            "whether a ticket must list expected_paths",
        ),
        "false",
    ),
    or(
        field(
            "require_session",
            Flag,
            "whether a ticket must be bound to a session (writ run, local mode)",
        ),
        "false",
    ),
    or(
        field("max_renewals", Count, "renewals one lease's chain may have"),
        "no limit",
    ),
];

/// The fields `section`'s entries take, in the order the policy writes them.
pub fn fields(section: Section) -> &'static [Field] {
    match section {
        Section::Keys => KEY_FIELDS,
        Section::UpstreamHosts => HOST_FIELDS,
        Section::Proxies => PROXY_FIELDS,
        Section::Recipients => RECIPIENT_FIELDS,
        Section::Repos => REPO_FIELDS,
        Section::Templates => TEMPLATE_FIELDS,
    }
}

/// The field `name` of `section`, or why there is none (naming those there are).
pub fn field_of(section: Section, name: &str) -> Result<&'static Field, String> {
    fields(section)
        .iter()
        .find(|f| f.name == name)
        .ok_or_else(|| {
            let names: Vec<&str> = fields(section).iter().map(|f| f.name).collect();
            format!(
                "{} has no field {:?}: it takes {}",
                section.noun(),
                name.chars().take(64).collect::<String>(),
                names.join(", ")
            )
        })
}

/// What a [`FieldEdit`] does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// `field=value`: replaced (a list by the comma-separated values; `field=` empties it).
    Set(String),
    /// `field+=value`: one value added to a list.
    Add(String),
    /// `field-=value`: one value taken from a list.
    Remove(String),
    /// `field!`: an optional field unset, to its default.
    Unset,
}

/// One `writ admin <noun> set` argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldEdit {
    pub field: String,
    pub change: Change,
}

/// The longest `field=value` argument taken.
pub const MAX_EDIT: usize = 8 * 1024;

impl FieldEdit {
    /// Parses `field=value`, `field+=value`, `field-=value` or `field!`. The field is checked
    /// against the section when the edit is applied.
    pub fn parse(arg: &str) -> Result<Self, String> {
        if arg.len() > MAX_EDIT {
            return Err(format!("an edit is at most {MAX_EDIT} bytes"));
        }
        if arg.chars().any(|c| c.is_control()) {
            return Err("an edit holds no control character".to_owned());
        }
        let named = |field: &str| -> Result<String, String> {
            let ok = !field.is_empty()
                && field
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'.');
            match ok {
                true => Ok(field.to_owned()),
                false => Err(format!(
                    "{:?} is not field=value, field+=value, field-=value or field!",
                    arg.chars().take(64).collect::<String>()
                )),
            }
        };
        if let Some(field) = arg.strip_suffix('!')
            && !field.contains('=')
        {
            return Ok(Self {
                field: named(field)?,
                change: Change::Unset,
            });
        }
        let Some((left, value)) = arg.split_once('=') else {
            return Err(format!(
                "{:?} is not field=value, field+=value, field-=value or field!",
                arg.chars().take(64).collect::<String>()
            ));
        };
        let (field, change) = if let Some(field) = left.strip_suffix('+') {
            (field, Change::Add(value.to_owned()))
        } else if let Some(field) = left.strip_suffix('-') {
            (field, Change::Remove(value.to_owned()))
        } else {
            (left, Change::Set(value.to_owned()))
        };
        Ok(Self {
            field: named(field)?,
            change,
        })
    }
}

impl fmt::Display for FieldEdit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.change {
            Change::Set(v) => write!(f, "{}={v}", self.field),
            Change::Add(v) => write!(f, "{}+={v}", self.field),
            Change::Remove(v) => write!(f, "{}-={v}", self.field),
            Change::Unset => write!(f, "{}!", self.field),
        }
    }
}

/// The policy as a tree of values, read from its canonical text.
fn tree(policy: &PolicyConfig) -> Result<Map<String, Value>, FieldError> {
    match parse_yaml::<Value>(&policy.to_yaml())? {
        Value::Object(map) => Ok(map),
        _ => Err(FieldError::at(".", "the policy is not a mapping")),
    }
}

/// The policy a tree describes, read back as the daemon reads a policy (with `min_ttl`).
fn read_back(tree: Map<String, Value>, min_ttl: Duration) -> Result<PolicyConfig, FieldError> {
    let text = serde_json::to_string(&Value::Object(tree))
        .map_err(|e| FieldError::at(".", e.to_string()))?;
    // JSON is YAML: the same parser, the same checks.
    PolicyConfig::from_yaml_with_min_ttl(&text, min_ttl)
}

/// The entry `name` of `section` in `tree`.
fn entry_mut<'a>(
    tree: &'a mut Map<String, Value>,
    section: Section,
    name: &str,
) -> Result<&'a mut Value, FieldError> {
    tree.get_mut(section.as_str())
        .and_then(Value::as_object_mut)
        .and_then(|entries| entries.get_mut(name))
        .ok_or_else(|| {
            FieldError::at(
                format!("{}.{name}", section.as_str()),
                format!("no {} {name} in the policy", section.noun()),
            )
        })
}

/// The value `text` gives a field of `kind`.
fn value_of(kind: FieldKind, text: &str, at: &str) -> Result<Value, FieldError> {
    match kind {
        Text => {
            if text.is_empty() {
                return Err(FieldError::at(
                    at,
                    "empty: field= empties a list; to unset an optional field, write field!",
                ));
            }
            Ok(Value::String(text.to_owned()))
        }
        Count => text
            .parse::<u64>()
            .map(|n| Value::Number(n.into()))
            .map_err(|_| FieldError::at(at, format!("{text:?} is not a count"))),
        Flag => match text {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err(FieldError::at(at, format!("{text:?}: true or false"))),
        },
        List => Ok(Value::Array(
            text.split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(|v| Value::String(v.to_owned()))
                .collect(),
        )),
    }
}

/// Whether an edit makes the entry (what a key is may be set) or changes it (it may not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Making {
    New,
    Existing,
}

/// Applies one edit to an entry (`obj`, the entry's mapping or, for a host, its list).
fn apply(
    section: Section,
    name: &str,
    entry: &mut Value,
    edit: &FieldEdit,
    making: Making,
) -> Result<(), FieldError> {
    let at = format!("{}.{name}.{}", section.as_str(), edit.field);
    let spec = field_of(section, &edit.field).map_err(|why| FieldError::at(&at, why))?;
    if spec.fixed && making == Making::Existing {
        return Err(FieldError::at(
            &at,
            format!(
                "can't change: it is what the key is (writ admin key rotate {name} makes a new \
                 key, declared otherwise)"
            ),
        ));
    }
    // A host's entry is its list; any other entry a mapping of its fields.
    let slot: &mut Value = match (section, entry) {
        (Section::UpstreamHosts, list) => list,
        (_, Value::Object(map)) => map.entry(edit.field.clone()).or_insert(Value::Null),
        (_, _) => return Err(FieldError::at(&at, "not a mapping")),
    };
    match &edit.change {
        Change::Set(text) => *slot = value_of(spec.kind, text, &at)?,
        Change::Add(text) | Change::Remove(text) => {
            if spec.kind != List {
                return Err(FieldError::at(
                    &at,
                    "+= and -= are for a list: write field=value",
                ));
            }
            if text.is_empty() {
                return Err(FieldError::at(&at, "no value to add or take"));
            }
            if slot.is_null() {
                *slot = Value::Array(Vec::new());
            }
            let Value::Array(items) = slot else {
                return Err(FieldError::at(&at, "not a list"));
            };
            let value = Value::String(text.clone());
            let held = items.contains(&value);
            match (&edit.change, held) {
                (Change::Add(_), true) => {
                    return Err(FieldError::at(&at, format!("{text:?} is listed already")));
                }
                (Change::Add(_), false) => items.push(value),
                (_, false) => {
                    return Err(FieldError::at(&at, format!("{text:?} is not listed")));
                }
                (_, true) => items.retain(|item| item != &value),
            }
        }
        Change::Unset => {
            if spec.required {
                return Err(FieldError::at(&at, "required: it can't be unset"));
            }
            *slot = Value::Null;
        }
    }
    Ok(())
}

/// Drops the fields an edit left without a value (unset, or never there), and a nested
/// section left empty.
fn tidy(entry: &mut Value) {
    if let Value::Object(map) = entry {
        for value in map.values_mut() {
            tidy(value);
        }
        map.retain(|_, value| match value {
            Value::Null => false,
            Value::Object(inner) => !inner.is_empty(),
            _ => true,
        });
    }
}

/// `policy` with the entry `name` of `section` edited by `edits` (each applied in order), read
/// back whole with the daemon's checks (`min_ttl`, the least a template's `max_ttl` may be).
pub fn edit(
    policy: &PolicyConfig,
    section: Section,
    name: &str,
    edits: &[FieldEdit],
    min_ttl: Duration,
) -> Result<PolicyConfig, FieldError> {
    let mut tree = tree(policy)?;
    let entry = entry_mut(&mut tree, section, name)?;
    for one in edits {
        apply(section, name, entry, one, Making::Existing)?;
    }
    tidy(entry);
    read_back(tree, min_ttl)
}

/// `policy` with a new entry `name` in `section`, its fields from `edits` (each applied in
/// order to an empty entry), read back whole with the daemon's checks: a required field left
/// out is refused there, naming it.
pub fn add(
    policy: &PolicyConfig,
    section: Section,
    name: &str,
    edits: &[FieldEdit],
    min_ttl: Duration,
) -> Result<PolicyConfig, FieldError> {
    let mut tree = tree(policy)?;
    let entries = tree
        .entry(section.as_str().to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(entries) = entries else {
        return Err(FieldError::at(section.as_str(), "not a mapping"));
    };
    if entries.contains_key(name) {
        return Err(FieldError::at(
            format!("{}.{name}", section.as_str()),
            format!(
                "there is a {} {name} already (writ admin {} edit {name} changes it)",
                section.noun(),
                section.noun()
            ),
        ));
    }
    let empty = match section {
        Section::UpstreamHosts => Value::Array(Vec::new()),
        _ => Value::Object(Map::new()),
    };
    entries.insert(name.to_owned(), empty);
    let entry = entry_mut(&mut tree, section, name)?;
    for one in edits {
        apply(section, name, entry, one, Making::New)?;
    }
    tidy(entry);
    read_back(tree, min_ttl)
}

/// The fields `edits` don't name that `section` requires: what an `add` with no terminal
/// refuses for, naming them.
pub fn missing(section: Section, edits: &[FieldEdit]) -> Vec<&'static str> {
    fields(section)
        .iter()
        .filter(|f| f.required && !edits.iter().any(|e| e.field == f.name))
        .map(|f| f.name)
        .collect()
}

/// The values the entry `name` of `section` holds, field by field as a prompt shows them (a
/// list's values joined by commas); none when there is no such entry.
pub fn current(
    policy: &PolicyConfig,
    section: Section,
    name: &str,
) -> Option<std::collections::BTreeMap<&'static str, String>> {
    let mut tree = tree(policy).ok()?;
    let entry = entry_mut(&mut tree, section, name).ok()?.clone();
    let shown = |value: &Value| match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Array(items) => Some(
            items
                .iter()
                .map(|i| match i {
                    Value::String(t) => t.clone(),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join(","),
        ),
        _ => None,
    };
    let mut values = std::collections::BTreeMap::new();
    for spec in fields(section) {
        let value = match (section, &entry) {
            (Section::UpstreamHosts, list) => Some(list),
            (_, Value::Object(map)) => map.get(spec.name),
            _ => None,
        };
        if let Some(text) = value.and_then(shown) {
            values.insert(spec.name, text);
        }
    }
    Some(values)
}

/// `policy` without the entry `name` of `section`, read back whole: a template a repo names,
/// a key something uses, a host a repo needs are refused there, naming the field.
pub fn remove(
    policy: &PolicyConfig,
    section: Section,
    name: &str,
    min_ttl: Duration,
) -> Result<PolicyConfig, FieldError> {
    let mut tree = tree(policy)?;
    let removed = tree
        .get_mut(section.as_str())
        .and_then(Value::as_object_mut)
        .and_then(|entries| entries.remove(name));
    if removed.is_none() {
        return Err(FieldError::at(
            format!("{}.{name}", section.as_str()),
            format!("no {} {name} in the policy", section.noun()),
        ));
    }
    read_back(tree, min_ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_syntax_parses_and_anything_else_is_refused() {
        for (arg, field, change) in [
            ("max_ttl=2h", "max_ttl", Change::Set("2h".into())),
            ("templates=", "templates", Change::Set(String::new())),
            (
                "branches+=agent/x-*",
                "branches",
                Change::Add("agent/x-*".into()),
            ),
            (
                "branches-=agent/*",
                "branches",
                Change::Remove("agent/*".into()),
            ),
            ("max_renewals!", "max_renewals", Change::Unset),
            (
                "protected_refs=a,b",
                "protected_refs",
                Change::Set("a,b".into()),
            ),
            (
                "committer_name=A = B",
                "committer_name",
                Change::Set("A = B".into()),
            ),
            (
                "committer_name=Wow!",
                "committer_name",
                Change::Set("Wow!".into()),
            ),
        ] {
            let parsed = FieldEdit::parse(arg).unwrap();
            assert_eq!(
                (parsed.field.as_str(), &parsed.change),
                (field, &change),
                "{arg}"
            );
            assert_eq!(parsed.to_string(), arg);
        }
        let not_one =
            |arg: &str| format!("{arg:?} is not field=value, field+=value, field-=value or field!");
        for bad in ["", "max_ttl", "=2h", "Max=1", "max ttl=1", "!"] {
            assert_eq!(FieldEdit::parse(bad), Err(not_one(bad)), "{bad:?}");
        }
        for bad in ["a\u{1b}=1", "x+=\u{7}"] {
            assert_eq!(
                FieldEdit::parse(bad),
                Err("an edit holds no control character".to_owned()),
                "{bad:?}"
            );
        }
        assert_eq!(
            FieldEdit::parse(&format!("x={}", "a".repeat(MAX_EDIT))),
            Err(format!("an edit is at most {MAX_EDIT} bytes"))
        );
    }
}
