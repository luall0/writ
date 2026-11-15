//! Every key of `policy.yaml` and of the ticket file has its row in the operator reference
//! (`docs/operators/policy-yaml.md`, `docs/operators/ticket.md`) and in the configuration
//! coverage registry (`docs/testing.md`), and every row names a key the parser takes
//! (AGENTS.md rule 19). The keys come from the parser itself: a probe key makes it list the
//! fields it expects, so a new field shows up here without anyone listing it. A new section
//! (a field holding a map of its own) is expanded by adding it to the probes below.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use writ_core::config::PolicyConfig;
use writ_core::ticket::TicketRequest;

const POLICY_PAGE: &str = include_str!("../../../docs/operators/policy-yaml.md");
const TICKET_PAGE: &str = include_str!("../../../docs/operators/ticket.md");
const TESTING: &str = include_str!("../../../docs/testing.md");
const POLICY_TEMPLATE: &str = include_str!("../../../docs/operators/templates/policy.yaml");
const TICKET_TEMPLATE: &str = include_str!("../../../docs/operators/templates/ticket.yaml");

/// What the parser says it expects instead of the probe: the fields of a map, or the values
/// of an enumeration.
fn expected(error: &str) -> Vec<String> {
    let (_, list) = error
        .split_once("expected one of ")
        .unwrap_or_else(|| panic!("no list of what is expected in: {error}"));
    list.split(", ")
        .map(|name| name.trim().trim_matches('`').to_owned())
        .collect()
}

/// A section's keys, `prefix` before each, minus the ones expanded as sections themselves.
fn keys_of(error: &str, prefix: &str, sections: &[&str]) -> Vec<String> {
    expected(error)
        .into_iter()
        .filter(|name| !sections.contains(&name.as_str()))
        .map(|name| format!("{prefix}{name}"))
        .collect()
}

fn policy_error(doc: &str) -> String {
    PolicyConfig::from_yaml(doc).unwrap_err().to_string()
}

fn ticket_error(doc: &str) -> String {
    TicketRequest::from_yaml(doc).unwrap_err().to_string()
}

/// The fields the parser reads only to refuse them, naming where they moved (M6.2) or that
/// format 2 removed them (M7.9.6; a format 1 policy is only rewritten): not keys.
const MOVED: &[&str] = &[
    "signing_keys",
    "templates.<name>.repos",
    "repos.<name>.push_modes",
    "repos.<name>.direct_ssh",
    "templates.<name>.push_modes",
];

/// Every key of `policy.yaml`, as the reference writes it (`repos.<name>.upstream`).
fn policy_keys() -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let top = expected(&policy_error("__probe__: 0"));
    assert_eq!(
        top,
        [
            "format",
            "keys",
            "upstream_hosts",
            "proxies",
            "recipients",
            "repos",
            "templates",
            "unseal",
            "signing_keys"
        ],
        "a new top-level section: probe it"
    );
    keys.extend(keys_of(
        &policy_error("format: 2\nkeys:\n  k:\n    __probe__: 0\nrepos: {}\ntemplates: {}"),
        "keys.<id>.",
        &[],
    ));
    // A map of hosts, each to a list of keys: one row.
    keys.insert("upstream_hosts.<host>".to_owned());
    // Top-level scalars (M7.6, M7.9.6): one row each.
    keys.insert("unseal".to_owned());
    keys.insert("format".to_owned());
    keys.extend(keys_of(
        &policy_error(
            "format: 2\nkeys: {}\nproxies:\n  p:\n    __probe__: 0\nrepos: {}\ntemplates: {}",
        ),
        "proxies.<name>.",
        &[],
    ));
    keys.extend(keys_of(
        &policy_error(
            "format: 2\nkeys: {}\nrecipients:\n  r:\n    __probe__: 0\nrepos: {}\ntemplates: {}",
        ),
        "recipients.<name>.",
        &[],
    ));
    keys.extend(keys_of(
        &policy_error("format: 2\nkeys: {}\nrepos:\n  r:\n    __probe__: 0\ntemplates: {}"),
        "repos.<name>.",
        &[],
    ));
    keys.extend(keys_of(
        &policy_error("format: 2\nkeys: {}\nrepos: {}\ntemplates:\n  t:\n    __probe__: 0"),
        "templates.<name>.",
        &[],
    ));
    keys.retain(|key| !MOVED.contains(&key.as_str()));
    keys
}

/// Every key of the ticket file (`repos.<repo>.operations`).
fn ticket_keys() -> BTreeSet<String> {
    let sections = ["caller", "common", "repos", "ticket", "limits"];
    let mut keys: BTreeSet<String> = keys_of(&ticket_error("__probe__: 0"), "", &sections)
        .into_iter()
        .collect();
    keys.extend(keys_of(
        &ticket_error("caller:\n  descends_from:\n    __probe__: 0"),
        "caller.descends_from.",
        &[],
    ));
    let caller = expected(&ticket_error("caller:\n  __probe__: 0"));
    assert_eq!(
        caller,
        ["descends_from"],
        "a new caller constraint: probe it"
    );
    for section in ["common", "ticket", "limits"] {
        keys.extend(keys_of(
            &ticket_error(&format!("{section}:\n  __probe__: 0")),
            &format!("{section}."),
            &[],
        ));
    }
    keys.extend(keys_of(
        &ticket_error("repos:\n  r:\n    __probe__: 0"),
        "repos.<repo>.",
        &["limits"],
    ));
    keys.extend(keys_of(
        &ticket_error("repos:\n  r:\n    operations: [fetch]\n    limits:\n      __probe__: 0"),
        "repos.<repo>.limits.",
        &[],
    ));
    keys
}

/// The keys of a reference page: the first cell of each table row, when it is a key in
/// backticks.
fn page_rows(page: &str) -> Vec<(String, String)> {
    page.lines()
        .filter_map(|line| line.strip_prefix("| `"))
        .filter_map(|rest| {
            let (key, _) = rest.split_once('`')?;
            Some((key.to_owned(), rest.to_owned()))
        })
        .collect()
}

/// The keys the coverage registry lists for one file (`policy.yaml: repos.<name>.upstream`).
fn registry(file: &str) -> BTreeSet<String> {
    let (_, section) = TESTING
        .split_once("## Configuration coverage: every key")
        .expect("the registry section in docs/testing.md");
    let section = section
        .split_once("\n## ")
        .map_or(section, |(body, _)| body);
    let prefix = format!("| `{file}: ");
    section
        .lines()
        .filter_map(|line| line.strip_prefix(prefix.as_str()))
        .filter_map(|rest| rest.split('`').next())
        .map(str::to_owned)
        .collect()
}

fn assert_same(what: &str, code: &BTreeSet<String>, listed: &BTreeSet<String>) {
    let missing: Vec<&String> = code.difference(listed).collect();
    let unknown: Vec<&String> = listed.difference(code).collect();
    assert!(
        missing.is_empty() && unknown.is_empty(),
        "{what}: keys the parser takes without a row {missing:?}; rows for keys it doesn't \
         take {unknown:?}"
    );
}

/// Each value the parser takes for `key` (from `probe`) is named, in backticks, in its row.
fn assert_values_listed(page: &[(String, String)], key: &str, error: &str) {
    let values = expected(error);
    assert!(!values.is_empty(), "{key}: no values from the parser");
    let (_, row) = page
        .iter()
        .find(|(k, _)| k == key)
        .unwrap_or_else(|| panic!("{key}: no row"));
    for value in values {
        assert!(
            row.contains(&format!("`{value}`")),
            "{key}: the value `{value}` is not in its row"
        );
    }
}

#[test]
fn every_policy_key_is_in_the_operator_reference() {
    let code = policy_keys();
    assert!(code.len() > 20, "{code:?}");
    let page = page_rows(POLICY_PAGE);
    let rows: BTreeSet<String> = page.iter().map(|(key, _)| key.clone()).collect();
    assert_eq!(rows.len(), page.len(), "a key with two rows");
    assert_same("docs/operators/policy-yaml.md", &code, &rows);
    assert_same(
        "docs/testing.md's configuration coverage registry (policy.yaml)",
        &code,
        &registry("policy.yaml"),
    );
    let repo = "format: 2\nkeys: {}\nrepos:\n  r:\n    FIELD: __probe__\ntemplates: {}";
    let key = "format: 2\nkeys:\n  k:\n    FIELD: __probe__\nrepos: {}\ntemplates: {}";
    for (name, doc) in [
        ("keys.<id>.use", key.replace("FIELD", "use")),
        ("keys.<id>.kind", key.replace("FIELD", "kind")),
        ("keys.<id>.format", key.replace("FIELD", "format")),
        ("keys.<id>.algorithm", key.replace("FIELD", "algorithm")),
        ("keys.<id>.hash", key.replace("FIELD", "hash")),
        (
            "repos.<name>.ticket_link",
            repo.replace("FIELD", "ticket_link"),
        ),
        (
            "repos.<name>.object_format",
            repo.replace("FIELD", "object_format"),
        ),
        (
            "templates.<name>.operations",
            "format: 2\nkeys: {}\nrepos: {}\ntemplates:\n  t:\n    operations: [__probe__]"
                .to_owned(),
        ),
        (
            "templates.<name>.paths_check",
            "format: 2\nkeys: {}\nrepos: {}\ntemplates:\n  t:\n    paths_check: __probe__"
                .to_owned(),
        ),
    ] {
        assert!(doc.contains("__probe__"), "{doc}");
        assert_values_listed(&page, name, &policy_error(&doc));
    }
}

#[test]
fn every_ticket_key_is_in_the_operator_reference() {
    let code = ticket_keys();
    assert!(code.len() > 20, "{code:?}");
    let page = page_rows(TICKET_PAGE);
    let rows: BTreeSet<String> = page.iter().map(|(key, _)| key.clone()).collect();
    assert_eq!(rows.len(), page.len(), "a key with two rows");
    assert_same("docs/operators/ticket.md", &code, &rows);
    assert_same(
        "docs/testing.md's configuration coverage registry (ticket)",
        &code,
        &registry("ticket"),
    );
    for (key, doc) in [
        (
            "repos.<repo>.operations",
            "repos:\n  r:\n    operations: [__probe__]",
        ),
        ("on_violation", "on_violation: __probe__"),
    ] {
        assert_values_listed(&page, key, &ticket_error(doc));
    }
}

#[test]
fn the_probe_reads_every_list_the_parser_writes() {
    // The probe depends on the parser's wording: one field, several, an enumeration.
    assert_eq!(
        expected(&ticket_error("caller:\n  __probe__: 0")),
        ["descends_from"]
    );
    assert_eq!(
        expected(&ticket_error("on_violation: __probe__")),
        ["deny_and_notify", "revoke_lease"]
    );
    assert_eq!(
        expected(&policy_error("__probe__: 0")),
        [
            "format",
            "keys",
            "upstream_hosts",
            "proxies",
            "recipients",
            "repos",
            "templates",
            "unseal",
            "signing_keys"
        ]
    );
}

/// The template with every commented-out setting (`# key: value`, `#   - key:`) taken in:
/// prose comments start with a capital or hold no `key:` first.
fn uncommented(template: &str, skip: &dyn Fn(&str) -> bool) -> String {
    template
        .lines()
        .map(|line| {
            let indent = line.len() - line.trim_start().len();
            let Some(rest) = line.trim_start().strip_prefix("# ") else {
                return line.to_owned();
            };
            let key = rest.trim_start().trim_start_matches("- ");
            let name: String = key
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || *c == '_')
                .collect();
            if name.is_empty()
                || !key
                    .strip_prefix(name.as_str())
                    .is_some_and(|rest| rest.starts_with(':'))
                || skip(line)
            {
                return line.to_owned();
            }
            format!("{}{rest}", " ".repeat(indent))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every key appears in the template, set or commented out (by its last name).
fn assert_template_names(template: &str, keys: &BTreeSet<String>) {
    for key in keys {
        // A map's entry (`upstream_hosts.<host>`) is named by its map.
        let name = key.rsplit('.').find(|part| !part.starts_with('<')).unwrap();
        assert!(
            template.contains(&format!("{name}:")),
            "{key}: not in the template"
        );
    }
}

#[test]
fn the_policy_template_parses_as_is_and_with_every_default_taken_in() {
    // docs/operators/templates/policy.yaml: the required keys set, each optional one
    // commented out at its default.
    PolicyConfig::from_yaml(POLICY_TEMPLATE).unwrap();
    let taken = uncommented(POLICY_TEMPLATE, &|line| {
        // Only with `ticket_link: notes`, not the default.
        line.contains("notes_ref:")
            // Examples of other keys (`  # <id>:` and their `  #   <field>:` lines), and a
            // hash, which left out is the strongest rather than this one.
            || line.contains("agent_pgp:")
            || line.contains("github_token:")
            || line.contains("proxy_password:")
            // An example template, with no repo naming it.
            || line.contains("prefetch:")
            || line.starts_with("  #   ")
            // The proxies and recipients sections are examples: none by default.
            || line.contains("proxies:")
            || line.contains("recipients:")
            || line.starts_with("#   ")
            || line.contains("hash:")
    });
    assert_ne!(taken, POLICY_TEMPLATE);
    let config = PolicyConfig::from_yaml(&taken).unwrap();
    let repo = config.repo(&"my-repo".parse().unwrap()).unwrap();
    assert_eq!(repo.ticket_link, writ_core::config::TicketLink::LedgerOnly);
    assert_eq!(
        PolicyConfig::from_yaml(POLICY_TEMPLATE).unwrap(),
        config,
        "a commented-out value is not the default"
    );
    // notes_ref too: refused only for want of `ticket_link: notes`, and at its default with it.
    let all = uncommented(POLICY_TEMPLATE, &|_| false);
    assert_eq!(
        PolicyConfig::from_yaml(&all).unwrap_err().to_string(),
        "repos.my-repo.notes_ref: only allowed when ticket_link is notes"
    );
    let with_notes = uncommented(POLICY_TEMPLATE, &|_| false).replacen(
        "ticket_link: ledger_only",
        "ticket_link: notes",
        1,
    );
    let notes = PolicyConfig::from_yaml(&with_notes).unwrap();
    let repo = notes.repo(&"my-repo".parse().unwrap()).unwrap();
    assert_eq!(repo.notes_ref, Some(writ_core::config::NotesRef::Commits));
    assert_eq!(repo.notes_ref(), writ_core::config::NotesRef::default());
    assert_template_names(POLICY_TEMPLATE, &policy_keys());
}

#[test]
fn the_ticket_template_parses_as_is_and_with_every_setting_taken_in() {
    TicketRequest::from_yaml(TICKET_TEMPLATE).unwrap();
    let taken = uncommented(TICKET_TEMPLATE, &|_| false);
    assert_ne!(taken, TICKET_TEMPLATE);
    let ticket = TicketRequest::from_yaml(&taken).unwrap();
    assert!(
        ticket.caller.is_some() && ticket.limits.ttl.is_some(),
        "{taken}"
    );
    assert_template_names(TICKET_TEMPLATE, &ticket_keys());
}
