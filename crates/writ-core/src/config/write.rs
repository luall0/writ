//! The policy in Writ's canonical layout: what `writ admin repo|template|key|host` signs once
//! it changed a field. One layout, whatever the text it started from: the sections in the
//! order `keys`, `upstream_hosts`, `proxies`, `recipients`, `repos`, `templates`, each entry's fields in the operator
//! reference's order, a field left out when it holds its default, lists in flow style (host
//! keys one per line), and a scalar quoted unless it reads back as the same string. Read back,
//! the text is the policy it was written from (the tests and a property test check it).

use std::fmt::Write as _;

use super::{
    Key, NotesRef, ObjectFormat, POLICY_FORMAT, PathsCheck, PolicyConfig, Proxy, Recipient,
    RepoEntry, Section, Template, TicketLink, UpstreamKey,
};
use crate::units::ByteSize;

/// The whole policy.
pub(super) fn policy(policy: &PolicyConfig) -> String {
    let mut out = format!("format: {POLICY_FORMAT}\n\n");
    section(&mut out, "keys", policy.keys.is_empty());
    for (id, key) in &policy.keys {
        entry(&mut out, id.as_str());
        write_key(&mut out, key);
    }
    if !policy.upstream_hosts.is_empty() {
        out.push_str("\nupstream_hosts:\n");
        for (host, pinned) in &policy.upstream_hosts {
            entry(&mut out, host.as_str());
            for key in pinned {
                let _ = writeln!(out, "    - {}", scalar(key.as_str()));
            }
        }
    }
    if !policy.proxies.is_empty() {
        out.push_str("\nproxies:\n");
        for (name, proxy) in &policy.proxies {
            entry(&mut out, name.as_str());
            write_proxy(&mut out, proxy);
        }
    }
    if !policy.recipients.is_empty() {
        out.push_str("\nrecipients:\n");
        for (name, recipient) in &policy.recipients {
            entry(&mut out, name.as_str());
            write_recipient(&mut out, recipient);
        }
    }
    out.push('\n');
    section(&mut out, "repos", policy.repos.is_empty());
    for (name, repo) in &policy.repos {
        entry(&mut out, name.as_str());
        write_repo(&mut out, repo);
    }
    out.push('\n');
    section(&mut out, "templates", policy.templates.is_empty());
    for (name, template) in &policy.templates {
        entry(&mut out, name.as_str());
        write_template(&mut out, template);
    }
    if policy.unseal != super::Unseal::default() {
        let _ = writeln!(out, "\nunseal: {}", policy.unseal.as_str());
    }
    out
}

/// One entry of `section`, as [`policy`] writes it, unindented (`<name>:` then its fields two
/// spaces in); none when the section has no entry by that name.
pub(super) fn one_entry(policy: &PolicyConfig, section: Section, name: &str) -> Option<String> {
    let mut out = String::new();
    match section {
        Section::Keys => {
            let (id, key) = policy.keys.iter().find(|(id, _)| id.as_str() == name)?;
            entry(&mut out, id.as_str());
            write_key(&mut out, key);
        }
        Section::UpstreamHosts => {
            let (host, pinned) = policy
                .upstream_hosts
                .iter()
                .find(|(host, _)| host.as_str() == name)?;
            entry(&mut out, host.as_str());
            for key in pinned {
                let _ = writeln!(out, "    - {}", scalar(key.as_str()));
            }
        }
        Section::Proxies => {
            let (proxy, body) = policy
                .proxies
                .iter()
                .find(|(proxy, _)| proxy.as_str() == name)?;
            entry(&mut out, proxy.as_str());
            write_proxy(&mut out, body);
        }
        Section::Recipients => {
            let (recipient, body) = policy
                .recipients
                .iter()
                .find(|(recipient, _)| recipient.as_str() == name)?;
            entry(&mut out, recipient.as_str());
            write_recipient(&mut out, body);
        }
        Section::Repos => {
            let (repo, body) = policy
                .repos
                .iter()
                .find(|(repo, _)| repo.as_str() == name)?;
            entry(&mut out, repo.as_str());
            write_repo(&mut out, body);
        }
        Section::Templates => {
            let (template, body) = policy
                .templates
                .iter()
                .find(|(template, _)| template.as_str() == name)?;
            entry(&mut out, template.as_str());
            write_template(&mut out, body);
        }
    }
    Some(
        out.lines()
            .map(|line| line.strip_prefix("  ").unwrap_or(line))
            .map(|line| format!("{line}\n"))
            .collect(),
    )
}

fn section(out: &mut String, name: &str, empty: bool) {
    match empty {
        true => {
            let _ = writeln!(out, "{name}: {{}}");
        }
        false => {
            let _ = writeln!(out, "{name}:");
        }
    }
}

fn entry(out: &mut String, name: &str) {
    let _ = writeln!(out, "  {}:", scalar(name));
}

fn field(out: &mut String, name: &str, value: &str) {
    let _ = writeln!(out, "    {name}: {value}");
}

fn list<S: AsRef<str>>(items: impl IntoIterator<Item = S>) -> String {
    let items: Vec<String> = items.into_iter().map(|s| scalar(s.as_ref())).collect();
    format!("[{}]", items.join(", "))
}

fn write_key(out: &mut String, key: &Key) {
    field(out, "use", key.key_use().as_str());
    match key {
        Key::Signing(k) => {
            field(out, "format", k.format.as_str());
            field(out, "algorithm", k.algorithm.as_str());
            if let Some(hash) = k.hash {
                field(out, "hash", hash.as_str());
            }
            if !k.uids.is_empty() {
                field(out, "uids", &list(k.uids.iter().map(|u| u.as_str())));
            }
        }
        Key::Upstream(UpstreamKey::Ssh { algorithm, .. }) => {
            field(out, "kind", "ssh");
            field(out, "algorithm", algorithm.as_str());
        }
        Key::Upstream(UpstreamKey::Token { host, .. }) => {
            field(out, "kind", "token");
            field(out, "host", &scalar(host.as_str()));
        }
    }
    if !key.backend().is_default() {
        field(out, "backend", &scalar(key.backend().as_str()));
    }
}

fn write_proxy(out: &mut String, proxy: &Proxy) {
    field(out, "url", &scalar(proxy.url.as_str()));
    if let Some(credential) = &proxy.credential {
        field(out, "credential", &scalar(credential.as_str()));
    }
    if let Some(timeout) = proxy.connect_timeout {
        field(out, "connect_timeout", &timeout.to_string());
    }
}

fn write_recipient(out: &mut String, recipient: &Recipient) {
    match recipient {
        Recipient::Hardware { backend } => field(out, "backend", &scalar(backend.as_str())),
        Recipient::Recovery { recipient } => field(out, "recipient", &scalar(recipient.as_str())),
    }
}

fn write_repo(out: &mut String, repo: &RepoEntry) {
    field(out, "upstream", &scalar(&repo.upstream));
    field(
        out,
        "upstream_credential",
        &scalar(repo.upstream_credential.as_str()),
    );
    if let Some(proxy) = &repo.proxy {
        field(out, "proxy", &scalar(proxy.as_str()));
    }
    field(
        out,
        "templates",
        &list(repo.templates.iter().map(|t| t.as_str())),
    );
    if !repo.protected_refs.is_empty() {
        field(
            out,
            "protected_refs",
            &list(repo.protected_refs.iter().map(|r| r.to_string())),
        );
    }
    if repo.ticket_link != TicketLink::default() {
        field(out, "ticket_link", repo.ticket_link.as_str());
    }
    if let Some(notes_ref) = repo.notes_ref {
        field(out, "notes_ref", NotesRef::as_str(notes_ref));
    }
    if repo.object_format != ObjectFormat::default() {
        field(out, "object_format", repo.object_format.as_str());
    }
}

fn write_template(out: &mut String, t: &Template) {
    // Fetch only: its operation implied, no count written (M7.9.7).
    let unsigned = t.unsigned_fetch;
    if unsigned {
        field(out, "unsigned_fetch", "true");
    } else {
        let operations: Vec<String> = t.operations.iter().map(|o| o.to_string()).collect();
        field(
            out,
            "operations",
            &list(operations.iter().map(String::as_str)),
        );
    }
    if !t.branches.is_empty() {
        field(
            out,
            "branches",
            &list(t.branches.iter().map(|b| b.to_string())),
        );
    }
    if t.force_push {
        field(out, "force_push", "true");
    }
    if !t.committer_emails.is_empty() {
        field(
            out,
            "committer_emails",
            &list(t.committer_emails.iter().map(|e| e.as_str())),
        );
    }
    if let Some(name) = &t.committer_name {
        field(out, "committer_name", &scalar(name.as_str()));
    }
    if let Some(key) = &t.signing_key {
        field(out, "signing_key", &scalar(key.as_str()));
    }
    field(out, "max_ttl", &scalar(&t.max_ttl.to_string()));
    if !unsigned {
        field(out, "max_signatures", &t.max_signatures.to_string());
        field(out, "max_pushes", &t.max_pushes.to_string());
    }
    field(out, "max_ops_per_minute", &t.max_ops_per_minute.to_string());
    if !unsigned {
        field(out, "max_push_size", &size(t.max_push_size));
    }
    if t.paths_check != PathsCheck::Warn {
        field(out, "paths_check", t.paths_check.as_str());
    }
    if t.require_expected_paths {
        field(out, "require_expected_paths", "true");
    }
    if t.require_session {
        field(out, "require_session", "true");
    }
    if let Some(renewals) = t.max_renewals {
        field(out, "max_renewals", &renewals.to_string());
    }
}

/// A size in the largest unit it is a whole number of (`50MiB`, `2GB`), bytes otherwise.
fn size(size: ByteSize) -> String {
    let bytes = size.bytes();
    let units: [(u64, &str); 6] = [
        (1 << 30, "GiB"),
        (1_000_000_000, "GB"),
        (1 << 20, "MiB"),
        (1_000_000, "MB"),
        (1 << 10, "KiB"),
        (1_000, "KB"),
    ];
    for (factor, unit) in units {
        if bytes != 0 && bytes.is_multiple_of(factor) {
            return format!("{}{unit}", bytes.checked_div(factor).unwrap_or(0));
        }
    }
    bytes.to_string()
}

/// Whether YAML reads `text`, written plain, as the same string: a name of the characters
/// Writ's values use, starting with a letter, digit or `_`, that isn't a boolean, null or
/// number to YAML.
fn plain(text: &str) -> bool {
    let Some(first) = text.chars().next() else {
        return false;
    };
    let safe = |c: char| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '@' | '+' | '-' | '*' | ':')
    };
    if !(first.is_ascii_alphanumeric() || first == '_') || !text.chars().all(safe) {
        return false;
    }
    // `a: b` would be a mapping; `a:b` reads as a string, but quoting costs nothing.
    if text.contains(':') {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "y" | "n"
    ) {
        return false;
    }
    // Anything that might be a number (an integer, a float, hex, octal, an exponent) is
    // quoted: `2h` and `50MiB` stay plain.
    let numeric = |c: char| {
        c.is_ascii_hexdigit() || matches!(c, 'x' | 'X' | 'o' | 'O' | '.' | '_' | '+' | '-')
    };
    !(first.is_ascii_digit() && text.chars().all(numeric))
}

/// `text` as a YAML scalar: plain when that reads back as `text`, double-quoted otherwise
/// (YAML's escapes: `\"`, `\\`, and control characters by code).
pub(crate) fn scalar(text: &str) -> String {
    if plain(text) {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scalar_is_plain_only_when_it_reads_back_the_same() {
        for text in [
            "omega-code",
            "agent/*",
            "refs/heads/main",
            "user+agent@example.org",
            "2h",
            "rsa4096",
            "ssh",
        ] {
            assert_eq!(scalar(text), text, "{text}");
        }
        for (text, written) in [
            ("true", "\"true\""),
            ("No", "\"No\""),
            ("12", "\"12\""),
            ("1e3", "\"1e3\""),
            ("0x1f", "\"0x1f\""),
            ("5d", "\"5d\""),
            ("", "\"\""),
            ("*", "\"*\""),
            ("a b", "\"a b\""),
            ("[h]:2222", "\"[h]:2222\""),
            ("ssh://git@h/x.git", "\"ssh://git@h/x.git\""),
            ("say \"hi\" \\ there", "\"say \\\"hi\\\" \\\\ there\""),
            ("bell\u{7}", "\"bell\\u0007\""),
        ] {
            assert_eq!(scalar(text), written, "{text:?}");
        }
    }

    #[test]
    fn a_size_is_written_in_its_largest_whole_unit() {
        for (bytes, written) in [
            (0, "0"),
            (1, "1"),
            (1 << 30, "1GiB"),
            (50 << 20, "50MiB"),
            (3 << 10, "3KiB"),
            (2_000_000_000, "2GB"),
            (50_000_000, "50MB"),
            (1_500, "1500"),
        ] {
            assert_eq!(size(ByteSize::from_bytes(bytes)), written, "{bytes}");
        }
    }
}
