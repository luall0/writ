//! YAML documents the daemon reads (the policy configuration, ticket files, its own config):
//! [`parse_yaml`], and [`FieldError`], an error that names the field it is about.

use serde::de::DeserializeOwned;

/// A parse or validation error, with the path of the field it is about
/// (`templates.quick-fix.max_ttl: invalid duration "1 hour"`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {message}")]
pub struct FieldError {
    /// Dotted path to the field (`templates.quick-fix.max_ttl`), or `.` for the whole document.
    pub path: String,
    pub message: String,
}

impl FieldError {
    pub(crate) fn at(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

/// The largest YAML document parsed: a ticket arrives in at most `MAX_BODY` (256 KiB), and a
/// policy or a daemon configuration is a few kilobytes.
pub const MAX_YAML_BYTES: usize = 1 << 20;

/// The parser's options, the same for every document (tickets from agents, the policy, the
/// daemon's configuration): no anchors, aliases or merge keys (a ticket is plain data, and an
/// alias multiplies what a small request costs to parse), no duplicate keys, `true`/`false`
/// only as booleans, one document, and bounded size, depth and node count. Library defaults
/// are never relied on for any of this.
fn options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_reader_input_bytes: Some(MAX_YAML_BYTES),
            max_total_scalar_bytes: MAX_YAML_BYTES,
            max_aliases: 0,
            max_anchors: 0,
            max_merge_keys: 0,
            max_documents: 1,
            max_depth: 32,
            max_nodes: 50_000,
        },
        merge_keys: serde_saphyr::MergeKeyPolicy::Error,
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
        strict_booleans: true,
    }
}

/// Parses YAML into `T` with the hardened [`options`], reporting the path of the failing
/// field. Every mapping's keys are unique as the text they are read as, whatever their YAML
/// form ([`UniqueKeys`]).
pub fn parse_yaml<T: DeserializeOwned>(text: &str) -> Result<T, FieldError> {
    if text.len() > MAX_YAML_BYTES {
        return Err(FieldError::at(
            ".",
            format!("the document is larger than {MAX_YAML_BYTES} bytes"),
        ));
    }
    parse_with::<UniqueKeys>(text)?;
    parse_with::<T>(text)
}

/// [`parse_yaml`]'s one pass, into `T`.
fn parse_with<T: DeserializeOwned>(text: &str) -> Result<T, FieldError> {
    let mut failed_at: Option<String> = None;
    let result = serde_saphyr::with_deserializer_from_str_with_options(text, options(), |de| {
        serde_path_to_error::deserialize::<_, T>(de).map_err(|e| {
            failed_at = Some(e.path().to_string());
            e.into_inner()
        })
    });
    result.map_err(|e| {
        // serde-saphyr's own message carries a snippet; keep the first line, plus the location.
        let full = e.to_string();
        let first = full.lines().next().unwrap_or("invalid YAML");
        let message = first.strip_prefix("error: ").unwrap_or(first).to_owned();
        FieldError::at(failed_at.unwrap_or_else(|| ".".to_owned()), message)
    })
}

/// A document read only to check that no mapping holds a key twice as the text its key is
/// read as (the review after M7.6, P-2): the parser compares a plain `1` and a quoted `"1"` (or
/// `!!str 1`) as different keys, while a map of names reads both as `"1"`, the last one
/// winning silently.
struct UniqueKeys;

impl<'de> serde::Deserialize<'de> for UniqueKeys {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        de.deserialize_any(Walk)
    }
}

/// A key, as the text a map of names reads it as.
struct KeyText(String);

impl<'de> serde::Deserialize<'de> for KeyText {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        String::deserialize(de).map(KeyText)
    }
}

struct Walk;

impl<'de> serde::de::Visitor<'de> for Walk {
    type Value = UniqueKeys;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("YAML")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<UniqueKeys, A::Error> {
        let mut seen = std::collections::BTreeSet::new();
        while let Some(KeyText(key)) = map.next_key()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "the key {key:?} is given twice (in two forms of one text)"
                )));
            }
            map.next_value::<UniqueKeys>()?;
        }
        Ok(UniqueKeys)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<UniqueKeys, A::Error> {
        while seq.next_element::<UniqueKeys>()?.is_some() {}
        Ok(UniqueKeys)
    }

    fn visit_bool<E>(self, _: bool) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
    fn visit_i64<E>(self, _: i64) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
    fn visit_i128<E>(self, _: i128) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
    fn visit_u64<E>(self, _: u64) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
    fn visit_u128<E>(self, _: u128) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
    fn visit_f64<E>(self, _: f64) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
    fn visit_str<E>(self, _: &str) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
    fn visit_unit<E>(self) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
    fn visit_none<E>(self) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, de: D) -> Result<UniqueKeys, D::Error> {
        de.deserialize_any(Walk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Doc {
        title: String,
        #[serde(default)]
        plan: Vec<String>,
        #[serde(default)]
        flag: bool,
    }

    fn refused(text: &str) -> String {
        match parse_yaml::<Doc>(text) {
            Ok(doc) => panic!("accepted {text:?} as {doc:?}"),
            Err(e) => e.to_string(),
        }
    }

    /// The review after M7.6 (P-2): a plain integer key and the same digits quoted or tagged
    /// were two keys to the parser, one to a map of names: the last won silently.
    #[test]
    fn a_key_given_twice_in_two_forms_is_refused() {
        use std::collections::BTreeMap;
        for text in [
            "1: a\n\"1\": b\n",
            "1: a\n!!str 1: b\n",
            "r:\n  1: a\n  '1': b\n",
        ] {
            let error = match parse_yaml::<BTreeMap<String, serde::de::IgnoredAny>>(text) {
                Ok(map) => panic!("accepted {text:?} as {map:?}"),
                Err(e) => e.to_string(),
            };
            assert!(
                error.contains("the key \"1\" is given twice (in two forms of one text)"),
                "{text:?}: {error}"
            );
        }
        // One of each, and keys that only look alike: read.
        let map: BTreeMap<String, String> = parse_yaml("1: a\n\"2\": b\n10: c\n").unwrap();
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn plain_data_is_read() {
        let doc: Doc = parse_yaml("title: t\nplan: [a, b]\nflag: true\n").unwrap();
        assert_eq!(doc.plan, ["a", "b"]);
        assert!(doc.flag);
    }

    #[test]
    fn anchors_aliases_and_merge_keys_are_refused() {
        // An alias multiplies what a small request costs to parse: refused at the anchor,
        // since a ticket is plain data and needs none.
        for text in ["title: &t x\nplan: [*t, *t, *t]\n", "title: &t x\n"] {
            let error = refused(text);
            assert!(
                error.contains("budget breached: Anchors"),
                "{text:?}: {error}"
            );
        }
        let error = refused("<<: {title: x}\n");
        assert!(error.contains("YAML merge keys are not allowed"), "{error}");
    }

    #[test]
    fn one_document_and_strict_booleans() {
        let error = refused("title: a\n---\ntitle: b\n");
        assert!(error.contains("budget breached: Documents"), "{error}");
        // YAML 1.1 booleans are not booleans.
        for word in ["yes", "on", "y", "no"] {
            let error = refused(&format!("title: t\nflag: {word}\n"));
            assert!(error.starts_with("flag: "), "{word}: {error}");
            assert!(error.contains("invalid boolean"), "{word}: {error}");
        }
        let error = refused("title: a\ntitle: b\n");
        assert!(error.contains("duplicate mapping key: title"), "{error}");
    }

    #[test]
    fn a_document_over_the_limit_is_refused_before_parsing() {
        let at_limit = format!("title: {}\n", "x".repeat(MAX_YAML_BYTES - 8));
        assert_eq!(at_limit.len(), MAX_YAML_BYTES);
        assert!(parse_yaml::<Doc>(&at_limit).is_ok());
        let over = format!("title: {}\n", "x".repeat(MAX_YAML_BYTES - 7));
        assert_eq!(
            refused(&over),
            format!(".: the document is larger than {MAX_YAML_BYTES} bytes")
        );
    }
}
