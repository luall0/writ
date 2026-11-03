//! Ref names, branch and ref patterns, and path patterns.
//!
//! Branch and ref patterns are deliberately simple so that "pattern A is within pattern B" is
//! exact, which template fit and narrowing need: a pattern is either an exact name or a
//! prefix followed by one trailing `*`, which matches any rest (including `/` and nothing).
//! `agent/*` covers `agent/fix-*`, which covers `agent/fix-login`.
//!
//! Path patterns (`expected_paths`) are globs over repository paths: `*` stays inside one
//! path component, `**` crosses them.

use std::fmt;
use std::str::FromStr;

use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// A pattern or ref name that failed validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind} {value:?}: {why}")]
pub struct PatternError {
    pub kind: &'static str,
    pub value: String,
    pub why: String,
}

fn pattern_error(kind: &'static str, value: &str, why: impl Into<String>) -> PatternError {
    PatternError {
        kind,
        value: value.to_owned(),
        why: why.into(),
    }
}

/// Checks a full ref name with the rules of `git check-ref-format`, a little stricter
/// (ASCII only, at most 1024 bytes).
fn check_ref_format(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 1024 {
        return Err("must be 1 to 1024 bytes");
    }
    if !name.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("only printable ASCII, no spaces");
    }
    if name
        .bytes()
        .any(|b| matches!(b, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\'))
    {
        return Err("must not contain ~ ^ : ? * [ or \\");
    }
    if name.contains("..") || name.contains("@{") || name == "@" {
        return Err("must not contain '..' or '@{'");
    }
    if name.ends_with('/') || name.ends_with('.') {
        return Err("must not end with '/' or '.'");
    }
    for component in name.split('/') {
        if component.is_empty() {
            return Err("must not contain empty components ('//' or a leading '/')");
        }
        if component.starts_with('.') || component.ends_with(".lock") {
            return Err("components must not start with '.' or end with .lock");
        }
    }
    Ok(())
}

/// A full ref name (`refs/heads/agent/x`), valid for git.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefName(String);

impl RefName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The branch name if this is `refs/heads/<branch>`.
    pub fn branch(&self) -> Option<&str> {
        self.0.strip_prefix("refs/heads/")
    }
}

impl FromStr for RefName {
    type Err = PatternError;

    fn from_str(value: &str) -> Result<Self, PatternError> {
        if !value.starts_with("refs/") {
            return Err(pattern_error("ref name", value, "must start with refs/"));
        }
        check_ref_format(value).map_err(|why| pattern_error("ref name", value, why))?;
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Display for RefName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An exact name or `prefix*`, over strings: the shared core of branch and ref patterns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Glob1 {
    Exact(String),
    Prefix(String),
}

impl Glob1 {
    fn parse(value: &str) -> Result<Self, &'static str> {
        match value.strip_suffix('*') {
            None if !value.contains('*') => Ok(Self::Exact(value.to_owned())),
            Some(prefix) if !prefix.contains('*') => Ok(Self::Prefix(prefix.to_owned())),
            _ => Err("'*' is only allowed once, at the end"),
        }
    }

    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Exact(exact) => name == exact,
            Self::Prefix(prefix) => name.starts_with(prefix.as_str()),
        }
    }

    /// [`Glob1::matches`], ignoring ASCII case (ref names are ASCII).
    fn matches_ignoring_case(&self, name: &str) -> bool {
        match self {
            Self::Exact(exact) => name.eq_ignore_ascii_case(exact),
            Self::Prefix(prefix) => name
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix)),
        }
    }

    /// Every name matched by `other` is matched by `self`.
    fn covers(&self, other: &Glob1) -> bool {
        match (self, other) {
            (_, Self::Exact(name)) => self.matches(name),
            (Self::Exact(_), Self::Prefix(_)) => false,
            (Self::Prefix(mine), Self::Prefix(theirs)) => theirs.starts_with(mine.as_str()),
        }
    }

    fn text(&self) -> String {
        match self {
            Self::Exact(exact) => exact.clone(),
            Self::Prefix(prefix) => format!("{prefix}*"),
        }
    }
}

macro_rules! glob1_pattern {
    ($(#[$meta:meta])* $name:ident, $kind:literal, $full:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Glob1);

        impl $name {
            /// Every name matched by `other` is also matched by `self`.
            pub fn covers(&self, other: &$name) -> bool {
                self.0.covers(&other.0)
            }
        }

        impl FromStr for $name {
            type Err = PatternError;

            fn from_str(value: &str) -> Result<Self, PatternError> {
                let glob = Glob1::parse(value).map_err(|why| pattern_error($kind, value, why))?;
                // The pattern must stand for valid names: check the exact name, or the prefix
                // completed with a sample character.
                let sample = match &glob {
                    Glob1::Exact(exact) => exact.clone(),
                    Glob1::Prefix(prefix) => format!("{prefix}x"),
                };
                let full: fn(&str) -> Result<(), &'static str> = $full;
                full(&sample).map_err(|why| pattern_error($kind, value, why))?;
                Ok(Self(glob))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0.text())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0.text())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                text.parse().map_err(de::Error::custom)
            }
        }
    };
}

glob1_pattern!(
    /// A branch pattern from a template or a ticket: a short branch name (`agent/oauth`) or a
    /// prefix with a trailing `*` (`agent/*`). Matches `refs/heads/<branch>`.
    BranchPattern,
    "branch pattern",
    |sample| check_ref_format(&format!("refs/heads/{sample}"))
);

glob1_pattern!(
    /// A full ref pattern for `protected_refs`: `refs/heads/main`, `refs/tags/*`.
    RefPattern,
    "ref pattern",
    |sample| {
        if sample.starts_with("refs/") {
            check_ref_format(sample)
        } else {
            Err("must start with refs/")
        }
    }
);

impl BranchPattern {
    /// Matches the ref if it is a branch whose name the pattern matches.
    pub fn matches_ref(&self, name: &RefName) -> bool {
        name.branch().is_some_and(|branch| self.0.matches(branch))
    }
}

impl RefPattern {
    pub fn matches(&self, name: &RefName) -> bool {
        self.0.matches(name.as_str())
    }

    /// Whether this protected-ref pattern protects `name`: matched **ignoring case**. On a
    /// case-insensitive file system (APFS, local mode's mirrors) `refs/heads/MAIN` and
    /// `refs/heads/main` are the same loose ref file, so an update of one moves the other.
    pub fn protects(&self, name: &RefName) -> bool {
        self.0.matches_ignoring_case(name.as_str())
    }
}

/// The `*`, `?`, `[` and `{` a path pattern may hold (`**` counts two).
pub const MAX_PATH_WILDCARDS: usize = 16;

/// A glob over repository paths (`src/auth/**`, `src/routes/oauth*`). `*` and `?` stay
/// inside one component, `**` crosses components. Holds the validated text; [`PathSet`]
/// compiles several for matching.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathPattern(String);

fn build_glob(value: &str) -> Result<Glob, globset::Error> {
    GlobBuilder::new(value)
        .literal_separator(true)
        .backslash_escape(true)
        .build()
}

impl PathPattern {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Matches a path relative to the repository root (`src/auth/login.rs`).
    pub fn matches(&self, path: &str) -> bool {
        build_glob(&self.0).is_ok_and(|glob| glob.compile_matcher().is_match(path))
    }
}

impl FromStr for PathPattern {
    type Err = PatternError;

    fn from_str(value: &str) -> Result<Self, PatternError> {
        let invalid = |why: &str| pattern_error("path pattern", value, why);
        if value.is_empty() || value.len() > 1024 {
            return Err(invalid("must be 1 to 1024 bytes"));
        }
        if value.starts_with('/') || value.chars().any(char::is_control) {
            return Err(invalid("must be relative, with no control characters"));
        }
        if value.split('/').any(|c| c == ".." || c == ".") {
            return Err(invalid("must not contain '.' or '..' components"));
        }
        // What makes a set of globs costly to match (the review after M5.5, S8): wildcards,
        // classes and alternatives. A literal is free.
        let wildcards = value
            .chars()
            .filter(|c| matches!(c, '*' | '?' | '[' | '{'))
            .count();
        if wildcards > MAX_PATH_WILDCARDS {
            return Err(invalid(&format!(
                "has {wildcards} of `*`, `?`, `[` and `{{`, at most {MAX_PATH_WILDCARDS}"
            )));
        }
        build_glob(value)
            .map_err(|e| pattern_error("path pattern", value, e.kind().to_string()))?;
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for PathPattern {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PathPattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(de::Error::custom)
    }
}

/// Several path patterns compiled together: a path matches if any pattern does.
pub struct PathSet(GlobSet);

impl PathSet {
    /// Compiles the patterns. Fails only if one doesn't compile, which validation prevents.
    pub fn new<'a>(
        patterns: impl IntoIterator<Item = &'a PathPattern>,
    ) -> Result<Self, PatternError> {
        let mut builder = GlobSetBuilder::new();
        for pattern in patterns {
            let glob = build_glob(&pattern.0)
                .map_err(|e| pattern_error("path pattern", &pattern.0, e.kind().to_string()))?;
            builder.add(glob);
        }
        builder
            .build()
            .map(Self)
            .map_err(|e| pattern_error("path pattern set", "", e.kind().to_string()))
    }

    pub fn matches(&self, path: &str) -> bool {
        self.0.is_match(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn branch(p: &str) -> BranchPattern {
        p.parse().unwrap()
    }

    fn refname(r: &str) -> RefName {
        r.parse().unwrap()
    }

    #[test]
    fn ref_names_follow_git() {
        for good in ["refs/heads/main", "refs/heads/agent/x-1", "refs/tags/v1.0"] {
            assert!(good.parse::<RefName>().is_ok(), "{good}");
        }
        for bad in [
            "main",
            "refs/heads/",
            "refs/heads/a..b",
            "refs/heads/a b",
            "refs/heads/.x",
            "refs/heads/x.lock",
            "refs/heads//x",
            "refs/heads/x@{1}",
            "refs/heads/x~1",
            "refs/heads/*",
            "refs/heads/x\u{7f}",
        ] {
            assert_eq!(
                bad.parse::<RefName>().unwrap_err().kind,
                "ref name",
                "{bad}"
            );
        }
    }

    #[test]
    fn branch_patterns_match_branches_only() {
        let p = branch("agent/*");
        assert!(p.matches_ref(&refname("refs/heads/agent/x")));
        assert!(p.matches_ref(&refname("refs/heads/agent/x/y")));
        assert!(!p.matches_ref(&refname("refs/heads/agents/x")));
        assert!(!p.matches_ref(&refname("refs/tags/agent/x")));
        assert!(!p.matches_ref(&refname("refs/heads/main")));
        let exact = branch("agent/oauth");
        assert!(exact.matches_ref(&refname("refs/heads/agent/oauth")));
        assert!(!exact.matches_ref(&refname("refs/heads/agent/oauth2")));
        assert!(branch("*").matches_ref(&refname("refs/heads/main")));
        for bad in [
            "",
            "a*b",
            "**",
            "agent/*/x",
            "refs/heads/../x",
            "a..*",
            "/x",
        ] {
            assert_eq!(
                bad.parse::<BranchPattern>().unwrap_err().kind,
                "branch pattern",
                "{bad}"
            );
        }
    }

    #[test]
    fn coverage_is_exact() {
        assert!(branch("agent/*").covers(&branch("agent/fix-*")));
        assert!(branch("agent/*").covers(&branch("agent/oauth")));
        assert!(branch("agent/*").covers(&branch("agent/*")));
        assert!(branch("*").covers(&branch("agent/*")));
        assert!(!branch("agent/fix-*").covers(&branch("agent/*")));
        assert!(!branch("agent/oauth").covers(&branch("agent/oauth*")));
        assert!(!branch("agent/*").covers(&branch("agents/x")));
        assert!(branch("agent/oauth").covers(&branch("agent/oauth")));
    }

    #[test]
    fn protected_ref_patterns() {
        let tags: RefPattern = "refs/tags/*".parse().unwrap();
        assert!(tags.matches(&refname("refs/tags/v1")));
        assert!(!tags.matches(&refname("refs/heads/v1")));
        assert!("refs/heads/main".parse::<RefPattern>().is_ok());
        for bad in ["heads/main", "*"] {
            let error = bad.parse::<RefPattern>().unwrap_err();
            assert_eq!(
                (error.kind, error.why.as_str()),
                ("ref pattern", "must start with refs/")
            );
        }
    }

    #[test]
    fn path_patterns() {
        let p: PathPattern = "src/auth/**".parse().unwrap();
        assert!(p.matches("src/auth/login.rs"));
        assert!(p.matches("src/auth/deep/er.rs"));
        assert!(!p.matches("src/billing/x.rs"));
        let q: PathPattern = "src/routes/oauth*".parse().unwrap();
        assert!(q.matches("src/routes/oauth_callback.rs"));
        assert!(!q.matches("src/routes/oauth/x.rs"));
        let set = PathSet::new([&p, &q]).unwrap();
        assert!(set.matches("src/auth/a.rs") && set.matches("src/routes/oauth.rs"));
        assert!(!set.matches("README.md"));
        // At most 16 of `*`, `?`, `[` and `{` (`**` counts two): what makes matching cost.
        let at = format!("src/{}", "*?".repeat(8));
        assert!(at.parse::<PathPattern>().is_ok(), "{at}");
        let over = format!("{at}*");
        let error = over.parse::<PathPattern>().unwrap_err();
        assert_eq!(error.kind, "path pattern");
        assert!(
            error
                .to_string()
                .contains("has 17 of `*`, `?`, `[` and `{`, at most 16"),
            "{error}"
        );
        let braces = format!("src/{}", "{a,b}".repeat(17));
        assert!(
            braces
                .parse::<PathPattern>()
                .unwrap_err()
                .to_string()
                .contains("has 17 of")
        );
        for bad in ["", "/abs", "../x", "a/./b", "src/[", "a\nb"] {
            assert_eq!(
                bad.parse::<PathPattern>().unwrap_err().kind,
                "path pattern",
                "{bad:?}"
            );
        }
    }
}
