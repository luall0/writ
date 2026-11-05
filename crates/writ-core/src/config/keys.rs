//! `keys.<id>`: every key the policy names, declared with what it is for (`use`) and what it
//! is. A signing key signs commits under a template; an upstream credential reaches a repo's
//! upstream, an SSH key for `ssh://` or a token for `https://`. The change that declares a
//! key makes it (a token is added with `writ admin token`); nothing about a key is guessed.
//!
//! The names here are the policy's; the daemon reads them into its own types and checks each
//! combination against the backend that holds the key (`writd`, `writ_crypto::algorithm`).

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

use crate::names::{NameError, Uid};
use crate::yaml::FieldError;

/// The most user ids one key carries.
pub const MAX_UIDS: usize = 16;

/// The backend a key is declared without one: the daemon's memory, from its keystore.
pub const DEFAULT_BACKEND: &str = "software";

/// A value that isn't one of the names a key field takes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{value:?} is not {what}: expected one of {expected}")]
pub struct UnknownName {
    pub what: &'static str,
    pub value: String,
    pub expected: &'static str,
}

/// Declares an enum of configuration names, read and written by name, whose error lists them.
macro_rules! names {
    ($(#[$meta:meta])* $name:ident, $what:literal, [$($variant:ident = $text:literal),+ $(,)?]) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            /// Every value, in the order the documentation lists them.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// Its name in the policy.
            pub fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text),+
                }
            }

            fn expected() -> &'static str {
                concat!($($text, ", "),+)
                    .trim_end_matches(", ")
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = UnknownName;

            fn from_str(s: &str) -> Result<Self, UnknownName> {
                match s {
                    $($text => Ok($name::$variant),)+
                    _ => Err(UnknownName {
                        what: $what,
                        value: s.chars().take(64).collect(),
                        expected: $name::expected(),
                    }),
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let text = String::deserialize(d)?;
                text.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

names!(
    /// What a key is for.
    KeyUse, "a key use", [Signing = "signing", Upstream = "upstream"]
);
names!(
    /// What an upstream credential is: an SSH key (`ssh://`) or a token (`https://`).
    UpstreamKind, "an upstream credential kind", [Ssh = "ssh", Token = "token"]
);
names!(
    /// The format a signing key signs commits in (git's `gpg.format`).
    KeyFormat, "a signature format (x509 is not supported)", [Ssh = "ssh", Openpgp = "openpgp"]
);
names!(
    /// A key's algorithm. RSA keys are 3072 or 4096 bits: 2048 is about 112-bit security,
    /// deprecated after 2030.
    KeyAlgorithm, "a key algorithm (RSA keys are 3072 or 4096 bits)", [
        Ed25519 = "ed25519",
        P256 = "p256",
        P384 = "p384",
        Rsa3072 = "rsa3072",
        Rsa4096 = "rsa4096",
    ]
);
names!(
    /// The hash a signing key's signatures are made with (nothing under SHA-256).
    HashName, "a hash (nothing under SHA-256 is offered)", [
        Sha256 = "sha256",
        Sha384 = "sha384",
        Sha512 = "sha512",
    ]
);

/// Where a key lives: a backend the daemon has (`software`, its memory; hardware ones
/// later). The policy only checks the name's form; the daemon refuses one it doesn't have.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct BackendName(String);

impl BackendName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The backend a key is declared without one.
    pub fn software() -> Self {
        Self(DEFAULT_BACKEND.to_owned())
    }

    pub fn is_default(&self) -> bool {
        self.0 == DEFAULT_BACKEND
    }
}

impl Default for BackendName {
    fn default() -> Self {
        Self::software()
    }
}

impl TryFrom<String> for BackendName {
    type Error = NameError;

    fn try_from(value: String) -> Result<Self, NameError> {
        let ok = !value.is_empty()
            && value.len() <= 32
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && value.bytes().next().is_some_and(|b| b.is_ascii_lowercase());
        if ok {
            Ok(Self(value))
        } else {
            Err(NameError {
                kind: "backend",
                value: value.chars().take(64).collect(),
                why: "1 to 32 lowercase letters, digits and '-', starting with a letter",
            })
        }
    }
}

impl fmt::Display for BackendName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A token's host: the host name or address it may be sent to (an `https://` URL's host,
/// compared ignoring ASCII case; an IPv6 address without brackets).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct TokenHost(String);

impl TokenHost {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `host` (an `https://` URL's) is this one.
    pub fn is(&self, host: &str) -> bool {
        self.0.eq_ignore_ascii_case(host)
    }
}

impl TryFrom<String> for TokenHost {
    type Error = NameError;

    fn try_from(value: String) -> Result<Self, NameError> {
        let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_');
        if value.is_empty()
            || value.len() > 253
            || value.starts_with('-')
            || !value.chars().all(plain)
        {
            return Err(NameError {
                kind: "token host",
                value: value.chars().take(64).collect(),
                why: "a plain host name or address (no scheme, port, path or wildcard)",
            });
        }
        Ok(Self(value))
    }
}

impl fmt::Display for TokenHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A key that signs commits under the templates that name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKey {
    pub format: KeyFormat,
    pub algorithm: KeyAlgorithm,
    /// Left out: the strongest the format, algorithm and backend allow.
    pub hash: Option<HashName>,
    /// The OpenPGP user ids its certificate carries (an `ssh` key has none).
    pub uids: Vec<Uid>,
    pub backend: BackendName,
}

/// A credential that reaches an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamKey {
    /// An SSH key, for `ssh://` upstreams: its public half is registered on the remote.
    Ssh {
        algorithm: KeyAlgorithm,
        backend: BackendName,
    },
    /// A token, for `https://` upstreams on `host`: added with `writ admin token`, never made.
    Token {
        host: TokenHost,
        backend: BackendName,
    },
}

/// A declared key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Signing(SigningKey),
    Upstream(UpstreamKey),
}

impl Key {
    pub fn key_use(&self) -> KeyUse {
        match self {
            Key::Signing(_) => KeyUse::Signing,
            Key::Upstream(_) => KeyUse::Upstream,
        }
    }

    pub fn backend(&self) -> &BackendName {
        match self {
            Key::Signing(k) => &k.backend,
            Key::Upstream(
                UpstreamKey::Ssh { backend, .. } | UpstreamKey::Token { backend, .. },
            ) => backend,
        }
    }

    /// Its algorithm, none for a token.
    pub fn algorithm(&self) -> Option<KeyAlgorithm> {
        match self {
            Key::Signing(k) => Some(k.algorithm),
            Key::Upstream(UpstreamKey::Ssh { algorithm, .. }) => Some(*algorithm),
            Key::Upstream(UpstreamKey::Token { .. }) => None,
        }
    }

    /// Whether it is key material the daemon makes (every key but a token).
    pub fn is_made(&self) -> bool {
        !matches!(self, Key::Upstream(UpstreamKey::Token { .. }))
    }

    /// What it is, in a few words (`signing ssh ed25519`, `upstream token for github.com`).
    pub fn describe(&self) -> String {
        match self {
            Key::Signing(k) => format!("signing {} {}", k.format, k.algorithm),
            Key::Upstream(UpstreamKey::Ssh { algorithm, .. }) => {
                format!("upstream ssh {algorithm}")
            }
            Key::Upstream(UpstreamKey::Token { host, .. }) => format!("upstream token for {host}"),
        }
    }
}

/// A key as written, before its fields are checked against its use and kind.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawKey {
    #[serde(rename = "use")]
    key_use: KeyUse,
    #[serde(default)]
    kind: Option<UpstreamKind>,
    #[serde(default)]
    format: Option<KeyFormat>,
    #[serde(default)]
    algorithm: Option<KeyAlgorithm>,
    #[serde(default)]
    hash: Option<HashName>,
    #[serde(default)]
    uids: Option<Vec<Uid>>,
    #[serde(default)]
    host: Option<TokenHost>,
    #[serde(default)]
    backend: Option<BackendName>,
}

impl RawKey {
    /// The key its fields describe, at `at` (`keys.<id>`): each field the use and kind need
    /// given, and none they don't take. Never adjusted.
    pub(super) fn check(self, at: &str) -> Result<Key, FieldError> {
        let field = |name: &str| format!("{at}.{name}");
        let refuse = |name: &str, given: bool, why: &str| match given {
            true => Err(FieldError::at(field(name), why.to_owned())),
            false => Ok(()),
        };
        let backend = self.backend.unwrap_or_default();
        match self.key_use {
            KeyUse::Signing => {
                refuse(
                    "kind",
                    self.kind.is_some(),
                    "only for an upstream credential",
                )?;
                refuse("host", self.host.is_some(), "only for an upstream token")?;
                let format = self
                    .format
                    .ok_or_else(|| FieldError::at(field("format"), "required for a signing key"))?;
                let algorithm = self.algorithm.ok_or_else(|| {
                    FieldError::at(field("algorithm"), "required for a signing key")
                })?;
                if format == KeyFormat::Ssh && self.uids.is_some() {
                    return Err(FieldError::at(
                        field("uids"),
                        "user ids are for an OpenPGP key; this one is format: ssh",
                    ));
                }
                // Left out: no certificate yet. Given: 1 to MAX_UIDS.
                if self
                    .uids
                    .as_ref()
                    .is_some_and(|uids| uids.is_empty() || uids.len() > MAX_UIDS)
                {
                    return Err(FieldError::at(
                        field("uids"),
                        format!("must list 1 to {MAX_UIDS} user ids (or be left out)"),
                    ));
                }
                let uids = self.uids.unwrap_or_default();
                let distinct: BTreeSet<&Uid> = uids.iter().collect();
                if distinct.len() != uids.len() {
                    return Err(FieldError::at(field("uids"), "a user id is listed twice"));
                }
                Ok(Key::Signing(SigningKey {
                    format,
                    algorithm,
                    hash: self.hash,
                    uids,
                    backend,
                }))
            }
            KeyUse::Upstream => {
                refuse("format", self.format.is_some(), "only for a signing key")?;
                refuse("hash", self.hash.is_some(), "only for a signing key")?;
                refuse(
                    "uids",
                    self.uids.is_some(),
                    "only for an OpenPGP signing key",
                )?;
                let kind = self.kind.ok_or_else(|| {
                    FieldError::at(
                        field("kind"),
                        "required for an upstream credential (ssh or token)",
                    )
                })?;
                match kind {
                    UpstreamKind::Ssh => {
                        refuse("host", self.host.is_some(), "only for an upstream token")?;
                        let algorithm = self.algorithm.ok_or_else(|| {
                            FieldError::at(field("algorithm"), "required for an ssh credential")
                        })?;
                        Ok(Key::Upstream(UpstreamKey::Ssh { algorithm, backend }))
                    }
                    UpstreamKind::Token => {
                        refuse(
                            "algorithm",
                            self.algorithm.is_some(),
                            "a token has no algorithm (it is made by the remote)",
                        )?;
                        let host = self.host.ok_or_else(|| {
                            FieldError::at(
                                field("host"),
                                "required for a token: the host it may be sent to",
                            )
                        })?;
                        Ok(Key::Upstream(UpstreamKey::Token { host, backend }))
                    }
                }
            }
        }
    }
}
