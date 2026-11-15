//! Replies and bodies on the wire: one JSON line, a reply wrapped in an envelope that names
//! the daemon's version (M7.9.8): `{"version": "0.2.0", "ok": …}` or
//! `{"version": "0.2.0", "error": {"message": …, "reasons": […]}}`. The version is read before
//! the rest, so a client can name both versions when it can't read a reply.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The version of this build: the workspace's, which every crate and binary takes
/// (docs/conventions.md#versions-and-the-changelog).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The first version whose replies name it: a reply without one is from a daemon before it.
pub const FIRST_NAMED_VERSION: &str = "0.2.0";

/// The longest version a reply may name.
const MAX_VERSION: usize = 32;

/// Whether `text` is a version as Writ writes one: `MAJOR.MINOR.PATCH`, each part digits with
/// no leading zero, at most [`MAX_VERSION`] bytes in all.
pub fn is_version(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    text.len() <= MAX_VERSION
        && parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (*part == "0" || !part.starts_with('0'))
        })
}

/// A failed command: a message, and every reason when there are several (a ticket that fits
/// no template).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

impl ApiError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            reasons: Vec::new(),
        }
    }

    pub fn with_reasons(message: impl Into<String>, reasons: Vec<String>) -> Self {
        Self {
            message: message.into(),
            reasons,
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)?;
        for reason in &self.reasons {
            write!(f, "\n  - {reason}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Envelope<T> {
    Ok(T),
    Error(ApiError),
}

/// The envelope as it is written: this build's version first, then `ok` or `error`.
#[derive(Serialize)]
struct Versioned<E> {
    version: &'static str,
    #[serde(flatten)]
    envelope: E,
}

/// Encodes a reply (one JSON line), naming this build's version.
pub fn encode_reply<T: Serialize>(reply: &Result<T, ApiError>) -> Vec<u8> {
    let envelope = match reply {
        Ok(value) => serde_json::to_vec(&Versioned {
            version: VERSION,
            envelope: Envelope::Ok(value),
        }),
        Err(error) => serde_json::to_vec(&Versioned {
            version: VERSION,
            envelope: Envelope::<()>::Error(error.clone()),
        }),
    };
    let mut bytes = envelope.unwrap_or_else(|_| {
        format!(
            r#"{{"version":"{VERSION}","error":{{"message":"the daemon could not encode its reply"}}}}"#
        )
        .into_bytes()
    });
    bytes.push(b'\n');
    bytes
}

/// A reply as read: the version the daemon named (`None` for a daemon before
/// [`FIRST_NAMED_VERSION`], or when the reply isn't even a JSON object), and what it said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply<T> {
    pub version: Option<String>,
    /// Whether the reply could be read: when it couldn't, `result`'s error already names
    /// both versions.
    pub readable: bool,
    pub result: Result<T, ApiError>,
}

/// Decodes a reply. An unreadable reply is an error too, naming both versions when the
/// daemon's isn't this build's.
pub fn decode_reply<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    decode_versioned(bytes).result
}

/// Decodes a reply and the version it names. A version that isn't one makes the reply
/// unreadable; every other field is read as strictly as before.
pub fn decode_versioned<T: DeserializeOwned>(bytes: &[u8]) -> Reply<T> {
    let mut object =
        match serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(bytes) {
            Ok(object) => object,
            Err(e) => {
                return Reply {
                    version: None,
                    readable: false,
                    result: Err(ApiError::new(format!(
                        "unreadable reply from the daemon: {e}"
                    ))),
                };
            }
        };
    let version = match object.remove("version") {
        None => None,
        Some(serde_json::Value::String(text)) if is_version(&text) => Some(text),
        Some(_) => {
            return Reply {
                version: None,
                readable: false,
                result: Err(ApiError::new(
                    "unreadable reply from the daemon: its version is not MAJOR.MINOR.PATCH",
                )),
            };
        }
    };
    let (readable, result) =
        match serde_json::from_value::<Envelope<T>>(serde_json::Value::Object(object)) {
            Ok(Envelope::Ok(value)) => (true, Ok(value)),
            Ok(Envelope::Error(error)) => (true, Err(error)),
            Err(e) => (
                false,
                Err(ApiError::new(unreadable(version.as_deref(), &e))),
            ),
        };
    Reply {
        version,
        readable,
        result,
    }
}

/// Why a reply couldn't be read: as before when the daemon is this build's version, with
/// both versions named when it isn't.
fn unreadable(theirs: Option<&str>, error: &serde_json::Error) -> String {
    match theirs {
        Some(theirs) if theirs == VERSION => format!("unreadable reply from the daemon: {error}"),
        Some(theirs) => format!(
            "unreadable reply from writd {theirs}, and this writ is {VERSION}: install the same \
             version of both (the changelog's Upgrading): {error}"
        ),
        None => format!(
            "unreadable reply from a daemon that names no version (a writd before \
             {FIRST_NAMED_VERSION}), and this writ is {VERSION}: install the same version of both \
             (the changelog's Upgrading): {error}"
        ),
    }
}

/// Decodes a request body.
pub fn decode_body<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(bytes).map_err(|e| ApiError::new(format!("unreadable request: {e}")))
}

/// Encodes a request body.
pub fn encode_body<T: Serialize>(body: &T) -> Result<Vec<u8>, ApiError> {
    serde_json::to_vec(body).map_err(|e| ApiError::new(format!("can't encode the request: {e}")))
}
