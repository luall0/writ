//! Replies and bodies on the wire: one JSON line, a reply wrapped in an envelope
//! (`{"ok": …}` or `{"error": {"message": …, "reasons": […]}}`).

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

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

/// Encodes a reply (one JSON line).
pub fn encode_reply<T: Serialize>(reply: &Result<T, ApiError>) -> Vec<u8> {
    let envelope = match reply {
        Ok(value) => serde_json::to_vec(&Envelope::Ok(value)),
        Err(error) => serde_json::to_vec(&Envelope::<()>::Error(error.clone())),
    };
    let mut bytes = envelope.unwrap_or_else(|_| {
        br#"{"error":{"message":"the daemon could not encode its reply"}}"#.to_vec()
    });
    bytes.push(b'\n');
    bytes
}

/// Decodes a reply. An unreadable reply is an error too.
pub fn decode_reply<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    match serde_json::from_slice::<Envelope<T>>(bytes) {
        Ok(Envelope::Ok(value)) => Ok(value),
        Ok(Envelope::Error(error)) => Err(error),
        Err(e) => Err(ApiError::new(format!(
            "unreadable reply from the daemon: {e}"
        ))),
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
