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

/// Parses YAML into `T`, reporting the path of the failing field.
pub fn parse_yaml<T: DeserializeOwned>(text: &str) -> Result<T, FieldError> {
    let mut failed_at: Option<String> = None;
    let result = serde_saphyr::with_deserializer_from_str(text, |de| {
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
