//! `recipients.<name>` (M7.6): what the daemon's keystore is wrapped to besides its own
//! identity. A **hardware** recipient (`backend: se-cryptokit`), a key-agreement key the
//! daemon makes in its device when the change that declares it applies, which alone can unwrap
//! what is wrapped to it; and the **recovery** recipient (`recipient: age1…`), an age X25519
//! key kept offline, which opens every secret when the hardware is gone. Only the form is
//! checked here: the daemon refuses a backend it doesn't have.
//!
//! A keystore with a hardware recipient unseals with it and no passphrase; one without unseals
//! with its passphrase. The recovery recipient is required beside a hardware one, optional
//! otherwise; there is at most one.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;

use super::FieldError;
use super::keys::BackendName;
use crate::names::KeyId;

/// The most recipients the policy declares.
pub const MAX_RECIPIENTS: usize = 8;

/// An age X25519 recipient (`age1…`, bech32 over 32 bytes), read strictly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecoveryRecipient(String);

/// bech32's alphabet, after the separator.
const BECH32: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

impl RecoveryRecipient {
    /// `age1` and 58 characters of bech32's alphabet, lower case: 32 bytes and a checksum. The
    /// checksum is age's to check (`writd` reads it with age before any secret is wrapped to
    /// it); its form is checked here.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let Some(data) = text.strip_prefix("age1") else {
            return Err("an age X25519 recipient starts with age1 (age-keygen, writ recovery new)");
        };
        if data.len() != 58 {
            return Err("an age X25519 recipient is age1 and 58 characters");
        }
        if !data.chars().all(|c| BECH32.contains(c)) {
            return Err("an age X25519 recipient is lower-case bech32");
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RecoveryRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One recipient of the keystore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    /// A key-agreement key in the device `backend`, made by the daemon.
    Hardware { backend: BackendName },
    /// The offline recovery key.
    Recovery { recipient: RecoveryRecipient },
}

impl Recipient {
    pub fn is_hardware(&self) -> bool {
        matches!(self, Recipient::Hardware { .. })
    }
}

/// A recipient as written: exactly one of its two fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRecipient {
    #[serde(default)]
    backend: Option<BackendName>,
    #[serde(default)]
    recipient: Option<String>,
}

impl RawRecipient {
    fn check(self, at: &str) -> Result<Recipient, FieldError> {
        match (self.backend, self.recipient) {
            (Some(backend), None) => {
                if backend.is_default() {
                    return Err(FieldError::at(
                        format!("{at}.backend"),
                        "a recipient is a hardware device's key (se-cryptokit), never software: \
                         the keystore's own identity is the software one",
                    ));
                }
                Ok(Recipient::Hardware { backend })
            }
            (None, Some(text)) => RecoveryRecipient::parse(&text)
                .map(|recipient| Recipient::Recovery { recipient })
                .map_err(|why| FieldError::at(format!("{at}.recipient"), why)),
            (Some(_), Some(_)) => Err(FieldError::at(
                at,
                "a recipient is a hardware key (backend) or the recovery key (recipient), not both",
            )),
            (None, None) => Err(FieldError::at(
                at,
                "a recipient takes backend (a hardware key the daemon makes) or recipient (the \
                 recovery key, age1…)",
            )),
        }
    }
}

/// The recipients as written, checked together: at most [`MAX_RECIPIENTS`], at most one
/// recovery recipient, and the recovery recipient beside any hardware one.
pub(super) fn check(
    raw: BTreeMap<KeyId, RawRecipient>,
) -> Result<BTreeMap<KeyId, Recipient>, FieldError> {
    if raw.len() > MAX_RECIPIENTS {
        return Err(FieldError::at(
            "recipients",
            format!("at most {MAX_RECIPIENTS} recipients are declared"),
        ));
    }
    let mut recipients = BTreeMap::new();
    for (name, entry) in raw {
        let recipient = entry.check(&format!("recipients.{name}"))?;
        recipients.insert(name, recipient);
    }
    let recovery = recipients
        .values()
        .filter(|r| matches!(r, Recipient::Recovery { .. }))
        .count();
    if recovery > 1 {
        return Err(FieldError::at(
            "recipients",
            "at most one recovery recipient (recipient: age1…) is declared",
        ));
    }
    if recovery == 0 && recipients.values().any(Recipient::is_hardware) {
        return Err(FieldError::at(
            "recipients",
            "a hardware recipient needs the recovery recipient beside it (recipient: age1…, \
             from writ recovery new): one lost device must not lose every secret",
        ));
    }
    Ok(recipients)
}
