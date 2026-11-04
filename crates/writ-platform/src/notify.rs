//! Tells me something happened, never an approval channel: the [`Notifier`] interface, the
//! [`Notification`] it delivers, and [`Notifiers`], a list of notifiers.
//!
//! The service sends no agent-written text (a ticket's id, template and revision, never its
//! title). A notifier treats what it gets as untrusted all the same: sent neutralized
//! ([`Notification::neutralized`]), and only ever in a body, never in headers or URLs.
//!
//! Portable implementation: [`telegram::TelegramNotifier`], plain-text messages from a
//! Telegram bot.

pub mod telegram;

use std::sync::Arc;

use writ_core::text::{self, Newlines};

use crate::Result;

/// Longest title sent, in characters.
pub const MAX_TITLE_CHARS: usize = 200;
/// Longest message sent, in characters.
pub const MAX_MESSAGE_CHARS: usize = 2000;
/// Longest tag sent, in characters.
const MAX_TAG_CHARS: usize = 64;

/// How loudly to notify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Priority {
    Low,
    #[default]
    Default,
    High,
}

/// One notification. The service writes none of the agent's text in it; implementations
/// neutralize control characters before sending all the same.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Notification {
    pub title: String,
    pub message: String,
    pub priority: Priority,
    /// Short labels, written by the daemon. Sinks without labels (Telegram) ignore them.
    pub tags: Vec<String>,
}

/// Tells me something happened. A notification is never an approval.
pub trait Notifier: Send + Sync {
    /// Delivers one notification. Blocking: async callers run it on a blocking thread.
    fn notify(&self, notification: &Notification) -> Result<()>;
}

impl Notification {
    /// The notification as it may be sent: every hidden character
    /// ([`writ_core::text::is_hidden_char`]) removed (the message keeps `\n`), the title
    /// capped at [`MAX_TITLE_CHARS`] and the message at [`MAX_MESSAGE_CHARS`]. Tags get the
    /// same treatment as the title, capped at 64 characters, and empty ones are dropped.
    pub fn neutralized(&self) -> Notification {
        Notification {
            title: text::strip(&self.title, Newlines::Drop, MAX_TITLE_CHARS),
            message: text::strip(&self.message, Newlines::Keep, MAX_MESSAGE_CHARS),
            priority: self.priority,
            tags: self
                .tags
                .iter()
                .map(|tag| text::strip(tag, Newlines::Drop, MAX_TAG_CHARS))
                .filter(|tag| !tag.is_empty())
                .collect(),
        }
    }
}

/// Delivers to every notifier in the list, even when an earlier one fails, and returns the
/// first error. An empty list delivers nothing and succeeds.
#[derive(Clone, Default)]
pub struct Notifiers(pub Vec<Arc<dyn Notifier>>);

impl std::fmt::Debug for Notifiers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Notifiers({} notifiers)", self.0.len())
    }
}

impl Notifier for Notifiers {
    fn notify(&self, notification: &Notification) -> Result<()> {
        let mut first_error = None;
        for notifier in &self.0 {
            if let Err(e) = notifier.notify(notification) {
                first_error.get_or_insert(e);
            }
        }
        match first_error {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }
}
