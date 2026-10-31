//! Tells me something happened. Never an approval channel.
//!
//! [`TelegramNotifier`] sends plain-text messages from a Telegram bot; [`Notifiers`] delivers
//! to a list of notifiers. Titles and messages may carry agent-written text: they are
//! neutralized ([`Notification::neutralized`]) before they leave the daemon, and only ever
//! travel in a JSON body, never in HTTP headers or URLs.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::{PlatformError, Result};

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

/// One notification. `title` and `message` may contain agent-written text (a ticket title):
/// implementations neutralize control characters before sending.
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
    /// The notification as it may be sent: control characters removed (the message keeps
    /// `\n`), bidi overrides and isolates and zero-width or invisible format characters
    /// removed, the title capped at [`MAX_TITLE_CHARS`] and the message at
    /// [`MAX_MESSAGE_CHARS`]. Tags get the same treatment as the title, capped at 64
    /// characters, and empty ones are dropped.
    pub fn neutralized(&self) -> Notification {
        Notification {
            title: neutralize(&self.title, false, MAX_TITLE_CHARS),
            message: neutralize(&self.message, true, MAX_MESSAGE_CHARS),
            priority: self.priority,
            tags: self
                .tags
                .iter()
                .map(|tag| neutralize(tag, false, MAX_TAG_CHARS))
                .filter(|tag| !tag.is_empty())
                .collect(),
        }
    }
}

/// Whether `c` must never reach a notification: control characters, bidi controls and
/// invisible format characters that could hide or reorder text.
pub fn is_forbidden_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'                  // Arabic letter mark
            | '\u{180E}'                // Mongolian vowel separator
            | '\u{200B}'..='\u{200F}'   // zero-width spaces and joiners, LRM, RLM
            | '\u{2028}'..='\u{2029}'   // line and paragraph separators
            | '\u{202A}'..='\u{202E}'   // bidi embeddings and overrides
            | '\u{2060}'..='\u{2064}'   // word joiner and invisible operators
            | '\u{2066}'..='\u{2069}'   // bidi isolates
            | '\u{FEFF}' // zero-width no-break space (BOM)
        )
}

fn neutralize(text: &str, keep_newlines: bool, max_chars: usize) -> String {
    text.chars()
        .filter(|&c| (keep_newlines && c == '\n') || !is_forbidden_char(c))
        .take(max_chars)
        .collect()
}

/// A Telegram bot token. A secret: zeroized, never printed, never in an error or log.
pub struct BotToken(Zeroizing<String>);

/// Longest token accepted (real ones are under 50 characters).
const MAX_TOKEN_LEN: usize = 256;
/// Largest token file read.
const MAX_TOKEN_FILE_LEN: u64 = 4096;

impl BotToken {
    /// Checks the shape `<digits>:<at least 20 of [A-Za-z0-9_-]>`; a `Config` error otherwise
    /// (the error never contains the token).
    pub fn new(token: String) -> Result<Self> {
        let token = Zeroizing::new(token);
        let well_formed = token.len() <= MAX_TOKEN_LEN
            && match token.split_once(':') {
                Some((id, secret)) => {
                    !id.is_empty()
                        && id.bytes().all(|b| b.is_ascii_digit())
                        && secret.len() >= 20
                        && secret
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                }
                None => false,
            };
        if well_formed {
            Ok(Self(token))
        } else {
            Err(PlatformError::Config(
                "invalid Telegram bot token: expected <digits>:<at least 20 of A-Z a-z 0-9 _ ->"
                    .to_owned(),
            ))
        }
    }

    /// Reads a file holding only the token (surrounding whitespace trimmed). Refuses a file
    /// readable or writable by group or others (mode & 0o077 != 0) with a `Config` error
    /// naming the path.
    pub fn from_file(path: &Path) -> Result<Self> {
        let unreadable = |e: std::io::Error| {
            PlatformError::Config(format!(
                "cannot read the Telegram bot token file {}: {}",
                path.display(),
                e.kind()
            ))
        };
        let file = std::fs::File::open(path).map_err(unreadable)?;
        // Checked on the open file, so the file read is the one checked.
        let metadata = file.metadata().map_err(unreadable)?;
        check_private(path, &metadata)?;
        // Capacity above the read limit: the buffer never grows, so no copy is left behind.
        let mut contents = Zeroizing::new(Vec::with_capacity(MAX_TOKEN_FILE_LEN as usize + 64));
        file.take(MAX_TOKEN_FILE_LEN + 1)
            .read_to_end(&mut contents)
            .map_err(unreadable)?;
        if contents.len() as u64 > MAX_TOKEN_FILE_LEN {
            return Err(PlatformError::Config(format!(
                "{} is too large to hold a Telegram bot token",
                path.display()
            )));
        }
        let text = std::str::from_utf8(&contents).map_err(|_| {
            PlatformError::Config(format!(
                "{} does not hold a valid Telegram bot token",
                path.display()
            ))
        })?;
        Self::new(text.trim().to_owned()).map_err(|_| {
            PlatformError::Config(format!(
                "{} does not hold a valid Telegram bot token",
                path.display()
            ))
        })
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for BotToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BotToken(<redacted>)")
    }
}

#[cfg(unix)]
fn check_private(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(PlatformError::Config(format!(
            "{} is accessible by group or others (mode {:o}); make it 0600",
            path.display(),
            mode & 0o777
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path, _metadata: &std::fs::Metadata) -> Result<()> {
    Ok(())
}

/// Where a Telegram message goes: a numeric chat id or a public `@channel`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChatId {
    Number(i64),
    Channel(String),
}

impl ChatId {
    fn parse(chat_id: &str) -> Result<Self> {
        let invalid = || {
            PlatformError::Config(
                "invalid Telegram chat id: expected an integer or @channelname (5 to 32 of \
                 A-Z a-z 0-9 _)"
                    .to_owned(),
            )
        };
        if let Some(name) = chat_id.strip_prefix('@') {
            if (5..=32).contains(&name.len())
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Ok(Self::Channel(chat_id.to_owned()));
            }
            return Err(invalid());
        }
        let digits = chat_id.strip_prefix('-').unwrap_or(chat_id);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        chat_id.parse().map(Self::Number).map_err(|_| invalid())
    }

    fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Number(id) => serde_json::Value::from(*id),
            Self::Channel(name) => serde_json::Value::from(name.as_str()),
        }
    }
}

/// The official Bot API server.
pub const TELEGRAM_API_BASE: &str = "https://api.telegram.org";
/// Telegram's limit on a message's text, in UTF-16 code units (how Telegram counts).
pub const MAX_TELEGRAM_TEXT_UTF16: usize = 4096;
/// Longest error description from Telegram kept in an error, in characters.
const MAX_DESCRIPTION_CHARS: usize = 200;
/// Largest Bot API reply read.
const MAX_REPLY_LEN: u64 = 64 * 1024;
/// Total time allowed for one Bot API request (connect, send, response).
const TELEGRAM_TIMEOUT: Duration = Duration::from_secs(10);

/// Sends notifications as plain-text Telegram messages from a bot (`sendMessage`, no
/// `parse_mode`: agent text can't inject Markdown or HTML). Blocking, with a 10-second total
/// timeout and no redirects.
///
/// The bot token is part of the request path, so the request URL and ureq's error texts
/// (which can embed it) never appear in an error, `Debug` output or log.
pub struct TelegramNotifier {
    token: BotToken,
    chat_id: ChatId,
    /// `https://api.telegram.org`, no trailing slash.
    api_base: String,
    agent: ureq::Agent,
}

impl std::fmt::Debug for TelegramNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramNotifier")
            .field("api_base", &self.api_base)
            .field("chat_id", &self.chat_id)
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

impl TelegramNotifier {
    /// `chat_id`: an integer (possibly negative, e.g. a group) or `@channelname` (5–32 of
    /// `[A-Za-z0-9_]`). `Config` error otherwise.
    pub fn new(token: BotToken, chat_id: &str) -> Result<Self> {
        Self::with_api_base(token, chat_id, TELEGRAM_API_BASE)
    }

    /// Same, against another Bot API server (self-hosted, or a test server):
    /// `http(s)://host[:port]` with no path, query, fragment or credentials.
    pub fn with_api_base(token: BotToken, chat_id: &str, api_base: &str) -> Result<Self> {
        let chat_id = ChatId::parse(chat_id)?;
        let api_base = parse_api_base(api_base)?;
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(TELEGRAM_TIMEOUT))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        Ok(Self {
            token,
            chat_id,
            api_base,
            agent: ureq::Agent::new_with_config(config),
        })
    }

    /// The JSON body of `sendMessage` for `notification`.
    fn body(&self, notification: &Notification) -> String {
        serde_json::json!({
            "chat_id": self.chat_id.to_json(),
            "text": telegram_text(notification),
            "disable_web_page_preview": true,
            "disable_notification": notification.priority == Priority::Low,
        })
        .to_string()
    }

    /// An error description from Telegram, safe to put in an error.
    fn description(&self, reply: &str) -> Option<String> {
        let json: serde_json::Value = serde_json::from_str(reply).ok()?;
        let description = json.get("description")?.as_str()?;
        let description = description.replace(self.token.expose(), "<redacted>");
        Some(neutralize(&description, false, MAX_DESCRIPTION_CHARS))
    }
}

/// The message text: neutralized title, a blank line, neutralized message, capped at
/// Telegram's 4096 UTF-16 code units.
fn telegram_text(notification: &Notification) -> String {
    let n = notification.neutralized();
    let mut text = String::new();
    let mut units = 0;
    for c in n
        .title
        .chars()
        .chain("\n\n".chars())
        .chain(n.message.chars())
    {
        units += c.len_utf16();
        if units > MAX_TELEGRAM_TEXT_UTF16 {
            break;
        }
        text.push(c);
    }
    text
}

fn parse_api_base(api_base: &str) -> Result<String> {
    let invalid =
        |why: &str| PlatformError::Config(format!("invalid Telegram Bot API base URL: {why}"));
    let uri: ureq::http::Uri = api_base.parse().map_err(|_| invalid("not a URL"))?;
    let scheme = match uri.scheme_str() {
        Some("http") => "http",
        Some("https") => "https",
        _ => return Err(invalid("the scheme must be http or https")),
    };
    let authority = uri.authority().ok_or_else(|| invalid("no host"))?;
    if authority.as_str().contains('@') {
        return Err(invalid("credentials in the URL are not supported"));
    }
    if authority.host().is_empty() {
        return Err(invalid("no host"));
    }
    let base = format!("{scheme}://{}", authority.as_str());
    // Nothing after the authority (a single trailing slash is tolerated).
    if api_base != base && api_base != format!("{base}/") {
        return Err(invalid("no path, query or fragment allowed"));
    }
    Ok(base)
}

/// A short, URL-free word for a ureq error (its own text can embed the request URL, and so
/// the token).
fn transport_failure(error: &ureq::Error) -> String {
    match error {
        ureq::Error::Timeout(_) => "timed out".to_owned(),
        ureq::Error::Io(e) => e.kind().to_string(),
        ureq::Error::HostNotFound => "host not found".to_owned(),
        ureq::Error::ConnectionFailed => "connection failed".to_owned(),
        ureq::Error::Tls(_) => "TLS error".to_owned(),
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => {
            "redirect refused".to_owned()
        }
        ureq::Error::BadUri(_) => "invalid request URL".to_owned(),
        ureq::Error::Protocol(_) => "HTTP protocol error".to_owned(),
        ureq::Error::BodyExceedsLimit(_) => "reply too large".to_owned(),
        _ => "request failed".to_owned(),
    }
}

impl Notifier for TelegramNotifier {
    fn notify(&self, notification: &Notification) -> Result<()> {
        let body = self.body(notification);
        let url = Zeroizing::new(format!(
            "{}/bot{}/sendMessage",
            self.api_base,
            self.token.expose()
        ));
        let mut response = self
            .agent
            .post(url.as_str())
            .content_type("application/json")
            .send(body.as_bytes())
            .map_err(|e| {
                PlatformError::Notify(format!(
                    "cannot reach the Telegram Bot API at {}: {}",
                    self.api_base,
                    transport_failure(&e)
                ))
            })?;
        let status = response.status();
        let reply = response
            .body_mut()
            .with_config()
            .limit(MAX_REPLY_LEN)
            .read_to_string()
            .map_err(|e| {
                PlatformError::Notify(format!(
                    "cannot read the Telegram Bot API reply (HTTP {}): {}",
                    status.as_u16(),
                    transport_failure(&e)
                ))
            })?;
        let reason = |what: String| match self.description(&reply) {
            Some(description) => format!("{what}: {description}"),
            None => what,
        };
        if !status.is_success() {
            return Err(PlatformError::Notify(reason(format!(
                "the Telegram Bot API answered HTTP {}",
                status.as_u16()
            ))));
        }
        let ok = serde_json::from_str::<serde_json::Value>(&reply)
            .ok()
            .and_then(|json| json.get("ok").and_then(serde_json::Value::as_bool));
        match ok {
            Some(true) => Ok(()),
            Some(false) => Err(PlatformError::Notify(reason(
                "the Telegram Bot API refused the message".to_owned(),
            ))),
            None => Err(PlatformError::Notify(
                "the Telegram Bot API gave an unexpected reply".to_owned(),
            )),
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
