//! Messages between clients and the daemon.
//!
//! Everything travels over the daemon's SSH protocol ([Q16](../../docs/decisions.md)): a
//! client opens a session channel, runs one command (an SSH exec request), writes a body on
//! stdin, and reads one JSON reply on stdout. The exit status is 0 when the command did what
//! was asked, 1 otherwise; on failure the daemon also writes `writ: <reason>` on stderr, for
//! people using plain `ssh`.
//!
//! | Listener | Authenticated as | Commands |
//! |---|---|---|
//! | agents | a session certificate | git, `writ-sign git` (gateway) |
//! | agents | a plain session key | [`Command::Request`], [`Command::Wait`] |
//! | approvals | any key | [`Command::Info`], [`Command::List`], [`Command::Show`], [`Command::Approve`], [`Command::Refuse`], [`Command::Revoke`] |
//!
//! Replies are wrapped in an envelope, `{"ok": …}` or `{"error": {"message": …, "reasons": […]}}`
//! ([`encode_reply`], [`decode_reply`]). Tickets travel as their canonical bytes in a string,
//! so a client can decode them strictly (`Ticket::from_canonical`) and sign exactly them.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use writ_core::lease::State;
use writ_core::names::{RepoName, TemplateName, TicketId};
use writ_core::units::Timestamp;

/// The largest body a command reads on stdin (a ticket file, an approval).
pub const MAX_BODY: usize = 256 * 1024;

/// A command run over the daemon's SSH protocol (the exec line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `writ request`: submit the ticket file on stdin; the connection's key is the session
    /// key. Reply: [`Submitted`].
    Request,
    /// `writ wait <id>`: wait until the ticket is decided. Reply: [`Decision`].
    Wait { id: TicketId },
    /// `writ info`: how this daemon takes decisions. Reply: [`Info`].
    Info,
    /// `writ ls [--all]`: pending tickets and active leases, or every ticket. Reply: [`Listing`].
    List { all: bool },
    /// `writ show <id>`: a ticket's canonical bytes and the revision it follows. Reply: [`Shown`].
    Show { id: TicketId },
    /// `writ approve <id>`: an approval ([`ApproveRequest`] on stdin). Reply: [`Ack`].
    Approve { id: TicketId },
    /// `writ refuse <id>`: a refusal ([`RefuseRequest`] on stdin). Reply: [`Ack`].
    Refuse { id: TicketId },
    /// `writ revoke <id>`: revoke a lease or withdraw a pending ticket ([`RevokeRequest`] on
    /// stdin). Reply: [`Ack`].
    Revoke { id: TicketId },
}

impl Command {
    /// Parses an exec line. Anything else is `None`.
    pub fn parse(line: &str) -> Option<Self> {
        let mut words = line.split(' ');
        if words.next()? != "writ" {
            return None;
        }
        let verb = words.next()?;
        let arg = words.next();
        if words.next().is_some() {
            return None;
        }
        let id = || arg?.parse::<TicketId>().ok();
        match (verb, arg) {
            ("request", None) => Some(Self::Request),
            ("wait", Some(_)) => Some(Self::Wait { id: id()? }),
            ("info", None) => Some(Self::Info),
            ("ls", None) => Some(Self::List { all: false }),
            ("ls", Some("--all")) => Some(Self::List { all: true }),
            ("show", Some(_)) => Some(Self::Show { id: id()? }),
            ("approve", Some(_)) => Some(Self::Approve { id: id()? }),
            ("refuse", Some(_)) => Some(Self::Refuse { id: id()? }),
            ("revoke", Some(_)) => Some(Self::Revoke { id: id()? }),
            _ => None,
        }
    }

    /// The exec line.
    pub fn line(&self) -> String {
        match self {
            Self::Request => "writ request".to_owned(),
            Self::Wait { id } => format!("writ wait {id}"),
            Self::Info => "writ info".to_owned(),
            Self::List { all: false } => "writ ls".to_owned(),
            Self::List { all: true } => "writ ls --all".to_owned(),
            Self::Show { id } => format!("writ show {id}"),
            Self::Approve { id } => format!("writ approve {id}"),
            Self::Refuse { id } => format!("writ refuse {id}"),
            Self::Revoke { id } => format!("writ revoke {id}"),
        }
    }

    /// Whether this command is served on the approval listener (the others on the agents').
    pub fn is_approval(&self) -> bool {
        !matches!(self, Self::Request | Self::Wait { .. })
    }

    /// The HTTPS route of an approval command: method and path (with its query). Agent
    /// commands have none: they only exist over SSH.
    ///
    /// | Command | Route |
    /// |---|---|
    /// | info | `GET /v1/info` |
    /// | ls, ls --all | `GET /v1/tickets`, `GET /v1/tickets?all=true` |
    /// | show | `GET /v1/tickets/<id>` |
    /// | approve, refuse, revoke | `POST /v1/tickets/<id>/approve` (`refuse`, `revoke`) |
    pub fn http_route(&self) -> Option<(&'static str, String)> {
        match self {
            Self::Request | Self::Wait { .. } => None,
            Self::Info => Some(("GET", "/v1/info".to_owned())),
            Self::List { all: false } => Some(("GET", "/v1/tickets".to_owned())),
            Self::List { all: true } => Some(("GET", "/v1/tickets?all=true".to_owned())),
            Self::Show { id } => Some(("GET", format!("/v1/tickets/{id}"))),
            Self::Approve { id } => Some(("POST", format!("/v1/tickets/{id}/approve"))),
            Self::Refuse { id } => Some(("POST", format!("/v1/tickets/{id}/refuse"))),
            Self::Revoke { id } => Some(("POST", format!("/v1/tickets/{id}/revoke"))),
        }
    }

    /// Parses an HTTPS request line (method, path with its query) into an approval command.
    /// Anything else, an unknown query parameter included, is `None`.
    pub fn from_http(method: &str, path_and_query: &str) -> Option<Self> {
        let (path, query) = match path_and_query.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (path_and_query, None),
        };
        let parts: Vec<&str> = path.strip_prefix("/v1/")?.split('/').collect();
        let id = |text: &str| text.parse::<TicketId>().ok();
        let command = match (method, parts.as_slice(), query) {
            ("GET", ["info"], None) => Self::Info,
            ("GET", ["tickets"], None) => Self::List { all: false },
            ("GET", ["tickets"], Some("all=true")) => Self::List { all: true },
            ("GET", ["tickets", t], None) => Self::Show { id: id(t)? },
            ("POST", ["tickets", t, "approve"], None) => Self::Approve { id: id(t)? },
            ("POST", ["tickets", t, "refuse"], None) => Self::Refuse { id: id(t)? },
            ("POST", ["tickets", t, "revoke"], None) => Self::Revoke { id: id(t)? },
            _ => return None,
        };
        Some(command)
    }
}

/// A failed command: a message, and every reason when there are several (a ticket that fits
/// no template).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Reply to [`Command::Request`]: the ticket is waiting for the approver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submitted {
    pub id: TicketId,
    /// The complete ticket the daemon built, as canonical bytes.
    pub canonical: String,
}

/// Reply to [`Command::Wait`]: how the ticket was decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", deny_unknown_fields)]
pub enum Decision {
    /// Signed: the lease (canonical bytes of the terms in force, narrowed if I narrowed them)
    /// and the session certificate (OpenSSH text).
    Active { lease: String, certificate: String },
    /// A signed amendment, now the terms of its lease (the certificate doesn't change).
    Applied { lease: String },
    /// Refused, with the approver's feedback.
    Refused { feedback: String },
    /// Not signed before `expires_at`.
    Expired,
    /// Withdrawn, or the lease was revoked before the wait.
    Revoked,
    /// The lease ended another way (closed, exhausted) before the wait.
    Ended { state: State },
}

/// Reply to [`Command::Info`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub decisions: Decisions,
}

/// Whether refusals and revocations need an approver signature (`writd.yaml`: `decisions`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decisions {
    /// An SSHSIG over a `writ-refusal/1` or `writ-revocation/1` document is required.
    #[default]
    Signed,
    /// Anyone who reaches the approval listener may refuse or revoke.
    Open,
}

/// Reply to [`Command::List`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listing {
    pub tickets: Vec<Summary>,
}

/// One line of `writ ls`. The title is agent-written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub id: TicketId,
    /// The lease it belongs to (itself, or the lease an amendment amends).
    pub lease: TicketId,
    pub state: State,
    pub template: TemplateName,
    pub revision: u32,
    pub repos: Vec<RepoName>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub title: String,
}

/// Reply to [`Command::Show`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shown {
    pub state: State,
    /// The ticket's canonical bytes (as submitted while pending, as signed once approved).
    pub canonical: String,
    /// What it follows: the refused ticket it revises, or the lease terms it amends.
    pub previous: Option<Previous>,
}

/// The ticket a revision or an amendment follows, for the diff `writ sign` shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Previous {
    pub relation: Relation,
    pub canonical: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    /// The refused ticket this one revises.
    Revises,
    /// The terms in force of the lease this one amends.
    Amends,
}

/// Body of [`Command::Approve`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    /// The canonical bytes signed: the submitted ticket, or a narrowing of it.
    pub signed: String,
    /// The armored SSHSIG over them, namespace `writ-approval`.
    pub signature: String,
}

/// Body of [`Command::Refuse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefuseRequest {
    pub feedback: String,
    /// With `decisions: signed`: an SSHSIG over the `writ-refusal/1` document.
    #[serde(default)]
    pub signature: Option<String>,
}

/// Body of [`Command::Revoke`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    /// With `decisions: signed`: an SSHSIG over the `writ-revocation/1` document.
    #[serde(default)]
    pub signature: Option<String>,
}

/// Reply to approve, refuse and revoke: where the ticket (or lease) now stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub id: TicketId,
    pub state: State,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lines_round_trip() {
        let id = TicketId::from_parts(1_800_000_000_000, [7; 10]);
        for command in [
            Command::Request,
            Command::Wait { id: id.clone() },
            Command::Info,
            Command::List { all: false },
            Command::List { all: true },
            Command::Show { id: id.clone() },
            Command::Approve { id: id.clone() },
            Command::Refuse { id: id.clone() },
            Command::Revoke { id },
        ] {
            assert_eq!(Command::parse(&command.line()), Some(command));
        }
        for line in [
            "",
            "writ",
            "writ request now",
            "writ wait",
            "writ wait wrt_nope",
            "writ ls -a",
            "writ ls --all extra",
            "writ  ls",
            "writ sign wrt_01JD8X0000000000000000000",
            "git-upload-pack 'x'",
        ] {
            assert_eq!(Command::parse(line), None, "{line:?}");
        }
    }

    #[test]
    fn http_routes_round_trip_and_agent_commands_have_none() {
        let id = TicketId::from_parts(1_800_000_000_000, [7; 10]);
        for command in [
            Command::Info,
            Command::List { all: false },
            Command::List { all: true },
            Command::Show { id: id.clone() },
            Command::Approve { id: id.clone() },
            Command::Refuse { id: id.clone() },
            Command::Revoke { id: id.clone() },
        ] {
            let (method, path) = command.http_route().unwrap();
            assert_eq!(Command::from_http(method, &path), Some(command));
        }
        assert_eq!(Command::Request.http_route(), None);
        assert_eq!(Command::Wait { id: id.clone() }.http_route(), None);
        for (method, path) in [
            ("POST", "/v1/info"),
            ("GET", "/v1/tickets?all=1"),
            ("GET", "/v1/tickets?all=true&x=1"),
            ("GET", "/v1/tickets/wrt_nope"),
            ("GET", &format!("/v1/tickets/{id}/approve")),
            ("POST", &format!("/v1/tickets/{id}/sign")),
            ("POST", "/v1/request"),
            ("GET", "/v2/info"),
            ("GET", "/v1/info/"),
            ("GET", "v1/info"),
        ] {
            assert_eq!(Command::from_http(method, path), None, "{method} {path}");
        }
    }

    #[test]
    fn replies_round_trip_and_errors_are_typed() {
        let ok: Result<Info, ApiError> = Ok(Info {
            decisions: Decisions::Open,
        });
        let bytes = encode_reply(&ok);
        assert_eq!(bytes, b"{\"ok\":{\"decisions\":\"open\"}}\n");
        assert_eq!(decode_reply::<Info>(&bytes), ok);

        let err: Result<Info, ApiError> = Err(ApiError::with_reasons("rejected", vec!["a".into()]));
        assert_eq!(decode_reply::<Info>(&encode_reply(&err)), err);
        assert!(decode_reply::<Info>(b"not json").is_err());
        assert!(decode_reply::<Info>(br#"{"ok":{"decisions":"open"},"x":1}"#).is_err());

        let decision = Decision::Refused {
            feedback: "no".into(),
        };
        let bytes = encode_reply(&Ok::<_, ApiError>(decision.clone()));
        assert_eq!(
            bytes,
            b"{\"ok\":{\"status\":\"refused\",\"feedback\":\"no\"}}\n"
        );
        assert_eq!(decode_reply::<Decision>(&bytes), Ok(decision));
    }
}
