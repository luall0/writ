//! The commands: an SSH exec line (`writ approve <id>`) or, for the approval API, an HTTPS
//! route (`POST /v1/tickets/<id>/approve`).

use writ_core::authority::AdminTarget;
use writ_core::names::{KeyId, TicketId};

/// A command run over the daemon's SSH protocol (the exec line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `writ request`: submit the ticket file on stdin; the connection's key is the session
    /// key. Reply: [`Submitted`].
    Request,
    /// `writ wait <id>`: wait until the ticket is decided. Reply: [`Decision`].
    Wait { id: TicketId },
    /// `writ close <lease>`: end the lease with a summary ([`CloseRequest`] on stdin), the
    /// connection's key being its session key. Reply: [`Report`].
    Close { id: TicketId },
    /// `writ info`: how this daemon takes decisions. Reply: [`Info`].
    Info,
    /// `writ ls [--all]`: pending tickets and active leases, or every ticket. Reply: [`Listing`].
    List { all: bool },
    /// `writ show <id>`: a ticket's canonical bytes and the revision it follows. Reply: [`Shown`].
    Show { id: TicketId },
    /// `writ report <lease>`: a lease's activity report. Reply: [`Report`].
    Report { id: TicketId },
    /// `writ approve <id>`: an approval ([`ApproveRequest`] on stdin). Reply: [`Ack`].
    Approve { id: TicketId },
    /// `writ refuse <id>`: a refusal ([`RefuseRequest`] on stdin). Reply: [`Ack`].
    Refuse { id: TicketId },
    /// `writ revoke <id>`: revoke a lease or withdraw a pending ticket ([`RevokeRequest`] on
    /// stdin). Reply: [`Ack`].
    Revoke { id: TicketId },
    /// `writ prove`: an agent signing key signs a remote's message, with an approver's
    /// signature over the `writ-proof/1` document ([`ProveRequest`] on stdin). Reply:
    /// [`Proved`].
    Prove,
    /// `writ unseal`: the keystore's passphrase and an approver's signature over this boot's
    /// `writ-unseal/1` document ([`UnsealRequest`] on stdin). Reply: [`Unsealed`]. The only
    /// command, with `info`, a sealed daemon answers.
    Unseal,
    /// `writ admin show <target>`: the version in force of the policy, `approvers` or
    /// `readers`. Reply: [`AdminShown`].
    AdminShow { target: AdminTarget },
    /// `writ admin apply`: an approver's signed `writ-admin/2` change ([`AdminRequest`] on
    /// stdin). Reply: [`AdminApplied`].
    AdminApply,
    /// `writ admin token <id>`, first step: the token file in force for the credential `id`
    /// (its digest, never the token). Reply: [`TokenShown`].
    TokenShow { id: KeyId },
    /// `writ admin token <id>`: an approver's signed `writ-token/2` ([`TokenRequest`] on
    /// stdin). Reply: [`TokenApplied`].
    TokenApply,
}

impl Command {
    /// Parses an exec line. Anything else is `None`.
    pub fn parse(line: &str) -> Option<Self> {
        let mut words = line.split(' ');
        if words.next()? != "writ" {
            return None;
        }
        let verb = words.next()?;
        if verb == "admin" {
            let what = words.next()?;
            let arg = words.next();
            if what == "token" {
                let third = words.next();
                if words.next().is_some() {
                    return None;
                }
                return match (arg?, third) {
                    ("show", Some(id)) => Some(Self::TokenShow {
                        id: id.parse().ok()?,
                    }),
                    ("apply", None) => Some(Self::TokenApply),
                    _ => None,
                };
            }
            if words.next().is_some() {
                return None;
            }
            return match (what, arg) {
                ("show", Some(target)) => Some(Self::AdminShow {
                    target: target.parse().ok()?,
                }),
                ("apply", None) => Some(Self::AdminApply),
                _ => None,
            };
        }
        let arg = words.next();
        if words.next().is_some() {
            return None;
        }
        let id = || arg?.parse::<TicketId>().ok();
        match (verb, arg) {
            ("request", None) => Some(Self::Request),
            ("wait", Some(_)) => Some(Self::Wait { id: id()? }),
            ("close", Some(_)) => Some(Self::Close { id: id()? }),
            ("report", Some(_)) => Some(Self::Report { id: id()? }),
            ("info", None) => Some(Self::Info),
            ("ls", None) => Some(Self::List { all: false }),
            ("ls", Some("--all")) => Some(Self::List { all: true }),
            ("show", Some(_)) => Some(Self::Show { id: id()? }),
            ("approve", Some(_)) => Some(Self::Approve { id: id()? }),
            ("refuse", Some(_)) => Some(Self::Refuse { id: id()? }),
            ("revoke", Some(_)) => Some(Self::Revoke { id: id()? }),
            ("prove", None) => Some(Self::Prove),
            ("unseal", None) => Some(Self::Unseal),
            _ => None,
        }
    }

    /// The exec line.
    pub fn line(&self) -> String {
        match self {
            Self::Request => "writ request".to_owned(),
            Self::Wait { id } => format!("writ wait {id}"),
            Self::Close { id } => format!("writ close {id}"),
            Self::Report { id } => format!("writ report {id}"),
            Self::Info => "writ info".to_owned(),
            Self::List { all: false } => "writ ls".to_owned(),
            Self::List { all: true } => "writ ls --all".to_owned(),
            Self::Show { id } => format!("writ show {id}"),
            Self::Approve { id } => format!("writ approve {id}"),
            Self::Refuse { id } => format!("writ refuse {id}"),
            Self::Revoke { id } => format!("writ revoke {id}"),
            Self::Prove => "writ prove".to_owned(),
            Self::Unseal => "writ unseal".to_owned(),
            Self::AdminShow { target } => format!("writ admin show {target}"),
            Self::AdminApply => "writ admin apply".to_owned(),
            Self::TokenShow { id } => format!("writ admin token show {id}"),
            Self::TokenApply => "writ admin token apply".to_owned(),
        }
    }

    /// Whether this command is served on the approval listener (the others on the agents').
    pub fn is_approval(&self) -> bool {
        !matches!(self, Self::Request | Self::Wait { .. } | Self::Close { .. })
    }

    /// The HTTPS route of an approval command: method and path (with its query). Agent
    /// commands have none: they only exist over SSH.
    ///
    /// | Command | Route |
    /// |---|---|
    /// | info | `GET /v1/info` |
    /// | ls, ls --all | `GET /v1/tickets`, `GET /v1/tickets?all=true` |
    /// | show | `GET /v1/tickets/<id>` |
    /// | report | `GET /v1/tickets/<id>/report` |
    /// | approve, refuse, revoke | `POST /v1/tickets/<id>/approve` (`refuse`, `revoke`) |
    /// | prove | `POST /v1/proofs` |
    /// | unseal | `POST /v1/unseal` |
    /// | admin show, admin apply | `GET /v1/admin/<target>`, `POST /v1/admin` |
    /// | admin token (show, apply) | `GET /v1/tokens/<id>`, `POST /v1/tokens` |
    pub fn http_route(&self) -> Option<(&'static str, String)> {
        match self {
            Self::Request | Self::Wait { .. } | Self::Close { .. } => None,
            Self::Info => Some(("GET", "/v1/info".to_owned())),
            Self::List { all: false } => Some(("GET", "/v1/tickets".to_owned())),
            Self::List { all: true } => Some(("GET", "/v1/tickets?all=true".to_owned())),
            Self::Show { id } => Some(("GET", format!("/v1/tickets/{id}"))),
            Self::Report { id } => Some(("GET", format!("/v1/tickets/{id}/report"))),
            Self::Approve { id } => Some(("POST", format!("/v1/tickets/{id}/approve"))),
            Self::Refuse { id } => Some(("POST", format!("/v1/tickets/{id}/refuse"))),
            Self::Revoke { id } => Some(("POST", format!("/v1/tickets/{id}/revoke"))),
            Self::Prove => Some(("POST", "/v1/proofs".to_owned())),
            Self::Unseal => Some(("POST", "/v1/unseal".to_owned())),
            Self::AdminShow { target } => Some(("GET", format!("/v1/admin/{target}"))),
            Self::AdminApply => Some(("POST", "/v1/admin".to_owned())),
            Self::TokenShow { id } => Some(("GET", format!("/v1/tokens/{id}"))),
            Self::TokenApply => Some(("POST", "/v1/tokens".to_owned())),
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
            ("GET", ["tickets", t, "report"], None) => Self::Report { id: id(t)? },
            ("POST", ["tickets", t, "approve"], None) => Self::Approve { id: id(t)? },
            ("POST", ["tickets", t, "refuse"], None) => Self::Refuse { id: id(t)? },
            ("POST", ["tickets", t, "revoke"], None) => Self::Revoke { id: id(t)? },
            ("POST", ["proofs"], None) => Self::Prove,
            ("POST", ["unseal"], None) => Self::Unseal,
            ("GET", ["admin", target], None) => Self::AdminShow {
                target: target.parse().ok()?,
            },
            ("POST", ["admin"], None) => Self::AdminApply,
            ("GET", ["tokens", id], None) => Self::TokenShow {
                id: id.parse().ok()?,
            },
            ("POST", ["tokens"], None) => Self::TokenApply,
            _ => return None,
        };
        Some(command)
    }
}
