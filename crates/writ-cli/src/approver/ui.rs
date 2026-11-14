//! `writ sign --ui` (M7.8): `writ sign` for the approval popup (`writ-popup`), which shows what
//! this prints and sends back what was clicked. Everything a signature relies on stays here:
//! the connection and its pins, the ticket fetched and decoded strictly, the checks of
//! [`fetch_reviewed`](super::fetch_reviewed), the trusted display (the very text `writ sign
//! --full` prints), the signature through ssh-keygen. The app only shows text and buttons.
//!
//! The protocol is one JSON object per line each way. To the app (stdout), an [`Event`]: the
//! ticket to show with the others waiting behind it, the others when they change, a ticket
//! gone, what an answer did, nothing waiting. From the app (stdin), an [`Answer`] naming the
//! ticket shown: `sign`, `refuse` (with feedback, which may be empty) or `skip` (its window
//! closed: it stays waiting, and isn't shown again by this run). An answer that names another
//! ticket, isn't one, or is longer than [`MAX_ANSWER`] signs nothing and is said. The end of
//! the app's output ends this command.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use writ_core::authority::TextDigest;
use writ_core::lease::State;
use writ_core::names::TicketId;
use writ_core::ticket::Ticket;
use writ_proto::{Command, Summary, Watched};

use super::{Reviewed, Signer, approve, fetch_reviewed, now, refuse_with, render};
use crate::client::Approvals;
use crate::{Exit, Paths, display};

/// The longest line the app may send (an answer with its feedback).
pub const MAX_ANSWER: usize = 64 * 1024;

/// The feedback a refusal without any carries: the daemon takes no empty feedback, and the
/// agent should know none was given.
pub const NO_FEEDBACK: &str = "Declined in the approval popup, with no feedback.";

/// The longest wait between two tries to reach the daemon.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// What this sends the app, one per line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// The ticket to show: what kind it is, its title and the whole trusted display (both
    /// cleaned of control and hidden characters), the approval key that will sign, and the
    /// other tickets waiting behind it.
    Show {
        id: TicketId,
        kind: Kind,
        title: String,
        display: String,
        key: String,
        waiting: Vec<Waiting>,
    },
    /// The tickets waiting behind the one shown changed.
    Queue { waiting: Vec<Waiting> },
    /// The ticket shown stopped waiting (signed or refused elsewhere, withdrawn, expired): its
    /// window closes.
    Gone { id: TicketId },
    /// What an answer did.
    Done { id: TicketId, message: String },
    /// What failed: an answer that signed nothing, a ticket that can't be shown. Cleaned.
    Failed {
        id: Option<TicketId>,
        message: String,
    },
    /// Nothing waits any more.
    Idle,
    /// How the connection to the daemon goes (lost, reached again). Cleaned.
    Status { message: String },
}

/// What a ticket shown is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Ticket,
    Revision,
    Amendment,
    Renewal,
}

/// A ticket waiting behind the one shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Waiting {
    pub id: TicketId,
    /// Agent text, cleaned.
    pub title: String,
    /// The repositories it asks for.
    pub repos: Vec<String>,
    /// Put aside by a `skip`: not shown again by this run.
    pub skipped: bool,
}

/// What the app sends back, one per line.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "answer", rename_all = "snake_case", deny_unknown_fields)]
pub enum Answer {
    Sign {
        id: TicketId,
    },
    Refuse {
        id: TicketId,
        #[serde(default)]
        feedback: String,
    },
    Skip {
        id: TicketId,
    },
}

impl Answer {
    fn id(&self) -> &TicketId {
        match self {
            Self::Sign { id } | Self::Refuse { id, .. } | Self::Skip { id } => id,
        }
    }
}

/// One line read from the app: an answer, or why it isn't one.
pub(crate) fn parse_answer(line: &[u8]) -> Result<Answer, String> {
    let text = std::str::from_utf8(line).map_err(|_| "an answer that isn't UTF-8".to_owned())?;
    serde_json::from_str(text.trim_end_matches(['\n', '\r'])).map_err(|e| {
        format!(
            "an answer that isn't one ({})",
            display::clean(&e.to_string())
        )
    })
}

/// Reads the app's lines, at most [`MAX_ANSWER`] bytes each, and hands each one over as an
/// answer or as why it isn't one. A longer line is dropped to its end and said, never
/// read whole. Ends with the input. Blocking: run on a thread of its own.
pub(crate) fn read_answers(
    mut input: impl BufRead,
    answers: &tokio::sync::mpsc::Sender<Result<Answer, String>>,
) {
    loop {
        let mut line = Vec::new();
        let mut over = false;
        loop {
            let buffer = match input.fill_buf() {
                Ok(buffer) => buffer,
                Err(_) => return,
            };
            if buffer.is_empty() {
                // The end of the input: a last line without its newline is dropped (an app
                // that stops mid-answer meant nothing).
                return;
            }
            let (taken, ended) = match buffer.iter().position(|b| *b == b'\n') {
                Some(at) => (at.saturating_add(1), true),
                None => (buffer.len(), false),
            };
            if !over {
                let room = MAX_ANSWER.saturating_sub(line.len());
                match buffer.get(..taken) {
                    Some(part) if part.len() <= room => line.extend_from_slice(part),
                    _ => {
                        over = true;
                        line.clear();
                    }
                }
            }
            input.consume(taken);
            if ended {
                break;
            }
        }
        let answer = if over {
            Err(format!("an answer longer than {MAX_ANSWER} bytes"))
        } else {
            parse_answer(&line)
        };
        if answers.blocking_send(answer).is_err() {
            return;
        }
    }
}

/// Writes one event, a line of JSON.
fn send(output: &mut impl Write, event: &Event) -> anyhow::Result<()> {
    let mut line = serde_json::to_vec(event)?;
    line.push(b'\n');
    output.write_all(&line)?;
    output.flush()?;
    Ok(())
}

/// Why serving one connection ended.
enum Ended {
    /// The app's input ended: this command is done.
    Input,
    /// The connection to the daemon failed, or the daemon refused the watch: reached again
    /// after a while (from the shortest wait if a watch was answered on it).
    Lost { reason: String, answered: bool },
}

/// The ticket on screen, as it will be signed.
struct Shown {
    reviewed: Reviewed,
    signed: Ticket,
}

/// What the popup is showing and what waits behind it.
#[derive(Default)]
struct Popup {
    /// The tickets waiting for a signature, in id order, as the last watch gave them (less
    /// those this run decided since).
    waiting: Vec<Summary>,
    shown: Option<Shown>,
    /// Put aside by a `skip`, or a ticket that couldn't be shown: not shown again.
    skipped: BTreeSet<TicketId>,
    /// Whether the app was last told nothing waits.
    idle: bool,
}

impl Popup {
    fn shown_id(&self) -> Option<&TicketId> {
        self.shown.as_ref().map(|s| &s.reviewed.submitted.id)
    }

    /// The tickets waiting behind the one shown.
    fn behind(&self) -> Vec<Waiting> {
        self.waiting
            .iter()
            .filter(|t| Some(&t.id) != self.shown_id())
            .map(|t| Waiting {
                id: t.id.clone(),
                title: display::clean(&t.title),
                repos: t.repos.iter().map(ToString::to_string).collect(),
                skipped: self.skipped.contains(&t.id),
            })
            .collect()
    }

    /// The waiting tickets now: the shown one gone if it left, the next one shown if none is.
    async fn update(
        &mut self,
        session: &Approvals,
        signer: &Signer,
        tickets: Vec<Summary>,
        output: &mut impl Write,
    ) -> anyhow::Result<()> {
        let before = self.behind();
        self.waiting = tickets
            .into_iter()
            .filter(|t| t.state == State::Pending)
            .collect();
        self.skipped
            .retain(|id| self.waiting.iter().any(|t| &t.id == id));
        if let Some(id) = self.shown_id().cloned()
            && !self.waiting.iter().any(|t| t.id == id)
        {
            self.shown = None;
            send(output, &Event::Gone { id })?;
        }
        if self.shown.is_some() {
            let behind = self.behind();
            if behind != before {
                send(output, &Event::Queue { waiting: behind })?;
            }
            return Ok(());
        }
        self.show_next(session, signer, output).await
    }

    /// Shows the oldest waiting ticket not put aside, or says nothing waits.
    async fn show_next(
        &mut self,
        session: &Approvals,
        signer: &Signer,
        output: &mut impl Write,
    ) -> anyhow::Result<()> {
        let candidates: Vec<TicketId> = self
            .waiting
            .iter()
            .map(|t| t.id.clone())
            .filter(|id| !self.skipped.contains(id))
            .collect();
        for id in candidates {
            match fetch_reviewed(session, &id).await {
                Ok(reviewed) => {
                    let signed = reviewed.submitted.clone();
                    self.shown = Some(Shown { reviewed, signed });
                    self.idle = false;
                    return self.send_shown(signer, output);
                }
                // A ticket that can't be shown (no longer waiting, or a reply the checks
                // refuse): said, put aside, the next one tried.
                Err(e) => {
                    self.skipped.insert(id.clone());
                    let message = display::clean_lines(&format!("{e:#}"));
                    send(
                        output,
                        &Event::Failed {
                            id: Some(id),
                            message,
                        },
                    )?;
                }
            }
        }
        if !self.idle {
            self.idle = true;
            send(output, &Event::Idle)?;
        }
        Ok(())
    }

    /// Sends the ticket shown, with the others behind it.
    fn send_shown(&self, signer: &Signer, output: &mut impl Write) -> anyhow::Result<()> {
        let Some(shown) = &self.shown else {
            return Ok(());
        };
        let submitted = &shown.reviewed.submitted;
        let kind = match (
            &submitted.text.amends,
            &submitted.text.renews,
            &submitted.text.revises,
        ) {
            (Some(_), _, _) => Kind::Amendment,
            (None, Some(_), _) => Kind::Renewal,
            (None, None, Some(_)) => Kind::Revision,
            (None, None, None) => Kind::Ticket,
        };
        // The very text `writ sign <id> --full` prints above its question.
        let display = render(&shown.reviewed, &shown.signed, now()?, display::Rows::All);
        let event = Event::Show {
            id: submitted.id.clone(),
            kind,
            title: display::clean(&submitted.text.title),
            display,
            key: display::clean(&signer.key.display().to_string()),
            waiting: self.behind(),
        };
        send(output, &event)
    }

    /// Acts on one line of the app: signs, refuses or puts aside the ticket shown, if the
    /// answer names it; anything else signs nothing and is said.
    async fn answer(
        &mut self,
        session: &Approvals,
        signer: &Signer,
        answer: Result<Answer, String>,
        output: &mut impl Write,
    ) -> anyhow::Result<()> {
        let answer = match answer {
            Ok(answer) => answer,
            Err(message) => {
                let message = format!("{message}: nothing signed");
                return send(output, &Event::Failed { id: None, message });
            }
        };
        let id = answer.id().clone();
        match self.shown_id() {
            Some(shown) if shown == &id => {}
            Some(shown) => {
                let message =
                    format!("the answer names {id}, but {shown} is shown: nothing signed");
                return send(
                    output,
                    &Event::Failed {
                        id: Some(id),
                        message,
                    },
                );
            }
            None => {
                let message =
                    format!("the answer names {id}, but no ticket is shown: nothing signed");
                return send(
                    output,
                    &Event::Failed {
                        id: Some(id),
                        message,
                    },
                );
            }
        }
        let Some(shown) = self.shown.take() else {
            return Ok(());
        };
        let done = match answer {
            Answer::Skip { .. } => {
                self.skipped.insert(id.clone());
                return self.show_next(session, signer, output).await;
            }
            Answer::Sign { .. } => approve(session, signer, &id, &shown.signed).await,
            Answer::Refuse { feedback, .. } => {
                let feedback = if feedback.trim().is_empty() {
                    NO_FEEDBACK.to_owned()
                } else {
                    feedback
                };
                refuse_with(session, signer, &id, feedback).await
            }
        };
        match done {
            Ok(message) => {
                self.waiting.retain(|t| t.id != id);
                send(output, &Event::Done { id, message })?;
                self.show_next(session, signer, output).await
            }
            // Touch ID cancelled, the daemon refusing: said, and the ticket shown again.
            Err(e) => {
                let message = display::clean_lines(&format!("{e:#}"));
                send(
                    output,
                    &Event::Failed {
                        id: Some(id),
                        message,
                    },
                )?;
                self.shown = Some(shown);
                self.send_shown(signer, output)
            }
        }
    }

    /// Serves the app on one connection, until the app's input ends or the connection fails.
    async fn serve(
        &mut self,
        session: &Approvals,
        signer: &Signer,
        answers: &mut tokio::sync::mpsc::Receiver<Result<Answer, String>>,
        output: &mut impl Write,
    ) -> anyhow::Result<Ended> {
        let mut since: Option<TextDigest> = None;
        let mut answered = false;
        loop {
            let command = Command::Watch {
                since: since.clone(),
            };
            let watch = session.call::<Watched>(&command, b"");
            tokio::pin!(watch);
            loop {
                tokio::select! {
                    watched = &mut watch => {
                        match watched {
                            Ok(Ok(watched)) => {
                                answered = true;
                                since = Some(watched.cursor.clone());
                                self.update(session, signer, watched.tickets, output).await?;
                            }
                            // The daemon refused the watch (sealed, too many watches): said,
                            // tried again on a new connection.
                            Ok(Err(refused)) => {
                                let reason = refused.to_string();
                                return Ok(Ended::Lost { reason, answered });
                            }
                            Err(e) => {
                                return Ok(Ended::Lost { reason: format!("{e:#}"), answered });
                            }
                        }
                        break;
                    }
                    answer = answers.recv() => match answer {
                        None => return Ok(Ended::Input),
                        Some(answer) => self.answer(session, signer, answer, output).await?,
                    },
                }
            }
        }
    }
}

/// `writ sign --ui`: serves the approval popup until its input ends.
pub async fn run(paths: &Paths, url: &str, signer: &Signer) -> anyhow::Result<Exit> {
    let (sender, mut answers) = tokio::sync::mpsc::channel(16);
    std::thread::Builder::new()
        .name("writ-ui-answers".to_owned())
        .spawn(move || read_answers(std::io::stdin().lock(), &sender))?;
    let mut output = std::io::stdout();
    let mut popup = Popup::default();
    let mut backoff = Duration::from_secs(1);
    loop {
        let lost = match Approvals::connect(paths, url).await {
            Ok(session) => {
                let served = popup
                    .serve(&session, signer, &mut answers, &mut output)
                    .await;
                session.close().await;
                match served? {
                    Ended::Input => return Ok(Exit::Ok),
                    Ended::Lost { reason, answered } => {
                        if answered {
                            backoff = Duration::from_secs(1);
                        }
                        reason
                    }
                }
            }
            Err(e) => format!("{e:#}"),
        };
        let message = display::clean_lines(&format!(
            "the daemon can't be reached ({lost}): trying again in {} s",
            backoff.as_secs()
        ));
        send(&mut output, &Event::Status { message })?;
        // Answers while away sign nothing; the end of the input still ends this.
        let retry = tokio::time::sleep(backoff);
        tokio::pin!(retry);
        loop {
            tokio::select! {
                () = &mut retry => break,
                answer = answers.recv() => match answer {
                    None => return Ok(Exit::Ok),
                    Some(_) => {
                        let message = "not connected to the daemon: nothing signed".to_owned();
                        send(&mut output, &Event::Failed { id: None, message })?;
                    }
                },
            }
        }
        backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> TicketId {
        TicketId::from_parts(1_800_000_000_000, [7; 10])
    }

    /// Every line `read_answers` hands over for `input`.
    fn read_all(input: &[u8]) -> Vec<Result<Answer, String>> {
        let (sender, mut answers) = tokio::sync::mpsc::channel(64);
        read_answers(input, &sender);
        drop(sender);
        let mut out = Vec::new();
        while let Ok(answer) = answers.try_recv() {
            out.push(answer);
        }
        out
    }

    #[test]
    fn answers_are_read_strictly() {
        let id = id();
        assert_eq!(
            parse_answer(format!(r#"{{"answer":"sign","id":"{id}"}}"#).as_bytes()),
            Ok(Answer::Sign { id: id.clone() })
        );
        assert_eq!(
            parse_answer(
                format!(r#"{{"answer":"refuse","id":"{id}","feedback":"no"}}"#).as_bytes()
            ),
            Ok(Answer::Refuse {
                id: id.clone(),
                feedback: "no".to_owned()
            })
        );
        // A refusal's feedback may be left out: none given.
        assert_eq!(
            parse_answer(format!(r#"{{"answer":"refuse","id":"{id}"}}"#).as_bytes()),
            Ok(Answer::Refuse {
                id: id.clone(),
                feedback: String::new()
            })
        );
        assert_eq!(
            parse_answer(format!("{{\"answer\":\"skip\",\"id\":\"{id}\"}}\r\n").as_bytes()),
            Ok(Answer::Skip { id: id.clone() })
        );
        for bad in [
            String::new(),
            "sign".to_owned(),
            r#"{"answer":"sign"}"#.to_owned(),
            r#"{"answer":"sign","id":"wrt_nope"}"#.to_owned(),
            format!(r#"{{"answer":"approve","id":"{id}"}}"#),
            format!(r#"{{"answer":"SIGN","id":"{id}"}}"#),
            format!(r#"{{"id":"{id}"}}"#),
            format!(r#"{{"answer":"sign","id":"{id}","narrow":"ttl"}}"#),
            format!(r#"{{"answer":"skip","id":"{id}","feedback":"x"}}"#),
            format!(r#"{{"answer":"sign","id":"{id}"}} {{"answer":"sign","id":"{id}"}}"#),
            format!(r#"[{{"answer":"sign","id":"{id}"}}]"#),
        ] {
            let error = parse_answer(bad.as_bytes()).unwrap_err();
            assert!(
                error.starts_with("an answer that isn't one ("),
                "{bad:?}: {error}"
            );
        }
        assert_eq!(
            parse_answer(b"{\"answer\":\"sign\",\"id\":\"\xff\"}"),
            Err("an answer that isn't UTF-8".to_owned())
        );
        // What serde says of a hostile line reaches the app cleaned.
        let error = parse_answer("{\"answer\":\"\u{1b}[2J\"}".as_bytes()).unwrap_err();
        assert!(!error.contains('\u{1b}'), "{error:?}");
    }

    #[test]
    fn a_line_is_read_up_to_its_bound_and_dropped_past_it() {
        let id = id();
        let answer = format!(r#"{{"answer":"refuse","id":"{id}","feedback":""#);
        // Padded to exactly MAX_ANSWER bytes with its newline, and one byte past.
        let at = |extra: usize| {
            let filler = MAX_ANSWER - answer.len() - 3 + extra;
            format!("{answer}{}\"}}\n", "x".repeat(filler))
        };
        assert_eq!(at(0).len(), MAX_ANSWER);
        let read = read_all(at(0).as_bytes());
        assert!(matches!(&read[..], [Ok(Answer::Refuse { .. })]), "{read:?}");
        let sign = format!("{{\"answer\":\"sign\",\"id\":\"{id}\"}}\n");
        let read = read_all(format!("{}{sign}", at(1)).as_bytes());
        assert_eq!(
            read,
            [
                Err(format!("an answer longer than {MAX_ANSWER} bytes")),
                // The line after it is read as its own.
                Ok(Answer::Sign { id: id.clone() }),
            ]
        );
        // A line that never ends past the bound, and a last line without its newline:
        // dropped.
        assert!(read_all("x".repeat(3 * MAX_ANSWER).as_bytes()).is_empty());
        assert!(read_all(sign.trim_end().as_bytes()).is_empty());
        assert!(read_all(b"").is_empty());
    }

    #[test]
    fn events_are_one_line_of_json_each() {
        let id = id();
        let mut out = Vec::new();
        send(
            &mut out,
            &Event::Show {
                id: id.clone(),
                kind: Kind::Amendment,
                title: "t".to_owned(),
                display: "a\nb".to_owned(),
                key: "/k.pub".to_owned(),
                waiting: vec![Waiting {
                    id: id.clone(),
                    title: "w".to_owned(),
                    repos: vec!["api".to_owned()],
                    skipped: true,
                }],
            },
        )
        .unwrap();
        send(&mut out, &Event::Idle).unwrap();
        send(
            &mut out,
            &Event::Failed {
                id: None,
                message: "m".to_owned(),
            },
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines,
            [
                format!(
                    r#"{{"type":"show","id":"{id}","kind":"amendment","title":"t","display":"a\nb","key":"/k.pub","waiting":[{{"id":"{id}","title":"w","repos":["api"],"skipped":true}}]}}"#
                )
                .as_str(),
                r#"{"type":"idle"}"#,
                r#"{"type":"failed","id":null,"message":"m"}"#,
            ]
        );
    }
}
