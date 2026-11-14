//! M7.8: `writ sign --ui`, what the approval popup runs, with the real binaries: `writd run`,
//! the approval API over SSH and over HTTPS, approver signatures made by `ssh-keygen` through
//! a throwaway `ssh-agent`. The test plays the app: it reads each event `writ` prints and
//! writes the answers a click would.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::mpsc;

use serde_json::{Value, json};
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::process::ends_within;
use writ_integration::{WAIT_LIMIT, stderr, stdout};

const POLICY: &str = r#"
keys:
  agent-01:
    use: signing
    format: ssh
    algorithm: ed25519
  upstream-01:
    use: upstream
    kind: ssh
    algorithm: ed25519
upstream_hosts:
  remote.invalid:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    templates: [feature]
templates:
  feature:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-01
    max_ttl: 2h
    max_signatures: 40
    max_pushes: 20
    max_ops_per_minute: 100
    max_push_size: 10MB
"#;

/// The feedback a refusal with none carries (`writ_cli`'s `NO_FEEDBACK`).
const NO_FEEDBACK: &str = "Declined in the approval popup, with no feedback.";

/// `text` with every relative time (` (in 59m59s)`) taken out: two displays made a second
/// apart differ only there.
fn timeless(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(" (in ") {
        out.push_str(&rest[..at]);
        match rest[at..].find(')') {
            Some(end) => rest = &rest[at + end + 1..],
            None => {
                rest = &rest[at..];
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

fn ticket(branch: &str, title: &str, extra: &str) -> String {
    format!(
        "repos:\n  demo:\n    operations: [fetch, commit_sign, push]\n    branches: [\"{branch}\"]\n\
         ticket:\n  title: \"{title}\"\n  task: A ticket for the popup\n{extra}limits:\n  ttl: 1h\n"
    )
}

/// `writ sign --ui`, played as the app plays it.
struct Popup {
    child: Child,
    input: Option<ChildStdin>,
    events: mpsc::Receiver<Value>,
}

impl Popup {
    fn start(daemon: &Daemon) -> Self {
        let mut child = daemon
            .writ(&["sign", "--ui"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let output = BufReader::new(child.stdout.take().unwrap());
        let (sender, events) = mpsc::channel();
        std::thread::spawn(move || {
            for line in output.lines() {
                let Ok(line) = line else { return };
                let event: Value = serde_json::from_str(&line)
                    .unwrap_or_else(|e| panic!("not one JSON line ({e}): {line:?}"));
                if sender.send(event).is_err() {
                    return;
                }
            }
        });
        Self {
            child,
            input,
            events,
        }
    }

    /// The next event (at most [`WAIT_LIMIT`]).
    fn next(&self) -> Value {
        self.events
            .recv_timeout(WAIT_LIMIT)
            .expect("writ sign --ui said nothing")
    }

    /// The next event, which must be of `kind`.
    fn expect(&self, kind: &str) -> Value {
        let event = self.next();
        assert_eq!(event["type"], kind, "{event}");
        event
    }

    fn send(&mut self, line: &str) {
        let input = self.input.as_mut().unwrap();
        input.write_all(line.as_bytes()).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
    }

    fn answer(&mut self, answer: Value) {
        self.send(&answer.to_string());
    }

    /// Ends the app's side: `writ` ends with its input, exit 0.
    fn close(mut self) {
        drop(self.input.take());
        assert!(ends_within(&mut self.child, WAIT_LIMIT), "still running");
        assert_eq!(self.child.wait().unwrap().code(), Some(0));
    }
}

/// The ids of the tickets an event lists as waiting (the one shown among them).
fn behind(event: &Value) -> Vec<String> {
    event["waiting"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["id"].as_str().unwrap().to_owned())
        .collect()
}

/// Submits a ticket without waiting for its decision: its id.
fn submit(daemon: &Daemon, name: &str, text: &str) -> String {
    let file = daemon.root().join(format!("{name}.yaml"));
    fs::write(&file, text).unwrap();
    let out = daemon.run(&["request", file.to_str().unwrap(), "--no-wait"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let first = stdout(&out);
    let id = first
        .split_whitespace()
        .find(|w| w.starts_with("wrt_"))
        .unwrap_or_else(|| panic!("no ticket id in {first:?}"));
    id.trim_end_matches([':', '.', ',']).to_owned()
}

fn pending(daemon: &Daemon) -> String {
    stdout(&daemon.run(&["ls"], ""))
}

fn the_popup_signs_refuses_and_follows_what_waits(approvals: Approvals) {
    let daemon = Daemon::start(POLICY, approvals);
    let mut popup = Popup::start(&daemon);
    popup.expect("idle");

    // Two tickets at once: the oldest shown, both listed (the window's sidebar).
    let first = daemon.request("first", &ticket("agent/a", "First", ""));
    let second = daemon.request("second", &ticket("agent/b", "Second", ""));
    let (older, newer) = if first.id < second.id {
        (first.id.clone(), second.id.clone())
    } else {
        (second.id.clone(), first.id.clone())
    };
    let (older, newer) = (&older, &newer);
    let shown = popup.expect("show");
    assert_eq!(shown["id"], older.as_str(), "{shown}");
    assert_eq!(shown["kind"], "ticket");
    let mut waiting = behind(&shown);
    if waiting.len() < 2 {
        waiting = behind(&popup.expect("queue"));
    }
    assert_eq!(waiting, [older.clone(), newer.clone()]);
    // The header and the structure the window shows (the display's tests check its rows).
    assert_eq!(shown["repos"], json!(["demo"]));
    assert!(
        shown["expires_at"].as_str().unwrap().ends_with('Z'),
        "{shown}"
    );
    let kinds: Vec<&str> = shown["doc"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds.first(), Some(&"ticket"), "{kinds:?}");
    assert_eq!(kinds.last(), Some(&"signing"), "{kinds:?}");
    for kind in ["who", "lease", "repository", "agent", "others"] {
        assert!(kinds.contains(&kind), "{kind} not in {kinds:?}");
    }
    // The display is the very text `writ sign --full` prints above its question.
    let display = shown["display"].as_str().unwrap().to_owned();
    let out = daemon.run(&["sign", older, "--full"], "n\n");
    assert_eq!(out.status.code(), Some(6), "{}", stderr(&out));
    assert!(
        timeless(&stdout(&out)).starts_with(&format!("{}\n", timeless(&display))),
        "--- ui\n{display}\n--- terminal\n{}",
        stdout(&out)
    );
    assert!(
        display.contains("│ First") || display.contains("│ Second"),
        "{display}"
    );
    assert!(
        shown["key"].as_str().unwrap().ends_with("approver.pub"),
        "{shown}"
    );

    // Answers that aren't for the ticket shown, or aren't answers: nothing signed.
    popup.send("sign");
    let failed = popup.expect("failed");
    assert_eq!(failed["id"], Value::Null);
    let message = failed["message"].as_str().unwrap();
    assert!(
        message.starts_with("an answer that isn't one (") && message.ends_with("): nothing signed"),
        "{message}"
    );
    popup.answer(json!({ "answer": "sign", "id": newer }));
    let failed = popup.expect("failed");
    assert_eq!(
        failed["message"],
        format!("the answer names {newer}, but {older} is shown: nothing signed")
    );
    popup.send(&"x".repeat(70 * 1024));
    let failed = popup.expect("failed");
    assert_eq!(
        failed["message"],
        "an answer longer than 65536 bytes: nothing signed"
    );
    let listing = pending(&daemon);
    assert_eq!(listing.matches("pending").count(), 2, "{listing}");

    // Picked from the list: the newer shown, then the older again; a ticket that isn't
    // waiting is refused, the one shown stays.
    popup.answer(json!({ "answer": "pick", "id": newer }));
    assert_eq!(popup.expect("show")["id"], newer.as_str());
    popup.answer(json!({ "answer": "pick", "id": "wrt_01JD8X00000000000000000000" }));
    assert_eq!(
        popup.expect("failed")["message"],
        "ticket wrt_01JD8X00000000000000000000 isn't waiting for a signature: nothing shown"
    );
    popup.answer(json!({ "answer": "sign", "id": older }));
    assert_eq!(
        popup.expect("failed")["message"],
        format!("the answer names {older}, but {newer} is shown: nothing signed")
    );
    popup.answer(json!({ "answer": "pick", "id": older }));
    assert_eq!(popup.expect("show")["id"], older.as_str());

    // Signed: the next one shown, alone in the list.
    popup.answer(json!({ "answer": "sign", "id": older }));
    let done = popup.expect("done");
    assert_eq!(done["message"], format!("Signed: lease {older} is active."));
    let next = popup.expect("show");
    assert_eq!(next["id"], newer.as_str());
    assert_eq!(behind(&next), std::slice::from_ref(newer));

    // Refused with no feedback: the agent is told none was given; then nothing waits.
    popup.answer(json!({ "answer": "refuse", "id": newer, "feedback": "  " }));
    let done = popup.expect("done");
    assert_eq!(
        done["message"],
        format!("Refused: ticket {newer}. The agent gets your feedback.")
    );
    popup.expect("idle");
    let (signed, refused) = if first.id == *older {
        (first, second)
    } else {
        (second, first)
    };
    let (status, out, err) = signed.finish();
    assert_eq!(status.code(), Some(0), "{out}{err}");
    let (status, out, err) = refused.finish();
    assert_eq!(status.code(), Some(4), "{out}{err}");
    assert!(out.contains(NO_FEEDBACK), "{out}");
    let lease = older.clone();

    // Refused with feedback: the agent reads it.
    let third = daemon.request("third", &ticket("agent/c", "Third", ""));
    let shown = popup.expect("show");
    assert_eq!(shown["id"], third.id.as_str());
    popup
        .answer(json!({ "answer": "refuse", "id": third.id, "feedback": "Too broad: one branch" }));
    popup.expect("done");
    popup.expect("idle");
    let (status, out, _) = third.finish();
    assert_eq!(status.code(), Some(4));
    assert!(out.contains("Too broad: one branch"), "{out}");

    // Withdrawn while shown: its window goes.
    let withdrawn = submit(&daemon, "withdrawn", &ticket("agent/d", "Withdrawn", ""));
    assert_eq!(popup.expect("show")["id"], withdrawn.as_str());
    assert!(daemon.run(&["revoke", &withdrawn], "").status.success());
    assert_eq!(popup.expect("gone")["id"], withdrawn.as_str());
    popup.expect("idle");

    // Put aside (its window closed): still waiting, not shown again by this run.
    let aside = submit(&daemon, "aside", &ticket("agent/e", "Aside", ""));
    assert_eq!(popup.expect("show")["id"], aside.as_str());
    popup.answer(json!({ "answer": "skip", "id": aside }));
    popup.expect("idle");
    assert!(pending(&daemon).contains(&aside), "still waiting");

    // An amendment shows as one, and signs as one; the ticket put aside is behind it.
    let amendment = submit(
        &daemon,
        "amend",
        &ticket("agent/a", "Amend", &format!("  amends: {lease}\n")),
    );
    let shown = popup.expect("show");
    assert_eq!(shown["id"], amendment.as_str());
    assert_eq!(shown["kind"], "amendment");
    let listed = shown["waiting"].as_array().unwrap();
    let entry = |id: &str| listed.iter().find(|w| w["id"] == id).unwrap().clone();
    assert_eq!(entry(&aside)["skipped"], json!(true));
    assert_eq!(entry(&amendment)["kind"], "amendment");
    popup.answer(json!({ "answer": "sign", "id": amendment }));
    assert_eq!(
        popup.expect("done")["message"],
        format!("Signed: amendment {amendment} now applies to its lease.")
    );
    popup.expect("idle");

    // The ticket put aside, picked from the list: it comes back.
    popup.answer(json!({ "answer": "pick", "id": aside }));
    let back = popup.expect("show");
    assert_eq!(back["id"], aside.as_str());
    assert_eq!(back["waiting"][0]["skipped"], json!(false));
    popup.answer(json!({ "answer": "refuse", "id": aside, "feedback": "not now" }));
    popup.expect("done");
    popup.expect("idle");

    popup.close();
}

#[test]
fn the_popup_signs_refuses_and_follows_what_waits_over_ssh() {
    the_popup_signs_refuses_and_follows_what_waits(Approvals::Ssh);
}

#[test]
fn the_popup_signs_refuses_and_follows_what_waits_over_https() {
    the_popup_signs_refuses_and_follows_what_waits(Approvals::Https);
}

/// No narrowing in the popup: `writ sign --ui` with a narrowing flag, or a ticket named, is
/// refused before it connects.
#[test]
fn the_popup_takes_no_narrowing_and_no_ticket_named() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    for args in [
        &["sign", "--ui", "--ttl", "1h"][..],
        &["sign", "--ui", "--drop-op", "push"],
        &["sign", "--ui", "--full"],
        &["sign", "--ui", "wrt_01JD8X00000000000000000000"],
    ] {
        let out = daemon.run(args, "");
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("cannot be used with"),
            "{args:?}: {}",
            stderr(&out)
        );
    }
}
