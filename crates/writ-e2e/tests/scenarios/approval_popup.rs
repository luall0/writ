//! Scenario 27, the approval popup's side of `writ` (M7.8): `writ sign --ui` on the approver's
//! machine, driven as `writ-popup` drives it (one JSON line each way). Two tickets submitted
//! at once: the oldest shown with the other stacked behind it, its display the very text
//! `writ sign --full` prints; an answer naming the ticket behind refused, nothing signed; the
//! first signed (the agent gets its lease), the second shown next and refused with feedback
//! (the agent reads it); a ticket withdrawn while shown closing its window; the end of the
//! app's input ending the command. Alone: a ticket another scenario left waiting would show
//! first (it is put aside, as a closed window does).

use serde_json::{Value, json};
use writ_e2e::Stack;
use writ_e2e::agent::expect;
use writ_e2e::docker::Talk;

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

fn ticket(title: &str) -> String {
    format!(
        "common:\n  committer_emails: [\"agent@writ.invalid\"]\n\
         repos:\n  lifecycle:\n    template: feature\n    operations: [fetch, commit_sign, push]\n    \
         branches: [\"agent/popup\"]\n\
         ticket:\n  title: \"{title}\"\n  task: \"A ticket for the approval popup\"\n\
         limits:\n  ttl: 1h\n"
    )
}

/// The next event `writ sign --ui` prints that isn't about a ticket of another scenario:
/// those shown are put aside (`skip`), and their stacked entries left out of what is read.
fn next(popup: &mut Talk, ours: &[&str]) -> Value {
    loop {
        let line = popup.line();
        let event: Value =
            serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON ({e}): {line:?}"));
        let id = event["id"].as_str().unwrap_or_default().to_owned();
        if event["type"] == "show" && !ours.contains(&id.as_str()) {
            popup.send(&json!({ "answer": "skip", "id": id }).to_string());
            continue;
        }
        if event["type"] == "failed" && !id.is_empty() && !ours.contains(&id.as_str()) {
            continue;
        }
        return event;
    }
}

fn kind<'a>(event: &'a Value, expected: &str) -> &'a Value {
    assert_eq!(event["type"], expected, "{event}");
    event
}

/// The ids of ours the event lists behind the one shown.
fn behind(event: &Value, ours: &[&str]) -> Vec<String> {
    event["waiting"]
        .as_array()
        .map(|all| {
            all.iter()
                .filter_map(|w| w["id"].as_str())
                .filter(|id| ours.contains(id))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[test]
#[ignore = "end to end: make e2e"]
fn the_popup_shows_what_waits_in_order_and_signs_or_refuses_on_its_answer() {
    let stack = Stack::exclusive();
    let agent = stack.agent("popup");
    let mut popup = stack.approver.talk("writ sign --ui");

    // Two tickets at once, from the agent's host.
    let (a, first) = agent.request("popup-a", &ticket("First of two"));
    let (b, second) = agent.request("popup-b", &ticket("Second of two"));
    let (older, newer) = if a < b { (&a, &b) } else { (&b, &a) };
    let ours = [a.as_str(), b.as_str()];
    let mut shown = next(&mut popup, &ours);
    while shown["type"] != "show" {
        // Nothing waiting yet, or a stack that changed before ours came.
        shown = next(&mut popup, &ours);
    }
    assert_eq!(shown["id"], older.as_str(), "{shown}");
    assert_eq!(shown["kind"], "ticket");
    let mut stacked = behind(&shown, &ours);
    while stacked.is_empty() {
        stacked = behind(kind(&next(&mut popup, &ours), "queue"), &ours);
    }
    assert_eq!(stacked, std::slice::from_ref(newer));
    let display = shown["display"].as_str().unwrap().to_owned();
    let out = stack
        .approver
        .run_with(&format!("writ sign {older} --full"), b"n\n");
    let (terminal, _) = expect(&out, 6, "the ticket shown, answered no in a terminal");
    assert!(
        timeless(&terminal).starts_with(&format!("{}\n", timeless(&display))),
        "--- the popup's\n{display}\n--- the terminal's\n{terminal}"
    );

    // An answer for the ticket behind: refused, nothing signed.
    popup.send(&json!({ "answer": "sign", "id": newer }).to_string());
    let failed = kind(&next(&mut popup, &ours), "failed").clone();
    assert_eq!(
        failed["message"],
        format!("the answer names {newer}, but {older} is shown: nothing signed")
    );
    let listing = stack.approver.ok("writ ls");
    assert!(
        listing.contains(older.as_str()) && listing.contains(newer.as_str()),
        "{listing}"
    );

    // Signed through the approval key: the lease is the agent's; the second comes next.
    popup.send(&json!({ "answer": "sign", "id": older }).to_string());
    let done = kind(&next(&mut popup, &ours), "done").clone();
    assert_eq!(done["message"], format!("Signed: lease {older} is active."));
    let shown = kind(&next(&mut popup, &ours), "show").clone();
    assert_eq!(shown["id"], newer.as_str());
    popup.send(
        &json!({ "answer": "refuse", "id": newer, "feedback": "One ticket is enough" }).to_string(),
    );
    let done = kind(&next(&mut popup, &ours), "done").clone();
    assert_eq!(
        done["message"],
        format!("Refused: ticket {newer}. The agent gets your feedback.")
    );
    let (signed, refused) = if a == *older {
        (first, second)
    } else {
        (second, first)
    };
    let (status, out, err) = signed.finish();
    assert_eq!(status.code(), Some(0), "{out}{err}");
    let (status, out, err) = refused.finish();
    assert_eq!(status.code(), Some(4), "{out}{err}");
    assert!(out.contains("One ticket is enough"), "{out}");
    // One grant line for the lease (a grant names it as `lease`), one refusal for the other.
    assert_eq!(stack.audited(older, "grant", "allowed").len(), 1);
    assert_eq!(stack.audited(newer, "refuse", "done").len(), 1);

    // Withdrawn while shown: its window goes.
    let withdrawn = agent.submit("popup-c", &ticket("Withdrawn"));
    let ours = [withdrawn.as_str()];
    let mut shown = next(&mut popup, &ours);
    while shown["type"] != "show" {
        shown = next(&mut popup, &ours);
    }
    assert_eq!(shown["id"], withdrawn.as_str());
    stack.approver.ok(&format!("writ revoke {withdrawn}"));
    assert_eq!(
        kind(&next(&mut popup, &ours), "gone")["id"],
        withdrawn.as_str()
    );

    // The app's input ends: so does the command.
    let (status, err) = popup.finish();
    assert_eq!(status.code(), Some(0), "{err}");
}
