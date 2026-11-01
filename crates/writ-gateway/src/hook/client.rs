//! The hook side, run by git as `writd hook pre-receive` in its own process: forwards the
//! push's quarantine and its ref updates to the daemon and exits with its answer.

use std::io::{Read, Write};

/// Runs the hook. Returns the exit code: 0 lets the push in, anything else refuses it.
pub fn run_pre_receive() -> i32 {
    match pre_receive() {
        Ok(()) => 0,
        Err(reason) => {
            eprintln!("writ: {reason}");
            1
        }
    }
}

fn pre_receive() -> Result<(), String> {
    let socket =
        std::env::var_os("WRIT_HOOK_SOCKET").ok_or("push not started by the writ gateway")?;
    let token =
        std::env::var("WRIT_HOOK_TOKEN").map_err(|_| "push not started by the writ gateway")?;
    // Set by receive-pack when the push sent objects; none for a push that only deletes.
    let quarantine = match std::env::var("GIT_QUARANTINE_PATH") {
        Ok(path) => path,
        Err(std::env::VarError::NotPresent) => String::new(),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("the push's quarantine path is not UTF-8".to_owned());
        }
    };
    if quarantine.contains('\n') {
        return Err("the push's quarantine path holds a newline".to_owned());
    }
    let mut updates = String::new();
    std::io::stdin()
        .read_to_string(&mut updates)
        .map_err(|e| format!("cannot read the ref updates: {e}"))?;
    let mut stream = std::os::unix::net::UnixStream::connect(socket)
        .map_err(|e| format!("cannot reach the daemon: {e}"))?;
    stream
        .write_all(request(&token, &quarantine, &updates).as_bytes())
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
        .map_err(|e| format!("cannot reach the daemon: {e}"))?;
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .map_err(|e| format!("no answer from the daemon: {e}"))?;
    answer(&reply)
}

/// What the hook sends: the token line, the quarantine line (empty when there is none), then
/// git's lines (each ending in `\n`).
fn request(token: &str, quarantine: &str, updates: &str) -> String {
    let mut text = format!("{token}\n{quarantine}\n{updates}");
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// The daemon's answer: `ok` lets the push in; `deny <reason>` or anything else refuses it.
fn answer(reply: &str) -> Result<(), String> {
    let reply = reply.strip_suffix('\n').unwrap_or(reply);
    if reply == "ok" {
        return Ok(());
    }
    match reply.split_once(' ') {
        Some(("deny", reason)) if !reason.is_empty() => Err(reason.to_owned()),
        _ => Err("unexpected answer from the daemon".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_line_sent_ends_with_a_newline() {
        assert_eq!(request("t", "", ""), "t\n\n");
        assert_eq!(request("t", "/q", "a b c\n"), "t\n/q\na b c\n");
        assert_eq!(request("t", "/q", "a b c"), "t\n/q\na b c\n");
    }

    #[test]
    fn only_ok_lets_the_push_in() {
        assert_eq!(answer("ok\n"), Ok(()));
        assert_eq!(answer("ok"), Ok(()));
        assert_eq!(
            answer("deny refs/heads/main is protected\n"),
            Err("refs/heads/main is protected".into())
        );
        for bad in [
            "", "\n", "ok ok\n", "OK\n", "okay\n", "deny\n", "deny \n", "ok\nok\n", " ok\n",
        ] {
            assert_eq!(
                answer(bad),
                Err("unexpected answer from the daemon".to_owned()),
                "{bad:?}"
            );
        }
    }
}
