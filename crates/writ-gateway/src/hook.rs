//! git's pre-receive hook, called back into the daemon.
//!
//! `git receive-pack` stores the pushed objects in a quarantine and runs the pre-receive
//! hook with the ref updates before anything is visible. The hook only forwards them, with
//! the push's token, to the daemon over a private Unix socket; the daemon decides. Git
//! deletes the quarantine when the hook refuses.

use std::io::{Read, Write};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::Gateway;

/// What the daemon knows about a push in progress.
#[derive(Debug, Clone)]
pub struct PushContext {
    pub lease: String,
    pub repo: String,
}

/// One line of the pre-receive input: `<old> <new> <ref>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub old: String,
    pub new: String,
    pub name: String,
}

impl RefUpdate {
    pub fn parse(line: &str) -> Option<Self> {
        let mut parts = line.split(' ');
        let (old, new, name) = (parts.next()?, parts.next()?, parts.next()?);
        let is_oid =
            |s: &str| matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit());
        (parts.next().is_none() && is_oid(old) && is_oid(new) && name.starts_with("refs/")).then(
            || Self {
                old: old.to_owned(),
                new: new.to_owned(),
                name: name.to_owned(),
            },
        )
    }
}

/// M0 policy: no update may touch a protected ref.
pub fn check_ref_updates(updates: &[RefUpdate], protected: &[String]) -> Result<(), String> {
    for update in updates {
        if protected
            .iter()
            .any(|pattern| ref_matches(pattern, &update.name))
        {
            return Err(format!("{} is protected", update.name));
        }
    }
    Ok(())
}

fn ref_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == pattern,
    }
}

pub(crate) async fn serve(gateway: Gateway, listener: UnixListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(answer(gateway.clone(), stream));
            }
            Err(e) => {
                eprintln!("writ gateway: hook socket failed: {e}");
                return;
            }
        }
    }
}

async fn answer(gateway: Gateway, mut stream: UnixStream) {
    let mut input = Vec::new();
    let reply = match (&mut stream).take(1 << 20).read_to_end(&mut input).await {
        Ok(_) => match decide(&gateway, &input) {
            Ok(()) => "ok\n".to_owned(),
            Err(reason) => format!("deny {reason}\n"),
        },
        Err(_) => "deny cannot read the push\n".to_owned(),
    };
    let _ = stream.write_all(reply.as_bytes()).await;
}

fn decide(gateway: &Gateway, input: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(input).map_err(|_| "malformed hook input")?;
    let mut lines = text.lines();
    let token = lines.next().ok_or("malformed hook input")?;
    let context = gateway
        .shared
        .pushes
        .lock()
        .map_err(|_| "internal error")?
        .get(token)
        .cloned()
        .ok_or("unknown push")?;
    let updates = lines
        .filter(|l| !l.is_empty())
        .map(|l| RefUpdate::parse(l).ok_or("malformed ref update"))
        .collect::<Result<Vec<_>, _>>()?;
    check_ref_updates(&updates, &gateway.shared.config.protected_refs)?;
    eprintln!(
        "writ gateway: push accepted for lease {} on {}: {} ref(s)",
        context.lease,
        context.repo,
        updates.len()
    );
    Ok(())
}

/// The hook side, run by git as `<program> hook pre-receive`. Returns the exit code.
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
    let mut updates = String::new();
    std::io::stdin()
        .read_to_string(&mut updates)
        .map_err(|e| format!("cannot read the ref updates: {e}"))?;
    let mut stream = std::os::unix::net::UnixStream::connect(socket)
        .map_err(|e| format!("cannot reach the daemon: {e}"))?;
    stream
        .write_all(format!("{token}\n{updates}").as_bytes())
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
        .map_err(|e| format!("cannot reach the daemon: {e}"))?;
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .map_err(|e| format!("no answer from the daemon: {e}"))?;
    match reply.trim_end().split_once(' ') {
        _ if reply.trim_end() == "ok" => Ok(()),
        Some(("deny", reason)) => Err(reason.to_owned()),
        _ => Err("unexpected answer from the daemon".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";

    #[test]
    fn parses_ref_updates() {
        assert_eq!(
            RefUpdate::parse(&format!("{A} {B} refs/heads/agent/x")),
            Some(RefUpdate {
                old: A.into(),
                new: B.into(),
                name: "refs/heads/agent/x".into()
            })
        );
        assert_eq!(RefUpdate::parse(&format!("{A} {B} HEAD")), None);
        assert_eq!(RefUpdate::parse(&format!("{A} zz refs/heads/x")), None);
        assert_eq!(
            RefUpdate::parse(&format!("{A} {B} refs/heads/x extra")),
            None
        );
    }

    #[test]
    fn protected_refs_are_refused() {
        let protected = vec!["refs/heads/main".to_owned(), "refs/tags/*".to_owned()];
        let update = |name: &str| RefUpdate {
            old: A.into(),
            new: B.into(),
            name: name.into(),
        };
        assert!(check_ref_updates(&[update("refs/heads/agent/x")], &protected).is_ok());
        assert!(check_ref_updates(&[update("refs/heads/main")], &protected).is_err());
        assert!(check_ref_updates(&[update("refs/tags/v1")], &protected).is_err());
        assert!(
            check_ref_updates(
                &[update("refs/heads/agent/x"), update("refs/heads/main")],
                &protected
            )
            .is_err()
        );
        assert!(check_ref_updates(&[update("refs/heads/mainline")], &protected).is_ok());
    }
}
