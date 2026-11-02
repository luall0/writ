//! `writd upstream-credential <socket> <operation>`: git's credential helper for an HTTPS
//! upstream, run as its own process by git (which shows its stderr in the daemon's captured
//! output). On `get` it passes git's request to the daemon's credential socket and the answer
//! back to git; `store` and `erase` do nothing. It never writes the token anywhere but to git.

use std::io::{Read, Write};

use zeroize::Zeroizing;

use super::{DEADLINE, MAX_MESSAGE, READ_LIMIT};

/// `writd upstream-credential <socket> <operation>`: git's credential helper for an HTTPS
/// upstream. Returns the exit code.
pub fn run(args: &[&str]) -> i32 {
    match helper(args) {
        Ok(()) => 0,
        Err(reason) => {
            eprintln!("writ: {reason}");
            1
        }
    }
}

fn helper(args: &[&str]) -> std::result::Result<(), String> {
    let [socket, operation] = args else {
        return Err("usage: writd upstream-credential <socket> <get|store|erase>".to_owned());
    };
    let mut request = Vec::new();
    std::io::stdin()
        .lock()
        .take(READ_LIMIT)
        .read_to_end(&mut request)
        .map_err(|e| format!("cannot read git's request: {e}"))?;
    // `store` and `erase`: nothing is kept, nothing to forget.
    if *operation != "get" {
        return Ok(());
    }
    if request.len() > MAX_MESSAGE {
        return Err("git's request is too long".to_owned());
    }
    let mut stream = std::os::unix::net::UnixStream::connect(socket)
        .map_err(|e| format!("cannot reach the daemon's credential socket: {e}"))?;
    stream
        .set_read_timeout(Some(DEADLINE))
        .and_then(|()| stream.set_write_timeout(Some(DEADLINE)))
        .map_err(|e| format!("cannot set a deadline: {e}"))?;
    stream
        .write_all(&request)
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
        .map_err(|e| format!("cannot ask the daemon: {e}"))?;
    let mut reply = Zeroizing::new(Vec::new());
    (&mut stream)
        .take(READ_LIMIT)
        .read_to_end(&mut reply)
        .map_err(|e| format!("cannot read the daemon's answer: {e}"))?;
    if reply.is_empty() {
        return Err("the daemon refused to give the upstream token".to_owned());
    }
    if reply.len() > MAX_MESSAGE {
        return Err("the daemon's answer is too long".to_owned());
    }
    let mut out = std::io::stdout().lock();
    out.write_all(&reply)
        .and_then(|()| out.flush())
        .map_err(|e| format!("cannot answer git: {e}"))
}
