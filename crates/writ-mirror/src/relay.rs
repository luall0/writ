//! `writd upstream-ssh <max bytes> <ssh> <args…>`: the program git runs as its ssh for
//! upstream. It runs ssh and passes upstream's bytes through to git, counting them: past the
//! cap it kills ssh and fails, so a sync never takes more than `mirrors.max_fetch` from
//! upstream (git itself has no limit on what a fetch takes in). It runs in its own process,
//! started by git, which shows its stderr in the daemon's captured output.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

/// What the relay says when upstream sent too much; the daemon recognizes it in git's stderr.
pub const TOO_LARGE: &str = "writ: upstream sent more than";

/// Runs the relay with its arguments (after `upstream-ssh`). Returns the exit code.
pub fn run(args: &[&str]) -> i32 {
    match relay(args) {
        Ok(code) => code,
        Err(reason) => {
            eprintln!("writ: {reason}");
            1
        }
    }
}

fn relay(args: &[&str]) -> Result<i32, String> {
    let [max, ssh, ssh_args @ ..] = args else {
        return Err("usage: writd upstream-ssh <max bytes> <ssh> <args…>".to_owned());
    };
    let max: u64 = max.parse().map_err(|_| "invalid byte cap".to_owned())?;
    if !ssh.starts_with('/') {
        return Err("ssh must be named by its absolute path".to_owned());
    }
    let mut child = Command::new(ssh)
        .args(ssh_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("cannot run ssh: {e}"))?;
    let mut from = child.stdout.take().ok_or("no pipe from ssh")?;
    let mut to = std::io::stdout().lock();
    let mut total: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                let _ = child.kill();
                return Err(format!("cannot read from ssh: {e}"));
            }
        };
        total = total.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if total > max {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "{} {max} bytes",
                TOO_LARGE.trim_start_matches("writ: ")
            ));
        }
        let chunk = buf.get(..n).unwrap_or_default();
        if to.write_all(chunk).and_then(|()| to.flush()).is_err() {
            // git hung up: nothing more to relay.
            let _ = child.kill();
            break;
        }
    }
    let status = child
        .wait()
        .map_err(|e| format!("cannot wait for ssh: {e}"))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_arguments_are_checked() {
        assert!(relay(&[]).unwrap_err().starts_with("usage:"));
        assert_eq!(relay(&["x", "/bin/echo"]).unwrap_err(), "invalid byte cap");
        assert_eq!(
            relay(&["10", "ssh"]).unwrap_err(),
            "ssh must be named by its absolute path"
        );
    }

    #[test]
    fn the_cap_is_held_on_both_sides() {
        // `printf 12345` is 5 bytes: allowed at 5, refused at 4.
        assert_eq!(relay(&["5", "/usr/bin/printf", "12345"]), Ok(0));
        assert_eq!(
            relay(&["4", "/usr/bin/printf", "12345"]),
            Err("upstream sent more than 4 bytes".to_owned())
        );
        // What `run` prints is what the daemon looks for.
        let printed = format!(
            "writ: {}",
            relay(&["4", "/usr/bin/printf", "12345"]).unwrap_err()
        );
        assert!(printed.starts_with(TOO_LARGE), "{printed}");
    }

    #[test]
    fn ssh_s_exit_code_is_passed_on() {
        assert_eq!(relay(&["10", "/bin/sh", "-c", "exit 7"]), Ok(7));
    }
}
