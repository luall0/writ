//! A command on a pseudo-terminal: what asks on a terminal only (`writ admin host add`'s scan,
//! the guided flows) runs for real, its answers typed ahead (the terminal holds them, one per
//! line, for each question in turn). The same on Linux and macOS, unlike `script`.

use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::process::{Command, ExitStatus, Stdio};

use rustix::fs::{Mode, OFlags};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

/// Runs `command` with a terminal as its stdin, stdout and stderr, `answers` typed one per
/// line: its exit status and what it showed (the streams merged, rows ending in `\r\n`).
pub fn on_terminal(mut command: Command, answers: &[&str]) -> (ExitStatus, String) {
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let name = ptsname(&master, Vec::new()).unwrap();
    let slave: OwnedFd = rustix::fs::open(
        name.as_c_str(),
        OFlags::RDWR | OFlags::NOCTTY,
        Mode::empty(),
    )
    .unwrap();
    let mut child = command
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave))
        .spawn()
        .unwrap();
    // Drop the command (and its copies of the terminal's end): the reads end with the child.
    drop(command);
    let mut writer = std::fs::File::from(master.try_clone().unwrap());
    let typed: String = answers.iter().map(|a| format!("{a}\n")).collect();
    writer.write_all(typed.as_bytes()).unwrap();
    let mut reader = std::fs::File::from(master);
    let shown = std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        // Ends at end of file or EIO (Linux, once no one holds the terminal's other end).
        while let Ok(n) = reader.read(&mut chunk) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
        }
        String::from_utf8_lossy(&out).into_owned()
    });
    let status = child.wait().unwrap();
    drop(writer);
    (status, shown.join().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_read_one_per_question_on_a_terminal() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "test -t 0 && echo tty; read a; echo \"got $a\"; read b; echo \"then $b\"",
        ]);
        let (status, shown) = on_terminal(command, &["y", "second"]);
        assert!(status.success());
        assert!(shown.contains("tty\r\n"), "{shown:?}");
        assert!(shown.contains("got y\r\n"), "{shown:?}");
        assert!(shown.contains("then second\r\n"), "{shown:?}");
    }
}
