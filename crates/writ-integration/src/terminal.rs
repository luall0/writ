//! A command on a pseudo-terminal: what asks on a terminal only (`writ admin host add`'s scan,
//! the guided flows) runs for real, its answers typed ahead (the terminal holds them, one per
//! line, for each question in turn). The same on Linux and macOS, unlike `script`.

use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::process::{Command, ExitStatus, Stdio};

use rustix::fs::{Mode, OFlags};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

/// Runs `command` with a terminal as its stdin, stdout and stderr, `answers` typed one per
/// line: its exit status and what it showed (the streams merged, rows ending in `\r\n`). For
/// what reads lines (the installer's `read`); `writ`'s questions take [`on_writ_terminal`].
pub fn on_terminal(command: Command, answers: &[&str]) -> (ExitStatus, String) {
    run(command, answers, "\n", false)
}

/// [`on_terminal`] for `writ`, whose questions are widgets reading keys in raw mode (M7.9.5):
/// the terminal keeps a typed `\r` as it is (no `ICRNL`), and each answer ends with `\r`,
/// Enter there (a `\n` is Ctrl-J). Answers typed before a question starts wait as typed, so
/// the run never depends on when each one comes up. On a select, an answer is the option's
/// name (it filters the options to it); empty, Enter: the first option. Drawn without colour
/// (`NO_COLOR`) on a terminal of 120 columns, so what it shows reads the same in every run.
pub fn on_writ_terminal(mut command: Command, answers: &[&str]) -> (ExitStatus, String) {
    command.env("NO_COLOR", "1");
    run(command, answers, "\r", true)
}

fn run(
    mut command: Command,
    answers: &[&str],
    enter: &str,
    raw_enter: bool,
) -> (ExitStatus, String) {
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
    if raw_enter {
        let mut modes = rustix::termios::tcgetattr(&slave).unwrap();
        modes.input_modes.remove(rustix::termios::InputModes::ICRNL);
        rustix::termios::tcsetattr(&slave, rustix::termios::OptionalActions::Now, &modes).unwrap();
        let size = rustix::termios::Winsize {
            ws_row: 40,
            ws_col: 120,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        rustix::termios::tcsetwinsize(&slave, size).unwrap();
    }
    let mut child = command
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave))
        .spawn()
        .unwrap();
    // Drop the command (and its copies of the terminal's end): the reads end with the child.
    drop(command);
    let mut writer = std::fs::File::from(master.try_clone().unwrap());
    let typed: String = answers.iter().map(|a| format!("{a}{enter}")).collect();
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
