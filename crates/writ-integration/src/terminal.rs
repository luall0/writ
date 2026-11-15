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
/// name (it filters the options to it); empty, Enter: the first option. An answer ending in
/// `\n` is a line for what reads lines (a passphrase `writd init` asks), typed as it is. Drawn
/// without colour
/// (`NO_COLOR`) on a terminal of 120 columns, so what it shows reads the same in every run.
pub fn on_writ_terminal(mut command: Command, answers: &[&str]) -> (ExitStatus, String) {
    command.env("NO_COLOR", "1");
    run(command, answers, "\r", true)
}

/// How long a command may still run after its last answer before it is killed.
const ENDS: std::time::Duration = std::time::Duration::from_secs(60);

/// How long an answer waits for the question before it to be answered.
const ANSWERED: std::time::Duration = std::time::Duration::from_secs(30);

/// How many questions `shown` shows answered: a line starting `> ` (writ's answered prefix
/// without colour, which nothing else draws at a line's start).
fn answered(shown: &[u8]) -> usize {
    let text = String::from_utf8_lossy(shown);
    text.split(['\n', '\r'])
        .filter(|line| strip(line).starts_with("> "))
        .count()
}

/// A line without the terminal's control sequences (cursor moves, clears).
fn strip(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // CSI: ESC [ … final byte in @..~
            if chars.peek() == Some(&'[') {
                chars.next();
                for f in chars.by_ref() {
                    if ('@'..='~').contains(&f) {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
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
    // Its own process group: a command still asking past ENDS is killed whole, the question
    // it started included (it holds the terminal open).
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave))
        .spawn()
        .unwrap();
    // Drop the command (and its copies of the terminal's end): the reads end with the child.
    drop(command);
    let mut writer = std::fs::File::from(master.try_clone().unwrap());
    let mut reader = std::fs::File::from(master);
    // What it shows, as it comes: the answers below wait on it.
    let seen = std::sync::Arc::new((
        std::sync::Mutex::new(Vec::<u8>::new()),
        std::sync::Condvar::new(),
    ));
    let shown = {
        let seen = seen.clone();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            // Ends at end of file or EIO (Linux, once no one holds the terminal's other end).
            while let Ok(n) = reader.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let (out, more) = &*seen;
                out.lock().unwrap().extend_from_slice(&chunk[..n]);
                more.notify_all();
            }
            let (out, more) = &*seen;
            let done = String::from_utf8_lossy(&out.lock().unwrap()).into_owned();
            // Nothing more will come: a writer still waiting gives up now.
            *out.lock().unwrap() = Vec::new();
            more.notify_all();
            done
        })
    };
    if raw_enter {
        // One answer at a time: each question may be a process of its own (the installer
        // runs `writ prompt` per question), which would read every answer typed ahead and
        // exit with them. The next answer is typed once the one before shows its answered
        // line (`> question answer`): a signal, never a sleep. Given up past ANSWERED, or
        // once the command ends (what it showed then says why).
        // The questions answered before each answer: the widgets' (a line answer, ending in
        // `\n`, draws no answered line).
        let mut widgets_before = 0;
        for answer in answers {
            let line = answer.ends_with('\n');
            let i = widgets_before;
            if !line {
                widgets_before += 1;
            }
            if i > 0 {
                let (out, more) = &*seen;
                let deadline = std::time::Instant::now() + ANSWERED;
                let mut shown_so_far = out.lock().unwrap();
                loop {
                    if answered(&shown_so_far) >= i {
                        break;
                    }
                    let left = deadline.saturating_duration_since(std::time::Instant::now());
                    if left.is_zero() || child.try_wait().ok().flatten().is_some() {
                        break;
                    }
                    shown_so_far = more
                        .wait_timeout(
                            shown_so_far,
                            left.min(std::time::Duration::from_millis(200)),
                        )
                        .unwrap()
                        .0;
                }
            }
            let typed = if line {
                (*answer).to_owned()
            } else {
                format!("{answer}{enter}")
            };
            if writer.write_all(typed.as_bytes()).is_err() {
                break;
            }
        }
        // A command still asking past ENDS after the last answer is killed: what it showed
        // then says which question had no answer (a guard, never a timing the test relies on).
        let (out, more) = &*seen;
        let deadline = std::time::Instant::now() + ENDS;
        let mut guard = out.lock().unwrap();
        while child.try_wait().ok().flatten().is_none() {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                let _ = Command::new("kill")
                    .args(["-KILL", "--", &format!("-{}", child.id())])
                    .status();
                let _ = child.kill();
                break;
            }
            guard = more
                .wait_timeout(guard, left.min(std::time::Duration::from_millis(200)))
                .unwrap()
                .0;
        }
        drop(guard);
    } else {
        let typed: String = answers.iter().map(|a| format!("{a}{enter}")).collect();
        writer.write_all(typed.as_bytes()).unwrap();
    }
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
