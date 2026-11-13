//! The stack's containers, reached with `docker exec` through the Docker socket the runner
//! container is given. A [`Host`] is one user on one container (the operator on `writd`, an
//! agent or the approver on `agent`): its commands run with `sh -c` in its home, after its
//! environment file when it has one (like `source dev/client.env`).
//!
//! Every command is bounded by [`TIMEOUT`]: a command that hangs fails its scenario instead
//! of the pipeline. Waiting for something that gives no signal (a container's service coming
//! up) is a bounded poll ([`eventually`]).

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdout, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The longest one command may take (a clone, a push through the daemon to Forgejo).
pub const TIMEOUT: Duration = Duration::from_secs(180);

/// The compose project `make e2e` started (`tool/e2e.sh`).
pub fn project() -> String {
    std::env::var("WRIT_E2E_PROJECT").unwrap_or_else(|_| {
        panic!("WRIT_E2E_PROJECT is not set: the scenarios run with `make e2e`")
    })
}

/// One of the stack's containers, by its compose service.
#[derive(Debug, Clone)]
pub struct Container {
    name: String,
}

impl Container {
    pub fn of(service: &str) -> Self {
        Self {
            name: format!("{}-{service}-1", project()),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// `docker <verb> <container>` (stop, start, restart), which must succeed.
    pub fn lifecycle(&self, verb: &str) {
        let out = finish(
            Command::new("docker")
                .args([verb, &self.name])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        assert_eq!(
            out.status.code(),
            Some(0),
            "docker {verb} {}: {}",
            self.name,
            stderr(&out)
        );
    }

    /// What the container wrote on its standard streams so far (`docker logs`), both merged.
    pub fn logs(&self) -> String {
        let out = finish(
            Command::new("docker")
                .args(["logs", &self.name])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        assert_eq!(out.status.code(), Some(0), "docker logs {}", self.name);
        format!("{}{}", stdout(&out), stderr(&out))
    }

    /// `docker exec` as `user` in `workdir`: the command line, ready to spawn.
    fn exec(&self, user: &str, workdir: &str, script: &str) -> Command {
        let mut command = Command::new("docker");
        command
            .args([
                "exec", "-i", "-u", user, "-w", workdir, &self.name, "sh", "-c", script,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Runs `script` as `user` (root's commands on Forgejo's container), to the end.
    pub fn run_as(&self, user: &str, script: &str) -> Output {
        let mut child = self.exec(user, "/", script).spawn().unwrap();
        drop(child.stdin.take());
        finish(child)
    }
}

/// One user on one container.
#[derive(Debug, Clone)]
pub struct Host {
    pub container: Container,
    pub user: String,
    /// Where its commands run (its home, or a scenario's directory in it).
    pub dir: String,
    /// The file its commands source first (its `WRIT_*` settings), relative to `dir`.
    pub env: Option<String>,
}

impl Host {
    pub fn new(service: &str, user: &str, dir: &str) -> Self {
        Self {
            container: Container::of(service),
            user: user.to_owned(),
            dir: dir.to_owned(),
            env: None,
        }
    }

    /// The same user, in another directory with another environment file.
    pub fn with(&self, dir: &str, env: Option<&str>) -> Self {
        Self {
            dir: dir.to_owned(),
            env: env.map(str::to_owned),
            ..self.clone()
        }
    }

    fn script(&self, script: &str) -> String {
        match &self.env {
            Some(env) => format!(". ./{env} && {script}"),
            None => script.to_owned(),
        }
    }

    /// Runs `script` to the end, with `stdin`.
    pub fn run_with(&self, script: &str, stdin: &[u8]) -> Output {
        self.run_within(script, stdin, TIMEOUT)
    }

    /// The same, for a command that may take longer than [`TIMEOUT`] (a wait for an expiry).
    pub fn run_within(&self, script: &str, stdin: &[u8], limit: Duration) -> Output {
        let mut child = self
            .container
            .exec(&self.user, &self.dir, &self.script(script))
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let bytes = stdin.to_vec();
        // Written from another thread: a command that answers before reading all of its
        // input must not block this one.
        std::thread::spawn(move || {
            let _ = input.write_all(&bytes);
        });
        finish_within(child, limit)
    }

    /// Runs `script` to the end, with nothing on stdin.
    pub fn run(&self, script: &str) -> Output {
        self.run_with(script, b"")
    }

    /// `command` on a terminal (`script`), `answers` typed one per line, which must exit 0:
    /// what it showed (the streams merged, rows ending in `\r\n`).
    pub fn on_terminal(&self, command: &str, answers: &[&str]) -> String {
        self.exits_on_terminal(command, answers, 0)
    }

    /// [`Host::on_terminal`], the command exiting with `code` (6: answered no, nothing
    /// signed; 1: refused). The code is always read: a command that fails never passes for
    /// one that showed the right text (the review after M7.6, T-2).
    pub fn exits_on_terminal(&self, command: &str, answers: &[&str], code: i32) -> String {
        assert!(!command.contains('\''), "{command}");
        let typed: String = answers.iter().map(|a| format!("{a}\n")).collect();
        let out = self.run_with(
            &format!("script -qec '{command}' /dev/null"),
            typed.as_bytes(),
        );
        assert_eq!(out.status.code(), Some(code), "{command}: {}", stdout(&out));
        stdout(&out)
    }

    /// Runs `script`, which must exit 0; its stdout.
    pub fn ok(&self, script: &str) -> String {
        let out = self.run(script);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}@{}: {script}\n--- stdout\n{}--- stderr\n{}",
            self.user,
            self.container.name(),
            stdout(&out),
            stderr(&out)
        );
        stdout(&out)
    }

    /// Writes `contents` to `path` (relative to its directory), with `mode`.
    pub fn write(&self, path: &str, contents: &str, mode: &str) {
        let out = self.run_with(
            &format!("umask 077 && cat > {path} && chmod {mode} {path}"),
            contents.as_bytes(),
        );
        assert_eq!(
            out.status.code(),
            Some(0),
            "writing {path}: {}",
            stderr(&out)
        );
    }

    /// A file's contents (relative to its directory).
    pub fn read(&self, path: &str) -> String {
        self.ok(&format!("cat {path}"))
    }

    /// Starts `script` and returns once it printed its first line (`writ request` naming the
    /// ticket it submitted), with the process still running.
    pub fn start(&self, script: &str) -> Running {
        let mut child = self
            .container
            .exec(&self.user, &self.dir, &self.script(script))
            .spawn()
            .unwrap();
        drop(child.stdin.take());
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let (lines, first) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut stdout = stdout;
            let mut line = String::new();
            let _ = stdout.read_line(&mut line);
            let _ = lines.send(line);
            stdout
        });
        let first = first
            .recv_timeout(TIMEOUT)
            .expect("the command printed nothing");
        let stdout = reader.join().unwrap();
        Running {
            child,
            stdout,
            first,
        }
    }
}

/// A command still running, after its first line.
pub struct Running {
    child: Child,
    stdout: BufReader<ChildStdout>,
    pub first: String,
}

impl Running {
    /// Waits for it to end: its status, its whole stdout and its stderr.
    pub fn finish(self) -> (ExitStatus, String, String) {
        let Self {
            child,
            mut stdout,
            first,
        } = self;
        let (done, ended) = mpsc::channel();
        std::thread::spawn(move || {
            let mut rest = String::new();
            let _ = stdout.read_to_string(&mut rest);
            let _ = done.send((rest, child.wait_with_output()));
        });
        let (rest, output) = ended
            .recv_timeout(TIMEOUT)
            .expect("the command did not end");
        let output = output.unwrap();
        (output.status, first + &rest, stderr(&output))
    }

    /// Whether it ends by itself within `limit` (a session the daemon drops). Asserting it
    /// doesn't only says it was still running when the scenario stopped looking.
    pub fn ends_within(&mut self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            if self.child.try_wait().unwrap().is_some() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            // poll: another process's exit gives this one no signal; bounded by `deadline`.
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Ends it (`docker exec`'s client; the command in the container sees its input close).
    pub fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Waits for a process to end, within [`TIMEOUT`].
pub fn finish(child: Child) -> Output {
    finish_within(child, TIMEOUT)
}

/// Waits for a process to end, within `limit`.
pub fn finish_within(child: Child, limit: Duration) -> Output {
    let (done, ended) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(child.wait_with_output());
    });
    ended
        .recv_timeout(limit)
        .expect("the command did not end in time")
        .unwrap()
}

/// Waits until `ready` holds, checking every 250 ms, for at most `limit`; fails the scenario
/// past it. For what gives no signal: a service coming up in another container.
pub fn eventually(what: &str, limit: Duration, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "{what}: not ready after {limit:?}"
        );
        // poll: another container's state gives the runner no signal; bounded by `deadline`.
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// A command's stdout, as text.
pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A command's stderr, as text.
pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}
