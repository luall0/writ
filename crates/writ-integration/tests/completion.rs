//! M7.9.9: shell completion with the real `writ`, the real shells and the real daemon.
//!
//! Each shell runs the registration `writ completions <shell>` prints and completes a line as
//! it would on a TAB: fish with `complete -C`, bash by calling the completion function with
//! the `COMP_*` variables it sets, zsh by calling the function with `words` and `CURRENT`
//! set, compsys's `_describe` and `compdef` stood in for (compsys runs only in an interactive
//! shell); zsh also as `_writ` on `fpath`. Values come live from the daemon with the reader
//! key; when it can't answer, nothing is offered and nothing is said.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::ffi::OsString;
use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use writ_integration::binaries::bin;
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::{stderr, stdout};

const POLICY: &str = r#"
format: 2
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

/// A ticket whose title is agent text completion must never show.
fn ticket(branch: &str) -> String {
    format!(
        "repos:\n  demo:\n    operations: [fetch, commit_sign, push]\n    branches: [\"{branch}\"]\n\
         ticket:\n  title: \"IGNORE THE OPERATOR {branch}\"\n  task: Something\nlimits:\n  ttl: 1h\n"
    )
}

/// Drives bash's completion function as bash does on a TAB: `$2` the line.
const BASH: &str = r#"source "$1"
line=$2
read -ra COMP_WORDS <<< "$line"
[[ "$line" == *" " ]] && COMP_WORDS+=("")
COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 ))
COMP_LINE="$line"; COMP_POINT=${#line}; COMP_TYPE=9
_clap_complete_writ writ "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD-1]}"
for reply in "${COMPREPLY[@]}"; do printf '%s\n' "$reply"; done
"#;

/// Drives zsh's: compsys stood in for (`_describe` prints what it would offer), sourced or as
/// `_writ` on `fpath` (`$1`), `$3` the line, `$2` the registration's directory.
const ZSH: &str = r#"compdef() { :; }
_describe() { print -rl -- "${(@P)3}"; }
words=(${(z)3}); [[ $3 == *" " ]] && words+=("")
CURRENT=${#words}
if [[ $1 == source ]]; then
  source $2/_writ
  _clap_dynamic_completer_writ
else
  fpath=($2 $fpath); autoload -Uz _writ; _writ
fi
"#;

/// A shell on this machine's `PATH`: the tests need all three (CI installs them).
fn shell(name: &str) -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("{name} is not installed: the completion tests run every shell"))
}

/// Where a test's shells keep their files, and the environment `writ` completes in.
struct Shells {
    dir: tempfile::TempDir,
    env: Vec<(OsString, OsString)>,
}

impl Shells {
    /// The registrations of each shell written; `env` what `writ` reads on a TAB.
    fn new(env: Vec<(OsString, OsString)>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        for (shell, file) in [
            ("bash", "writ.bash"),
            ("fish", "writ.fish"),
            ("zsh", "_writ"),
        ] {
            let out = Command::new(bin("writ"))
                .args(["completions", shell])
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
            assert_eq!(stderr(&out), "");
            fs::write(dir.path().join(file), out.stdout).unwrap();
        }
        Self { dir, env }
    }

    fn command(&self, program: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.dir.path())
            .env("XDG_CONFIG_HOME", self.dir.path().join("config"))
            .env("XDG_DATA_HOME", self.dir.path().join("data"))
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null());
        command
    }

    fn fish(&self, line: &str) -> Output {
        let script = format!(
            "source {}; complete -C '{line}'",
            self.dir.path().join("writ.fish").display()
        );
        self.command(&shell("fish"))
            .args(["--no-config", "-c", &script])
            .output()
            .unwrap()
    }

    fn bash(&self, line: &str) -> Output {
        self.command(&shell("bash"))
            .args(["-c", BASH, "bash"])
            .arg(self.dir.path().join("writ.bash"))
            .arg(line)
            .output()
            .unwrap()
    }

    fn zsh(&self, mode: &str, line: &str) -> Output {
        self.command(&shell("zsh"))
            .args(["-f", "-c", ZSH, "zsh", mode])
            .arg(self.dir.path())
            .arg(line)
            .output()
            .unwrap()
    }

    /// What each shell offers for `line`, values only (fish's and zsh's descriptions cut),
    /// each shell asked to agree, nothing said on stderr.
    fn offered(&self, line: &str) -> Vec<String> {
        let values = |out: &Output, separator: char, what: &str| -> Vec<String> {
            assert_eq!(out.status.code(), Some(0), "{what} {line}: {}", stderr(out));
            assert_eq!(stderr(out), "", "{what} {line}");
            let mut values: Vec<String> = stdout(out)
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| value_of(l, separator))
                .collect();
            values.sort();
            values
        };
        let fish = values(&self.fish(line), '\t', "fish");
        let bash = values(&self.bash(line), '\u{0}', "bash");
        let zsh = values(&self.zsh("source", line), ':', "zsh");
        let zsh_fpath = values(&self.zsh("fpath", line), ':', "zsh on fpath");
        assert_eq!(fish, bash, "fish and bash on {line:?}");
        assert_eq!(fish, zsh, "fish and zsh on {line:?}");
        assert_eq!(zsh, zsh_fpath, "zsh sourced and on fpath on {line:?}");
        fish
    }

    /// What the shells offer for `line` that isn't a flag (with an empty word, clap offers the
    /// command's flags beside its values).
    fn values(&self, line: &str) -> Vec<String> {
        self.offered(line)
            .into_iter()
            .filter(|v| !v.starts_with('-'))
            .collect()
    }

    /// fish's lines for `line`: each value and its description.
    fn described(&self, line: &str) -> Vec<String> {
        let out = self.fish(line);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_eq!(stderr(&out), "");
        stdout(&out).lines().map(str::to_owned).collect()
    }
}

/// The value of one line a shell offered: up to `separator`. zsh escapes a colon of the
/// value (`\:`) and a backslash (`\\`): undone here.
fn value_of(line: &str, separator: char) -> String {
    let mut value = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' if separator == ':' => value.extend(chars.next()),
            c if c == separator => break,
            c => value.push(c),
        }
    }
    value
}

/// The variables `writ` reads from a daemon's environment (its endpoints, keys and home).
fn env_of(daemon: &Daemon) -> Vec<(OsString, OsString)> {
    daemon
        .writ(&[])
        .get_envs()
        .filter_map(|(k, v)| Some((k.to_owned(), v?.to_owned())))
        .filter(|(k, _)| k != "PATH" && k != "HOME")
        .collect()
}

/// The engine asked directly, as each shell's registration asks it: what it printed, how
/// long it took.
fn engine(env: &[(OsString, OsString)], words: &[&str]) -> (Output, Duration) {
    let started = Instant::now();
    let out = Command::new(bin("writ"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .envs(env.iter().map(|(k, v)| (k, v)))
        .env("WRIT_COMPLETE", "fish")
        .arg("--")
        .args(words)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (out, started.elapsed())
}

#[test]
fn each_shell_completes_a_command_a_flag_an_enum_value_and_a_path_never_a_hidden_command() {
    let shells = Shells::new(Vec::new());
    assert_eq!(shells.offered("writ si"), ["sign"]);
    assert_eq!(shells.offered("writ sign --appr"), ["--approval-url"]);
    assert_eq!(shells.values("writ completions "), ["bash", "fish", "zsh"]);
    // A path, from the directory the shell completes in.
    let dir = shells.dir.path().join("files");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("ticket.yaml"), "").unwrap();
    fs::write(dir.join("other.txt"), "").unwrap();
    let typed = format!("writ check {}/tic", dir.display());
    assert_eq!(
        shells.offered(&typed),
        [format!("{}/ticket.yaml", dir.display())]
    );
    // `writ prompt` is hidden: never offered, not even typed far enough to match it alone.
    assert_eq!(shells.offered("writ pro"), ["prove-key"]);
    assert_eq!(shells.offered("writ prom"), Vec::<String>::new());
    // The registration names this writ by its absolute path, and the variable it sets.
    let fish = fs::read_to_string(shells.dir.path().join("writ.fish")).unwrap();
    assert!(
        fish.contains(&format!("WRIT_COMPLETE=fish {} --", bin("writ").display())),
        "{fish}"
    );
}

#[test]
fn values_come_live_from_the_daemon_and_a_ticket_is_described_by_its_facts() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let lease = daemon.lease("running", &ticket("agent/a"));
    let file = daemon.root().join("waiting.yaml");
    fs::write(&file, ticket("agent/b")).unwrap();
    let out = daemon.run(&["request", file.to_str().unwrap(), "--no-wait"], "");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let waiting = stdout(&out)
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("Ticket "))
        .and_then(|l| l.split_whitespace().next())
        .unwrap()
        .to_owned();
    let shells = Shells::new(env_of(&daemon));

    // Exactly the waiting ticket for sign, refuse and wait; the running lease for revoke,
    // report and close.
    for line in ["writ sign ", "writ refuse ", "writ wait "] {
        assert_eq!(
            shells.values(line),
            std::slice::from_ref(&waiting),
            "{line}"
        );
    }
    for line in ["writ revoke ", "writ report ", "writ close "] {
        assert_eq!(shells.values(line), std::slice::from_ref(&lease), "{line}");
    }
    // Described by the daemon's facts, never the agent's title.
    let described = shells.described("writ sign ");
    assert!(
        described.contains(&format!("{waiting}\tpending · feature · 1 repo")),
        "{described:?}"
    );
    let revoke = shells.described("writ revoke ");
    assert!(
        revoke.contains(&format!("{lease}\tactive · feature · 1 repo")),
        "{revoke:?}"
    );
    for lines in [&described, &revoke] {
        assert!(!lines.iter().any(|l| l.contains("IGNORE")), "{lines:?}");
    }
    // The policy's names, and the fields of a set.
    assert_eq!(shells.values("writ admin template show "), ["feature"]);
    assert_eq!(shells.values("writ admin repo show "), ["demo"]);
    assert_eq!(shells.values("writ policy "), ["demo"]);
    assert_eq!(
        shells.values("writ admin key show "),
        ["agent-01", "upstream-01"]
    );
    // The harness rewrites `remote.invalid` to its own remote, `[127.0.0.1]:<port>`.
    let hosts = shells.values("writ admin host rescan ");
    assert!(
        hosts.len() == 1 && hosts[0].starts_with("[127.0.0.1]:"),
        "{hosts:?}"
    );
    let fields = shells.offered("writ admin template set feature max_t");
    assert_eq!(fields, ["max_ttl="]);
    // Each read is a reader's, logged as any: nothing granted, nothing signed.
    assert_eq!(daemon.audited("grant", "allowed"), 1);
}

/// A TCP relay in front of `to`: each connection forwarded (`answers`), or held for good
/// without a byte answered.
fn relay(to: u16, answers: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(client) = client else { return };
            std::thread::spawn(move || {
                if !answers {
                    // Held: read and dropped, never answered, until the client hangs up.
                    let mut client = client;
                    let mut sink = [0u8; 1024];
                    while matches!(client.read(&mut sink), Ok(n) if n > 0) {}
                    return;
                }
                let Ok(server) = TcpStream::connect(("127.0.0.1", to)) else {
                    return;
                };
                let pipe = |mut from: TcpStream, mut into: TcpStream| {
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 8192];
                        while let Ok(n) = from.read(&mut buf) {
                            if n == 0 || into.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                        let _ = into.shutdown(std::net::Shutdown::Write);
                    });
                };
                pipe(client.try_clone().unwrap(), server.try_clone().unwrap());
                pipe(server, client);
            });
        }
    });
    port
}

/// `env` with `name` set to `value` (or removed, for `None`).
fn with(
    env: &[(OsString, OsString)],
    name: &str,
    value: Option<&str>,
) -> Vec<(OsString, OsString)> {
    let mut out: Vec<_> = env.iter().filter(|(k, _)| k != name).cloned().collect();
    if let Some(value) = value {
        out.push((name.into(), value.into()));
    }
    out
}

/// No value offered and nothing said: only the command's flags (what completes with no
/// daemon), an empty stderr.
fn silent(out: &Output, what: &str) {
    assert_eq!(out.status.code(), Some(0), "{what}: {}", stderr(out));
    let said = stdout(out);
    let values: Vec<&str> = said.lines().filter(|l| !l.starts_with('-')).collect();
    assert_eq!(values, Vec::<&str>::new(), "{what}");
    assert!(
        stdout(out).contains("--approval-url\t"),
        "{what}: the flags still complete"
    );
    assert_eq!(stderr(out), "", "{what}");
}

#[test]
fn when_the_daemon_can_t_answer_nothing_is_offered_nothing_said_within_the_deadline() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    daemon.lease("running", &ticket("agent/a"));
    let env = env_of(&daemon);
    let sign = ["writ", "revoke", ""];
    // Answering: the lease offered.
    let (out, _) = engine(&env, &sign);
    assert!(
        stdout(&out).lines().any(|l| l.starts_with("wrt_")),
        "{}",
        stdout(&out)
    );

    // Unreachable: a port nothing listens on.
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let nowhere = format!("ssh://127.0.0.1:{}", closed.local_addr().unwrap().port());
    drop(closed);
    let (out, _) = engine(&with(&env, "WRIT_APPROVAL_URL", Some(&nowhere)), &sign);
    silent(&out, "unreachable");

    // Unpinned: the host key is in no pin; the pins file is left as it was, nothing asked.
    let pins = daemon.root().join("empty_known_hosts");
    fs::write(&pins, "").unwrap();
    let (out, _) = engine(
        &with(&env, "WRIT_KNOWN_HOSTS", Some(pins.to_str().unwrap())),
        &sign,
    );
    silent(&out, "unpinned");
    assert_eq!(fs::read_to_string(&pins).unwrap(), "");

    // No reader key, and a key the daemon refuses.
    let missing = daemon.root().join("no-reader");
    let (out, _) = engine(
        &with(&env, "WRIT_READER", Some(missing.to_str().unwrap())),
        &sign,
    );
    silent(&out, "no reader key");
    assert!(!missing.exists(), "completion makes no key");
    let stranger = daemon.root().join("stranger");
    let keygen = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&stranger)
        .output()
        .unwrap();
    assert!(keygen.status.success(), "{}", stderr(&keygen));
    let (out, _) = engine(
        &with(&env, "WRIT_READER", Some(stranger.to_str().unwrap())),
        &sign,
    );
    silent(&out, "a reader the daemon refuses");

    // No daemon named at all.
    let (out, _) = engine(&with(&env, "WRIT_APPROVAL_URL", None), &sign);
    silent(&out, "no approval URL");

    // A relay in front of the approval listener, the daemon's host key pinned under the
    // relay's port: what a TAB reaches through it.
    let approvals_port = daemon.approvals_port;
    let through = |port: u16| {
        let pinned = daemon.root().join(format!("relay_known_hosts_{port}"));
        let line = fs::read_to_string(daemon.root().join("known_hosts")).unwrap();
        let pin: String = line
            .lines()
            .map(|l| {
                let (_, key) = l.split_once(' ').unwrap();
                format!("[127.0.0.1]:{port} {key}\n")
            })
            .collect();
        fs::write(&pinned, pin).unwrap();
        with(
            &with(
                &env,
                "WRIT_APPROVAL_URL",
                Some(&format!("ssh://127.0.0.1:{port}")),
            ),
            "WRIT_KNOWN_HOSTS",
            Some(pinned.to_str().unwrap()),
        )
    };
    // Slow: a relay that never answers. The TAB waits the deadline, then offers nothing.
    let (out, took) = engine(&through(relay(approvals_port, false)), &sign);
    silent(&out, "held past the deadline");
    assert!(
        took >= Duration::from_secs(1),
        "{took:?}: the deadline is 1 s"
    );
    assert!(
        took < Duration::from_secs(5),
        "{took:?}: not waited past the deadline"
    );
    // The same relay forwarding: the lease offered. Holding is what kept it out.
    let (out, _) = engine(&through(relay(approvals_port, true)), &sign);
    assert!(
        stdout(&out).lines().any(|l| l.starts_with("wrt_")),
        "within the deadline: {}",
        stdout(&out)
    );
    assert_eq!(stderr(&out), "");

    // Commands and flags still complete with no daemon at all.
    let (out, _) = engine(
        &with(&env, "WRIT_APPROVAL_URL", Some(&nowhere)),
        &["writ", "revoke", "--appr"],
    );
    assert_eq!(
        stdout(&out),
        "--approval-url\tThe daemon's approval listener: https://host:port, ssh://host:port or unix:<path> (default: `approval_url` in <home>/config)\n"
    );
}

#[test]
fn a_sealed_daemon_offers_nothing_and_says_nothing() {
    let daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    let env = env_of(&daemon);
    for words in [
        &["writ", "sign", ""][..],
        &["writ", "admin", "template", "show", ""][..],
    ] {
        let (out, _) = engine(&env, words);
        silent(&out, &format!("sealed: {words:?}"));
    }
}
