//! The installer (M7): `deploy/install.sh` with the `local` setup, against a fake root (every
//! system path under a directory, `WRIT_INSTALL_ROOT`) with the system tools that need root
//! stubbed on PATH (`sudo`, `dscl`, `dseditgroup`, `launchctl`, `codesign`, `chown`), and the
//! real binaries (`writd init` makes the keystore for real). The real install on the Mac is a
//! manual check (docs/guides/manual-checks.md). Runs on Linux too (`WRIT_INSTALL_OS` stands
//! for macOS): the frame and the setup are POSIX sh.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use writ_crypto::keys::{KeyKind, generate};
use writ_integration::terminal::on_terminal;
use writ_integration::{stderr, stdout};

/// The keystore's passphrase, typed twice (chosen, confirmed).
const PASSPHRASE: &str = "an installer test passphrase\nan installer test passphrase\n";

/// Logs each call (`<tool> <args>`), failing when `STUB_FAIL` names the tool.
const LOGGING: &str = r#"#!/bin/sh
name=$(basename "$0")
{ printf '%s' "$name"; printf ' %s' "$@"; printf '\n'; } >> "$WRIT_INSTALL_ROOT/.calls"
[ "${STUB_FAIL:-}" = "$name" ] && { echo "$name: failing (stub)" >&2; exit 1; }
exit 0
"#;

/// The directory service, as a file of `<record> [<attribute> <value>]` lines.
const DSCL: &str = r#"#!/bin/sh
db="$WRIT_INSTALL_ROOT/.dscl"; touch "$db"
{ printf 'dscl'; printf ' %s' "$@"; printf '\n'; } >> "$WRIT_INSTALL_ROOT/.calls"
shift
case $1 in
  -list) awk -v dir="$2/" -v attr="$3" '$2 == attr && index($1, dir) == 1 { sub(dir, "", $1); print $1, $3 }' "$db" ;;
  -read) grep -q "^$2\( \|$\)" "$db" ;;
  -create) shift; printf '%s\n' "$*" >> "$db" ;;
  -delete) grep -v "^$2\( \|$\)" "$db" > "$db.new" || true; mv "$db.new" "$db" ;;
esac
"#;

/// `sudo [-u <user>] <command>`: the command, as the test's user.
const SUDO: &str = "#!/bin/sh\n[ \"$1\" = -u ] && shift 2\nexec \"$@\"\n";

/// A Mac's directories, in a fake root, with the stubs and an approval key.
struct Fake {
    _dir: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    stubs: PathBuf,
    approver: PathBuf,
}

impl Fake {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();
        let (root, home, stubs) = (base.join("root"), base.join("home"), base.join("stubs"));
        for system in [
            "etc/paths.d",
            "var/db",
            "Library/LaunchDaemons",
            "Library/Logs",
            "Library/Application Support",
        ] {
            fs::create_dir_all(root.join(system)).unwrap();
        }
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&stubs).unwrap();
        let script = |name: &str, text: &str| {
            let path = stubs.join(name);
            fs::write(&path, text).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        };
        script("sudo", SUDO);
        script("dscl", DSCL);
        for tool in ["dseditgroup", "launchctl", "codesign", "chown"] {
            script(tool, LOGGING);
        }
        let approver = base.join("approver.pub");
        let key = generate(KeyKind::Ed25519).unwrap();
        fs::write(
            &approver,
            format!("{}\n", key.public_key().to_openssh().unwrap()),
        )
        .unwrap();
        Self {
            _dir: dir,
            root,
            home,
            stubs,
            approver,
        }
    }

    /// `deploy/install.sh <action>` in the fake root, with `env` on top.
    fn command(&self, action: &str, env: &[(&str, &str)]) -> Command {
        let deploy = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/install.sh");
        let binaries = writ_integration::binaries::bin("writd")
            .parent()
            .unwrap()
            .to_path_buf();
        let mut command = Command::new("/bin/sh");
        command
            .arg(deploy)
            .arg(action)
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", self.stubs.display()),
            )
            .env("HOME", &self.home)
            .env("WRIT_INSTALL_ROOT", &self.root)
            .env("WRIT_INSTALL_OS", "Darwin")
            .env("WRIT_INSTALL_BINARIES", binaries)
            .envs(env.iter().copied());
        command
    }

    /// The command with `stdin`, no terminal.
    fn run(&self, action: &str, env: &[(&str, &str)], stdin: &str) -> Output {
        let mut child = self
            .command(action, env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        writ_integration::process::finish(child)
    }

    fn install(&self, env: &[(&str, &str)]) -> Output {
        let approver = self.approver.display().to_string();
        let mut all = vec![("SETUP", "local"), ("APPROVER", approver.as_str())];
        all.extend_from_slice(env);
        self.run("install", &all, PASSPHRASE)
    }

    /// Every path under the fake root (relative, sorted), the stubs' own files left out.
    fn tree(&self) -> Vec<String> {
        listing(&self.root)
            .into_iter()
            .filter(|p| p != ".calls" && p != ".dscl" && !p.starts_with(".dscl"))
            .collect()
    }

    fn home(&self) -> Vec<String> {
        listing(&self.home)
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.root.join(".calls")).unwrap_or_default()
    }

    fn directory(&self) -> String {
        fs::read_to_string(self.root.join(".dscl")).unwrap_or_default()
    }

    fn manifest(&self) -> PathBuf {
        self.root
            .join("Library/Application Support/Writ/install.manifest")
    }

    /// `p` (a system path) under the fake root.
    fn at(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }

    /// A shown text with the fake root's and home's paths as `/` and `~`.
    fn shown(&self, text: &str) -> String {
        text.replace(&self.root.display().to_string(), "")
            .replace(&self.home.display().to_string(), "~")
    }
}

fn listing(base: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            out.push(path.strip_prefix(base).unwrap().display().to_string());
            if entry.file_type().unwrap().is_dir() {
                walk(base, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(base, base, &mut out);
    out.sort();
    out
}

fn ok(out: &Output) -> String {
    assert!(out.status.success(), "{}{}", stdout(out), stderr(out));
    stdout(out)
}

fn refused(out: &Output, words: &str) {
    assert_eq!(out.status.code(), Some(1), "{}{}", stdout(out), stderr(out));
    assert!(
        stderr(out).contains(words),
        "{words}\nnot in:\n{}",
        stderr(out)
    );
}

#[test]
fn the_dry_run_lists_every_change_and_makes_none_and_a_setup_is_picked_from_the_offered() {
    let fake = Fake::new();
    let before = fake.tree();
    let out = fake.install(&[("DRY_RUN", "1")]);
    let said = fake.shown(&ok(&out));
    for change in [
        "Dry run: these are the changes; none is made.",
        "    (root) dscl . -create /Users/_writd UniqueID 450",
        "    (root) dseditgroup -o edit -a ",
        "    (root) codesign --force --sign - --options runtime --identifier dev.writ.writd /opt/writ/bin/writd",
        "    (root) write /etc/paths.d/writ (0644, root:wheel):\n        /opt/writ/bin",
        "    (root) install -d -m 0750 /Library/Application Support/Writ/run",
        "    (_writd) /opt/writ/bin/writd init /var/db/writ/writd.yaml",
        "    (root) launchctl bootstrap system /Library/LaunchDaemons/dev.writ.writd.plist",
        "        url = unix:/Library/Application Support/Writ/run/agents.sock",
    ] {
        assert!(said.contains(change), "{change:?} not in:\n{said}");
    }
    assert_eq!(fake.tree(), before, "nothing made");
    assert_eq!(fake.home(), Vec::<String>::new());
    assert!(!fake.calls().contains("-create"), "{}", fake.calls());

    // A setup this OS doesn't offer, none at all without a terminal, no approver: refused.
    refused(
        &fake.run("install", &[("SETUP", "detached")], ""),
        "setup detached is not offered on Darwin (offered: local )",
    );
    refused(
        &fake.run("install", &[], ""),
        "SETUP=<name> is needed without a terminal (offered on Darwin: local )",
    );
    refused(
        &fake.run("install", &[("SETUP", "local")], ""),
        "APPROVER=<your approval key's .pub> is needed",
    );
    refused(
        &fake.run(
            "install",
            &[("WRIT_INSTALL_OS", "Linux"), ("SETUP", "local")],
            "",
        ),
        "no setup for Linux in this build",
    );
    // On a terminal, the setup is asked.
    let mut asked = fake.command("install", &[("DRY_RUN", "1")]);
    asked.env("APPROVER", &fake.approver);
    let (status, shown) = on_terminal(asked, &["local"]);
    assert!(status.success(), "{shown}");
    assert!(
        shown.contains("Which setup? Offered on Darwin: local"),
        "{shown}"
    );
    assert_eq!(fake.tree(), before);
}

#[test]
fn an_install_upgrades_and_uninstalls_leaving_the_mac_as_before() {
    let fake = Fake::new();
    let before = fake.tree();
    let said = fake.shown(&ok(&fake.install(&[])));
    assert!(said.contains("keystore made: /var/db/writ/keys"), "{said}");
    assert!(said.contains("Installed. What is left:"), "{said}");
    let manifest = fs::read_to_string(fake.manifest()).unwrap();
    assert_eq!(
        fake.shown(&manifest),
        "setup local-macos\ngroup _writd\nuser _writd\ngroup _writ\nmember _writ ".to_owned()
            + &whoami()
            + "\ndir /opt\ndir /opt/writ\ndir /opt/writ/bin\nfile /opt/writ/bin/writd\n\
               file /opt/writ/bin/writ\nfile /opt/writ/bin/writ-sign\nfile /etc/paths.d/writ\n\
               tree /Library/Application Support/Writ/run\ntree /Library/Logs/Writ\n\
               userdir ~/.writ\nuserdata ~/.writ/reader\ndata /var/db/writ\n\
               file /Library/LaunchDaemons/dev.writ.writd.plist\ndaemon dev.writ.writd\n\
               userfile ~/.writ/known_hosts\nuserfile ~/.writ/config\nuserfile ~/.writ/approver.pub\n"
    );
    // The daemon's configuration: local mode, the sockets in the group's directory.
    let config = fs::read_to_string(fake.at("/var/db/writ/writd.yaml")).unwrap();
    assert!(
        config.contains("attestor: macos_process_chain\nsession_watcher: macos\n"),
        "{config}"
    );
    let plist = fs::read_to_string(fake.at("/Library/LaunchDaemons/dev.writ.writd.plist")).unwrap();
    for part in [
        "<key>UserName</key><string>_writd</string>",
        "<key>ExitTimeOut</key><integer>330</integer>",
        "<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>",
    ] {
        assert!(plist.contains(part), "{part} not in {plist}");
    }
    // The client: the host key pinned under the local alias, the endpoints set.
    let host_key = fs::read_to_string(fake.at("/var/db/writ/boot/host.pub"))
        .ok()
        .or_else(|| {
            let out = Command::new(writ_integration::binaries::bin("writd"))
                .arg("host-key")
                .arg(fake.at("/var/db/writ/writd.yaml"))
                .output()
                .unwrap();
            Some(stdout(&out))
        })
        .unwrap();
    let pins = fs::read_to_string(fake.home.join(".writ/known_hosts")).unwrap();
    assert_eq!(pins, format!("writ-local {}\n", host_key.trim()));
    let client = fake.shown(&fs::read_to_string(fake.home.join(".writ/config")).unwrap());
    assert!(
        client.contains("url = unix:/Library/Application Support/Writ/run/agents.sock\n")
            && client.contains(
                "approval_url = unix:/Library/Application Support/Writ/run/approvals.sock\n"
            ),
        "{client}"
    );
    let calls = fake.shown(&fake.calls());
    for call in [
        "dseditgroup -o edit -a ",
        "codesign --force --sign - --options runtime --identifier dev.writ.writ /opt/writ/bin/writ\n",
        "launchctl bootstrap system /Library/LaunchDaemons/dev.writ.writd.plist\n",
    ] {
        assert!(calls.contains(call), "{call} not in {calls}");
    }
    let identity = fs::read(fake.at("/var/db/writ/keys/identity.age")).unwrap();

    // Run again: an upgrade. The daemon stopped in order and started again, the binaries
    // replaced, the keystore, state, configuration and pins kept.
    fs::write(fake.root.join(".calls"), "").unwrap();
    let said = ok(&fake.run("install", &[], ""));
    assert!(said.contains("Upgrading the installed setup"), "{said}");
    assert!(!said.contains("keystore made"), "{said}");
    assert_eq!(
        fake.shown(&fake.calls())
            .lines()
            .filter(|l| l.starts_with("launchctl"))
            .collect::<Vec<_>>(),
        [
            "launchctl bootout system/dev.writ.writd",
            "launchctl bootstrap system /Library/LaunchDaemons/dev.writ.writd.plist",
        ]
    );
    assert_eq!(
        fs::read(fake.at("/var/db/writ/keys/identity.age")).unwrap(),
        identity
    );
    assert_eq!(
        fs::read_to_string(fake.home.join(".writ/known_hosts")).unwrap(),
        pins
    );

    // A repository wired by the installed writ: the uninstall asks about it.
    let repo = fake.home.join("work");
    git(&repo, &["init", "-q"]);
    let before_repo = config_of(&repo);
    let writ = fake.at("/opt/writ/bin/writ");
    let wired = Command::new(&writ)
        .args(["init", "demo", "--agents", "none"])
        .current_dir(&repo)
        .env("HOME", &fake.home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("WRIT_URL")
        .output()
        .unwrap();
    ok(&wired);
    // No terminal and no REPOS: refused before anything changes.
    let installed = fake.tree();
    refused(
        &fake.run("uninstall", &[], ""),
        "REPOS=undo or REPOS=keep is needed without a terminal: nothing done",
    );
    assert_eq!(fake.tree(), installed);
    // A manifest others could write is not trusted.
    fs::set_permissions(fake.manifest(), fs::Permissions::from_mode(0o664)).unwrap();
    refused(
        &fake.run("uninstall", &[("REPOS", "keep")], ""),
        "can be written by group or others (-rw-rw-r--): nothing done",
    );
    fs::set_permissions(fake.manifest(), fs::Permissions::from_mode(0o644)).unwrap();

    // Uninstalled, the repository taken back too: the Mac as before, but the daemon's data
    // and the reader key that goes with it.
    let said = ok(&fake.run("uninstall", &[("REPOS", "undo")], ""));
    assert!(
        said.contains("Writ wiring removed (wrapper mode)"),
        "{said}"
    );
    assert_eq!(config_of(&repo), before_repo);
    let mut expected = before.clone();
    expected.extend(
        listing(&fake.at("/var/db/writ"))
            .iter()
            .map(|p| format!("var/db/writ/{p}")),
    );
    expected.push("var/db/writ".to_owned());
    expected.sort();
    assert_eq!(fake.tree(), expected);
    assert_eq!(fake.directory(), "", "the role user and the groups removed");
    assert!(
        fake.home().contains(&".writ/reader".to_owned()),
        "{:?}",
        fake.home()
    );
    assert!(
        !fake.home.join(".writ/config").exists() && !fake.home.join(".writ/known_hosts").exists()
    );

    // Installed again: the data picked up (no new keystore), the same uid for _writd.
    let said = ok(&fake.install(&[]));
    assert!(
        said.contains("The daemon's data from before is kept"),
        "{said}"
    );
    assert!(!said.contains("keystore made"), "{said}");
    assert_eq!(
        fs::read(fake.at("/var/db/writ/keys/identity.age")).unwrap(),
        identity
    );

    // PURGE=1: confirmed on a terminal only.
    refused(
        &fake.run("uninstall", &[("PURGE", "1"), ("REPOS", "keep")], ""),
        "PURGE=1 needs a terminal to confirm: nothing done",
    );
    let (status, shown) = on_terminal(
        fake.command("uninstall", &[("PURGE", "1"), ("REPOS", "keep")]),
        &["delete"],
    );
    assert!(status.success(), "{shown}");
    assert!(shown.contains("Type delete to delete it:"), "{shown}");
    assert_eq!(fake.tree(), before);
    assert_eq!(
        fake.home(),
        ["work".to_owned(), "work/.git".to_owned()]
            .into_iter()
            .chain(
                listing(&repo.join(".git"))
                    .into_iter()
                    .map(|p| format!("work/.git/{p}"))
            )
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    );
    assert_eq!(fake.directory(), "");
}

#[test]
fn a_failed_install_stops_saying_where_and_the_uninstall_takes_back_what_was_made() {
    let fake = Fake::new();
    let before = fake.tree();
    let out = fake.install(&[("STUB_FAIL", "codesign")]);
    refused(&out, "install: stopped at: The binaries in ");
    assert!(
        stderr(&out).contains("`make uninstall` takes it back."),
        "{}",
        stderr(&out)
    );
    assert!(fake.directory().contains("/Users/_writd"));
    let said = ok(&fake.run("uninstall", &[("REPOS", "keep")], ""));
    assert!(said.contains("Uninstalled."), "{said}");
    assert_eq!(fake.tree(), before);
    assert_eq!(fake.directory(), "");
    assert_eq!(fake.home(), Vec::<String>::new());
}

#[test]
fn the_uninstall_takes_back_only_the_installer_s_own_paths() {
    let fake = Fake::new();
    ok(&fake.install(&[]));
    // A line naming something else (the manifest written by hand, as root could): left as
    // it is, and said.
    let outside = fake.at("/etc/hosts");
    fs::write(&outside, "127.0.0.1 localhost\n").unwrap();
    let mut manifest = fs::read_to_string(fake.manifest()).unwrap();
    manifest.push_str(&format!(
        "file {}\ntree {}\n",
        outside.display(),
        fake.at("/var/db").display()
    ));
    fs::write(fake.manifest(), manifest).unwrap();
    let said = fake.shown(&ok(&fake.run("uninstall", &[("REPOS", "keep")], "")));
    assert!(
        said.contains("left as it is (not one of this installer's paths): /etc/hosts"),
        "{said}"
    );
    assert!(
        said.contains("left as it is (not one of this installer's paths): /var/db\n"),
        "{said}"
    );
    assert!(outside.exists() && fake.at("/var/db/writ").exists());
}

fn whoami() -> String {
    String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned()
}

fn git(repo: &Path, args: &[&str]) {
    fs::create_dir_all(repo).unwrap();
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
}

fn config_of(repo: &Path) -> String {
    fs::read_to_string(repo.join(".git/config")).unwrap()
}
