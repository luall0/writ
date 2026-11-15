//! The installer (M7, M7.1): `deploy/install.sh` with the `local` setups of the Mac and of
//! Linux, against a fake root (every system path under a directory, `WRIT_INSTALL_ROOT`) with
//! the system tools that need root stubbed on PATH (the Mac's `sudo`, `dscl`, `dseditgroup`,
//! `launchctl`, `codesign`, `chown`; Linux's `sudo`, `useradd`, `userdel`, `groupadd`,
//! `groupdel`, `gpasswd`, `getent`, `systemctl`, `chown`), and the real binaries (`writd init`
//! makes the keystore for real). Both run on either OS (`WRIT_INSTALL_OS` stands for
//! `uname -s`): the frame and the setups are POSIX sh. On Linux, the unit file is checked by
//! `systemd-analyze verify`. The real installs are manual checks
//! (docs/guides/manual-checks.md).

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
use writ_integration::terminal::on_writ_terminal;
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

/// Linux's user and group tools, as a file of `passwd <name> <uid>` and
/// `group <name> <gid> [<member>…]` lines.
const USERS: &str = r#"#!/bin/sh
db="$WRIT_INSTALL_ROOT/.users"; touch "$db"
name=$(basename "$0")
{ printf '%s' "$name"; printf ' %s' "$@"; printf '\n'; } >> "$WRIT_INSTALL_ROOT/.calls"
[ "${STUB_FAIL:-}" = "$name" ] && { echo "$name: failing (stub)" >&2; exit 1; }
case $name in
  getent) awk -v kind="$1" -v key="$2" '$1 == kind && ($2 == key || $3 == key) { print; found = 1 } END { exit !found }' "$db" ;;
  useradd)
    uid=; own=no
    while [ $# -gt 1 ]; do
      case $1 in --uid) uid=$2; shift ;; --user-group) own=yes ;; --home-dir|--shell|--comment) shift ;; esac
      shift
    done
    [ -n "$uid" ] || uid=$((999 - $(grep -c '^passwd ' "$db")))
    echo "passwd $1 $uid" >> "$db"
    [ "$own" = yes ] && echo "group $1 $uid" >> "$db" ;;
  userdel) grep -v "^passwd $1 \|^group $1 " "$db" > "$db.new" || true; mv "$db.new" "$db" ;;
  groupadd) for g; do :; done; echo "group $g $((900 + $(grep -c '^group ' "$db")))" >> "$db" ;;
  groupdel) grep -v "^group $1 " "$db" > "$db.new" || true; mv "$db.new" "$db" ;;
  gpasswd)
    case $1 in
      -a) sed "s/^group $3 .*/& $2/" "$db" > "$db.new" ;;
      -d) sed "s/^\(group $3 .*\) $2\$/\1/" "$db" > "$db.new" ;;
    esac
    mv "$db.new" "$db" ;;
esac
"#;

/// `sudo [-u <user>] <command>`: the command, as the test's user.
const SUDO: &str = "#!/bin/sh\n[ \"$1\" = -u ] && shift 2\nexec \"$@\"\n";

/// Which system the fake root stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Os {
    Mac,
    Linux,
}

impl Os {
    /// What `uname -s` says there.
    fn uname(self) -> &'static str {
        match self {
            Self::Mac => "Darwin",
            Self::Linux => "Linux",
        }
    }
}

/// A Mac's or a Linux machine's directories, in a fake root, with the stubs and an approval
/// key.
struct Fake {
    _dir: tempfile::TempDir,
    os: Os,
    root: PathBuf,
    home: PathBuf,
    stubs: PathBuf,
    approver: PathBuf,
}

impl Fake {
    fn new() -> Self {
        Self::of(Os::Mac)
    }

    fn of(os: Os) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();
        let (root, home, stubs) = (base.join("root"), base.join("home"), base.join("stubs"));
        let systems: &[&str] = match os {
            Os::Mac => &[
                "etc/paths.d",
                "var/db",
                "Library/LaunchDaemons",
                "Library/Logs",
                "Library/Application Support",
            ],
            Os::Linux => &["etc/systemd/system", "usr/local/bin", "var/lib"],
        };
        for system in systems {
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
        match os {
            Os::Mac => {
                script("dscl", DSCL);
                for tool in ["dseditgroup", "launchctl", "codesign", "chown"] {
                    script(tool, LOGGING);
                }
            }
            Os::Linux => {
                for tool in [
                    "useradd", "userdel", "groupadd", "groupdel", "gpasswd", "getent",
                ] {
                    script(tool, USERS);
                }
                for tool in ["systemctl", "chown"] {
                    script(tool, LOGGING);
                }
            }
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
            os,
            root,
            home,
            stubs,
            approver,
        }
    }

    /// The binaries the installer installs: the ones `make test` built, and `writ-se` (the
    /// Secure Enclave helper), built there on the Mac only, a stub elsewhere (the macOS setup
    /// runs against a fake root on Linux too).
    fn binaries(&self) -> PathBuf {
        let built = writ_integration::binaries::bin("writd")
            .parent()
            .unwrap()
            .to_path_buf();
        let dir = self.root.parent().unwrap().join("binaries");
        if !dir.exists() {
            fs::create_dir_all(&dir).unwrap();
            for name in ["writd", "writ", "writ-sign"] {
                std::os::unix::fs::symlink(built.join(name), dir.join(name)).unwrap();
            }
            // The Swift programs (the Secure Enclave helper, the approval popup): built on the
            // Mac by `make test`, a stub elsewhere.
            for swift in ["writ-se", "writ-popup"] {
                let program = built.join(swift);
                if program.exists() {
                    std::os::unix::fs::symlink(program, dir.join(swift)).unwrap();
                } else {
                    fs::write(dir.join(swift), "#!/bin/sh\nexit 1\n").unwrap();
                    fs::set_permissions(dir.join(swift), fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
            }
        }
        dir
    }

    /// `deploy/install.sh <action>` in the fake root, with `env` on top.
    fn command(&self, action: &str, env: &[(&str, &str)]) -> Command {
        let deploy = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/install.sh");
        let binaries = self.binaries();
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
            .env("WRIT_INSTALL_OS", self.os.uname())
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
            .filter(|p| {
                !p.starts_with(".calls") && !p.starts_with(".dscl") && !p.starts_with(".users")
            })
            .collect()
    }

    fn home(&self) -> Vec<String> {
        listing(&self.home)
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.root.join(".calls")).unwrap_or_default()
    }

    /// The users and groups the stubs hold.
    fn directory(&self) -> String {
        let db = match self.os {
            Os::Mac => ".dscl",
            Os::Linux => ".users",
        };
        fs::read_to_string(self.root.join(db)).unwrap_or_default()
    }

    fn manifest(&self) -> PathBuf {
        match self.os {
            Os::Mac => self
                .root
                .join("Library/Application Support/Writ/install.manifest"),
            Os::Linux => self.root.join("etc/writ/install.manifest"),
        }
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
            &[("WRIT_INSTALL_OS", "FreeBSD"), ("SETUP", "local")],
            "",
        ),
        "no setup for FreeBSD in this build",
    );
    // On a terminal, the setup is asked.
    let mut asked = fake.command("install", &[("DRY_RUN", "1")]);
    asked.env("APPROVER", &fake.approver);
    // The setup, then this setup's six questions (Enter: software, a passphrase, the popup
    // through Secretive's agent).
    let (status, shown) = on_writ_terminal(asked, &["local", "", "", "", "", "", ""]);
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
    // Root's files go to sudo on its standard input: no temporary file of yours (an agent
    // could change one while sudo asks for the password), so a TMPDIR nobody can write is
    // no matter.
    let closed = fake.root.parent().unwrap().join("closed-tmp");
    fs::create_dir_all(&closed).unwrap();
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o500)).unwrap();
    let closed_tmp = closed.display().to_string();
    let said = fake.shown(&ok(&fake.install(&[("TMPDIR", closed_tmp.as_str())])));
    assert_eq!(listing(&closed), Vec::<String>::new());
    assert!(said.contains("keystore made: /var/db/writ/keys"), "{said}");
    assert!(said.contains("Installed. What is left:"), "{said}");
    let manifest = fs::read_to_string(fake.manifest()).unwrap();
    assert_eq!(
        fake.shown(&manifest),
        "setup local-macos\ngroup _writd\nuser _writd\ngroup _writ\nmember _writ ".to_owned()
            + &whoami()
            + "\ndir /opt\ndir /opt/writ\ndir /opt/writ/bin\nfile /opt/writ/bin/writd\n\
               file /opt/writ/bin/writ\nfile /opt/writ/bin/writ-sign\nfile /opt/writ/bin/writ-se\n\
               file /opt/writ/bin/writ-popup\n\
               file /etc/paths.d/writ\n\
               tree /Library/Application Support/Writ/run\ntree /Library/Logs/Writ\n\
               userdir ~/.writ\nuserdata ~/.writ/reader\nnewdata /var/db/writ\ndata /var/db/writ\n\
               file /Library/LaunchDaemons/dev.writ.writd.plist\ndaemon dev.writ.writd\n\
               userfile ~/.writ/known_hosts\nuserfile ~/.writ/config\nuserfile ~/.writ/approver.pub\n\
               userdir ~/Library\nuserdir ~/Library/LaunchAgents\n\
               userfile ~/Library/LaunchAgents/dev.writ.popup.plist\nagent dev.writ.popup\n"
    );
    // The popup's LaunchAgent: writ-popup in your session, your Writ home and Secretive's
    // agent (no APPROVAL_AGENT given), started in your GUI session.
    let popup = fake.shown(
        &fs::read_to_string(fake.home.join("Library/LaunchAgents/dev.writ.popup.plist")).unwrap(),
    );
    for part in [
        "<key>Label</key><string>dev.writ.popup</string>",
        "<array><string>/opt/writ/bin/writ-popup</string></array>",
        "<key>WRIT_HOME</key><string>~/.writ</string>",
        "<key>WRIT_APPROVAL_AGENT</key><string>~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh</string>",
        "<key>LimitLoadToSessionType</key><string>Aqua</string>",
        "<key>KeepAlive</key><true/>",
    ] {
        assert!(popup.contains(part), "{part} not in {popup}");
    }
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
        "codesign --force --sign - --options runtime --identifier dev.writ.writ-popup /opt/writ/bin/writ-popup\n",
        &format!(
            "launchctl bootstrap gui/{} ~/Library/LaunchAgents/dev.writ.popup.plist\n",
            uid()
        ),
    ] {
        assert!(calls.contains(call), "{call} not in {calls}");
    }
    let identity = fs::read(fake.at("/var/db/writ/keys/identity.age")).unwrap();
    // The approval key: what was read once, in the daemon's approvers and your approver.pub.
    let key = fs::read_to_string(&fake.approver).unwrap();
    assert_eq!(
        fs::read_to_string(fake.at("/var/db/writ/approvers")).unwrap(),
        format!("approver {key}")
    );
    assert_eq!(
        fs::read_to_string(fake.home.join(".writ/approver.pub")).unwrap(),
        key
    );

    // Run again: an upgrade. The daemon stopped in order and started again, the binaries
    // replaced, the plist written again (an older install's settings don't stay), the
    // keystore, state, configuration and pins kept; a new writ says the sessions bound
    // under the old one are to be started again.
    fs::write(fake.root.join(".calls"), "").unwrap();
    let plist_path = fake.at("/Library/LaunchDaemons/dev.writ.writd.plist");
    fs::write(&plist_path, "<plist>an older install's</plist>\n").unwrap();
    fs::write(fake.at("/opt/writ/bin/writ"), "an older writ").unwrap();
    let said = ok(&fake.run("install", &[], ""));
    assert!(said.contains("Upgrading the installed setup"), "{said}");
    assert!(!said.contains("keystore made"), "{said}");
    assert_eq!(fs::read_to_string(&plist_path).unwrap(), plist);
    assert!(
        said.contains("writ changed: agents started with writ run before the upgrade are bound to the old writ,"),
        "{said}"
    );
    assert!(
        said.contains("Start each again (writ run -- <agent>)"),
        "{said}"
    );
    assert_eq!(
        fake.shown(&fake.calls())
            .lines()
            .filter(|l| l.starts_with("launchctl"))
            .collect::<Vec<_>>(),
        [
            "launchctl bootout system/dev.writ.writd".to_owned(),
            format!("launchctl bootout gui/{}/dev.writ.popup", uid()),
            "launchctl bootstrap system /Library/LaunchDaemons/dev.writ.writd.plist".to_owned(),
            format!(
                "launchctl bootstrap gui/{} ~/Library/LaunchAgents/dev.writ.popup.plist",
                uid()
            ),
        ]
    );
    let again = ok(&fake.run("install", &[], ""));
    assert!(!again.contains("writ changed"), "the same writ: {again}");
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

    // Installed again: the data picked up (no new keystore), the same uid for _writd; no
    // approval key needed (the kept approvers stand), one given not used.
    let said = ok(&fake.run("install", &[("SETUP", "local")], ""));
    assert!(
        said.contains("The daemon's data from before is kept"),
        "{said}"
    );
    assert!(!said.contains("keystore made"), "{said}");
    assert!(
        said.contains("approver.pub is not there: copy your approval key's .pub to it"),
        "{said}"
    );
    assert!(!fake.home.join(".writ/approver.pub").exists());
    assert_eq!(
        fs::read_to_string(fake.at("/var/db/writ/approvers")).unwrap(),
        format!("approver {key}"),
        "the kept approvers"
    );
    assert_eq!(
        fs::read(fake.at("/var/db/writ/keys/identity.age")).unwrap(),
        identity
    );

    // PURGE=1: confirmed on a terminal only.
    refused(
        &fake.run("uninstall", &[("PURGE", "1"), ("REPOS", "keep")], ""),
        "PURGE=1 needs a terminal to confirm: nothing done",
    );
    let (status, shown) = on_writ_terminal(
        fake.command("uninstall", &[("PURGE", "1"), ("REPOS", "keep")]),
        &["delete", "y"],
    );
    assert!(status.success(), "{shown}");
    assert!(
        shown.contains("> Type delete to delete it, Enter keeps it delete"),
        "{shown}"
    );
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

/// The approval key's fingerprint, as `ssh-keygen -l` says it.
fn fingerprint(key: &Path) -> String {
    let out = Command::new("ssh-keygen")
        .args(["-l", "-f"])
        .arg(key)
        .output()
        .unwrap();
    stdout(&out).split(' ').nth(1).unwrap().to_owned()
}

#[test]
fn a_keystore_that_failed_to_be_made_is_taken_back_and_never_taken_for_kept_data() {
    for os in [Os::Mac, Os::Linux] {
        let fake = Fake::of(os);
        let before = fake.tree();
        let data = match os {
            Os::Mac => "/var/db/writ",
            Os::Linux => "/var/lib/writ",
        };
        // writd init refuses a passphrase too short: the install stops at the keystore.
        let approver = fake.approver.display().to_string();
        let out = fake.run(
            "install",
            &[("SETUP", "local"), ("APPROVER", approver.as_str())],
            "short\nshort\n",
        );
        refused(&out, "install: stopped at: The keystore (writd init");
        let manifest = fake.shown(&fs::read_to_string(fake.manifest()).unwrap());
        assert!(
            manifest.contains(&format!("newdata {data}\n")),
            "{manifest}"
        );
        assert!(
            !manifest.contains(&format!("\ndata {data}\n")),
            "{manifest}"
        );
        // The uninstall takes the half-made data back whole, kept data or not.
        let said = ok(&fake.run("uninstall", &[("REPOS", "keep")], ""));
        assert!(said.contains("Uninstalled."), "{said}");
        assert_eq!(fake.tree(), before, "{os:?}");
        // So the next install makes a keystore, never "kept from before".
        let said = fake.shown(&ok(&fake.install(&[])));
        assert!(
            said.contains(&format!("keystore made: {data}/keys")),
            "{said}"
        );
        assert!(!said.contains("kept"), "{said}");
    }
}

#[test]
fn the_approval_key_is_read_once_and_must_be_one() {
    let fake = Fake::new();
    let before = fake.tree();
    let bad = fake.root.parent().unwrap().join("bad.pub");
    // The private half given by mistake: a throwaway key made here, never one of the user's.
    let private = generate(KeyKind::Ed25519)
        .unwrap()
        .to_openssh(writ_crypto::ssh_key::LineEnding::LF)
        .unwrap();
    for (text, why) in [
        ("ssh-ed25519 not-base64\n", "is not an SSH public key"),
        ("hello\n", "is not an SSH public key"),
        (private.as_str(), "is a private key: give its .pub"),
    ] {
        fs::write(&bad, text).unwrap();
        let path = bad.display().to_string();
        refused(&fake.install(&[("APPROVER", path.as_str())]), why);
        assert_eq!(fake.tree(), before);
    }
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

// ----- The `local` setup on Linux (M7.1) -----

#[test]
fn on_linux_the_dry_run_lists_every_change_and_makes_none() {
    let fake = Fake::of(Os::Linux);
    let before = fake.tree();
    let said = fake.shown(&ok(&fake.install(&[("DRY_RUN", "1")])));
    for change in [
        "Dry run: these are the changes; none is made.",
        "    (root) useradd --system --user-group --no-create-home --home-dir /var/lib/writ \
         --shell /usr/sbin/nologin --comment Writ daemon writd",
        "    (root) groupadd --system writ",
        "    (root) gpasswd -a ",
        "    (root) install -m 0755 ",
        "    (root) write /etc/writ/writd.yaml (0644, root:root):",
        "        attestor: linux_process_chain\n        session_watcher: linux",
        "        agents: [{ unix: /run/writ/agents.sock }]",
        "    (root) install -d -m 0700 /var/lib/writ",
        "    (writd) /usr/local/bin/writd init /etc/writ/writd.yaml",
        "    (root) write /etc/systemd/system/writd.service (0644, root:root):",
        "        AmbientCapabilities=CAP_SYS_PTRACE",
        "    (root) systemctl enable --now writd.service",
        "        url = unix:/run/writ/agents.sock",
    ] {
        assert!(said.contains(change), "{change:?} not in:\n{said}");
    }
    assert_eq!(fake.tree(), before, "nothing made");
    assert_eq!(fake.home(), Vec::<String>::new());
    assert_eq!(fake.directory(), "");
    refused(
        &fake.run("install", &[], ""),
        "SETUP=<name> is needed without a terminal (offered on Linux: local )",
    );
}

/// The unit's settings that make the daemon what deployment.md says it is.
const UNIT_SETTINGS: &[&str] = &[
    "User=writd\n",
    "Group=writ\n",
    "ExecStart=/usr/local/bin/writd run /etc/writ/writd.yaml\n",
    "TimeoutStopSec=330\n",
    "KillMode=mixed\n",
    "UMask=0077\n",
    "RuntimeDirectory=writ\n",
    "RuntimeDirectoryMode=0750\n",
    "ReadWritePaths=/var/lib/writ\n",
    "NoNewPrivileges=yes\n",
    "CapabilityBoundingSet=CAP_SYS_PTRACE\n",
    "AmbientCapabilities=CAP_SYS_PTRACE\n",
    "SystemCallFilter=~ptrace process_vm_readv process_vm_writev\n",
    "ProtectSystem=strict\n",
    "ProtectHome=yes\n",
    "PrivateTmp=yes\n",
    "LimitMEMLOCK=infinity\n",
    "LimitCORE=0\n",
    "WantedBy=multi-user.target\n",
];

/// On Linux, the unit as systemd reads it (`systemd-analyze verify`), its program the fake
/// root's `writd`. Elsewhere, nothing: systemd is Linux's.
fn verified_by_systemd(fake: &Fake, unit: &str) {
    if std::env::consts::OS != "linux" {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("writd.service");
    let writd = fake.at("/usr/local/bin/writd");
    fs::write(
        &copy,
        unit.replace("/usr/local/bin/writd", writd.to_str().unwrap()),
    )
    .unwrap();
    let out = Command::new("systemd-analyze")
        .arg("verify")
        .arg(&copy)
        .output()
        .expect("systemd-analyze is needed on Linux (the systemd package)");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
}

#[test]
fn on_linux_an_install_upgrades_and_uninstalls_leaving_the_machine_as_before() {
    let fake = Fake::of(Os::Linux);
    let before = fake.tree();
    let said = fake.shown(&ok(&fake.install(&[])));
    assert!(said.contains("keystore made: /var/lib/writ/keys"), "{said}");
    assert!(
        said.contains("1. Log in again (or run newgrp writ)"),
        "{said}"
    );
    assert!(said.contains("journalctl -u writd"), "{said}");
    let me = whoami();
    let manifest = fs::read_to_string(fake.manifest()).unwrap();
    assert_eq!(
        fake.shown(&manifest),
        format!(
            "setup local-linux\nuser writd\ngroup writ\nmember writ {me}\n\
             file /usr/local/bin/writd\nfile /usr/local/bin/writ\nfile /usr/local/bin/writ-sign\n\
             userdir ~/.writ\nuserdata ~/.writ/reader\nfile /etc/writ/writd.yaml\n\
             newdata /var/lib/writ\ndata /var/lib/writ\nfile /etc/systemd/system/writd.service\ndaemon writd\n\
             userfile ~/.writ/known_hosts\nuserfile ~/.writ/config\nuserfile ~/.writ/approver.pub\n"
        )
    );
    assert_eq!(
        fake.directory(),
        format!("passwd writd 999\ngroup writd 999\ngroup writ 901 {me}\n")
    );
    let config = fake.shown(&fs::read_to_string(fake.at("/etc/writ/writd.yaml")).unwrap());
    for part in [
        "state_dir: /var/lib/writ/state\n",
        "keystore: { sealed: { dir: /var/lib/writ/keys, boot: /var/lib/writ/boot } }\n",
        "agents: [{ unix: /run/writ/agents.sock }]\n",
        "ssh: [{ unix: /run/writ/approvals.sock }]\n",
        "attestor: linux_process_chain\nsession_watcher: linux\n",
    ] {
        assert!(config.contains(part), "{part} not in {config}");
    }
    let unit = fs::read_to_string(fake.at("/etc/systemd/system/writd.service")).unwrap();
    for part in UNIT_SETTINGS {
        assert!(unit.contains(part), "{part} not in {unit}");
    }
    for hiding in ["ProtectProc=invisible", "PrivatePIDs", "ProcSubset"] {
        assert!(
            !unit.contains(hiding),
            "{hiding} would hide the agents:\n{unit}"
        );
    }
    verified_by_systemd(&fake, &unit);
    let calls = fake.shown(&fake.calls());
    for call in [
        "systemctl daemon-reload\n",
        "systemctl enable --now writd.service\n",
        &format!("gpasswd -a {me} writ\n"),
    ] {
        assert!(calls.contains(call), "{call} not in {calls}");
    }
    let client = fake.shown(&fs::read_to_string(fake.home.join(".writ/config")).unwrap());
    assert!(
        client.contains("url = unix:/run/writ/agents.sock\n")
            && client.contains("approval_url = unix:/run/writ/approvals.sock\n"),
        "{client}"
    );
    let pins = fs::read_to_string(fake.home.join(".writ/known_hosts")).unwrap();
    assert!(pins.starts_with("writ-local ssh-ed25519 "), "{pins}");
    let identity = fs::read(fake.at("/var/lib/writ/keys/identity.age")).unwrap();

    // Run again: an upgrade, the daemon stopped and started through systemd, the unit
    // written again and reloaded (an older install's settings don't stay), the rest kept.
    fs::write(fake.root.join(".calls"), "").unwrap();
    let unit_path = fake.at("/etc/systemd/system/writd.service");
    fs::write(
        &unit_path,
        "[Service]\nExecStart=/usr/local/bin/writd run old\n",
    )
    .unwrap();
    fs::write(fake.at("/usr/local/bin/writ"), "an older writ").unwrap();
    let said = ok(&fake.run("install", &[], ""));
    assert!(said.contains("Upgrading the installed setup"), "{said}");
    assert_eq!(fs::read_to_string(&unit_path).unwrap(), unit);
    assert!(
        said.contains("Start each again (writ run -- <agent>)"),
        "{said}"
    );
    assert_eq!(
        fake.calls()
            .lines()
            .filter(|l| l.starts_with("systemctl"))
            .collect::<Vec<_>>(),
        [
            "systemctl stop writd.service",
            "systemctl daemon-reload",
            "systemctl start writd.service"
        ]
    );
    assert_eq!(
        fs::read(fake.at("/var/lib/writ/keys/identity.age")).unwrap(),
        identity
    );

    // Uninstalled: the machine as before, but the daemon's data and the reader key; the user,
    // the group and the membership taken back.
    fs::write(fake.root.join(".calls"), "").unwrap();
    ok(&fake.run("uninstall", &[("REPOS", "keep")], ""));
    let calls = fake.calls();
    for call in [
        "systemctl disable --now writd.service\n",
        &format!("gpasswd -d {me} writ\n"),
        "groupdel writ\n",
        "userdel writd\n",
        "systemctl daemon-reload\n",
    ] {
        assert!(calls.contains(call), "{call} not in {calls}");
    }
    let mut expected = before.clone();
    expected.extend(
        listing(&fake.at("/var/lib/writ"))
            .iter()
            .map(|p| format!("var/lib/writ/{p}")),
    );
    expected.push("var/lib/writ".to_owned());
    expected.sort();
    assert_eq!(fake.tree(), expected);
    assert_eq!(fake.directory(), "");
    assert!(fake.home().contains(&".writ/reader".to_owned()));

    // Installed again: the data picked up, the user made with the data's uid, no approval
    // key asked.
    let said = ok(&fake.run("install", &[("SETUP", "local")], ""));
    assert!(
        said.contains("The daemon's data from before is kept"),
        "{said}"
    );
    assert!(!said.contains("keystore made"), "{said}");
    let uid = rustix::process::getuid().as_raw();
    assert!(
        fake.directory()
            .starts_with(&format!("passwd writd {uid}\n")),
        "{}",
        fake.directory()
    );
    assert!(fake.calls().contains(&format!(" --uid {uid} ")));

    // PURGE=1 on a terminal: everything gone.
    let (status, shown) = on_writ_terminal(
        fake.command("uninstall", &[("PURGE", "1"), ("REPOS", "keep")]),
        &["delete", "y"],
    );
    assert!(status.success(), "{shown}");
    assert_eq!(fake.tree(), before);
    assert_eq!(fake.home(), Vec::<String>::new());
    assert_eq!(fake.directory(), "");
}

#[test]
fn on_linux_a_failed_install_stops_saying_where_and_the_uninstall_takes_back_what_was_made() {
    let fake = Fake::of(Os::Linux);
    let before = fake.tree();
    let out = fake.install(&[("STUB_FAIL", "groupadd")]);
    refused(
        &out,
        "install: stopped at: The system user writd and the sockets' group writ",
    );
    assert!(fake.directory().contains("passwd writd "));
    ok(&fake.run("uninstall", &[("REPOS", "keep")], ""));
    assert_eq!(fake.tree(), before);
    assert_eq!(fake.directory(), "");
    // A user of that name already there (not this install's): refused, nothing made.
    fs::write(fake.root.join(".users"), "passwd writd 120\n").unwrap();
    refused(
        &fake.install(&[]),
        "writd exists already and isn't this install's",
    );
    // Its uninstall takes back what was made, never that user.
    ok(&fake.run("uninstall", &[("REPOS", "keep")], ""));
    assert_eq!(fake.tree(), before);
    assert_eq!(fake.directory(), "passwd writd 120\n");
}

/// Your user id (the GUI session's domain is `gui/<uid>`).
fn uid() -> String {
    let out = Command::new("id").arg("-u").output().unwrap();
    stdout(&out).trim().to_owned()
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

#[test]
fn a_guided_install_asks_everything_shows_every_change_and_waits_for_the_go() {
    let fake = Fake::new();
    let before = fake.tree();
    let approver = fake.approver.display().to_string();
    // No variable at all: every answer typed. A path that isn't a key is asked again (a
    // backend is a select of the ones offered: a wrong one can't be picked, and one given by
    // its variable is refused by name); then no at the go.
    let (status, shown) = on_writ_terminal(
        fake.command("install", &[]),
        &[
            "",
            "/nonexistent/key.pub",
            &approver,
            "",
            "",
            "",
            "",
            "",
            "",
            "n",
        ],
    );
    assert!(status.success(), "{shown}");
    let shown = fake.shown(&shown);
    for said in [
        "Writ's installer: a few questions, then every change it will make, then your go.",
        "Which setup? Offered on Darwin: local",
        "  local: the daemon on this Mac, under its own user, out of your reach; your agents run here",
        "> Setup local",
        "Give the path to its public half, the .pub",
        "? Approval key (.pub)",
        "  /nonexistent/key.pub: not a readable file",
        "se-cryptokit: in this Mac's Secure Enclave, which makes it and never lets it out",
        "> TLS key software",
        "> SSH CA key software",
        "> Agent signing key software",
        "> Keystore opened by passphrase",
        "not offered with these answers",
        "The approval popup: a window in front of every app, full-screen ones too, when a",
        "> Approval popup yes",
        "? Approval key's agent socket",
        "~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh",
        "Your answers:",
        "  Setup: local (the daemon on this Mac",
        &format!(
            "  Approval key: {} ({approver})",
            fingerprint(&fake.approver)
        ),
        "  TLS key: software",
        "  SSH CA key: software",
        "  Keystore opened by: a passphrase",
        "  Auto-unseal: no",
        "  Agent signing key agent-01: Ed25519, in software",
        "  Approval popup: at login, signing through ~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh",
        "The changes, in order (none is made yet):",
        "    (root) dscl . -create /Users/_writd UniqueID 450",
        "agent-01: { use: signing, format: ssh, algorithm: ed25519 }",
        "/opt/writ/bin/writd init /var/db/writ/writd.yaml --tls-backend software --ca-backend software",
        "> Install? n",
        "Nothing changed.",
    ] {
        assert!(shown.contains(said), "{said:?} not in:\n{shown}");
    }
    assert_eq!(fake.tree(), before, "nothing made before the go");
    assert!(!fake.calls().contains("-create"), "{}", fake.calls());

    // The same answers and yes: installed, the passphrase asked by writd init.
    let (status, shown) = on_writ_terminal(
        fake.command("install", &[]),
        &[
            "",
            &approver,
            "",
            "",
            "",
            "",
            "",
            "",
            "y",
            // Read as lines by writd init (echo off): typed as they are.
            "an installer test passphrase\n",
            "an installer test passphrase\n",
        ],
    );
    assert!(status.success(), "{shown}");
    let shown = fake.shown(&shown);
    assert!(
        shown.contains("keystore made: /var/db/writ/keys"),
        "{shown}"
    );
    assert!(
        shown.contains("signing key agent-01: ssh-ed25519 "),
        "{shown}"
    );
    let policy = fs::read_to_string(fake.at("/var/db/writ/policy.yaml")).unwrap();
    assert!(
        policy.contains("  agent-01: { use: signing, format: ssh, algorithm: ed25519 }\n"),
        "{policy}"
    );

    // The uninstall, guided too: what it takes back shown, no at its go changing nothing,
    // then yes, the data kept (Enter at the question).
    let installed = fake.tree();
    let (status, shown) = on_writ_terminal(fake.command("uninstall", &[]), &["", "n"]);
    assert!(status.success(), "{shown}");
    assert!(
        shown.contains("> Type delete to delete it, Enter keeps it"),
        "{shown}"
    );
    assert!(
        shown.contains("What the uninstall takes back, newest first (nothing is done yet):"),
        "{shown}"
    );
    assert!(
        shown.contains("> Uninstall? n") && shown.contains("Nothing changed."),
        "{shown}"
    );
    assert_eq!(fake.tree(), installed);
    let (status, shown) = on_writ_terminal(fake.command("uninstall", &[]), &["", "y"]);
    assert!(status.success(), "{shown}");
    assert!(shown.contains("Uninstalled."), "{shown}");
    assert!(
        fake.at("/var/db/writ/keys/identity.age").exists(),
        "the data kept"
    );
}

/// A recovery key's recipient (age1 and 58 bech32 characters), for the installer's variables.
const RECOVERY: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";

#[test]
fn without_a_terminal_each_answer_is_a_variable_checked_like_a_typed_one() {
    let fake = Fake::new();
    let before = fake.tree();
    for (name, value, why) in [
        (
            "TLS_BACKEND",
            "yubikey",
            "TLS_BACKEND=yubikey: one of software se-cryptokit",
        ),
        (
            "AGENT_BACKEND",
            "tpm",
            "AGENT_BACKEND=tpm: one of software se-cryptokit",
        ),
        (
            "CA_BACKEND",
            "yubikey",
            "CA_BACKEND=yubikey: one of software se-cryptokit",
        ),
        (
            "UNSEAL",
            "touchid",
            "UNSEAL=touchid: one of passphrase se-cryptokit",
        ),
    ] {
        refused(&fake.install(&[(name, value)]), why);
        assert_eq!(fake.tree(), before, "{name}: nothing made");
    }
    // The Secure Enclave keystore needs its recovery key; auto-unseal needs everything there.
    for (env, why) in [
        (
            vec![("UNSEAL", "se-cryptokit")],
            "RECOVERY=: the recovery key's age1... recipient (writ recovery new)",
        ),
        (
            vec![("RECOVERY", RECOVERY)],
            "RECOVERY is for UNSEAL=se-cryptokit",
        ),
        (
            vec![
                ("UNSEAL", "se-cryptokit"),
                ("RECOVERY", RECOVERY),
                ("AUTO_UNSEAL", "yes"),
            ],
            "AUTO_UNSEAL=yes needs CA_BACKEND, AGENT_BACKEND and UNSEAL all se-cryptokit",
        ),
        // The approval popup (M7.8): its two answers, checked like the others.
        (vec![("POPUP", "maybe")], "POPUP=maybe: one of yes no"),
        (
            vec![("POPUP", "no"), ("APPROVAL_AGENT", "/tmp/agent.sock")],
            "APPROVAL_AGENT is for POPUP=yes",
        ),
        (
            vec![("APPROVAL_AGENT", "agent.sock")],
            "APPROVAL_AGENT=agent.sock: an absolute path",
        ),
        (
            vec![("APPROVAL_AGENT", "/tmp/a</string><key>x")],
            "APPROVAL_AGENT=/tmp/a</string><key>x: no < > & \" ' or tab in the path",
        ),
        (
            vec![("APPROVAL_AGENT", "/tmp/a&b")],
            "no < > & \" ' or tab in the path",
        ),
    ] {
        refused(&fake.install(&env), why);
        assert_eq!(fake.tree(), before, "{env:?}: nothing made");
    }
    refused(
        &fake.install(&[("APPROVER", "/nonexistent/key.pub")]),
        "APPROVER=/nonexistent/key.pub: not a readable file",
    );
    // The Secure Enclave for everything, auto-unseal on, as a dry run shows it.
    let said = fake.shown(&ok(&fake.install(&[
        ("DRY_RUN", "1"),
        ("TLS_BACKEND", "se-cryptokit"),
        ("CA_BACKEND", "se-cryptokit"),
        ("AGENT_BACKEND", "se-cryptokit"),
        ("UNSEAL", "se-cryptokit"),
        ("RECOVERY", RECOVERY),
        ("AUTO_UNSEAL", "yes"),
    ])));
    for change in [
        "agent-01: { use: signing, format: ssh, algorithm: p256, backend: se-cryptokit }",
        "/opt/writ/bin/writd init /var/db/writ/writd.yaml --tls-backend se-cryptokit --ca-backend se-cryptokit",
        &format!("recovery: {{ recipient: {RECOVERY} }}"),
        "se-01: { backend: se-cryptokit }",
        "unseal: auto",
        "opened by the Secure Enclave, no passphrase",
    ] {
        assert!(said.contains(change), "{change:?} not in:\n{said}");
    }
    assert_eq!(fake.tree(), before);
}

/// The approval popup's answers (M7.8): `POPUP=no` installs `writ-popup` and starts nothing;
/// `APPROVAL_AGENT` is what the popup's `writ` signs through; an install made before M7.8
/// gets the popup at its upgrade, and the uninstall takes it back.
#[test]
fn the_approval_popup_is_started_at_login_as_answered_and_taken_back() {
    let fake = Fake::new();
    let before = fake.tree();
    ok(&fake.install(&[("POPUP", "no")]));
    let manifest = fs::read_to_string(fake.manifest()).unwrap();
    assert!(manifest.contains("file "), "{manifest}");
    assert!(
        manifest.contains(&format!(
            "file {}",
            fake.at("/opt/writ/bin/writ-popup").display()
        )),
        "{manifest}"
    );
    assert!(!manifest.contains("agent dev.writ.popup"), "{manifest}");
    assert!(manifest.ends_with("choice popup no\n"), "{manifest}");
    assert!(!fake.home.join("Library").exists());
    assert!(!fake.calls().contains("gui/"), "{}", fake.calls());
    // Its upgrade remembers the no.
    ok(&fake.run("install", &[], ""));
    assert!(!fake.home.join("Library").exists());
    assert!(!fake.calls().contains("gui/"), "{}", fake.calls());

    // An upgrade of an install made before M7.8 (no popup, no answer recorded): the popup
    // added, through the agent APPROVAL_AGENT names.
    let without = fs::read_to_string(fake.manifest())
        .unwrap()
        .replace("choice popup no\n", "");
    fs::write(fake.manifest(), without).unwrap();
    let said = fake.shown(&ok(&fake.run(
        "install",
        &[("APPROVAL_AGENT", "/private/var/run/approval-agent.sock")],
        "",
    )));
    assert!(
        said.contains("The approval popup (~/Library/LaunchAgents/dev.writ.popup.plist), started in your session"),
        "{said}"
    );
    let plist =
        fs::read_to_string(fake.home.join("Library/LaunchAgents/dev.writ.popup.plist")).unwrap();
    assert!(
        plist.contains(
            "<key>WRIT_APPROVAL_AGENT</key><string>/private/var/run/approval-agent.sock</string>"
        ),
        "{plist}"
    );
    let manifest = fake.shown(&fs::read_to_string(fake.manifest()).unwrap());
    assert!(
        manifest.ends_with(
            "userdir ~/Library\nuserdir ~/Library/LaunchAgents\n\
             userfile ~/Library/LaunchAgents/dev.writ.popup.plist\nagent dev.writ.popup\n"
        ),
        "{manifest}"
    );
    // The next upgrade keeps that plist (your answers) and starts the popup again.
    fs::write(fake.root.join(".calls"), "").unwrap();
    ok(&fake.run("install", &[], ""));
    assert_eq!(
        fs::read_to_string(fake.home.join("Library/LaunchAgents/dev.writ.popup.plist")).unwrap(),
        plist
    );
    let calls = fake.shown(&fake.calls());
    assert!(
        calls.contains(&format!("launchctl bootout gui/{}/dev.writ.popup\n", uid()))
            && calls.contains(&format!(
                "launchctl bootstrap gui/{} ~/Library/LaunchAgents/dev.writ.popup.plist\n",
                uid()
            )),
        "{calls}"
    );

    // Uninstalled: the popup stopped, its plist and the folders the install made gone.
    fs::write(fake.root.join(".calls"), "").unwrap();
    ok(&fake.run("uninstall", &[("REPOS", "keep")], ""));
    assert!(
        fake.shown(&fake.calls())
            .contains(&format!("launchctl bootout gui/{}/dev.writ.popup\n", uid())),
        "{}",
        fake.calls()
    );
    assert!(!fake.home.join("Library").exists(), "{:?}", fake.home());
    let mut expected = before;
    expected.extend(
        listing(&fake.at("/var/db/writ"))
            .iter()
            .map(|p| format!("var/db/writ/{p}")),
    );
    expected.push("var/db/writ".to_owned());
    expected.sort();
    assert_eq!(fake.tree(), expected);
}
