//! The keystore's data key rotated when a recipient is removed or replaced (the review after
//! M7.6, S-8), with the real `writd` and `writ`: on a passphrase keystore owed (said by `writ
//! info` and the change's answer) and done at the next unseal; on the Mac, against the fake
//! `writ-se`, at once on a hardware keystore. A copy of the keys directory taken before, with
//! what was taken out, opens nothing of the keystore after; the keys, the CA and a token still
//! work. A rotation cut short at each point of its sequence ends whole, old or new, and a
//! second unseal changes nothing; a record or staging directory not writd's refuses the start
//! by name. With them: M7.6's recovery marker moved out of the hardware recipients' names
//! (S-3), `writd recover` answered "no" changing nothing (S-6), `writd init` with a failing CA
//! device leaving nothing behind (S-10).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use writ_integration::daemon::{Approvals, Daemon, PASSPHRASE, ssh_options};
use writ_integration::https_remote::HttpsRemote;
use writ_integration::{stderr, stdout};
use writ_platform::DataKey;
use writ_platform::unlock::x25519::X25519Unwrap;
use writ_platform::unlock::{OpenError, PassphraseFile};

const POLICY: &str = r#"
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

const HTTPS_TOKEN: &str = "writ-test-rotation-https-token-0123456789";

const DEMO_TICKET: &str = "repos:\n  demo:\n    operations: [fetch]\n    branches: [\"agent/x\"]\n\
                           ticket:\n  title: \"Demo\"\n  task: Demo\nlimits:\n  ttl: 30m\n";
const WEB_TICKET: &str = "repos:\n  web:\n    operations: [fetch]\n    branches: [\"agent/x\"]\n\
                          ticket:\n  title: \"Web\"\n  task: Web\nlimits:\n  ttl: 30m\n";

fn ok(out: &Output) {
    assert!(out.status.success(), "{}{}", stdout(out), stderr(out));
}

fn keys(daemon: &Daemon) -> PathBuf {
    daemon.root().join("s/keys")
}

/// `writ recovery new`: the secret key and the recipient it prints.
fn new_recovery_key(daemon: &Daemon) -> (String, String) {
    let out = daemon.run(&["recovery", "new"], "");
    ok(&out);
    let said = stdout(&out);
    let secret = said
        .lines()
        .skip_while(|l| !l.starts_with("Recovery key "))
        .skip(1)
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or_else(|| panic!("{said}"))
        .to_owned();
    let recipient = said
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("writ admin recipient add recovery recipient=")
        })
        .unwrap_or_else(|| panic!("{said}"))
        .to_owned();
    (secret, recipient)
}

/// Every file under `dir`, by its path there, with its bytes.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, into: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if fs::symlink_metadata(&path).unwrap().is_dir() {
                walk(root, &path, into);
            } else {
                into.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    walk(dir, dir, &mut files);
    files
}

/// A copy of `dir` at `to`, modes kept (an operator's backup).
fn copy_dir(dir: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let target = to.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_dir(&path, &target);
        } else {
            fs::copy(&path, &target).unwrap();
        }
    }
}

/// The data key the recovery key `secret` opens from the `identity.recovery.age` in `dir`.
fn recovered(dir: &Path, secret: &str) -> Result<DataKey, String> {
    let way = X25519Unwrap::new("recovery", secret.parse::<age::x25519::Identity>().unwrap());
    writ_platform::unlock::data_key(&dir.join("identity.recovery.age"), &[&way])
        .map_err(|e| e.to_string())
}

/// Whether `key` opens the age file `file`.
fn opens(key: &DataKey, file: &Path) -> Result<(), OpenError> {
    let way = key.way().unwrap();
    writ_platform::unlock::open(
        &fs::read(file).unwrap(),
        &[&way],
        PassphraseFile::Refused,
        1 << 20,
    )
    .map(|_| ())
}

/// The age files of the keys directory sealed to a recipient (the identity's own file aside:
/// the passphrase's or the hardware's).
fn sealed_files(dir: &Path) -> Vec<PathBuf> {
    snapshot(dir)
        .into_keys()
        .filter(|p| p.extension().is_some_and(|x| x == "age"))
        .filter(|p| p != Path::new("identity.age"))
        .map(|p| dir.join(p))
        .collect()
}

/// `old` (the identity before a rotation) opens none of the keystore's files now: each
/// refused exactly as a file sealed to another identity is.
fn opens_nothing(old: &DataKey, dir: &Path) {
    let files = sealed_files(dir);
    // At least the CA, the authority key, a signing key and an upstream key.
    assert!(files.len() >= 4, "{files:?}");
    for file in files {
        match opens(old, &file) {
            Err(OpenError::NoWay) => {}
            other => panic!("{}: {other:?}", file.display()),
        }
    }
}

/// `key` (the identity in force) opens every file sealed to it: the CA, the authority key,
/// each signing and upstream key, and the tokens on a passphrase keystore (`tokens`; a
/// hardware keystore seals them to its recipients).
fn opens_all(key: &DataKey, dir: &Path, tokens: bool) {
    let files: Vec<PathBuf> = sealed_files(dir)
        .into_iter()
        .filter(|p| {
            let name = p.strip_prefix(dir).unwrap().to_string_lossy().into_owned();
            !name.starts_with("identity.recovery")
                && !name.starts_with("recovery-check")
                && (tokens || !name.starts_with("tokens/"))
        })
        .collect();
    assert!(files.len() >= 4, "{files:?}");
    for file in files {
        opens(key, &file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
}

/// A bare repo `web` on an HTTPS test remote, with one commit on `main`.
fn web_remote(runtime: &tokio::runtime::Runtime, root: &Path) -> HttpsRemote {
    let remote = HttpsRemote::start(runtime, root, HTTPS_TOKEN);
    let git = |cwd: &Path, args: &[&str]| {
        let out = Command::new("git")
            .args(["-c", "user.name=Up", "-c", "user.email=up@example.com"])
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
    };
    git(root, &["init", "-q", "--bare", "web.git"]);
    let seed = root.join("seed");
    fs::create_dir_all(&seed).unwrap();
    git(&seed, &["init", "-q", "-b", "main"]);
    git(&seed, &["commit", "-q", "--allow-empty", "-m", "first"]);
    git(
        &seed,
        &["push", "-q", root.join("web.git").to_str().unwrap(), "main"],
    );
    remote
}

/// The policy with the `web` repo on `remote`, its token `token-01`.
fn with_web(remote: &HttpsRemote) -> String {
    POLICY
        .replace(
            "keys:\n",
            "keys:\n  token-01:\n    use: upstream\n    kind: token\n    host: 127.0.0.1\n",
        )
        .replace(
            "templates:\n  feature:",
            &format!(
                "  web:\n    upstream: {}\n    upstream_credential: token-01\n    \
                 templates: [feature]\ntemplates:\n  feature:",
                remote.url("web")
            ),
        )
}

/// `writd.yaml` taking the HTTPS remote's CA, and the fake `writ-se` when `helper`.
fn edit_yaml(yaml: &str, ca: &Path, helper: bool) -> String {
    let yaml = yaml.replace(
        "mirrors: { fresh_for: 0s }",
        &format!("mirrors: {{ fresh_for: 0s, ca_certs: {} }}", ca.display()),
    );
    match helper {
        true => format!(
            "{yaml}signers:\n  se_cryptokit:\n    helper: {}\n",
            writ_integration::binaries::bin("writ-fake-se").display()
        ),
        false => yaml,
    }
}

fn ls_remote(daemon: &Daemon, lease: &str, repo: &str) -> Output {
    let ssh = format!(
        "ssh {}",
        ssh_options(&daemon.root().join("known_hosts"), &daemon.session(lease)).join(" ")
    );
    Command::new("git")
        .args([
            "ls-remote",
            &format!("ssh://git@127.0.0.1:{}/{repo}.git", daemon.agents_port),
        ])
        .env("GIT_SSH_COMMAND", ssh)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", daemon.root().join("home"))
        .output()
        .unwrap()
}

/// The leases of [`everything_works`]: one per repo.
struct Leases {
    demo: String,
    web: String,
}

impl Leases {
    fn of(daemon: &Daemon) -> Self {
        Self {
            demo: daemon.lease("demo", DEMO_TICKET),
            web: daemon.lease("web", WEB_TICKET),
        }
    }
}

/// The keys, the CA and the token work: a lease on each repo reads its upstream through the
/// daemon (the CA certified the session, the upstream key or the token reaches the remote),
/// and a new lease is certified.
fn everything_works(daemon: &Daemon, leases: &Leases) {
    for (lease, repo) in [(&leases.demo, "demo"), (&leases.web, "web")] {
        let out = ls_remote(daemon, lease, repo);
        assert_eq!(out.status.code(), Some(0), "{repo}: {}", stderr(&out));
    }
}

fn recipient_add(daemon: &Daemon, name: &str, recipient: &str) {
    ok(&daemon.run(
        &[
            "admin",
            "recipient",
            "add",
            name,
            &format!("recipient={recipient}"),
            "--yes",
        ],
        "",
    ));
}

/// What [`passphrase_keystore`] keeps running: the remote, on its runtime.
type Remote = (tokio::runtime::Runtime, HttpsRemote);

/// A passphrase keystore with a token and the recovery key `recovery` (`R1`), unsealed.
fn passphrase_keystore(root: &Path) -> (Daemon, Remote, (String, String)) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let remote = web_remote(&runtime, root);
    let ca = root.join("web-ca.pem");
    fs::write(&ca, &remote.ca_pem).unwrap();
    let daemon = Daemon::start_sealed_with(&with_web(&remote), Approvals::Ssh, |yaml| {
        edit_yaml(yaml, &ca, false)
    });
    ok(&daemon.unseal());
    ok(&daemon.run(
        &["admin", "token", "token-01", "--yes"],
        &format!("{HTTPS_TOKEN}\n"),
    ));
    let r1 = new_recovery_key(&daemon);
    recipient_add(&daemon, "recovery", &r1.1);
    (daemon, (runtime, remote), r1)
}

/// The guarantee "a recipient taken out opens no copy of the keystore made from then on", on
/// a passphrase keystore: owed (the daemon holds no passphrase), said, done at the next
/// unseal; the old recovery key with a copy taken before opens nothing after.
#[test]
fn on_a_passphrase_keystore_a_replaced_recovery_key_is_owed_then_the_unseal_rotates_the_data_key() {
    let remote_dir = tempfile::tempdir().unwrap();
    let (mut daemon, _remote, (r1, r1_recipient)) = passphrase_keystore(remote_dir.path());
    let leases = Leases::of(&daemon);
    let dir = keys(&daemon);
    let before = remote_dir.path().join("before");
    copy_dir(&dir, &before);
    let recipient_before = fs::read_to_string(dir.join("recipient")).unwrap();

    // Replaced: owed, and said so in the answer.
    let (r2, r2_recipient) = new_recovery_key(&daemon);
    let out = daemon.run(
        &[
            "admin",
            "recipient",
            "set",
            "recovery",
            &format!("recipient={r2_recipient}"),
            "--yes",
        ],
        "",
    );
    ok(&out);
    let owed = format!("the recovery recipient {r1_recipient} replaced");
    assert!(
        stdout(&out).contains(&format!(
            "Keystore: the keystore's data key is to be rotated ({owed}): this passphrase \
             keystore rotates it at its next unseal"
        )),
        "{}",
        stdout(&out)
    );
    assert!(dir.join("rotation-owed").exists());
    // Until then the old key, with the copy, still opens the keystore in force: as said.
    let old = recovered(&before, &r1).unwrap();
    opens(&old, &dir.join("ca.age")).unwrap();
    // The new key checks at once (the recovery files are its).
    ok(&daemon.run(&["recovery", "check"], &format!("{r2}\n")));

    // The next unseal says it rotates, then does.
    daemon.restart();
    let out = daemon.unseal();
    ok(&out);
    assert!(
        stdout(&out).contains(&format!(
            "This unseal rotates the keystore's data key first ({owed})"
        )),
        "{}",
        stdout(&out)
    );
    assert!(!dir.join("rotation-owed").exists());
    assert!(!dir.join("rotation").exists());
    assert_ne!(
        fs::read_to_string(dir.join("recipient")).unwrap(),
        recipient_before
    );
    assert!(
        daemon
            .audit()
            .contains("keystore: at unseal, the keystore's data key rotated"),
        "{}",
        daemon.audit()
    );
    // The old key with the copy: the old identity, which opens nothing now; the old key opens
    // no file of the keystore in force.
    opens_nothing(&recovered(&before, &r1).unwrap(), &dir);
    let refused = recovered(&dir, &r1).unwrap_err();
    assert!(
        refused.ends_with("identity.recovery.age: nothing given unwraps it"),
        "{refused}"
    );
    // The new key opens every file sealed to the identity: the keys and, on a passphrase
    // keystore, the tokens.
    opens_all(&recovered(&dir, &r2).unwrap(), &dir, true);
    everything_works(&daemon, &leases);
    ok(&daemon.run(&["recovery", "check"], &format!("{r2}\n")));

    // A second unseal changes nothing.
    let settled = snapshot(&dir);
    daemon.restart();
    ok(&daemon.unseal());
    assert_eq!(snapshot(&dir), settled);
}

/// Where a rotation is cut short, and which keystore it must end as: the old one (nothing in
/// force changed before the commit) or the new one.
const CUTS: [(&str, bool); 4] = [
    ("staged", false),
    ("committed", true),
    ("moved-one", true),
    ("moved", true),
];

/// A rotation cut short at each point of its sequence (a test build's hook stops `writd`
/// there, as a crash would): the start that follows ends it whole, the old keystore or the
/// new one exactly, from the keystore's own record; the unseal then opens it (rotating if it
/// is still owed), and a second unseal changes nothing.
#[test]
fn a_rotation_cut_short_at_each_point_ends_whole_old_or_new_and_a_second_unseal_changes_nothing() {
    for (point, new) in CUTS {
        let remote_dir = tempfile::tempdir().unwrap();
        let (mut daemon, _remote, _) = passphrase_keystore(remote_dir.path());
        let leases = Leases::of(&daemon);
        let (r2, r2_recipient) = new_recovery_key(&daemon);
        ok(&daemon.run(
            &[
                "admin",
                "recipient",
                "set",
                "recovery",
                &format!("recipient={r2_recipient}"),
                "--yes",
            ],
            "",
        ));
        let dir = keys(&daemon);
        let old = snapshot(&dir);
        let old_key = recovered(&dir, &r2).unwrap();

        daemon.restart_with_env(&[("WRIT_TEST_ROTATION_STOP", point)]);
        let out = daemon.unseal();
        // The daemon gone mid-answer: `writ` fails, the keystore left as the cut left it.
        assert_eq!(out.status.code(), Some(1), "{point}: {}", stdout(&out));
        assert_eq!(
            daemon.exited().code(),
            Some(86),
            "{point}: {}",
            daemon.log()
        );

        // The start settles it: no staging left, and the keystore whole.
        daemon.restart();
        assert!(!dir.join("rotation").exists(), "{point}");
        let now = snapshot(&dir);
        match new {
            false => assert_eq!(now, old, "{point}: not the old keystore exactly"),
            true => {
                assert!(!dir.join("rotation-owed").exists(), "{point}");
                assert_ne!(
                    now.get(Path::new("recipient")),
                    old.get(Path::new("recipient"))
                );
                opens_nothing(&old_key, &dir);
                opens_all(&recovered(&dir, &r2).unwrap(), &dir, true);
            }
        }
        // The unseal opens it (and rotates when the cut came before the commit).
        ok(&daemon.unseal());
        assert!(!dir.join("rotation-owed").exists(), "{point}");
        opens_nothing(&old_key, &dir);
        everything_works(&daemon, &leases);
        let settled = snapshot(&dir);
        daemon.restart();
        ok(&daemon.unseal());
        assert_eq!(
            snapshot(&dir),
            settled,
            "{point}: the second unseal changed it"
        );
    }
}

/// What isn't a record or a staging directory writd wrote refuses the start, by name (the
/// unseal never runs on it); staging with no record is a rotation never committed, removed.
#[test]
fn a_rotation_record_or_staging_not_writd_s_refuses_the_start_by_name() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    ok(&daemon.unseal());
    let dir = keys(&daemon);
    let staging = dir.join("rotation");
    let ca = fs::read(dir.join("ca.age")).unwrap();
    let digest = "0".repeat(64);
    let record = |text: &str| {
        let _ = fs::remove_dir_all(&staging);
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(
            &staging,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        fs::write(staging.join("commit"), text).unwrap();
    };
    for (text, said) in [
        (
            "garbage\n".to_owned(),
            "rotation/commit: not a writ-rotation/1 record: refused (not a record writd wrote)",
        ),
        (
            format!("writ-rotation/1\nput ../../policy.yaml sha256:{digest}\n"),
            "\"../../policy.yaml\" is not a file of the keystore: refused",
        ),
        (
            format!("writ-rotation/1\nput ca.age sha256:{digest}\n"),
            "ca.age: neither staged nor in place as its rotation's record says: refused",
        ),
    ] {
        record(&text);
        let refused = daemon.restart_refused();
        assert!(refused.contains(said), "{text:?}: {refused}");
        assert_eq!(fs::read(dir.join("ca.age")).unwrap(), ca, "{text:?}");
    }
    // A staged file that isn't the one the record names: refused, nothing moved.
    record(&format!("writ-rotation/1\nput ca.age sha256:{digest}\n"));
    fs::write(staging.join("ca.age"), b"planted").unwrap();
    fs::set_permissions(
        staging.join("ca.age"),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let refused = daemon.restart_refused();
    assert!(
        refused.contains("rotation/ca.age: not the file its rotation's record names: refused"),
        "{refused}"
    );
    assert_eq!(fs::read(dir.join("ca.age")).unwrap(), ca);
    // Not a directory.
    fs::remove_dir_all(&staging).unwrap();
    fs::write(&staging, b"x").unwrap();
    let refused = daemon.restart_refused();
    assert!(
        refused.contains("rotation: not the directory a rotation of the data key stages in"),
        "{refused}"
    );
    fs::remove_file(&staging).unwrap();
    // A rotation owed that isn't writd's record.
    fs::write(dir.join("rotation-owed"), "anything\n").unwrap();
    let refused = daemon.restart_refused();
    assert!(
        refused.contains("rotation-owed: not a record writd wrote: refused"),
        "{refused}"
    );
    fs::remove_file(dir.join("rotation-owed")).unwrap();
    // Staging with no record: never committed, removed; the keystore opens as it was.
    fs::create_dir(&staging).unwrap();
    fs::write(staging.join("ca.age"), b"never committed").unwrap();
    daemon.restart();
    assert!(!staging.exists());
    assert_eq!(fs::read(dir.join("ca.age")).unwrap(), ca);
    ok(&daemon.unseal());
}

/// M7.6 kept the recovery marker as `recipients/recovery.pub`, where a hardware recipient
/// named `recovery` would put its own (S-3): an existing keystore's is moved out once, at
/// start, and nothing else changes.
#[test]
fn an_m7_6_recovery_marker_is_moved_out_of_the_hardware_recipients_names_once() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    ok(&daemon.unseal());
    let (secret, recipient) = new_recovery_key(&daemon);
    recipient_add(&daemon, "recovery", &recipient);
    let dir = keys(&daemon);
    let marker = dir.join("identity.recovery.pub");
    assert_eq!(
        fs::read_to_string(&marker).unwrap(),
        format!("{recipient}\n")
    );
    // M7.6's layout.
    daemon.stop();
    let old = dir.join("recipients/recovery.pub");
    fs::create_dir_all(dir.join("recipients")).unwrap();
    fs::rename(&marker, &old).unwrap();
    let mut before = snapshot(&dir);
    daemon.restart();
    assert!(!old.exists());
    assert_eq!(
        fs::read_to_string(&marker).unwrap(),
        format!("{recipient}\n")
    );
    // Nothing else moved, and no rotation: the marker named the recipient in force.
    let moved = before.remove(Path::new("recipients/recovery.pub")).unwrap();
    before.insert(PathBuf::from("identity.recovery.pub"), moved);
    assert_eq!(snapshot(&dir), before);
    ok(&daemon.unseal());
    assert_eq!(snapshot(&dir), before);
    ok(&daemon.run(&["recovery", "check"], &format!("{secret}\n")));
}

/// `writd recover` asks every question before it touches the keystore (S-6): "no" to trusting
/// the versions altered at rest, after a policy that drops the recovery recipient, changes
/// nothing (its files, the data key, no rotation started).
#[test]
fn writd_recover_answered_no_changes_nothing_even_for_a_policy_dropping_a_recipient() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    ok(&daemon.unseal());
    let (_, recipient) = new_recovery_key(&daemon);
    recipient_add(&daemon, "recovery", &recipient);
    let shown = daemon.run(&["admin", "show", "policy"], "");
    ok(&shown);
    let block = format!("recipients:\n  recovery:\n    recipient: {recipient}\n");
    let without = stdout(&shown).replace(&block, "");
    assert_ne!(without, stdout(&shown), "{}", stdout(&shown));
    fs::write(daemon.root().join("recovered.yaml"), &without).unwrap();
    daemon.stop();
    daemon.alter_at_rest("policy", |text| format!("{text}# altered at rest\n"));
    let dir = keys(&daemon);
    let before = snapshot(&dir);
    let out = daemon.writd_with(
        &["recover", "writd.yaml", "policy", "recovered.yaml"],
        &format!("{PASSPHRASE}\nn\n"),
    );
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains(
            "not recovered: the versions in force don't carry this keystore's MAC (altered, \
             or another keystore's state), and the others weren't trusted"
        ),
        "{}",
        stderr(&out)
    );
    assert!(stdout(&out).contains("Trust them and seal all three with this keystore? [y/N]"));
    assert_eq!(snapshot(&dir), before, "the keystore changed");
}

/// `writd recover` with a policy that takes the recovery recipient out rotates the data key
/// there, the passphrase given wrapping the new identity: the old identity opens nothing after,
/// the daemon unseals with the same passphrase.
#[test]
fn writd_recover_rotates_the_data_key_for_a_policy_taking_a_recipient_out() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    ok(&daemon.unseal());
    let (secret, recipient) = new_recovery_key(&daemon);
    recipient_add(&daemon, "recovery", &recipient);
    let shown = daemon.run(&["admin", "show", "policy"], "");
    ok(&shown);
    let block = format!("recipients:\n  recovery:\n    recipient: {recipient}\n");
    let without = stdout(&shown).replace(&block, "");
    assert_ne!(without, stdout(&shown));
    fs::write(daemon.root().join("recovered.yaml"), &without).unwrap();
    daemon.stop();
    let dir = keys(&daemon);
    let old = recovered(&dir, &secret).unwrap();
    let out = daemon.writd_with(
        &["recover", "writd.yaml", "policy", "recovered.yaml"],
        &format!("{PASSPHRASE}\n"),
    );
    ok(&out);
    assert!(
        stdout(&out).contains(&format!(
            "keystore: the keystore's data key rotated (the recovery recipient {recipient} \
             removed)"
        )),
        "{}",
        stdout(&out)
    );
    assert!(!dir.join("identity.recovery.age").exists());
    assert!(!dir.join("identity.recovery.pub").exists());
    opens_nothing(&old, &dir);
    assert!(
        daemon
            .audit()
            .contains("keystore: by writd recover, the keystore's data key rotated"),
        "{}",
        daemon.audit()
    );
    daemon.restart();
    ok(&daemon.unseal());
}

/// On the Mac, against the fake `writ-se` (never the real Secure Enclave): a hardware
/// keystore rotates its data key at once when its recovery recipient is replaced, and again
/// when a hardware recipient is removed. One hardware recipient is named `recovery` (S-3).
#[test]
fn on_the_mac_a_replaced_recovery_key_or_a_removed_hardware_key_rotates_the_data_key_at_once() {
    if !writ_integration::on_the_mac("this test") {
        return;
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let remote_dir = tempfile::tempdir().unwrap();
    let remote = web_remote(&runtime, remote_dir.path());
    let ca = remote_dir.path().join("web-ca.pem");
    fs::write(&ca, &remote.ca_pem).unwrap();
    let mut daemon = Daemon::start_sealed_with(&with_web(&remote), Approvals::Ssh, |yaml| {
        edit_yaml(yaml, &ca, true)
    });
    ok(&daemon.unseal());
    ok(&daemon.run(
        &["admin", "token", "token-01", "--yes"],
        &format!("{HTTPS_TOKEN}\n"),
    ));
    let (r1, r1_recipient) = new_recovery_key(&daemon);
    recipient_add(&daemon, "offline", &r1_recipient);
    for name in ["recovery", "se-02"] {
        ok(&daemon.run(
            &[
                "admin",
                "recipient",
                "add",
                name,
                "backend=se-cryptokit",
                "--yes",
            ],
            "",
        ));
    }
    let dir = keys(&daemon);
    assert!(dir.join("recipients/recovery.blob").exists());
    let leases = Leases::of(&daemon);

    // The recovery recipient replaced: rotated at once.
    let before = remote_dir.path().join("before-1");
    copy_dir(&dir, &before);
    let (r2, r2_recipient) = new_recovery_key(&daemon);
    let out = daemon.run(
        &[
            "admin",
            "recipient",
            "set",
            "offline",
            &format!("recipient={r2_recipient}"),
            "--yes",
        ],
        "",
    );
    ok(&out);
    assert!(
        stdout(&out).contains(&format!(
            "Keystore: the keystore's data key rotated (the recovery recipient {r1_recipient} \
             replaced)"
        )),
        "{}",
        stdout(&out)
    );
    assert!(!dir.join("rotation-owed").exists());
    opens_nothing(&recovered(&before, &r1).unwrap(), &dir);
    // The token, sealed to the hardware and the recovery recipient: the new key opens it,
    // the old one doesn't.
    let token = dir.join("tokens/token-01.age");
    let r1_way = X25519Unwrap::new("r1", r1.parse::<age::x25519::Identity>().unwrap());
    assert!(matches!(
        writ_platform::unlock::open(
            &fs::read(&token).unwrap(),
            &[&r1_way],
            PassphraseFile::Refused,
            1 << 20
        ),
        Err(OpenError::NoWay)
    ));
    let r2_way = X25519Unwrap::new("r2", r2.parse::<age::x25519::Identity>().unwrap());
    writ_platform::unlock::open(
        &fs::read(&token).unwrap(),
        &[&r2_way],
        PassphraseFile::Refused,
        1 << 20,
    )
    .unwrap();
    everything_works(&daemon, &leases);

    // A hardware recipient removed: rotated at once; the identity it opened (from a copy
    // taken before) opens nothing after.
    let before = remote_dir.path().join("before-2");
    copy_dir(&dir, &before);
    let out = daemon.run(&["admin", "recipient", "remove", "se-02", "--yes"], "");
    ok(&out);
    assert!(
        stdout(&out).contains(
            "Keystore: the keystore's data key rotated (hardware recipient se-02 removed)"
        ),
        "{}",
        stdout(&out)
    );
    assert!(!dir.join("recipients/se-02.blob").exists());
    assert!(!dir.join("recipients/se-02.pub").exists());
    opens_nothing(&recovered(&before, &r2).unwrap(), &dir);
    opens_all(&recovered(&dir, &r2).unwrap(), &dir, false);
    everything_works(&daemon, &leases);

    // A start again: the device (the one left, named `recovery`) unseals, no passphrase.
    daemon.restart();
    ok(&daemon.run(&["unseal"], ""));
    everything_works(&daemon, &leases);
    ok(&daemon.run(&["recovery", "check"], &format!("{r2}\n")));
}

/// A CA owed by `writd init --ca-backend <device>` (2026-11-14: a device key is made only by
/// the running daemon) whose device fails to make it at the first start: the start stops,
/// naming it, nothing made and the CA still owed; the device back, the next start makes it
/// (S-10 was `writd init` failing there and leaving a half-made keystore: it now never
/// touches the device). On the Mac, the fake `writ-se` refusing to make it.
#[test]
fn on_the_mac_a_ca_device_that_fails_at_the_first_start_keeps_the_ca_owed() {
    if !writ_integration::on_the_mac("this test") {
        return;
    }
    let helper = writ_integration::binaries::bin("writ-fake-se");
    let mut daemon = Daemon::start_sealed_init(
        POLICY,
        Approvals::Ssh,
        &["--ca-backend", "se-cryptokit"],
        |yaml| {
            format!(
                "{yaml}signers:\n  se_cryptokit:\n    helper: {}\n",
                helper.display()
            )
        },
    );
    daemon.stop();
    let root = daemon.root().to_owned();
    for dir in ["s/keys", "s/boot"] {
        fs::remove_dir_all(root.join(dir)).unwrap();
        fs::create_dir(root.join(dir)).unwrap();
    }
    fs::remove_file(root.join("s/leases.db")).unwrap();
    // The helper, refusing to make a key.
    let faulty = root.join("faulty-se");
    fs::write(
        &faulty,
        format!(
            "#!/bin/sh\nexec {} --fault create:refuse \"$@\"\n",
            helper.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&faulty, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let yaml = fs::read_to_string(root.join("writd.yaml")).unwrap();
    let helper_line = format!("helper: {}", helper.display());
    assert!(yaml.contains(&helper_line));
    fs::write(
        root.join("writd.yaml"),
        yaml.replace(&helper_line, &format!("helper: {}", faulty.display())),
    )
    .unwrap();
    // `writd init` never asks the device to make it: it says it is owed.
    let out = daemon.writd_with(
        &["init", "writd.yaml", "--ca-backend", "se-cryptokit"],
        &format!("{PASSPHRASE}\n"),
    );
    ok(&out);
    assert!(
        stdout(&out).contains(
            "CA key: on se-cryptokit, owed: the daemon makes it at its first start (its log \
             says so)"
        ),
        "{}",
        stdout(&out)
    );
    let owed = root.join("s/keys/to-make.json");
    assert!(owed.exists());
    assert!(!root.join("s/keys/ca.age").exists());
    // The first start: the device refuses, the start stops naming it, the CA still owed.
    let refused = daemon.restart_refused();
    assert!(
        refused.contains("the helper refused: refused-on-demand"),
        "{refused}"
    );
    assert!(owed.exists(), "{refused}");
    for file in ["ca.age", "ca.pub", "ca.backend"] {
        assert!(
            !root.join("s/keys").join(file).exists(),
            "{file}: {refused}"
        );
    }
    // The device back: the next start makes it, and the file is gone.
    fs::write(root.join("writd.yaml"), &yaml).unwrap();
    daemon.restart();
    assert!(!owed.exists());
    let public = fs::read_to_string(root.join("s/keys/ca.pub")).unwrap();
    assert!(public.starts_with("ecdsa-sha2-nistp256 "), "{public}");
    assert_eq!(
        fs::read_to_string(root.join("s/keys/ca.backend")).unwrap(),
        "se-cryptokit\n"
    );
    assert!(
        daemon.audit().contains(&format!(
            "the CA's key made on se-cryptokit at the daemon's start (owed by a command run \
             by hand): {}",
            public.trim()
        )),
        "{}",
        daemon.audit()
    );
}
