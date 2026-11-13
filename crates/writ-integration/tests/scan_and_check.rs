//! The daemon's two checks (M6.2) with the real binaries: `writ admin host add` has the daemon
//! scan the host on the approver's signature (shown with fingerprints, compared by the approver,
//! pinned by a second signed change only when they match; a host not reached or silent past
//! `mirrors.scan_timeout` refused with why), and `writ admin repo check` reaches a repo's
//! upstream with its credential (read, sync, write with nothing pushed; a credential without
//! access fails at the step it fails). Each one logged.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use writ_core::config::PolicyConfig;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::HashAlg;
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::remote::TestRemote;
use writ_integration::terminal::on_terminal;
use writ_integration::{audit_events, stderr, stdout};

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
  upstream-02:
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

fn in_force(daemon: &Daemon) -> PolicyConfig {
    let out = daemon.run(&["admin", "show", "policy"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    PolicyConfig::from_yaml(&stdout(&out)).unwrap()
}

/// The pinned keys of `host`, as the policy in force holds them.
fn pins(daemon: &Daemon, host: &str) -> Option<Vec<String>> {
    in_force(daemon)
        .upstream_hosts()
        .iter()
        .find(|(name, _)| name.to_string() == host)
        .map(|(_, keys)| keys.iter().map(ToString::to_string).collect())
}

#[test]
fn a_host_is_scanned_on_a_signature_pinned_once_compared_and_a_repo_checked() {
    let daemon = Daemon::start_with(POLICY, Approvals::Ssh, |yaml| {
        yaml.replace(
            "mirrors: { fresh_for: 0s }",
            "mirrors: { fresh_for: 0s, scan_timeout: 2s }",
        )
    });
    // A second host, not pinned: the one an approver adds.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let other = TestRemote::start(
        &runtime,
        &daemon.root().join("other-remote"),
        generate(KeyKind::Ed25519).unwrap().public_key().clone(),
    );
    let host = format!("[127.0.0.1]:{}", other.port);
    let public = other.host_key.public_key();
    let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
    let key_line = public.to_openssh().unwrap();

    // Without a terminal and no keys given: refused, nothing reached.
    let out = daemon.run(&["admin", "host", "add", &host], "");
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains(
            "host add scans the host on a terminal, where you compare its keys: without one, \
             give keys=<type> <base64>,…"
        ),
        "{}",
        stderr(&out)
    );
    assert_eq!(daemon.audited("scan", "allowed"), 0);

    // On a terminal: scanned, shown, not matching (answered no): nothing pinned.
    let (status, shown) = on_terminal(daemon.writ(&["admin", "host", "add", &host]), &["n"]);
    // Answered no: nothing signed, the exit says so (6).
    assert_eq!(status.code(), Some(6), "{shown}");
    assert!(
        shown.contains(&format!("{host} offered these keys")),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("  ssh-ed25519 {fingerprint}\r\n")),
        "{shown}"
    );
    assert!(shown.contains("Nothing pinned."), "{shown}");
    assert_eq!(pins(&daemon, &host), None);

    // Matching: the second signed change pins exactly what was scanned.
    let (status, shown) = on_terminal(
        daemon.writ(&["admin", "host", "add", &host, "--yes"]),
        &["y"],
    );
    assert!(status.success(), "{shown}");
    let pinned = pins(&daemon, &host).expect("pinned");
    assert_eq!(pinned.len(), 1);
    assert_eq!(
        pinned[0].split(' ').take(2).collect::<Vec<_>>(),
        key_line.split(' ').take(2).collect::<Vec<_>>()
    );
    // Each scan logged before the daemon connects out, then with its fingerprints, both with
    // the approver who signed it.
    let started = audit_events(&daemon.audit(), "scan", "allowed");
    assert_eq!(started.len(), 2, "{started:?}");
    assert_eq!(
        started[1]["reason"],
        format!("127.0.0.1:{}: scanning", other.port)
    );
    assert_eq!(started[1]["approver"], started[0]["approver"]);
    let scans = audit_events(&daemon.audit(), "scan", "done");
    assert_eq!(scans.len(), 2, "{scans:?}");
    assert_eq!(
        scans[1]["reason"],
        format!("127.0.0.1:{}: {fingerprint}", other.port)
    );
    assert!(
        scans[1]["approver"]
            .as_str()
            .unwrap()
            .starts_with("SHA256:")
    );

    // Its key changed (the pin holds another one, beside an RSA key a scan can't read):
    // rescanned, each key shown against the pin, the RSA one kept, the pin replaced.
    let old = generate(KeyKind::Ed25519)
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap();
    let rsa_path = daemon.root().join("host-rsa");
    let made = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "rsa", "-b", "3072", "-N", "", "-C", "", "-f"])
        .arg(&rsa_path)
        .status()
        .unwrap();
    assert!(made.success());
    let rsa = std::fs::read_to_string(rsa_path.with_extension("pub")).unwrap();
    let rsa = rsa.split(' ').take(2).collect::<Vec<_>>().join(" ");
    let out = daemon.run(
        &[
            "admin",
            "host",
            "set",
            &host,
            &format!("keys={old},{rsa}"),
            "--yes",
        ],
        "",
    );
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    // Without a terminal: refused, naming set.
    let out = daemon.run(&["admin", "host", "rescan", &host], "");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains(&format!(
            "rescan compares the host's keys on a terminal: without one, writ admin host set \
             {host} keys=<type> <base64>,… replaces them"
        )),
        "{}",
        stderr(&out)
    );
    // A host not pinned: refused, naming add.
    let (status, shown) = on_terminal(
        daemon.writ(&["admin", "host", "rescan", "[127.0.0.1]:1"]),
        &[],
    );
    assert_eq!(status.code(), Some(1), "{shown}");
    assert!(
        shown.contains("no host [127.0.0.1]:1 in the policy in force (writ admin host add"),
        "{shown}"
    );
    // Not matching: nothing changed.
    let (status, shown) = on_terminal(daemon.writ(&["admin", "host", "rescan", &host]), &["n"]);
    assert_eq!(status.code(), Some(6), "{shown}");
    assert!(
        shown.contains(&format!(
            "  ssh-ed25519 {fingerprint}  (new: not in the pin)\r\n"
        )),
        "{shown}"
    );
    assert!(
        shown.contains("  ssh-ed25519 (pinned, no longer offered: it goes)\r\n"),
        "{shown}"
    );
    assert!(shown.contains("Nothing pinned."), "{shown}");
    assert_eq!(pins(&daemon, &host).unwrap().len(), 2);
    // Matching: the scanned key replaces the old one, the RSA one kept.
    let (status, shown) = on_terminal(
        daemon.writ(&["admin", "host", "rescan", &host, "--yes"]),
        &["y"],
    );
    assert!(status.success(), "{shown}");
    assert!(
        shown.contains("Kept the pinned ssh-rsa key (a scan reads no ssh-rsa key"),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("with host {host} rescanned")),
        "{shown}"
    );
    let now: Vec<String> = pins(&daemon, &host)
        .unwrap()
        .iter()
        .map(|k| k.split(' ').take(2).collect::<Vec<_>>().join(" "))
        .collect();
    let scanned_key = key_line.split(' ').take(2).collect::<Vec<_>>().join(" ");
    assert_eq!(now.len(), 2, "{now:?}");
    assert!(now.contains(&scanned_key) && now.contains(&rsa), "{now:?}");
    // Rescanned again: the pin holds them already.
    let (status, shown) = on_terminal(daemon.writ(&["admin", "host", "rescan", &host]), &["y"]);
    assert!(status.success(), "{shown}");
    assert!(
        shown.contains(&format!("  ssh-ed25519 {fingerprint}  (pinned)\r\n")),
        "{shown}"
    );
    assert!(
        shown.contains("The pin already holds these keys: nothing changed."),
        "{shown}"
    );

    // A host that refuses the connection, and one silent past mirrors.scan_timeout.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let (status, shown) = on_terminal(
        daemon.writ(&[
            "admin",
            "host",
            "add",
            &format!("[127.0.0.1]:{closed_port}"),
        ]),
        &[],
    );
    assert_eq!(status.code(), Some(1), "{shown}");
    assert!(
        shown.contains(&format!(
            "cannot reach 127.0.0.1:{closed_port}: connection refused"
        )),
        "{shown}"
    );
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let silent_port = silent.local_addr().unwrap().port();
    let (status, shown) = on_terminal(
        daemon.writ(&[
            "admin",
            "host",
            "add",
            &format!("[127.0.0.1]:{silent_port}"),
        ]),
        &[],
    );
    drop(silent);
    assert_eq!(status.code(), Some(1), "{shown}");
    assert!(
        shown.contains(&format!(
            "cannot reach 127.0.0.1:{silent_port}: no answer within 2s (mirrors.scan_timeout)"
        )),
        "{shown}"
    );
    // Each failing scan went out (its line first), then was denied with why.
    assert_eq!(daemon.audited("scan", "denied"), 2);
    assert_eq!(daemon.audited("scan", "allowed"), 7);
    assert_eq!(daemon.audited("scan", "done"), 5);

    // The check: read, sync, write with nothing pushed, against the repo's upstream.
    let head = daemon.upstream_commit("main", "upstream work");
    let pushes = daemon.remote.receive_packs();
    let out = daemon.run(&["admin", "repo", "check", "demo"], "");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let printed = stdout(&out);
    assert!(
        printed.contains("  read: ok: upstream answers with its credential, 1 ref\n"),
        "{printed}"
    );
    assert!(
        printed.contains("  sync: ok: the mirror synced, 1 ref moved"),
        "{printed}"
    );
    assert!(
        printed
            .contains("  write: ok: upstream takes pushes with its credential (nothing pushed)\n"),
        "{printed}"
    );
    assert!(printed.contains("demo is ready"), "{printed}");
    // Write access proven by receive-pack answering, nothing sent: upstream as it was.
    assert_eq!(daemon.remote.receive_packs(), pushes + 1);
    let upstream = std::process::Command::new("git")
        .args(["rev-parse", "main"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .current_dir(daemon.remote.repo("demo"))
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&upstream.stdout).trim(), head);
    assert_eq!(daemon.audited("check", "allowed"), 1);

    // A repo whose credential the remote doesn't take: added without a terminal (the check
    // left to run by hand), then checked: read fails, nothing after it.
    let out = daemon.run(
        &[
            "admin",
            "repo",
            "add",
            "locked",
            &format!("upstream={}", daemon.remote.url("demo")),
            "upstream_credential=upstream-02",
            "templates=feature",
            "--yes",
        ],
        "",
    );
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert!(
        stdout(&out).contains("Once its credential is registered: writ admin repo check locked"),
        "{}",
        stdout(&out)
    );
    let out = daemon.run(&["admin", "repo", "check", "locked"], "");
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    let printed = stdout(&out);
    assert!(printed.contains("  read: failed: "), "{printed}");
    assert!(!printed.contains("  sync:"), "{printed}");
    assert_eq!(daemon.audited("check", "denied"), 1);

    // A hostile upstream: what it says comes back escaped, in the output and the audit line.
    daemon.remote.set_mode(writ_integration::remote::Mode::Say(
        b"fatal: \x1b]0;owned\x07\x1b[2Jrepository gone\r\nforged: ok\n".to_vec(),
    ));
    let out = daemon.run(&["admin", "repo", "check", "demo"], "");
    daemon
        .remote
        .set_mode(writ_integration::remote::Mode::Serve);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    let printed = stdout(&out);
    assert!(printed.contains("  read: failed: "), "{printed}");
    assert!(printed.contains("repository gone"), "{printed}");
    assert!(
        !printed.contains('\x1b') && !printed.contains('\x07'),
        "{printed:?}"
    );
    assert!(!printed.contains("\nforged: ok"), "{printed:?}");
    let denied = audit_events(&daemon.audit(), "check", "denied");
    let reason = denied.last().unwrap()["reason"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        reason.starts_with("read: ") && reason.contains("repository gone"),
        "{reason}"
    );
    assert!(
        !reason.contains('\x1b') && !reason.contains('\n'),
        "{reason:?}"
    );

    // A remote with endless refs: the read stops at its bound, failed.
    daemon
        .remote
        .set_mode(writ_integration::remote::Mode::Flood(3 << 20));
    let out = daemon.run(&["admin", "repo", "check", "demo"], "");
    daemon
        .remote
        .set_mode(writ_integration::remote::Mode::Serve);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    let printed = stdout(&out);
    assert!(
        printed.contains("  read: failed: repo demo: check failed: "),
        "{printed}"
    );
    assert!(!printed.contains("  sync:"), "{printed}");

    // A repo not in the registry: refused before anything is reached.
    let out = daemon.run(&["admin", "repo", "check", "nowhere"], "");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("repo nowhere is not in the registry"),
        "{}",
        stderr(&out)
    );
    assert_eq!(daemon.audited("check", "denied"), 4);
}

#[test]
fn a_host_behind_a_proxy_is_scanned_through_it_on_the_approver_s_signature() {
    use writ_integration::proxy::{ProxyKind, TestProxy};

    // A remote the daemon reaches only through the proxy, under names only the proxy
    // resolves: one pinned with a repo behind the proxy, one an approver adds.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let remote = TestRemote::start(
        &runtime,
        &dir.path().join("remote"),
        generate(KeyKind::Ed25519).unwrap().public_key().clone(),
    );
    let proxy = TestProxy::start(&runtime, ProxyKind::Socks5, None);
    let at = ([127, 0, 0, 1], remote.port).into();
    proxy.map("pinned.invalid", at);
    proxy.map("added.invalid", at);
    let public = remote.host_key.public_key();
    let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
    let key: Vec<String> = public
        .to_openssh()
        .unwrap()
        .split(' ')
        .take(2)
        .map(str::to_owned)
        .collect();
    let pinned = format!("[pinned.invalid]:{}", remote.port);
    let policy = POLICY.replacen(
        "repos:\n",
        &format!(
            "  \"{pinned}\":\n    - \"{}\"\nproxies:\n  p:\n    url: \"{}\"\nrepos:\n  \
                 behind:\n    upstream: ssh://git@pinned.invalid:{}/demo.git\n    \
                 upstream_credential: upstream-02\n    proxy: p\n    templates: [feature]\n",
            key.join(" "),
            proxy.url(),
            remote.port
        ),
        1,
    );
    let daemon = Daemon::start_with(&policy, Approvals::Ssh, |yaml| {
        yaml.replace(
            "mirrors: { fresh_for: 0s }",
            "mirrors: { fresh_for: 0s, scan_timeout: 2s }",
        )
    });

    // A rescan with no --proxy goes through the one its repos share: the pin is current.
    let (status, shown) = on_terminal(daemon.writ(&["admin", "host", "rescan", &pinned]), &["y"]);
    assert!(status.success(), "{shown}");
    assert!(
        shown.contains(&format!(
            "Scanning pinned.invalid:{} from the daemon through proxy p",
            remote.port
        )),
        "{shown}"
    );
    assert!(
        shown.contains("The pin already holds these keys"),
        "{shown}"
    );
    assert!(
        proxy
            .asked()
            .contains(&format!("pinned.invalid:{}", remote.port))
    );

    // A new host, `proxy=` naming the proxy: scanned through it, pinned once compared.
    let added = format!("[added.invalid]:{}", remote.port);
    let (status, shown) = on_terminal(
        daemon.writ(&["admin", "host", "add", &added, "proxy=p", "--yes"]),
        &["y"],
    );
    assert!(status.success(), "{shown}");
    assert!(
        shown.contains(&format!("  ssh-ed25519 {fingerprint}\r\n")),
        "{shown}"
    );
    assert_eq!(pins(&daemon, &added).map(|p| p.len()), Some(1));
    let scans = audit_events(&daemon.audit(), "scan", "done");
    assert_eq!(
        scans.last().unwrap()["reason"],
        format!(
            "added.invalid:{} through proxy p: {fingerprint}",
            remote.port
        )
    );

    // Directly, the name reaches nothing: refused, logged.
    let other = format!("[other.invalid]:{}", remote.port);
    let (_, shown) = on_terminal(daemon.writ(&["admin", "host", "add", &other]), &["y"]);
    assert!(shown.contains("cannot reach other.invalid:"), "{shown}");
    // A proxy the policy doesn't declare: refused by the daemon, nothing reached.
    let asked = proxy.asked().len();
    let (_, shown) = on_terminal(
        daemon.writ(&["admin", "host", "add", &other, "proxy=nope"]),
        &["y"],
    );
    assert!(
        shown.contains("proxy nope is not declared in proxies"),
        "{shown}"
    );
    assert_eq!(proxy.asked().len(), asked);
    let denied = audit_events(&daemon.audit(), "scan", "denied");
    assert_eq!(
        denied.last().unwrap()["reason"],
        format!(
            "other.invalid:{} through proxy nope: proxy nope is not declared in proxies",
            remote.port
        )
    );
    assert!(pins(&daemon, &other).is_none());
}
