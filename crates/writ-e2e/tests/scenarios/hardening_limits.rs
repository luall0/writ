//! Scenario 17, hardening limits: `writd init` (which hardens itself as `writd run` does) on
//! the daemon's host under the two conditions the compose file doesn't give the daemon. Under a
//! 64 KiB lock limit, the default of many hosts: the memory lock not applied, said once on
//! stderr with its fix, the other steps applied, and the keystore made all the same (a
//! warning, never a refusal). As root: every step applied. The unlimited limit as `writ` is
//! scenario 16's. Each runs beside the shared daemon, in a directory of its own.

use writ_e2e::agent::expect;
use writ_e2e::setup::{POLICY_YAML, WRITD_YAML};
use writ_e2e::{Host, Stack};

const PASSPHRASE: &[u8] = b"the hardening scenario's passphrase\n";

/// A directory beside the daemon's files, with its approvers and readers (`writd init`
/// records them) and the end-to-end configuration; `writd init` run there by `script`.
fn init_in(host: &Host, dir: &str, script: &str) -> (String, String) {
    host.ok(&format!(
        "mkdir -p {dir} && cp /home/writ/approvers /home/writ/readers {dir}/"
    ));
    let there = host.with(&format!("{}/{dir}", host.dir), None);
    there.write("writd.yaml", WRITD_YAML, "0644");
    there.write("policy.yaml", POLICY_YAML, "0644");
    let (made, said) = expect(&there.run_with(script, PASSPHRASE), 0, script);
    assert!(made.starts_with("keystore made: /"), "{made}");
    (made, said)
}

#[test]
#[ignore = "end to end: make e2e"]
fn a_low_lock_limit_is_a_warning_with_its_fix_and_root_is_hardened_too() {
    let stack = Stack::shared();

    // As `writ`, under a 64 KiB lock limit (lowered where it starts, as a host's default).
    let (_, said) = init_in(
        &stack.operator,
        "hardening-low-limit",
        "ulimit -l 64 && writd init writd.yaml",
    );
    let warnings: Vec<&str> = said.lines().filter(|l| l.contains("not applied")).collect();
    assert_eq!(warnings.len(), 1, "only the memory lock: {said}");
    assert!(
        warnings[0].starts_with(
            "writd: warning: memory locked not applied: the lock limit is 65536 bytes, \
             not unlimited, and the process lacks CAP_IPC_LOCK"
        ),
        "{said}"
    );
    assert!(
        warnings[0]
            .contains("(fix: raise the daemon's lock limit to unlimited (`ulimit -l unlimited`"),
        "{said}"
    );

    // As root, under the compose file's unlimited limit: nothing to warn about.
    let root = Host::new("writd", "root", "/root");
    let (_, said) = init_in(&root, "hardening-root", "writd init writd.yaml");
    assert!(!said.contains("not applied"), "{said}");
    assert!(!said.contains("refused"), "{said}");
}
