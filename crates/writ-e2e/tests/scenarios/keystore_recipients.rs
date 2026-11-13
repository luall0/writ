//! Scenario 26, the keystore's recipients (M7.6), on the pipeline's passphrase keystore (no
//! Secure Enclave on Linux): a recovery key made on the approver's machine (`writ recovery
//! new`, saved nowhere), declared as the policy's recipient, checked against the daemon's
//! challenge (`writ recovery check`: the right key, another), replaced, edited on a terminal,
//! removed; every `writ admin recipient` verb and flag; a hardware recipient refused by name,
//! the daemon having no such device. The policy put back. Then the SSH CA shown and rotated
//! live (`writ admin ca`), a backend the daemon lacks refused.

use writ_e2e::Stack;
use writ_e2e::agent::expect;
use writ_e2e::stdout;

/// The approval flags, given explicitly, and `--yes`.
const FLAGS: &str = "--yes --approval-url \"$WRIT_APPROVAL_URL\" --key \
                     \"$HOME/.writ/approver.pub\" --agent \"$WRIT_APPROVAL_AGENT\"";

/// `writ recovery new` on the approver's machine: the secret key and its recipient.
fn new_key(approver: &writ_e2e::Host) -> (String, String) {
    let said = approver.ok("writ recovery new");
    let secret = said
        .lines()
        // The key: the first line with text after the one that announces it.
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

#[test]
#[ignore = "end to end: make e2e"]
fn the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine() {
    // It changes the policy every scenario runs under: alone, and put back at the end.
    let stack = Stack::exclusive();
    let approver = &stack.approver;
    approver.ok("writ admin show policy > policy-before-recipients.yaml");
    let url = approver.ok("printf %s \"$WRIT_APPROVAL_URL\"");

    // None yet; a key made here, saved nowhere.
    assert_eq!(
        approver
            .ok(&format!("writ admin recipient list --approval-url {url}"))
            .trim(),
        "No recipient in the policy in force."
    );
    let (secret, recipient) = new_key(approver);
    let found = approver.run(&format!("grep -rlF '{secret}' \"$HOME\" 2>/dev/null"));
    assert_eq!(stdout(&found).trim(), "", "the secret key is on no file");

    // Declared: the keystore wraps its identity to it too.
    let said = approver.ok(&format!(
        "writ admin recipient add recovery recipient={recipient} {FLAGS}"
    ));
    assert!(said.contains("with recipient recovery added"), "{said}");
    assert_eq!(
        approver.ok("writ admin recipient list").trim(),
        format!("recovery  recovery {recipient}")
    );
    let shown = approver.ok(&format!(
        "writ admin recipient show recovery --approval-url {url}"
    ));
    assert!(
        shown.starts_with(&format!("recovery:\n  recipient: {recipient}\n")),
        "{shown}"
    );
    assert!(
        shown.contains("unwraps: everything, off the daemon's host"),
        "{shown}"
    );

    // Checked: this key opens the daemon's challenge; another is named by its recipient.
    let checked = approver.run_with(
        &format!("writ recovery check --approval-url {url}"),
        format!("{secret}\n").as_bytes(),
    );
    let (out, _) = expect(&checked, 0, "the right recovery key");
    assert!(
        out.starts_with("Recovery key checked: it is recipient recovery"),
        "{out}"
    );
    let (other, other_recipient) = new_key(approver);
    let (_, err) = expect(
        &approver.run_with("writ recovery check", format!("{other}\n").as_bytes()),
        1,
        "another recovery key",
    );
    assert!(
        err.contains(&format!(
            "not the daemon's recovery key: this key's recipient is {other_recipient}, not the \
             daemon's recovery recipient {recipient}"
        )),
        "{err}"
    );

    // Replaced: the new key checks, the old one no longer.
    approver.ok(&format!(
        "writ admin recipient set recovery recipient={other_recipient} {FLAGS}"
    ));
    expect(
        &approver.run_with("writ recovery check", format!("{other}\n").as_bytes()),
        0,
        "the new key",
    );
    expect(
        &approver.run_with("writ recovery check", format!("{secret}\n").as_bytes()),
        1,
        "the replaced key",
    );
    // Edited on a terminal, Enter keeping the recipient.
    let typed = approver.run_with(
        &format!("script -qec 'writ admin recipient edit recovery {FLAGS}' /dev/null"),
        b"\n",
    );
    assert_eq!(typed.status.code(), Some(0), "{}", stdout(&typed));

    // A hardware key on a daemon without the device: refused by name, nothing changed.
    let (_, err) = expect(
        &approver.run(&format!(
            "writ admin recipient add se-01 backend=se-cryptokit {FLAGS}"
        )),
        1,
        "a hardware recipient on Linux",
    );
    assert!(err.contains("recipients.se-01.backend"), "{err}");

    // Removed; then the policy as it was.
    approver.ok(&format!("writ admin recipient remove recovery {FLAGS}"));
    assert_eq!(
        approver.ok("writ admin recipient list").trim(),
        "No recipient in the policy in force."
    );
    let (_, err) = expect(
        &approver.run("writ recovery check </dev/null"),
        1,
        "no recovery key",
    );
    assert!(err.contains("declares no recovery recipient"), "{err}");
    approver.ok("writ admin apply policy policy-before-recipients.yaml --yes");

    // The SSH CA (M7.6): shown, rotated live (the leases of every other scenario keep
    // working: the old CA trusted until they end), a backend the daemon lacks refused.
    let shown = approver.ok(&format!("writ admin ca show --approval-url {url}"));
    assert!(shown.contains("backend: software"), "{shown}");
    assert!(
        shown.contains("no other CA is trusted") || shown.contains("a CA it replaced"),
        "{shown}"
    );
    let said = approver.ok(&format!("writ admin ca rotate --backend software {FLAGS}"));
    assert!(said.contains("SSH CA rotated: SHA256:"), "{said}");
    let (_, err) = expect(
        &approver.run(&format!(
            "writ admin ca rotate --backend se-cryptokit {FLAGS}"
        )),
        1,
        "a CA backend the daemon lacks",
    );
    assert!(
        err.contains("the daemon has no backend se-cryptokit"),
        "{err}"
    );
    let shown = approver.ok("writ admin ca show");
    assert!(shown.contains("SSH CA of daemon"), "{shown}");
    assert_eq!(
        approver.ok("writ admin show policy"),
        approver.ok("cat policy-before-recipients.yaml")
    );
}
