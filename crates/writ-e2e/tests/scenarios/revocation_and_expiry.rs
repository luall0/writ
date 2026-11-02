//! Scenario 9, revocation and expiry with operations in flight: a session holding git's
//! upload-pack open through the daemon is dropped the moment its lease is revoked, or when it
//! expires (narrowed to a short TTL at signature); the certificate is refused afterwards.

use std::time::Duration;

use writ_e2e::Stack;
use writ_e2e::agent::{Agent, expect, ticket};
use writ_e2e::docker::Running;

/// git's upload-pack through the gateway with the agent's current session, its input held
/// open (a FIFO the shell keeps open) so it stays in flight until the daemon drops it.
fn hold_open(agent: &Agent) -> Running {
    agent.start(
        // Grouped: the environment file is sourced first with `&&`, and `a && b & c` would
        // put the whole chain, mkfifo included, in the background.
        "rm -f in.fifo && mkfifo in.fifo && { ssh -F /dev/null -o BatchMode=yes \
         -o IdentitiesOnly=yes -o IdentityAgent=none -i .writ/sessions/current/key \
         -o CertificateFile=.writ/sessions/current/key-cert.pub \
         -o UserKnownHostsFile=.writ/known_hosts -o GlobalKnownHostsFile=/dev/null \
         -o StrictHostKeyChecking=yes -o LogLevel=ERROR -p 2222 git@writd \
         \"git-upload-pack 'inflight.git'\" < in.fifo & }; exec 3> in.fifo; wait $!",
    )
}

/// A ref advertisement's first pkt-line: four hex digits of length, then an object id.
fn advertised(first: &str) -> bool {
    first.len() > 44 && first.as_bytes()[..4].iter().all(u8::is_ascii_hexdigit)
}

#[test]
#[ignore = "end to end: make e2e"]
fn revocation_and_expiry_drop_sessions_in_flight_and_refuse_the_certificate() {
    let stack = Stack::shared();

    // Revoked while in flight.
    let agent = stack.agent("inflight");
    let lease = agent.lease(&stack, &ticket(&["inflight"], &["agent/*"], "1h", ""));
    let mut open = hold_open(&agent);
    assert!(
        advertised(&open.first),
        "the session is open: {:?}",
        open.first
    );
    assert!(
        !open.ends_within(Duration::from_millis(500)),
        "the session should stay open"
    );
    stack.approver.ok(&format!("writ revoke {lease}"));
    assert!(
        open.ends_within(Duration::from_secs(30)),
        "the open session was not dropped"
    );
    open.kill();
    let out = agent.run("ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
         -i .writ/sessions/current/key -o CertificateFile=.writ/sessions/current/key-cert.pub \
         -o UserKnownHostsFile=.writ/known_hosts -o GlobalKnownHostsFile=/dev/null \
         -o StrictHostKeyChecking=yes -o LogLevel=ERROR -p 2222 git@writd \"git-upload-pack 'inflight.git'\" < /dev/null");
    expect(&out, 255, "a revoked certificate");
    assert_eq!(stack.audited(&lease, "revoke", "done").len(), 1);
    assert!(
        !stack.audited(&lease, "connect", "denied").is_empty(),
        "the refused certificate is logged"
    );

    // Expired while in flight: the approver narrowed the lease to a short TTL.
    let short = stack.agent("inflight-expiry");
    let id = short.submit("ticket", &ticket(&["inflight"], &["agent/*"], "1h", ""));
    stack.approve_with(&id, "--ttl 45s");
    expect(&short.run(&format!("writ wait {id}")), 0, "the short lease");
    let mut open = hold_open(&short);
    assert!(
        advertised(&open.first),
        "the session is open: {:?}",
        open.first
    );
    assert!(
        open.ends_within(Duration::from_secs(90)),
        "the session outlived the lease"
    );
    open.kill();
    let out = short.run("ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
         -i .writ/sessions/current/key -o CertificateFile=.writ/sessions/current/key-cert.pub \
         -o UserKnownHostsFile=.writ/known_hosts -o GlobalKnownHostsFile=/dev/null \
         -o StrictHostKeyChecking=yes -o LogLevel=ERROR -p 2222 git@writd \"git-upload-pack 'inflight.git'\" < /dev/null");
    expect(&out, 255, "an expired certificate");
    assert_eq!(stack.audited(&id, "expire", "done").len(), 1);
}
