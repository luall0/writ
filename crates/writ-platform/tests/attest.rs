//! Every attestor, real and fake, through the attestor contract.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;

use writ_core::caller::{CallerFacts, CodeIdentity, ProcessRef};
use writ_platform::attest::network::NetworkAttestor;
use writ_platform::contract;
use writ_platform::testing::FakeAttestor;
use writ_platform::{CallerAttestor, PeerInfo, PlatformError};

fn tcp(addr: &str) -> PeerInfo {
    PeerInfo::Tcp {
        remote: addr.parse::<SocketAddr>().unwrap(),
    }
}

fn tcp_facts(addr: &str) -> CallerFacts {
    CallerFacts {
        source_addr: Some(addr.parse::<SocketAddr>().unwrap().ip()),
        process_chain: None,
    }
}

fn unix() -> PeerInfo {
    PeerInfo::Unix {
        uid: 501,
        gid: 20,
        pid: Some(4242),
    }
}

fn memory() -> PeerInfo {
    PeerInfo::Memory {
        label: "test".to_owned(),
    }
}

fn chain_facts() -> CallerFacts {
    CallerFacts {
        source_addr: None,
        process_chain: Some(vec![ProcessRef {
            pid: 4242,
            generation: 9,
            executable: "/Applications/Agent.app/Contents/MacOS/agent".into(),
            code_identity: Some(CodeIdentity {
                signing_id: "com.example.agent".to_owned(),
                team_id: Some("ABCDE12345".to_owned()),
            }),
        }]),
    }
}

#[test]
fn network_attestor_passes_the_contract() {
    contract::attestor(
        &NetworkAttestor::new(),
        &[
            (tcp("192.0.2.10:40000"), Some(tcp_facts("192.0.2.10:40000"))),
            (tcp("[2001:db8::1]:22"), Some(tcp_facts("[2001:db8::1]:22"))),
            (tcp("127.0.0.1:1"), Some(tcp_facts("127.0.0.1:1"))),
            (unix(), None),
            (memory(), None),
        ],
        false,
    );
}

#[test]
fn network_attestor_refuses_with_an_attestation_error() {
    let result = NetworkAttestor::new().attest(&unix());
    assert!(matches!(result, Err(PlatformError::Attestation(_))));
}

#[test]
fn fixed_fake_attestor_passes_the_contract() {
    let attestor = FakeAttestor::fixed(chain_facts());
    contract::attestor(
        &attestor,
        &[
            (memory(), Some(chain_facts())),
            (unix(), Some(chain_facts())),
        ],
        true,
    );
}

#[test]
fn failing_fake_attestor_passes_the_contract() {
    contract::attestor(
        &FakeAttestor::failing(),
        &[
            (tcp("192.0.2.10:40000"), None),
            (unix(), None),
            (memory(), None),
        ],
        false,
    );
}

#[test]
fn network_like_fake_attestor_passes_the_contract() {
    contract::attestor(
        &FakeAttestor::network_like(),
        &[
            (tcp("192.0.2.10:40000"), Some(tcp_facts("192.0.2.10:40000"))),
            (memory(), Some(CallerFacts::default())),
            (unix(), None),
        ],
        false,
    );
}

#[test]
fn fake_attestor_facts_change_at_runtime_for_every_clone() {
    let attestor = FakeAttestor::network_like();
    let clone = attestor.clone();
    attestor.set_facts(chain_facts());
    assert_eq!(clone.attest(&unix()).unwrap(), chain_facts());
    attestor.set_failing();
    assert!(clone.attest(&memory()).is_err());
}
