// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAT-traversal tests (M5): the direct→relay fallback, and what a relay does
//! and does not see.
//!
//! These are deterministic and need no real NAT. The "cannot connect directly"
//! condition is created honestly rather than simulated with firewall rules:
//! the destination's direct address is **never given** to the sender, so the only
//! address the sender can construct is a relay circuit. That is exactly the state
//! a NAT-bound peer is in.
//!
//! What these tests cannot prove is real hole punching through real NATs — see
//! `scripts/` for the namespace harness and the documented VPS procedure.

use std::sync::Arc;
use std::time::Duration;

use prism_core::Seed32;
use prism_net::{
    spawn, ConnectionPath, InboundOutcome, InboundSink, NetConfig, NetHandle, PeerKey, RelayLimits,
};
use tokio::sync::{mpsc, oneshot};

/// Records every application delivery it is handed, so a test can assert both
/// what a destination received and — for a relay — that it received *nothing*.
struct RecordingSink {
    tx: mpsc::UnboundedSender<(PeerKey, Vec<u8>)>,
}

impl InboundSink for RecordingSink {
    fn deliver(&self, from: PeerKey, sealed: Vec<u8>, reply: oneshot::Sender<InboundOutcome>) {
        let _ = self.tx.send((from, sealed));
        let _ = reply.send(InboundOutcome::Accepted);
    }
    fn validate_locator(&self, _key: &[u8], _value: &[u8]) -> bool {
        false
    }
}

/// Surface swarm warnings when a test fails; `RUST_LOG` controls the level.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
}

fn seed(fill: u8) -> Seed32 {
    Seed32::from_bytes([fill; 32])
}

/// A node that uses relays but is not one.
fn relay_client_config(relays: Vec<String>) -> NetConfig {
    NetConfig {
        enable_mdns: false,
        enable_dht: false,
        bootstrap: Vec::new(),
        external_addrs: Vec::new(),
        enable_nat_traversal: true,
        relays,
        relay_server: None,
    }
}

/// Poll for a listen address, optionally one matching a predicate (bounded).
async fn wait_for_listener(handle: &NetHandle, want: impl Fn(&str) -> bool) -> String {
    let mut last = Vec::new();
    for _ in 0..100 {
        if let Ok(addrs) = handle.listeners().await {
            if let Some(addr) = addrs.iter().find(|a| want(a)) {
                return addr.clone();
            }
            last = addrs;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no matching listen address appeared; saw: {last:?}");
}

/// **The milestone's headline case.** Bob is reachable *only* through a relay —
/// his direct address is never disclosed to Alice — and an end-to-end payload
/// still arrives.
#[tokio::test]
async fn a_payload_is_delivered_when_a_relay_is_the_only_route() {
    init_tracing();
    let (relay_tx, mut relay_rx) = mpsc::unbounded_channel();
    let (bob_tx, mut bob_rx) = mpsc::unbounded_channel();

    // The relay: opt-in, capped, and publicly addressed so it serves circuits.
    let relay_cfg = NetConfig {
        enable_mdns: false,
        enable_dht: false,
        bootstrap: Vec::new(),
        external_addrs: Vec::new(),
        enable_nat_traversal: true,
        relays: Vec::new(),
        relay_server: Some(RelayLimits::default()),
    };
    let (relay, _jr) = spawn(
        &seed(0xC0),
        Arc::new(RecordingSink { tx: relay_tx }),
        "/ip4/127.0.0.1/tcp/0",
        relay_cfg,
    )
    .unwrap();
    let relay_addr = wait_for_listener(&relay, |a| a.contains("/tcp/")).await;
    // A relay must know its own external address: the reservation it grants
    // carries the addresses the client should advertise, and a relay with none
    // makes the client reject the reservation (`NoAddressesInReservation`). A real
    // relay gets this from `--external-address` or an AutoNAT confirmation.
    relay
        .add_external_address(relay_addr.clone())
        .await
        .unwrap();
    let relay_entry = format!("{relay_addr}/p2p/{}", relay.local_peer_id());

    // Bob reserves a slot on the relay so he can be reached through it.
    let (bob, _jb) = spawn(
        &seed(0xB0),
        Arc::new(RecordingSink { tx: bob_tx }),
        "/ip4/127.0.0.1/tcp/0",
        relay_client_config(vec![relay_entry.clone()]),
    )
    .unwrap();
    // The reservation is granted when a circuit address appears among Bob's
    // listeners — that address is what makes him reachable at all.
    let circuit = wait_for_listener(&bob, |a| a.contains("p2p-circuit")).await;
    assert!(
        circuit.contains(relay.local_peer_id()),
        "Bob's circuit address must route through the relay"
    );

    // Alice knows the relay, and *nothing* about how to reach Bob directly.
    let (alice, _ja) = spawn(
        &seed(0xA1),
        Arc::new(RecordingSink {
            tx: mpsc::unbounded_channel().0,
        }),
        "/ip4/127.0.0.1/tcp/0",
        relay_client_config(vec![relay_entry]),
    )
    .unwrap();

    // No direct address was ever seeded, so the fallback is the only way through.
    //
    // Bounded retry: the first circuit dial can race Alice's own connection to
    // the relay, and M5 deliberately ships **no** send-retry logic (general
    // reconnection/retry is deferred — see docs/net.md "Known limitations"), so
    // the retry belongs here in the test rather than being hidden in the library.
    let mut delivered = Err(prism_net::NetError::PeerNotReachable);
    for _ in 0..20 {
        delivered = alice
            .deliver(bob.local_key(), b"through-the-relay".to_vec())
            .await;
        if delivered.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        delivered.is_ok(),
        "delivery over a relay-only route must succeed: {delivered:?}"
    );

    let (from, payload) = tokio::time::timeout(Duration::from_secs(5), bob_rx.recv())
        .await
        .expect("Bob must receive the payload")
        .expect("the sink channel stays open");
    assert_eq!(payload, b"through-the-relay");
    assert_eq!(
        from,
        alice.local_key(),
        "the payload must be attributed to Alice's authenticated key, even relayed"
    );

    // The path is reported, so the user is never left guessing how they connected.
    let path = alice
        .peers()
        .await
        .unwrap()
        .into_iter()
        .find(|p| p.key == bob.local_key())
        .and_then(|p| p.path);
    assert!(
        path.is_some(),
        "a connected peer must report how it is carried"
    );
    // It is `Relayed` unless DCUtR has already upgraded the connection — which is
    // a *success*, not a failure, and is possible here because both ends share a
    // loopback interface. Asserting `Relayed` specifically is left to the
    // namespace harness, where no direct route exists at all.

    // **Canary: the relay carried the bytes but never saw them as a payload.**
    // A relay terminates no Prism session, so its sink must never be invoked.
    assert!(
        relay_rx.try_recv().is_err(),
        "the relay must never receive an application payload"
    );
}

/// A direct address, when known, is preferred and reported as direct — a relay is
/// a fallback, never the default path.
#[tokio::test]
async fn a_known_direct_address_is_used_and_reported_direct() {
    let (bob_tx, mut bob_rx) = mpsc::unbounded_channel();
    let (alice, _ja) = spawn(
        &seed(0xA2),
        Arc::new(RecordingSink {
            tx: mpsc::unbounded_channel().0,
        }),
        "/ip4/127.0.0.1/tcp/0",
        relay_client_config(Vec::new()),
    )
    .unwrap();
    let (bob, _jb) = spawn(
        &seed(0xB2),
        Arc::new(RecordingSink { tx: bob_tx }),
        "/ip4/127.0.0.1/tcp/0",
        relay_client_config(Vec::new()),
    )
    .unwrap();

    let bob_addr = wait_for_listener(&bob, |a| a.contains("/tcp/")).await;
    alice
        .add_peer_address(bob.local_key(), bob_addr)
        .await
        .unwrap();

    alice
        .deliver(bob.local_key(), b"direct".to_vec())
        .await
        .expect("direct delivery must succeed");
    let _ = tokio::time::timeout(Duration::from_secs(5), bob_rx.recv())
        .await
        .expect("Bob must receive it");

    let path = alice
        .peers()
        .await
        .unwrap()
        .into_iter()
        .find(|p| p.key == bob.local_key())
        .and_then(|p| p.path);
    assert_eq!(
        path,
        Some(ConnectionPath::Direct),
        "a dialable direct address must produce a direct connection"
    );
}

/// With neither a direct address nor a relay, the honest answer is still
/// "not reachable" — the fallback must not paper over an unreachable peer.
#[tokio::test]
async fn without_a_relay_an_unreachable_peer_stays_unreachable() {
    let (alice, _ja) = spawn(
        &seed(0xA3),
        Arc::new(RecordingSink {
            tx: mpsc::unbounded_channel().0,
        }),
        "/ip4/127.0.0.1/tcp/0",
        relay_client_config(Vec::new()),
    )
    .unwrap();
    let stranger = PeerKey::from_bytes(
        *prism_core::IdentityKeypair::from_seed(&seed(0x9E))
            .public()
            .as_bytes(),
    );
    assert!(
        alice.deliver(stranger, b"nowhere".to_vec()).await.is_err(),
        "no direct address and no relay must remain an error, not a silent success"
    );
}
