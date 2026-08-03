// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deterministic two-swarm tests over loopback TCP (no mDNS, so they are
//! CI-safe). They exercise prism-net's transport contract — carrying opaque
//! bytes between authenticated peers, bundle serving, acks, and the
//! not-reachable path. The cryptographic end-to-end (decrypted == sent) is
//! tested at the daemon level, where prism-core is wired in.

use std::sync::Arc;
use std::time::Duration;

use prism_core::{IdentityKeypair, Seed32};
use prism_net::{spawn, InboundOutcome, InboundSink, NetConfig, NetError, PeerKey};
use tokio::sync::{mpsc, oneshot};

/// A sink that records deliveries and answers with a fixed verdict.
struct RecordingSink {
    tx: mpsc::UnboundedSender<(PeerKey, Vec<u8>)>,
    outcome: InboundOutcome,
}

impl InboundSink for RecordingSink {
    fn deliver(&self, from: PeerKey, sealed: Vec<u8>, reply: oneshot::Sender<InboundOutcome>) {
        let _ = self.tx.send((from, sealed));
        let _ = reply.send(self.outcome);
    }
    fn validate_locator(&self, _key: &[u8], _value: &[u8]) -> bool {
        false
    }
}

/// A sink that ignores everything (for the initiator side).
struct NullSink;
impl InboundSink for NullSink {
    fn deliver(&self, _from: PeerKey, _sealed: Vec<u8>, reply: oneshot::Sender<InboundOutcome>) {
        let _ = reply.send(InboundOutcome::Accepted);
    }
    fn validate_locator(&self, _key: &[u8], _value: &[u8]) -> bool {
        false
    }
}

/// A sink that validates DHT locators the way the daemon does (via prism-core),
/// so a DHT node stores valid records under FilterBoth.
struct ValidatingSink;
impl InboundSink for ValidatingSink {
    fn deliver(&self, _from: PeerKey, _sealed: Vec<u8>, reply: oneshot::Sender<InboundOutcome>) {
        let _ = reply.send(InboundOutcome::Accepted);
    }
    fn validate_locator(&self, key: &[u8], value: &[u8]) -> bool {
        match <&[u8; 32]>::try_from(key) {
            Ok(k) => prism_core::open_locator(value, k).is_ok(),
            Err(_) => false,
        }
    }
}

/// A validating sink that also records what it was asked to validate, so a test
/// can prove the swarm consults the validator *before* storing an inbound
/// record (the anti-poisoning front door) rather than storing it silently.
struct AuditingSink {
    /// Every (key, value) offered for validation, and the verdict returned.
    seen: Arc<std::sync::Mutex<Vec<bool>>>,
}

impl InboundSink for AuditingSink {
    fn deliver(&self, _from: PeerKey, _sealed: Vec<u8>, reply: oneshot::Sender<InboundOutcome>) {
        let _ = reply.send(InboundOutcome::Accepted);
    }
    fn validate_locator(&self, key: &[u8], value: &[u8]) -> bool {
        let verdict = match <&[u8; 32]>::try_from(key) {
            Ok(k) => prism_core::open_locator(value, k).is_ok(),
            Err(_) => false,
        };
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(verdict);
        }
        verdict
    }
}

fn seed(fill: u8) -> Seed32 {
    Seed32::from_bytes([fill; 32])
}

/// Transport-only config: no mDNS (CI-safe, deterministic) and no DHT — these
/// tests exercise only the request/response transport contract.
fn transport_only() -> NetConfig {
    NetConfig {
        enable_mdns: false,
        enable_dht: false,
        bootstrap: Vec::new(),
        external_addrs: Vec::new(),
        // These tests assert the plain transport contract; NAT traversal has its
        // own harness, and leaving AutoNAT off keeps them deterministic.
        enable_nat_traversal: false,
        relays: Vec::new(),
        relay_server: None,
    }
}

/// DHT config with mDNS OFF — simulating peers on *different* networks, whose
/// only path to each other is the DHT (no shared LAN multicast).
fn dht_only(bootstrap: Vec<String>) -> NetConfig {
    NetConfig {
        enable_mdns: false,
        enable_dht: true,
        bootstrap,
        external_addrs: Vec::new(),
        enable_nat_traversal: false,
        relays: Vec::new(),
        relay_server: None,
    }
}

/// Poll a handle's listen addresses until one appears (bounded).
async fn first_listener(handle: &prism_net::NetHandle) -> String {
    for _ in 0..50 {
        if let Ok(addrs) = handle.listeners().await {
            if let Some(addr) = addrs.into_iter().next() {
                return addr;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no listen address appeared");
}

#[tokio::test]
async fn fetch_bundle_and_deliver_message_end_to_end() {
    let (rec_tx, mut rec_rx) = mpsc::unbounded_channel();

    let (alice, _ja) = spawn(
        &seed(0xA1),
        Arc::new(NullSink),
        "/ip4/127.0.0.1/tcp/0",
        transport_only(),
    )
    .unwrap();
    let (bob, _jb) = spawn(
        &seed(0xB0),
        Arc::new(RecordingSink {
            tx: rec_tx,
            outcome: InboundOutcome::Accepted,
        }),
        "/ip4/127.0.0.1/tcp/0",
        transport_only(),
    )
    .unwrap();

    // Bob publishes an (opaque) bundle and Alice is told his address.
    let bob_addr = first_listener(&bob).await;
    bob.set_bundle(b"opaque-bundle-bytes".to_vec())
        .await
        .unwrap();
    alice
        .add_peer_address(bob.local_key(), bob_addr)
        .await
        .unwrap();

    // Alice fetches Bob's bundle: opaque bytes round-trip verbatim.
    let bundle = alice.fetch_bundle(bob.local_key()).await.unwrap();
    assert_eq!(bundle, b"opaque-bundle-bytes");

    // Alice delivers a sealed message; Bob's sink receives it, tagged with
    // Alice's authenticated key; the ack flows back.
    alice
        .deliver(bob.local_key(), b"sealed-message".to_vec())
        .await
        .unwrap();

    let (from, sealed) = rec_rx.recv().await.expect("delivery recorded");
    assert_eq!(sealed, b"sealed-message");
    assert_eq!(
        &from,
        &bob_peer_key_of(&seed(0xA1)),
        "delivery must be tagged with the Noise-authenticated sender key"
    );
}

#[tokio::test]
async fn delivering_to_an_undiscovered_peer_is_not_reachable() {
    let (alice, _ja) = spawn(
        &seed(0xA1),
        Arc::new(NullSink),
        "/ip4/127.0.0.1/tcp/0",
        transport_only(),
    )
    .unwrap();
    // A peer we never discovered and whose address we never learned.
    let stranger =
        PeerKey::from_bytes(*IdentityKeypair::from_seed(&seed(0x77)).public().as_bytes());

    let bundle = alice.fetch_bundle(stranger).await;
    assert!(matches!(bundle, Err(NetError::PeerNotReachable)));
    let delivered = alice.deliver(stranger, b"nowhere".to_vec()).await;
    assert!(matches!(delivered, Err(NetError::PeerNotReachable)));
}

#[tokio::test]
async fn a_rejecting_receiver_surfaces_a_request_failure() {
    let (rec_tx, _rec_rx) = mpsc::unbounded_channel();
    let (alice, _ja) = spawn(
        &seed(0xA1),
        Arc::new(NullSink),
        "/ip4/127.0.0.1/tcp/0",
        transport_only(),
    )
    .unwrap();
    let (bob, _jb) = spawn(
        &seed(0xB0),
        Arc::new(RecordingSink {
            tx: rec_tx,
            outcome: InboundOutcome::Rejected,
        }),
        "/ip4/127.0.0.1/tcp/0",
        transport_only(),
    )
    .unwrap();

    let bob_addr = first_listener(&bob).await;
    alice
        .add_peer_address(bob.local_key(), bob_addr)
        .await
        .unwrap();

    // Bob's sink rejects → Alice sees a clean request failure, not a hang.
    let result = alice.deliver(bob.local_key(), b"sealed".to_vec()).await;
    assert!(matches!(result, Err(NetError::RequestFailed(_))));
}

/// The Ed25519 public key bytes an identity seed yields (= its `PeerKey`).
fn bob_peer_key_of(seed: &Seed32) -> PeerKey {
    PeerKey::from_bytes(*IdentityKeypair::from_seed(seed).public().as_bytes())
}

/// The primary M4 test: two peers on *different* networks (mDNS off, so no
/// shared LAN) publish and discover each other **through the DHT only**, via a
/// bootstrap node. Alice publishes a signed locator; Bob — who never saw Alice
/// on a LAN and only knows the bootstrap node — resolves it and validates it to
/// Alice's identity.
#[tokio::test]
async fn peers_discover_each_other_through_the_dht_only() {
    // A bootstrap DHT server.
    let (boot, _jboot) = spawn(
        &seed(0xB7),
        Arc::new(ValidatingSink),
        "/ip4/127.0.0.1/tcp/0",
        dht_only(Vec::new()),
    )
    .unwrap();
    let boot_addr = first_listener(&boot).await;
    // Advertise its address → Kademlia server mode, so it stores/serves records.
    boot.add_external_address(boot_addr.clone()).await.unwrap();
    let boot_entry = format!("{boot_addr}/p2p/{}", boot.local_peer_id());

    // Alice and Bob know only the bootstrap node (no LAN, no direct knowledge
    // of each other).
    let (alice, _ja) = spawn(
        &seed(0xA1),
        Arc::new(ValidatingSink),
        "/ip4/127.0.0.1/tcp/0",
        dht_only(vec![boot_entry.clone()]),
    )
    .unwrap();
    let (bob, _jb) = spawn(
        &seed(0xB0),
        Arc::new(ValidatingSink),
        "/ip4/127.0.0.1/tcp/0",
        dht_only(vec![boot_entry]),
    )
    .unwrap();

    // Alice signs a locator naming (an opaque, here-loopback) address.
    let alice_identity = IdentityKeypair::from_seed(&seed(0xA1));
    let alice_addr = first_listener(&alice).await;
    let value =
        prism_core::seal_locator(&alice_identity, std::slice::from_ref(&alice_addr), 1).unwrap();
    let key = prism_core::own_locator_key(&alice_identity.public());

    // Let the bootstrap connections settle before publishing/resolving.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Republish + resolve until the DHT converges (bounded, ~6 s worst case).
    let mut found = None;
    for _ in 0..60 {
        let _ = alice.publish_locator(key, value.clone()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(Some(bytes)) = bob.resolve_locator(key).await {
            found = Some(bytes);
            break;
        }
    }

    let bytes = found.expect("Bob must resolve Alice's locator through the DHT");
    let loc = prism_core::open_locator(&bytes, &key).expect("the resolved locator is valid");
    assert_eq!(
        loc.identity(),
        &alice_identity.public(),
        "the resolved locator carries Alice's authenticated identity"
    );
    assert_eq!(loc.addrs(), &[alice_addr]);
}

/// The anti-poisoning front door: an inbound DHT record is offered to the
/// validator *before* it can be stored, and a tampered one is vetoed.
///
/// This tests the **wiring** (the validator is installed and consulted on the
/// `PutRecord` path under `StoreInserts::FilterBoth`); that the validator itself
/// rejects unsigned / wrongly-signed / oversized / malformed records is covered
/// exhaustively by `prism-core`'s locator tests.
///
/// Honest scope: nothing stops an attacker from serving *its own* hostile record
/// from its own store — which is exactly why the daemon validates again on
/// resolve (`handle_resolve` → `open_locator`, surfacing `NotReachable` on
/// failure). Storage-side vetoing keeps honest nodes from *amplifying* a bad
/// record; it is not a claim that a record can never be offered to us.
#[tokio::test]
async fn a_tampered_inbound_record_is_vetoed_before_storage() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));

    // An honest DHT server that audits every record offered to it.
    let (boot, _jboot) = spawn(
        &seed(0xE1),
        Arc::new(AuditingSink {
            seen: Arc::clone(&seen),
        }),
        "/ip4/127.0.0.1/tcp/0",
        dht_only(Vec::new()),
    )
    .unwrap();
    let boot_addr = first_listener(&boot).await;
    boot.add_external_address(boot_addr.clone()).await.unwrap();
    let boot_entry = format!("{boot_addr}/p2p/{}", boot.local_peer_id());

    // An attacker that knows the honest server and publishes a tampered record.
    let (attacker, _ja) = spawn(
        &seed(0xE2),
        Arc::new(NullSink),
        "/ip4/127.0.0.1/tcp/0",
        dht_only(vec![boot_entry]),
    )
    .unwrap();

    let att_identity = IdentityKeypair::from_seed(&seed(0xE2));
    let att_addr = first_listener(&attacker).await;
    let good = prism_core::seal_locator(&att_identity, std::slice::from_ref(&att_addr), 1).unwrap();
    let key = prism_core::own_locator_key(&att_identity.public());
    // Flip a payload byte: the signature no longer covers these bytes.
    let mut tampered = good.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(
        prism_core::open_locator(&tampered, &key).is_err(),
        "precondition: the tampered record must be invalid"
    );

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Publish it repeatedly until the honest node has been offered it.
    for _ in 0..60 {
        let _ = attacker.publish_locator(key, tampered.clone()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if seen.lock().map(|s| !s.is_empty()).unwrap_or(false) {
            break;
        }
    }

    let verdicts = seen.lock().expect("lock").clone();
    assert!(
        !verdicts.is_empty(),
        "the honest node must consult the validator on an inbound record"
    );
    assert!(
        verdicts.iter().all(|ok| !ok),
        "every tampered record must be vetoed (no silent storage)"
    );
}
