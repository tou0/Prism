// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deterministic two-swarm tests over loopback TCP (no mDNS, so they are
//! CI-safe). They exercise prism-net's transport contract — carrying opaque
//! bytes between authenticated peers, bundle serving, acks, and the
//! not-reachable path. The cryptographic end-to-end (decrypted == sent) is
//! tested at the daemon level, where prism-core is wired in.

use std::sync::Arc;
use std::time::Duration;

use prism_core::{IdentityKeypair, Seed32};
use prism_net::{spawn, InboundOutcome, InboundSink, NetError, PeerKey};
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
}

/// A sink that ignores everything (for the initiator side).
struct NullSink;
impl InboundSink for NullSink {
    fn deliver(&self, _from: PeerKey, _sealed: Vec<u8>, reply: oneshot::Sender<InboundOutcome>) {
        let _ = reply.send(InboundOutcome::Accepted);
    }
}

fn seed(fill: u8) -> Seed32 {
    Seed32::from_bytes([fill; 32])
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

    let (alice, _ja) = spawn(&seed(0xA1), Arc::new(NullSink), "/ip4/127.0.0.1/tcp/0").unwrap();
    let (bob, _jb) = spawn(
        &seed(0xB0),
        Arc::new(RecordingSink {
            tx: rec_tx,
            outcome: InboundOutcome::Accepted,
        }),
        "/ip4/127.0.0.1/tcp/0",
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
    let (alice, _ja) = spawn(&seed(0xA1), Arc::new(NullSink), "/ip4/127.0.0.1/tcp/0").unwrap();
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
    let (alice, _ja) = spawn(&seed(0xA1), Arc::new(NullSink), "/ip4/127.0.0.1/tcp/0").unwrap();
    let (bob, _jb) = spawn(
        &seed(0xB0),
        Arc::new(RecordingSink {
            tx: rec_tx,
            outcome: InboundOutcome::Rejected,
        }),
        "/ip4/127.0.0.1/tcp/0",
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
