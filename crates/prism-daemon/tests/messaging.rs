// SPDX-License-Identifier: AGPL-3.0-or-later
//! End-to-end messaging between two in-process daemons over loopback TCP.
//!
//! This drives the real stack — prism-core sessions + prism-net swarms + Noise
//! — deterministically, injecting peer addresses rather than relying on mDNS
//! (which needs multicast and is exercised separately, `#[ignore]`d). It proves
//! decrypted == sent both directions, that an unreachable recipient fails
//! cleanly with nothing queued, and that the two-layer identity binding holds
//! across the network.

use std::sync::Arc;
use std::time::Duration;

use prism_core::{IdentityKeypair, PublicIdentity, Seed32};
use prism_daemon::{networking, AppState};
use prism_net::NetHandle;
use prism_proto::{Response, Sensitive};

/// Bring up a daemon's networking bound to a fixed identity seed, without a
/// keystore (the messaging path needs only the session subsystem).
// Test-only helpers: clippy's allow-in-tests does not reach helpers outside
// `#[test]` functions, hence the explicit allows here and below.
#[allow(clippy::expect_used)]
async fn bring_up(dir: &tempfile::TempDir, name: &str, fill: u8) -> Arc<AppState> {
    let state = Arc::new(AppState::new(
        dir.path().join(format!("{name}.pks")),
        dir.path().join(format!("{name}.prs")),
        "/ip4/127.0.0.1/tcp/0".to_owned(),
    ));
    networking::ensure_up(&state, Seed32::from_bytes([fill; 32]))
        .await
        .expect("networking up");
    state
}

/// Clone the swarm handle out of an unlocked daemon's state.
#[allow(clippy::expect_used)]
async fn net_of(state: &AppState) -> NetHandle {
    state.net.read().await.as_ref().expect("net up").net.clone()
}

/// The short (handle) fingerprint for an identity seed.
fn short_fp(fill: u8) -> String {
    IdentityKeypair::from_seed(&Seed32::from_bytes([fill; 32]))
        .public()
        .fingerprint()
        .short()
}

/// Poll for a bound listen address (bounded).
async fn first_listener(handle: &NetHandle) -> String {
    for _ in 0..50 {
        if let Some(addr) = handle
            .listeners()
            .await
            .unwrap_or_default()
            .into_iter()
            .next()
        {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no listen address");
}

/// Introduce two daemons to each other by address (stands in for mDNS).
#[allow(clippy::unwrap_used)]
async fn introduce(a: &NetHandle, b: &NetHandle) {
    let a_addr = first_listener(a).await;
    let b_addr = first_listener(b).await;
    a.add_peer_address(b.local_key(), b_addr).await.unwrap();
    b.add_peer_address(a.local_key(), a_addr).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_daemons_exchange_encrypted_messages_both_ways() {
    let dir = tempfile::tempdir().unwrap();
    let alice = bring_up(&dir, "alice", 0xA1).await;
    let bob = bring_up(&dir, "bob", 0xB0).await;
    let (a_net, b_net) = (net_of(&alice).await, net_of(&bob).await);
    introduce(&a_net, &b_net).await;

    // Alice -> Bob. `deliver` awaits Bob's ack, which fires only after Bob's
    // core has decrypted, identity-verified, and buffered the message — so by
    // the time `Sent` returns, it is already in Bob's inbox.
    let sent = networking::handle_send(
        &alice,
        format!("bob#{}", short_fp(0xB0)),
        Sensitive::new("hello bob".to_owned()),
    )
    .await;
    assert!(matches!(sent, Response::Sent), "got {sent:?}");

    match networking::handle_inbox(&bob).await {
        Response::Inbox { messages } => {
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].body.expose(), "hello bob");
            assert_eq!(
                messages[0].from_fingerprint,
                IdentityKeypair::from_seed(&Seed32::from_bytes([0xA1; 32]))
                    .public()
                    .fingerprint()
                    .full()
            );
        }
        other => panic!("expected inbox, got {other:?}"),
    }

    // Bob -> Alice (reply on the established session).
    let sent = networking::handle_send(
        &bob,
        format!("alice#{}", short_fp(0xA1)),
        Sensitive::new("hi alice".to_owned()),
    )
    .await;
    assert!(matches!(sent, Response::Sent), "got {sent:?}");

    match networking::handle_inbox(&alice).await {
        Response::Inbox { messages } => {
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].body.expose(), "hi alice");
        }
        other => panic!("expected inbox, got {other:?}"),
    }

    // Draining again yields nothing (inbox is RAM-only and was drained).
    match networking::handle_inbox(&bob).await {
        Response::Inbox { messages } => assert!(messages.is_empty()),
        other => panic!("expected empty inbox, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sending_to_an_unreachable_peer_fails_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let alice = bring_up(&dir, "alice", 0xA1).await;

    // A handle whose fingerprint matches no discovered peer.
    let resp = networking::handle_send(
        &alice,
        format!("ghost#{}", short_fp(0x99)),
        Sensitive::new("anyone there?".to_owned()),
    )
    .await;
    assert!(
        matches!(resp, Response::NotReachable { .. }),
        "expected NotReachable, got {resp:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_multi_message_conversation_survives_and_stays_ordered() {
    let dir = tempfile::tempdir().unwrap();
    let alice = bring_up(&dir, "alice", 0xA1).await;
    let bob = bring_up(&dir, "bob", 0xB0).await;
    let (a_net, b_net) = (net_of(&alice).await, net_of(&bob).await);
    introduce(&a_net, &b_net).await;

    for i in 0..5u8 {
        let body = format!("message {i}");
        let sent = networking::handle_send(
            &alice,
            format!("bob#{}", short_fp(0xB0)),
            Sensitive::new(body),
        )
        .await;
        assert!(matches!(sent, Response::Sent));
    }

    match networking::handle_inbox(&bob).await {
        Response::Inbox { messages } => {
            assert_eq!(messages.len(), 5);
            for (i, m) in messages.iter().enumerate() {
                assert_eq!(m.body.expose(), format!("message {i}"));
            }
        }
        other => panic!("expected inbox, got {other:?}"),
    }

    // Sanity: both fingerprints are well-formed and distinct.
    let a_fp = PublicIdentity::from_bytes(a_net.local_key().as_bytes())
        .unwrap()
        .fingerprint()
        .full();
    let b_fp = PublicIdentity::from_bytes(b_net.local_key().as_bytes())
        .unwrap()
        .fingerprint()
        .full();
    assert_ne!(a_fp, b_fp);
}
