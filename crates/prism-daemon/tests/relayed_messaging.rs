// SPDX-License-Identifier: AGPL-3.0-or-later
//! M5 assurances that only exist end-to-end: a real prism-core session carried
//! **through a relay**, the identity binding still enforced over that path, and
//! the relay retaining nothing about who it carried.
//!
//! These drive the whole stack — prism-core sessions, prism-net swarms, Noise and
//! Circuit Relay v2 — so they prove the milestone's central claim rather than
//! assuming it from the opaque-bytes test in prism-net.
//!
//! The circuit address is **injected** into the sender, exactly as
//! `messaging.rs` injects direct addresses instead of relying on mDNS: how the
//! address is *discovered* (DHT locator) is tested separately, and mixing it in
//! here would make the test about DHT convergence rather than relayed delivery.

use std::sync::Arc;
use std::time::Duration;

use prism_core::{IdentityKeypair, Seed32};
use prism_daemon::{networking, AppState};
use prism_net::{InboundOutcome, InboundSink, NetConfig, NetHandle, PeerKey, RelayLimits};
use prism_proto::{Response, Sensitive};
use tokio::sync::{mpsc, oneshot};

/// A sink for the **relay** node. It records any application delivery it is
/// handed, so a test can assert it is handed none: a relay terminates no Prism
/// session, so this must stay empty.
struct RelaySink {
    tx: mpsc::UnboundedSender<(PeerKey, Vec<u8>)>,
}

impl InboundSink for RelaySink {
    fn deliver(&self, from: PeerKey, sealed: Vec<u8>, reply: oneshot::Sender<InboundOutcome>) {
        let _ = self.tx.send((from, sealed));
        let _ = reply.send(InboundOutcome::Accepted);
    }
    fn validate_locator(&self, _key: &[u8], _value: &[u8]) -> bool {
        false
    }
}

/// Config for a node that routes through `relays` and does no discovery, so the
/// only route to a peer is the one the test provides.
fn via_relays(relays: Vec<String>) -> NetConfig {
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

#[allow(clippy::expect_used)]
async fn bring_up(
    dir: &tempfile::TempDir,
    name: &str,
    fill: u8,
    config: NetConfig,
) -> Arc<AppState> {
    let state = Arc::new(AppState::with_net_config(
        dir.path().join(format!("{name}.pks")),
        dir.path().join(format!("{name}.prs")),
        "/ip4/127.0.0.1/tcp/0".to_owned(),
        config,
    ));
    networking::ensure_up(&state, Seed32::from_bytes([fill; 32]))
        .await
        .expect("networking up");
    state
}

#[allow(clippy::expect_used)]
async fn net_of(state: &AppState) -> NetHandle {
    state.net.read().await.as_ref().expect("net up").net.clone()
}

fn short_fp(fill: u8) -> String {
    IdentityKeypair::from_seed(&Seed32::from_bytes([fill; 32]))
        .public()
        .fingerprint()
        .short()
}

/// Poll a handle's listeners for one matching `want` (bounded).
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
    panic!("no matching listen address; saw: {last:?}");
}

/// Start a capped, non-retaining relay that advertises its own address (without
/// which the reservations it grants carry no addresses and clients reject them).
/// Returns its handle, its `…/p2p/<id>` entry, and the sink receiver.
#[allow(clippy::unwrap_used)]
async fn start_relay(
    fill: u8,
) -> (
    NetHandle,
    String,
    mpsc::UnboundedReceiver<(PeerKey, Vec<u8>)>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let config = NetConfig {
        enable_mdns: false,
        enable_dht: false,
        bootstrap: Vec::new(),
        external_addrs: Vec::new(),
        enable_nat_traversal: true,
        relays: Vec::new(),
        relay_server: Some(RelayLimits::default()),
    };
    let (relay, join) = prism_net::spawn(
        &Seed32::from_bytes([fill; 32]),
        Arc::new(RelaySink { tx }),
        "/ip4/127.0.0.1/tcp/0",
        config,
    )
    .unwrap();
    let addr = wait_for_listener(&relay, |a| a.contains("/tcp/")).await;
    relay.add_external_address(addr.clone()).await.unwrap();
    let entry = format!("{addr}/p2p/{}", relay.local_peer_id());
    (relay, entry, rx, join)
}

/// Give `sender` the circuit route to `target` (stands in for resolving the
/// target's published locator).
#[allow(clippy::unwrap_used)]
async fn seed_circuit_route(sender: &NetHandle, relay_entry: &str, target: &NetHandle) {
    let circuit = format!("{relay_entry}/p2p-circuit/p2p/{}", target.local_peer_id());
    sender
        .add_peer_address(target.local_key(), circuit)
        .await
        .unwrap();
}

/// Wait until `handle` holds a relay reservation (its circuit address appears).
async fn wait_for_reservation(handle: &NetHandle) {
    let _ = wait_for_listener(handle, |a| a.contains("p2p-circuit")).await;
}

/// **M5's central claim.** A real Olm session, carried entirely through a relay:
/// decrypted == sent, and the relay never sees a payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::unwrap_used)]
async fn decrypted_equals_sent_through_a_relay() {
    let dir = tempfile::tempdir().unwrap();
    let (relay, relay_entry, mut relay_rx, _jr) = start_relay(0xC1).await;

    let alice = bring_up(&dir, "alice", 0xA1, via_relays(vec![relay_entry.clone()])).await;
    let bob = bring_up(&dir, "bob", 0xB0, via_relays(vec![relay_entry.clone()])).await;
    let (a_net, b_net) = (net_of(&alice).await, net_of(&bob).await);

    // Bob becomes reachable through the relay; Alice is given only that route —
    // never Bob's direct address, so a circuit is the only way through.
    wait_for_reservation(&b_net).await;
    seed_circuit_route(&a_net, &relay_entry, &b_net).await;

    // Bounded retry: the first circuit dial can race Alice's own connection to
    // the relay, and M5 ships no send-retry (deferred robustness work).
    let mut sent = Response::Locked;
    for _ in 0..20 {
        sent = networking::handle_send(
            &alice,
            format!("bob#{}", short_fp(0xB0)),
            Sensitive::new("hello bob, over the relay".to_owned()),
        )
        .await;
        if matches!(sent, Response::Sent) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(matches!(sent, Response::Sent), "got {sent:?}");

    // The ack fires only after Bob's core decrypted, identity-verified and
    // buffered it, so it is already in his inbox.
    match networking::handle_inbox(&bob).await {
        Response::Inbox { messages } => {
            assert_eq!(messages.len(), 1);
            assert_eq!(
                messages[0].body.expose(),
                "hello bob, over the relay",
                "decrypted must equal sent, through the relay"
            );
            assert_eq!(
                messages[0].from_fingerprint,
                IdentityKeypair::from_seed(&Seed32::from_bytes([0xA1; 32]))
                    .public()
                    .fingerprint()
                    .full(),
                "attributed to Alice's cryptographically proven identity"
            );
        }
        other => panic!("expected inbox, got {other:?}"),
    }

    // Reply direction on the established session, still relayed.
    seed_circuit_route(&b_net, &relay_entry, &a_net).await;
    let mut replied = Response::Locked;
    for _ in 0..20 {
        replied = networking::handle_send(
            &bob,
            format!("alice#{}", short_fp(0xA1)),
            Sensitive::new("hi alice".to_owned()),
        )
        .await;
        if matches!(replied, Response::Sent) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(matches!(replied, Response::Sent), "got {replied:?}");
    match networking::handle_inbox(&alice).await {
        Response::Inbox { messages } => {
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].body.expose(), "hi alice");
        }
        other => panic!("expected inbox, got {other:?}"),
    }

    // The relay carried both messages and was handed neither: it terminates no
    // Prism session. (This asserts the sink is never invoked — confidentiality
    // itself rests on Olm end-to-end plus the per-hop Noise/TLS, not on us
    // inspecting bytes.)
    assert!(
        relay_rx.try_recv().is_err(),
        "the relay must never receive an application payload"
    );
    drop(relay);
}

/// The two-layer identity binding must hold **through the relay**: a peer that
/// relays someone else's ciphertext is rejected, because the Noise-authenticated
/// sender is not the identity the message is cryptographically bound to.
///
/// Eve gets Alice's genuine ciphertext for Bob (produced by Alice's own core) and
/// delivers it over a circuit. Bob must refuse it and keep an empty inbox.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
async fn a_relayed_message_from_the_wrong_identity_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (relay, relay_entry, _relay_rx, _jr) = start_relay(0xC2).await;

    let alice = bring_up(&dir, "alice", 0xA2, via_relays(vec![relay_entry.clone()])).await;
    let bob = bring_up(&dir, "bob", 0xB2, via_relays(vec![relay_entry.clone()])).await;
    let eve = bring_up(&dir, "eve", 0xE2, via_relays(vec![relay_entry.clone()])).await;
    let (a_net, b_net, e_net) = (net_of(&alice).await, net_of(&bob).await, net_of(&eve).await);

    wait_for_reservation(&b_net).await;
    seed_circuit_route(&a_net, &relay_entry, &b_net).await;
    seed_circuit_route(&e_net, &relay_entry, &b_net).await;

    // Alice's core seals a message *for Bob*, bound to Alice's identity. Taking
    // the bytes without transmitting them is exactly the interception an attacker
    // would attempt.
    let bob_bundle = {
        let mut fetched = None;
        for _ in 0..20 {
            if let Ok(bundle) = a_net.fetch_bundle(b_net.local_key()).await {
                fetched = Some(bundle);
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        fetched.expect("Alice must fetch Bob's bundle over the relay")
    };
    let alice_core = alice
        .net
        .read()
        .await
        .as_ref()
        .expect("net up")
        .core
        .clone();
    let sealed = alice_core
        .deliver(
            *b_net.local_key().as_bytes(),
            Some(bob_bundle),
            zeroize::Zeroizing::new(b"ciphertext bound to Alice".to_vec()),
        )
        .await
        .expect("Alice's core seals a message for Bob");

    // Eve relays Alice's ciphertext to Bob. Transport identity (Eve) does not
    // match the message's proven identity (Alice) -> rejected.
    let delivered = e_net.deliver(b_net.local_key(), sealed).await;
    // Specifically `RequestFailed`, not `PeerNotReachable`: the distinction is
    // the whole point. The former means Bob received it over the circuit and
    // *refused* it; the latter would mean Eve never reached him, which would let
    // this test pass for the wrong reason.
    assert!(
        matches!(delivered, Err(prism_net::NetError::RequestFailed(_))),
        "Bob must receive it over the circuit and refuse it (not merely be unreachable), got {delivered:?}"
    );

    match networking::handle_inbox(&bob).await {
        Response::Inbox { messages } => assert!(
            messages.is_empty(),
            "a wrong-identity relayed message must never reach the inbox"
        ),
        other => panic!("expected inbox, got {other:?}"),
    }
    drop(relay);
}

/// Non-retention, as something a regression would break: after carrying a
/// circuit, the relay has written **no file** and has emitted **no log line
/// naming both endpoints**. A circuit ledger or a `info!(src, dst)` would fail
/// this.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::unwrap_used)]
async fn a_relay_retains_nothing_about_who_it_carried() {
    let logs = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let writer = LogCapture {
        buf: Arc::clone(&logs),
    };
    // Capture at DEBUG: the strict claim is that *no* level names both ends.
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(writer)
            .finish(),
    );

    let dir = tempfile::tempdir().unwrap();
    let relay_dir = tempfile::tempdir().unwrap();
    let files_before = count_files(relay_dir.path());

    let (relay, relay_entry, _rx, _jr) = start_relay(0xC3).await;
    let alice = bring_up(&dir, "alice", 0xA3, via_relays(vec![relay_entry.clone()])).await;
    let bob = bring_up(&dir, "bob", 0xB3, via_relays(vec![relay_entry.clone()])).await;
    let (a_net, b_net) = (net_of(&alice).await, net_of(&bob).await);

    wait_for_reservation(&b_net).await;
    seed_circuit_route(&a_net, &relay_entry, &b_net).await;
    for _ in 0..20 {
        if matches!(
            networking::handle_send(
                &alice,
                format!("bob#{}", short_fp(0xB3)),
                Sensitive::new("carried".to_owned()),
            )
            .await,
            Response::Sent
        ) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // 1. Nothing was persisted by the relay.
    assert_eq!(
        count_files(relay_dir.path()),
        files_before,
        "a relay must not write anything about the traffic it carries"
    );

    // 2. No emitted line names both endpoints — that pairing is precisely the
    //    routing record non-retention promises not to keep.
    let captured = String::from_utf8_lossy(&logs.lock().unwrap().clone()).into_owned();
    let (a_id, b_id) = (a_net.local_peer_id(), b_net.local_peer_id());
    for line in captured.lines() {
        assert!(
            !(line.contains(a_id) && line.contains(b_id)),
            "a log line paired both circuit endpoints: {line}"
        );
    }
    drop(relay);
}

/// Count regular files under `dir`, recursively.
fn count_files(dir: &std::path::Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => count_files(&e.path()),
            Ok(_) => 1,
            Err(_) => 0,
        })
        .sum()
}

/// A `tracing` writer that accumulates output in memory for assertions.
#[derive(Clone)]
struct LogCapture {
    buf: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl std::io::Write for LogCapture {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut buf) = self.buf.lock() {
            buf.extend_from_slice(data);
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = LogCapture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
