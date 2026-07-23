// SPDX-License-Identifier: AGPL-3.0-or-later
//! Subscription / push lifecycle over the real IPC socket.
//!
//! These exercise the push path without any networking or crypto: events are
//! injected directly into the daemon's broadcast, so the tests are deterministic
//! and fast. They assert the three lifecycle guarantees from the M3 brief:
//! a subscribed client receives pushes, an unsubscribed one-shot client is
//! unaffected (the CLI stays request→response), and a disconnect cleans up the
//! subscription with no dangling receiver.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use prism_daemon::events::DaemonEvent;
use prism_daemon::{bind_secure, serve, AppState};
use prism_proto::{
    read_message, write_message, Envelope, Event, PeerInfo, Request, Response, PROTOCOL_VERSION,
};
use tokio::net::UnixStream;

/// Start a daemon on a temp socket; return the socket path and the shared state
/// (so a test can inject events and inspect the subscriber count).
#[allow(clippy::expect_used)]
async fn start(dir: &tempfile::TempDir) -> (PathBuf, Arc<AppState>) {
    let socket = dir.path().join("run").join("prismd.sock");
    let listener = bind_secure(&socket).expect("bind secure socket");
    let state = Arc::new(AppState::new(
        dir.path().join("keystore.pks"),
        dir.path().join("sessions.prs"),
        "/ip4/127.0.0.1/tcp/0".to_owned(),
    ));
    tokio::spawn(serve(listener, Arc::clone(&state)));
    (socket, state)
}

#[allow(clippy::expect_used)]
async fn send(stream: &mut UnixStream, request: Request) {
    write_message(stream, &Envelope::new(request))
        .await
        .expect("send request");
}

#[allow(clippy::expect_used)]
async fn recv(stream: &mut UnixStream) -> Response {
    let envelope: Envelope<Response> = read_message(stream).await.expect("read response");
    envelope.message
}

/// Spin until `predicate` holds, or panic after ~2 s. Used to await async
/// state transitions (a forwarder subscribing, a disconnect unsubscribing)
/// without racing on fixed sleeps.
#[allow(clippy::expect_used)]
async fn spin_until(mut predicate: impl FnMut() -> bool) {
    for _ in 0..200 {
        if predicate() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not reached within the timeout");
}

fn a_peer() -> PeerInfo {
    PeerInfo {
        fingerprint: "3R95oF6ZdppUsD".to_owned(),
        peer_id: "12D3KooWTest".to_owned(),
        connected: true,
    }
}

/// A subscribed client receives a pushed event; injecting after the forwarder
/// has subscribed (awaited via the receiver count) guarantees delivery.
#[tokio::test]
async fn subscribed_client_receives_pushes() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (socket, state) = start(&dir).await;
    let mut client = UnixStream::connect(&socket).await.expect("connect");

    send(&mut client, Request::Subscribe).await;
    assert!(matches!(recv(&mut client).await, Response::Subscribed));

    // Wait until the forwarder has actually subscribed to the broadcast.
    let s = Arc::clone(&state);
    spin_until(move || s.events.receiver_count() > 0).await;

    let _ = state.events.send(DaemonEvent::PeerDiscovered(a_peer()));

    match recv(&mut client).await {
        Response::Event(Event::PeerDiscovered { peer }) => {
            assert_eq!(peer.fingerprint, "3R95oF6ZdppUsD");
        }
        _ => panic!("expected a PeerDiscovered push"),
    }
}

/// An unsubscribed one-shot client keeps getting clean request→response, even
/// while events are flying on another connection: the CLI path is unaffected.
#[tokio::test]
async fn unsubscribed_client_is_unaffected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (socket, state) = start(&dir).await;

    // A subscriber on one connection.
    let mut sub = UnixStream::connect(&socket).await.expect("connect sub");
    send(&mut sub, Request::Subscribe).await;
    assert!(matches!(recv(&mut sub).await, Response::Subscribed));
    let s = Arc::clone(&state);
    spin_until(move || s.events.receiver_count() > 0).await;

    // A separate one-shot client that never subscribes.
    let mut one_shot = UnixStream::connect(&socket)
        .await
        .expect("connect one-shot");

    // Fire an event; it must go only to the subscriber.
    let _ = state.events.send(DaemonEvent::PeerDiscovered(a_peer()));

    // The one-shot client's single read is exactly its Pong — never an Event.
    send(&mut one_shot, Request::Ping).await;
    assert!(matches!(recv(&mut one_shot).await, Response::Pong));
}

/// Dropping a subscribed connection tears down its subscription: the broadcast
/// receiver count returns to zero, so nothing dangles.
#[tokio::test]
async fn disconnect_drops_subscription() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (socket, state) = start(&dir).await;
    let mut client = UnixStream::connect(&socket).await.expect("connect");

    send(&mut client, Request::Subscribe).await;
    assert!(matches!(recv(&mut client).await, Response::Subscribed));
    let s = Arc::clone(&state);
    spin_until(move || s.events.receiver_count() > 0).await;

    drop(client); // client goes away

    let s = Arc::clone(&state);
    spin_until(move || s.events.receiver_count() == 0).await;
}

/// A version-mismatched request is rejected (the version bump to 2 is enforced).
#[tokio::test]
async fn wrong_version_is_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (socket, _state) = start(&dir).await;
    let mut client = UnixStream::connect(&socket).await.expect("connect");

    let envelope = Envelope {
        version: PROTOCOL_VERSION.wrapping_add(1),
        message: Request::Ping,
    };
    write_message(&mut client, &envelope)
        .await
        .expect("send request");
    assert!(matches!(recv(&mut client).await, Response::Error { .. }));
}
