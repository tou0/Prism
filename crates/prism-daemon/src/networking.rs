// SPDX-License-Identifier: AGPL-3.0-or-later
//! Wiring between the core session thread and the libp2p swarm, plus the
//! `send` orchestration that enforces persist-before-transmit.
//!
//! The daemon is the hub: prism-net speaks raw peer keys and opaque bytes,
//! prism-core owns all cryptography, and this module maps between them (peer
//! key ↔ Prism fingerprint) and sequences the two subsystems.

use std::sync::Arc;

use prism_core::bundle::DEFAULT_ONE_TIME_KEYS;
use prism_core::{IdentityKeypair, PublicIdentity, Seed32};
use prism_net::{InboundOutcome, InboundSink, NetError, PeerKey};
use prism_proto::{PeerInfo, Response};
use tokio::sync::oneshot;
use tracing::info;
use zeroize::Zeroizing;

use crate::session_core::{spawn_core, CoreMsg};
use crate::state::{AppState, NetworkHandles};

/// Bridges inbound network deliveries to the core session thread without
/// blocking the swarm: it hands the sealed bytes off via a non-blocking
/// `try_send` and lets the core thread resolve the verdict later.
struct CoreInboundSink {
    core_tx: tokio::sync::mpsc::Sender<CoreMsg>,
}

impl InboundSink for CoreInboundSink {
    fn deliver(&self, from: PeerKey, sealed: Vec<u8>, reply: oneshot::Sender<InboundOutcome>) {
        let msg = CoreMsg::Inbound {
            from: *from.as_bytes(),
            sealed,
            reply,
        };
        // Non-blocking: if the core queue is full or gone, reject immediately
        // so the swarm can answer the peer without stalling.
        if let Err(err) = self.core_tx.try_send(msg) {
            let returned = match err {
                tokio::sync::mpsc::error::TrySendError::Full(m)
                | tokio::sync::mpsc::error::TrySendError::Closed(m) => m,
            };
            if let CoreMsg::Inbound { reply, .. } = returned {
                let _ = reply.send(InboundOutcome::Rejected);
            }
        }
    }
}

/// The short (handle) fingerprint for a peer's key, or `None` if the bytes are
/// not a valid identity key.
fn short_fingerprint(key: &PeerKey) -> Option<String> {
    PublicIdentity::from_bytes(key.as_bytes())
        .ok()
        .map(|id| id.fingerprint().short())
}

/// The full fingerprint for a peer's key.
fn full_fingerprint(key: &PeerKey) -> Option<String> {
    PublicIdentity::from_bytes(key.as_bytes())
        .ok()
        .map(|id| id.fingerprint().full())
}

/// Bring up the networking subsystem for the unlocked identity, if it is not
/// already running. Idempotent: a second call is a no-op.
///
/// Builds the session store (blocking I/O, no Argon2), spawns the core thread,
/// publishes an initial signed bundle, starts the swarm, and advertises the
/// bundle. Errors leave the daemon unlocked but offline.
pub async fn ensure_up(state: &AppState, seed: Seed32) -> Result<(), String> {
    if state.net.read().await.is_some() {
        return Ok(());
    }
    let mut guard = state.net.write().await;
    if guard.is_some() {
        return Ok(()); // raced with another unlock
    }

    // Build the session manager off the async executor (it does file I/O).
    // `Seed32` is not `Clone` (secrets rule), so we build the identity from the
    // seed and move that into the blocking task, keeping `seed` for the Noise
    // transport key below.
    let sessions_path = state.sessions_path.clone();
    let identity = IdentityKeypair::from_seed(&seed);
    let manager = tokio::task::spawn_blocking(move || {
        crate::session_core::open_manager(&identity, sessions_path)
    })
    .await
    .map_err(|_| "failed to build the session store".to_owned())?
    .map_err(|e| e.to_string())?;

    let core =
        spawn_core(manager).map_err(|e| format!("failed to start the session thread: {e}"))?;

    // Publish an initial bundle so peers can establish with us.
    let bundle = core.publish_bundle(DEFAULT_ONE_TIME_KEYS).await?;

    // Start the swarm, feeding inbound deliveries to the core thread.
    let sink = Arc::new(CoreInboundSink {
        core_tx: core.sender(),
    });
    let (net, _join) = prism_net::spawn(&seed, sink, &state.listen_addr)
        .map_err(|e| format!("failed to start networking: {e}"))?;
    net.set_bundle(bundle)
        .await
        .map_err(|e| format!("failed to advertise the bundle: {e}"))?;

    info!(peer_id = net.local_peer_id(), "networking is up");
    *guard = Some(NetworkHandles { net, core });
    Ok(())
}

/// A `Sensitive` body cannot be borrowed as bytes without exposing it; do so
/// only here, into a zeroizing buffer handed straight to the core thread.
fn body_bytes(body: &prism_proto::Sensitive) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(body.expose().as_bytes().to_vec())
}

/// Handle a `Send` request: resolve the recipient on the LAN, encrypt (which
/// persists), then transmit. The transmit step happens strictly **after** the
/// core thread confirms the durable write.
pub async fn handle_send(state: &AppState, to: String, body: prism_proto::Sensitive) -> Response {
    let guard = state.net.read().await;
    let Some(handles) = guard.as_ref() else {
        return locked();
    };

    let Some((_, target_fp)) = to.split_once('#') else {
        return Response::Error {
            message: "recipient must be a handle, nick#fingerprint".to_owned(),
        };
    };

    // Resolve the handle to a discovered peer by matching the short fingerprint.
    let peers = match handles.net.peers().await {
        Ok(peers) => peers,
        Err(e) => {
            return Response::Error {
                message: e.to_string(),
            }
        }
    };
    let Some(record) = peers
        .into_iter()
        .find(|p| short_fingerprint(&p.key).as_deref() == Some(target_fp))
    else {
        return Response::NotReachable { handle: to };
    };
    let peer_key = record.key;
    let peer_bytes = *peer_key.as_bytes();

    // Fetch the peer's bundle only on first contact (no session yet).
    let bundle = if handles.core.has_session(peer_bytes).await {
        None
    } else {
        match handles.net.fetch_bundle(peer_key).await {
            Ok(bundle) => Some(bundle),
            Err(NetError::PeerNotReachable) => return Response::NotReachable { handle: to },
            Err(e) => {
                return Response::Error {
                    message: e.to_string(),
                }
            }
        }
    };

    // Encrypt + persist (persist-before-transmit lives in the core thread).
    let sealed = match handles
        .core
        .deliver(peer_bytes, bundle, body_bytes(&body))
        .await
    {
        Ok(sealed) => sealed,
        Err(message) => return Response::Error { message },
    };

    // Only now, with the advanced ratchet state durable, transmit.
    match handles.net.deliver(peer_key, sealed).await {
        Ok(()) => Response::Sent,
        // The emit failed after we persisted: the message key is spent (a
        // harmless chain gap) and nothing is queued — M2b is synchronous only.
        Err(NetError::PeerNotReachable) => Response::NotReachable { handle: to },
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    }
}

/// Handle an `Inbox` request: drain the core thread's RAM buffer.
pub async fn handle_inbox(state: &AppState) -> Response {
    let guard = state.net.read().await;
    let Some(handles) = guard.as_ref() else {
        return locked();
    };
    let messages = handles
        .core
        .inbox()
        .await
        .into_iter()
        .map(|entry| prism_proto::InboxItem {
            from_fingerprint: entry.from_fingerprint,
            // Body is UTF-8 lossily rendered for display; it never hit disk.
            body: prism_proto::Sensitive::new(String::from_utf8_lossy(&entry.body).into_owned()),
        })
        .collect();
    Response::Inbox { messages }
}

/// Handle a `Peers` request: list discovered peers with their fingerprints.
pub async fn handle_peers(state: &AppState) -> Response {
    let guard = state.net.read().await;
    let Some(handles) = guard.as_ref() else {
        return locked();
    };
    let peers = match handles.net.peers().await {
        Ok(peers) => peers,
        Err(e) => {
            return Response::Error {
                message: e.to_string(),
            }
        }
    };
    let peers = peers
        .into_iter()
        .filter_map(|p| {
            full_fingerprint(&p.key).map(|fingerprint| PeerInfo {
                fingerprint,
                peer_id: p.peer_id,
                connected: p.connected,
            })
        })
        .collect();
    Response::Peers { peers }
}

/// Handle a `Status` request: our handle, peer id, listen addresses, peer count.
pub async fn handle_status(state: &AppState) -> Response {
    let handle = match state.unlocked.read().await.as_ref() {
        Some(identity) => identity.handle(),
        None => return locked(),
    };
    let guard = state.net.read().await;
    let Some(handles) = guard.as_ref() else {
        return locked();
    };
    let listen_addrs = handles.net.listeners().await.unwrap_or_default();
    let peer_count = handles.net.peers().await.map(|p| p.len()).unwrap_or(0);
    Response::Status {
        handle,
        peer_id: handles.net.local_peer_id().to_owned(),
        listen_addrs,
        peer_count,
    }
}

/// The response for a network command issued before the keystore is unlocked.
fn locked() -> Response {
    Response::Error {
        message: "unlock the keystore first (run `prism unlock`)".to_owned(),
    }
}
