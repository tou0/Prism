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

    fn validate_locator(&self, key: &[u8], value: &[u8]) -> bool {
        // The crypto lives here (prism-core), never in prism-net. A DHT key is
        // always our 32-byte derived key; anything else is malformed. Full
        // validation (signature, strict key check, key/fingerprint binding) is
        // `open_locator` — a fast, pure function, so this runs inline safely.
        match <&[u8; 32]>::try_from(key) {
            Ok(dht_key) => prism_core::open_locator(value, dht_key).is_ok(),
            Err(_) => false,
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

/// Resolve a peer by its short (handle) fingerprint via the DHT: fetch the
/// signed locator, validate it (prism-core — signature, strict key check,
/// key/fingerprint binding), seed its addresses for the dial path, and return
/// the peer key. `None` if the DHT has no record or it fails validation.
///
/// A validated locator with an empty address set (a NAT-bound peer) still
/// returns its key, but with nothing to dial — the caller then surfaces
/// `NotReachable`, which is the honest M4 outcome (discovered, not connectable
/// until relays land in M5).
async fn resolve_via_dht(handles: &NetworkHandles, short_fp: &str) -> Option<PeerKey> {
    let key = prism_core::dht_locator_key(short_fp);
    let bytes = handles.net.resolve_locator(key).await.ok()??;
    let locator = prism_core::open_locator(&bytes, &key).ok()?;
    let peer_key = PeerKey::from_bytes(*locator.identity().as_bytes());
    for addr in locator.addrs() {
        let _ = handles
            .net
            .add_dht_peer_address(peer_key, addr.clone())
            .await;
    }
    Some(peer_key)
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

    let core = spawn_core(manager, state.events.clone())
        .map_err(|e| format!("failed to start the session thread: {e}"))?;

    // Publish an initial bundle so peers can establish with us.
    let bundle = core.publish_bundle(DEFAULT_ONE_TIME_KEYS).await?;

    // Start the swarm, feeding inbound deliveries to the core thread.
    let sink = Arc::new(CoreInboundSink {
        core_tx: core.sender(),
    });
    let (net, _join) = prism_net::spawn(&seed, sink, &state.listen_addr, state.net_config.clone())
        .map_err(|e| format!("failed to start networking: {e}"))?;
    net.set_bundle(bundle)
        .await
        .map_err(|e| format!("failed to advertise the bundle: {e}"))?;

    // Watch the peer list and push discover/lost events to subscribers.
    let peer_watch = crate::peer_watch::spawn_peer_watch(net.clone(), state.events.clone());

    // The DHT locator is published by a daemon-lifetime task started in
    // `serve()` — it must outlive any single networking bring-up and re-seal from
    // the current address set (see locator_publish.rs).
    info!(peer_id = net.local_peer_id(), "networking is up");
    *guard = Some(NetworkHandles {
        net,
        core,
        _peer_watch: peer_watch,
    });
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

    // Resolve the handle to a discovered peer by matching the short fingerprint,
    // first on the LAN (mDNS), then — if not found — via the DHT (M4).
    let peers = match handles.net.peers().await {
        Ok(peers) => peers,
        Err(e) => {
            return Response::Error {
                message: e.to_string(),
            }
        }
    };
    let peer_key = match peers
        .into_iter()
        .find(|p| short_fingerprint(&p.key).as_deref() == Some(target_fp))
    {
        // Discovered with a dialable address — send directly.
        Some(record) if !record.addrs.is_empty() => record.key,
        // Either undiscovered, or discovered without a dialable address: a peer
        // we hold an open (peer-initiated or bootstrap) connection to but no
        // recorded address for. Resolve via the DHT, which validates the signed
        // locator and seeds its addresses so the dial can proceed.
        _ => match resolve_via_dht(handles, target_fp).await {
            Some(key) => key,
            None => return Response::NotReachable { handle: to },
        },
    };
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
                source: map_source(p.source),
            })
        })
        .collect();
    Response::Peers { peers }
}

/// Map a networking discovery source to its IPC mirror.
pub(crate) fn map_source(source: prism_net::DiscoverySource) -> prism_proto::PeerSource {
    match source {
        prism_net::DiscoverySource::Mdns => prism_proto::PeerSource::Mdns,
        prism_net::DiscoverySource::Dht => prism_proto::PeerSource::Dht,
        prism_net::DiscoverySource::Manual => prism_proto::PeerSource::Manual,
    }
}

/// Handle a `Status` request: our handle, peer id, listen addresses, peer count,
/// and the DHT posture (enabled, routing-table liveness, published addresses).
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
    let dht = handles.net.dht_status().await.ok();
    // What we publish: the same globally-routable set the locator is sealed over
    // (config externals + bound listeners, IP-hygiene filtered). Shown verbatim
    // so the user sees exactly what is exposed on the DHT.
    let mut candidates = state.net_config.external_addrs.clone();
    candidates.extend(listen_addrs.iter().cloned());
    let published_addrs = if state.net_config.enable_dht {
        // Dedup so the display matches the sealed locator (external addrs and
        // listeners can overlap); the locator itself already dedups internally.
        let mut a = prism_net::public_addrs(&candidates);
        a.sort();
        a.dedup();
        a
    } else {
        Vec::new()
    };
    Response::Status {
        handle,
        peer_id: handles.net.local_peer_id().to_owned(),
        listen_addrs,
        peer_count,
        dht_enabled: state.net_config.enable_dht,
        dht_routing_peers: dht.map(|d| d.routing_peers).unwrap_or(0),
        published_addrs,
    }
}

/// Handle a `Resolve` request (M4): resolve a handle to its signed DHT locator,
/// validate it, and report the peer id and published addresses. Returns
/// `NotReachable` when no valid record is found.
pub async fn handle_resolve(state: &AppState, handle: String) -> Response {
    let guard = state.net.read().await;
    let Some(handles) = guard.as_ref() else {
        return locked();
    };
    // Accept `nick#fp` or a bare `#fp` / `fp`; the fingerprint is what we key on.
    let short_fp = handle.rsplit('#').next().unwrap_or(&handle);
    let key = prism_core::dht_locator_key(short_fp);
    let bytes = match handles.net.resolve_locator(key).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Response::NotReachable { handle },
        Err(e) => {
            return Response::Error {
                message: e.to_string(),
            }
        }
    };
    let Ok(locator) = prism_core::open_locator(&bytes, &key) else {
        // A record exists but fails validation — treat as not found (hostile or
        // corrupt); never surface unvalidated network data as a real peer.
        return Response::NotReachable { handle };
    };
    let peer_key = prism_net::PeerKey::from_bytes(*locator.identity().as_bytes());
    let peer_id = prism_net::peer_id_for(&peer_key).unwrap_or_default();
    let fingerprint = full_fingerprint(&peer_key).unwrap_or_else(|| short_fp.to_owned());
    Response::Resolved {
        fingerprint,
        peer_id,
        addrs: locator.addrs().to_vec(),
    }
}

/// The response for a network command issued before the keystore is unlocked.
fn locked() -> Response {
    Response::Error {
        message: "unlock the keystore first (run `prism unlock`)".to_owned(),
    }
}
