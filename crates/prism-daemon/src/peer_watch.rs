// SPDX-License-Identifier: AGPL-3.0-or-later
//! Peer-discovery watch: turns the swarm's peer list into push events.
//!
//! This polls the existing `NetHandle::peers()` API and diffs successive
//! snapshots, emitting [`DaemonEvent::PeerDiscovered`] / [`DaemonEvent::PeerLost`]
//! onto the push broadcast. The TUI takes its initial peer list from an explicit
//! `Peers` request and then keeps it current from these events; the reducer
//! treats discovery idempotently, so the snapshot/event overlap is harmless.
//!
//! It diffs the **`connected` flag**, not just presence: a peer whose
//! connection drops (e.g. its daemon is killed) is re-emitted as a
//! `PeerDiscovered` upsert with `connected = false`, so the UI reflects the
//! change within one poll instead of showing a stale "connected". Note that
//! `connected` tracks *an open connection*, not reachability — see the
//! "Known limitations" note in `docs/net.md`.

use std::collections::HashMap;
use std::time::Duration;

use prism_core::PublicIdentity;
use prism_net::NetHandle;
use prism_proto::PeerInfo;
use tokio::sync::broadcast;

use crate::events::DaemonEvent;

/// How often to poll the peer list. A peer appearing in a side list ~1.5 s
/// later is imperceptible for LAN mDNS.
const POLL_INTERVAL: Duration = Duration::from_millis(1500);

/// Start the peer-watch task. It runs for the lifetime of the networking
/// subsystem (its `JoinHandle` is held in `NetworkHandles`).
///
// DEFERRED IMPROVEMENT — nice-to-have, NOT a blocker. The idiomatic design is an
// event channel (mpsc) pushed from prism-net's SwarmTask on mDNS
// discovered/expired, instead of polling. It is deliberately left out of M3:
// this milestone adds no network capability and must not reopen the
// signed/tested/audited prism-net layer (M2b). Revisit when the net layer is
// reworked — see the note in CLAUDE.md (M4/M5 roadmap).
pub fn spawn_peer_watch(
    net: NetHandle,
    events: broadcast::Sender<DaemonEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        // The previous snapshot: fingerprint -> was it connected?
        let mut known: HashMap<String, bool> = HashMap::new();

        loop {
            ticker.tick().await;

            let records = match net.peers().await {
                Ok(records) => records,
                // Transient query failure: skip this tick, keep `known` as-is.
                Err(_) => continue,
            };

            // Map current peers by full fingerprint (drop any with unparseable
            // keys — prism-net already validated them, this is belt-and-braces).
            let current: HashMap<String, PeerInfo> = records
                .into_iter()
                .filter_map(|record| {
                    let fingerprint = PublicIdentity::from_bytes(record.key.as_bytes())
                        .ok()
                        .map(|id| id.fingerprint().full())?;
                    Some((
                        fingerprint.clone(),
                        PeerInfo {
                            fingerprint,
                            peer_id: record.peer_id,
                            connected: record.connected,
                        },
                    ))
                })
                .collect();

            // `send` errors only when nobody is subscribed, which is fine to
            // ignore — the next subscriber fetches a fresh snapshot via `Peers`.
            for event in compute_peer_events(&known, &current) {
                let _ = events.send(event);
            }

            known = current
                .iter()
                .map(|(fingerprint, peer)| (fingerprint.clone(), peer.connected))
                .collect();
        }
    })
}

/// Diff the previous snapshot (`fingerprint -> connected`) against the current
/// peers, producing the push events to emit:
///
/// - a fingerprint not seen before → `PeerDiscovered`;
/// - a fingerprint whose `connected` flag changed → `PeerDiscovered` again (an
///   upsert the TUI merges in place — this is how a dropped connection greys a
///   peer within one poll);
/// - a fingerprint gone from the current set → `PeerLost`.
///
/// Pure and side-effect-free, so the diff logic is unit-testable without a
/// live swarm.
fn compute_peer_events(
    prev: &HashMap<String, bool>,
    current: &HashMap<String, PeerInfo>,
) -> Vec<DaemonEvent> {
    let mut events = Vec::new();
    for (fingerprint, peer) in current {
        match prev.get(fingerprint) {
            None => events.push(DaemonEvent::PeerDiscovered(peer.clone())),
            Some(&was_connected) if was_connected != peer.connected => {
                events.push(DaemonEvent::PeerDiscovered(peer.clone()));
            }
            Some(_) => {} // present and unchanged: nothing to emit
        }
    }
    for fingerprint in prev.keys() {
        if !current.contains_key(fingerprint) {
            events.push(DaemonEvent::PeerLost(fingerprint.clone()));
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(fingerprint: &str, connected: bool) -> PeerInfo {
        PeerInfo {
            fingerprint: fingerprint.to_owned(),
            peer_id: "pid".to_owned(),
            connected,
        }
    }

    fn map(peers: &[PeerInfo]) -> HashMap<String, PeerInfo> {
        peers
            .iter()
            .map(|p| (p.fingerprint.clone(), p.clone()))
            .collect()
    }

    #[test]
    fn new_peer_is_discovered() {
        let events = compute_peer_events(&HashMap::new(), &map(&[peer("alice", true)]));
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], DaemonEvent::PeerDiscovered(p) if p.fingerprint == "alice"));
    }

    #[test]
    fn unchanged_peer_emits_nothing() {
        let prev = HashMap::from([("alice".to_owned(), true)]);
        let events = compute_peer_events(&prev, &map(&[peer("alice", true)]));
        assert!(events.is_empty());
    }

    /// The core of the bug-A fix: a connection dropping (connected true->false)
    /// is surfaced as a PeerDiscovered upsert carrying connected=false.
    #[test]
    fn connection_drop_is_emitted_as_an_upsert() {
        let prev = HashMap::from([("alice".to_owned(), true)]);
        let events = compute_peer_events(&prev, &map(&[peer("alice", false)]));
        assert_eq!(events.len(), 1);
        match &events[0] {
            DaemonEvent::PeerDiscovered(p) => {
                assert_eq!(p.fingerprint, "alice");
                assert!(!p.connected, "must carry the new connected=false");
            }
            _ => panic!("expected a PeerDiscovered upsert"),
        }
    }

    #[test]
    fn reconnection_is_also_emitted() {
        let prev = HashMap::from([("alice".to_owned(), false)]);
        let events = compute_peer_events(&prev, &map(&[peer("alice", true)]));
        assert!(
            matches!(&events[0], DaemonEvent::PeerDiscovered(p) if p.connected),
            "false->true must re-emit with connected=true"
        );
    }

    #[test]
    fn disappearance_is_peer_lost() {
        let prev = HashMap::from([("alice".to_owned(), true)]);
        let events = compute_peer_events(&prev, &HashMap::new());
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], DaemonEvent::PeerLost(fp) if fp == "alice"));
    }
}
