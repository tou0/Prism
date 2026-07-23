// SPDX-License-Identifier: AGPL-3.0-or-later
//! Peer-discovery watch: turns the swarm's peer list into push events.
//!
//! This polls the existing `NetHandle::peers()` API and diffs successive
//! snapshots, emitting [`DaemonEvent::PeerDiscovered`] / [`DaemonEvent::PeerLost`]
//! onto the push broadcast. The TUI takes its initial peer list from an explicit
//! `Peers` request and then keeps it current from these events; the reducer
//! treats discovery idempotently, so the snapshot/event overlap is harmless.

use std::collections::{HashMap, HashSet};
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
        // Fingerprints seen in the previous snapshot.
        let mut known: HashSet<String> = HashSet::new();

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

            let current_set: HashSet<String> = current.keys().cloned().collect();

            // Newly appeared peers. `send` errors only when nobody is
            // subscribed, which is fine to ignore — the next subscriber fetches
            // a fresh snapshot via a `Peers` request.
            for fingerprint in current_set.difference(&known) {
                if let Some(peer) = current.get(fingerprint) {
                    let _ = events.send(DaemonEvent::PeerDiscovered(peer.clone()));
                }
            }
            // Peers that disappeared.
            for fingerprint in known.difference(&current_set) {
                let _ = events.send(DaemonEvent::PeerLost(fingerprint.clone()));
            }

            known = current_set;
        }
    })
}
