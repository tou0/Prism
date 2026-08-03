// SPDX-License-Identifier: AGPL-3.0-or-later
//! Publishing our signed DHT locator (milestones M4/M5).
//!
//! The locator is **re-sealed on every cycle** from the addresses we currently
//! hold, not sealed once at startup. That matters for M5: a NAT-bound node only
//! acquires its relay **circuit address** once a reservation is granted, which
//! happens *after* networking comes up. A locator sealed once at startup would
//! advertise the addresses we had before the reservation existed — so peers would
//! discover our identity with no way to reach us, and the whole direct→relay
//! fallback would be undiscoverable. Re-sealing also refreshes `published_at`,
//! keeping the record fresh against its DHT TTL.
//!
//! The identity is read from `AppState` (where the daemon already holds it in
//! RAM after unlock) and used **transiently** inside a cycle to sign; this task
//! keeps no copy of it between cycles.
//!
//! A node with no publishable address still publishes an **identity-only**
//! locator: discoverable, but not directly connectable — the honest posture.

use std::sync::Arc;
use std::time::Duration;

use tracing::debug;

use crate::state::AppState;

/// Fast initial cadence, so the record appears soon after the DHT connection and
/// any relay reservation are up.
const INITIAL_INTERVAL: Duration = Duration::from_secs(5);
/// Number of fast initial attempts (~1 minute) before dropping to steady state.
const INITIAL_ATTEMPTS: usize = 12;
/// Steady-state re-publication interval (well under a typical DHT record TTL).
const STEADY_INTERVAL: Duration = Duration::from_secs(600);

/// Spawn the locator re-publication task. Runs for the lifetime of the
/// networking subsystem.
pub fn spawn_locator_publish(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for _ in 0..INITIAL_ATTEMPTS {
            publish_once(&state).await;
            tokio::time::sleep(INITIAL_INTERVAL).await;
        }
        loop {
            publish_once(&state).await;
            tokio::time::sleep(STEADY_INTERVAL).await;
        }
    })
}

/// Seal and publish one locator from the current address set. Silent on failure:
/// a locked keystore or a down network is a normal transient state, and the next
/// cycle retries.
async fn publish_once(state: &AppState) {
    let Some(seed) = state.unlocked.read().await.as_ref().map(|id| id.seed()) else {
        return; // locked: nothing to sign with, and nothing to advertise
    };
    let guard = state.net.read().await;
    let Some(handles) = guard.as_ref() else {
        return; // networking is not up
    };

    let addrs = publishable_addrs(handles, &state.net_config).await;
    let identity = prism_core::IdentityKeypair::from_seed(&seed);
    let published_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let key = prism_core::own_locator_key(&identity.public());
    // Falls back to an identity-only locator: being discoverable without a
    // reachable address is a real, honest state (NAT-bound, no relay yet).
    let Ok(sealed) = prism_core::seal_locator(&identity, &addrs, published_at)
        .or_else(|_| prism_core::seal_locator(&identity, &[], published_at))
    else {
        return;
    };

    if handles.net.publish_locator(key, sealed).await.is_ok() {
        debug!(addrs = addrs.len(), "published DHT locator");
    }
}

/// The addresses we advertise: configured externals plus everything we are
/// currently listening on — which includes any **relay circuit address** granted
/// by a reservation — filtered by IP hygiene and bounded to what a locator
/// accepts.
///
/// Circuit addresses survive the hygiene filter because the IP they carry is the
/// *relay's*, which is globally routable; and the canonical
/// `<relay>/p2p/<id>/p2p-circuit` form stays within the locator's per-address
/// length cap, so no format change is needed to advertise a relayed path.
async fn publishable_addrs(
    handles: &crate::state::NetworkHandles,
    config: &prism_net::NetConfig,
) -> Vec<String> {
    let mut candidates = config.external_addrs.clone();
    if let Ok(listeners) = handles.net.listeners().await {
        candidates.extend(listeners);
    }
    let mut addrs: Vec<String> = prism_net::public_addrs(&candidates)
        .into_iter()
        .filter(|a| a.len() <= prism_core::locator::MAX_ADDR_LEN)
        .collect();
    addrs.sort();
    addrs.dedup();
    addrs.truncate(prism_core::locator::MAX_LOCATOR_ADDRS);
    addrs
}
