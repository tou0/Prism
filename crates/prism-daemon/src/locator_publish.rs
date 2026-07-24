// SPDX-License-Identifier: AGPL-3.0-or-later
//! Publishing our signed DHT locator (milestone M4).
//!
//! The locator is **sealed once** at startup (the private identity key is used
//! transiently there and never held by this task — the task carries only the
//! public, signed bytes and the record key), then **re-published on an
//! interval**. Re-publishing serves two purposes: it survives the brief window
//! before the node connects to a bootstrap peer (an early `put` would only
//! store locally), and it refreshes the record before its DHT TTL expires.
//!
//! A node with no globally-routable address publishes an **empty-address**
//! locator: its identity is discoverable, but it is not directly connectable
//! until NAT traversal / relays (M5). This is the honest M4 posture — discovery
//! is not reachability.

use std::time::Duration;

use prism_net::NetHandle;
use tracing::debug;

/// Fast initial cadence, to publish soon after the bootstrap connection is up.
const INITIAL_INTERVAL: Duration = Duration::from_secs(5);
/// Number of fast initial attempts (~1 minute) before dropping to steady state.
const INITIAL_ATTEMPTS: usize = 12;
/// Steady-state re-publication interval (well under a typical DHT record TTL).
const STEADY_INTERVAL: Duration = Duration::from_secs(600);

/// Spawn the locator re-publication task. `key` is the DHT record key
/// (`prism_core::own_locator_key`) and `sealed` the signed locator bytes; both
/// are public. The task runs for the lifetime of the networking subsystem.
pub fn spawn_locator_publish(
    net: NetHandle,
    key: [u8; 32],
    sealed: Vec<u8>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for _ in 0..INITIAL_ATTEMPTS {
            if net.publish_locator(key, sealed.clone()).await.is_ok() {
                debug!("published DHT locator");
            }
            tokio::time::sleep(INITIAL_INTERVAL).await;
        }
        loop {
            let _ = net.publish_locator(key, sealed.clone()).await;
            tokio::time::sleep(STEADY_INTERVAL).await;
        }
    })
}
