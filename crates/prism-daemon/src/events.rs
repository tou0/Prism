// SPDX-License-Identifier: AGPL-3.0-or-later
//! Server-initiated push events, fanned out to subscribed IPC connections.
//!
//! Events flow over a [`tokio::sync::broadcast`] channel owned by
//! [`crate::state::AppState`]. Broadcast fan-out requires the message type to be
//! `Clone`, so message payloads sit behind an [`Arc`]: cloning a [`DaemonEvent`]
//! for each subscriber clones an `Arc` (and small owned fields), **never the
//! plaintext body**. The body stays in a zeroizing buffer until the exact moment
//! it is rendered into a wire [`prism_proto::Event`] for a specific subscriber.

use std::sync::Arc;

use prism_proto::{Event, PeerInfo, Sensitive};
use zeroize::Zeroizing;

/// A decrypted inbound message awaiting push. Deliberately **not** `Clone`
/// (it holds plaintext); it is shared across subscribers via [`Arc`].
pub struct InboundMessage {
    /// The verified sender's full fingerprint (base58).
    pub from_fingerprint: String,
    /// The decrypted body, zeroized when the last `Arc` drops.
    pub body: Zeroizing<Vec<u8>>,
}

/// An event pushed to subscribed connections. `Clone` is cheap: an `Arc` bump
/// plus small owned fields — the plaintext is never duplicated.
#[derive(Clone)]
pub enum DaemonEvent {
    /// An inbound message was received, decrypted, and identity-verified.
    Message(Arc<InboundMessage>),
    /// A peer appeared on the local network (mDNS discovery).
    PeerDiscovered(PeerInfo),
    /// A previously discovered peer is no longer visible.
    PeerLost(String),
}

impl DaemonEvent {
    /// Render this event into its wire form for one subscriber.
    ///
    /// The message body is exposed here (lossy UTF-8, mirroring the `Inbox`
    /// drain) into a [`Sensitive`] wrapper — the only point it leaves the
    /// zeroizing buffer, and never logged.
    pub fn to_wire(&self) -> Event {
        match self {
            DaemonEvent::Message(msg) => Event::Message {
                from_fingerprint: msg.from_fingerprint.clone(),
                body: Sensitive::new(String::from_utf8_lossy(&msg.body).into_owned()),
            },
            DaemonEvent::PeerDiscovered(peer) => Event::PeerDiscovered { peer: peer.clone() },
            DaemonEvent::PeerLost(fingerprint) => Event::PeerLost {
                fingerprint: fingerprint.clone(),
            },
        }
    }
}
