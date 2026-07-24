// SPDX-License-Identifier: AGPL-3.0-or-later
//! The composed libp2p `NetworkBehaviour`: mDNS (LAN discovery) + Kademlia
//! (off-LAN discovery) + a CBOR request/response protocol carrying opaque
//! Prism payloads.
//!
//! mDNS and Kademlia are each wrapped in a [`Toggle`] so they can be disabled
//! at runtime with **zero footprint**: a disabled mDNS never opens its
//! multicast socket (so `--no-mdns` leaves the `hickory-proto` path entirely
//! un-exercised — see `docs/security-debt.md`), and a disabled DHT installs no
//! Kademlia protocol handler (a LAN-only node).

use libp2p::kad::store::MemoryStore;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{kad, mdns, request_response};

use crate::protocol::{WireRequest, WireResponse};

/// Prism's network behaviour. mDNS finds peers on the LAN; Kademlia finds them
/// off-LAN via signed locator records; request-response carries the (opaque)
/// bundle fetches and message deliveries.
#[derive(NetworkBehaviour)]
pub(crate) struct PrismBehaviour {
    /// Local-network peer discovery (optional; link-local multicast).
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    /// Distributed off-LAN discovery via signed locator records (optional).
    pub kad: Toggle<kad::Behaviour<MemoryStore>>,
    /// The Prism message protocol (opaque payloads, CBOR-framed).
    pub rr: request_response::cbor::Behaviour<WireRequest, WireResponse>,
}
