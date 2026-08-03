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
use libp2p::{autonat, dcutr, identify, kad, mdns, relay, request_response};

use crate::protocol::{WireRequest, WireResponse};

/// Prism's network behaviour. mDNS finds peers on the LAN; Kademlia finds them
/// off-LAN via signed locator records; request-response carries the (opaque)
/// bundle fetches and message deliveries; identify + AutoNAT establish whether
/// we are reachable from outside (M5).
#[derive(NetworkBehaviour)]
pub(crate) struct PrismBehaviour {
    /// Local-network peer discovery (optional; link-local multicast).
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    /// Distributed off-LAN discovery via signed locator records (optional).
    pub kad: Toggle<kad::Behaviour<MemoryStore>>,
    /// The Prism message protocol (opaque payloads, CBOR-framed).
    pub rr: request_response::cbor::Behaviour<WireRequest, WireResponse>,
    /// Peer metadata exchange (M5). **Load-bearing, not cosmetic**: peers report
    /// the address they observe for us, which is the only source of external
    /// address *candidates* for AutoNAT to verify, and DCUtR and relay
    /// reservations depend on that same address knowledge. Always enabled.
    pub identify: identify::Behaviour,
    /// AutoNAT v2 *client* (M5): asks servers to dial our candidate addresses
    /// back, so we learn whether we are publicly reachable or NAT-bound. On
    /// success it emits `ExternalAddrConfirmed`, which promotes the candidate to
    /// a real external address. Disabled when NAT traversal is off.
    pub autonat: Toggle<autonat::v2::client::Behaviour>,
    /// AutoNAT v2 *server* (M5): performs those dial-backs for other nodes.
    /// Enabled only on a node the operator declares publicly reachable — a
    /// NAT-bound node cannot usefully dial anyone back.
    pub autonat_server: Toggle<autonat::v2::server::Behaviour>,
    /// Circuit Relay v2 *server* (M5): forwards opaque encrypted bytes for
    /// NAT-bound peers. **Opt-in and capped** (spec §6) — disabled unless the
    /// operator asks for it, so a node is never drained against its owner's
    /// will. It terminates no session and can read nothing.
    pub relay_server: Toggle<relay::Behaviour>,
    /// Circuit Relay v2 *client* (M5): lets us hold a reservation on a relay so
    /// NAT-bound peers can be reached through it, and dial others the same way.
    /// Follows `enable_nat_traversal`.
    pub relay_client: Toggle<relay::client::Behaviour>,
    /// DCUtR — Direct Connection Upgrade through Relay (M5): once a relayed
    /// connection exists, both peers coordinate a simultaneous dial to punch
    /// through their NATs and continue **directly**, dropping the relay. This is
    /// what keeps relays a fallback rather than a permanent hop.
    pub dcutr: Toggle<dcutr::Behaviour>,
}
