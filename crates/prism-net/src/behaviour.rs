// SPDX-License-Identifier: AGPL-3.0-or-later
//! The composed libp2p `NetworkBehaviour`: mDNS discovery + a CBOR
//! request/response protocol carrying opaque Prism payloads.

use libp2p::swarm::NetworkBehaviour;
use libp2p::{mdns, request_response};

use crate::protocol::{WireRequest, WireResponse};

/// Prism's network behaviour. mDNS finds peers on the LAN; request-response
/// carries the (opaque) bundle fetches and message deliveries.
#[derive(NetworkBehaviour)]
pub(crate) struct PrismBehaviour {
    /// Local-network peer discovery.
    pub mdns: mdns::tokio::Behaviour,
    /// The Prism message protocol (opaque payloads, CBOR-framed).
    pub rr: request_response::cbor::Behaviour<WireRequest, WireResponse>,
}
