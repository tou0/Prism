// SPDX-License-Identifier: AGPL-3.0-or-later
//! DCUtR restricted to the TCP hole-punching path (milestone M5).
//!
//! # Why this wrapper exists
//!
//! `libp2p-dcutr` is transport-agnostic: its address-candidate set is a plain
//! LRU of multiaddrs fed from `FromSwarm::NewExternalAddrCandidate`, with no
//! transport filter (it drops only *relayed* addresses). Whatever candidates a
//! node accumulates are sent to the peer in the DCUtR `Connect` message, and the
//! peer dials them. Because Prism listens on QUIC as well as TCP, QUIC addresses
//! would become candidates and hole punching would run over the **QUIC + DCUtR**
//! integration.
//!
//! M5's whole purpose is to make NAT traversal *reliable*, so it deliberately
//! does not rest that mechanism on an integration we have not vetted — the same
//! rule applied at M2 to unstabilized crypto. QUIC stays a general transport
//! (used for ordinary direct and relayed connections, where it is a plain
//! modern-transport win); only **hole punching** is pinned to the mature TCP
//! simultaneous-open path.
//!
//! # What this does and does not guarantee
//!
//! It filters the candidates **we advertise**: a QUIC address is never offered to
//! a peer as a hole-punch target. Since every Prism node runs this filter, no
//! Prism node advertises a QUIC candidate, so hole punching across a Prism
//! network is TCP-only.
//!
//! It cannot filter what a *peer* advertises: `dcutr` builds its dial from the
//! remote's address list internally, which is not interceptable without forking
//! the crate. A peer running different or older code could still offer a QUIC
//! address, and we would attempt it. That is the honest limit of this approach —
//! see `docs/net.md`.

use std::task::{Context, Poll};

use libp2p::core::transport::PortUse;
use libp2p::core::{Endpoint, Multiaddr};
use libp2p::dcutr;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NewExternalAddrCandidate,
    THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::PeerId;

/// Whether a multiaddr uses QUIC (and so must not become a hole-punch
/// candidate). Matches both `quic-v1` and the legacy draft-29 `quic`.
pub(crate) fn is_quic(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|p| matches!(p, Protocol::QuicV1 | Protocol::Quic))
}

/// `dcutr::Behaviour` with QUIC excluded from the hole-punch candidate set.
///
/// Every `NetworkBehaviour` method delegates unchanged; the single behavioural
/// difference is in [`NetworkBehaviour::on_swarm_event`], which swallows a
/// `NewExternalAddrCandidate` carrying a QUIC address so the inner behaviour
/// never learns of it.
pub(crate) struct TcpOnlyDcutr {
    inner: dcutr::Behaviour,
}

impl TcpOnlyDcutr {
    /// Wrap a fresh DCUtR behaviour for `local_peer_id`.
    pub(crate) fn new(local_peer_id: PeerId) -> Self {
        Self {
            inner: dcutr::Behaviour::new(local_peer_id),
        }
    }
}

impl NetworkBehaviour for TcpOnlyDcutr {
    type ConnectionHandler = <dcutr::Behaviour as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = <dcutr::Behaviour as NetworkBehaviour>::ToSwarm;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.inner.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    /// The one place this wrapper differs: a QUIC external-address candidate is
    /// dropped instead of being forwarded, so it can never enter DCUtR's
    /// candidate LRU and never be advertised as a hole-punch target.
    ///
    /// Every other event — including `ExternalAddrConfirmed` for a QUIC address,
    /// which matters for the DHT locator and for AutoNAT — passes through
    /// untouched. Only hole punching is constrained.
    fn on_swarm_event(&mut self, event: FromSwarm) {
        if let FromSwarm::NewExternalAddrCandidate(NewExternalAddrCandidate { addr }) = &event {
            if is_quic(addr) {
                return;
            }
        }
        self.inner.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner
            .on_connection_handler_event(peer_id, connection_id, event)
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_addresses_are_recognised_and_tcp_ones_are_not() {
        let cases = [
            ("/ip4/203.0.113.9/udp/4001/quic-v1", true),
            ("/ip4/203.0.113.9/udp/4001/quic", true),
            ("/ip6/2606:4700::1111/udp/4001/quic-v1", true),
            ("/ip4/203.0.113.9/tcp/4001", false),
            ("/ip6/2606:4700::1111/tcp/4001", false),
            // A relayed TCP address is not QUIC; dcutr drops relayed addresses
            // itself, so this filter must not claim responsibility for them.
            ("/ip4/203.0.113.9/tcp/4001/p2p-circuit", false),
        ];
        for (input, expected) in cases {
            let addr: Multiaddr = match input.parse() {
                Ok(a) => a,
                Err(_) => panic!("test input must parse: {input}"),
            };
            assert_eq!(is_quic(&addr), expected, "for {input}");
        }
    }
}
