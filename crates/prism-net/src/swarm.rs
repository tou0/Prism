// SPDX-License-Identifier: AGPL-3.0-or-later
//! The swarm task: the single owner of the libp2p `Swarm`.
//!
//! It polls the swarm continuously, maintains the mDNS-discovered peer table,
//! serves inbound bundle fetches from a cached copy, and hands inbound message
//! deliveries to the [`InboundSink`] (the core session thread) **without ever
//! blocking its own poll loop** — so a slow disk write in the core thread can
//! never stall discovery or in-flight requests (the deadlock-prevention
//! invariant). Outbound commands arrive over a channel from the daemon.

use std::collections::{HashMap, HashSet};

use futures::stream::{FuturesUnordered, StreamExt};
use libp2p::kad::store::RecordStore;
use libp2p::kad::{self, GetRecordOk, QueryId, QueryResult, Quorum, Record, RecordKey};
use libp2p::request_response::{
    Event as RrEvent, Message as RrMessage, OutboundRequestId, ResponseChannel,
};
use libp2p::swarm::SwarmEvent;
use libp2p::{mdns, Multiaddr, PeerId, Swarm};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use crate::behaviour::{PrismBehaviour, PrismBehaviourEvent};
use crate::identity::{peer_id_from_key, peer_key_from_id, PeerKey};
use crate::protocol::{WireRequest, WireResponse, WIRE_VERSION};
use crate::{
    DhtStatus, DiscoverySource, InboundSink, NatStatus, NetError, PeerRecord, Reachability,
};

/// Reply channel for a `resolve_locator` query: the opaque record bytes, or
/// `None` if the query finished without finding a record.
type ResolveReply = oneshot::Sender<Result<Option<Vec<u8>>, NetError>>;

/// Turn per-address AutoNAT results into one verdict (M5).
///
/// AutoNAT v2 reports **per address**, deliberately: it has no aggregate
/// "am I behind a NAT" answer, so this is where that question is decided.
/// * any address dialled back ⇒ [`Reachability::Public`] (we are reachable
///   *somewhere*, which is all a peer needs);
/// * no results at all ⇒ [`Reachability::Unknown`] — an honest "not yet known",
///   never optimistically reported as reachable;
/// * results exist and all failed ⇒ [`Reachability::Private`].
fn aggregate_reachability(results: &HashMap<Multiaddr, bool>) -> Reachability {
    if results.values().any(|ok| *ok) {
        Reachability::Public
    } else if results.is_empty() {
        Reachability::Unknown
    } else {
        Reachability::Private
    }
}

/// A command from the daemon to the swarm task. Each carries a `oneshot` for
/// the reply the daemon awaits.
pub(crate) enum Command {
    /// Snapshot the discovered-peer table.
    Peers {
        reply: oneshot::Sender<Vec<PeerRecord>>,
    },
    /// Fetch a peer's signed prekey bundle (opaque bytes).
    FetchBundle {
        key: PeerKey,
        reply: oneshot::Sender<Result<Vec<u8>, NetError>>,
    },
    /// Deliver a sealed message to a peer and await its ack.
    Deliver {
        key: PeerKey,
        sealed: Vec<u8>,
        reply: oneshot::Sender<Result<(), NetError>>,
    },
    /// Snapshot our own bound listen addresses (for status).
    Listeners { reply: oneshot::Sender<Vec<String>> },
    /// Update the cached bundle served to peers that request it.
    SetBundle { bundle: Vec<u8> },
    /// Manually seed a peer's address (out-of-band hint; mDNS remains the
    /// automatic discovery mechanism). Used for deterministic tests, a future
    /// designated-peer feature, and DHT-resolved peers (with `source: Dht`).
    AddPeerAddress {
        key: PeerKey,
        addr: String,
        source: DiscoverySource,
    },
    /// Publish our signed locator record to the DHT (opaque signed bytes).
    PublishLocator {
        key: Vec<u8>,
        value: Vec<u8>,
        reply: oneshot::Sender<Result<(), NetError>>,
    },
    /// Resolve a locator by its DHT key; returns opaque record bytes or `None`.
    ResolveLocator { key: Vec<u8>, reply: ResolveReply },
    /// Trigger a Kademlia bootstrap via the configured bootstrap peers.
    Bootstrap {
        reply: oneshot::Sender<Result<(), NetError>>,
    },
    /// Snapshot the DHT's local state.
    DhtStatus { reply: oneshot::Sender<DhtStatus> },
    /// Snapshot our own reachability as AutoNAT sees it (M5).
    NatStatus { reply: oneshot::Sender<NatStatus> },
    /// Advertise a globally-routable address as ours (confirms it to the swarm,
    /// which upgrades Kademlia to server mode so we serve/store records).
    AddExternalAddress { addr: String },
}

/// What a pending outbound request is waiting to resolve.
enum Pending {
    Bundle(oneshot::Sender<Result<Vec<u8>, NetError>>),
    Ack(oneshot::Sender<Result<(), NetError>>),
}

/// One entry in the discovered-peer table.
struct PeerEntry {
    peer_id: PeerId,
    addrs: Vec<Multiaddr>,
    connected: bool,
    source: DiscoverySource,
}

/// The swarm task's owned state.
pub(crate) struct SwarmTask {
    swarm: Swarm<PrismBehaviour>,
    sink: std::sync::Arc<dyn InboundSink>,
    cmd_rx: mpsc::Receiver<Command>,
    /// Discovered peers, keyed by their Ed25519 public key.
    by_key: HashMap<PeerKey, PeerEntry>,
    /// Reverse index for swarm events that carry only a `PeerId`.
    by_id: HashMap<PeerId, PeerKey>,
    /// Outbound requests awaiting a response.
    pending_outbound: HashMap<OutboundRequestId, Pending>,
    /// Inbound deliveries awaiting the core thread's verdict, paired with the
    /// libp2p response channel to answer once it resolves. Polled in the main
    /// loop so a slow core never blocks swarm polling.
    pending_inbound: FuturesUnordered<
        futures::future::BoxFuture<'static, (crate::InboundOutcome, ResponseChannel<WireResponse>)>,
    >,
    /// The bundle served to peers on `GetBundle`, if published yet.
    current_bundle: Option<Vec<u8>>,
    /// Our own bound listen addresses.
    listen_addrs: Vec<Multiaddr>,
    /// Whether the Kademlia DHT is enabled on this node.
    dht_enabled: bool,
    /// Bootstrap peers to add and dial on startup (peer id + transport addr).
    bootstrap: Vec<(PeerId, Multiaddr)>,
    /// DHT `get_record` queries awaiting a result.
    pending_get: HashMap<QueryId, ResolveReply>,
    /// DHT `put_record` queries awaiting a result.
    pending_put: HashMap<QueryId, oneshot::Sender<Result<(), NetError>>>,
    /// Distinct peers seen entering the routing table (approximate liveness for
    /// `status`; never decremented — a coarse "have we joined?" signal).
    dht_peers: HashSet<PeerId>,
    /// Last AutoNAT verdict per probed address (M5): `true` = dialled back
    /// successfully. Keyed by address because reachability is per-address — one
    /// confirmed address is enough to be Public, while Private requires that
    /// every address probed so far has failed.
    autonat_results: HashMap<Multiaddr, bool>,
}

impl SwarmTask {
    pub(crate) fn new(
        swarm: Swarm<PrismBehaviour>,
        sink: std::sync::Arc<dyn InboundSink>,
        cmd_rx: mpsc::Receiver<Command>,
        dht_enabled: bool,
        bootstrap: Vec<(PeerId, Multiaddr)>,
    ) -> Self {
        Self {
            swarm,
            sink,
            cmd_rx,
            by_key: HashMap::new(),
            by_id: HashMap::new(),
            pending_outbound: HashMap::new(),
            pending_inbound: FuturesUnordered::new(),
            current_bundle: None,
            listen_addrs: Vec::new(),
            dht_enabled,
            bootstrap,
            pending_get: HashMap::new(),
            pending_put: HashMap::new(),
            dht_peers: HashSet::new(),
            autonat_results: HashMap::new(),
        }
    }

    /// Aggregate the per-address AutoNAT results into a single verdict.
    ///
    /// One confirmed address is enough to be [`Reachability::Public`] (we are
    /// dialable *somewhere*); [`Reachability::Private`] requires that every
    /// address probed so far failed; with no results the answer is honestly
    /// [`Reachability::Unknown`] rather than an optimistic guess.
    fn reachability(&self) -> Reachability {
        aggregate_reachability(&self.autonat_results)
    }

    /// Snapshot our reachability for `status`.
    fn nat_status(&self) -> NatStatus {
        let confirmed_addrs = self
            .autonat_results
            .iter()
            .filter(|(_, ok)| **ok)
            .map(|(addr, _)| addr.to_string())
            .collect();
        NatStatus {
            reachability: self.reachability(),
            confirmed_addrs,
            probes: self.autonat_results.len(),
        }
    }

    /// Run until the command channel closes (daemon shutdown).
    pub(crate) async fn run(mut self) {
        self.start_bootstrap();
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => self.on_swarm_event(event),
                cmd = self.cmd_rx.recv() => match cmd {
                    Some(cmd) => self.on_command(cmd),
                    None => break, // daemon dropped the handle
                },
                Some((outcome, channel)) = self.pending_inbound.next() => {
                    let response = match outcome {
                        crate::InboundOutcome::Accepted => WireResponse::Ack { version: WIRE_VERSION },
                        crate::InboundOutcome::Rejected => WireResponse::Error {
                            version: WIRE_VERSION,
                            reason: "message rejected".to_owned(),
                        },
                    };
                    // The peer may have gone away; a failed send is not fatal.
                    let _ = self.swarm.behaviour_mut().rr.send_response(channel, response);
                }
            }
        }
        debug!("swarm task shutting down");
    }

    fn on_command(&mut self, cmd: Command) {
        match cmd {
            Command::Peers { reply } => {
                let peers = self
                    .by_key
                    .iter()
                    .map(|(key, entry)| PeerRecord {
                        key: *key,
                        peer_id: entry.peer_id.to_base58(),
                        addrs: entry.addrs.iter().map(Multiaddr::to_string).collect(),
                        connected: entry.connected,
                        source: entry.source,
                    })
                    .collect();
                let _ = reply.send(peers);
            }
            Command::FetchBundle { key, reply } => match self.addresses_for(&key) {
                Some((peer_id, addrs)) => {
                    let id = self.swarm.behaviour_mut().rr.send_request_with_addresses(
                        &peer_id,
                        WireRequest::GetBundle {
                            version: WIRE_VERSION,
                        },
                        addrs,
                    );
                    self.pending_outbound.insert(id, Pending::Bundle(reply));
                }
                None => {
                    let _ = reply.send(Err(NetError::PeerNotReachable));
                }
            },
            Command::Deliver { key, sealed, reply } => match self.addresses_for(&key) {
                Some((peer_id, addrs)) => {
                    let id = self.swarm.behaviour_mut().rr.send_request_with_addresses(
                        &peer_id,
                        WireRequest::Deliver {
                            version: WIRE_VERSION,
                            sealed,
                        },
                        addrs,
                    );
                    self.pending_outbound.insert(id, Pending::Ack(reply));
                }
                None => {
                    let _ = reply.send(Err(NetError::PeerNotReachable));
                }
            },
            Command::Listeners { reply } => {
                let _ = reply.send(self.listen_addrs.iter().map(Multiaddr::to_string).collect());
            }
            Command::SetBundle { bundle } => self.current_bundle = Some(bundle),
            Command::AddPeerAddress { key, addr, source } => match addr.parse::<Multiaddr>() {
                Ok(addr) => self.upsert_peer(key, peer_id_from_key(&key), Some(addr), source),
                Err(_) => warn!("ignoring unparseable peer address hint"),
            },
            Command::PublishLocator { key, value, reply } => {
                match self.swarm.behaviour_mut().kad.as_mut() {
                    Some(kad) => {
                        let record = Record::new(RecordKey::new(&key), value);
                        match kad.put_record(record, Quorum::One) {
                            Ok(id) => {
                                self.pending_put.insert(id, reply);
                            }
                            Err(e) => {
                                let _ = reply.send(Err(NetError::RequestFailed(e.to_string())));
                            }
                        }
                    }
                    None => {
                        let _ = reply.send(Err(NetError::DhtDisabled));
                    }
                }
            }
            Command::ResolveLocator { key, reply } => {
                match self.swarm.behaviour_mut().kad.as_mut() {
                    Some(kad) => {
                        let id = kad.get_record(RecordKey::new(&key));
                        self.pending_get.insert(id, reply);
                    }
                    None => {
                        let _ = reply.send(Err(NetError::DhtDisabled));
                    }
                }
            }
            Command::Bootstrap { reply } => {
                let result = match self.swarm.behaviour_mut().kad.as_mut() {
                    Some(kad) => kad
                        .bootstrap()
                        .map(|_| ())
                        .map_err(|_| NetError::NoBootstrapPeers),
                    None => Err(NetError::DhtDisabled),
                };
                let _ = reply.send(result);
            }
            Command::DhtStatus { reply } => {
                let _ = reply.send(DhtStatus {
                    enabled: self.dht_enabled,
                    routing_peers: self.dht_peers.len(),
                });
            }
            Command::NatStatus { reply } => {
                let _ = reply.send(self.nat_status());
            }
            Command::AddExternalAddress { addr } => match addr.parse::<Multiaddr>() {
                Ok(addr) => self.swarm.add_external_address(addr),
                Err(_) => warn!("ignoring unparseable external address"),
            },
        }
    }

    /// Seed the configured bootstrap peers into Kademlia and kick off a
    /// bootstrap query. A no-op if the DHT is disabled or no bootstrap peers
    /// are configured (a lone node still runs — it just has no DHT entry
    /// point, which is the documented "M4 must be joinable via --bootstrap").
    fn start_bootstrap(&mut self) {
        if self.bootstrap.is_empty() {
            return;
        }
        let peers = std::mem::take(&mut self.bootstrap);
        // Record each bootstrap peer's address in the peer table too — not only
        // in Kademlia — so it is a dialable messaging peer, not merely a DHT
        // entry point (a bootstrap node is often also a reachable contact).
        for (peer, addr) in &peers {
            if let Some(key) = peer_key_from_id(peer) {
                self.upsert_peer(
                    key,
                    Some(*peer),
                    Some(addr.clone()),
                    DiscoverySource::Manual,
                );
            }
        }
        if let Some(kad) = self.swarm.behaviour_mut().kad.as_mut() {
            for (peer, addr) in &peers {
                kad.add_address(peer, addr.clone());
            }
            // Errors only with no known peers, which we just guarded against.
            let _ = kad.bootstrap();
        }
    }

    fn on_kad_event(&mut self, event: kad::Event) {
        match event {
            kad::Event::OutboundQueryProgressed { id, result, .. } => match result {
                QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(peer_record))) => {
                    // First record wins; the daemon validates it. Later records
                    // for the same query find no waiting sender (harmless).
                    if let Some(reply) = self.pending_get.remove(&id) {
                        let _ = reply.send(Ok(Some(peer_record.record.value)));
                    }
                }
                QueryResult::GetRecord(Ok(GetRecordOk::FinishedWithNoAdditionalRecord {
                    ..
                }))
                | QueryResult::GetRecord(Err(_)) => {
                    if let Some(reply) = self.pending_get.remove(&id) {
                        let _ = reply.send(Ok(None));
                    }
                }
                QueryResult::PutRecord(result) => {
                    if let Some(reply) = self.pending_put.remove(&id) {
                        let _ = reply.send(
                            result
                                .map(|_| ())
                                .map_err(|e| NetError::RequestFailed(e.to_string())),
                        );
                    }
                }
                _ => {}
            },
            kad::Event::InboundRequest {
                request:
                    kad::InboundRequest::PutRecord {
                        record: Some(record),
                        ..
                    },
            } => {
                // FilterBoth: nothing is auto-stored. Validate the record via
                // prism-core (delegated through the sink — prism-net runs no
                // crypto) before storing it on the network's behalf.
                if self
                    .sink
                    .validate_locator(record.key.as_ref(), &record.value)
                {
                    if let Some(kad) = self.swarm.behaviour_mut().kad.as_mut() {
                        if let Err(e) = kad.store_mut().put(record) {
                            debug!(error = %e, "not storing a valid locator (store full)");
                        }
                    }
                } else {
                    debug!("rejected an invalid inbound DHT locator");
                }
            }
            kad::Event::RoutingUpdated { peer, .. } => {
                self.dht_peers.insert(peer);
            }
            _ => {}
        }
    }

    /// Resolve a peer key to its `PeerId` and known addresses, if discovered.
    fn addresses_for(&self, key: &PeerKey) -> Option<(PeerId, Vec<Multiaddr>)> {
        let entry = self.by_key.get(key)?;
        if entry.addrs.is_empty() {
            return None;
        }
        Some((entry.peer_id, entry.addrs.clone()))
    }

    fn on_swarm_event(&mut self, event: SwarmEvent<PrismBehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(PrismBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, addr) in list {
                    if let Some(key) = peer_key_from_id(&peer_id) {
                        debug!(peer = %peer_id, "mDNS discovered");
                        self.upsert_peer(key, Some(peer_id), Some(addr), DiscoverySource::Mdns);
                    }
                }
            }
            SwarmEvent::Behaviour(PrismBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                for (peer_id, addr) in list {
                    if let Some(key) = self.by_id.get(&peer_id).copied() {
                        if let Some(entry) = self.by_key.get_mut(&key) {
                            entry.addrs.retain(|a| a != &addr);
                        }
                    }
                }
            }
            SwarmEvent::Behaviour(PrismBehaviourEvent::Kad(event)) => self.on_kad_event(event),
            // AutoNAT v2 (M5): one dial-back probe finished. The behaviour has
            // already told the swarm to confirm the address on success; we only
            // record the per-address verdict so `status` can report reachability.
            SwarmEvent::Behaviour(PrismBehaviourEvent::Autonat(event)) => {
                let reachable = event.result.is_ok();
                self.autonat_results.insert(event.tested_addr, reachable);
                debug!(
                    reachable,
                    verdict = ?self.reachability(),
                    "AutoNAT probe completed"
                );
            }
            // identify (M5): peers report the address they observe for us. The
            // behaviour turns that into an external-address *candidate*, which
            // AutoNAT then verifies — we never trust an observed address on a
            // peer's word alone, so nothing is recorded here.
            SwarmEvent::Behaviour(PrismBehaviourEvent::Identify(_)) => {}
            SwarmEvent::Behaviour(PrismBehaviourEvent::AutonatServer(_)) => {}
            SwarmEvent::Behaviour(PrismBehaviourEvent::Rr(RrEvent::Message {
                peer,
                message,
                ..
            })) => self.on_rr_message(peer, message),
            SwarmEvent::Behaviour(PrismBehaviourEvent::Rr(RrEvent::OutboundFailure {
                request_id,
                error,
                ..
            })) => {
                if let Some(pending) = self.pending_outbound.remove(&request_id) {
                    let err = NetError::RequestFailed(error.to_string());
                    match pending {
                        Pending::Bundle(reply) => {
                            let _ = reply.send(Err(err));
                        }
                        Pending::Ack(reply) => {
                            let _ = reply.send(Err(err));
                        }
                    }
                }
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                if let Some(key) = peer_key_from_id(&peer_id) {
                    // A connection without prior discovery (an inbound dial):
                    // `source` is only applied if this is the first sighting;
                    // an already-discovered peer keeps its mDNS/DHT source.
                    self.upsert_peer(key, Some(peer_id), None, DiscoverySource::Manual);
                    if let Some(entry) = self.by_key.get_mut(&key) {
                        entry.connected = true;
                    }
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                if let Some(key) = self.by_id.get(&peer_id).copied() {
                    if let Some(entry) = self.by_key.get_mut(&key) {
                        entry.connected = false;
                    }
                }
            }
            SwarmEvent::NewListenAddr { address, .. } if !self.listen_addrs.contains(&address) => {
                self.listen_addrs.push(address);
            }
            _ => {}
        }
    }

    fn on_rr_message(&mut self, peer: PeerId, message: RrMessage<WireRequest, WireResponse>) {
        match message {
            RrMessage::Request {
                request, channel, ..
            } => {
                if !request.version_ok() {
                    let _ = self.swarm.behaviour_mut().rr.send_response(
                        channel,
                        WireResponse::Error {
                            version: WIRE_VERSION,
                            reason: "unsupported protocol version".to_owned(),
                        },
                    );
                    return;
                }
                match request {
                    WireRequest::GetBundle { .. } => {
                        let response = match &self.current_bundle {
                            Some(bundle) => WireResponse::Bundle {
                                version: WIRE_VERSION,
                                bundle: bundle.clone(),
                            },
                            None => WireResponse::Error {
                                version: WIRE_VERSION,
                                reason: "no bundle published".to_owned(),
                            },
                        };
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .rr
                            .send_response(channel, response);
                    }
                    WireRequest::Deliver { sealed, .. } => {
                        // The identity check happens in the core thread, which
                        // compares this Noise-authenticated key against the
                        // message's crypto-proven identity. If we cannot even
                        // recover the key, reject outright.
                        let Some(from) = peer_key_from_id(&peer) else {
                            let _ = self.swarm.behaviour_mut().rr.send_response(
                                channel,
                                WireResponse::Error {
                                    version: WIRE_VERSION,
                                    reason: "unidentifiable peer".to_owned(),
                                },
                            );
                            return;
                        };
                        let (tx, rx) = oneshot::channel();
                        // Hand off without blocking; if the core queue is full
                        // the sink resolves `tx` with Rejected immediately.
                        self.sink.deliver(from, sealed, tx);
                        self.pending_inbound.push(Box::pin(async move {
                            let outcome = rx.await.unwrap_or(crate::InboundOutcome::Rejected);
                            (outcome, channel)
                        }));
                    }
                }
            }
            RrMessage::Response {
                request_id,
                response,
            } => {
                let Some(pending) = self.pending_outbound.remove(&request_id) else {
                    return;
                };
                match (pending, response) {
                    (Pending::Bundle(reply), WireResponse::Bundle { bundle, .. }) => {
                        let _ = reply.send(Ok(bundle));
                    }
                    (Pending::Ack(reply), WireResponse::Ack { .. }) => {
                        let _ = reply.send(Ok(()));
                    }
                    (Pending::Bundle(reply), WireResponse::Error { reason, .. }) => {
                        let _ = reply.send(Err(NetError::RequestFailed(reason)));
                    }
                    (Pending::Ack(reply), WireResponse::Error { reason, .. }) => {
                        let _ = reply.send(Err(NetError::RequestFailed(reason)));
                    }
                    // Type-mismatched response (e.g. Ack for a bundle fetch).
                    (Pending::Bundle(reply), _) => {
                        let _ = reply.send(Err(NetError::RequestFailed(
                            "unexpected response kind".to_owned(),
                        )));
                    }
                    (Pending::Ack(reply), _) => {
                        let _ = reply.send(Err(NetError::RequestFailed(
                            "unexpected response kind".to_owned(),
                        )));
                    }
                }
            }
        }
    }

    /// Insert or update a peer entry, adding a `PeerId` and/or address. `source`
    /// is recorded only on **first** sighting; a re-sighting keeps the original
    /// discovery source (so a peer first found by mDNS stays tagged mDNS).
    fn upsert_peer(
        &mut self,
        key: PeerKey,
        peer_id: Option<PeerId>,
        addr: Option<Multiaddr>,
        source: DiscoverySource,
    ) {
        let peer_id = peer_id
            .or_else(|| self.by_key.get(&key).map(|e| e.peer_id))
            .or_else(|| peer_id_from_key(&key));
        let Some(peer_id) = peer_id else {
            return;
        };
        self.by_id.insert(peer_id, key);
        let entry = self.by_key.entry(key).or_insert_with(|| PeerEntry {
            peer_id,
            addrs: Vec::new(),
            connected: false,
            source,
        });
        entry.peer_id = peer_id;
        if let Some(addr) = addr {
            if !entry.addrs.contains(&addr) {
                entry.addrs.push(addr);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Multiaddr {
        match s.parse() {
            Ok(a) => a,
            Err(_) => panic!("test address must parse: {s}"),
        }
    }

    /// The AutoNAT v2 -> verdict synthesis, which is ours rather than the
    /// library's (v2 reports per address and has no aggregate status).
    #[test]
    fn reachability_is_aggregated_honestly() {
        let mut r = HashMap::new();
        assert_eq!(
            aggregate_reachability(&r),
            Reachability::Unknown,
            "no probe has completed: the honest answer is Unknown, not Public"
        );

        r.insert(addr("/ip4/203.0.113.9/tcp/4001"), false);
        assert_eq!(
            aggregate_reachability(&r),
            Reachability::Private,
            "every probed address failed"
        );

        r.insert(addr("/ip4/203.0.113.9/udp/4001/quic-v1"), true);
        assert_eq!(
            aggregate_reachability(&r),
            Reachability::Public,
            "one dialable address is enough to be reachable"
        );

        // A later failure on another address must not undo a confirmed one.
        r.insert(addr("/ip4/203.0.113.9/tcp/9999"), false);
        assert_eq!(aggregate_reachability(&r), Reachability::Public);
    }
}
