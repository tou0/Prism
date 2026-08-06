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
use std::time::{Duration as StdDuration, Instant};

use futures::stream::{FuturesUnordered, StreamExt};
use libp2p::core::transport::ListenerId;
use libp2p::kad::store::RecordStore;
use libp2p::kad::{self, GetRecordOk, QueryId, QueryResult, Quorum, Record, RecordKey};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{
    Event as RrEvent, Message as RrMessage, OutboundRequestId, ResponseChannel,
};
use libp2p::swarm::SwarmEvent;
use libp2p::{dcutr, mdns, relay, Multiaddr, PeerId, Swarm};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use crate::behaviour::{PrismBehaviour, PrismBehaviourEvent};
use crate::identity::{peer_id_from_key, peer_key_from_id, PeerKey};
use crate::protocol::{WireRequest, WireResponse, WIRE_VERSION};
use crate::{
    ConnectionPath, DhtStatus, DiscoverySource, InboundSink, NatStatus, NetError, PeerRecord,
    Reachability,
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

/// Backoff schedule for re-requesting a relay reservation: 2, 4, 8, 16, 32 s,
/// then capped at 60 s. Bounded so a permanently-refusing relay is retried
/// forever but cheaply — a client with no reservation is unreachable inbound, so
/// giving up entirely is never the right answer.
const MAX_RESERVATION_BACKOFF_SECS: u64 = 60;

fn reservation_backoff(attempts: u32) -> StdDuration {
    let secs = 1u64
        .checked_shl(attempts.min(6))
        .unwrap_or(MAX_RESERVATION_BACKOFF_SECS)
        .min(MAX_RESERVATION_BACKOFF_SECS);
    StdDuration::from_secs(secs.max(2))
}

/// Our reservation on one configured relay (M5).
///
/// Reservations were originally requested **once** at startup, which meant any
/// first-attempt failure — a relay not yet dialable, a transient error, a refusal
/// — left the node permanently unreachable inbound for the life of the process.
/// A real-network field test hit exactly that; loopback never did, because there
/// the first attempt always succeeds instantly. Hence the explicit state machine.
struct RelayReservation {
    /// The relay's address, including its trailing `/p2p/<peer-id>`.
    addr: Multiaddr,
    /// The listener currently representing this reservation, if one exists.
    listener: Option<ListenerId>,
    /// True once a `/p2p-circuit` address has actually appeared for `listener`
    /// — i.e. the relay granted the reservation. A listener alone is not enough.
    active: bool,
    /// Consecutive failures, driving the backoff.
    attempts: u32,
    /// When the next attempt is due. `None` means "due now".
    next_attempt: Option<Instant>,
}

impl RelayReservation {
    fn new(addr: Multiaddr) -> Self {
        Self {
            addr,
            listener: None,
            active: false,
            attempts: 0,
            next_attempt: None,
        }
    }

    /// Whether an attempt should be made now (no live listener and the backoff
    /// has elapsed).
    fn is_due(&self, now: Instant) -> bool {
        self.listener.is_none() && self.next_attempt.is_none_or(|due| due <= now)
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
    /// How the currently open connection is carried, if any (M5).
    path: Option<ConnectionPath>,
}

/// Whether a multiaddr routes through a relay circuit.
///
/// A relayed address contains `/p2p-circuit`; that single component is the
/// difference between "the peer learns our IP" and "a relay carries the bytes",
/// so it is what decides the path we report to the user.
fn path_of(addr: &Multiaddr) -> ConnectionPath {
    if addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
        ConnectionPath::Relayed
    } else {
        ConnectionPath::Direct
    }
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
    /// Our reservations on the configured relays (M5). Also the source of the
    /// circuit addresses used to *reach* peers, so it is kept even when a
    /// reservation is not (yet) active.
    reservations: Vec<RelayReservation>,
    /// DHT `get_record` queries awaiting a result.
    pending_get: HashMap<QueryId, ResolveReply>,
    /// DHT `put_record` queries awaiting a result.
    pending_put: HashMap<QueryId, oneshot::Sender<Result<(), NetError>>>,
    /// Distinct peers seen entering the routing table (approximate liveness for
    /// `status`; never decremented — a coarse "have we joined?" signal).
    dht_peers: HashSet<PeerId>,
    /// Relay-server load counters (M5). **Aggregate only, by design**: this is
    /// the whole of what a Prism relay remembers about the traffic it carries —
    /// counts, never pairs, never per-peer entries, never persisted. See the
    /// non-retention note in the relay event handler.
    relay_reservations: usize,
    relay_circuits: usize,
    relay_circuits_total: u64,
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
        relays: Vec<Multiaddr>,
    ) -> Self {
        let reservations = relays.into_iter().map(RelayReservation::new).collect();
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
            reservations,
            pending_get: HashMap::new(),
            pending_put: HashMap::new(),
            dht_peers: HashSet::new(),
            relay_reservations: 0,
            relay_circuits: 0,
            relay_circuits_total: 0,
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

    /// Attempt any relay reservation that is due (M5).
    ///
    /// Called at startup and then on every retry tick. Listening on
    /// `<relay>/p2p-circuit` is what makes libp2p connect to the relay and ask
    /// for a reservation; the relay may refuse (its caps), the dial may not be
    /// possible yet, or the request may fail — none of which is fatal, and all of
    /// which are retried with backoff. Being unreachable inbound is not a state
    /// to accept silently.
    ///
    /// Reservations are requested whenever relays are configured, without waiting
    /// for AutoNAT: waiting would leave a NAT-bound node unreachable for the
    /// length of a probe, and a publicly-reachable node holding an unused
    /// reservation costs only that relay slot.
    fn poll_relay_reservations(&mut self) {
        let now = Instant::now();
        for index in 0..self.reservations.len() {
            if !self.reservations[index].is_due(now) {
                continue;
            }
            let addr = self.reservations[index].addr.clone();
            let circuit = addr.clone().with(Protocol::P2pCircuit);
            match self.swarm.listen_on(circuit) {
                Ok(listener) => {
                    debug!(relay = %addr, ?listener, "requesting a relay reservation");
                    let entry = &mut self.reservations[index];
                    entry.listener = Some(listener);
                    entry.next_attempt = None;
                }
                Err(e) => {
                    let entry = &mut self.reservations[index];
                    entry.attempts = entry.attempts.saturating_add(1);
                    let backoff = reservation_backoff(entry.attempts);
                    entry.next_attempt = Some(now + backoff);
                    warn!(
                        relay = %addr, error = %e, attempts = entry.attempts,
                        retry_in_secs = backoff.as_secs(),
                        "could not request a relay reservation; will retry"
                    );
                }
            }
        }
    }

    /// A reservation listener died (refused, expired, or the relay went away):
    /// schedule another attempt with backoff.
    fn on_reservation_lost(&mut self, listener: ListenerId, reason: &str) {
        let now = Instant::now();
        for entry in &mut self.reservations {
            if entry.listener != Some(listener) {
                continue;
            }
            entry.listener = None;
            entry.active = false;
            entry.attempts = entry.attempts.saturating_add(1);
            let backoff = reservation_backoff(entry.attempts);
            entry.next_attempt = Some(now + backoff);
            // Warn, not debug: losing a reservation makes this node unreachable
            // inbound, and the silence here is what made the field bug invisible.
            warn!(
                relay = %entry.addr, reason, attempts = entry.attempts,
                retry_in_secs = backoff.as_secs(),
                "relay reservation lost; will retry"
            );
        }
    }

    /// Circuit addresses we can use to reach a peer through our relays.
    ///
    /// Deliberately **not** filtered by our own reservation state: a reservation
    /// makes *us* reachable inbound, whereas dialling out through a relay needs a
    /// reservation held by the **target**, not by us. Requiring our own would
    /// wrongly refuse to dial a reachable peer whenever our reservation happened
    /// to be down.
    fn circuit_addrs_for(&self, peer_id: PeerId) -> Vec<Multiaddr> {
        self.reservations
            .iter()
            .map(|entry| {
                entry
                    .addr
                    .clone()
                    .with(Protocol::P2pCircuit)
                    .with(Protocol::P2p(peer_id))
            })
            .collect()
    }

    /// Run until the command channel closes (daemon shutdown).
    pub(crate) async fn run(mut self) {
        self.start_bootstrap();
        self.poll_relay_reservations();
        // Retry tick: cheap (a few comparisons) and the only thing that turns a
        // failed reservation into an eventually-successful one.
        let mut retry = tokio::time::interval(StdDuration::from_secs(1));
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = retry.tick() => self.poll_relay_reservations(),
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
                        path: entry.path,
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
        let peer_id = match self.by_key.get(key) {
            Some(entry) => entry.peer_id,
            // Never discovered, but its PeerId is derivable from the identity key
            // — enough to address a relay circuit, which is the only route to a
            // peer we have no direct address for.
            None => peer_id_from_key(key)?,
        };

        // Direct addresses first: a direct connection is cheaper, faster, and
        // involves no third party. Only when there is none do we fall back.
        let direct: Vec<Multiaddr> = self
            .by_key
            .get(key)
            .map(|entry| entry.addrs.clone())
            .unwrap_or_default();
        if !direct.is_empty() {
            return Some((peer_id, direct));
        }

        // Fallback: reach the peer through each configured relay, by addressing
        // `<relay>/p2p-circuit/p2p/<target>`. This is the automatic direct->relay
        // fallback — the caller does not choose, and the user needs no action.
        // Once the circuit is up, DCUtR tries to upgrade it to a direct
        // connection; if that succeeds the relay drops out of the path.
        let circuits = self.circuit_addrs_for(peer_id);
        if circuits.is_empty() {
            // No direct address and no relay: honestly unreachable.
            return None;
        }
        Some((peer_id, circuits))
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
            // DCUtR (M5): a hole-punch attempt finished. Success means the
            // relayed connection has been replaced by a direct one; the
            // ConnectionEstablished event that follows updates the reported path.
            SwarmEvent::Behaviour(PrismBehaviourEvent::Dcutr(dcutr::Event { result, .. })) => {
                debug!(punched = result.is_ok(), "DCUtR hole-punch attempt");
            }
            // Relay client (M5): reservation accepted/closed on a relay we use.
            // Peer ids of relays are public infrastructure metadata, not user
            // data, so they are debug-loggable.
            SwarmEvent::Behaviour(PrismBehaviourEvent::RelayClient(event)) => {
                debug!(?event, "relay client event");
            }
            SwarmEvent::Behaviour(PrismBehaviourEvent::AutonatServer(_)) => {}
            // Relay server (M5). **Non-retention lives here, as an absence**:
            // these events carry the peer ids on both ends of a circuit, and we
            // deliberately keep only *aggregate counters* — never a pair, never a
            // per-peer entry, never anything written to disk. The counters exist
            // so an operator can see load; they identify nobody.
            //
            // Nothing is logged at info level either: a log line naming both ends
            // would be exactly the routing record we promise not to keep.
            SwarmEvent::Behaviour(PrismBehaviourEvent::RelayServer(event)) => match event {
                relay::Event::ReservationReqAccepted { .. } => {
                    self.relay_reservations = self.relay_reservations.saturating_add(1);
                }
                relay::Event::ReservationClosed { .. }
                | relay::Event::ReservationTimedOut { .. } => {
                    self.relay_reservations = self.relay_reservations.saturating_sub(1);
                }
                relay::Event::CircuitReqAccepted { .. } => {
                    self.relay_circuits = self.relay_circuits.saturating_add(1);
                    self.relay_circuits_total = self.relay_circuits_total.saturating_add(1);
                }
                relay::Event::CircuitClosed { .. } => {
                    self.relay_circuits = self.relay_circuits.saturating_sub(1);
                }
                _ => {}
            },
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
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let path = path_of(endpoint.get_remote_address());
                if let Some(key) = peer_key_from_id(&peer_id) {
                    // A connection without prior discovery (an inbound dial):
                    // `source` is only applied if this is the first sighting;
                    // an already-discovered peer keeps its mDNS/DHT source.
                    self.upsert_peer(key, Some(peer_id), None, DiscoverySource::Manual);
                    if let Some(entry) = self.by_key.get_mut(&key) {
                        entry.connected = true;
                        // A DCUtR upgrade replaces a relayed connection with a
                        // direct one, so the newest connection decides the path.
                        entry.path = Some(path);
                    }
                    debug!(?path, "connection established");
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                if let Some(key) = self.by_id.get(&peer_id).copied() {
                    if let Some(entry) = self.by_key.get_mut(&key) {
                        entry.connected = false;
                        entry.path = None;
                    }
                }
            }
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } => {
                // A circuit address appearing is the *only* proof a relay actually
                // granted the reservation — a live listener alone is not.
                if address.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
                    for entry in &mut self.reservations {
                        if entry.listener == Some(listener_id) {
                            entry.active = true;
                            entry.attempts = 0;
                            entry.next_attempt = None;
                            debug!(relay = %entry.addr, %address, "relay reservation active");
                        }
                    }
                }
                if !self.listen_addrs.contains(&address) {
                    self.listen_addrs.push(address);
                }
            }
            // A listener died. Two things must happen, neither of which used to:
            // its addresses must stop being advertised (a dead circuit address in
            // our published DHT locator would send peers down a route that no
            // longer exists), and a reservation listener must be re-attempted.
            SwarmEvent::ListenerClosed {
                listener_id,
                addresses,
                reason,
            } => {
                let reason = match &reason {
                    Ok(()) => "closed".to_owned(),
                    Err(e) => e.to_string(),
                };
                self.listen_addrs.retain(|a| !addresses.contains(a));
                self.on_reservation_lost(listener_id, &reason);
                debug!(?addresses, reason, "listener closed");
            }
            // One address of a still-live listener went away.
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                self.listen_addrs.retain(|a| a != &address);
                debug!(%address, "listen address expired");
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
            // Discovery alone opens no connection, so there is no path yet;
            // ConnectionEstablished fills it in.
            path: None,
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
