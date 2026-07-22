// SPDX-License-Identifier: AGPL-3.0-or-later
//! The swarm task: the single owner of the libp2p `Swarm`.
//!
//! It polls the swarm continuously, maintains the mDNS-discovered peer table,
//! serves inbound bundle fetches from a cached copy, and hands inbound message
//! deliveries to the [`InboundSink`] (the core session thread) **without ever
//! blocking its own poll loop** — so a slow disk write in the core thread can
//! never stall discovery or in-flight requests (the deadlock-prevention
//! invariant). Outbound commands arrive over a channel from the daemon.

use std::collections::HashMap;

use futures::stream::{FuturesUnordered, StreamExt};
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
use crate::{InboundSink, NetError, PeerRecord};

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
    /// automatic discovery mechanism). Used for deterministic tests and a
    /// future designated-peer feature.
    AddPeerAddress { key: PeerKey, addr: String },
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
}

impl SwarmTask {
    pub(crate) fn new(
        swarm: Swarm<PrismBehaviour>,
        sink: std::sync::Arc<dyn InboundSink>,
        cmd_rx: mpsc::Receiver<Command>,
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
        }
    }

    /// Run until the command channel closes (daemon shutdown).
    pub(crate) async fn run(mut self) {
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
            Command::AddPeerAddress { key, addr } => match addr.parse::<Multiaddr>() {
                Ok(addr) => self.upsert_peer(key, peer_id_from_key(&key), Some(addr)),
                Err(_) => warn!("ignoring unparseable peer address hint"),
            },
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
                        self.upsert_peer(key, Some(peer_id), Some(addr));
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
                    self.upsert_peer(key, Some(peer_id), None);
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
            SwarmEvent::NewListenAddr { address, .. } => {
                if !self.listen_addrs.contains(&address) {
                    self.listen_addrs.push(address);
                }
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

    /// Insert or update a peer entry, adding a `PeerId` and/or address.
    fn upsert_peer(&mut self, key: PeerKey, peer_id: Option<PeerId>, addr: Option<Multiaddr>) {
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
        });
        entry.peer_id = peer_id;
        if let Some(addr) = addr {
            if !entry.addrs.contains(&addr) {
                entry.addrs.push(addr);
            }
        }
    }
}
