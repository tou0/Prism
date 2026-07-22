// SPDX-License-Identifier: AGPL-3.0-or-later
//! `prism-net` — the Prism libp2p networking layer (milestone M2b).
//!
//! prism-net moves **opaque bytes between authenticated peers** on the local
//! network (mDNS discovery, TCP + Noise + Yamux, a CBOR request/response
//! protocol). It performs **no application cryptography**: prekey bundles and
//! sealed messages are produced and validated exclusively by `prism-core`, and
//! this layer never parses them, never validates keys, never runs the ratchet,
//! and never sees plaintext.
//!
//! The one unavoidable contact with a key is the **Noise transport keypair**,
//! which spec §6 mandates be the same Ed25519 key as the application identity
//! (so the libp2p `PeerId` binds to the Prism identity). That single, narrow
//! exception is confined to [`identity`] and documented in `docs/net.md`.
//!
//! The daemon owns the [`NetHandle`] (to issue commands) and provides an
//! [`InboundSink`] (the core session thread) that decrypts and
//! identity-verifies inbound messages. See `crates/prism-daemon` for the task
//! wiring and the persist-before-transmit ordering.

mod behaviour;
mod identity;
mod protocol;
mod swarm;

use std::sync::Arc;
use std::time::Duration;

use libp2p::swarm::NetworkBehaviour;
use libp2p::{mdns, noise, request_response, tcp, yamux, Multiaddr, SwarmBuilder};
use prism_core::Seed32;
use tokio::sync::{mpsc, oneshot};

pub use identity::PeerKey;

use behaviour::PrismBehaviour;
use protocol::{WireRequest, WireResponse, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PROTOCOL_ID};
use swarm::{Command, SwarmTask};

/// Errors surfaced by the networking layer. No variant carries key or secret
/// material (peer ids and addresses are public).
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// The libp2p transport or swarm could not be constructed.
    #[error("failed to build the network transport: {0}")]
    Build(String),
    /// The listen address string was not a valid multiaddr.
    #[error("invalid listen address")]
    BadListenAddr,
    /// The identity seed could not be turned into a Noise keypair.
    #[error("could not derive the transport key from the identity")]
    KeyDecode,
    /// No discovered, addressable route to the peer (offline / not on the LAN).
    /// Nothing is queued — the caller decides whether to retry.
    #[error("peer not reachable")]
    PeerNotReachable,
    /// The remote refused or failed the request (timeout, protocol error, …).
    #[error("network request failed: {0}")]
    RequestFailed(String),
    /// The swarm task is no longer running.
    #[error("the network task is not running")]
    Offline,
}

/// The verdict the core session thread returns for an inbound delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundOutcome {
    /// Decrypted and identity-verified; the peer receives an ack.
    Accepted,
    /// Rejected (bad identity, undecryptable, or the core queue was full).
    Rejected,
}

/// Sink for inbound message deliveries. Implemented by the daemon over a
/// channel to the core session thread.
///
/// [`deliver`](InboundSink::deliver) **must not block**: it hands the sealed
/// bytes off and returns immediately, resolving `reply` later with the
/// verdict. This is what keeps a slow core disk-write from stalling the swarm.
pub trait InboundSink: Send + Sync + 'static {
    /// Hand a Noise-authenticated peer's sealed message to the core thread.
    fn deliver(&self, from: PeerKey, sealed: Vec<u8>, reply: oneshot::Sender<InboundOutcome>);
}

/// A discovered peer. All fields are public metadata.
#[derive(Debug, Clone)]
pub struct PeerRecord {
    /// The peer's Ed25519 public key (its identity and transport key).
    pub key: PeerKey,
    /// The libp2p peer id, base58 (for display/logs).
    pub peer_id: String,
    /// Known multiaddresses (as strings; the daemon needs no libp2p types).
    pub addrs: Vec<String>,
    /// Whether a connection is currently open.
    pub connected: bool,
}

/// Handle the daemon uses to drive the swarm task. Cloneable.
#[derive(Clone)]
pub struct NetHandle {
    cmd_tx: mpsc::Sender<Command>,
    local_key: PeerKey,
    local_peer_id: String,
}

impl NetHandle {
    /// Our own transport/identity public key.
    pub fn local_key(&self) -> PeerKey {
        self.local_key
    }

    /// Our own libp2p peer id, base58.
    pub fn local_peer_id(&self) -> &str {
        &self.local_peer_id
    }

    /// Snapshot the discovered-peer table.
    pub async fn peers(&self) -> Result<Vec<PeerRecord>, NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Peers { reply }).await?;
        rx.await.map_err(|_| NetError::Offline)
    }

    /// Fetch a peer's signed prekey bundle (opaque bytes for `prism-core`).
    pub async fn fetch_bundle(&self, key: PeerKey) -> Result<Vec<u8>, NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::FetchBundle { key, reply }).await?;
        rx.await.map_err(|_| NetError::Offline)?
    }

    /// Deliver a sealed message to a peer and await its ack.
    pub async fn deliver(&self, key: PeerKey, sealed: Vec<u8>) -> Result<(), NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Deliver { key, sealed, reply }).await?;
        rx.await.map_err(|_| NetError::Offline)?
    }

    /// Snapshot our own bound listen addresses (for status).
    pub async fn listeners(&self) -> Result<Vec<String>, NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Listeners { reply }).await?;
        rx.await.map_err(|_| NetError::Offline)
    }

    /// Update the bundle served to peers that request one.
    pub async fn set_bundle(&self, bundle: Vec<u8>) -> Result<(), NetError> {
        self.send(Command::SetBundle { bundle }).await
    }

    /// Seed a peer address out-of-band (mDNS remains automatic discovery).
    pub async fn add_peer_address(&self, key: PeerKey, addr: String) -> Result<(), NetError> {
        self.send(Command::AddPeerAddress { key, addr }).await
    }

    async fn send(&self, cmd: Command) -> Result<(), NetError> {
        self.cmd_tx.send(cmd).await.map_err(|_| NetError::Offline)
    }
}

/// Build the composed behaviour (mDNS + CBOR request-response with bounded
/// sizes). Called by the swarm builder with the transport keypair.
fn build_behaviour(
    keypair: &libp2p::identity::Keypair,
) -> Result<PrismBehaviour, Box<dyn std::error::Error + Send + Sync>> {
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), keypair.public().to_peer_id())?;
    let codec = request_response::cbor::codec::Codec::<WireRequest, WireResponse>::default()
        .set_request_size_maximum(MAX_REQUEST_BYTES)
        .set_response_size_maximum(MAX_RESPONSE_BYTES);
    let rr = request_response::Behaviour::with_codec(
        codec,
        [(PROTOCOL_ID, request_response::ProtocolSupport::Full)],
        request_response::Config::default().with_request_timeout(Duration::from_secs(20)),
    );
    Ok(PrismBehaviour { mdns, rr })
}

/// Start the networking subsystem for `seed`, listening on `listen` (a
/// multiaddr string, e.g. `/ip4/0.0.0.0/tcp/0`). Returns a handle plus the
/// task's join handle; dropping the handle stops the task.
///
/// The seed is used **only** to build the Noise transport keypair (see
/// [`identity`]) and is not retained.
pub fn spawn(
    seed: &Seed32,
    sink: Arc<dyn InboundSink>,
    listen: &str,
) -> Result<(NetHandle, tokio::task::JoinHandle<()>), NetError> {
    let keypair = identity::keypair_from_seed(seed)?;
    let local_peer_id = keypair.public().to_peer_id();
    let local_key = identity::peer_key_from_id(&local_peer_id).ok_or(NetError::KeyDecode)?;
    let listen_addr: Multiaddr = listen.parse().map_err(|_| NetError::BadListenAddr)?;

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| NetError::Build(e.to_string()))?
        .with_behaviour(build_behaviour)
        .map_err(|e| NetError::Build(e.to_string()))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    swarm
        .listen_on(listen_addr)
        .map_err(|e| NetError::Build(e.to_string()))?;

    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let join = tokio::spawn(SwarmTask::new(swarm, sink, cmd_rx).run());

    Ok((
        NetHandle {
            cmd_tx,
            local_key,
            local_peer_id: local_peer_id.to_base58(),
        },
        join,
    ))
}

/// Assert at compile time that the derived behaviour is a `NetworkBehaviour`.
const _: fn() = || {
    fn is_behaviour<T: NetworkBehaviour>() {}
    let _ = is_behaviour::<PrismBehaviour>;
};
