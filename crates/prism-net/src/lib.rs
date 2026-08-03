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

use libp2p::kad::store::MemoryStore;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{
    autonat, identify, kad, mdns, noise, request_response, tcp, yamux, Multiaddr, PeerId,
    StreamProtocol, SwarmBuilder,
};
use prism_core::Seed32;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

pub use identity::PeerKey;

use behaviour::PrismBehaviour;
use protocol::{WireRequest, WireResponse, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PROTOCOL_ID};

/// Kademlia protocol id — Prism-specific, so nodes never join the public IPFS
/// DHT or mix records with unrelated networks. Carries the DHT wire version.
const KAD_PROTOCOL: StreamProtocol = StreamProtocol::new("/prism/kad/1.0.0");

/// identify protocol id — Prism-specific, so we only exchange peer metadata
/// within this network. Versioned like the other Prism protocols.
const IDENTIFY_PROTOCOL: &str = "/prism/id/1.0.0";

/// Agent string broadcast by identify. Deliberately **coarse** — no build
/// version — since it reaches every peer we meet and an exact version would help
/// target known-vulnerable builds.
const AGENT_VERSION: &str = "prism";
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
    /// A DHT operation was requested but the DHT is disabled on this node.
    #[error("the DHT is disabled on this node")]
    DhtDisabled,
    /// A DHT bootstrap was requested but no bootstrap peers are known.
    #[error("no bootstrap peers are configured")]
    NoBootstrapPeers,
    /// The swarm task is no longer running.
    #[error("the network task is not running")]
    Offline,
}

/// How a peer was discovered. Public, non-secret metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Local-network mDNS multicast.
    Mdns,
    /// The Kademlia DHT (a resolved signed locator).
    Dht,
    /// Seeded out of band (an explicit address hint).
    Manual,
}

/// A snapshot of the DHT's local state, for `status`.
#[derive(Debug, Clone)]
pub struct DhtStatus {
    /// Whether the DHT is enabled on this node.
    pub enabled: bool,
    /// Distinct peers seen entering the routing table (approximate liveness).
    pub routing_peers: usize,
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

    /// Validate an inbound DHT locator record — its DHT key and opaque value —
    /// before it is stored on behalf of the network. Returns `true` to store.
    ///
    /// prism-net holds no application crypto: the daemon's implementation calls
    /// `prism_core::open_locator` (verify signature, strict key validation,
    /// key/fingerprint binding, size bounds). Unlike [`deliver`](Self::deliver),
    /// this is **synchronous** — locator validation is a fast, pure function (a
    /// signature check), so it needs no cross-thread offload and cannot stall
    /// the swarm poll loop the way a ratchet decrypt + disk write could.
    fn validate_locator(&self, key: &[u8], value: &[u8]) -> bool;
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
    /// How this peer was discovered.
    pub source: DiscoverySource,
}

/// Configuration for the networking subsystem, chosen by the daemon from CLI
/// flags / the config file. Defaults: both discovery mechanisms on, no
/// bootstrap peers, no advertised external address (a home client).
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// Run mDNS LAN discovery (disable on WAN-exposed/headless nodes).
    pub enable_mdns: bool,
    /// Participate in the Kademlia DHT (off-LAN discovery).
    pub enable_dht: bool,
    /// Bootstrap-node multiaddrs, each including a trailing `/p2p/<peer-id>`.
    /// Empty by default — no hard-coded entry points ship in the binary.
    pub bootstrap: Vec<String>,
    /// Globally-routable multiaddrs to advertise as ours (a public/VPS node
    /// knows its own address; a NAT-bound node leaves this empty in M4).
    ///
    /// Since M5 this is a *declaration*, not the only source: AutoNAT can
    /// confirm an address discovered via identify, and a node that declares one
    /// here also runs the AutoNAT **server** side (it is asserting it is
    /// publicly reachable, so it can dial others back).
    pub external_addrs: Vec<String>,
    /// Run NAT traversal (M5): AutoNAT reachability detection, and — once wired
    /// in the following commits — DCUtR hole punching and relay clients. On by
    /// default; disabling it leaves a node with direct connectivity only.
    pub enable_nat_traversal: bool,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            enable_mdns: true,
            enable_dht: true,
            bootstrap: Vec::new(),
            external_addrs: Vec::new(),
            enable_nat_traversal: true,
        }
    }
}

/// What AutoNAT has concluded about our reachability from outside. Public,
/// non-secret metadata.
///
/// Deliberately three-valued: "we have not found out yet" is a distinct and
/// honest answer, and must not be reported as "reachable" or "behind a NAT".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    /// No probe has completed yet (or NAT traversal is disabled).
    Unknown,
    /// At least one of our addresses was dialled back successfully.
    Public,
    /// Every address probed so far failed — we are behind a NAT or firewall.
    Private,
}

/// A snapshot of our own reachability, for `status`.
#[derive(Debug, Clone)]
pub struct NatStatus {
    /// The current verdict.
    pub reachability: Reachability,
    /// Addresses AutoNAT confirmed dialable from outside (public metadata).
    pub confirmed_addrs: Vec<String>,
    /// How many address probes have completed (0 ⇒ the verdict is `Unknown`).
    pub probes: usize,
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
        self.send(Command::AddPeerAddress {
            key,
            addr,
            source: DiscoverySource::Manual,
        })
        .await
    }

    /// Seed a peer's address learned from a validated DHT locator, tagging it as
    /// DHT-discovered so `peers`/the TUI can distinguish it from mDNS.
    pub async fn add_dht_peer_address(&self, key: PeerKey, addr: String) -> Result<(), NetError> {
        self.send(Command::AddPeerAddress {
            key,
            addr,
            source: DiscoverySource::Dht,
        })
        .await
    }

    /// Publish our signed locator record to the DHT under `key`. The `value`
    /// is opaque, signed bytes produced by `prism-core`; prism-net never builds
    /// or inspects it.
    pub async fn publish_locator(&self, key: [u8; 32], value: Vec<u8>) -> Result<(), NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::PublishLocator {
            key: key.to_vec(),
            value,
            reply,
        })
        .await?;
        rx.await.map_err(|_| NetError::Offline)?
    }

    /// Resolve a peer's locator from the DHT by its record key. Returns the
    /// opaque record bytes (for `prism-core` to validate) or `None` if the DHT
    /// query completed without finding a record.
    pub async fn resolve_locator(&self, key: [u8; 32]) -> Result<Option<Vec<u8>>, NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::ResolveLocator {
            key: key.to_vec(),
            reply,
        })
        .await?;
        rx.await.map_err(|_| NetError::Offline)?
    }

    /// Trigger a Kademlia bootstrap (populate the routing table via the
    /// configured bootstrap peers). Errors if the DHT is disabled or no
    /// bootstrap peers are known.
    pub async fn bootstrap(&self) -> Result<(), NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Bootstrap { reply }).await?;
        rx.await.map_err(|_| NetError::Offline)?
    }

    /// Snapshot the DHT's local state (for `status`).
    /// Snapshot our own reachability as AutoNAT sees it (M5). Public metadata.
    pub async fn nat_status(&self) -> Result<NatStatus, NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::NatStatus { reply }).await?;
        rx.await.map_err(|_| NetError::Offline)
    }

    pub async fn dht_status(&self) -> Result<DhtStatus, NetError> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::DhtStatus { reply }).await?;
        rx.await.map_err(|_| NetError::Offline)
    }

    /// Advertise a globally-routable address as ours (post-spawn). Confirms it
    /// to the swarm, upgrading Kademlia to server mode so this node serves and
    /// stores records for the network.
    pub async fn add_external_address(&self, addr: String) -> Result<(), NetError> {
        self.send(Command::AddExternalAddress { addr }).await
    }

    async fn send(&self, cmd: Command) -> Result<(), NetError> {
        self.cmd_tx.send(cmd).await.map_err(|_| NetError::Offline)
    }
}

/// Build the composed behaviour (mDNS + Kademlia + CBOR request-response), each
/// discovery mechanism toggled by `config`. Called by the swarm builder with
/// the transport keypair.
fn build_behaviour(
    keypair: &libp2p::identity::Keypair,
    config: &NetConfig,
) -> Result<PrismBehaviour, Box<dyn std::error::Error + Send + Sync>> {
    let local_peer_id = keypair.public().to_peer_id();

    let mdns = if config.enable_mdns {
        Toggle::from(Some(mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            local_peer_id,
        )?))
    } else {
        Toggle::from(None)
    };

    let kad = if config.enable_dht {
        let store = MemoryStore::new(local_peer_id);
        let mut cfg = kad::Config::new(KAD_PROTOCOL);
        // Never auto-store: every incoming record is validated first (delegated
        // to prism-core via InboundSink::validate_locator). This is the M4
        // "strict validation on ingestion" hardening.
        cfg.set_record_filtering(kad::StoreInserts::FilterBoth);
        cfg.set_query_timeout(Duration::from_secs(60));
        let mut behaviour = kad::Behaviour::with_config(local_peer_id, store, cfg);
        // A node that advertises a globally-routable address serves records
        // (helping hold the DHT); a NAT-bound node stays a client.
        if !config.external_addrs.is_empty() {
            behaviour.set_mode(Some(kad::Mode::Server));
        }
        Toggle::from(Some(behaviour))
    } else {
        Toggle::from(None)
    };

    // identify (M5): always on. Peers report the address they observe for us,
    // which is the only source of external-address candidates for AutoNAT, and
    // DCUtR/relay reservations rest on the same address knowledge.
    //
    // `agent_version` is deliberately coarse ("prism", no build version): it is
    // broadcast to every peer we meet, and advertising an exact build would help
    // an attacker target known-vulnerable versions. It is not our version
    // negotiation mechanism — that stays multistream-select inside Noise.
    let identify = identify::Behaviour::new(
        identify::Config::new(IDENTIFY_PROTOCOL.to_owned(), keypair.public())
            .with_agent_version(AGENT_VERSION.to_owned()),
    );

    // AutoNAT v2 client: verifies candidate addresses via dial-backs.
    let autonat = if config.enable_nat_traversal {
        Toggle::from(Some(autonat::v2::client::Behaviour::default()))
    } else {
        Toggle::from(None)
    };

    // AutoNAT v2 server: only a node declaring itself publicly reachable can
    // usefully dial others back, so this follows `external_addrs` (the same rule
    // that puts Kademlia into server mode).
    let autonat_server = if !config.external_addrs.is_empty() {
        Toggle::from(Some(autonat::v2::server::Behaviour::default()))
    } else {
        Toggle::from(None)
    };

    let codec = request_response::cbor::codec::Codec::<WireRequest, WireResponse>::default()
        .set_request_size_maximum(MAX_REQUEST_BYTES)
        .set_response_size_maximum(MAX_RESPONSE_BYTES);
    let rr = request_response::Behaviour::with_codec(
        codec,
        [(PROTOCOL_ID, request_response::ProtocolSupport::Full)],
        request_response::Config::default().with_request_timeout(Duration::from_secs(20)),
    );
    Ok(PrismBehaviour {
        mdns,
        kad,
        rr,
        identify,
        autonat,
        autonat_server,
    })
}

/// Derive a QUIC listen address from a TCP one: `/ip4/A/tcp/P` becomes
/// `/ip4/A/udp/P/quic-v1`, keeping the interface and the port *number* (TCP and
/// UDP ports are separate namespaces, so reusing the number is both legal and
/// what an operator opening a firewall expects).
///
/// Returns `None` when the input is not a plain IP+TCP address — including when
/// it is already a QUIC address — so the caller simply does not add a second
/// listener. Only the address family and port are read; nothing else is assumed.
fn quic_listen_addr(tcp: &Multiaddr) -> Option<Multiaddr> {
    let mut ip = None;
    let mut port = None;
    for proto in tcp.iter() {
        match proto {
            Protocol::Ip4(_) | Protocol::Ip6(_) => ip = Some(proto),
            Protocol::Tcp(p) => port = Some(p),
            // Anything else (already QUIC, a circuit address, /dns/, …) is not
            // a plain TCP listener: do not guess.
            _ => return None,
        }
    }
    let mut quic = Multiaddr::empty();
    quic.push(ip?);
    quic.push(Protocol::Udp(port?));
    quic.push(Protocol::QuicV1);
    Some(quic)
}

/// Parse a bootstrap multiaddr string into `(peer id, transport address)`.
/// The entry must carry a trailing `/p2p/<peer-id>`; the returned address has
/// that component stripped (Kademlia wants the peer id and transport address
/// separately). Returns `None` for an unparseable or peer-id-less entry.
fn parse_bootstrap(entry: &str) -> Option<(PeerId, Multiaddr)> {
    let addr: Multiaddr = entry.parse().ok()?;
    let peer = addr.iter().find_map(|proto| match proto {
        Protocol::P2p(peer_id) => Some(peer_id),
        _ => None,
    })?;
    let transport: Multiaddr = addr
        .iter()
        .filter(|proto| !matches!(proto, Protocol::P2p(_)))
        .collect();
    Some((peer, transport))
}

/// Start the networking subsystem for `seed`, listening on `listen` (a
/// multiaddr string, e.g. `/ip4/0.0.0.0/tcp/0`), with `config` (discovery
/// toggles, bootstrap peers, advertised addresses). Returns a handle plus the
/// task's join handle; dropping the handle stops the task.
///
/// The seed is used **only** to build the Noise transport keypair (see
/// [`identity`]) and is not retained.
pub fn spawn(
    seed: &Seed32,
    sink: Arc<dyn InboundSink>,
    listen: &str,
    config: NetConfig,
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
        // QUIC (M5): UDP hole punching succeeds materially more often than TCP
        // simultaneous-open, so QUIC carries the NAT-traversal case. QUIC is
        // TLS 1.3-encrypted (libp2p's audited implementation, PeerId bound into
        // the certificate) rather than Noise — see docs/net.md.
        .with_quic()
        .with_behaviour(|kp| build_behaviour(kp, &config))
        .map_err(|e| NetError::Build(e.to_string()))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // TCP is required: a failure here is fatal.
    swarm
        .listen_on(listen_addr.clone())
        .map_err(|e| NetError::Build(e.to_string()))?;

    // QUIC is best-effort: derived from the TCP listen address (same interface,
    // same port number — TCP/4001 pairs with UDP/4001, which is what an operator
    // expects to open). A node whose UDP is blocked must still work over TCP, so
    // a QUIC bind failure is logged and tolerated, never fatal.
    if let Some(quic_addr) = quic_listen_addr(&listen_addr) {
        if let Err(e) = swarm.listen_on(quic_addr) {
            warn!(error = %e, "QUIC listener unavailable; continuing with TCP only");
        }
    }

    // Advertise configured globally-routable addresses (a public/VPS node knows
    // its own; a NAT-bound node advertises none in M4).
    for ext in &config.external_addrs {
        match ext.parse::<Multiaddr>() {
            Ok(addr) => swarm.add_external_address(addr),
            Err(_) => warn!("ignoring unparseable external address"),
        }
    }

    // The swarm task adds these to Kademlia and bootstraps on startup.
    let bootstrap: Vec<(PeerId, Multiaddr)> = config
        .bootstrap
        .iter()
        .filter_map(|entry| {
            let parsed = parse_bootstrap(entry);
            if parsed.is_none() {
                warn!("ignoring unparseable or peer-id-less bootstrap address");
            }
            parsed
        })
        .collect();

    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let join =
        tokio::spawn(SwarmTask::new(swarm, sink, cmd_rx, config.enable_dht, bootstrap).run());

    Ok((
        NetHandle {
            cmd_tx,
            local_key,
            local_peer_id: local_peer_id.to_base58(),
        },
        join,
    ))
}

/// Filter multiaddr strings down to the **globally-routable** ones — dropping
/// loopback, private (RFC 1918), link-local, CGNAT (100.64/10), and other
/// non-public IPs — so only addresses safe to publish to the public DHT
/// remain (spec §13 IP hygiene). Unparseable or IP-less addresses are dropped
/// (conservative: never publish something we cannot classify as public).
///
/// This lives in prism-net because it owns multiaddr semantics; the daemon
/// calls it before asking `prism-core` to seal a locator, so private/LAN
/// addresses never reach the DHT.
pub fn public_addrs(addrs: &[String]) -> Vec<String> {
    addrs
        .iter()
        .filter(|a| is_globally_routable(a))
        .cloned()
        .collect()
}

/// The libp2p peer id (base58) for a peer's Ed25519 identity key, for display.
///
/// `None` if the key is not a valid Ed25519 point — which cannot happen for a
/// key that has already passed locator validation, but is surfaced honestly
/// rather than panicking. The daemon uses this to show the peer id of a peer
/// resolved from the DHT (it has the key, but no live connection yet).
pub fn peer_id_for(key: &PeerKey) -> Option<String> {
    crate::identity::peer_id_from_key(key).map(|id| id.to_string())
}

/// Whether a multiaddr string carries a globally-routable IP.
fn is_globally_routable(addr: &str) -> bool {
    let Ok(ma) = addr.parse::<Multiaddr>() else {
        return false;
    };
    for proto in ma.iter() {
        match proto {
            Protocol::Ip4(ip) => return is_global_v4(ip),
            Protocol::Ip6(ip) => return is_global_v6(ip),
            // A hostname is presumed publicly resolvable/reachable.
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) => return true,
            _ => {}
        }
    }
    false
}

/// Globally-routable IPv4: excludes private/loopback/link-local/CGNAT/etc.
/// (`Ipv4Addr::is_global` is still unstable, so the checks are explicit.)
fn is_global_v4(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    let is_cgnat = o[0] == 100 && (64..=127).contains(&o[1]); // 100.64.0.0/10
    let is_shared_benchmark = o[0] == 198 && (o[1] == 18 || o[1] == 19); // 198.18/15
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || o[0] == 0
        || is_cgnat
        || is_shared_benchmark)
}

/// Globally-routable IPv6: excludes loopback/unspecified/unique-local/link-local.
fn is_global_v6(ip: std::net::Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_loopback()
        || ip.is_unspecified()
        || (first & 0xfe00) == 0xfc00  // unique local fc00::/7
        || (first & 0xffc0) == 0xfe80) // link local  fe80::/10
}

/// Assert at compile time that the derived behaviour is a `NetworkBehaviour`.
const _: fn() = || {
    fn is_behaviour<T: NetworkBehaviour>() {}
    let _ = is_behaviour::<PrismBehaviour>;
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_listen_addr_mirrors_the_tcp_listener() {
        let cases = [
            (
                "/ip4/0.0.0.0/tcp/4001",
                Some("/ip4/0.0.0.0/udp/4001/quic-v1"),
            ),
            ("/ip4/0.0.0.0/tcp/0", Some("/ip4/0.0.0.0/udp/0/quic-v1")),
            (
                "/ip4/203.0.113.9/tcp/4001",
                Some("/ip4/203.0.113.9/udp/4001/quic-v1"),
            ),
            ("/ip6/::/tcp/4001", Some("/ip6/::/udp/4001/quic-v1")),
            // Already QUIC, or not a plain TCP listener: do not guess.
            ("/ip4/0.0.0.0/udp/4001/quic-v1", None),
            ("/ip4/0.0.0.0/tcp/4001/p2p-circuit", None),
            ("/ip4/0.0.0.0/tcp/4001/ws", None),
        ];
        for (input, expected) in cases {
            let parsed: Multiaddr = match input.parse() {
                Ok(a) => a,
                Err(_) => panic!("test input must parse: {input}"),
            };
            let got = quic_listen_addr(&parsed).map(|a| a.to_string());
            assert_eq!(got.as_deref(), expected, "for {input}");
        }
    }

    #[test]
    fn public_addrs_keeps_only_globally_routable() {
        let addrs: Vec<String> = [
            "/ip4/198.51.100.7/tcp/4001",    // documentation (TEST-NET-2) -> dropped
            "/ip4/8.8.8.8/tcp/4001",         // public
            "/ip4/127.0.0.1/tcp/4001",       // loopback
            "/ip4/192.168.1.5/tcp/4001",     // private
            "/ip4/10.0.0.9/tcp/4001",        // private
            "/ip4/172.16.3.4/tcp/4001",      // private
            "/ip4/169.254.1.1/tcp/4001",     // link-local
            "/ip4/100.100.0.1/tcp/4001",     // CGNAT
            "/ip6/::1/tcp/4001",             // loopback v6
            "/ip6/fe80::1/tcp/4001",         // link-local v6
            "/ip6/fc00::1/tcp/4001",         // unique-local v6
            "/ip6/2606:4700::1111/tcp/4001", // public v6
            "not-a-multiaddr",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();

        let kept = public_addrs(&addrs);
        assert_eq!(
            kept,
            vec![
                "/ip4/8.8.8.8/tcp/4001".to_owned(),
                "/ip6/2606:4700::1111/tcp/4001".to_owned(),
            ],
            "only the two public addresses survive"
        );
    }

    #[test]
    fn parse_bootstrap_requires_a_peer_id() {
        assert!(parse_bootstrap("/ip4/1.2.3.4/tcp/4001").is_none());
        let with_peer =
            "/ip4/1.2.3.4/tcp/4001/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp";
        let parsed = parse_bootstrap(with_peer);
        assert!(parsed.is_some());
        let (_, transport) = parsed.unwrap();
        // The /p2p/ component is stripped from the transport address.
        assert_eq!(transport.to_string(), "/ip4/1.2.3.4/tcp/4001");
    }
}
