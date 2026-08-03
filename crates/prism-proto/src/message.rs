// SPDX-License-Identifier: AGPL-3.0-or-later
//! IPC message types exchanged between the client and the daemon.

use serde::{Deserialize, Serialize};

use crate::sensitive::Sensitive;

/// Version of the IPC protocol spoken by this build.
///
/// Every message is wrapped in a versioned [`Envelope`]. This is the local
/// IPC slice of the "every message carries a version" rule; authenticated
/// version negotiation on the *network* handshake arrives with a later
/// networking milestone.
///
/// Bumped to `2` for M3: the subscription/push contract ([`Request::Subscribe`],
/// [`Response::Subscribed`], [`Response::Event`]) is a real addition to the
/// client↔daemon protocol. The daemon rejects mismatched versions; a richer
/// compatibility window is deferred with the rest of version negotiation.
///
/// Bumped to `4` for M5 (NAT traversal + relays): [`PeerInfo::path`] (direct vs
/// relayed) and the reachability/relay fields on [`Response::Status`].
///
/// Bumped to `3` for M4 (DHT discovery): [`Request::Resolve`] /
/// [`Response::Resolved`], the DHT fields on [`Response::Status`], and the
/// discovery [`PeerSource`] on [`PeerInfo`]. Client and daemon ship from the
/// same build, so the strict version match is not a compatibility concern here.
pub const PROTOCOL_VERSION: u16 = 4;

/// The user's choice of recovery mode at identity creation (spec §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryMode {
    /// No recovery phrase: nothing exists outside the user's head to reveal
    /// under coercion. The default.
    None,
    /// Opt-in recovery phrase: a mnemonic is generated and returned once.
    Phrase,
}

/// A request sent by the client to the daemon.
///
/// Deliberately **no `Clone` / `PartialEq`**: several variants carry secrets
/// ([`Sensitive`]), which must not be duplicable or comparable.
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// Liveness check: expects a [`Response::Pong`].
    Ping,
    /// Create a new identity: generate keys daemon-side, seal the keystore,
    /// and unlock it. Expects [`Response::Created`].
    Init {
        /// The chosen nickname.
        nick: String,
        /// The keystore passphrase.
        passphrase: Sensitive,
        /// Whether to generate an opt-in recovery phrase.
        recovery: RecoveryMode,
        /// Overwrite an existing keystore (destructive; the CLI confirms).
        force: bool,
    },
    /// Recreate an identity from a recovery phrase (deterministic: the same
    /// phrase yields the same identity). Expects [`Response::Created`].
    Restore {
        /// The chosen nickname (need not match the original).
        nick: String,
        /// The keystore passphrase for the recreated keystore.
        passphrase: Sensitive,
        /// The BIP-39 recovery phrase.
        mnemonic: Sensitive,
        /// Overwrite an existing keystore (destructive; the CLI confirms).
        force: bool,
    },
    /// Unlock the keystore, loading the identity into daemon RAM. Expects
    /// [`Response::Identity`].
    Unlock {
        /// The keystore passphrase.
        passphrase: Sensitive,
    },
    /// Ask who is currently unlocked. Expects [`Response::Identity`] or
    /// [`Response::Locked`].
    Whoami,
    /// Send an encrypted message to a contact on the local network. Expects
    /// [`Response::Sent`], [`Response::NotReachable`], or [`Response::Error`].
    Send {
        /// The recipient's handle, `nick#fingerprint`.
        to: String,
        /// The message plaintext. Wrapped so it is redacted in `Debug`,
        /// zeroized, and never logged; it travels only over the local socket.
        body: Sensitive,
    },
    /// Drain the in-RAM inbox of received messages. Expects [`Response::Inbox`].
    Inbox,
    /// List peers discovered on the local network. Expects [`Response::Peers`].
    Peers,
    /// Resolve a handle through the DHT (M4): look up the signed locator by
    /// fingerprint, validate it, and report the addresses published for it.
    /// Expects [`Response::Resolved`] or [`Response::NotReachable`].
    Resolve {
        /// The handle to resolve, `nick#fingerprint` (the fingerprint part is
        /// what the DHT is keyed on; the nick is ignored).
        handle: String,
    },
    /// Network and identity status. Expects [`Response::Status`].
    Status,
    /// Subscribe this connection to server-initiated push events (M3).
    ///
    /// The daemon first replies [`Response::Subscribed`], then pushes any
    /// currently buffered inbox messages, then streams live [`Response::Event`]
    /// frames (inbound messages, peer discovery) until the connection closes.
    /// One-shot clients never send this, so their strictly request→response
    /// flow is unaffected.
    Subscribe,
}

/// A response sent by the daemon to the client.
///
/// Deliberately **no `Clone` / `PartialEq`** (see [`Request`]); test code
/// matches variants with `matches!`.
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    /// Successful reply to [`Request::Ping`].
    Pong,
    /// The currently unlocked identity.
    Identity {
        /// Public handle, `nick#fingerprint`.
        handle: String,
        /// The full identity-key fingerprint (base58).
        fingerprint: String,
    },
    /// An identity was created (or restored) and unlocked.
    Created {
        /// Public handle, `nick#fingerprint`.
        handle: String,
        /// The full identity-key fingerprint (base58).
        fingerprint: String,
        /// The one-time recovery phrase, present only for
        /// [`RecoveryMode::Phrase`] on `Init`. Shown once, never stored.
        mnemonic: Option<Sensitive>,
    },
    /// No identity is unlocked (locked keystore, or none exists yet).
    Locked,
    /// A message was encrypted, persisted, and delivered to the peer.
    Sent,
    /// The recipient is not currently reachable on the local network; nothing
    /// was queued (offline store-and-forward is a later milestone).
    NotReachable {
        /// The handle that could not be reached.
        handle: String,
    },
    /// The drained inbox contents.
    Inbox {
        /// Received messages, oldest first.
        messages: Vec<InboxItem>,
    },
    /// Discovered peers on the local network.
    Peers {
        /// One entry per discovered peer.
        peers: Vec<PeerInfo>,
    },
    /// A handle was resolved through the DHT (M4): its signed locator was found
    /// and validated.
    Resolved {
        /// The resolved peer's full fingerprint (base58), taken from the record.
        fingerprint: String,
        /// The peer's libp2p peer id (base58).
        peer_id: String,
        /// The globally-routable addresses the peer published. **May be empty**:
        /// the identity is discoverable but not directly connectable — a
        /// NAT-bound peer, reachable once relays land (M5). Discovery is not
        /// reachability.
        addrs: Vec<String>,
    },
    /// Network and identity status.
    Status {
        /// Our handle, `nick#fingerprint`.
        handle: String,
        /// Our libp2p peer id (base58).
        peer_id: String,
        /// Our bound listen addresses.
        listen_addrs: Vec<String>,
        /// Number of currently discovered peers.
        peer_count: usize,
        /// Whether the Kademlia DHT is enabled on this node (M4).
        dht_enabled: bool,
        /// Distinct peers seen in the DHT routing table (approximate liveness).
        dht_routing_peers: usize,
        /// The globally-routable addresses we publish in our DHT locator — what
        /// other nodes learn about us. Empty means we publish an identity-only
        /// locator (no reachable address advertised). Shown so the user can see
        /// exactly what is exposed (honest IP posture, spec §13).
        published_addrs: Vec<String>,
        /// Our reachability from outside, as AutoNAT sees it (M5).
        reachability: ReachabilityInfo,
        /// Whether this node acts as a relay for other peers (M5).
        relaying: bool,
        /// Relays we may route through (public infrastructure metadata, not
        /// secret — the user is shown who could be carrying their traffic).
        relays: Vec<String>,
    },
    /// The request could not be served; carries a human-readable reason.
    Error {
        /// Human-readable error message (never contains secrets).
        message: String,
    },
    /// Acknowledges [`Request::Subscribe`]: this connection is now subscribed
    /// to push events (M3).
    Subscribed,
    /// A server-initiated push to a subscribed connection (M3).
    ///
    /// This is a *distinct variant*, so a client can always tell an unsolicited
    /// push apart from the reply to its most recent request: anything that is
    /// not an `Event` is that reply. A one-shot client never subscribes, so it
    /// never receives an `Event` and its single read is always its response.
    Event(Event),
}

/// A server-initiated push event delivered to a subscribed connection (M3).
///
/// Carried inside [`Response::Event`]. Message bodies stay wrapped in
/// [`Sensitive`] (redacted in `Debug`, zeroized on drop, never logged).
#[derive(Debug, Serialize, Deserialize)]
pub enum Event {
    /// An inbound message was received, decrypted, and identity-verified.
    Message {
        /// The sender's full fingerprint (base58), cryptographically verified.
        from_fingerprint: String,
        /// The decrypted message body.
        body: Sensitive,
    },
    /// A peer appeared on the local network (mDNS discovery).
    PeerDiscovered {
        /// The newly discovered peer.
        peer: PeerInfo,
    },
    /// A previously discovered peer is no longer visible on the local network.
    PeerLost {
        /// The full fingerprint (base58) of the peer that disappeared.
        fingerprint: String,
    },
}

/// One received message in the inbox.
#[derive(Debug, Serialize, Deserialize)]
pub struct InboxItem {
    /// The sender's full fingerprint (base58), cryptographically verified.
    pub from_fingerprint: String,
    /// The decrypted message body (redacted in `Debug`, zeroized on drop).
    pub body: Sensitive,
}

/// How an open connection to a peer is carried (M5). Mirror of prism-net's
/// `ConnectionPath`, kept here so the IPC layer needs no networking dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerPath {
    /// Direct — dialled directly, or upgraded from relayed by hole punching.
    Direct,
    /// Carried through a relay (which cannot read the traffic).
    Relayed,
}

/// Our own reachability from outside, as AutoNAT sees it (M5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReachabilityInfo {
    /// No probe has completed yet — honestly unknown, not assumed reachable.
    Unknown,
    /// At least one of our addresses was dialled back successfully.
    Public,
    /// Every address probed so far failed: we are behind a NAT or firewall.
    Private,
}

/// How a peer was discovered (M4). Mirror of prism-net's `DiscoverySource`,
/// kept in the proto crate so the IPC layer carries no networking dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerSource {
    /// Local-network mDNS multicast.
    Mdns,
    /// The Kademlia DHT (a resolved signed locator).
    Dht,
    /// Seeded out of band (a bootstrap node or an explicit address hint).
    Manual,
}

/// One discovered peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// The peer's full identity fingerprint (base58), derived from its key.
    pub fingerprint: String,
    /// The peer's libp2p peer id (base58).
    pub peer_id: String,
    /// Whether a connection is currently open.
    pub connected: bool,
    /// How this peer was discovered (mDNS, DHT, or seeded manually).
    pub source: PeerSource,
    /// How the open connection is carried, if one is open (M5).
    pub path: Option<PeerPath>,
}

/// Transport envelope wrapping every IPC message with a protocol version.
#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// Protocol version of the wrapped message.
    pub version: u16,
    /// The wrapped request or response.
    pub message: T,
}

impl<T> Envelope<T> {
    /// Wrap `message` with the current [`PROTOCOL_VERSION`].
    pub fn new(message: T) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_request_round_trips() {
        let json = serde_json::to_string(&Request::Subscribe).expect("serialize");
        let back: Request = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(back, Request::Subscribe));
    }

    #[test]
    fn subscribed_response_round_trips() {
        let json = serde_json::to_string(&Response::Subscribed).expect("serialize");
        let back: Response = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(back, Response::Subscribed));
    }

    #[test]
    fn message_event_preserves_sender_and_body() {
        let event = Response::Event(Event::Message {
            from_fingerprint: "3R95oF6ZdppUsD".to_owned(),
            body: Sensitive::new("hello over the wire".to_owned()),
        });
        let json = serde_json::to_string(&event).expect("serialize");
        let back: Response = serde_json::from_str(&json).expect("deserialize");
        match back {
            Response::Event(Event::Message {
                from_fingerprint,
                body,
            }) => {
                assert_eq!(from_fingerprint, "3R95oF6ZdppUsD");
                assert_eq!(body.expose(), "hello over the wire");
            }
            other => panic!("expected a message event, got {other:?}"),
        }
    }

    #[test]
    fn peer_events_round_trip() {
        let discovered = Response::Event(Event::PeerDiscovered {
            peer: PeerInfo {
                fingerprint: "abc".to_owned(),
                peer_id: "12D3Koo".to_owned(),
                connected: true,
                source: PeerSource::Mdns,
                path: Some(PeerPath::Direct),
            },
        });
        let json = serde_json::to_string(&discovered).expect("serialize");
        let back: Response = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(
            back,
            Response::Event(Event::PeerDiscovered { peer }) if peer.fingerprint == "abc"
        ));

        let lost = Response::Event(Event::PeerLost {
            fingerprint: "abc".to_owned(),
        });
        let json = serde_json::to_string(&lost).expect("serialize");
        let back: Response = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(
            back,
            Response::Event(Event::PeerLost { fingerprint }) if fingerprint == "abc"
        ));
    }

    #[test]
    fn envelope_carries_protocol_version() {
        assert_eq!(PROTOCOL_VERSION, 4);
        let env = Envelope::new(Request::Subscribe);
        assert_eq!(env.version, 4);
    }
}
