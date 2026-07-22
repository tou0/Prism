// SPDX-License-Identifier: AGPL-3.0-or-later
//! Encrypted 1:1 sessions: Olm 3DH establishment + Double Ratchet, via
//! vodozemac, anchored to the M1 Ed25519 identity.
//!
//! The [`SessionManager`] is transport-agnostic: it turns plaintext into
//! opaque wire bytes and back. A real transport (M2b+) moves those bytes;
//! nothing in here changes. M2 exercises the full flow locally.
//!
//! # Identity anchoring
//!
//! - **Outbound**: a session is only ever established against an
//!   identity-signed prekey bundle ([`crate::bundle`]), verified under the
//!   identity the caller *expects* (out-of-band knowledge).
//! - **Inbound**: Olm pre-key messages carry only Curve25519 keys, so the
//!   initiator proves its identity *inside* the encrypted channel: every
//!   pre-reply plaintext carries a binding envelope — the sender's Ed25519
//!   key plus a signature over both parties' identity and Curve25519 keys
//!   (full channel binding, defeating unknown-key-share splices). The
//!   responder needs no reverse binding: only the holder of the
//!   bundle-signed identity/one-time private keys can complete the 3DH.
//!
//! # Persist-before-transmit (correctness, not preference)
//!
//! The ratchet derives a unique message key per advance. If an advance were
//! released (as ciphertext or plaintext) before the new state was durable, a
//! crash would resurrect the pre-advance state and **reuse a message key** —
//! catastrophic for confidentiality. Therefore every mutating operation here
//! persists the advanced state to the sealed store **before** its output
//! escapes the call. If persisting fails, the output is withheld: the
//! affected message key burns unused (a harmless skipped index), never
//! reused.
//!
//! # Session config
//!
//! Sessions use [`SessionConfig::version_1`] — the audited, production Olm
//! configuration (vodozemac 0.10 gates `version_2`, which only widens the
//! truncated MAC, behind the `experimental-session-config` cargo feature;
//! an experimental flag has no place in this codebase). The wire envelope,
//! the store, and per-session configs are all versioned, so moving to v2
//! when it stabilizes is a compatible evolution.

use std::path::PathBuf;

use vodozemac::olm::{
    Account, InboundCreationResult, OlmMessage, PreKeyMessage, Session, SessionConfig,
};
use vodozemac::Curve25519PublicKey;
use zeroize::Zeroizing;

use crate::bundle::{open_bundle, seal_bundle, BundleError, KeySlot};
use crate::identity::{IdentityKeypair, PublicIdentity, SIGNATURE_LEN};
use crate::secret::RngError;
use crate::session_store::{SealedSessionStore, SessionRecord, SessionStoreError, StorePayload};
use crate::validate::{validate_x25519_public, KeyRejection};

/// Version byte of the wire-message envelope.
pub const WIRE_VERSION: u8 = 1;
/// Hard cap on a whole wire message (defensive parse bound).
pub const MAX_WIRE_LEN: usize = 128 * 1024;
/// Hard cap on a plaintext payload accepted for encryption.
pub const MAX_PLAINTEXT_LEN: usize = 64 * 1024;
/// Domain for the initiator's identity-binding signature.
pub const BINDING_DOMAIN: &[u8] = b"prism v1 session identity binding";

/// Version byte of the plaintext envelope (inside the encryption).
const PLAINTEXT_VERSION: u8 = 1;
/// Plaintext-envelope flag: a binding envelope is present.
const FLAG_BINDING: u8 = 0b0000_0001;
/// Serialized binding envelope length: sender_ed[32] ‖ sig[64].
const BINDING_LEN: usize = 32 + SIGNATURE_LEN;
/// Wire kinds.
const KIND_PREKEY: u8 = 0;
const KIND_NORMAL: u8 = 1;
/// Cap on the session-id field in the wire envelope.
const MAX_SESSION_ID_LEN: usize = 64;

/// The audited Olm session configuration (see module docs).
fn session_config() -> SessionConfig {
    SessionConfig::version_1()
}

/// Opaque routing identifier of a session (vodozemac session id, base64).
/// Public data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// The base64 form, e.g. for logs (public, carries no key material).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How the sender picks the establishment key from a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtkChoice {
    /// First listed one-time key, or the fallback key if none are listed.
    Auto,
    /// A specific one-time key by index (tests / a future claiming directory).
    Index(u16),
    /// Force the fallback key (exhaustion path).
    Fallback,
}

/// A successfully decrypted message. **No `Debug`/`Clone`**: carries the
/// plaintext.
pub struct Decrypted {
    /// The session the message arrived on.
    pub session: SessionId,
    /// The peer identity bound to that session (bundle-verified for sessions
    /// we initiated, binding-envelope-verified for inbound ones).
    pub peer: PublicIdentity,
    /// The decrypted payload, zeroized on drop.
    pub plaintext: Zeroizing<Vec<u8>>,
}

/// Errors of the session layer. No variant ever carries key or secret bytes.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Bundle ingestion failed (parse, validation, identity, signature).
    #[error(transparent)]
    Bundle(#[from] BundleError),
    /// A key inside a message failed strict ingestion validation.
    #[error("message key {slot:?} rejected: {reason}")]
    InvalidKey {
        /// Which key was rejected.
        slot: KeySlot,
        /// Why it was rejected.
        reason: KeyRejection,
    },
    /// The requested one-time key index does not exist in the bundle.
    #[error("one-time key index {index} not present in the bundle")]
    NoSuchOneTimeKey {
        /// The requested index.
        index: u16,
    },
    /// A message referenced a session this manager does not know.
    #[error("unknown session")]
    UnknownSession,
    /// Structurally invalid wire bytes.
    #[error("malformed message: {0}")]
    MalformedMessage(&'static str),
    /// The wire envelope declares a version this build does not understand.
    #[error("unsupported message version {found} (this build supports {WIRE_VERSION})")]
    UnsupportedVersion {
        /// The version byte found on the wire.
        found: u8,
    },
    /// The plaintext exceeds [`MAX_PLAINTEXT_LEN`].
    #[error("plaintext larger than the accepted maximum")]
    PlaintextTooLarge,
    /// The wire message exceeds [`MAX_WIRE_LEN`].
    #[error("wire message larger than the accepted maximum")]
    WireTooLarge,
    /// An inbound establishment referenced a one-time key we no longer hold
    /// (already consumed, or never ours). Honest causes: a replayed first
    /// message, two senders racing for the same key, or a stale bundle.
    #[error("the one-time key for this session is unknown or already consumed")]
    OneTimeKeyMissing,
    /// Session establishment failed inside the protocol library.
    #[error("session establishment failed")]
    Establishment,
    /// Decryption failed. Deliberately opaque: a wrong key, a tampered
    /// message, and a replay must be indistinguishable to a caller.
    #[error("decryption failed")]
    DecryptFailed,
    /// Encryption failed inside the protocol library (does not happen for
    /// in-bound payload sizes; explicit error instead of a panic path).
    #[error("encryption failed")]
    EncryptFailed,
    /// The first message of a session carried no identity binding.
    #[error("initial message carries no identity binding")]
    MissingBinding,
    /// The binding envelope did not verify, or contradicts the session peer.
    #[error("identity binding rejected")]
    BadBinding,
    /// The sealed store failed (the output of the operation was withheld).
    #[error(transparent)]
    Store(#[from] SessionStoreError),
    /// The OS CSPRNG failed.
    #[error(transparent)]
    Rng(#[from] RngError),
}

/// One live session plus everything bound to it.
///
/// No `Clone`/`Debug`: wraps the ratchet state.
struct ManagedSession {
    session_id: String,
    peer: PublicIdentity,
    initiated_by_us: bool,
    /// Binding envelope attached to pre-reply messages (outbound only).
    binding: Option<Vec<u8>>,
    session: Session,
}

/// The session manager: owns the vodozemac account, all live sessions, and
/// the sealed store they persist into (see the module docs for the
/// persist-before-transmit contract).
///
/// No `Clone`/`Debug`: holds the identity keypair and ratchet state. All
/// operations are synchronous and CPU-cheap (no KDF; the store write is one
/// AEAD + an fsync'd atomic rename).
pub struct SessionManager {
    identity: IdentityKeypair,
    account: Account,
    fallback_pub: Option<[u8; 32]>,
    published_bundle: Option<Vec<u8>>,
    sessions: Vec<ManagedSession>,
    store: SealedSessionStore,
}

impl SessionManager {
    /// Open the manager for `identity`, loading `path` if it exists or
    /// creating (and immediately persisting) a fresh account otherwise.
    ///
    /// The store is sealed under a key derived from the identity seed, so a
    /// store written by a different identity fails to open (`AuthFailed`)
    /// rather than being silently adopted.
    pub fn open(identity: &IdentityKeypair, path: PathBuf) -> Result<Self, SessionError> {
        let seed = identity.to_seed();
        let mut store = SealedSessionStore::new(path, &seed)?;
        let identity = IdentityKeypair::from_seed(&seed);

        if let Some(payload) = store.load()? {
            let mut sessions = Vec::with_capacity(payload.sessions.len());
            for record in payload.sessions {
                // Defensive even on our own authenticated file.
                let peer = PublicIdentity::from_bytes(&record.peer_ed25519)
                    .map_err(|_| SessionStoreError::Corrupted("stored peer identity key"))?;
                sessions.push(ManagedSession {
                    session_id: record.session_id,
                    peer,
                    initiated_by_us: record.initiated_by_us,
                    binding: record.binding,
                    session: Session::from_pickle(record.session),
                });
            }
            Ok(Self {
                identity,
                account: Account::from_pickle(payload.account),
                fallback_pub: payload.fallback_pub,
                published_bundle: payload.published_bundle,
                sessions,
                store,
            })
        } else {
            let mut manager = Self {
                identity,
                account: Account::new(),
                fallback_pub: None,
                published_bundle: None,
                sessions: Vec::new(),
                store,
            };
            manager.persist()?;
            Ok(manager)
        }
    }

    /// Our public identity (the M1 Ed25519 root).
    pub fn identity(&self) -> PublicIdentity {
        self.identity.public()
    }

    /// The currently published signed bundle, if any (wire bytes, re-served
    /// as published).
    pub fn current_bundle(&self) -> Option<&[u8]> {
        self.published_bundle.as_deref()
    }

    /// The peer identity bound to a session.
    pub fn peer_of(&self, session: &SessionId) -> Option<&PublicIdentity> {
        self.find(&session.0).map(|s| &s.peer)
    }

    /// Find an established session with `peer`, if any — so a caller can decide
    /// between encrypting on it and establishing a new one. Returns the first
    /// match; in the normal single-initiator flow both sides share one session
    /// id, so there is exactly one (simultaneous mutual initiation, i.e. glare,
    /// is out of scope for M2b).
    pub fn find_session(&self, peer: &PublicIdentity) -> Option<SessionId> {
        self.sessions
            .iter()
            .find(|s| &s.peer == peer)
            .map(|s| SessionId(s.session_id.clone()))
    }

    /// Generate `count` fresh one-time keys (plus the fallback key on first
    /// use), sign the bundle with the identity, mark the keys as published,
    /// persist, and return the wire bundle.
    ///
    /// Previously published but unconsumed one-time keys stay valid for
    /// inbound establishment; they simply rotate out of the advertised set.
    pub fn publish_bundle(&mut self, count: usize) -> Result<Vec<u8>, SessionError> {
        let count = count.min(crate::bundle::MAX_ONE_TIME_KEYS);
        if self.fallback_pub.is_none() {
            // First publication: create the long-lived fallback key. Called
            // exactly once — regenerating would rotate the previous one out.
            self.account.generate_fallback_key();
            let fallback = self
                .account
                .fallback_key()
                .into_values()
                .next()
                .ok_or(SessionError::Establishment)?;
            self.fallback_pub = Some(fallback.to_bytes());
        }
        self.account.generate_one_time_keys(count);

        let fallback = self.fallback_pub.ok_or(SessionError::Establishment)?;
        let otks: Vec<[u8; 32]> = self
            .account
            .one_time_keys()
            .into_values()
            .map(|key| key.to_bytes())
            .collect();
        let wire = seal_bundle(
            &self.identity,
            &self.account.curve25519_key().to_bytes(),
            &fallback,
            &otks,
        )?;

        self.account.mark_keys_as_published();
        self.published_bundle = Some(wire.clone());
        self.persist()?;
        Ok(wire)
    }

    /// Establish an outbound session against a received bundle.
    ///
    /// `expected` is the identity obtained out of band (the contact's
    /// handle); the bundle is rejected unless it is signed by exactly that
    /// identity, and every key in it passed strict validation. The advanced
    /// state is persisted before the id is returned.
    pub fn establish_outbound(
        &mut self,
        expected: &PublicIdentity,
        bundle_bytes: &[u8],
        choice: OtkChoice,
    ) -> Result<SessionId, SessionError> {
        let bundle = open_bundle(expected, bundle_bytes)?;

        let their_key: [u8; 32] = match choice {
            OtkChoice::Auto => bundle
                .one_time_keys()
                .first()
                .copied()
                .unwrap_or(*bundle.fallback()),
            OtkChoice::Index(index) => *bundle
                .one_time_keys()
                .get(usize::from(index))
                .ok_or(SessionError::NoSuchOneTimeKey { index })?,
            OtkChoice::Fallback => *bundle.fallback(),
        };

        let session = self
            .account
            .create_outbound_session(
                session_config(),
                Curve25519PublicKey::from_bytes(*bundle.ik_curve()),
                Curve25519PublicKey::from_bytes(their_key),
            )
            .map_err(|_| SessionError::Establishment)?;

        // The binding this session will attach to every pre-reply message:
        // proves to the responder that our Ed25519 identity stands behind
        // the Curve25519 key that ran the 3DH, bound to *their* identity too.
        let binding = make_binding(
            &self.identity,
            &self.account.curve25519_key().to_bytes(),
            expected,
            bundle.ik_curve(),
        );

        let session_id = session.session_id();
        self.sessions.push(ManagedSession {
            session_id: session_id.clone(),
            peer: expected.clone(),
            initiated_by_us: true,
            binding: Some(binding),
            session,
        });
        self.persist()?;
        Ok(SessionId(session_id))
    }

    /// Encrypt `payload` for `session`. The advanced ratchet state is durably
    /// persisted **before** the ciphertext is returned; on persist failure
    /// the ciphertext is withheld and its message key burns unused.
    pub fn encrypt(
        &mut self,
        session: &SessionId,
        payload: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        if payload.len() > MAX_PLAINTEXT_LEN {
            return Err(SessionError::PlaintextTooLarge);
        }
        let entry = self
            .sessions
            .iter_mut()
            .find(|s| s.session_id == session.0)
            .ok_or(SessionError::UnknownSession)?;

        // Attach the identity binding while the peer has not proven receipt
        // (every message until then is prekey-framed and may be their first).
        let binding = if entry.initiated_by_us && !entry.session.has_received_message() {
            entry.binding.as_deref()
        } else {
            None
        };
        let envelope = encode_plaintext_envelope(binding, payload);
        let olm = entry
            .session
            .encrypt(envelope.as_slice())
            .map_err(|_| SessionError::EncryptFailed)?;

        let (kind, olm_bytes) = match &olm {
            OlmMessage::PreKey(message) => (KIND_PREKEY, message.to_bytes()),
            OlmMessage::Normal(message) => (KIND_NORMAL, message.to_bytes()),
        };
        let wire = encode_wire(kind, &entry.session_id, &olm_bytes)?;

        // Persist BEFORE the ciphertext escapes (module docs).
        self.persist()?;
        Ok(wire)
    }

    /// Decrypt a received wire message, establishing an inbound session if it
    /// is a first contact. The advanced state (including a consumed one-time
    /// key) is durably persisted **before** the plaintext is returned.
    pub fn decrypt(&mut self, wire: &[u8]) -> Result<Decrypted, SessionError> {
        let (kind, session_id, olm_bytes) = parse_wire(wire)?;

        match kind {
            KIND_PREKEY => {
                let message = PreKeyMessage::from_bytes(olm_bytes)
                    .map_err(|_| SessionError::MalformedMessage("undecodable pre-key message"))?;
                if message.session_id() != session_id {
                    return Err(SessionError::MalformedMessage(
                        "envelope session id contradicts the message",
                    ));
                }
                // Strict ingestion validation of every visible handshake key
                // (spec §5.3), before any library call. (The inner ratchet
                // key of a pre-key message is not exposed pre-decryption;
                // vodozemac's contributory-behavior checks cover it at use.)
                validate_message_key(&message.identity_key(), KeySlot::IdentityCurve25519)?;
                validate_message_key(&message.base_key(), KeySlot::EphemeralBaseKey)?;
                validate_message_key(&message.one_time_key(), KeySlot::OneTimeKey(0))?;

                if self.find(&session_id).is_some() {
                    // Known session: every message until the initiator sees a
                    // reply is prekey-framed — route it to the session rather
                    // than re-establishing (also neutralizes replays).
                    let olm = OlmMessage::PreKey(message);
                    return self.decrypt_on_existing(&session_id, &olm);
                }

                let InboundCreationResult { session, plaintext } = self
                    .account
                    .create_inbound_session(session_config(), message.identity_key(), &message)
                    .map_err(|e| match e {
                        vodozemac::olm::SessionCreationError::MissingOneTimeKey(_) => {
                            SessionError::OneTimeKeyMissing
                        }
                        vodozemac::olm::SessionCreationError::Decryption(_) => {
                            SessionError::DecryptFailed
                        }
                        _ => SessionError::Establishment,
                    })?;
                let plaintext = Zeroizing::new(plaintext);

                // The initiator MUST prove an identity: no binding, no session.
                let (binding, payload) = parse_plaintext_envelope(&plaintext)?;
                let binding = binding.ok_or(SessionError::MissingBinding)?;
                let peer = verify_binding(
                    binding,
                    &message.identity_key().to_bytes(),
                    &self.identity.public(),
                    &self.account.curve25519_key().to_bytes(),
                )?;

                self.sessions.push(ManagedSession {
                    session_id: session_id.clone(),
                    peer: peer.clone(),
                    initiated_by_us: false,
                    binding: None,
                    session,
                });

                // Persist BEFORE the plaintext escapes: the consumed one-time
                // key and the new ratchet state must survive a crash.
                self.persist()?;
                Ok(Decrypted {
                    session: SessionId(session_id),
                    peer,
                    plaintext: Zeroizing::new(payload.to_vec()),
                })
            }
            KIND_NORMAL => {
                let message = vodozemac::olm::Message::from_bytes(olm_bytes)
                    .map_err(|_| SessionError::MalformedMessage("undecodable message"))?;
                // Strict ingestion validation of the ratchet key (spec §5.3).
                validate_message_key(&message.ratchet_key(), KeySlot::RatchetKey)?;
                let olm = OlmMessage::Normal(message);
                self.decrypt_on_existing(&session_id, &olm)
            }
            _ => Err(SessionError::MalformedMessage("unknown message kind")),
        }
    }

    /// Decrypt on an already-established session, enforcing binding
    /// consistency and the persist-before-release contract.
    fn decrypt_on_existing(
        &mut self,
        session_id: &str,
        olm: &OlmMessage,
    ) -> Result<Decrypted, SessionError> {
        let entry = self
            .sessions
            .iter_mut()
            .find(|s| s.session_id == session_id)
            .ok_or(SessionError::UnknownSession)?;

        let plaintext = Zeroizing::new(
            entry
                .session
                .decrypt(olm)
                .map_err(|_| SessionError::DecryptFailed)?,
        );
        let (binding, payload) = parse_plaintext_envelope(&plaintext)?;
        if let Some(binding) = binding {
            // Redundant bindings on later pre-reply messages must at least
            // name the already-bound peer (the channel itself authenticates
            // them; a contradiction is an active splice attempt).
            if binding[..32] != *entry.peer.as_bytes() {
                return Err(SessionError::BadBinding);
            }
        }
        let peer = entry.peer.clone();

        // Persist BEFORE the plaintext escapes (module docs).
        self.persist()?;
        Ok(Decrypted {
            session: SessionId(session_id.to_owned()),
            peer,
            plaintext: Zeroizing::new(payload.to_vec()),
        })
    }

    fn find(&self, session_id: &str) -> Option<&ManagedSession> {
        self.sessions.iter().find(|s| s.session_id == session_id)
    }

    /// Serialize everything into the sealed store. Durable when `Ok`.
    fn persist(&mut self) -> Result<(), SessionError> {
        let payload = StorePayload {
            account: self.account.pickle(),
            fallback_pub: self.fallback_pub,
            published_bundle: self.published_bundle.clone(),
            sessions: self
                .sessions
                .iter()
                .map(|s| SessionRecord {
                    session_id: s.session_id.clone(),
                    peer_ed25519: *s.peer.as_bytes(),
                    initiated_by_us: s.initiated_by_us,
                    binding: s.binding.clone(),
                    session: s.session.pickle(),
                })
                .collect(),
        };
        self.store.store(&payload)?;
        Ok(())
    }
}

/// Validate a Curve25519 key arriving inside a message (spec §5.3).
fn validate_message_key(key: &Curve25519PublicKey, slot: KeySlot) -> Result<(), SessionError> {
    validate_x25519_public(&key.to_bytes())
        .map_err(|reason| SessionError::InvalidKey { slot, reason })
}

/// Build the initiator's binding envelope: `sender_ed[32] ‖ sig[64]`, where
/// the signature covers both parties' identity and Curve25519 keys.
fn make_binding(
    identity: &IdentityKeypair,
    our_curve: &[u8; 32],
    peer: &PublicIdentity,
    peer_curve: &[u8; 32],
) -> Vec<u8> {
    let message = binding_message(
        identity.public().as_bytes(),
        our_curve,
        peer.as_bytes(),
        peer_curve,
    );
    let signature = identity.sign(BINDING_DOMAIN, &message);
    let mut envelope = Vec::with_capacity(BINDING_LEN);
    envelope.extend_from_slice(identity.public().as_bytes());
    envelope.extend_from_slice(&signature);
    envelope
}

/// Verify an initiator's binding envelope on the responder side. Returns the
/// proven initiator identity.
fn verify_binding(
    envelope: &[u8],
    sender_curve: &[u8; 32],
    our_identity: &PublicIdentity,
    our_curve: &[u8; 32],
) -> Result<PublicIdentity, SessionError> {
    if envelope.len() != BINDING_LEN {
        return Err(SessionError::BadBinding);
    }
    let sender_ed: [u8; 32] = envelope[..32]
        .try_into()
        .map_err(|_| SessionError::BadBinding)?;
    // Strict ingestion validation of the claimed identity key (spec §5.3).
    let sender =
        PublicIdentity::from_bytes(&sender_ed).map_err(|reason| SessionError::InvalidKey {
            slot: KeySlot::IdentityEd25519,
            reason,
        })?;
    let signature: &[u8; SIGNATURE_LEN] = envelope[32..]
        .try_into()
        .map_err(|_| SessionError::BadBinding)?;

    // The signed message names the Curve25519 key that actually ran the 3DH
    // (as seen in the pre-key message) and *our* identity: a binding minted
    // for any other channel cannot be replayed onto this one.
    let message = binding_message(&sender_ed, sender_curve, our_identity.as_bytes(), our_curve);
    sender
        .verify(BINDING_DOMAIN, &message, signature)
        .map_err(|_| SessionError::BadBinding)?;
    Ok(sender)
}

/// The byte string the binding signature covers.
fn binding_message(
    sender_ed: &[u8; 32],
    sender_curve: &[u8; 32],
    recipient_ed: &[u8; 32],
    recipient_curve: &[u8; 32],
) -> [u8; 128] {
    let mut message = [0u8; 128];
    message[..32].copy_from_slice(sender_ed);
    message[32..64].copy_from_slice(sender_curve);
    message[64..96].copy_from_slice(recipient_ed);
    message[96..128].copy_from_slice(recipient_curve);
    message
}

/// Encode the plaintext envelope: `version ‖ flags ‖ [binding] ‖ payload`,
/// in a zeroizing buffer sized exactly once.
fn encode_plaintext_envelope(binding: Option<&[u8]>, payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let binding_len = binding.map_or(0, <[u8]>::len);
    let mut envelope = Zeroizing::new(Vec::with_capacity(2 + binding_len + payload.len()));
    envelope.push(PLAINTEXT_VERSION);
    match binding {
        Some(binding) => {
            envelope.push(FLAG_BINDING);
            envelope.extend_from_slice(binding);
        }
        None => envelope.push(0),
    }
    envelope.extend_from_slice(payload);
    envelope
}

/// Parse the plaintext envelope; returns the binding (if flagged) and the
/// payload slice.
fn parse_plaintext_envelope(plaintext: &[u8]) -> Result<(Option<&[u8]>, &[u8]), SessionError> {
    if plaintext.len() < 2 {
        return Err(SessionError::MalformedMessage(
            "plaintext envelope truncated",
        ));
    }
    let version = plaintext[0];
    if version != PLAINTEXT_VERSION {
        return Err(SessionError::UnsupportedVersion { found: version });
    }
    let flags = plaintext[1];
    if flags & !FLAG_BINDING != 0 {
        return Err(SessionError::MalformedMessage("unknown plaintext flags"));
    }
    let rest = &plaintext[2..];
    if flags & FLAG_BINDING != 0 {
        if rest.len() < BINDING_LEN {
            return Err(SessionError::MalformedMessage("binding truncated"));
        }
        let (binding, payload) = rest.split_at(BINDING_LEN);
        Ok((Some(binding), payload))
    } else {
        Ok((None, rest))
    }
}

/// Encode the wire envelope: `version ‖ kind ‖ sid_len ‖ sid ‖ olm bytes`.
fn encode_wire(kind: u8, session_id: &str, olm_bytes: &[u8]) -> Result<Vec<u8>, SessionError> {
    let sid = session_id.as_bytes();
    if sid.len() > MAX_SESSION_ID_LEN {
        return Err(SessionError::MalformedMessage("session id too long"));
    }
    let total = 3 + sid.len() + olm_bytes.len();
    if total > MAX_WIRE_LEN {
        return Err(SessionError::WireTooLarge);
    }
    let mut wire = Vec::with_capacity(total);
    wire.push(WIRE_VERSION);
    wire.push(kind);
    // Cast is exact: bounded by MAX_SESSION_ID_LEN above.
    wire.push(sid.len() as u8);
    wire.extend_from_slice(sid);
    wire.extend_from_slice(olm_bytes);
    Ok(wire)
}

/// Parse the wire envelope defensively; every bound is checked before use.
fn parse_wire(wire: &[u8]) -> Result<(u8, String, &[u8]), SessionError> {
    if wire.len() > MAX_WIRE_LEN {
        return Err(SessionError::WireTooLarge);
    }
    if wire.len() < 4 {
        return Err(SessionError::MalformedMessage("truncated"));
    }
    let version = wire[0];
    if version != WIRE_VERSION {
        return Err(SessionError::UnsupportedVersion { found: version });
    }
    let kind = wire[1];
    let sid_len = usize::from(wire[2]);
    if sid_len == 0 || sid_len > MAX_SESSION_ID_LEN {
        return Err(SessionError::MalformedMessage("bad session id length"));
    }
    if wire.len() < 3 + sid_len + 1 {
        return Err(SessionError::MalformedMessage("truncated"));
    }
    let sid = std::str::from_utf8(&wire[3..3 + sid_len])
        .map_err(|_| SessionError::MalformedMessage("session id is not valid UTF-8"))?
        .to_owned();
    Ok((kind, sid, &wire[3 + sid_len..]))
}
