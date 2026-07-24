// SPDX-License-Identifier: AGPL-3.0-or-later
//! Identity-signed DHT locator records (milestone M4).
//!
//! A locator is the artifact a peer publishes on the Kademlia DHT so that
//! another node, knowing only its handle (`nick#fingerprint`), can discover
//! *where* it is (its addresses) and *who* it is (its full identity key). It is
//! the DHT analogue of the prekey [`crate::bundle`]: **one Ed25519 identity
//! signature over the whole canonical payload**, validated on ingestion before
//! anything in it is trusted.
//!
//! The record is stored on the DHT under a key derived from the publisher's
//! **short fingerprint** — the only thing a looker has from the handle (the
//! full identity key travels *inside* the record, so the looker learns it
//! authentically). Validation therefore binds three things: the signature (only
//! the identity's owner can produce it), strict key validation (spec §5.3), and
//! the **key binding** — the record's identity must hash to the very DHT key it
//! was fetched from / stored under, so an attacker cannot plant a record for
//! someone else's fingerprint (that would cost a ~2^82 fingerprint grind).
//!
//! This does **not** resist a resourceful Sybil/Eclipse adversary positioning
//! node-IDs around a key — that is deferred S/Kademlia hardening (roadmap M7).
//! It authenticates records; it does not make the routing layer trustworthy.
//!
//! Canonical wire layout (fixed order, deterministic — signatures require
//! byte-exact reproducibility, which protobuf does not guarantee):
//!
//! ```text
//! signed payload                     wire locator = payload ‖ sig[64]
//!   0        version       u8 = 1
//!   1..33    ik_ed25519    [32]   identity key (self-description, never a trust root)
//!   33..41   published_at  u64 BE (unix seconds; freshness is caller policy, see below)
//!   41..43   addr_count    u16 BE (≤ MAX_LOCATOR_ADDRS)
//!   43..     addr_i        u16 BE len (1..=MAX_ADDR_LEN) ‖ len bytes (UTF-8),
//!                          strictly ascending bytewise (canonical; rejects dups)
//! ```
//!
//! Addresses are **opaque UTF-8 strings** here: `prism-core` has no network
//! dependency and never parses a multiaddr. IP-hygiene filtering (dropping
//! private/loopback/LAN addresses) happens in `prism-net`, which owns multiaddr
//! semantics, *before* a record is sealed.
//!
//! `published_at` is signed but **not** checked against a clock here:
//! `prism-core` stays clock-free (spec §18.14 — never rest security-critical
//! logic on synchronized wall-clocks). Authenticity is the signature; freshness
//! is a heuristic applied by the caller (which has a clock) and by the DHT
//! record TTL.

use crate::identity::{IdentityKeypair, PublicIdentity, SIGNATURE_LEN};

/// Current locator wire-format version.
pub const LOCATOR_VERSION: u8 = 1;

/// Hard cap on addresses accepted in a locator (parse/DoS bound). A node
/// publishes only a handful of globally-routable addresses.
pub const MAX_LOCATOR_ADDRS: usize = 6;

/// Hard cap on a single address string, in bytes. A multiaddr such as
/// `/ip4/198.51.100.7/tcp/4001/p2p/12D3Koo…` is well under this.
pub const MAX_ADDR_LEN: usize = 128;

/// Domain for the locator signature (see [`crate::IdentityKeypair::sign`]).
pub const LOCATOR_SIGNING_DOMAIN: &[u8] = b"prism v1 dht locator";

/// Domain prefix for deriving a locator's DHT key from a short fingerprint.
const LOCATOR_KEY_DOMAIN: &[u8] = b"prism v1 dht locator key";

// Fixed byte offsets of the canonical fixed-length header.
const VERSION_OFFSET: usize = 0;
const IK_ED_OFFSET: usize = 1;
const PUBLISHED_AT_OFFSET: usize = 33;
const ADDR_COUNT_OFFSET: usize = 41;
const ADDRS_OFFSET: usize = 43;

/// The Kademlia record key under which the identity with this **short
/// fingerprint** publishes its locator. Deterministic and derivable by anyone
/// holding the handle; both the publisher (from its own identity) and a looker
/// (from the handle it was given) compute the same 32 bytes.
///
/// blake3 over a domain-tagged short fingerprint: fixed width, uniform in the
/// keyspace, and domain-separated from every other blake3 use in Prism.
pub fn dht_locator_key(short_fingerprint: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LOCATOR_KEY_DOMAIN);
    hasher.update(short_fingerprint.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The DHT key under which `identity` publishes its own locator.
pub fn own_locator_key(identity: &PublicIdentity) -> [u8; 32] {
    dht_locator_key(&identity.fingerprint().short())
}

/// Errors produced while building or ingesting a locator. Never carries key
/// bytes or any secret (identities, fingerprints, and addresses are public).
#[derive(Debug, thiserror::Error)]
pub enum LocatorError {
    /// Structurally invalid wire bytes (truncated, trailing bytes, bad order,
    /// non-UTF-8 address, empty address).
    #[error("malformed dht locator: {0}")]
    Malformed(&'static str),
    /// The locator declares a version this build does not understand.
    #[error("unsupported dht locator version {found} (this build supports {LOCATOR_VERSION})")]
    UnsupportedVersion {
        /// The version byte found in the record.
        found: u8,
    },
    /// More addresses than [`MAX_LOCATOR_ADDRS`].
    #[error("dht locator declares too many addresses ({count})")]
    TooManyAddresses {
        /// The declared count.
        count: usize,
    },
    /// An address exceeds [`MAX_ADDR_LEN`] bytes.
    #[error("dht locator address exceeds {MAX_ADDR_LEN} bytes")]
    AddressTooLong,
    /// The embedded identity key failed strict validation (spec §5.3).
    #[error("dht locator identity key rejected: {0}")]
    InvalidIdentity(crate::validate::KeyRejection),
    /// The identity signature over the payload did not verify.
    #[error("dht locator signature is invalid")]
    BadSignature,
    /// The record's identity does not hash to the DHT key it was stored under
    /// (a record planted under someone else's fingerprint).
    #[error("dht locator does not match its DHT key")]
    KeyMismatch,
}

/// A parsed and fully validated DHT locator. Every field is public; the
/// identity passed strict validation, the whole payload is covered by the
/// verified identity signature, and the identity is bound to the DHT key.
#[derive(Debug, Clone)]
pub struct DhtLocator {
    identity: PublicIdentity,
    addrs: Vec<String>,
    published_at: u64,
}

impl DhtLocator {
    /// The identity that signed this locator (its full Ed25519 public key —
    /// self-description, obtained authentically because the signature and the
    /// DHT-key binding both check out).
    pub fn identity(&self) -> &PublicIdentity {
        &self.identity
    }

    /// The published addresses (opaque multiaddr strings), in canonical order.
    pub fn addrs(&self) -> &[String] {
        &self.addrs
    }

    /// The publisher's declared publication time (unix seconds). The caller
    /// applies any freshness policy against its own clock; this crate does not.
    pub fn published_at(&self) -> u64 {
        self.published_at
    }
}

/// Encode the canonical signed payload (everything but the signature).
fn canonical_payload(ik_ed: &[u8; 32], published_at: u64, sorted_addrs: &[String]) -> Vec<u8> {
    let addrs_len: usize = sorted_addrs.iter().map(|a| 2 + a.len()).sum();
    let mut payload = Vec::with_capacity(ADDRS_OFFSET + addrs_len);
    payload.push(LOCATOR_VERSION);
    payload.extend_from_slice(ik_ed);
    payload.extend_from_slice(&published_at.to_be_bytes());
    // Cast is exact: the caller bounds the count by MAX_LOCATOR_ADDRS < u16::MAX.
    payload.extend_from_slice(&(sorted_addrs.len() as u16).to_be_bytes());
    for addr in sorted_addrs {
        // Cast is exact: each address is bounded by MAX_ADDR_LEN < u16::MAX.
        payload.extend_from_slice(&(addr.len() as u16).to_be_bytes());
        payload.extend_from_slice(addr.as_bytes());
    }
    payload
}

/// Build and sign a locator for `identity` over `addrs` and `published_at`.
///
/// Addresses are sorted into canonical order and de-duplicated; each must be
/// non-empty and at most [`MAX_ADDR_LEN`] bytes, and there must be at most
/// [`MAX_LOCATOR_ADDRS`] of them. An empty address list is valid (a peer with
/// no globally-routable address is discoverable but not directly connectable).
/// The signature is made under [`LOCATOR_SIGNING_DOMAIN`] and covers everything.
pub fn seal_locator(
    identity: &IdentityKeypair,
    addrs: &[String],
    published_at: u64,
) -> Result<Vec<u8>, LocatorError> {
    for addr in addrs {
        if addr.is_empty() {
            return Err(LocatorError::Malformed("empty address"));
        }
        if addr.len() > MAX_ADDR_LEN {
            return Err(LocatorError::AddressTooLong);
        }
    }

    let mut sorted: Vec<String> = addrs.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() > MAX_LOCATOR_ADDRS {
        return Err(LocatorError::TooManyAddresses {
            count: sorted.len(),
        });
    }

    let ik_ed = identity.public();
    let payload = canonical_payload(ik_ed.as_bytes(), published_at, &sorted);
    let signature = identity.sign(LOCATOR_SIGNING_DOMAIN, &payload);

    let mut wire = payload;
    wire.extend_from_slice(&signature);
    Ok(wire)
}

/// Parse, validate, and authenticate a received locator, binding it to the DHT
/// key `dht_key` it was stored under / fetched from.
///
/// Rejection order: shape (length/version/count) → embedded identity key
/// validation → signature under that identity → DHT-key binding → per-address
/// shape and canonical order. Nothing is returned unless every step passed.
///
/// The same function serves both call sites: a looker validating a `get_record`
/// result, and a random DHT node validating an incoming `put_record` before
/// storing it (both pass the record's DHT key).
pub fn open_locator(bytes: &[u8], dht_key: &[u8; 32]) -> Result<DhtLocator, LocatorError> {
    // Shape: enough bytes for the fixed header and the signature?
    if bytes.len() < ADDRS_OFFSET + SIGNATURE_LEN {
        return Err(LocatorError::Malformed("truncated"));
    }
    let version = bytes[VERSION_OFFSET];
    if version != LOCATOR_VERSION {
        return Err(LocatorError::UnsupportedVersion { found: version });
    }

    let count_bytes: [u8; 2] = bytes[ADDR_COUNT_OFFSET..ADDR_COUNT_OFFSET + 2]
        .try_into()
        .map_err(|_| LocatorError::Malformed("truncated"))?;
    let count = usize::from(u16::from_be_bytes(count_bytes));
    if count > MAX_LOCATOR_ADDRS {
        return Err(LocatorError::TooManyAddresses { count });
    }

    // Walk the variable address section to find the payload/signature split,
    // bounding every length before indexing (no trust in the declared sizes).
    let mut cursor = ADDRS_OFFSET;
    let mut addrs: Vec<String> = Vec::with_capacity(count);
    for _ in 0..count {
        if cursor + 2 > bytes.len() {
            return Err(LocatorError::Malformed("truncated address length"));
        }
        let len_bytes: [u8; 2] = bytes[cursor..cursor + 2]
            .try_into()
            .map_err(|_| LocatorError::Malformed("truncated"))?;
        let len = usize::from(u16::from_be_bytes(len_bytes));
        if len == 0 {
            return Err(LocatorError::Malformed("empty address"));
        }
        if len > MAX_ADDR_LEN {
            return Err(LocatorError::AddressTooLong);
        }
        cursor += 2;
        if cursor + len > bytes.len() {
            return Err(LocatorError::Malformed("truncated address"));
        }
        let addr = std::str::from_utf8(&bytes[cursor..cursor + len])
            .map_err(|_| LocatorError::Malformed("non-utf8 address"))?;
        if let Some(previous) = addrs.last() {
            if previous.as_str() >= addr {
                return Err(LocatorError::Malformed("addresses not in canonical order"));
            }
        }
        addrs.push(addr.to_owned());
        cursor += len;
    }

    // Exact length: the signature must be the only thing left. Rejects both
    // truncation and trailing bytes.
    let payload_len = cursor;
    if bytes.len() != payload_len + SIGNATURE_LEN {
        return Err(LocatorError::Malformed(
            "length does not match declared addresses",
        ));
    }
    let (payload, signature) = bytes.split_at(payload_len);

    // Embedded identity key: strict validation before any trust.
    let ik_ed_bytes: [u8; 32] = payload[IK_ED_OFFSET..IK_ED_OFFSET + 32]
        .try_into()
        .map_err(|_| LocatorError::Malformed("truncated"))?;
    let identity =
        PublicIdentity::from_bytes(&ik_ed_bytes).map_err(LocatorError::InvalidIdentity)?;

    // Authenticate the whole payload under the embedded identity (a locator is
    // self-signed; the DHT-key binding below is what ties it to a fingerprint).
    let signature: &[u8; SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| LocatorError::Malformed("truncated signature"))?;
    identity
        .verify(LOCATOR_SIGNING_DOMAIN, payload, signature)
        .map_err(|_| LocatorError::BadSignature)?;

    // Key binding: the identity must hash to the DHT key it lives under, so a
    // record cannot be planted under a fingerprint its signer does not own.
    if &own_locator_key(&identity) != dht_key {
        return Err(LocatorError::KeyMismatch);
    }

    let published_at = u64::from_be_bytes(
        payload[PUBLISHED_AT_OFFSET..PUBLISHED_AT_OFFSET + 8]
            .try_into()
            .map_err(|_| LocatorError::Malformed("truncated"))?,
    );

    Ok(DhtLocator {
        identity,
        addrs,
        published_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Seed32;

    fn identity(fill: u8) -> IdentityKeypair {
        IdentityKeypair::from_seed(&Seed32::from_bytes([fill; 32]))
    }

    fn addrs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The DHT key an identity's own locator lives under.
    fn key_for(id: &IdentityKeypair) -> [u8; 32] {
        own_locator_key(&id.public())
    }

    #[test]
    fn seal_open_round_trip() {
        let signer = identity(0x21);
        let a = addrs(&["/ip4/198.51.100.7/tcp/4001", "/ip4/203.0.113.9/tcp/4001"]);
        let wire = seal_locator(&signer, &a, 1_700_000_000).expect("seal");

        let loc = open_locator(&wire, &key_for(&signer)).expect("open");
        assert_eq!(loc.identity(), &signer.public());
        assert_eq!(loc.published_at(), 1_700_000_000);
        // Canonical (sorted) order.
        assert_eq!(
            loc.addrs(),
            &["/ip4/198.51.100.7/tcp/4001", "/ip4/203.0.113.9/tcp/4001"]
        );
    }

    #[test]
    fn empty_address_list_is_valid() {
        // A NAT-bound peer with no globally-routable address: discoverable,
        // not directly connectable (connection awaits M5).
        let signer = identity(0x21);
        let wire = seal_locator(&signer, &[], 1).expect("seal");
        let loc = open_locator(&wire, &key_for(&signer)).expect("open");
        assert!(loc.addrs().is_empty());
    }

    #[test]
    fn addresses_are_sorted_and_deduped_on_seal() {
        let signer = identity(0x21);
        let a = addrs(&[
            "/ip4/9.9.9.9/tcp/1",
            "/ip4/1.1.1.1/tcp/1",
            "/ip4/9.9.9.9/tcp/1",
        ]);
        let wire = seal_locator(&signer, &a, 1).expect("seal");
        let loc = open_locator(&wire, &key_for(&signer)).expect("open");
        assert_eq!(loc.addrs(), &["/ip4/1.1.1.1/tcp/1", "/ip4/9.9.9.9/tcp/1"]);
    }

    #[test]
    fn key_mismatch_is_rejected() {
        // A record signed by one identity but fetched under another's DHT key
        // (an attacker planting a locator under someone else's fingerprint).
        let signer = identity(0x21);
        let victim = identity(0x99);
        let wire = seal_locator(&signer, &addrs(&["/ip4/9.9.9.9/tcp/1"]), 1).expect("seal");
        assert!(matches!(
            open_locator(&wire, &key_for(&victim)),
            Err(LocatorError::KeyMismatch)
        ));
    }

    #[test]
    fn bad_signature_is_rejected() {
        let signer = identity(0x21);
        let mut wire = seal_locator(&signer, &addrs(&["/ip4/9.9.9.9/tcp/1"]), 1).expect("seal");
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        assert!(matches!(
            open_locator(&wire, &key_for(&signer)),
            Err(LocatorError::BadSignature)
        ));
        // Tampering with the payload (an address byte) also breaks the signature.
        let mut wire = seal_locator(&signer, &addrs(&["/ip4/9.9.9.9/tcp/1"]), 1).expect("seal");
        wire[ADDRS_OFFSET + 3] ^= 0x01;
        assert!(matches!(
            open_locator(&wire, &key_for(&signer)),
            Err(LocatorError::BadSignature)
        ));
    }

    #[test]
    fn hostile_identity_key_is_rejected() {
        // Hand-craft a locator whose embedded identity is the all-zero key
        // (off-curve / rejected by strict validation). We cannot sign for it,
        // but validation must reject on the key before ever trusting a sig.
        let mut payload = Vec::new();
        payload.push(LOCATOR_VERSION);
        payload.extend_from_slice(&[0u8; 32]); // zero identity key
        payload.extend_from_slice(&1u64.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        let mut wire = payload;
        wire.extend_from_slice(&[0u8; SIGNATURE_LEN]);
        let key = dht_locator_key("whatever");
        assert!(matches!(
            open_locator(&wire, &key),
            Err(LocatorError::InvalidIdentity(_))
        ));
    }

    #[test]
    fn truncations_and_trailing_bytes_are_clean_errors() {
        let signer = identity(0x21);
        let wire = seal_locator(&signer, &addrs(&["/ip4/9.9.9.9/tcp/1"]), 1).expect("seal");
        let key = key_for(&signer);
        for len in [
            0,
            1,
            ADDRS_OFFSET,
            ADDRS_OFFSET + SIGNATURE_LEN - 1,
            wire.len() - 1,
        ] {
            assert!(
                matches!(
                    open_locator(&wire[..len], &key),
                    Err(LocatorError::Malformed(_))
                ),
                "a {len}-byte prefix must be malformed"
            );
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(matches!(
            open_locator(&trailing, &key),
            Err(LocatorError::Malformed(_))
        ));
    }

    #[test]
    fn forged_addr_count_is_a_clean_error() {
        let signer = identity(0x21);
        let mut wire = seal_locator(&signer, &addrs(&["/ip4/9.9.9.9/tcp/1"]), 1).expect("seal");
        // Absurd count: rejected by the cap before any allocation.
        wire[ADDR_COUNT_OFFSET] = 0xff;
        wire[ADDR_COUNT_OFFSET + 1] = 0xff;
        assert!(matches!(
            open_locator(&wire, &key_for(&signer)),
            Err(LocatorError::TooManyAddresses { .. })
        ));
    }

    #[test]
    fn unknown_version_is_a_clean_error() {
        let signer = identity(0x21);
        let mut wire = seal_locator(&signer, &addrs(&["/ip4/9.9.9.9/tcp/1"]), 1).expect("seal");
        wire[VERSION_OFFSET] = LOCATOR_VERSION + 1;
        assert!(matches!(
            open_locator(&wire, &key_for(&signer)),
            Err(LocatorError::UnsupportedVersion { found }) if found == LOCATOR_VERSION + 1
        ));
    }

    #[test]
    fn too_many_addresses_rejected_on_seal() {
        let signer = identity(0x21);
        let many: Vec<String> = (0..=MAX_LOCATOR_ADDRS)
            .map(|i| format!("/ip4/10.0.0.{i}/tcp/1"))
            .collect();
        assert!(matches!(
            seal_locator(&signer, &many, 1),
            Err(LocatorError::TooManyAddresses { .. })
        ));
    }

    #[test]
    fn oversized_address_rejected_on_seal() {
        let signer = identity(0x21);
        let long = "x".repeat(MAX_ADDR_LEN + 1);
        assert!(matches!(
            seal_locator(&signer, &[long], 1),
            Err(LocatorError::AddressTooLong)
        ));
    }

    #[test]
    fn non_canonical_address_order_is_rejected() {
        // Hand-sign a locator with descending addresses: the canonical-order
        // check must reject it even though the signature is valid.
        let signer = identity(0x21);
        let mut payload = Vec::new();
        payload.push(LOCATOR_VERSION);
        payload.extend_from_slice(signer.public().as_bytes());
        payload.extend_from_slice(&1u64.to_be_bytes());
        payload.extend_from_slice(&2u16.to_be_bytes());
        for a in ["/ip4/9.9.9.9/tcp/1", "/ip4/1.1.1.1/tcp/1"] {
            payload.extend_from_slice(&(a.len() as u16).to_be_bytes());
            payload.extend_from_slice(a.as_bytes());
        }
        let sig = signer.sign(LOCATOR_SIGNING_DOMAIN, &payload);
        let mut wire = payload;
        wire.extend_from_slice(&sig);
        assert!(matches!(
            open_locator(&wire, &key_for(&signer)),
            Err(LocatorError::Malformed(_))
        ));
    }

    #[test]
    fn dht_key_is_deterministic_and_binds_to_the_short_fingerprint() {
        let id = identity(0x42).public();
        assert_eq!(
            own_locator_key(&id),
            dht_locator_key(&id.fingerprint().short())
        );
        // Different fingerprints → different keys.
        let other = identity(0x43).public();
        assert_ne!(own_locator_key(&id), own_locator_key(&other));
    }
}
