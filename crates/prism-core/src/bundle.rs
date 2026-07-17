// SPDX-License-Identifier: AGPL-3.0-or-later
//! Identity-signed prekey bundles.
//!
//! A bundle is the artifact a peer publishes so that strangers can establish
//! an encrypted session asynchronously (spec §5.1). It carries the vodozemac
//! Curve25519 key material, subordinated to the M1 Ed25519 identity by **one
//! signature over the whole canonical payload** — every key in the bundle is
//! identity-signed, and nothing from a bundle may be used before both the
//! identity match and the signature verify.
//!
//! Canonical wire layout (fixed order, deterministic — signatures require
//! byte-exact reproducibility, which protobuf does not guarantee):
//!
//! ```text
//! signed payload                          wire bundle = payload ‖ sig[64]
//!   0        version        u8 = 1
//!   1..33    ik_ed25519     [32]  M1 identity key (self-description)
//!   33..65   ik_curve25519  [32]  vodozemac account identity key
//!   65..97   fallback_key   [32]  reusable last resort ("signed prekey" role)
//!   97..99   otk_count      u16 BE (≤ MAX_ONE_TIME_KEYS)
//!   99..     otk_i          [32] × count, strictly ascending bytewise
//! ```
//!
//! The strict ascending order makes the encoding canonical (and rejects
//! duplicates); the exact-length check rejects trailing bytes. The signature
//! is made with [`crate::IdentityKeypair::sign`] under
//! [`BUNDLE_SIGNING_DOMAIN`], so it can never be confused with any other
//! Prism signature.
//!
//! Consumers **must** pass the identity they expect (obtained out of band,
//! e.g. from the contact's handle): the embedded `ik_ed25519` is
//! self-description for directories, never a trust root — there is no
//! "trust the embedded key" path.

use crate::identity::{IdentityKeypair, PublicIdentity, SIGNATURE_LEN};
use crate::validate::{validate_x25519_public, KeyRejection};

/// Current bundle wire-format version.
pub const BUNDLE_VERSION: u8 = 1;

/// Hard cap on one-time keys accepted in a bundle (parse bound).
pub const MAX_ONE_TIME_KEYS: usize = 64;

/// Default number of one-time keys in a published bundle. 20 keeps the wire
/// bundle near ~800 bytes — comfortably under DHT-record fragmentation
/// thresholds for M4 — while covering bursts of asynchronous first contacts.
pub const DEFAULT_ONE_TIME_KEYS: usize = 20;

/// Domain for the bundle signature (see [`crate::IdentityKeypair::sign`]).
pub const BUNDLE_SIGNING_DOMAIN: &[u8] = b"prism v1 prekey bundle";

/// Fixed byte offsets of the canonical layout.
const VERSION_OFFSET: usize = 0;
const IK_ED_OFFSET: usize = 1;
const IK_CURVE_OFFSET: usize = 33;
const FALLBACK_OFFSET: usize = 65;
const COUNT_OFFSET: usize = 97;
const OTKS_OFFSET: usize = 99;

/// Which key slot of a bundle (or message) a rejection applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySlot {
    /// The embedded Ed25519 identity key.
    IdentityEd25519,
    /// The Curve25519 account identity key.
    IdentityCurve25519,
    /// The reusable fallback key.
    FallbackKey,
    /// The i-th one-time key.
    OneTimeKey(u16),
}

/// Errors produced while building or ingesting a bundle. Never carries key
/// bytes or any secret.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// Structurally invalid wire bytes (truncated, trailing bytes, bad order).
    #[error("malformed prekey bundle: {0}")]
    Malformed(&'static str),
    /// The bundle declares a version this build does not understand.
    #[error("unsupported prekey bundle version {found} (this build supports {BUNDLE_VERSION})")]
    UnsupportedVersion {
        /// The version byte found in the bundle.
        found: u8,
    },
    /// More one-time keys than [`MAX_ONE_TIME_KEYS`].
    #[error("prekey bundle declares too many one-time keys ({count})")]
    TooManyKeys {
        /// The declared count.
        count: usize,
    },
    /// A key failed strict ingestion validation (spec §5.3).
    #[error("prekey bundle key {slot:?} rejected: {reason}")]
    InvalidKey {
        /// Which key was rejected.
        slot: KeySlot,
        /// Why it was rejected.
        reason: KeyRejection,
    },
    /// The embedded identity is not the identity the caller expected.
    #[error("prekey bundle belongs to a different identity than expected")]
    WrongIdentity,
    /// The identity signature over the payload did not verify.
    #[error("prekey bundle signature is invalid")]
    BadSignature,
}

/// A parsed and fully validated prekey bundle. All fields are public key
/// material (`Debug` is therefore fine); every one passed strict validation
/// and the whole payload is covered by the verified identity signature.
#[derive(Debug)]
pub struct PrekeyBundle {
    identity: PublicIdentity,
    ik_curve: [u8; 32],
    fallback: [u8; 32],
    one_time_keys: Vec<[u8; 32]>,
}

impl PrekeyBundle {
    /// The identity that signed this bundle (equal to the expected identity
    /// passed to [`open_bundle`]).
    pub fn identity(&self) -> &PublicIdentity {
        &self.identity
    }

    /// The Curve25519 account identity key.
    pub fn ik_curve(&self) -> &[u8; 32] {
        &self.ik_curve
    }

    /// The reusable fallback key.
    pub fn fallback(&self) -> &[u8; 32] {
        &self.fallback
    }

    /// The one-time keys, in canonical (ascending) order.
    pub fn one_time_keys(&self) -> &[[u8; 32]] {
        &self.one_time_keys
    }
}

/// Encode the canonical signed payload (everything but the signature).
fn canonical_payload(
    ik_ed: &[u8; 32],
    ik_curve: &[u8; 32],
    fallback: &[u8; 32],
    sorted_otks: &[[u8; 32]],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(OTKS_OFFSET + 32 * sorted_otks.len());
    payload.push(BUNDLE_VERSION);
    payload.extend_from_slice(ik_ed);
    payload.extend_from_slice(ik_curve);
    payload.extend_from_slice(fallback);
    // Cast is exact: the caller bounds the count by MAX_ONE_TIME_KEYS < u16::MAX.
    payload.extend_from_slice(&(sorted_otks.len() as u16).to_be_bytes());
    for otk in sorted_otks {
        payload.extend_from_slice(otk);
    }
    payload
}

/// Build and sign a bundle over the given key material.
///
/// One-time keys are sorted into canonical order; duplicates are rejected.
/// The signature is made by `identity` under [`BUNDLE_SIGNING_DOMAIN`] and
/// covers the entire payload.
pub fn seal_bundle(
    identity: &IdentityKeypair,
    ik_curve: &[u8; 32],
    fallback: &[u8; 32],
    one_time_keys: &[[u8; 32]],
) -> Result<Vec<u8>, BundleError> {
    if one_time_keys.len() > MAX_ONE_TIME_KEYS {
        return Err(BundleError::TooManyKeys {
            count: one_time_keys.len(),
        });
    }

    let mut sorted: Vec<[u8; 32]> = one_time_keys.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(BundleError::Malformed("duplicate one-time key"));
    }

    let ik_ed = identity.public();
    let payload = canonical_payload(ik_ed.as_bytes(), ik_curve, fallback, &sorted);
    let signature = identity.sign(BUNDLE_SIGNING_DOMAIN, &payload);

    let mut wire = payload;
    wire.extend_from_slice(&signature);
    Ok(wire)
}

/// Parse, validate, and authenticate a received bundle.
///
/// Rejection order: shape (length/version/count/order) → embedded identity
/// key validation → identity match against `expected` → signature under
/// `expected` → strict validation of every Curve25519 key. Nothing from the
/// bundle is returned unless every step passed.
pub fn open_bundle(expected: &PublicIdentity, bytes: &[u8]) -> Result<PrekeyBundle, BundleError> {
    // Shape: enough bytes for the fixed fields and the signature?
    if bytes.len() < OTKS_OFFSET + SIGNATURE_LEN {
        return Err(BundleError::Malformed("truncated"));
    }
    let version = bytes[VERSION_OFFSET];
    if version != BUNDLE_VERSION {
        return Err(BundleError::UnsupportedVersion { found: version });
    }

    let count_bytes: [u8; 2] = bytes[COUNT_OFFSET..COUNT_OFFSET + 2]
        .try_into()
        .map_err(|_| BundleError::Malformed("truncated"))?;
    let count = usize::from(u16::from_be_bytes(count_bytes));
    if count > MAX_ONE_TIME_KEYS {
        return Err(BundleError::TooManyKeys { count });
    }
    let payload_len = OTKS_OFFSET + 32 * count;
    // Exact length: reject both truncation and trailing bytes.
    if bytes.len() != payload_len + SIGNATURE_LEN {
        return Err(BundleError::Malformed(
            "length does not match declared key count",
        ));
    }
    let (payload, signature) = bytes.split_at(payload_len);

    // Embedded identity key: validate strictly, then require it to be the
    // identity the caller already expects (out-of-band knowledge).
    let ik_ed_bytes: [u8; 32] = payload[IK_ED_OFFSET..IK_ED_OFFSET + 32]
        .try_into()
        .map_err(|_| BundleError::Malformed("truncated"))?;
    let embedded =
        PublicIdentity::from_bytes(&ik_ed_bytes).map_err(|reason| BundleError::InvalidKey {
            slot: KeySlot::IdentityEd25519,
            reason,
        })?;
    if &embedded != expected {
        return Err(BundleError::WrongIdentity);
    }

    // Authenticate the whole payload before touching the curve keys.
    let signature: &[u8; SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| BundleError::Malformed("truncated signature"))?;
    expected
        .verify(BUNDLE_SIGNING_DOMAIN, payload, signature)
        .map_err(|_| BundleError::BadSignature)?;

    // Strictly validate every Curve25519 key (spec §5.3).
    let ik_curve: [u8; 32] = payload[IK_CURVE_OFFSET..IK_CURVE_OFFSET + 32]
        .try_into()
        .map_err(|_| BundleError::Malformed("truncated"))?;
    validate_x25519_public(&ik_curve).map_err(|reason| BundleError::InvalidKey {
        slot: KeySlot::IdentityCurve25519,
        reason,
    })?;

    let fallback: [u8; 32] = payload[FALLBACK_OFFSET..FALLBACK_OFFSET + 32]
        .try_into()
        .map_err(|_| BundleError::Malformed("truncated"))?;
    validate_x25519_public(&fallback).map_err(|reason| BundleError::InvalidKey {
        slot: KeySlot::FallbackKey,
        reason,
    })?;

    let mut one_time_keys = Vec::with_capacity(count);
    for i in 0..count {
        let start = OTKS_OFFSET + 32 * i;
        let otk: [u8; 32] = payload[start..start + 32]
            .try_into()
            .map_err(|_| BundleError::Malformed("truncated"))?;
        // Cast is exact: i < count <= MAX_ONE_TIME_KEYS < u16::MAX.
        validate_x25519_public(&otk).map_err(|reason| BundleError::InvalidKey {
            slot: KeySlot::OneTimeKey(i as u16),
            reason,
        })?;
        if let Some(previous) = one_time_keys.last() {
            if *previous >= otk {
                return Err(BundleError::Malformed(
                    "one-time keys not in canonical order",
                ));
            }
        }
        one_time_keys.push(otk);
    }

    Ok(PrekeyBundle {
        identity: embedded,
        ik_curve,
        fallback,
        one_time_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Seed32;

    fn identity(fill: u8) -> IdentityKeypair {
        IdentityKeypair::from_seed(&Seed32::from_bytes([fill; 32]))
    }

    /// A canonical, valid, non-blocklisted X25519 u-coordinate.
    fn x_key(fill: u8) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = fill;
        key[1] = 1;
        key
    }

    fn valid_bundle_with(otks: &[[u8; 32]]) -> (IdentityKeypair, Vec<u8>) {
        let signer = identity(0x21);
        let wire = seal_bundle(&signer, &x_key(2), &x_key(3), otks).expect("seal");
        (signer, wire)
    }

    #[test]
    fn seal_open_round_trip() {
        let otks = [x_key(10), x_key(5), x_key(7)];
        let (signer, wire) = valid_bundle_with(&otks);

        let bundle = open_bundle(&signer.public(), &wire).expect("open");
        assert_eq!(bundle.identity(), &signer.public());
        assert_eq!(bundle.ik_curve(), &x_key(2));
        assert_eq!(bundle.fallback(), &x_key(3));
        // Sorted into canonical order.
        assert_eq!(bundle.one_time_keys(), &[x_key(5), x_key(7), x_key(10)]);
    }

    #[test]
    fn zero_one_time_keys_is_a_valid_bundle() {
        let (signer, wire) = valid_bundle_with(&[]);
        let bundle = open_bundle(&signer.public(), &wire).expect("open");
        assert!(bundle.one_time_keys().is_empty());
    }

    #[test]
    fn wrong_identity_is_rejected_before_signature() {
        let (_signer, wire) = valid_bundle_with(&[x_key(5)]);
        let other = identity(0x22);
        assert!(matches!(
            open_bundle(&other.public(), &wire),
            Err(BundleError::WrongIdentity)
        ));
    }

    #[test]
    fn bad_signature_is_rejected() {
        let (signer, mut wire) = valid_bundle_with(&[x_key(5)]);
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        assert!(matches!(
            open_bundle(&signer.public(), &wire),
            Err(BundleError::BadSignature)
        ));
        // Tampering with the payload also breaks the signature.
        let (signer, mut wire) = valid_bundle_with(&[x_key(5)]);
        wire[FALLBACK_OFFSET] ^= 0x01;
        assert!(matches!(
            open_bundle(&signer.public(), &wire),
            Err(BundleError::BadSignature)
        ));
    }

    #[test]
    fn hostile_curve_keys_are_rejected_per_slot() {
        // A bundle whose signature is VALID but which contains a hostile key
        // in each Curve25519 slot: signed-but-poisonous must still fail.
        let zero = [0u8; 32];
        let mut low_order = [0u8; 32];
        low_order[0] = 0x01; // u = 1, small order

        let signer = identity(0x21);
        let cases: [(Vec<u8>, KeySlot); 3] = [
            (
                seal_bundle(&signer, &zero, &x_key(3), &[x_key(5)]).expect("seal"),
                KeySlot::IdentityCurve25519,
            ),
            (
                seal_bundle(&signer, &x_key(2), &low_order, &[x_key(5)]).expect("seal"),
                KeySlot::FallbackKey,
            ),
            (
                seal_bundle(&signer, &x_key(2), &x_key(3), &[zero]).expect("seal"),
                KeySlot::OneTimeKey(0),
            ),
        ];
        for (wire, expected_slot) in cases {
            match open_bundle(&signer.public(), &wire) {
                Err(BundleError::InvalidKey { slot, .. }) => assert_eq!(slot, expected_slot),
                other => panic!("expected InvalidKey for {expected_slot:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn truncations_and_trailing_bytes_are_clean_errors() {
        let (signer, wire) = valid_bundle_with(&[x_key(5), x_key(6)]);
        for len in [
            0,
            1,
            OTKS_OFFSET,
            OTKS_OFFSET + SIGNATURE_LEN - 1,
            wire.len() - 1,
        ] {
            assert!(
                matches!(
                    open_bundle(&signer.public(), &wire[..len]),
                    Err(BundleError::Malformed(_))
                ),
                "a {len}-byte prefix must be malformed"
            );
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(matches!(
            open_bundle(&signer.public(), &trailing),
            Err(BundleError::Malformed(_))
        ));
    }

    #[test]
    fn forged_count_field_is_a_clean_error() {
        let (signer, mut wire) = valid_bundle_with(&[x_key(5), x_key(6)]);
        // Claim 3 keys while carrying 2: length mismatch.
        wire[COUNT_OFFSET + 1] = 3;
        assert!(matches!(
            open_bundle(&signer.public(), &wire),
            Err(BundleError::Malformed(_))
        ));
        // Absurd count: rejected by the cap before any allocation.
        wire[COUNT_OFFSET] = 0xff;
        wire[COUNT_OFFSET + 1] = 0xff;
        assert!(matches!(
            open_bundle(&signer.public(), &wire),
            Err(BundleError::TooManyKeys { .. })
        ));
    }

    #[test]
    fn unknown_version_is_a_clean_error() {
        let (signer, mut wire) = valid_bundle_with(&[x_key(5)]);
        wire[VERSION_OFFSET] = BUNDLE_VERSION + 1;
        assert!(matches!(
            open_bundle(&signer.public(), &wire),
            Err(BundleError::UnsupportedVersion { found }) if found == BUNDLE_VERSION + 1
        ));
    }

    #[test]
    fn duplicate_one_time_keys_are_rejected_on_both_sides() {
        let signer = identity(0x21);
        assert!(matches!(
            seal_bundle(&signer, &x_key(2), &x_key(3), &[x_key(5), x_key(5)]),
            Err(BundleError::Malformed(_))
        ));
        // Hand-craft a signed bundle with an out-of-order/duplicate list: the
        // canonical-order check must reject it even though the signature is
        // valid (sign it ourselves).
        let payload = {
            let ik_ed = signer.public();
            let mut p = Vec::new();
            p.push(BUNDLE_VERSION);
            p.extend_from_slice(ik_ed.as_bytes());
            p.extend_from_slice(&x_key(2));
            p.extend_from_slice(&x_key(3));
            p.extend_from_slice(&2u16.to_be_bytes());
            p.extend_from_slice(&x_key(6));
            p.extend_from_slice(&x_key(5)); // descending: not canonical
            p
        };
        let sig = signer.sign(BUNDLE_SIGNING_DOMAIN, &payload);
        let mut wire = payload;
        wire.extend_from_slice(&sig);
        assert!(matches!(
            open_bundle(&signer.public(), &wire),
            Err(BundleError::Malformed(_))
        ));
    }

    #[test]
    fn too_many_keys_rejected_on_seal() {
        let signer = identity(0x21);
        let mut otks = Vec::new();
        for i in 0..=MAX_ONE_TIME_KEYS {
            let mut key = x_key(2);
            key[2] = (i / 256) as u8;
            key[3] = (i % 256) as u8;
            otks.push(key);
        }
        assert!(matches!(
            seal_bundle(&signer, &x_key(2), &x_key(3), &otks),
            Err(BundleError::TooManyKeys { .. })
        ));
    }

    #[test]
    fn default_bundle_size_stays_dht_friendly() {
        // 20 one-time keys: 99 + 640 + 64 = 803 bytes.
        let otks: Vec<[u8; 32]> = (0..DEFAULT_ONE_TIME_KEYS)
            .map(|i| {
                let mut key = x_key(4);
                key[2] = i as u8;
                key
            })
            .collect();
        let (_, wire) = {
            let signer = identity(0x21);
            let wire = seal_bundle(&signer, &x_key(2), &x_key(3), &otks).expect("seal");
            (signer, wire)
        };
        assert_eq!(
            wire.len(),
            OTKS_OFFSET + 32 * DEFAULT_ONE_TIME_KEYS + SIGNATURE_LEN
        );
        assert!(wire.len() < 1024, "bundle must stay well under 1 KiB");
    }
}
