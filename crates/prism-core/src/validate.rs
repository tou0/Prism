// SPDX-License-Identifier: AGPL-3.0-or-later
//! Strict validation of external public keys on ingestion (spec §5.3).
//!
//! Every public key received from outside (prekey bundles, session
//! establishment messages, ratchet keys) passes through this module **before**
//! any cryptographic use — defense in depth on top of whatever `vodozemac`,
//! `x25519-dalek`, or `ed25519-dalek` already do internally. Rejection is a
//! clean typed error; a rejected key never reaches a DH, a signature check
//! never runs under a rejected key, and no session is established on one.
//!
//! What is checked, and why:
//!
//! - **X25519 (Montgomery u-coordinate)**: RFC 7748 implementations *mask*
//!   bit 255 and reduce u mod p, so distinct encodings can denote the same
//!   point; we reject **non-canonical** encodings outright (bit 255 set, or
//!   u ≥ p). We then reject the **small-order points** (libsodium's blocklist,
//!   reduced to canonical form): the zero/identity point and every low-order
//!   point — the "invalid-curve / small-subgroup" class. For Montgomery-u,
//!   every canonical u lies on the curve or its twist and Curve25519 is
//!   twist-secure, so "off-curve" concretely means the non-canonical
//!   encodings rejected above.
//! - **Ed25519**: parse via `ed25519-dalek` (rejects non-decompressible /
//!   off-curve encodings), reject **weak** keys (small-order, including the
//!   identity element), and require **round-trip canonicality**
//!   (`to_bytes() == input`), which rejects encodings that decompress only
//!   after modular reduction.
//!
//! All comparisons here are on *public* material — no secret-dependent
//! branching is involved, so plain (non-constant-time) comparisons are fine.

use ed25519_dalek::VerifyingKey;

/// Why an external public key was rejected. Never carries key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyRejection {
    /// The all-zero point (X25519 u = 0): DH with it yields a known output.
    #[error("public key rejected: zero point")]
    Zero,
    /// A known small-order (low-order) point: subgroup-confinement class.
    #[error("public key rejected: small-order point")]
    SmallOrder,
    /// A non-canonical encoding (bit 255 set, u ≥ p, or re-encoding differs).
    #[error("public key rejected: non-canonical encoding")]
    NonCanonical,
    /// Not a decodable curve point at all.
    #[error("public key rejected: not a valid curve point")]
    OffCurve,
    /// An Ed25519 key of small order (includes the identity element).
    #[error("public key rejected: weak (small-order) key")]
    Weak,
}

/// The Curve25519 prime `p = 2^255 - 19`, little-endian.
const P_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Canonical small-order X25519 u-coordinates (libsodium's blocklist reduced
/// to canonical form — the non-canonical entries `p`, `p + 1`, and every
/// bit-255-set variant are already rejected by the canonicality checks).
///
/// In order: u = 0; u = 1; the two low-order points generating the 8-torsion
/// (`e0eb…b800` and `5f9c…1157`); and u = p − 1 (≡ −1).
const SMALL_ORDER_X25519_LE: [[u8; 32]; 5] = [
    // u = 0
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // u = 1
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // 325606250916557431795983626356110631294008115727848805560023387167927233504
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    // 39382357235489614581723060781553021112529911719440698176882885853963445705823
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // u = p - 1
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// `true` if the little-endian value is strictly less than `p = 2^255 - 19`.
fn is_canonical_field_element(le: &[u8; 32]) -> bool {
    // Compare most-significant byte first.
    for i in (0..32).rev() {
        if le[i] != P_LE[i] {
            return le[i] < P_LE[i];
        }
    }
    false // equal to p: not canonical
}

/// Validate an external X25519 public key (Montgomery u-coordinate).
///
/// Rejects, in order: non-canonical encodings (bit 255 set, or u ≥ p), the
/// zero point, and every canonical small-order point. Accepted keys are safe
/// to feed to a Diffie-Hellman: they cannot confine the shared secret to a
/// small subgroup.
pub fn validate_x25519_public(bytes: &[u8; 32]) -> Result<(), KeyRejection> {
    if bytes[31] & 0x80 != 0 {
        return Err(KeyRejection::NonCanonical);
    }
    if !is_canonical_field_element(bytes) {
        return Err(KeyRejection::NonCanonical);
    }
    if bytes == &SMALL_ORDER_X25519_LE[0] {
        return Err(KeyRejection::Zero);
    }
    for small in &SMALL_ORDER_X25519_LE[1..] {
        if bytes == small {
            return Err(KeyRejection::SmallOrder);
        }
    }
    Ok(())
}

/// Validate and parse an external Ed25519 public key.
///
/// Rejects off-curve (non-decompressible) encodings, non-canonical encodings
/// (round-trip re-encoding differs), and weak (small-order) keys, including
/// the identity element. Crate-internal: the public entry point is
/// [`crate::PublicIdentity::from_bytes`].
pub(crate) fn validate_ed25519_public(bytes: &[u8; 32]) -> Result<VerifyingKey, KeyRejection> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| KeyRejection::OffCurve)?;
    if &key.to_bytes() != bytes {
        return Err(KeyRejection::NonCanonical);
    }
    if key.is_weak() {
        return Err(KeyRejection::Weak);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_blocklist_is_rejected_with_the_right_reason() {
        assert_eq!(
            validate_x25519_public(&SMALL_ORDER_X25519_LE[0]),
            Err(KeyRejection::Zero)
        );
        for small in &SMALL_ORDER_X25519_LE[1..] {
            assert_eq!(validate_x25519_public(small), Err(KeyRejection::SmallOrder));
        }
    }

    #[test]
    fn x25519_non_canonical_encodings_are_rejected() {
        // u = p and u = p + 1 (the non-canonical tail of libsodium's list).
        let mut p = P_LE;
        assert_eq!(validate_x25519_public(&p), Err(KeyRejection::NonCanonical));
        p[0] = 0xee;
        assert_eq!(validate_x25519_public(&p), Err(KeyRejection::NonCanonical));
        // Any encoding with bit 255 set, even of a fine value.
        let mut high_bit = [0u8; 32];
        high_bit[0] = 9;
        high_bit[31] = 0x80;
        assert_eq!(
            validate_x25519_public(&high_bit),
            Err(KeyRejection::NonCanonical)
        );
        // All-ones: bit 255 set.
        assert_eq!(
            validate_x25519_public(&[0xff; 32]),
            Err(KeyRejection::NonCanonical)
        );
    }

    #[test]
    fn x25519_honest_keys_are_accepted() {
        // The Curve25519 base point u = 9.
        let mut base = [0u8; 32];
        base[0] = 9;
        assert_eq!(validate_x25519_public(&base), Ok(()));
        // p - 2: canonical, not small-order.
        let mut p_minus_2 = P_LE;
        p_minus_2[0] = 0xeb;
        assert_eq!(validate_x25519_public(&p_minus_2), Ok(()));
    }

    #[test]
    fn x25519_validation_never_panics_on_any_single_byte_pattern() {
        for fill in 0..=255u8 {
            let _ = validate_x25519_public(&[fill; 32]);
        }
    }

    #[test]
    fn ed25519_identity_element_is_weak() {
        // (0, 1) compresses to 0x01 followed by zeros.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(validate_ed25519_public(&identity), Err(KeyRejection::Weak));
    }

    #[test]
    fn ed25519_zero_bytes_are_rejected() {
        // y = 0 decompresses to a small-order point: must not survive.
        assert!(validate_ed25519_public(&[0u8; 32]).is_err());
    }

    #[test]
    fn ed25519_non_canonical_encoding_is_rejected() {
        // y = p reduces to y = 0 on decompression; re-encoding differs.
        let result = validate_ed25519_public(&P_LE);
        assert!(
            matches!(
                result,
                Err(KeyRejection::NonCanonical)
                    | Err(KeyRejection::OffCurve)
                    | Err(KeyRejection::Weak)
            ),
            "y = p must be rejected, got {result:?}"
        );
    }

    #[test]
    fn ed25519_off_curve_encoding_is_rejected_and_a_real_key_accepted() {
        // Scan for the first single-byte-fill encoding that fails to
        // decompress: a deterministic off-curve vector.
        let mut found_off_curve = false;
        for fill in 2..=255u8 {
            let candidate = [fill; 32];
            if VerifyingKey::from_bytes(&candidate).is_err() {
                assert_eq!(
                    validate_ed25519_public(&candidate),
                    Err(KeyRejection::OffCurve)
                );
                found_off_curve = true;
                break;
            }
        }
        assert!(found_off_curve, "no off-curve fill pattern found");

        // A real key round-trips.
        let keypair = crate::IdentityKeypair::from_seed(&crate::Seed32::from_bytes([7; 32]));
        let bytes = *keypair.public().as_bytes();
        assert!(validate_ed25519_public(&bytes).is_ok());
    }
}
