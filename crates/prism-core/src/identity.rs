// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ed25519 identity keys, fingerprints, and handles.
//!
//! A Prism identity is an Ed25519 key pair. Its public half is displayed as a
//! *handle*, Discord-style (`nick#fingerprint`), where the fingerprint is
//! `base58(blake3(public_key))` truncated to [`SHORT_FINGERPRINT_LEN`]
//! characters (~82 bits — forging a look-alike costs ~2^82 operations, see
//! `docs/specification.md` §4.1). The full fingerprint stays available for
//! SAS/out-of-band verification in later milestones.
//!
//! The private half lives in [`IdentityKeypair`], which derives no
//! `Clone`/`Debug`/`Display` and zeroizes its key material on drop (via
//! `ed25519-dalek`'s `zeroize` feature).

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::secret::{RngError, Seed32};

/// Number of base58 characters shown in the short (handle) fingerprint.
/// 14 characters ≈ 82 bits of the blake3 hash (spec §4.1).
pub const SHORT_FINGERPRINT_LEN: usize = 14;

/// Maximum nickname length, in characters.
pub const NICK_MAX_CHARS: usize = 32;

/// A nickname was rejected by [`validate_nick`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum NickError {
    /// The nickname is empty.
    #[error("nickname must not be empty")]
    Empty,
    /// The nickname exceeds [`NICK_MAX_CHARS`] characters.
    #[error("nickname must not exceed {NICK_MAX_CHARS} characters")]
    TooLong,
    /// The nickname contains `#`, which separates nick and fingerprint in a
    /// handle.
    #[error("nickname must not contain '#'")]
    ContainsHash,
    /// The nickname contains whitespace or a control character.
    #[error("nickname must not contain whitespace or control characters")]
    ForbiddenCharacter,
}

/// Validate a nickname: 1..=[`NICK_MAX_CHARS`] characters, no `#`, no
/// whitespace, no control characters. Nicknames are free and non-unique
/// (uniqueness comes from the fingerprint), so no other restriction applies.
pub fn validate_nick(nick: &str) -> Result<(), NickError> {
    if nick.is_empty() {
        return Err(NickError::Empty);
    }
    if nick.chars().count() > NICK_MAX_CHARS {
        return Err(NickError::TooLong);
    }
    for c in nick.chars() {
        if c == '#' {
            return Err(NickError::ContainsHash);
        }
        if c.is_whitespace() || c.is_control() {
            return Err(NickError::ForbiddenCharacter);
        }
    }
    Ok(())
}

/// An Ed25519 identity key pair (the private half of a Prism identity).
///
/// No `Clone`, `Debug`, or `Display`. Construction is deterministic from a
/// [`Seed32`]: the same seed always yields the same identity, which is what
/// makes mnemonic-based recovery possible.
pub struct IdentityKeypair {
    signing: SigningKey,
}

impl IdentityKeypair {
    /// Generate a fresh identity from the OS CSPRNG (zero-recovery mode).
    pub fn generate() -> Result<Self, RngError> {
        Ok(Self::from_seed(&Seed32::generate()?))
    }

    /// Rebuild the identity from its 32-byte private seed. Deterministic.
    pub fn from_seed(seed: &Seed32) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed.expose()),
        }
    }

    /// Extract the private seed, e.g. to seal it into the keystore.
    pub fn to_seed(&self) -> Seed32 {
        Seed32::from_bytes(self.signing.to_bytes())
    }

    /// The public half of this identity.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity(self.signing.verifying_key())
    }
}

/// The public half of a Prism identity. Public data: freely printable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentity(VerifyingKey);

impl PublicIdentity {
    /// The raw Ed25519 public key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// The blake3 fingerprint of the public key.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint(*blake3::hash(self.0.as_bytes()).as_bytes())
    }

    /// The displayed handle for this identity: `nick#<short fingerprint>`.
    /// Deterministic: the same key and nick always produce the same handle.
    pub fn handle(&self, nick: &str) -> String {
        format!("{nick}#{}", self.fingerprint().short())
    }
}

/// The blake3 hash of an identity public key. Public data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// The raw 32 fingerprint bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The full base58 fingerprint (~44 characters), kept for SAS and
    /// out-of-band verification of the most sensitive exchanges.
    pub fn full(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// The short fingerprint shown in handles: the first
    /// [`SHORT_FINGERPRINT_LEN`] characters of [`Fingerprint::full`].
    /// (base58 is pure ASCII, so character and byte counts coincide.)
    pub fn short(&self) -> String {
        let mut s = self.full();
        s.truncate(SHORT_FINGERPRINT_LEN);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_seed(fill: u8) -> Seed32 {
        Seed32::from_bytes([fill; 32])
    }

    #[test]
    fn same_seed_gives_same_handle() {
        let a = IdentityKeypair::from_seed(&fixed_seed(7));
        let b = IdentityKeypair::from_seed(&fixed_seed(7));
        assert_eq!(a.public(), b.public());
        assert_eq!(a.public().handle("alice"), b.public().handle("alice"));
    }

    #[test]
    fn different_seeds_give_different_fingerprints() {
        let a = IdentityKeypair::from_seed(&fixed_seed(7));
        let b = IdentityKeypair::from_seed(&fixed_seed(8));
        assert_ne!(a.public().fingerprint(), b.public().fingerprint());
    }

    #[test]
    fn seed_round_trips_through_the_keypair() {
        let seed = Seed32::generate().unwrap();
        let keypair = IdentityKeypair::from_seed(&seed);
        assert_eq!(keypair.to_seed().expose(), seed.expose());
    }

    #[test]
    fn short_fingerprint_is_a_14_char_prefix_of_the_full_one() {
        let fp = IdentityKeypair::from_seed(&fixed_seed(42))
            .public()
            .fingerprint();
        let (full, short) = (fp.full(), fp.short());
        assert_eq!(short.len(), SHORT_FINGERPRINT_LEN);
        assert!(full.starts_with(&short));
        assert!(short.is_ascii());
    }

    #[test]
    fn full_fingerprint_is_valid_base58_of_the_hash() {
        let fp = IdentityKeypair::from_seed(&fixed_seed(42))
            .public()
            .fingerprint();
        let decoded = bs58::decode(fp.full()).into_vec().unwrap();
        assert_eq!(decoded.as_slice(), fp.as_bytes());
    }

    #[test]
    fn handle_has_the_expected_shape() {
        let handle = IdentityKeypair::from_seed(&fixed_seed(1))
            .public()
            .handle("alice");
        let (nick, fp) = handle.split_once('#').unwrap();
        assert_eq!(nick, "alice");
        assert_eq!(fp.len(), SHORT_FINGERPRINT_LEN);
    }

    #[test]
    fn nick_validation_accepts_reasonable_nicks() {
        for nick in ["alice", "Alice42", "a", "émilie", "nick-o_matic.9"] {
            assert_eq!(validate_nick(nick), Ok(()), "nick {nick:?} should pass");
        }
    }

    #[test]
    fn nick_validation_rejects_bad_nicks() {
        assert_eq!(validate_nick(""), Err(NickError::Empty));
        assert_eq!(
            validate_nick(&"x".repeat(NICK_MAX_CHARS + 1)),
            Err(NickError::TooLong)
        );
        assert_eq!(validate_nick("al#ce"), Err(NickError::ContainsHash));
        assert_eq!(validate_nick("al ice"), Err(NickError::ForbiddenCharacter));
        assert_eq!(
            validate_nick("al\u{0007}ice"),
            Err(NickError::ForbiddenCharacter)
        );
    }
}
