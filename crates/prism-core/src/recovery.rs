// SPDX-License-Identifier: AGPL-3.0-or-later
//! Optional identity recovery via a BIP-39 mnemonic.
//!
//! At `init` the user chooses between two modes (spec §4.2):
//! - **zero-recovery** — the identity seed comes straight from the OS CSPRNG
//!   and nothing can regenerate it (see [`crate::secret::Seed32::generate`]);
//! - **recovery phrase** — a 12-word English BIP-39 mnemonic is generated from
//!   OS-CSPRNG entropy and the identity seed is *derived* from it, so the
//!   phrase alone regenerates the identity later.
//!
//! Derivation chain (documented, frozen — changing any step would change every
//! recovered identity):
//!
//! ```text
//! mnemonic --BIP-39 seed derivation, empty passphrase--> 64-byte seed
//!          --HKDF-SHA512(salt = none, info = IDENTITY_KDF_INFO)--> 32-byte Ed25519 seed
//! ```
//!
//! The mnemonic is **never stored**: the keystore persists only the derived
//! seed, identically to zero-recovery mode, which is what makes the on-disk
//! format indistinguishable between modes (spec §18.6).

use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::secret::{fill_random, RngError, Seed32};

/// Number of words in a Prism recovery phrase. 12 words carry 128 bits of
/// entropy, matching Ed25519's ~128-bit security level; more words would add
/// transcription risk without adding real key security.
pub const MNEMONIC_WORD_COUNT: usize = 12;

/// Entropy fed into mnemonic generation: 128 bits for 12 words.
const MNEMONIC_ENTROPY_LEN: usize = 16;

/// HKDF-SHA512 domain-separation label for deriving the Ed25519 identity seed
/// from a BIP-39 seed. Frozen: changing it would break every recovery phrase
/// already handed out.
pub const IDENTITY_KDF_INFO: &[u8] = b"prism v1 identity ed25519";

/// A recovery phrase could not be generated, parsed, or turned into a seed.
///
/// Variants never carry the offending words themselves — at most a 1-based
/// word position — so they are safe to display and log.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// The OS CSPRNG failed while drawing mnemonic entropy.
    #[error(transparent)]
    Rng(#[from] RngError),
    /// The phrase does not have exactly [`MNEMONIC_WORD_COUNT`] words.
    #[error("a Prism recovery phrase has exactly {MNEMONIC_WORD_COUNT} words (found {found})")]
    WordCount {
        /// How many words were supplied.
        found: usize,
    },
    /// A word is not in the English BIP-39 word list.
    #[error("word {position} is not a valid recovery word (check for typos)")]
    UnknownWord {
        /// 1-based position of the unrecognized word.
        position: usize,
    },
    /// All words are valid but the checksum does not match: a word is wrong,
    /// missing, or out of order.
    #[error("checksum mismatch: a word is wrong or out of order (re-check the phrase)")]
    Checksum,
    /// Any other reason the phrase is invalid.
    #[error("invalid recovery phrase")]
    Invalid,
    /// The HKDF expansion failed (cannot happen for a 32-byte output; kept as
    /// an explicit error instead of a panic path).
    #[error("identity key derivation failed")]
    Kdf,
}

/// A BIP-39 recovery phrase.
///
/// No `Clone`, `Debug`, or `Display`; the words are only reachable through
/// [`RecoveryPhrase::expose_phrase`]. The inner `bip39::Mnemonic` is zeroized
/// on drop (its `zeroize` feature is enabled workspace-wide).
pub struct RecoveryPhrase(Mnemonic);

impl RecoveryPhrase {
    /// Generate a fresh 12-word phrase from OS-CSPRNG entropy.
    pub fn generate() -> Result<Self, RecoveryError> {
        let mut entropy = Zeroizing::new([0u8; MNEMONIC_ENTROPY_LEN]);
        fill_random(entropy.as_mut())?;
        let mnemonic = Mnemonic::from_entropy(entropy.as_ref())
            // 16 bytes is always a valid entropy length; still no panic path.
            .map_err(|_| RecoveryError::Invalid)?;
        Ok(Self(mnemonic))
    }

    /// Parse a user-supplied phrase.
    ///
    /// Whitespace layout and ASCII case are forgiven (words may be separated
    /// by any whitespace and typed in any case); everything else — word count,
    /// word validity, checksum — is strictly validated.
    pub fn parse(input: &str) -> Result<Self, RecoveryError> {
        let found = input.split_whitespace().count();
        if found != MNEMONIC_WORD_COUNT {
            return Err(RecoveryError::WordCount { found });
        }

        // Normalize into a single zeroized buffer, one char at a time, to
        // avoid scattering un-wiped copies of the words across the heap.
        let mut normalized = Zeroizing::new(String::with_capacity(input.len()));
        for (i, word) in input.split_whitespace().enumerate() {
            if i > 0 {
                normalized.push(' ');
            }
            for c in word.chars() {
                normalized.push(c.to_ascii_lowercase());
            }
        }

        let mnemonic =
            Mnemonic::parse_in_normalized(Language::English, &normalized).map_err(|e| match e {
                bip39::Error::UnknownWord(index) => RecoveryError::UnknownWord {
                    position: index + 1,
                },
                bip39::Error::InvalidChecksum => RecoveryError::Checksum,
                bip39::Error::BadWordCount(found) => RecoveryError::WordCount { found },
                _ => RecoveryError::Invalid,
            })?;
        Ok(Self(mnemonic))
    }

    /// Derive the Ed25519 identity seed from this phrase (the documented,
    /// frozen chain: BIP-39 seed with empty passphrase, then HKDF-SHA512 with
    /// [`IDENTITY_KDF_INFO`]). Deterministic: the phrase alone regenerates the
    /// identity.
    pub fn derive_identity_seed(&self) -> Result<Seed32, RecoveryError> {
        let bip39_seed = Zeroizing::new(self.0.to_seed_normalized(""));
        let hkdf = Hkdf::<Sha512>::new(None, bip39_seed.as_ref());
        let mut okm = Zeroizing::new([0u8; Seed32::LEN]);
        hkdf.expand(IDENTITY_KDF_INFO, okm.as_mut())
            .map_err(|_| RecoveryError::Kdf)?;
        Ok(Seed32::from_bytes(*okm))
    }

    /// The phrase as a single space-separated string, in a zeroized buffer.
    /// For one-time display at `init` and for transporting a just-typed phrase
    /// to the daemon; never persist it.
    pub fn expose_phrase(&self) -> Zeroizing<String> {
        let mut s = Zeroizing::new(String::new());
        for (i, word) in self.0.words().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            s.push_str(word);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid 12-word vector (Trezor official test vector #1).
    const KNOWN_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon about";

    #[test]
    fn generated_phrase_has_12_words_and_round_trips() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let text = phrase.expose_phrase();
        assert_eq!(text.split_whitespace().count(), MNEMONIC_WORD_COUNT);

        let reparsed = RecoveryPhrase::parse(&text).unwrap();
        assert_eq!(
            reparsed.derive_identity_seed().unwrap().expose(),
            phrase.derive_identity_seed().unwrap().expose(),
            "reparsing the displayed phrase must regenerate the same identity"
        );
    }

    #[test]
    fn two_generated_phrases_differ() {
        let a = RecoveryPhrase::generate().unwrap().expose_phrase();
        let b = RecoveryPhrase::generate().unwrap().expose_phrase();
        assert_ne!(*a, *b);
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = RecoveryPhrase::parse(KNOWN_PHRASE).unwrap();
        let b = RecoveryPhrase::parse(KNOWN_PHRASE).unwrap();
        assert_eq!(
            a.derive_identity_seed().unwrap().expose(),
            b.derive_identity_seed().unwrap().expose()
        );
    }

    #[test]
    fn parse_forgives_case_and_whitespace() {
        let messy = "  Abandon ABANDON abandon\tabandon abandon abandon \n abandon abandon \
                     abandon abandon abandon aboUt ";
        let a = RecoveryPhrase::parse(messy).unwrap();
        let b = RecoveryPhrase::parse(KNOWN_PHRASE).unwrap();
        assert_eq!(
            a.derive_identity_seed().unwrap().expose(),
            b.derive_identity_seed().unwrap().expose()
        );
    }

    #[test]
    fn parse_rejects_wrong_word_count() {
        assert!(matches!(
            RecoveryPhrase::parse("abandon abandon abandon"),
            Err(RecoveryError::WordCount { found: 3 })
        ));
    }

    #[test]
    fn parse_rejects_unknown_word_with_its_position() {
        let phrase = "abandon abandon abandon abandon abandon prisme abandon abandon abandon \
                      abandon abandon about";
        assert!(matches!(
            RecoveryPhrase::parse(phrase),
            Err(RecoveryError::UnknownWord { position: 6 })
        ));
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        // All valid words, but the last one breaks the checksum.
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon";
        assert!(matches!(
            RecoveryPhrase::parse(phrase),
            Err(RecoveryError::Checksum)
        ));
    }
}
