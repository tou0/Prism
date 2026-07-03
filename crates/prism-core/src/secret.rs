// SPDX-License-Identifier: AGPL-3.0-or-later
//! Secret wrappers shared across the crate.
//!
//! Every secret lives behind a type that (a) zeroizes its memory on drop,
//! (b) derives no `Clone`, `Debug`, or `Display`, and (c) uses a fixed-size,
//! pre-allocated buffer whenever the size is known up front.
//!
//! `mlock` of these regions is deliberately deferred to the M8 hardening pass
//! (see `docs/keystore.md`): until then, secret memory may reach swap. The
//! wrappers keep their backing buffers private so that adding `mlock` later is
//! a change local to this module.

use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// The OS CSPRNG could not produce random bytes.
///
/// This is the only random source Prism uses: production paths never fall back
/// to a seeded or otherwise deterministic RNG, so this error is surfaced
/// instead of degrading.
#[derive(Debug, thiserror::Error)]
#[error("the OS random number generator failed: {0}")]
pub struct RngError(#[from] rand_core::Error);

/// Fill `buf` from the OS CSPRNG (`OsRng`), failing cleanly instead of
/// panicking. All random material in Prism (seeds, salts, nonces, mnemonic
/// entropy) is drawn through this function.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), RngError> {
    OsRng.try_fill_bytes(buf)?;
    Ok(())
}

/// A user passphrase.
///
/// Wraps [`SecretString`]: zeroized on drop, no `Clone`, and nothing to print
/// (this type intentionally implements no `Debug` or `Display`). The passphrase
/// is only ever readable through [`Passphrase::expose_bytes`].
pub struct Passphrase(SecretString);

impl Passphrase {
    /// Wrap an already-wrapped secret string.
    pub fn new(passphrase: SecretString) -> Self {
        Self(passphrase)
    }

    /// Expose the passphrase bytes for key derivation. Keep the borrow short
    /// and never copy the bytes into an unmanaged buffer.
    pub fn expose_bytes(&self) -> &[u8] {
        self.0.expose_secret().as_bytes()
    }

    /// Whether the passphrase is empty. Empty passphrases are rejected by the
    /// keystore (see `keystore::KeystoreError::EmptyPassphrase`).
    pub fn is_empty(&self) -> bool {
        self.0.expose_secret().is_empty()
    }
}

impl From<String> for Passphrase {
    /// Take ownership of `s` (moved, not copied) and treat it as secret from
    /// here on. Intended for input paths (e.g. `rpassword`) that hand us a
    /// plain `String`.
    fn from(s: String) -> Self {
        Self(SecretString::from(s))
    }
}

/// A 32-byte secret (an Ed25519 private seed or derived key material) held in
/// a fixed-size buffer that is zeroized on drop.
///
/// No `Clone`, `Debug`, or `Display`; the bytes are only reachable through
/// [`Seed32::expose`].
pub struct Seed32(Zeroizing<[u8; Self::LEN]>);

impl Seed32 {
    /// Byte length of the seed.
    pub const LEN: usize = 32;

    /// Generate a fresh seed from the OS CSPRNG.
    pub fn generate() -> Result<Self, RngError> {
        let mut buf = Zeroizing::new([0u8; Self::LEN]);
        fill_random(buf.as_mut())?;
        Ok(Self(buf))
    }

    /// Wrap raw seed bytes, taking ownership.
    ///
    /// The caller must not retain another copy of `bytes`; prefer moving a
    /// value whose source container is itself zeroized on drop.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Expose the seed bytes. Keep the borrow as short as possible and never
    /// copy the bytes into an unmanaged buffer.
    pub fn expose(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_seeds_are_distinct_and_nonzero() {
        let a = Seed32::generate().unwrap();
        let b = Seed32::generate().unwrap();
        assert_ne!(a.expose(), b.expose(), "two fresh seeds must differ");
        assert_ne!(a.expose(), &[0u8; 32], "a fresh seed must not be all-zero");
    }

    #[test]
    fn passphrase_reports_emptiness() {
        assert!(Passphrase::from(String::new()).is_empty());
        assert!(!Passphrase::from("correct horse".to_owned()).is_empty());
    }

    #[test]
    fn passphrase_exposes_exact_bytes() {
        let p = Passphrase::from("s3cret".to_owned());
        assert_eq!(p.expose_bytes(), b"s3cret");
    }
}
