// SPDX-License-Identifier: AGPL-3.0-or-later
//! A wrapper for secret strings crossing the IPC boundary.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// A secret string (passphrase, mnemonic) inside an IPC message.
///
/// Backed by [`secrecy::SecretString`]: zeroized on drop, `Debug` prints a
/// redaction marker, and there is deliberately **no `Clone`, no `PartialEq`,
/// and no `Display`** (CLAUDE.md secrets rule). Serialization exposes the
/// secret by design — that is the one purpose of this type: carrying it
/// across the local, kernel-protected IPC socket. The frame codec zeroizes
/// the serialized buffers on both sides (see [`crate::frame`]).
pub struct Sensitive(SecretString);

impl Sensitive {
    /// Wrap a secret string, taking ownership.
    pub fn new(secret: String) -> Self {
        Self(SecretString::from(secret))
    }

    /// Wrap a secret already held in a `Zeroizing<String>`, moving its buffer
    /// out without an intermediate bare `String` copy.
    ///
    /// Prefer this over `Sensitive::new(z.to_string())` at call sites that
    /// already hold a zeroizing buffer (passphrase input, an exposed
    /// mnemonic): `.to_string()` would allocate a *second* plaintext copy of
    /// the secret. `mem::take` hands the original heap buffer straight to the
    /// `SecretString`, leaving an empty (harmless) string behind in the
    /// `Zeroizing` wrapper.
    pub fn from_zeroizing(mut secret: Zeroizing<String>) -> Self {
        Self(SecretString::from(std::mem::take(&mut *secret)))
    }

    /// Borrow the secret. Keep the borrow as short as possible; never copy
    /// the contents into an unmanaged buffer and never log it.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// Move the inner secret out, without copying it. For handing the secret
    /// to another zeroizing wrapper (e.g. `prism_core::Passphrase`).
    pub fn into_secret(self) -> SecretString {
        self.0
    }
}

impl std::fmt::Debug for Sensitive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sensitive([redacted])")
    }
}

impl Serialize for Sensitive {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.expose_secret())
    }
}

impl<'de> Deserialize<'de> for Sensitive {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_secret() {
        let secret = Sensitive::new("hunter2".to_owned());
        let debug = format!("{secret:?}");
        assert!(!debug.contains("hunter2"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn from_zeroizing_preserves_the_secret() {
        let secret = Sensitive::from_zeroizing(Zeroizing::new("correct horse".to_owned()));
        assert_eq!(secret.expose(), "correct horse");
    }

    #[test]
    fn round_trips_through_serde() {
        let secret = Sensitive::new("correct horse".to_owned());
        let json = serde_json::to_string(&secret).expect("serialize");
        let back: Sensitive = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.expose(), "correct horse");
    }
}
