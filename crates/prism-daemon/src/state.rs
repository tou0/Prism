// SPDX-License-Identifier: AGPL-3.0-or-later
//! Daemon runtime state: the keystore location and the unlocked identity.
//!
//! The daemon is the only process that ever holds the identity keypair in
//! plaintext (in RAM); the client never sees a private key. The unlocked
//! identity lives behind an async `RwLock`: mutating handlers (init, restore,
//! unlock) take the write lock for their whole operation, which also
//! serializes concurrent attempts to (re)create or unlock the keystore.

use std::path::PathBuf;

use prism_core::IdentityKeypair;
use tokio::sync::RwLock;

/// The identity currently unlocked in daemon RAM. No `Clone`/`Debug`: it
/// wraps the private identity key.
pub struct UnlockedIdentity {
    keypair: IdentityKeypair,
    nick: String,
}

impl UnlockedIdentity {
    /// Bundle a freshly loaded keypair with its nickname.
    pub fn new(keypair: IdentityKeypair, nick: String) -> Self {
        Self { keypair, nick }
    }

    /// The public handle, `nick#fingerprint`.
    pub fn handle(&self) -> String {
        self.keypair.public().handle(&self.nick)
    }

    /// The full identity-key fingerprint (base58).
    pub fn fingerprint(&self) -> String {
        self.keypair.public().fingerprint().full()
    }
}

/// Shared daemon state, one per process, behind an `Arc`.
pub struct AppState {
    /// Where the encrypted keystore lives on disk.
    pub keystore_path: PathBuf,
    /// The unlocked identity, if any.
    pub unlocked: RwLock<Option<UnlockedIdentity>>,
}

impl AppState {
    /// State for a daemon serving the keystore at `keystore_path`.
    pub fn new(keystore_path: PathBuf) -> Self {
        Self {
            keystore_path,
            unlocked: RwLock::new(None),
        }
    }
}
