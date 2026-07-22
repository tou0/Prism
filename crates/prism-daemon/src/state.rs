// SPDX-License-Identifier: AGPL-3.0-or-later
//! Daemon runtime state: paths, the unlocked identity, and (once unlocked) the
//! networking subsystem handles.
//!
//! The daemon is the only process that ever holds the identity keypair in
//! plaintext (in RAM); the client never sees a private key. The unlocked
//! identity lives behind an async `RwLock`: mutating handlers (init, restore,
//! unlock) take the write lock for their whole operation, which also
//! serializes concurrent attempts to (re)create or unlock the keystore.

use std::path::PathBuf;

use prism_core::{IdentityKeypair, Seed32};
use tokio::sync::RwLock;

use crate::session_core::CoreHandle;

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

    /// The chosen nickname.
    pub fn nick(&self) -> &str {
        &self.nick
    }

    /// A fresh copy of the identity seed, e.g. to bootstrap the networking
    /// subsystem (session store key + Noise transport key).
    pub fn seed(&self) -> Seed32 {
        self.keypair.to_seed()
    }
}

/// The networking subsystem, present only after a successful unlock/init.
pub struct NetworkHandles {
    /// Handle to the libp2p swarm task.
    pub net: prism_net::NetHandle,
    /// Handle to the core session thread.
    pub core: CoreHandle,
}

/// Shared daemon state, one per process, behind an `Arc`.
pub struct AppState {
    /// Where the encrypted keystore lives on disk.
    pub keystore_path: PathBuf,
    /// Where the sealed ratchet-state store lives on disk.
    pub sessions_path: PathBuf,
    /// The multiaddr the swarm listens on (e.g. `/ip4/0.0.0.0/tcp/0`).
    pub listen_addr: String,
    /// The unlocked identity, if any.
    pub unlocked: RwLock<Option<UnlockedIdentity>>,
    /// The networking subsystem, brought up on first unlock/init.
    pub net: RwLock<Option<NetworkHandles>>,
}

impl AppState {
    /// State for a daemon serving the given keystore and session store, whose
    /// swarm listens on `listen_addr`.
    pub fn new(keystore_path: PathBuf, sessions_path: PathBuf, listen_addr: String) -> Self {
        Self {
            keystore_path,
            sessions_path,
            listen_addr,
            unlocked: RwLock::new(None),
            net: RwLock::new(None),
        }
    }
}
