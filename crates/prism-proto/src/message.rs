// SPDX-License-Identifier: AGPL-3.0-or-later
//! IPC message types exchanged between the client and the daemon.

use serde::{Deserialize, Serialize};

use crate::sensitive::Sensitive;

/// Version of the IPC protocol spoken by this build.
///
/// Every message is wrapped in a versioned [`Envelope`]. This is the local
/// IPC slice of the "every message carries a version" rule; authenticated
/// version negotiation on the *network* handshake arrives with M2.
pub const PROTOCOL_VERSION: u16 = 1;

/// The user's choice of recovery mode at identity creation (spec §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryMode {
    /// No recovery phrase: nothing exists outside the user's head to reveal
    /// under coercion. The default.
    None,
    /// Opt-in recovery phrase: a mnemonic is generated and returned once.
    Phrase,
}

/// A request sent by the client to the daemon.
///
/// Deliberately **no `Clone` / `PartialEq`**: several variants carry secrets
/// ([`Sensitive`]), which must not be duplicable or comparable.
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// Liveness check: expects a [`Response::Pong`].
    Ping,
    /// Create a new identity: generate keys daemon-side, seal the keystore,
    /// and unlock it. Expects [`Response::Created`].
    Init {
        /// The chosen nickname.
        nick: String,
        /// The keystore passphrase.
        passphrase: Sensitive,
        /// Whether to generate an opt-in recovery phrase.
        recovery: RecoveryMode,
        /// Overwrite an existing keystore (destructive; the CLI confirms).
        force: bool,
    },
    /// Recreate an identity from a recovery phrase (deterministic: the same
    /// phrase yields the same identity). Expects [`Response::Created`].
    Restore {
        /// The chosen nickname (need not match the original).
        nick: String,
        /// The keystore passphrase for the recreated keystore.
        passphrase: Sensitive,
        /// The BIP-39 recovery phrase.
        mnemonic: Sensitive,
        /// Overwrite an existing keystore (destructive; the CLI confirms).
        force: bool,
    },
    /// Unlock the keystore, loading the identity into daemon RAM. Expects
    /// [`Response::Identity`].
    Unlock {
        /// The keystore passphrase.
        passphrase: Sensitive,
    },
    /// Ask who is currently unlocked. Expects [`Response::Identity`] or
    /// [`Response::Locked`].
    Whoami,
}

/// A response sent by the daemon to the client.
///
/// Deliberately **no `Clone` / `PartialEq`** (see [`Request`]); test code
/// matches variants with `matches!`.
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    /// Successful reply to [`Request::Ping`].
    Pong,
    /// The currently unlocked identity.
    Identity {
        /// Public handle, `nick#fingerprint`.
        handle: String,
        /// The full identity-key fingerprint (base58).
        fingerprint: String,
    },
    /// An identity was created (or restored) and unlocked.
    Created {
        /// Public handle, `nick#fingerprint`.
        handle: String,
        /// The full identity-key fingerprint (base58).
        fingerprint: String,
        /// The one-time recovery phrase, present only for
        /// [`RecoveryMode::Phrase`] on `Init`. Shown once, never stored.
        mnemonic: Option<Sensitive>,
    },
    /// No identity is unlocked (locked keystore, or none exists yet).
    Locked,
    /// The request could not be served; carries a human-readable reason.
    Error {
        /// Human-readable error message (never contains secrets).
        message: String,
    },
}

/// Transport envelope wrapping every IPC message with a protocol version.
#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// Protocol version of the wrapped message.
    pub version: u16,
    /// The wrapped request or response.
    pub message: T,
}

impl<T> Envelope<T> {
    /// Wrap `message` with the current [`PROTOCOL_VERSION`].
    pub fn new(message: T) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message,
        }
    }
}
