// SPDX-License-Identifier: AGPL-3.0-or-later
//! IPC message types exchanged between the client and the daemon.

use serde::{Deserialize, Serialize};

/// Version of the IPC protocol spoken by this build.
///
/// Every message is wrapped in a versioned [`Envelope`]. This is the M0 slice
/// of the "every message carries a version" rule; authenticated version
/// negotiation on the *network* handshake arrives with M2.
pub const PROTOCOL_VERSION: u16 = 1;

/// A request sent by the client to the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Liveness check: expects a [`Response::Pong`].
    Ping,
}

/// A response sent by the daemon to the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// Successful reply to [`Request::Ping`].
    Pong,
    /// The request could not be served; carries a human-readable reason.
    Error {
        /// Human-readable error message (never contains secrets).
        message: String,
    },
}

/// Transport envelope wrapping every IPC message with a protocol version.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
