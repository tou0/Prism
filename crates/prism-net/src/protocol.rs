// SPDX-License-Identifier: AGPL-3.0-or-later
//! The on-wire request/response protocol carried over libp2p.
//!
//! prism-net treats every payload as **opaque bytes**: the prekey bundle and
//! the sealed message are produced and validated exclusively by `prism-core`.
//! This module only defines the tiny framing envelope (a version byte and a
//! kind) and the size ceilings; it never inspects payload contents.
//!
//! Framing is delegated to libp2p's audited CBOR request-response codec with
//! explicit size maxima. The protocol id is negotiated by multistream-select
//! **inside** the Noise channel, so it is authenticated against an external
//! downgrade attacker.

use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};

/// The negotiated protocol id (carries the wire version).
pub const PROTOCOL_ID: StreamProtocol = StreamProtocol::new("/prism/msg/1.0.0");

/// Version of the request/response envelope. Mismatches are rejected cleanly.
pub const WIRE_VERSION: u8 = 1;

/// Maximum accepted request size (bytes). A published bundle is < 1 KiB and a
/// sealed message is capped by `prism-core` at 64 KiB of plaintext; 256 KiB
/// leaves generous headroom while bounding a hostile peer's allocation.
pub const MAX_REQUEST_BYTES: u64 = 256 * 1024;

/// Maximum accepted response size (bytes). Responses carry at most a bundle
/// plus framing.
pub const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// A request from an initiator to a responder. Payloads are opaque.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum WireRequest {
    /// "Send me your signed prekey bundle" (first-contact establishment).
    GetBundle {
        /// Envelope version; must equal [`WIRE_VERSION`].
        version: u8,
    },
    /// "Here is a sealed message for you" (opaque `prism-core` wire bytes).
    Deliver {
        /// Envelope version; must equal [`WIRE_VERSION`].
        version: u8,
        /// Opaque sealed-message bytes (validated only by `prism-core`).
        sealed: Vec<u8>,
    },
}

/// A response from a responder back to the initiator. Payloads are opaque.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum WireResponse {
    /// The responder's signed prekey bundle (opaque bytes).
    Bundle {
        /// Envelope version; must equal [`WIRE_VERSION`].
        version: u8,
        /// Opaque bundle bytes (validated only by `prism-core`).
        bundle: Vec<u8>,
    },
    /// The delivered message was accepted (decrypted and identity-verified).
    Ack {
        /// Envelope version; must equal [`WIRE_VERSION`].
        version: u8,
    },
    /// The request could not be served. Reason is a non-secret, non-key label.
    Error {
        /// Envelope version; must equal [`WIRE_VERSION`].
        version: u8,
        /// Human-readable, secret-free reason.
        reason: String,
    },
}

impl WireRequest {
    /// `true` if the envelope version is the one this build speaks.
    pub(crate) fn version_ok(&self) -> bool {
        match self {
            WireRequest::GetBundle { version } | WireRequest::Deliver { version, .. } => {
                *version == WIRE_VERSION
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_gate_accepts_current_and_rejects_others() {
        assert!(WireRequest::GetBundle {
            version: WIRE_VERSION
        }
        .version_ok());
        assert!(WireRequest::Deliver {
            version: WIRE_VERSION,
            sealed: vec![1, 2, 3],
        }
        .version_ok());
        assert!(!WireRequest::GetBundle {
            version: WIRE_VERSION.wrapping_add(1),
        }
        .version_ok());
    }
}
