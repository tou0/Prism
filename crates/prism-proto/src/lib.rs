// SPDX-License-Identifier: AGPL-3.0-or-later
//! `prism-proto` — Prism IPC messages and their framed codec.
//!
//! This crate defines the messages exchanged between the client (`prism`) and
//! the daemon (`prismd`) over the local IPC socket, plus a small length-prefixed
//! framing codec over `tokio` byte streams.
//!
//! For milestone M0 the IPC body is serialized with `serde_json`. The *network*
//! wire format between peers is protobuf (`prost`) and arrives with M2; it is
//! deliberately not present yet (build only the current milestone).
//!
//! Everything read from the socket is treated as hostile: frames are bounded by
//! [`MAX_FRAME_LEN`] and the length prefix is validated before any allocation.

mod frame;
mod message;
mod sensitive;

pub use frame::{read_message, read_message_opt, write_message, MAX_FRAME_LEN};
pub use message::{Envelope, RecoveryMode, Request, Response, PROTOCOL_VERSION};
pub use sensitive::Sensitive;

/// Errors produced while (de)serializing or framing IPC messages.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// Underlying I/O failure on the socket.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The message body could not be serialized or deserialized.
    #[error("message (de)serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// A frame's declared length exceeds [`MAX_FRAME_LEN`]. Rejected before
    /// allocating, to bound memory against a hostile peer.
    #[error("frame too large: {len} bytes")]
    FrameTooLarge {
        /// The declared (rejected) length, in bytes.
        len: usize,
    },
    /// The connection closed in the middle of a frame.
    #[error("connection closed before a full message was received")]
    UnexpectedEof,
}
