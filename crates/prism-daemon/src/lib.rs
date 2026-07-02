// SPDX-License-Identifier: AGPL-3.0-or-later
//! `prism-daemon` — the Prism background daemon library.
//!
//! The daemon (`prismd`) holds the unlocked keys in RAM, runs the network, and
//! exposes a local IPC socket that the thin client (`prism`) talks to. For
//! milestone M0 it only serves the IPC `ping`/`pong` exchange over a securely
//! permissioned Unix socket; no keys, crypto, or networking exist yet.
//!
//! The binary entry point lives in `main.rs`; the socket and server logic live
//! here so they can be driven directly by tests.

pub mod server;
pub mod socket;

use std::path::PathBuf;

pub use server::serve;
pub use socket::{bind_secure, SocketGuard};

/// Errors produced by the daemon.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    /// Underlying I/O failure (binding, accepting, filesystem permissions).
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// An IPC framing or (de)serialization error.
    #[error("IPC protocol error: {0}")]
    Proto(#[from] prism_proto::ProtoError),
    /// The configured socket path has no parent directory.
    #[error("socket path has no parent directory: {0}")]
    SocketPath(PathBuf),
    /// A live daemon is already listening on this socket.
    #[error("a daemon is already listening on {0}")]
    AlreadyRunning(PathBuf),
}
