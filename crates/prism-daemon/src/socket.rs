// SPDX-License-Identifier: AGPL-3.0-or-later
//! Secure binding of the IPC Unix socket.
//!
//! The daemon holds unlocked keys, so the socket is the primary local attack
//! surface. Defense in depth (see `docs/specification.md` §10.1):
//! - the parent runtime directory is forced to `0700` (owner-only);
//! - the socket file itself is set to `0600`;
//! - a stale socket from a crashed run is detected and replaced, while a live
//!   daemon is reported as [`DaemonError::AlreadyRunning`];
//! - the peer-credential (`SO_PEERCRED`) UID check happens in [`crate::server`].

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};

use tokio::net::UnixListener;

use crate::DaemonError;

/// RAII guard that unlinks the socket file when dropped (on daemon shutdown).
#[derive(Debug)]
pub struct SocketGuard {
    path: PathBuf,
}

impl SocketGuard {
    /// Create a guard that will remove `path` on drop.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        // Best-effort cleanup; ignore errors (the file may already be gone).
        let _ = fs::remove_file(&self.path);
    }
}

/// Bind the IPC socket with locked-down permissions.
///
/// Ensures the parent directory exists and is `0700`, replaces a stale socket
/// left by a crashed daemon, binds, and sets the socket file to `0600`.
pub fn bind_secure(path: &Path) -> Result<UnixListener, DaemonError> {
    let dir = path
        .parent()
        .ok_or_else(|| DaemonError::SocketPath(path.to_path_buf()))?;

    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;

    if path.exists() {
        // A socket file already exists. If a daemon answers, refuse to steal
        // its address; otherwise treat it as stale and remove it.
        match StdUnixStream::connect(path) {
            Ok(_) => return Err(DaemonError::AlreadyRunning(path.to_path_buf())),
            Err(_) => fs::remove_file(path)?,
        }
    }

    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}
