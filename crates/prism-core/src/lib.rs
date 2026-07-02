// SPDX-License-Identifier: AGPL-3.0-or-later
//! `prism-core` — shared core for Prism.
//!
//! This crate will hold identity, cryptography, and the encrypted keystore
//! (milestone M1 onward, see `docs/specification.md`). It has no network or UI
//! dependencies. For milestone M0 it provides only shared constants and the
//! resolution of the default IPC socket path.

use std::path::PathBuf;

use directories::ProjectDirs;

/// Human-readable application name, used in identifiers and paths.
pub const APP_NAME: &str = "prism";

/// File name of the daemon's IPC socket inside the runtime directory.
pub const DEFAULT_SOCKET_FILE: &str = "prismd.sock";

// Components used to derive per-platform directories.
const QUALIFIER: &str = "";
const ORGANIZATION: &str = "prism";
const APPLICATION: &str = "prism";

/// Errors produced by `prism-core`.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// No per-user runtime directory could be determined (e.g. `XDG_RUNTIME_DIR`
    /// is unset). Callers should fall back to an explicit `--socket` path.
    #[error("could not determine a per-user runtime directory for the IPC socket")]
    NoRuntimeDir,
}

/// Resolve the default IPC socket path inside the per-user runtime directory.
///
/// On Linux this is `$XDG_RUNTIME_DIR/prism/prismd.sock`, which lives in a
/// directory owned by, and private to, the current user. The daemon still
/// enforces `0700`/`0600` permissions and a peer-credential check on top of
/// this (see `prism-daemon`).
pub fn default_socket_path() -> Result<PathBuf, CoreError> {
    let dirs =
        ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION).ok_or(CoreError::NoRuntimeDir)?;
    let runtime_dir = dirs.runtime_dir().ok_or(CoreError::NoRuntimeDir)?;
    Ok(runtime_dir.join(DEFAULT_SOCKET_FILE))
}
