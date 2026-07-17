// SPDX-License-Identifier: AGPL-3.0-or-later
//! `prism-core` — shared core for Prism.
//!
//! Identity, cryptography, and the encrypted keystore (see
//! `docs/specification.md` §4–5 and `docs/keystore.md`). No network or UI
//! dependencies. Also provides shared constants and the resolution of default
//! paths (IPC socket, keystore file).

pub mod identity;
pub mod keystore;
pub mod recovery;
pub mod secret;

pub use identity::{
    validate_nick, BadSignature, Fingerprint, IdentityKeypair, NickError, PublicIdentity,
    NICK_MAX_CHARS, SHORT_FINGERPRINT_LEN, SIGNATURE_LEN,
};
pub use secret::{Passphrase, RngError, Seed32};

use std::path::PathBuf;

use directories::ProjectDirs;

/// Human-readable application name, used in identifiers and paths.
pub const APP_NAME: &str = "prism";

/// File name of the daemon's IPC socket inside the runtime directory.
pub const DEFAULT_SOCKET_FILE: &str = "prismd.sock";

/// File name of the encrypted keystore inside the data directory.
pub const DEFAULT_KEYSTORE_FILE: &str = "keystore.pks";

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
    /// No per-user data directory could be determined. Callers should fall
    /// back to an explicit `--keystore` path.
    #[error("could not determine a per-user data directory for the keystore")]
    NoDataDir,
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

/// Resolve the default keystore path inside the per-user data directory.
///
/// On Linux this is `~/.local/share/prism/keystore.pks`. The keystore module
/// forces the directory to `0700` and the file to `0600` when writing (see
/// [`keystore::seal_to_path`]).
pub fn default_keystore_path() -> Result<PathBuf, CoreError> {
    let dirs =
        ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION).ok_or(CoreError::NoDataDir)?;
    Ok(dirs.data_dir().join(DEFAULT_KEYSTORE_FILE))
}
