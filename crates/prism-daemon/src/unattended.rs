// SPDX-License-Identifier: AGPL-3.0-or-later
//! Unattended unlock for always-on nodes (milestone M5).
//!
//! An always-on bootstrap or relay node cannot publish its locator or serve
//! circuits until its keystore is unlocked, because the identity lives in RAM
//! only after unlock (the M4 real-internet test surfaced this). This module lets
//! such a node read its passphrase from a **file** at startup and unlock itself,
//! with no human present.
//!
//! # This weakens at-rest protection, deliberately and visibly
//!
//! Normally the passphrase exists only in the operator's head, so seizing the
//! disk yields nothing usable. With unattended unlock the passphrase sits **on
//! the same machine as the keystore**: anyone who can read that file — root, a
//! backup, a filesystem snapshot, a stolen disk or VM image — owns that identity.
//! The keystore's Argon2id work factor no longer buys anything against them.
//!
//! Therefore:
//! * it is **opt-in twice** — `--unattended` *and* `--passphrase-file` must both
//!   be given, so it can never happen by accident;
//! * it is never the default, and interactive `unlock` is untouched;
//! * it is appropriate for a **dedicated bootstrap/relay node that holds no
//!   personal conversations**, and inappropriate for a personal node;
//! * the file must be `0600` and owned by the daemon's own user, or we refuse —
//!   the same hygiene the IPC socket gets, for the same reason.
//!
//! A passphrase is never logged, never included in an error, and never rendered
//! by `Debug`: it is read straight into a `Zeroizing` buffer and wrapped in
//! `Passphrase`.
//!
//! Considered and deliberately not built here (see CLAUDE.md M5): an OS-held
//! credential (systemd credential / TPM), and a bootstrap-only mode needing no
//! messaging identity at all — the latter is a design change, not a flag.

use std::path::{Path, PathBuf};

use prism_core::Passphrase;
use zeroize::Zeroizing;

/// Why an unattended unlock could not proceed. No variant carries the passphrase
/// or any part of it.
#[derive(Debug, thiserror::Error)]
pub enum UnattendedError {
    /// `--unattended` was given without a passphrase source.
    #[error("--unattended requires --passphrase-file <PATH>")]
    NoSource,
    /// The passphrase file could not be read.
    #[error("cannot read the passphrase file: {0}")]
    Unreadable(String),
    /// The file is readable by more than its owner, or owned by someone else.
    #[error(
        "refusing to use passphrase file {path}: it must be mode 0600 and owned by this user \
         (found mode {mode:o}, uid {uid})"
    )]
    BadPermissions {
        /// The offending path (a path is not secret).
        path: String,
        /// The permission bits found.
        mode: u32,
        /// The owning uid found.
        uid: u32,
    },
    /// The file held no passphrase.
    #[error("the passphrase file is empty")]
    Empty,
}

/// Configuration for unattended unlock, assembled from CLI flags.
#[derive(Debug, Clone, Default)]
pub struct UnattendedConfig {
    /// Whether unattended unlock was explicitly requested.
    pub enabled: bool,
    /// Path to the file holding the keystore passphrase.
    pub passphrase_file: Option<PathBuf>,
}

impl UnattendedConfig {
    /// Read the passphrase for an unattended unlock, enforcing file hygiene.
    ///
    /// `Ok(None)` means unattended mode was not requested — the daemon simply
    /// waits for an interactive `unlock`, which stays the default.
    pub fn load_passphrase(&self) -> Result<Option<Passphrase>, UnattendedError> {
        if !self.enabled {
            return Ok(None);
        }
        let path = self
            .passphrase_file
            .as_deref()
            .ok_or(UnattendedError::NoSource)?;
        check_permissions(path)?;
        read_passphrase(path).map(Some)
    }
}

/// Refuse a passphrase file that anyone but its owner can read, or that this
/// user does not own.
///
/// A group- or world-readable secret on a shared host is exactly the failure this
/// whole feature risks, so it is a hard error rather than a warning: an operator
/// who mis-set the mode would otherwise never find out.
#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), UnattendedError> {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::metadata(path).map_err(|e| UnattendedError::Unreadable(e.to_string()))?;
    let mode = meta.mode() & 0o777;
    let uid = meta.uid();
    let our_uid = rustix::process::getuid().as_raw();
    if mode & 0o077 != 0 || uid != our_uid {
        return Err(UnattendedError::BadPermissions {
            path: path.display().to_string(),
            mode,
            uid,
        });
    }
    Ok(())
}

/// On non-Unix platforms the mode check does not apply; the file is still read
/// with the same care. (Windows ACL enforcement would belong here.)
#[cfg(not(unix))]
fn check_permissions(path: &Path) -> Result<(), UnattendedError> {
    std::fs::metadata(path)
        .map(|_| ())
        .map_err(|e| UnattendedError::Unreadable(e.to_string()))
}

/// Read the file into a zeroizing buffer and wrap it as a `Passphrase`.
///
/// A trailing newline is stripped, since `printf '%s' … > file` and an editor
/// disagree about it and an operator should not have to know which was used.
fn read_passphrase(path: &Path) -> Result<Passphrase, UnattendedError> {
    let bytes = Zeroizing::new(
        std::fs::read(path).map_err(|e| UnattendedError::Unreadable(e.to_string()))?,
    );
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| UnattendedError::Unreadable("not valid UTF-8".to_owned()))?;
    let trimmed = text.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        return Err(UnattendedError::Empty);
    }
    // `From<String>` moves the string in and treats it as secret from here on.
    Ok(Passphrase::from(trimmed.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not requesting unattended mode yields no passphrase — interactive unlock
    /// remains the default path.
    #[test]
    fn disabled_by_default() {
        let cfg = UnattendedConfig::default();
        assert!(matches!(cfg.load_passphrase(), Ok(None)));
    }

    #[test]
    fn enabled_without_a_file_is_an_error() {
        let cfg = UnattendedConfig {
            enabled: true,
            passphrase_file: None,
        };
        assert!(matches!(
            cfg.load_passphrase(),
            Err(UnattendedError::NoSource)
        ));
    }

    #[cfg(unix)]
    fn write_with_mode(name: &str, contents: &str, mode: u32) -> PathBuf {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!("prism-unattended-{name}"));
        let _ = std::fs::remove_file(&path);
        let mut f = match std::fs::File::create(&path) {
            Ok(f) => f,
            Err(e) => panic!("test setup: cannot create {}: {e}", path.display()),
        };
        if write!(f, "{contents}").is_err() {
            panic!("test setup: cannot write the passphrase file");
        }
        if std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).is_err() {
            panic!("test setup: cannot set mode {mode:o}");
        }
        path
    }

    #[cfg(unix)]
    #[test]
    fn a_0600_file_is_accepted_and_the_newline_is_stripped() {
        let path = write_with_mode("ok", "correct horse battery staple\n", 0o600);
        let cfg = UnattendedConfig {
            enabled: true,
            passphrase_file: Some(path.clone()),
        };
        // Note: `Passphrase` implements no `Debug` (secrets rule), so the failure
        // arms below cannot print the value even by accident.
        match cfg.load_passphrase() {
            Ok(Some(pass)) => {
                assert_eq!(pass.expose_bytes(), b"correct horse battery staple");
            }
            Ok(None) => panic!("expected a passphrase, got none"),
            Err(e) => panic!("expected a passphrase, got error: {e}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    /// The core of the hygiene rule: a group/world-readable secret is refused
    /// outright, not warned about.
    #[cfg(unix)]
    #[test]
    fn a_group_or_world_readable_file_is_refused() {
        for mode in [0o640, 0o644, 0o604, 0o666] {
            let path = write_with_mode(&format!("mode{mode:o}"), "secret", mode);
            let cfg = UnattendedConfig {
                enabled: true,
                passphrase_file: Some(path.clone()),
            };
            assert!(
                matches!(
                    cfg.load_passphrase(),
                    Err(UnattendedError::BadPermissions { .. })
                ),
                "mode {mode:o} must be refused"
            );
            let _ = std::fs::remove_file(&path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_empty_file_is_an_error() {
        let path = write_with_mode("empty", "\n", 0o600);
        let cfg = UnattendedConfig {
            enabled: true,
            passphrase_file: Some(path.clone()),
        };
        assert!(matches!(cfg.load_passphrase(), Err(UnattendedError::Empty)));
        let _ = std::fs::remove_file(&path);
    }

    /// No error may echo the passphrase — errors are logged, and a leak here
    /// would put the secret in the operator's logs.
    #[cfg(unix)]
    #[test]
    fn errors_never_contain_the_passphrase() {
        let secret = "super-secret-passphrase";
        let path = write_with_mode("leak", secret, 0o644);
        let cfg = UnattendedConfig {
            enabled: true,
            passphrase_file: Some(path.clone()),
        };
        let err = match cfg.load_passphrase() {
            Err(e) => e,
            Ok(_) => panic!("a 0644 file must be refused"),
        };
        let rendered = format!("{err} {err:?}");
        assert!(
            !rendered.contains(secret),
            "the error must not echo the passphrase"
        );
        let _ = std::fs::remove_file(&path);
    }
}
