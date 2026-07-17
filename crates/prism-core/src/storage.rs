// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared low-level file plumbing for the sealed stores (keystore, session
//! store): private directories, atomic writes, and bounded reads.
//!
//! Extracted from the M1 keystore without behavior change; both stores get
//! exactly the same crash-safety and permission discipline.

use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

/// Path of the temporary sibling used for atomic writes: `<file>.tmp`.
fn tmp_sibling(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(".tmp");
    PathBuf::from(os)
}

/// Ensure the parent directory of `path` exists with `0700` permissions and
/// return it. `None` if the path has no usable parent.
///
/// Note: `set_permissions` follows symlinks, so if the directory is a symlink
/// this chmods its target, and only the leaf directory is fixed (parents
/// created by `create_dir_all` keep the umask default). Store paths are
/// user-supplied, so this is self-inflicted at worst, and the files
/// themselves are always `0600`. Revisit if paths ever become externally
/// influenced (same caveat as M1).
pub(crate) fn prepare_private_dir(path: &Path) -> io::Result<Option<&Path>> {
    let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(None);
    };
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(Some(dir))
}

/// Write `bytes` to `path` atomically and privately: temp sibling (created
/// `0600`, `create_new`) → write → fsync → rename over `path` → fsync of
/// `dir`. A crash at any point leaves either the old file or the new file,
/// never a torn one. A stale temp file from an earlier crashed attempt is
/// removed first; on failure the temp file is best-effort cleaned up and the
/// original file is untouched.
pub(crate) fn write_atomically_private(path: &Path, dir: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp_path = tmp_sibling(path);
    match fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut tmp = options.open(&tmp_path)?;
        tmp.write_all(bytes)?;
        tmp.sync_all()?;
        drop(tmp);

        fs::rename(&tmp_path, path)?;
        // Make the rename itself durable.
        #[cfg(unix)]
        fs::File::open(dir)?.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

/// Read `path` fully, bounded to `max + 1` bytes so a hostile or unbounded
/// file (e.g. a `/dev/zero` symlink) can never force a large allocation.
///
/// Returns `Ok(None)` if the file does not exist. A returned buffer longer
/// than `max` means the file is oversized; the caller maps that to its own
/// "too large" error.
pub(crate) fn read_bounded(path: &Path, max: usize) -> io::Result<Option<Vec<u8>>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::with_capacity(max.saturating_add(1));
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}
