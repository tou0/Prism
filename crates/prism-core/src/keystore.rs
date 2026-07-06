// SPDX-License-Identifier: AGPL-3.0-or-later
//! The encrypted keystore: a single file holding the identity at rest.
//!
//! Format (fully documented in `docs/keystore.md`):
//!
//! ```text
//! ┌─ Header (45 bytes, plaintext, authenticated as AEAD associated data) ─┐
//! │ 0   7   magic  = b"PRISMKS"                                           │
//! │ 7   1   format version = 0x01                                         │
//! │ 8   4   Argon2id m_cost, KiB (u32 BE)                                 │
//! │ 12  4   Argon2id t_cost      (u32 BE)                                 │
//! │ 16  1   Argon2id p_cost      (u8)                                     │
//! │ 17  16  Argon2id salt   (OS CSPRNG, fresh on every write)             │
//! │ 33  12  AEAD nonce      (OS CSPRNG, fresh on every write)             │
//! ├─ Body ────────────────────────────────────────────────────────────────┤
//! │ 45  ..  ChaCha20-Poly1305 ciphertext (payload ‖ 16-byte tag)          │
//! └───────────────────────────────────────────────────────────────────────┘
//!
//! plaintext payload = seed (32 bytes) ‖ nick_len (u16 BE) ‖ nick (UTF-8)
//! ```
//!
//! Security properties:
//! - **AEAD-authenticated header**: the whole 45-byte header is the AEAD
//!   associated data, so tampering with any header field (including the
//!   version byte, the KDF parameters, or the salt) fails the Poly1305 tag.
//! - **Crypto agility without a version bump** (spec §14.1): each keystore
//!   carries its own Argon2 parameters and is opened with them, so the
//!   default difficulty can be raised later without migrating old files.
//!   Because the parameters steer the KDF, they can only be *authenticated
//!   after* the KDF has run — so they are bounds-checked defensively first
//!   (see [`ARGON2_MAX_M_COST_KIB`]) to keep a forged header from demanding
//!   absurd memory or CPU work.
//! - **No nonce reuse by construction**: every write draws a fresh salt *and*
//!   nonce, so each write also uses a fresh AEAD key.
//! - **Recovery-mode indistinguishability**: both recovery modes persist the
//!   same payload shape (only the 32-byte derived seed, never the mnemonic)
//!   and the same default KDF parameters, so nothing on disk reveals whether
//!   a recovery phrase exists (spec §4.2).
//! - **Atomic writes**: temp file → fsync → rename → fsync of the directory;
//!   a crash never leaves a half-written keystore.
//!
//! Sealing and opening run Argon2id (hundreds of ms and 64 MiB by design;
//! calibration in `docs/keystore.md`): **never call them on an async executor
//! thread** — use `spawn_blocking`.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroizing;

use crate::secret::{fill_random, Passphrase, RngError, Seed32};

/// Magic bytes identifying a Prism keystore file.
pub const MAGIC: &[u8; 7] = b"PRISMKS";
/// Current on-disk format version.
pub const FORMAT_VERSION: u8 = 1;
/// Length of the random Argon2id salt stored in the header.
pub const SALT_LEN: usize = 16;
/// Length of the random ChaCha20-Poly1305 nonce stored in the header.
pub const NONCE_LEN: usize = 12;
/// Byte offset of the Argon2id m_cost field (u32 BE) in the header.
pub const M_COST_OFFSET: usize = MAGIC.len() + 1;
/// Byte offset of the Argon2id t_cost field (u32 BE) in the header.
pub const T_COST_OFFSET: usize = M_COST_OFFSET + 4;
/// Byte offset of the Argon2id p_cost field (u8) in the header.
pub const P_COST_OFFSET: usize = T_COST_OFFSET + 4;
/// Byte offset of the Argon2id salt in the header.
pub const SALT_OFFSET: usize = P_COST_OFFSET + 1;
/// Byte offset of the AEAD nonce in the header.
pub const NONCE_OFFSET: usize = SALT_OFFSET + SALT_LEN;
/// Total header length: magic ‖ version ‖ KDF params ‖ salt ‖ nonce.
pub const HEADER_LEN: usize = NONCE_OFFSET + NONCE_LEN;
/// Length of the Poly1305 authentication tag appended to the ciphertext.
pub const TAG_LEN: usize = 16;
/// Length of the AEAD key derived from the passphrase.
pub const KEY_LEN: usize = 32;

/// Default Argon2id memory cost, in KiB (64 MiB), written into new keystores.
/// Calibration notes live in `docs/keystore.md`.
pub const ARGON2_DEFAULT_M_COST_KIB: u32 = 64 * 1024;
/// Default Argon2id iteration count written into new keystores. Calibrated
/// (with [`ARGON2_DEFAULT_M_COST_KIB`]) to ~330 ms on the reference machine,
/// i.e. roughly 1–2 s on modest hardware; see `docs/keystore.md`.
pub const ARGON2_DEFAULT_T_COST: u32 = 8;
/// Default Argon2id parallelism written into new keystores.
pub const ARGON2_DEFAULT_P_COST: u8 = 1;

/// Maximum Argon2id memory cost accepted when *opening* a keystore (1 GiB).
///
/// The header's KDF parameters can only be authenticated after the KDF has
/// run, so a forged header could otherwise demand arbitrary memory. This cap
/// bounds that to a survivable allocation while leaving generous headroom for
/// future difficulty raises.
pub const ARGON2_MAX_M_COST_KIB: u32 = 1024 * 1024;
/// Maximum Argon2id iteration count accepted when opening (same rationale as
/// [`ARGON2_MAX_M_COST_KIB`]: bound the CPU work a forged header can demand).
pub const ARGON2_MAX_T_COST: u32 = 64;
/// Maximum Argon2id parallelism accepted when opening.
pub const ARGON2_MAX_P_COST: u8 = 8;

/// Upper bound on the stored nickname, in bytes. A parsing bound, looser than
/// the user-facing rule ([`crate::identity::NICK_MAX_CHARS`] characters).
pub const NICK_MAX_BYTES: usize = 128;

/// Smallest well-formed plaintext payload: seed ‖ nick_len ‖ 1-byte nick.
const MIN_PAYLOAD_LEN: usize = Seed32::LEN + 2 + 1;

/// Errors produced by the keystore. No variant ever carries secret material.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// Underlying filesystem failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The OS CSPRNG failed while drawing the salt or nonce.
    #[error(transparent)]
    Rng(#[from] RngError),
    /// Argon2id rejected its inputs (never happens with the fixed constants;
    /// kept as an explicit error instead of a panic path).
    #[error("key derivation failed: {0}")]
    Kdf(String),
    /// AEAD encryption failed (never happens for our payload sizes; kept as
    /// an explicit error instead of a panic path).
    #[error("encryption failed")]
    Encrypt,
    /// The AEAD tag did not verify. Indistinguishable causes, honestly named:
    /// a wrong passphrase, or a corrupted/tampered file.
    #[error("invalid passphrase, or the keystore file is corrupted or tampered with")]
    AuthFailed,
    /// The file does not start with the Prism keystore magic bytes.
    #[error("not a Prism keystore file (bad magic bytes)")]
    NotAKeystore,
    /// The file uses a format version this build does not understand.
    #[error(
        "unsupported keystore format version {found} \
         (this build supports version {FORMAT_VERSION})"
    )]
    UnsupportedVersion {
        /// The version byte found in the file.
        found: u8,
    },
    /// The file is too short to possibly be a valid keystore.
    #[error("keystore file is truncated")]
    Truncated,
    /// The header's Argon2 parameters are outside the bounds this build
    /// accepts. Rejected *before* the KDF runs: a forged header must not be
    /// able to demand absurd memory or CPU work (the parameters are only
    /// AEAD-authenticated after the KDF has produced the key).
    #[error(
        "keystore Argon2 parameters out of accepted range \
         (m={m} KiB, t={t}, p={p})"
    )]
    KdfParamsOutOfRange {
        /// Memory cost found in the header, in KiB.
        m: u32,
        /// Iteration count found in the header.
        t: u32,
        /// Parallelism found in the header.
        p: u8,
    },
    /// The AEAD tag verified but the decrypted payload is malformed. Should
    /// never happen for a file we wrote; parsed defensively anyway.
    #[error("keystore payload is corrupted ({0})")]
    Corrupted(&'static str),
    /// Refusing to overwrite an existing keystore without `force`.
    #[error("a keystore already exists at {0}")]
    AlreadyExists(PathBuf),
    /// No keystore file at the given path.
    #[error("no keystore found at {0} (run `prism init` first)")]
    NotFound(PathBuf),
    /// The keystore path has no parent directory to create the file in.
    #[error("keystore path has no parent directory: {0}")]
    BadPath(PathBuf),
    /// Empty passphrases are rejected outright.
    #[error("the passphrase must not be empty")]
    EmptyPassphrase,
    /// The nickname is empty or exceeds [`NICK_MAX_BYTES`].
    #[error("the nickname must be 1 to {NICK_MAX_BYTES} bytes long")]
    BadNickLength,
}

/// What the keystore protects: the identity seed and the chosen nickname.
///
/// Deliberately mode-less: there is no field that could record whether the
/// seed came from the OS CSPRNG or from a recovery phrase, which enforces
/// on-disk indistinguishability at the type level. No `Clone`/`Debug`.
pub struct KeystoreContents {
    nick: String,
    seed: Seed32,
}

impl KeystoreContents {
    /// Bundle a nickname and an identity seed for sealing.
    pub fn new(nick: String, seed: Seed32) -> Self {
        Self { nick, seed }
    }

    /// The stored nickname.
    pub fn nick(&self) -> &str {
        &self.nick
    }

    /// The identity seed.
    pub fn seed(&self) -> &Seed32 {
        &self.seed
    }
}

/// Derive the AEAD key from the passphrase with Argon2id under the given
/// parameters (the defaults when sealing, the header's when opening — the
/// caller bounds-checks them first). Blocking and CPU/RAM-heavy by design:
/// never call on an async executor thread.
fn derive_key(
    passphrase: &Passphrase,
    salt: &[u8; SALT_LEN],
    m_cost: u32,
    t_cost: u32,
    p_cost: u8,
) -> Result<Zeroizing<[u8; KEY_LEN]>, KeystoreError> {
    let params = Params::new(m_cost, t_cost, u32::from(p_cost), Some(KEY_LEN))
        .map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase.expose_bytes(), salt, key.as_mut())
        .map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    Ok(key)
}

/// Encrypt `contents` under `passphrase` into a complete keystore file image.
///
/// Draws a fresh salt and nonce from the OS CSPRNG on every call. Blocking
/// (runs Argon2id): use `spawn_blocking` from async code.
pub fn seal_bytes(
    contents: &KeystoreContents,
    passphrase: &Passphrase,
) -> Result<Vec<u8>, KeystoreError> {
    if passphrase.is_empty() {
        return Err(KeystoreError::EmptyPassphrase);
    }
    let nick = contents.nick.as_bytes();
    if nick.is_empty() || nick.len() > NICK_MAX_BYTES {
        return Err(KeystoreError::BadNickLength);
    }

    let mut header = [0u8; HEADER_LEN];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[MAGIC.len()] = FORMAT_VERSION;
    header[M_COST_OFFSET..M_COST_OFFSET + 4]
        .copy_from_slice(&ARGON2_DEFAULT_M_COST_KIB.to_be_bytes());
    header[T_COST_OFFSET..T_COST_OFFSET + 4].copy_from_slice(&ARGON2_DEFAULT_T_COST.to_be_bytes());
    header[P_COST_OFFSET] = ARGON2_DEFAULT_P_COST;
    fill_random(&mut header[SALT_OFFSET..SALT_OFFSET + SALT_LEN])?;
    fill_random(&mut header[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN])?;

    let mut payload = Zeroizing::new(Vec::with_capacity(Seed32::LEN + 2 + nick.len()));
    payload.extend_from_slice(contents.seed.expose());
    // Cast is exact: nick.len() <= NICK_MAX_BYTES < u16::MAX, checked above.
    let nick_len = nick.len() as u16;
    payload.extend_from_slice(&nick_len.to_be_bytes());
    payload.extend_from_slice(nick);

    let salt: [u8; SALT_LEN] = header[SALT_OFFSET..SALT_OFFSET + SALT_LEN]
        .try_into()
        .map_err(|_| KeystoreError::Truncated)?;
    let key = derive_key(
        passphrase,
        &salt,
        ARGON2_DEFAULT_M_COST_KIB,
        ARGON2_DEFAULT_T_COST,
        ARGON2_DEFAULT_P_COST,
    )?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&header[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN]),
            Payload {
                msg: &payload,
                aad: &header,
            },
        )
        .map_err(|_| KeystoreError::Encrypt)?;

    let mut image = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    image.extend_from_slice(&header);
    image.extend_from_slice(&ciphertext);
    Ok(image)
}

/// Decrypt a complete keystore file image. The inverse of [`seal_bytes`].
///
/// Everything is parsed defensively; failures are clean typed errors, never
/// panics. Blocking (runs Argon2id): use `spawn_blocking` from async code.
pub fn open_bytes(
    bytes: &[u8],
    passphrase: &Passphrase,
) -> Result<KeystoreContents, KeystoreError> {
    if passphrase.is_empty() {
        return Err(KeystoreError::EmptyPassphrase);
    }
    if bytes.len() < HEADER_LEN {
        return Err(KeystoreError::Truncated);
    }
    let (header, body) = bytes.split_at(HEADER_LEN);
    if &header[..MAGIC.len()] != MAGIC {
        return Err(KeystoreError::NotAKeystore);
    }
    let found = header[MAGIC.len()];
    if found != FORMAT_VERSION {
        return Err(KeystoreError::UnsupportedVersion { found });
    }
    if body.len() < MIN_PAYLOAD_LEN + TAG_LEN {
        return Err(KeystoreError::Truncated);
    }

    // Parse the header's KDF parameters and bounds-check them BEFORE running
    // the KDF: they steer the KDF itself, so the AEAD tag can only vouch for
    // them afterwards. Without this cap a forged header could demand absurd
    // memory/CPU work (see KeystoreError::KdfParamsOutOfRange).
    let m_cost = u32::from_be_bytes(
        header[M_COST_OFFSET..M_COST_OFFSET + 4]
            .try_into()
            .map_err(|_| KeystoreError::Truncated)?,
    );
    let t_cost = u32::from_be_bytes(
        header[T_COST_OFFSET..T_COST_OFFSET + 4]
            .try_into()
            .map_err(|_| KeystoreError::Truncated)?,
    );
    let p_cost = header[P_COST_OFFSET];
    if m_cost > ARGON2_MAX_M_COST_KIB
        || t_cost == 0
        || t_cost > ARGON2_MAX_T_COST
        || p_cost == 0
        || p_cost > ARGON2_MAX_P_COST
    {
        return Err(KeystoreError::KdfParamsOutOfRange {
            m: m_cost,
            t: t_cost,
            p: p_cost,
        });
    }

    let salt: [u8; SALT_LEN] = header[SALT_OFFSET..SALT_OFFSET + SALT_LEN]
        .try_into()
        .map_err(|_| KeystoreError::Truncated)?;
    let key = derive_key(passphrase, &salt, m_cost, t_cost, p_cost)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let payload = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&header[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN]),
                Payload {
                    msg: body,
                    aad: header,
                },
            )
            // The AEAD tag is the sole integrity check (no hand-rolled
            // comparisons); its failure cannot distinguish a wrong passphrase
            // from a damaged file.
            .map_err(|_| KeystoreError::AuthFailed)?,
    );
    parse_payload(&payload)
}

/// Parse the decrypted payload: seed ‖ nick_len ‖ nick, strictly.
fn parse_payload(payload: &[u8]) -> Result<KeystoreContents, KeystoreError> {
    if payload.len() < MIN_PAYLOAD_LEN {
        return Err(KeystoreError::Corrupted("payload too short"));
    }
    let mut seed_buf = Zeroizing::new([0u8; Seed32::LEN]);
    seed_buf.copy_from_slice(&payload[..Seed32::LEN]);

    let nick_len_bytes: [u8; 2] = payload[Seed32::LEN..Seed32::LEN + 2]
        .try_into()
        .map_err(|_| KeystoreError::Corrupted("nick length"))?;
    let nick_len = usize::from(u16::from_be_bytes(nick_len_bytes));
    if nick_len == 0 || nick_len > NICK_MAX_BYTES {
        return Err(KeystoreError::Corrupted("nick length out of bounds"));
    }
    let nick_bytes = &payload[Seed32::LEN + 2..];
    if nick_bytes.len() != nick_len {
        return Err(KeystoreError::Corrupted("payload length mismatch"));
    }
    let nick = std::str::from_utf8(nick_bytes)
        .map_err(|_| KeystoreError::Corrupted("nick is not valid UTF-8"))?
        .to_owned();

    Ok(KeystoreContents {
        nick,
        seed: Seed32::from_buffer(seed_buf),
    })
}

/// Path of the temporary sibling used for atomic writes: `<file>.tmp`.
fn tmp_sibling(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(".tmp");
    PathBuf::from(os)
}

/// Seal `contents` and write the keystore file atomically.
///
/// Refuses to overwrite an existing keystore unless `force` is set. The write
/// is crash-safe: temp file (created `0600`) → fsync → rename over the final
/// path → fsync of the parent directory (which is forced to `0700`).
/// Blocking (runs Argon2id): use `spawn_blocking` from async code.
pub fn seal_to_path(
    path: &Path,
    contents: &KeystoreContents,
    passphrase: &Passphrase,
    force: bool,
) -> Result<(), KeystoreError> {
    if path.exists() && !force {
        return Err(KeystoreError::AlreadyExists(path.to_path_buf()));
    }
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| KeystoreError::BadPath(path.to_path_buf()))?;
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }

    let image = seal_bytes(contents, passphrase)?;

    let tmp_path = tmp_sibling(path);
    // Remove a stale temp file left behind by a crashed earlier attempt.
    match fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    let result = write_atomically(&tmp_path, path, dir, &image);
    if result.is_err() {
        // Best-effort cleanup; the original keystore (if any) is untouched.
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

/// The atomic tail of [`seal_to_path`]: write temp → fsync → rename → fsync
/// the directory.
fn write_atomically(
    tmp_path: &Path,
    path: &Path,
    dir: &Path,
    image: &[u8],
) -> Result<(), KeystoreError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut tmp = options.open(tmp_path)?;
    tmp.write_all(image)?;
    tmp.sync_all()?;
    drop(tmp);

    fs::rename(tmp_path, path)?;
    // Make the rename itself durable.
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Read and decrypt the keystore at `path`. The inverse of [`seal_to_path`].
/// Blocking (runs Argon2id): use `spawn_blocking` from async code.
pub fn open_from_path(
    path: &Path,
    passphrase: &Passphrase,
) -> Result<KeystoreContents, KeystoreError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(KeystoreError::NotFound(path.to_path_buf()))
        }
        Err(e) => return Err(e.into()),
    };
    open_bytes(&bytes, passphrase)
}
