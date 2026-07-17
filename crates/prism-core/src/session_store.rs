// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sealed ratchet-state store: `sessions.prs` ("Prism Ratchet Store").
//!
//! Ratchet state advances on **every** message, so this store is built for
//! frequent rewrites — unlike the keystore, whose Argon2id-per-write
//! discipline would cost hundreds of milliseconds and 64 MiB per message.
//! Instead, the store is sealed under a **vault key** derived once, in RAM,
//! from the identity seed:
//!
//! ```text
//! vault_key = HKDF-SHA512(ikm = identity seed, salt = none,
//!                         info = "prism v1 session-store key")   → 32 bytes
//! ```
//!
//! The vault key never touches disk and there is no keystore format change:
//! the sessions file is unreadable without the passphrase → seed chain, i.e.
//! it lives under the keystore's protection umbrella. Restoring an identity
//! on a new device (same seed, no sessions file) starts with fresh sessions,
//! which is the correct semantics. Residual documented in `docs/sessions.md`:
//! a holder of the recovery phrase alone can derive the vault key — the file
//! is protected exactly to the extent the seed is.
//!
//! On-disk format v1 (mirrors the keystore discipline; no KDF parameters —
//! the key is full-entropy, so no KDF runs at open time):
//!
//! ```text
//! ┌─ Header (20 bytes, plaintext, authenticated as AEAD associated data) ─┐
//! │ 0   7   magic  = "PRISMRS"                                            │
//! │ 7   1   format version = 0x01                                         │
//! │ 8   12  AEAD nonce (OS CSPRNG, fresh on every write)                  │
//! ├─ Body ────────────────────────────────────────────────────────────────┤
//! │ 20  ..  ChaCha20-Poly1305 ciphertext (payload ‖ 16-byte tag)          │
//! └───────────────────────────────────────────────────────────────────────┘
//!
//! payload = serde_json of StorePayload (account pickle, session records)
//! ```
//!
//! Same key + fresh random 96-bit nonce per write is the standard AEAD model
//! (collision bound after 2^30 writes ≈ 2^-37). Writes are atomic
//! (temp → fsync → rename → fsync dir, `0600`/`0700`; see [`crate::storage`]).
//!
//! **Serialization hygiene** (the M1 `expose_phrase` bug class): the payload
//! holds ratchet secrets, and `serde_json::to_vec` would grow its buffer by
//! reallocation, strewing un-wiped fragments across the heap. Serialization
//! here goes into a **pre-sized `Zeroizing` buffer** whose capacity hint is
//! tracked across writes, so growth-reallocation is rare (first write, or a
//! store that outgrew its hint) rather than per-write. Residuals that remain
//! (documented in `docs/sessions.md`): serde's internal scratch during
//! (de)serialization, and any rare hint overflow. vodozemac's pickle types
//! zeroize their key material on drop.

use std::path::PathBuf;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use vodozemac::olm::{AccountPickle, SessionPickle};
use zeroize::Zeroizing;

use crate::secret::{fill_random, RngError, Seed32};

/// Magic bytes identifying a Prism ratchet-store file.
pub const SESSIONS_MAGIC: &[u8; 7] = b"PRISMRS";
/// Current on-disk format version of the ratchet store.
pub const SESSIONS_FORMAT_VERSION: u8 = 1;
/// Length of the AEAD nonce in the header.
pub const SESSIONS_NONCE_LEN: usize = 12;
/// Total header length: magic ‖ version ‖ nonce.
pub const SESSIONS_HEADER_LEN: usize = SESSIONS_MAGIC.len() + 1 + SESSIONS_NONCE_LEN;
/// Length of the Poly1305 tag.
const TAG_LEN: usize = 16;
/// Hard bound on the sessions file size (64 MiB): a hostile or unbounded
/// file cannot force a larger allocation. Far above any realistic store.
pub const MAX_SESSIONS_LEN: usize = 64 * 1024 * 1024;
/// HKDF info string for the vault-key derivation.
pub const VAULT_KEY_DOMAIN: &[u8] = b"prism v1 session-store key";
/// Default file name of the ratchet store inside the data directory.
pub const DEFAULT_SESSIONS_FILE: &str = "sessions.prs";

/// Initial capacity hint for the serialized payload buffer.
const INITIAL_CAPACITY_HINT: usize = 16 * 1024;

/// Errors produced by the ratchet store. No variant ever carries secrets.
#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    /// Underlying filesystem failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The OS CSPRNG failed while drawing the nonce.
    #[error(transparent)]
    Rng(#[from] RngError),
    /// HKDF vault-key derivation failed (impossible by the HKDF definition
    /// for a 32-byte output; kept as an explicit error instead of a panic
    /// path, mirroring the keystore's KDF error).
    #[error("vault key derivation failed")]
    Kdf,
    /// AEAD encryption failed (never happens for our payload sizes; kept as
    /// an explicit error instead of a panic path).
    #[error("encryption failed")]
    Encrypt,
    /// The AEAD tag did not verify: wrong vault key (wrong identity), or a
    /// corrupted/tampered file — indistinguishable causes, honestly named.
    #[error("session store cannot be opened: wrong identity, or the file is corrupted")]
    AuthFailed,
    /// The file does not start with the Prism ratchet-store magic bytes.
    #[error("not a Prism session store (bad magic bytes)")]
    NotASessionStore,
    /// The file uses a format version this build does not understand.
    #[error(
        "unsupported session-store format version {found} \
         (this build supports version {SESSIONS_FORMAT_VERSION})"
    )]
    UnsupportedVersion {
        /// The version byte found in the file.
        found: u8,
    },
    /// The file is too short to possibly be a valid store.
    #[error("session store file is truncated")]
    Truncated,
    /// The file exceeds [`MAX_SESSIONS_LEN`].
    #[error("session store file is larger than the accepted maximum")]
    TooLarge,
    /// The decrypted payload is malformed. Should never happen for a file we
    /// wrote (it is AEAD-authenticated); parsed defensively anyway.
    #[error("session store payload is corrupted ({0})")]
    Corrupted(&'static str),
    /// The store path has no parent directory to create the file in.
    #[error("session store path has no parent directory: {0}")]
    BadPath(PathBuf),
}

/// Everything the store persists. **Ratchet state only** — decrypted message
/// content cannot structurally reach this type, which is what the
/// no-plaintext-on-disk guarantee rests on (asserted by tests).
///
/// No `Clone`/`Debug`: the pickles hold ratchet secrets.
#[derive(Serialize, Deserialize)]
pub(crate) struct StorePayload {
    /// The vodozemac account (identity curve key, one-time keys, fallback).
    pub account: AccountPickle,
    /// Public half of the current fallback key, if one was generated
    /// (`Account::fallback_key()` stops exposing it once marked published).
    pub fallback_pub: Option<[u8; 32]>,
    /// The currently published signed bundle, for re-serving as-is.
    pub published_bundle: Option<Vec<u8>>,
    /// All live sessions.
    pub sessions: Vec<SessionRecord>,
}

/// One persisted session and the peer identity bound to it.
///
/// No `Clone`/`Debug`: the pickle holds ratchet secrets.
#[derive(Serialize, Deserialize)]
pub(crate) struct SessionRecord {
    /// vodozemac session id (base64), the routing key for incoming messages.
    pub session_id: String,
    /// The peer's Ed25519 identity key, as bound at establishment
    /// (bundle-verified outbound, binding-envelope-verified inbound).
    pub peer_ed25519: [u8; 32],
    /// Whether we initiated this session (outbound) or the peer did.
    pub initiated_by_us: bool,
    /// The identity-binding envelope we attach to pre-reply messages
    /// (outbound sessions only; public material: sender key + signature).
    pub binding: Option<Vec<u8>>,
    /// The vodozemac ratchet state.
    pub session: SessionPickle,
}

/// Derive the vault key from the identity seed (see the module docs).
///
/// Expanding 32 bytes out of HKDF-SHA512 cannot fail (well under 255 × 64);
/// the impossible failure is still a typed error, never a panic or a
/// silently-zeroed key.
pub(crate) fn derive_vault_key(seed: &Seed32) -> Result<Zeroizing<[u8; 32]>, SessionStoreError> {
    let hkdf = Hkdf::<Sha512>::new(None, seed.expose());
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(VAULT_KEY_DOMAIN, key.as_mut())
        .map_err(|_| SessionStoreError::Kdf)?;
    Ok(key)
}

/// Serialize `value` into a pre-sized zeroizing buffer (see module docs).
fn serialize_presized<T: Serialize>(
    value: &T,
    capacity: usize,
) -> Result<Zeroizing<Vec<u8>>, SessionStoreError> {
    let mut buf = Zeroizing::new(Vec::with_capacity(capacity));
    serde_json::to_writer(&mut *buf, value)
        .map_err(|_| SessionStoreError::Corrupted("payload serialization"))?;
    Ok(buf)
}

/// Encrypt a serialized payload into a complete store-file image.
fn seal_store_bytes(payload: &[u8], vault_key: &[u8; 32]) -> Result<Vec<u8>, SessionStoreError> {
    let mut header = [0u8; SESSIONS_HEADER_LEN];
    header[..SESSIONS_MAGIC.len()].copy_from_slice(SESSIONS_MAGIC);
    header[SESSIONS_MAGIC.len()] = SESSIONS_FORMAT_VERSION;
    fill_random(&mut header[SESSIONS_MAGIC.len() + 1..])?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(vault_key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&header[SESSIONS_MAGIC.len() + 1..]),
            Payload {
                msg: payload,
                aad: &header,
            },
        )
        .map_err(|_| SessionStoreError::Encrypt)?;

    let mut image = Vec::with_capacity(SESSIONS_HEADER_LEN + ciphertext.len());
    image.extend_from_slice(&header);
    image.extend_from_slice(&ciphertext);
    Ok(image)
}

/// Decrypt a complete store-file image. The inverse of [`seal_store_bytes`].
fn open_store_bytes(
    bytes: &[u8],
    vault_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, SessionStoreError> {
    if bytes.len() < SESSIONS_HEADER_LEN + TAG_LEN {
        return Err(SessionStoreError::Truncated);
    }
    let (header, body) = bytes.split_at(SESSIONS_HEADER_LEN);
    if &header[..SESSIONS_MAGIC.len()] != SESSIONS_MAGIC {
        return Err(SessionStoreError::NotASessionStore);
    }
    let found = header[SESSIONS_MAGIC.len()];
    if found != SESSIONS_FORMAT_VERSION {
        return Err(SessionStoreError::UnsupportedVersion { found });
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(vault_key));
    let payload = cipher
        .decrypt(
            Nonce::from_slice(&header[SESSIONS_MAGIC.len() + 1..]),
            Payload {
                msg: body,
                aad: header,
            },
        )
        .map_err(|_| SessionStoreError::AuthFailed)?;
    Ok(Zeroizing::new(payload))
}

/// The sealed, atomically-rewritten ratchet store bound to one path and one
/// vault key. No `Clone`/`Debug`: holds the vault key.
pub struct SealedSessionStore {
    path: PathBuf,
    vault_key: Zeroizing<[u8; 32]>,
    capacity_hint: usize,
}

impl SealedSessionStore {
    /// Bind a store to `path`, deriving the vault key from `seed`.
    pub(crate) fn new(path: PathBuf, seed: &Seed32) -> Result<Self, SessionStoreError> {
        Ok(Self {
            path,
            vault_key: derive_vault_key(seed)?,
            capacity_hint: INITIAL_CAPACITY_HINT,
        })
    }

    /// The file path this store reads and writes.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Persist `payload` atomically. Durable when this returns `Ok`: the
    /// bytes are fsync'd and the rename is fsync'd in the parent directory —
    /// the property the persist-before-transmit contract builds on.
    pub(crate) fn store(&mut self, payload: &StorePayload) -> Result<(), SessionStoreError> {
        let serialized = serialize_presized(payload, self.capacity_hint)?;
        // Keep the hint ahead of growth so the next serialization does not
        // reallocate (reallocation leaves un-wiped fragments; see module docs).
        if serialized.len() > self.capacity_hint / 2 {
            self.capacity_hint = serialized.len().saturating_mul(2);
        }

        let image = seal_store_bytes(&serialized, &self.vault_key)?;
        let dir = crate::storage::prepare_private_dir(&self.path)?
            .ok_or_else(|| SessionStoreError::BadPath(self.path.clone()))?;
        crate::storage::write_atomically_private(&self.path, dir, &image)?;
        Ok(())
    }

    /// Load the persisted payload, or `None` if no store file exists yet.
    pub(crate) fn load(&mut self) -> Result<Option<StorePayload>, SessionStoreError> {
        let Some(bytes) = crate::storage::read_bounded(&self.path, MAX_SESSIONS_LEN)? else {
            return Ok(None);
        };
        if bytes.len() > MAX_SESSIONS_LEN {
            return Err(SessionStoreError::TooLarge);
        }
        let payload_bytes = open_store_bytes(&bytes, &self.vault_key)?;
        self.capacity_hint = self
            .capacity_hint
            .max(payload_bytes.len().saturating_mul(2));
        let payload: StorePayload = serde_json::from_slice(&payload_bytes)
            .map_err(|_| SessionStoreError::Corrupted("payload deserialization"))?;
        Ok(Some(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vodozemac::olm::Account;

    fn seed(fill: u8) -> Seed32 {
        Seed32::from_bytes([fill; 32])
    }

    fn sample_payload() -> StorePayload {
        let mut account = Account::new();
        account.generate_one_time_keys(2);
        StorePayload {
            account: account.pickle(),
            fallback_pub: Some([7u8; 32]),
            published_bundle: Some(vec![1, 2, 3]),
            sessions: Vec::new(),
        }
    }

    #[test]
    fn round_trips_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store").join("sessions.prs");
        let mut store = SealedSessionStore::new(path.clone(), &seed(1)).unwrap();

        assert!(store.load().unwrap().is_none(), "no file yet");
        store.store(&sample_payload()).unwrap();

        let reloaded = store.load().unwrap().expect("payload");
        assert_eq!(reloaded.fallback_pub, Some([7u8; 32]));
        assert_eq!(reloaded.published_bundle.as_deref(), Some(&[1, 2, 3][..]));
        // The account pickle round-trips into a working account.
        let account = Account::from_pickle(reloaded.account);
        assert_eq!(account.stored_one_time_key_count(), 2);
    }

    #[test]
    fn file_and_directory_permissions_are_locked_down() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store").join("sessions.prs");
        let mut store = SealedSessionStore::new(path.clone(), &seed(1)).unwrap();
        store.store(&sample_payload()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            let dir_mode = std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o600);
            assert_eq!(dir_mode, 0o700);
        }
        // No temp sibling left behind.
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("sessions.prs")]);
    }

    #[test]
    fn a_different_seed_cannot_open_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.prs");
        let mut store = SealedSessionStore::new(path.clone(), &seed(1)).unwrap();
        store.store(&sample_payload()).unwrap();

        let mut wrong = SealedSessionStore::new(path, &seed(2)).unwrap();
        assert!(matches!(wrong.load(), Err(SessionStoreError::AuthFailed)));
    }

    #[test]
    fn tampering_with_any_byte_fails_the_tag() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.prs");
        let mut store = SealedSessionStore::new(path.clone(), &seed(1)).unwrap();
        store.store(&sample_payload()).unwrap();

        let image = std::fs::read(&path).unwrap();
        for offset in [
            SESSIONS_MAGIC.len() + 1,
            SESSIONS_HEADER_LEN,
            image.len() - 1,
        ] {
            let mut tampered = image.clone();
            tampered[offset] ^= 0x01;
            std::fs::write(&path, &tampered).unwrap();
            assert!(
                matches!(store.load(), Err(SessionStoreError::AuthFailed)),
                "flipping byte {offset} must fail the AEAD tag"
            );
        }
    }

    #[test]
    fn magic_version_truncation_and_size_are_clean_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.prs");
        let mut store = SealedSessionStore::new(path.clone(), &seed(1)).unwrap();
        store.store(&sample_payload()).unwrap();
        let image = std::fs::read(&path).unwrap();

        let mut bad_magic = image.clone();
        bad_magic[0] ^= 0x01;
        std::fs::write(&path, &bad_magic).unwrap();
        assert!(matches!(
            store.load(),
            Err(SessionStoreError::NotASessionStore)
        ));

        let mut future = image.clone();
        future[SESSIONS_MAGIC.len()] = SESSIONS_FORMAT_VERSION + 1;
        std::fs::write(&path, &future).unwrap();
        assert!(matches!(
            store.load(),
            Err(SessionStoreError::UnsupportedVersion { found }) if found == SESSIONS_FORMAT_VERSION + 1
        ));

        std::fs::write(&path, &image[..SESSIONS_HEADER_LEN + TAG_LEN - 1]).unwrap();
        assert!(matches!(store.load(), Err(SessionStoreError::Truncated)));

        // Oversized: one byte past the cap.
        let oversized = vec![0u8; MAX_SESSIONS_LEN + 1];
        std::fs::write(&path, &oversized).unwrap();
        assert!(matches!(store.load(), Err(SessionStoreError::TooLarge)));
    }

    #[test]
    fn every_write_uses_a_fresh_nonce_and_fresh_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.prs");
        let mut store = SealedSessionStore::new(path.clone(), &seed(1)).unwrap();

        store.store(&sample_payload()).unwrap();
        let first = std::fs::read(&path).unwrap();
        store.store(&sample_payload()).unwrap();
        let second = std::fs::read(&path).unwrap();

        assert_ne!(
            first[SESSIONS_MAGIC.len() + 1..SESSIONS_HEADER_LEN],
            second[SESSIONS_MAGIC.len() + 1..SESSIONS_HEADER_LEN],
            "nonce must be fresh on every write"
        );
        assert_ne!(first[SESSIONS_HEADER_LEN..], second[SESSIONS_HEADER_LEN..]);
    }

    #[test]
    fn a_stale_tmp_file_from_a_crash_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.prs");
        // Simulate a crash mid-write: a half-written temp sibling.
        std::fs::write(dir.path().join("sessions.prs.tmp"), b"half-written").unwrap();

        let mut store = SealedSessionStore::new(path.clone(), &seed(1)).unwrap();
        store.store(&sample_payload()).unwrap();
        assert!(store.load().unwrap().is_some());
        assert!(!dir.path().join("sessions.prs.tmp").exists());
    }

    #[test]
    fn vault_keys_differ_per_seed_and_match_the_golden_vector() {
        let a = derive_vault_key(&seed(1)).unwrap();
        let b = derive_vault_key(&seed(2)).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
        // Golden vector: freezes the HKDF domain and construction (a silent
        // change would strand every existing sessions.prs).
        assert_eq!(
            hex::encode(derive_vault_key(&seed(0x42)).unwrap().as_ref()),
            "df070359f21939271cb314e3421502699b43653779cb9efbdb09dced0c5887c6",
            "the vault-key derivation changed"
        );
    }
}
