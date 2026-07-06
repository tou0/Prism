// SPDX-License-Identifier: AGPL-3.0-or-later
//! Keystore integration tests: round-trips, hostile inputs, atomicity, and
//! recovery-mode indistinguishability.
//!
//! Every Argon2id run here costs real time by design (hundreds of ms at the
//! default parameters), so tests share one sealed image where possible.

use std::sync::OnceLock;

use prism_core::keystore::{
    open_bytes, open_from_path, seal_bytes, seal_to_path, KeystoreContents, KeystoreError,
    ARGON2_MAX_M_COST_KIB, FORMAT_VERSION, HEADER_LEN, MAGIC, MAX_KEYSTORE_LEN, M_COST_OFFSET,
    NICK_MAX_BYTES, NONCE_LEN, NONCE_OFFSET, SALT_LEN, SALT_OFFSET, T_COST_OFFSET,
};
use prism_core::recovery::RecoveryPhrase;
use prism_core::{IdentityKeypair, Passphrase, Seed32};

const NICK: &str = "alice";
const PASSPHRASE: &str = "correct horse battery staple";
const SEED_FILL: u8 = 0x07;

fn passphrase() -> Passphrase {
    Passphrase::from(PASSPHRASE.to_owned())
}

fn contents() -> KeystoreContents {
    KeystoreContents::new(NICK.to_owned(), Seed32::from_bytes([SEED_FILL; 32]))
}

/// One sealed keystore image, shared across read-only tests to keep the
/// number of Argon2id runs down.
// Test-only helper: clippy's `allow-unwrap-in-tests` does not reach helpers
// outside `#[test]` functions, hence the explicit allow.
#[allow(clippy::unwrap_used)]
fn image() -> &'static [u8] {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| seal_bytes(&contents(), &passphrase()).unwrap())
}

#[test]
fn round_trip_returns_the_same_identity() {
    let opened = open_bytes(image(), &passphrase()).unwrap();
    assert_eq!(opened.nick(), NICK);
    assert_eq!(opened.seed().expose(), &[SEED_FILL; 32]);

    // Same seed -> same identity -> same handle.
    let expected = IdentityKeypair::from_seed(contents().seed());
    let recovered = IdentityKeypair::from_seed(opened.seed());
    assert_eq!(expected.public(), recovered.public());
    assert_eq!(
        expected.public().handle(opened.nick()),
        recovered.public().handle(NICK)
    );
}

#[test]
fn wrong_passphrase_is_a_clean_auth_error() {
    let wrong = Passphrase::from("not the passphrase".to_owned());
    assert!(matches!(
        open_bytes(image(), &wrong),
        Err(KeystoreError::AuthFailed)
    ));
}

#[test]
fn empty_passphrase_is_rejected_without_running_the_kdf() {
    let empty = Passphrase::from(String::new());
    assert!(matches!(
        seal_bytes(&contents(), &empty),
        Err(KeystoreError::EmptyPassphrase)
    ));
    assert!(matches!(
        open_bytes(image(), &empty),
        Err(KeystoreError::EmptyPassphrase)
    ));
}

#[test]
fn nick_length_bounds_are_enforced_on_seal() {
    let empty = KeystoreContents::new(String::new(), Seed32::from_bytes([1; 32]));
    assert!(matches!(
        seal_bytes(&empty, &passphrase()),
        Err(KeystoreError::BadNickLength)
    ));

    let oversized =
        KeystoreContents::new("x".repeat(NICK_MAX_BYTES + 1), Seed32::from_bytes([1; 32]));
    assert!(matches!(
        seal_bytes(&oversized, &passphrase()),
        Err(KeystoreError::BadNickLength)
    ));
}

#[test]
fn a_flipped_byte_in_any_region_is_rejected() {
    // (offset into the file, expected error)
    let magic_off = 0;
    let version_off = MAGIC.len();
    // Low byte of t_cost: the flip (8 -> 9) stays within the accepted bounds,
    // so it must be caught by the AEAD tag, not the range check.
    let t_cost_off = T_COST_OFFSET + 3;
    let ciphertext_off = HEADER_LEN;
    let tag_last = image().len() - 1;

    for (offset, name) in [
        (t_cost_off, "KDF parameters"),
        (SALT_OFFSET, "salt"),
        (NONCE_OFFSET, "nonce"),
        (ciphertext_off, "ciphertext"),
        (tag_last, "tag"),
    ] {
        let mut tampered = image().to_vec();
        tampered[offset] ^= 0x01;
        assert!(
            matches!(
                open_bytes(&tampered, &passphrase()),
                Err(KeystoreError::AuthFailed)
            ),
            "flipping a byte in the {name} must fail the AEAD tag"
        );
    }

    let mut bad_magic = image().to_vec();
    bad_magic[magic_off] ^= 0x01;
    assert!(matches!(
        open_bytes(&bad_magic, &passphrase()),
        Err(KeystoreError::NotAKeystore)
    ));

    let mut bad_version = image().to_vec();
    bad_version[version_off] ^= 0x01;
    assert!(matches!(
        open_bytes(&bad_version, &passphrase()),
        Err(KeystoreError::UnsupportedVersion { .. })
    ));
}

#[test]
fn unknown_format_version_is_a_clean_error() {
    let mut future = image().to_vec();
    future[MAGIC.len()] = FORMAT_VERSION + 1;
    assert!(matches!(
        open_bytes(&future, &passphrase()),
        Err(KeystoreError::UnsupportedVersion { found }) if found == FORMAT_VERSION + 1
    ));
}

#[test]
fn truncated_files_are_clean_errors_not_panics_or_hangs() {
    // Every possible header-level truncation, plus a body-level one; all are
    // rejected before the KDF runs (cheap), except the last-byte cut which
    // must fail the AEAD tag.
    for len in [
        0,
        1,
        MAGIC.len(),
        HEADER_LEN - 1,
        HEADER_LEN,
        HEADER_LEN + 5,
    ] {
        let cut = &image()[..len];
        assert!(
            matches!(
                open_bytes(cut, &passphrase()),
                Err(KeystoreError::Truncated)
            ),
            "a {len}-byte prefix must be Truncated"
        );
    }

    let cut = &image()[..image().len() - 1];
    assert!(matches!(
        open_bytes(cut, &passphrase()),
        Err(KeystoreError::AuthFailed)
    ));
}

#[test]
fn garbage_that_is_not_a_keystore_is_rejected() {
    assert!(matches!(
        open_bytes(&[0x42; 128], &passphrase()),
        Err(KeystoreError::NotAKeystore)
    ));
}

#[test]
fn every_write_uses_a_fresh_salt_and_nonce() {
    let a = seal_bytes(&contents(), &passphrase()).unwrap();
    let b = image();
    assert_eq!(a.len(), b.len());
    assert_ne!(
        a[SALT_OFFSET..SALT_OFFSET + SALT_LEN],
        b[SALT_OFFSET..SALT_OFFSET + SALT_LEN],
        "salt must be fresh"
    );
    assert_ne!(
        a[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN],
        b[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN],
        "nonce must be fresh"
    );
    assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..], "ciphertext must differ");
}

/// A forged header demanding absurd KDF work must be rejected *before* the
/// KDF runs — cheaply — not attempted. (The AEAD tag cannot protect these
/// fields up front: they steer the KDF that produces the tag's key.)
#[test]
fn hostile_kdf_params_are_rejected_before_running_the_kdf() {
    // Memory demand far beyond the cap (u32::MAX KiB = 4 TiB).
    let mut greedy = image().to_vec();
    greedy[M_COST_OFFSET..M_COST_OFFSET + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        open_bytes(&greedy, &passphrase()),
        Err(KeystoreError::KdfParamsOutOfRange { m: u32::MAX, .. })
    ));

    // Just above the memory cap.
    let mut above = image().to_vec();
    above[M_COST_OFFSET..M_COST_OFFSET + 4]
        .copy_from_slice(&(ARGON2_MAX_M_COST_KIB + 1).to_be_bytes());
    assert!(matches!(
        open_bytes(&above, &passphrase()),
        Err(KeystoreError::KdfParamsOutOfRange { .. })
    ));

    // Degenerate zero iteration count.
    let mut zero_t = image().to_vec();
    zero_t[T_COST_OFFSET..T_COST_OFFSET + 4].copy_from_slice(&0u32.to_be_bytes());
    assert!(matches!(
        open_bytes(&zero_t, &passphrase()),
        Err(KeystoreError::KdfParamsOutOfRange { t: 0, .. })
    ));
}

/// The critical M1 property (spec §4.2): the on-disk keystore must not reveal
/// whether a recovery phrase exists. Both modes are sealed with the same nick
/// and compared structurally.
#[test]
fn keystores_are_indistinguishable_between_recovery_modes() {
    let zero_recovery = KeystoreContents::new(NICK.to_owned(), Seed32::generate().unwrap());
    let phrase = RecoveryPhrase::generate().unwrap();
    let with_recovery =
        KeystoreContents::new(NICK.to_owned(), phrase.derive_identity_seed().unwrap());

    let a = seal_bytes(&zero_recovery, &passphrase()).unwrap();
    let b = seal_bytes(&with_recovery, &passphrase()).unwrap();

    // Identical total length: no field, flag, or size difference.
    assert_eq!(a.len(), b.len());
    // Identical fixed header structure (magic ‖ version ‖ KDF parameters —
    // the same defaults regardless of mode); everything after is uniformly
    // random (salt, nonce) or ciphertext in both modes.
    assert_eq!(a[..SALT_OFFSET], b[..SALT_OFFSET]);
    // Nothing mode-dependent survives a round-trip either: the payload is
    // seed ‖ nick in both cases (KeystoreContents has no mode field at all).
    let opened = open_bytes(&b, &passphrase()).unwrap();
    assert_eq!(opened.nick(), NICK);
    assert_eq!(
        opened.seed().expose(),
        with_recovery.seed().expose(),
        "recovery-derived seed must round-trip unchanged"
    );
}

#[test]
fn atomic_write_creates_locked_down_files_and_respects_force() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store").join("keystore.pks");

    seal_to_path(&path, &contents(), &passphrase(), false).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "keystore file must be 0600");
        assert_eq!(dir_mode, 0o700, "keystore directory must be 0700");
    }

    // No temp file left behind.
    let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(leftovers, vec![std::ffi::OsString::from("keystore.pks")]);

    // Refuses to overwrite without force...
    assert!(matches!(
        seal_to_path(&path, &contents(), &passphrase(), false),
        Err(KeystoreError::AlreadyExists(_))
    ));

    // ...and the original is still readable afterwards.
    let opened = open_from_path(&path, &passphrase()).unwrap();
    assert_eq!(opened.nick(), NICK);

    // With force, a new identity replaces the old one.
    let other = KeystoreContents::new("bob".to_owned(), Seed32::from_bytes([9; 32]));
    seal_to_path(&path, &other, &passphrase(), true).unwrap();
    let reopened = open_from_path(&path, &passphrase()).unwrap();
    assert_eq!(reopened.nick(), "bob");
}

#[test]
fn an_oversized_file_is_rejected_before_reading_it_all() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bloated.pks");

    // A valid image followed by a large blob: bigger than any real keystore.
    let mut bloated = image().to_vec();
    bloated.extend(std::iter::repeat(0u8).take(MAX_KEYSTORE_LEN + 4096));
    std::fs::write(&path, &bloated).unwrap();

    assert!(matches!(
        open_from_path(&path, &passphrase()),
        Err(KeystoreError::TooLarge)
    ));
}

#[test]
fn opening_a_missing_keystore_is_a_clean_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nowhere.pks");
    assert!(matches!(
        open_from_path(&path, &passphrase()),
        Err(KeystoreError::NotFound(_))
    ));
}
