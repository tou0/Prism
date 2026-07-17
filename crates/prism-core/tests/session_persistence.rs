// SPDX-License-Identifier: AGPL-3.0-or-later
//! Persistence tests: resume-after-restart, the persist-before-transmit
//! contract under crash windows, replay-after-reload, the no-plaintext-on-
//! disk guarantee, and the full M1 keystore → M2 session chain.

use prism_core::keystore::{self, KeystoreContents};
use prism_core::session::{OtkChoice, SessionError, SessionManager};
use prism_core::{IdentityKeypair, Passphrase, Seed32};

fn identity(fill: u8) -> IdentityKeypair {
    IdentityKeypair::from_seed(&Seed32::from_bytes([fill; 32]))
}

// Test-only helper: clippy's allow-expect-in-tests does not reach helpers
// outside #[test] fns, hence the explicit allow.
#[allow(clippy::expect_used)]
fn open(dir: &tempfile::TempDir, name: &str, fill: u8) -> SessionManager {
    SessionManager::open(&identity(fill), dir.path().join(name).join("sessions.prs"))
        .expect("open manager")
}

#[test]
fn restart_resumes_the_same_session_in_both_directions() {
    let dir = tempfile::tempdir().unwrap();
    let mut alice = open(&dir, "alice", 0xA1);
    let mut bob = open(&dir, "bob", 0xB0);
    let bob_public = identity(0xB0).public();

    let bundle = bob.publish_bundle(4).unwrap();
    let sid = alice
        .establish_outbound(&bob_public, &bundle, OtkChoice::Auto)
        .unwrap();
    let received = bob
        .decrypt(&alice.encrypt(&sid, b"before restart").unwrap())
        .unwrap();
    let bob_sid = received.session;
    assert!(alice
        .decrypt(&bob.encrypt(&bob_sid, b"ack").unwrap())
        .is_ok());

    // "Restart": drop both managers, reload everything from the sealed files.
    drop(alice);
    drop(bob);
    let mut alice = open(&dir, "alice", 0xA1);
    let mut bob = open(&dir, "bob", 0xB0);

    // The SAME sessions continue, both directions, ratchet intact.
    let wire = alice.encrypt(&sid, b"after restart").unwrap();
    let received = bob.decrypt(&wire).unwrap();
    assert_eq!(received.plaintext.as_slice(), b"after restart");
    assert_eq!(received.session, bob_sid, "same session resumed");
    assert_eq!(
        received.peer.fingerprint().full(),
        identity(0xA1).public().fingerprint().full()
    );
    let reply = bob.encrypt(&bob_sid, b"still here").unwrap();
    assert_eq!(
        alice.decrypt(&reply).unwrap().plaintext.as_slice(),
        b"still here"
    );
}

/// The persist-before-transmit contract, positive case: a crash immediately
/// after `encrypt` returns must NOT reuse a message key, because the advanced
/// state was durable before the ciphertext escaped.
#[test]
fn crash_after_encrypt_reuses_no_message_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut alice = open(&dir, "alice", 0xA1);
    let mut bob = open(&dir, "bob", 0xB0);
    let bob_public = identity(0xB0).public();

    // Reach the normal (post-reply) phase so chain indices are observable.
    let bundle = bob.publish_bundle(4).unwrap();
    let sid = alice
        .establish_outbound(&bob_public, &bundle, OtkChoice::Auto)
        .unwrap();
    let bob_sid = bob
        .decrypt(&alice.encrypt(&sid, b"hi").unwrap())
        .unwrap()
        .session;
    assert!(alice
        .decrypt(&bob.encrypt(&bob_sid, b"hi back").unwrap())
        .is_ok());

    let c1 = alice.encrypt(&sid, b"message one").unwrap();
    // CRASH: alice's process dies right after encrypt() returned (the wire
    // bytes escaped; nothing else did).
    drop(alice);
    let mut alice = open(&dir, "alice", 0xA1);
    let c2 = alice.encrypt(&sid, b"message two").unwrap();

    // The reloaded state continued the chain instead of reusing it.
    let index = |wire: &[u8]| -> u64 {
        let sid_len = usize::from(wire[2]);
        let message = vodozemac::olm::Message::from_bytes(&wire[3 + sid_len..]).unwrap();
        message.chain_index()
    };
    assert_eq!(
        index(&c2),
        index(&c1) + 1,
        "the ratchet advance must survive the crash (no key reuse)"
    );

    // Both decrypt cleanly on Bob's side.
    assert_eq!(
        bob.decrypt(&c1).unwrap().plaintext.as_slice(),
        b"message one"
    );
    assert_eq!(
        bob.decrypt(&c2).unwrap().plaintext.as_slice(),
        b"message two"
    );
}

/// Negative control: demonstrate the catastrophic key reuse that stale state
/// produces — exactly what persist-BEFORE-transmit prevents. We violate the
/// ordering by hand (snapshot the file, encrypt, restore the snapshot).
#[test]
fn stale_state_would_reuse_message_keys_which_the_contract_prevents() {
    let dir = tempfile::tempdir().unwrap();
    let mut alice = open(&dir, "alice", 0xA1);
    let mut bob = open(&dir, "bob", 0xB0);
    let bob_public = identity(0xB0).public();

    let bundle = bob.publish_bundle(4).unwrap();
    let sid = alice
        .establish_outbound(&bob_public, &bundle, OtkChoice::Auto)
        .unwrap();
    let bob_sid = bob
        .decrypt(&alice.encrypt(&sid, b"hi").unwrap())
        .unwrap()
        .session;
    assert!(alice
        .decrypt(&bob.encrypt(&bob_sid, b"hi back").unwrap())
        .is_ok());

    // Snapshot alice's durable state, send, then roll the file back — i.e.
    // simulate "transmit happened but persist did not" (the forbidden order).
    let store_path = dir.path().join("alice").join("sessions.prs");
    let snapshot = std::fs::read(&store_path).unwrap();
    let c1 = alice.encrypt(&sid, b"real message").unwrap();
    drop(alice);
    std::fs::write(&store_path, &snapshot).unwrap();

    let mut stale_alice = open(&dir, "alice", 0xA1);
    let c1_again = stale_alice
        .encrypt(&sid, b"attacker-visible reuse")
        .unwrap();

    let index = |wire: &[u8]| -> u64 {
        let sid_len = usize::from(wire[2]);
        vodozemac::olm::Message::from_bytes(&wire[3 + sid_len..])
            .unwrap()
            .chain_index()
    };
    // Same chain index twice = the same message key encrypted two different
    // plaintexts. This is the disaster scenario; it exists only because we
    // forcibly rolled the state back.
    assert_eq!(index(&c1), index(&c1_again), "stale state reuses the key");

    // The receiver accepts only one of the twins; the ratchet burns the key.
    assert!(bob.decrypt(&c1).is_ok());
    assert!(matches!(
        bob.decrypt(&c1_again),
        Err(SessionError::DecryptFailed)
    ));
}

/// Crash after a decrypt: the consumed receiving key must stay consumed, so
/// the same ciphertext cannot be accepted twice across a restart (replay
/// window closed by persist-before-release on the decrypt side).
#[test]
fn crash_after_decrypt_does_not_reopen_the_replay_window() {
    let dir = tempfile::tempdir().unwrap();
    let mut alice = open(&dir, "alice", 0xA1);
    let mut bob = open(&dir, "bob", 0xB0);
    let bob_public = identity(0xB0).public();

    let bundle = bob.publish_bundle(4).unwrap();
    let sid = alice
        .establish_outbound(&bob_public, &bundle, OtkChoice::Auto)
        .unwrap();
    let wire = alice.encrypt(&sid, b"exactly once").unwrap();

    assert_eq!(
        bob.decrypt(&wire).unwrap().plaintext.as_slice(),
        b"exactly once"
    );
    // CRASH after the plaintext was released (state was already durable).
    drop(bob);
    let mut bob = open(&dir, "bob", 0xB0);
    assert!(
        bob.decrypt(&wire).is_err(),
        "a replay across restart must not decrypt again"
    );
}

#[test]
fn a_store_written_by_another_identity_is_not_adopted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared").join("sessions.prs");
    let mut mine = SessionManager::open(&identity(0xA1), path.clone()).unwrap();
    let _ = mine.publish_bundle(1).unwrap();
    drop(mine);

    // A different identity derives a different vault key: AuthFailed, never
    // a silent adoption of foreign ratchet state.
    assert!(matches!(
        SessionManager::open(&identity(0xB0), path),
        Err(SessionError::Store(
            prism_core::session_store::SessionStoreError::AuthFailed
        ))
    ));
}

/// The M2 no-plaintext rule: no decrypted message content may ever be
/// written to disk — only ratchet state is persisted.
#[test]
fn no_plaintext_ever_touches_disk() {
    let dir = tempfile::tempdir().unwrap();
    let mut alice = open(&dir, "alice", 0xA1);
    let mut bob = open(&dir, "bob", 0xB0);
    let bob_public = identity(0xB0).public();

    // Unique, incompressible canaries for both directions.
    let canary_a: &[u8] = b"CANARY-a1f83e2b-alice-to-bob-7d0c419e";
    let canary_b: &[u8] = b"CANARY-b7e2910d-bob-to-alice-33c8f0aa";

    let bundle = bob.publish_bundle(4).unwrap();
    let sid = alice
        .establish_outbound(&bob_public, &bundle, OtkChoice::Auto)
        .unwrap();
    let wire = alice.encrypt(&sid, canary_a).unwrap();
    assert!(
        !wire.windows(canary_a.len()).any(|w| w == canary_a),
        "the wire form is ciphertext"
    );
    let received = bob.decrypt(&wire).unwrap();
    assert_eq!(received.plaintext.as_slice(), canary_a);
    let reply = bob.encrypt(&received.session, canary_b).unwrap();
    assert_eq!(
        alice.decrypt(&reply).unwrap().plaintext.as_slice(),
        canary_b
    );

    // Managers still open (worst case: everything they will ever persist is
    // on disk right now). Scan EVERY file under the test root.
    let mut scanned = 0;
    for entry in walk(dir.path()) {
        let bytes = std::fs::read(&entry).unwrap();
        for canary in [canary_a, canary_b] {
            assert!(
                !bytes.windows(canary.len()).any(|w| w == canary),
                "plaintext canary found in {entry:?}"
            );
        }
        scanned += 1;
    }
    assert!(scanned >= 2, "expected to scan at least the two stores");
}

/// The whole chain, end to end: a real M1 keystore (Argon2id-sealed) holds
/// the identity; unlocking it yields the seed; the seed opens the session
/// store; sessions work. One test only — it pays a real KDF.
#[test]
fn full_stack_from_sealed_keystore_to_session() {
    let dir = tempfile::tempdir().unwrap();
    let passphrase = Passphrase::new("correct horse battery staple".to_owned().into());

    // init: create the identity and seal it (M1).
    let original = IdentityKeypair::generate().unwrap();
    keystore::seal_to_path(
        &dir.path().join("keystore.pks"),
        &KeystoreContents::new("alice".to_owned(), original.to_seed()),
        &passphrase,
        false,
    )
    .unwrap();

    // unlock: reload the identity from disk (M1), then open sessions (M2).
    let contents = keystore::open_from_path(&dir.path().join("keystore.pks"), &passphrase).unwrap();
    let unlocked = IdentityKeypair::from_seed(contents.seed());
    let mut alice = SessionManager::open(&unlocked, dir.path().join("sessions.prs")).unwrap();

    let mut bob = open(&dir, "bob", 0xB0);
    let bundle = bob.publish_bundle(2).unwrap();
    let sid = alice
        .establish_outbound(&identity(0xB0).public(), &bundle, OtkChoice::Auto)
        .unwrap();
    let received = bob
        .decrypt(&alice.encrypt(&sid, b"full stack").unwrap())
        .unwrap();
    assert_eq!(received.plaintext.as_slice(), b"full stack");
    assert_eq!(
        received.peer.fingerprint().full(),
        original.public().fingerprint().full(),
        "the identity from the sealed keystore is the one the binding proves"
    );
}

/// Recursively list files under `root` (test helper).
#[allow(clippy::expect_used)]
fn walk(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}
