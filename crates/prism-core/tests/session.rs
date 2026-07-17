// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local Alice ↔ Bob session tests: the full establish/encrypt/decrypt flow,
//! out-of-order delivery, third parties, identity binding, one-time-key
//! lifecycle, and hostile wire input. No network — bytes move by hand,
//! which is the point: the manager is transport-agnostic.

use prism_core::bundle::{open_bundle, DEFAULT_ONE_TIME_KEYS};
use prism_core::session::{Decrypted, OtkChoice, SessionError, SessionManager};
use prism_core::{IdentityKeypair, Seed32};

const WIRE_VERSION: u8 = 1;
const KIND_PREKEY: u8 = 0;
const KIND_NORMAL: u8 = 1;

fn identity(fill: u8) -> IdentityKeypair {
    IdentityKeypair::from_seed(&Seed32::from_bytes([fill; 32]))
}

// Test-only helper: clippy's allow-expect-in-tests does not reach helpers
// outside #[test] fns, hence the explicit allow.
#[allow(clippy::expect_used)]
fn manager(dir: &tempfile::TempDir, name: &str, fill: u8) -> (IdentityKeypair, SessionManager) {
    let id = identity(fill);
    let mgr = SessionManager::open(&id, dir.path().join(name).join("sessions.prs"))
        .expect("open manager");
    (id, mgr)
}

#[allow(clippy::expect_used)]
fn decrypt_ok(mgr: &mut SessionManager, wire: &[u8]) -> Decrypted {
    mgr.decrypt(wire).expect("decrypt")
}

#[test]
fn full_round_trip_both_directions() {
    let dir = tempfile::tempdir().unwrap();
    let (_alice_id, mut alice) = manager(&dir, "alice", 0xA1);
    let (bob_id, mut bob) = manager(&dir, "bob", 0xB0);

    // Bob publishes; the "directory" hands Alice the full signed bundle.
    let bundle = bob.publish_bundle(DEFAULT_ONE_TIME_KEYS).unwrap();
    let sid = alice
        .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Auto)
        .unwrap();

    // Alice -> Bob.
    let wire1 = alice.encrypt(&sid, b"hello bob").unwrap();
    assert_eq!(wire1[1], KIND_PREKEY, "first message is prekey-framed");
    let received = decrypt_ok(&mut bob, &wire1);
    assert_eq!(received.plaintext.as_slice(), b"hello bob");
    assert_eq!(
        received.peer.fingerprint().full(),
        alice.identity().fingerprint().full(),
        "binding must prove alice's identity"
    );
    let bob_sid = received.session;

    // Bob -> Alice (responder messages are normal-framed from the start).
    let reply = bob.encrypt(&bob_sid, b"hi alice").unwrap();
    assert_eq!(reply[1], KIND_NORMAL);
    let received = decrypt_ok(&mut alice, &reply);
    assert_eq!(received.plaintext.as_slice(), b"hi alice");
    assert_eq!(
        received.peer.fingerprint().full(),
        bob_id.public().fingerprint().full()
    );

    // After the reply, Alice's messages leave the prekey phase.
    let wire2 = alice.encrypt(&sid, b"how are you?").unwrap();
    assert_eq!(wire2[1], KIND_NORMAL, "post-reply messages are normal");
    assert_eq!(
        decrypt_ok(&mut bob, &wire2).plaintext.as_slice(),
        b"how are you?"
    );

    // Longer conversation, both directions, empty payload included.
    for round in 0..5u8 {
        let msg = vec![round; usize::from(round) * 100];
        let wire = alice.encrypt(&sid, &msg).unwrap();
        assert_eq!(decrypt_ok(&mut bob, &wire).plaintext.as_slice(), &msg[..]);
        let wire = bob.encrypt(&bob_sid, &msg).unwrap();
        assert_eq!(decrypt_ok(&mut alice, &wire).plaintext.as_slice(), &msg[..]);
    }
}

#[test]
fn out_of_order_and_dropped_messages_are_handled() {
    let dir = tempfile::tempdir().unwrap();
    let (_alice_id, mut alice) = manager(&dir, "alice", 0xA1);
    let (bob_id, mut bob) = manager(&dir, "bob", 0xB0);

    let bundle = bob.publish_bundle(4).unwrap();
    let sid = alice
        .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Auto)
        .unwrap();

    let m1 = alice.encrypt(&sid, b"one").unwrap();
    let m2 = alice.encrypt(&sid, b"two (dropped)").unwrap();
    let m3 = alice.encrypt(&sid, b"three").unwrap();

    // Deliver 3 first, then 1; never deliver 2 (skipped-message keys).
    assert_eq!(decrypt_ok(&mut bob, &m3).plaintext.as_slice(), b"three");
    assert_eq!(decrypt_ok(&mut bob, &m1).plaintext.as_slice(), b"one");
    drop(m2);

    // The conversation continues normally afterwards, both ways.
    let bob_sid = {
        // Bob learned the session id from the first decrypted message (m3).
        let received = bob.decrypt(&alice.encrypt(&sid, b"four").unwrap()).unwrap();
        received.session
    };
    let reply = bob.encrypt(&bob_sid, b"got them").unwrap();
    assert_eq!(
        alice.decrypt(&reply).unwrap().plaintext.as_slice(),
        b"got them"
    );
}

#[test]
fn prekey_phase_out_of_order_first_contact() {
    let dir = tempfile::tempdir().unwrap();
    let (_alice_id, mut alice) = manager(&dir, "alice", 0xA1);
    let (bob_id, mut bob) = manager(&dir, "bob", 0xB0);

    let bundle = bob.publish_bundle(4).unwrap();
    let sid = alice
        .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Auto)
        .unwrap();

    // Both messages are prekey-framed; the SECOND arrives first and creates
    // the inbound session, the first is then routed to it.
    let m0 = alice.encrypt(&sid, b"first sent").unwrap();
    let m1 = alice.encrypt(&sid, b"second sent").unwrap();
    assert_eq!(
        decrypt_ok(&mut bob, &m1).plaintext.as_slice(),
        b"second sent"
    );
    assert_eq!(
        decrypt_ok(&mut bob, &m0).plaintext.as_slice(),
        b"first sent"
    );
}

#[test]
fn a_third_party_cannot_decrypt_and_ciphertext_is_opaque() {
    let dir = tempfile::tempdir().unwrap();
    let (_alice_id, mut alice) = manager(&dir, "alice", 0xA1);
    let (bob_id, mut bob) = manager(&dir, "bob", 0xB0);
    let (_eve_id, mut eve) = manager(&dir, "eve", 0xEE);

    let bundle = bob.publish_bundle(4).unwrap();
    let sid = alice
        .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Auto)
        .unwrap();

    let secret = b"the meeting is at dawn";
    let wire = alice.encrypt(&sid, secret).unwrap();

    // Eve holds neither Bob's account nor the session: clean failure.
    assert!(eve.decrypt(&wire).is_err());
    // And the ciphertext never contains the plaintext.
    assert!(
        !wire.windows(secret.len()).any(|w| w == secret),
        "plaintext must not appear in the wire bytes"
    );

    // Bob still decrypts fine after Eve's attempt.
    assert_eq!(decrypt_ok(&mut bob, &wire).plaintext.as_slice(), secret);
}

#[test]
fn bundles_from_the_wrong_identity_or_tampered_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (_alice_id, mut alice) = manager(&dir, "alice", 0xA1);
    let (bob_id, mut bob) = manager(&dir, "bob", 0xB0);
    let carol = identity(0xCC);

    let bundle = bob.publish_bundle(4).unwrap();

    // Claimed-to-be-carol bundle: rejected before any key is used.
    assert!(matches!(
        alice.establish_outbound(&carol.public(), &bundle, OtkChoice::Auto),
        Err(SessionError::Bundle(
            prism_core::bundle::BundleError::WrongIdentity
        ))
    ));

    // Tampered bundle: signature failure.
    let mut tampered = bundle.clone();
    tampered[40] ^= 0x01;
    assert!(matches!(
        alice.establish_outbound(&bob_id.public(), &tampered, OtkChoice::Auto),
        Err(SessionError::Bundle(
            prism_core::bundle::BundleError::BadSignature
        ))
    ));

    // A valid bundle still works afterwards (no state was poisoned).
    assert!(alice
        .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Auto)
        .is_ok());
}

#[test]
fn hostile_wire_input_is_a_clean_error_never_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let (_alice_id, mut alice) = manager(&dir, "alice", 0xA1);
    let (bob_id, mut bob) = manager(&dir, "bob", 0xB0);

    let bundle = bob.publish_bundle(4).unwrap();
    let sid = alice
        .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Auto)
        .unwrap();
    let wire = alice.encrypt(&sid, b"legit").unwrap();

    // Garbage of many shapes.
    assert!(bob.decrypt(&[]).is_err());
    assert!(bob.decrypt(&[0xff]).is_err());
    assert!(bob.decrypt(&[0u8; 4096]).is_err());

    // Unknown wire version.
    let mut v = wire.clone();
    v[0] = WIRE_VERSION + 9;
    assert!(matches!(
        bob.decrypt(&v),
        Err(SessionError::UnsupportedVersion { .. })
    ));

    // Unknown kind.
    let mut k = wire.clone();
    k[1] = 7;
    assert!(matches!(
        bob.decrypt(&k),
        Err(SessionError::MalformedMessage(_))
    ));

    // Bad session-id length field.
    let mut s = wire.clone();
    s[2] = 0;
    assert!(bob.decrypt(&s).is_err());

    // Truncations at every prefix length of a real message.
    for len in [3usize, 4, 10, wire.len() / 2, wire.len() - 1] {
        assert!(bob.decrypt(&wire[..len]).is_err(), "prefix {len} must fail");
    }

    // Bit flips across the whole message: never a panic, never a success.
    for offset in (0..wire.len()).step_by(7) {
        let mut flipped = wire.clone();
        flipped[offset] ^= 0x01;
        assert!(
            bob.decrypt(&flipped).is_err(),
            "flipping byte {offset} must not yield a valid decryption"
        );
    }

    // The pristine message still decrypts after all that hostility.
    assert_eq!(decrypt_ok(&mut bob, &wire).plaintext.as_slice(), b"legit");
}

#[test]
fn first_message_without_binding_is_rejected() {
    use vodozemac::olm::{Account, OlmMessage, SessionConfig};
    use vodozemac::Curve25519PublicKey;

    let dir = tempfile::tempdir().unwrap();
    let (bob_id, mut bob) = manager(&dir, "bob", 0xB0);
    let bundle_bytes = bob.publish_bundle(4).unwrap();
    let bundle = open_bundle(&bob_id.public(), &bundle_bytes).unwrap();

    // A protocol-level-valid initiator that skips Prism's binding envelope.
    let mallory = Account::new();
    let mut session = mallory
        .create_outbound_session(
            SessionConfig::version_1(),
            Curve25519PublicKey::from_bytes(*bundle.ik_curve()),
            Curve25519PublicKey::from_bytes(bundle.one_time_keys()[0]),
        )
        .unwrap();

    // Plaintext envelope: version 1, flags 0 (no binding), payload.
    let mut envelope = vec![1u8, 0u8];
    envelope.extend_from_slice(b"no binding here");
    let olm = session.encrypt(&envelope).unwrap();
    let OlmMessage::PreKey(prekey) = olm else {
        panic!("first message must be prekey-framed");
    };

    let wire = hand_wire(KIND_PREKEY, &prekey.session_id(), &prekey.to_bytes());
    assert!(matches!(
        bob.decrypt(&wire),
        Err(SessionError::MissingBinding)
    ));
}

#[test]
fn binding_claiming_someone_elses_identity_is_rejected() {
    use vodozemac::olm::{Account, OlmMessage, SessionConfig};
    use vodozemac::Curve25519PublicKey;

    let dir = tempfile::tempdir().unwrap();
    let (bob_id, mut bob) = manager(&dir, "bob", 0xB0);
    let bundle_bytes = bob.publish_bundle(4).unwrap();
    let bundle = open_bundle(&bob_id.public(), &bundle_bytes).unwrap();

    let alice = identity(0xA1); // the victim whose identity is claimed
    let carol = identity(0xCC); // the attacker who signs

    let mallory_account = Account::new();
    let mut session = mallory_account
        .create_outbound_session(
            SessionConfig::version_1(),
            Curve25519PublicKey::from_bytes(*bundle.ik_curve()),
            Curve25519PublicKey::from_bytes(bundle.one_time_keys()[0]),
        )
        .unwrap();

    // Binding message layout: sender_ed ‖ sender_curve ‖ recipient_ed ‖
    // recipient_curve, signed under the binding domain. Carol signs a message
    // that CLAIMS alice's identity: the signature cannot verify under
    // alice's key.
    let mut signed = Vec::new();
    signed.extend_from_slice(alice.public().as_bytes());
    signed.extend_from_slice(&mallory_account.curve25519_key().to_bytes());
    signed.extend_from_slice(bob_id.public().as_bytes());
    signed.extend_from_slice(bundle.ik_curve()); // (wrong slot value is fine: it must fail earlier)
    let forged_sig = carol.sign(b"prism v1 session identity binding", &signed);

    let mut envelope = vec![1u8, 1u8]; // version 1, FLAG_BINDING
    envelope.extend_from_slice(alice.public().as_bytes());
    envelope.extend_from_slice(&forged_sig);
    envelope.extend_from_slice(b"impersonation attempt");

    let olm = session.encrypt(&envelope).unwrap();
    let OlmMessage::PreKey(prekey) = olm else {
        panic!("first message must be prekey-framed");
    };
    let wire = hand_wire(KIND_PREKEY, &prekey.session_id(), &prekey.to_bytes());
    assert!(matches!(bob.decrypt(&wire), Err(SessionError::BadBinding)));
}

#[test]
fn a_stolen_binding_cannot_be_spliced_onto_another_channel() {
    use vodozemac::olm::{Account, OlmMessage, SessionConfig};
    use vodozemac::Curve25519PublicKey;

    let dir = tempfile::tempdir().unwrap();
    let (_alice_id, mut alice) = manager(&dir, "alice", 0xA1);
    let (bob_id, mut bob) = manager(&dir, "bob", 0xB0);

    // Alice establishes honestly; her first wire message carries her binding.
    let bundle_bytes = bob.publish_bundle(4).unwrap();
    let sid = alice
        .establish_outbound(&bob_id.public(), &bundle_bytes, OtkChoice::Index(0))
        .unwrap();
    let honest_wire = alice.encrypt(&sid, b"hello").unwrap();

    // Extract Alice's binding envelope by decrypting as Bob... an attacker
    // on the wire cannot, but a MALICIOUS RECIPIENT (Bob) could try to
    // replay Alice's binding to impersonate her toward himself on a channel
    // HE controls. The binding signs the initiator's actual Curve25519 key,
    // so it cannot be grafted onto a different account's session.
    let received = bob.decrypt(&honest_wire).unwrap();
    assert_eq!(received.plaintext.as_slice(), b"hello");

    // Mallory's own account tries to ride a copied binding. We reconstruct
    // the binding bytes alice would have produced (public material: her key
    // and a signature she really made) — the splice must still fail because
    // the signed message names ALICE's curve key, not mallory's.
    let bundle = open_bundle(&bob_id.public(), &bundle_bytes).unwrap();
    let mallory_account = Account::new();
    let mut mallory_session = mallory_account
        .create_outbound_session(
            SessionConfig::version_1(),
            Curve25519PublicKey::from_bytes(*bundle.ik_curve()),
            Curve25519PublicKey::from_bytes(bundle.one_time_keys()[1]),
        )
        .unwrap();

    // A binding alice signed for HER channel (sender_curve = alice's curve).
    // Mallory cannot mint one for her own curve key without alice's Ed25519
    // key, so she reuses alice's — which names a different curve key than
    // the one running mallory's 3DH.
    let alice_id = identity(0xA1);
    let mut alice_signed = Vec::new();
    alice_signed.extend_from_slice(alice_id.public().as_bytes());
    alice_signed.extend_from_slice(&[0x42u8; 32]); // alice's (other) curve key
    alice_signed.extend_from_slice(bob_id.public().as_bytes());
    alice_signed.extend_from_slice(bundle.ik_curve());
    let alice_sig = alice_id.sign(b"prism v1 session identity binding", &alice_signed);

    let mut envelope = vec![1u8, 1u8];
    envelope.extend_from_slice(alice_id.public().as_bytes());
    envelope.extend_from_slice(&alice_sig);
    envelope.extend_from_slice(b"spliced");

    let olm = mallory_session.encrypt(&envelope).unwrap();
    let OlmMessage::PreKey(prekey) = olm else {
        panic!("first message must be prekey-framed");
    };
    let wire = hand_wire(KIND_PREKEY, &prekey.session_id(), &prekey.to_bytes());
    assert!(matches!(bob.decrypt(&wire), Err(SessionError::BadBinding)));
}

#[test]
fn one_time_key_lifecycle_exhaustion_collision_and_replenish() {
    let dir = tempfile::tempdir().unwrap();
    let (bob_id, mut bob) = manager(&dir, "bob", 0xB0);
    let bundle = bob.publish_bundle(2).unwrap();

    // Two initiators consume the two published one-time keys.
    let (_i1, mut init1) = manager(&dir, "init1", 0x11);
    let (_i2, mut init2) = manager(&dir, "init2", 0x12);
    let (_i3, mut init3) = manager(&dir, "init3", 0x13);
    let (_i4, mut init4) = manager(&dir, "init4", 0x14);

    let s1 = init1
        .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Index(0))
        .unwrap();
    let s2 = init2
        .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Index(1))
        .unwrap();
    assert!(bob.decrypt(&init1.encrypt(&s1, b"one").unwrap()).is_ok());
    assert!(bob.decrypt(&init2.encrypt(&s2, b"two").unwrap()).is_ok());

    // Exhaustion: a third initiator with the same (now stale) bundle falls
    // back to the fallback key and still establishes.
    let s3 = init3
        .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Fallback)
        .unwrap();
    assert!(bob.decrypt(&init3.encrypt(&s3, b"three").unwrap()).is_ok());

    // Collision: a fourth initiator picks an already-consumed one-time key —
    // clean typed failure at Bob, no crash, no session.
    let s4 = init4
        .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Index(0))
        .unwrap();
    assert!(matches!(
        bob.decrypt(&init4.encrypt(&s4, b"four").unwrap()),
        Err(SessionError::OneTimeKeyMissing)
    ));

    // A bundle published with zero one-time keys still works via fallback.
    let empty_bundle = bob.publish_bundle(0).unwrap();
    let parsed = open_bundle(&bob_id.public(), &empty_bundle).unwrap();
    assert!(parsed.one_time_keys().is_empty());
    let (_i5, mut init5) = manager(&dir, "init5", 0x15);
    let s5 = init5
        .establish_outbound(&bob_id.public(), &empty_bundle, OtkChoice::Auto)
        .unwrap();
    assert!(bob.decrypt(&init5.encrypt(&s5, b"five").unwrap()).is_ok());

    // Replenish: a fresh publication advertises new keys again.
    let refreshed = bob.publish_bundle(3).unwrap();
    let parsed = open_bundle(&bob_id.public(), &refreshed).unwrap();
    assert_eq!(parsed.one_time_keys().len(), 3);
    assert_eq!(
        bob.current_bundle(),
        Some(refreshed.as_slice()),
        "the manager re-serves the latest published bundle"
    );
}

#[test]
fn unknown_sessions_and_replays_are_clean_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (_alice_id, mut alice) = manager(&dir, "alice", 0xA1);
    let (bob_id, mut bob) = manager(&dir, "bob", 0xB0);

    let bundle = bob.publish_bundle(4).unwrap();
    let sid = alice
        .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Auto)
        .unwrap();

    let first = alice.encrypt(&sid, b"first").unwrap();
    assert!(bob.decrypt(&first).is_ok());

    // Exact replay of the first (prekey) message: routed to the existing
    // session, rejected by the ratchet — and no duplicate session appears.
    assert!(matches!(
        bob.decrypt(&first),
        Err(SessionError::DecryptFailed)
    ));

    // A normal-kind message for a session id Bob has never seen.
    let post_reply = {
        let bob_sid = bob
            .decrypt(&alice.encrypt(&sid, b"again").unwrap())
            .unwrap()
            .session;
        assert!(alice
            .decrypt(&bob.encrypt(&bob_sid, b"reply").unwrap())
            .is_ok());
        alice.encrypt(&sid, b"normal now").unwrap()
    };
    assert_eq!(post_reply[1], KIND_NORMAL);
    let mut foreign = post_reply.clone();
    // Overwrite the session id with an unknown (but well-formed) one.
    let sid_len = usize::from(foreign[2]);
    for byte in &mut foreign[3..3 + sid_len] {
        *byte = b'A';
    }
    assert!(matches!(
        bob.decrypt(&foreign),
        Err(SessionError::UnknownSession)
    ));

    // The original still decrypts.
    assert!(bob.decrypt(&post_reply).is_ok());
}

#[test]
fn payload_and_wire_size_caps_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let (_alice_id, mut alice) = manager(&dir, "alice", 0xA1);
    let (bob_id, mut bob) = manager(&dir, "bob", 0xB0);

    let bundle = bob.publish_bundle(1).unwrap();
    let sid = alice
        .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Auto)
        .unwrap();

    // One byte over the plaintext cap.
    let oversized = vec![0u8; 64 * 1024 + 1];
    assert!(matches!(
        alice.encrypt(&sid, &oversized),
        Err(SessionError::PlaintextTooLarge)
    ));
    // At the cap: fine, and round-trips.
    let max = vec![0x5a; 64 * 1024];
    let wire = alice.encrypt(&sid, &max).unwrap();
    assert_eq!(decrypt_ok(&mut bob, &wire).plaintext.as_slice(), &max[..]);

    // An oversized wire blob is rejected before any parsing.
    let huge = vec![0u8; 128 * 1024 + 1];
    assert!(matches!(
        bob.decrypt(&huge),
        Err(SessionError::WireTooLarge)
    ));
}

#[test]
fn artifacts_survive_a_file_based_transport() {
    // The brief allows "in memory or via a temp file": prove the artifacts
    // are transport-agnostic bytes by round-tripping every one through disk.
    let dir = tempfile::tempdir().unwrap();
    let (_alice_id, mut alice) = manager(&dir, "alice", 0xA1);
    let (bob_id, mut bob) = manager(&dir, "bob", 0xB0);

    let mailbox = dir.path().join("mailbox");
    std::fs::create_dir_all(&mailbox).unwrap();
    let via_file = |name: &str, bytes: &[u8]| -> Vec<u8> {
        let path = mailbox.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::read(&path).unwrap()
    };

    let bundle = via_file("bundle", &bob.publish_bundle(2).unwrap());
    let sid = alice
        .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Auto)
        .unwrap();
    let wire = via_file("msg1", &alice.encrypt(&sid, b"via disk").unwrap());
    let received = bob.decrypt(&wire).unwrap();
    assert_eq!(received.plaintext.as_slice(), b"via disk");
    let reply = via_file("msg2", &bob.encrypt(&received.session, b"ack").unwrap());
    assert_eq!(alice.decrypt(&reply).unwrap().plaintext.as_slice(), b"ack");
}

/// Hand-encode the documented wire envelope (used by the crafted-attacker
/// tests, which deliberately bypass the manager's encrypt path).
fn hand_wire(kind: u8, session_id: &str, olm_bytes: &[u8]) -> Vec<u8> {
    let sid = session_id.as_bytes();
    let mut wire = Vec::with_capacity(3 + sid.len() + olm_bytes.len());
    wire.push(WIRE_VERSION);
    wire.push(kind);
    wire.push(sid.len() as u8);
    wire.extend_from_slice(sid);
    wire.extend_from_slice(olm_bytes);
    wire
}
