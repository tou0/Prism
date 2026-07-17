// SPDX-License-Identifier: AGPL-3.0-or-later
//! Property-based tests (spec §15): arbitrary payloads round-trip, and no
//! byte pattern — random or a mutation of a valid message — can panic the
//! ingestion paths.

use prism_core::session::{OtkChoice, SessionManager};
use prism_core::{IdentityKeypair, Seed32};
use proptest::prelude::*;

fn identity(fill: u8) -> IdentityKeypair {
    IdentityKeypair::from_seed(&Seed32::from_bytes([fill; 32]))
}

// Test-only helper: clippy's allow-expect-in-tests does not reach helpers
// outside #[test] fns, hence the explicit allow.
#[allow(clippy::expect_used)]
fn pair(dir: &tempfile::TempDir) -> (SessionManager, SessionManager, prism_core::PublicIdentity) {
    let alice = SessionManager::open(&identity(0xA1), dir.path().join("a").join("s.prs"))
        .expect("open alice");
    let bob = SessionManager::open(&identity(0xB0), dir.path().join("b").join("s.prs"))
        .expect("open bob");
    (alice, bob, identity(0xB0).public())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 16, // each case pays several fsync'd store writes
        ..ProptestConfig::default()
    })]

    /// Any payload (0..=4096 bytes) round-trips bit-exactly, both directions.
    #[test]
    fn any_payload_round_trips(payload in proptest::collection::vec(any::<u8>(), 0..=4096)) {
        let dir = tempfile::tempdir().unwrap();
        let (mut alice, mut bob, bob_public) = pair(&dir);

        let bundle = bob.publish_bundle(1).unwrap();
        let sid = alice.establish_outbound(&bob_public, &bundle, OtkChoice::Auto).unwrap();

        let wire = alice.encrypt(&sid, &payload).unwrap();
        let received = bob.decrypt(&wire).unwrap();
        prop_assert_eq!(received.plaintext.as_slice(), &payload[..]);

        let reply = bob.encrypt(&received.session, &payload).unwrap();
        let echoed = alice.decrypt(&reply).unwrap();
        prop_assert_eq!(echoed.plaintext.as_slice(), &payload[..]);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Arbitrary bytes fed to decrypt never panic — they fail typed.
    #[test]
    fn arbitrary_bytes_never_panic_decrypt(bytes in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let dir = tempfile::tempdir().unwrap();
        let (_, mut bob, _) = pair(&dir);
        prop_assert!(bob.decrypt(&bytes).is_err());
    }

    /// Arbitrary bytes fed to bundle ingestion never panic.
    #[test]
    fn arbitrary_bytes_never_panic_open_bundle(bytes in proptest::collection::vec(any::<u8>(), 0..=1024)) {
        let expected = identity(0xB0).public();
        prop_assert!(prism_core::bundle::open_bundle(&expected, &bytes).is_err());
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 48,
        ..ProptestConfig::default()
    })]

    /// Any single-byte mutation of a VALID wire message either fails typed
    /// or (for bytes outside the authenticated regions, of which there are
    /// none) decrypts — it never panics and never yields wrong plaintext.
    #[test]
    fn mutations_of_a_valid_message_never_panic(offset in 0usize..512, xor in 1u8..=255) {
        let dir = tempfile::tempdir().unwrap();
        let (mut alice, mut bob, bob_public) = pair(&dir);

        let bundle = bob.publish_bundle(1).unwrap();
        let sid = alice.establish_outbound(&bob_public, &bundle, OtkChoice::Auto).unwrap();
        let wire = alice.encrypt(&sid, b"canonical plaintext").unwrap();

        let mut mutated = wire.clone();
        let index = offset % mutated.len();
        mutated[index] ^= xor;

        match bob.decrypt(&mutated) {
            Err(_) => {}
            Ok(received) => {
                // Only reachable if the mutation was outside every
                // authenticated field — then the plaintext must be intact.
                prop_assert_eq!(received.plaintext.as_slice(), b"canonical plaintext");
            }
        }
    }
}
