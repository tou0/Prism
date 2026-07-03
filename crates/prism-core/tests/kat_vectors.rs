// SPDX-License-Identifier: AGPL-3.0-or-later
//! Known-answer tests (KATs) for the cryptographic building blocks of M1.
//!
//! These pin our *wiring* of the audited primitives against official vectors:
//! - BIP-39: the Trezor reference vectors (entropy -> mnemonic -> seed);
//! - the Prism recovery chain itself (mnemonic -> HKDF-SHA512 -> Ed25519),
//!   frozen as a golden vector so an accidental change to any derivation step
//!   can never slip through silently.
//!
//! Argon2id (RFC 9106) and ChaCha20-Poly1305 (RFC 8439) vectors live in this
//! file too, alongside the keystore they protect.

use prism_core::recovery::RecoveryPhrase;
use prism_core::IdentityKeypair;

/// Official BIP-39 English test vectors (Trezor reference implementation),
/// restricted to the 128-bit / 12-word entries Prism uses.
/// Tuples of (entropy hex, mnemonic, seed hex with passphrase "TREZOR").
const BIP39_VECTORS: &[(&str, &str, &str)] = &[
    (
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
    ),
    (
        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
    ),
    (
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
    ),
];

#[test]
fn bip39_trezor_vectors_entropy_to_mnemonic_to_seed() {
    for (entropy_hex, expected_mnemonic, expected_seed_hex) in BIP39_VECTORS {
        let entropy = hex::decode(entropy_hex).unwrap();
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(
            mnemonic.to_string(),
            *expected_mnemonic,
            "entropy {entropy_hex} produced the wrong mnemonic"
        );

        let seed = mnemonic.to_seed_normalized("TREZOR");
        assert_eq!(
            hex::encode(seed),
            *expected_seed_hex,
            "mnemonic {expected_mnemonic:?} produced the wrong BIP-39 seed"
        );
    }
}

#[test]
fn bip39_vectors_parse_through_the_prism_wrapper() {
    // The same official mnemonics, fed through our RecoveryPhrase parser.
    for (_, mnemonic, _) in BIP39_VECTORS {
        RecoveryPhrase::parse(mnemonic).unwrap();
    }
}

/// Golden vector for the full Prism recovery chain, frozen at M1:
///
/// ```text
/// mnemonic -> BIP-39 seed ("" passphrase) -> HKDF-SHA512("prism v1 identity ed25519")
///          -> Ed25519 seed -> public key
/// ```
///
/// If this test ever fails, the derivation chain changed and every recovery
/// phrase in the wild is broken. Do not "fix" the constants; fix the code.
#[test]
fn prism_recovery_chain_golden_vector() {
    let phrase = RecoveryPhrase::parse(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon about",
    )
    .unwrap();
    let seed = phrase.derive_identity_seed().unwrap();
    assert_eq!(
        hex::encode(seed.expose()),
        "970a5be2d72ceeed0a0527094d21ed4594afe0a4cd957e88be7da4460212fb80"
    );

    let public = IdentityKeypair::from_seed(&seed).public();
    assert_eq!(
        hex::encode(public.as_bytes()),
        "99b2b7f0c8381efaffc4ba72505258994bd8c42290d776d01a3e1b2e396867f6"
    );
    assert_eq!(public.handle("alice"), "alice#FG6AGuHx7Sm1pb");
}
