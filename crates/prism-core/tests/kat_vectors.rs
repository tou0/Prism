// SPDX-License-Identifier: AGPL-3.0-or-later
//! Known-answer tests (KATs) for the cryptographic building blocks of M1.
//!
//! These pin our *wiring* of the audited primitives against official vectors:
//! - BIP-39: the Trezor reference vectors (entropy -> mnemonic -> seed);
//! - the Prism recovery chain itself (mnemonic -> HKDF-SHA512 -> Ed25519),
//!   frozen as a golden vector so an accidental change to any derivation step
//!   can never slip through silently.
//!
//! - Argon2id: the RFC 9106 §5.3 reference vector;
//! - ChaCha20-Poly1305: the RFC 8439 §2.8.2 AEAD vector.

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

/// Argon2id reference vector from RFC 9106 §5.3 (t=3, m=32 KiB, p=4, with
/// secret and associated data). Exercises the exact `argon2` crate APIs the
/// keystore relies on, pinned against the RFC output.
#[test]
fn argon2id_rfc9106_reference_vector() {
    use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&[0x04; 12]).unwrap())
        .build()
        .unwrap();
    let argon2 =
        Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(&[0x01; 32], &[0x02; 16], &mut out)
        .unwrap();

    assert_eq!(
        hex::encode(out),
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    );
}

/// ChaCha20-Poly1305 AEAD vector from RFC 8439 §2.8.2, driven through the
/// same encrypt/decrypt calls the keystore uses (payload + associated data),
/// including tag rejection on tamper.
#[test]
fn chacha20poly1305_rfc8439_reference_vector() {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let key =
        hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
    let nonce = hex::decode("070000004041424344454647").unwrap();
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: \
        If I could offer you only one tip for the future, sunscreen would be it.";
    let expected_ciphertext = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5\
        a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c98\
        03aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
    let expected_tag = "1ae10b594f09e26a7e902ecbd0600691";

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .unwrap();

    let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
    assert_eq!(hex::encode(ciphertext), expected_ciphertext);
    assert_eq!(hex::encode(tag), expected_tag);

    // Decrypt round-trips...
    let opened = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &sealed,
                aad: &aad,
            },
        )
        .unwrap();
    assert_eq!(opened, plaintext);

    // ...and a single flipped bit fails the tag.
    let mut tampered = sealed.clone();
    tampered[0] ^= 0x01;
    assert!(cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &tampered,
                aad: &aad,
            },
        )
        .is_err());
}
