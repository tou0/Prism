// SPDX-License-Identifier: AGPL-3.0-or-later
//! A complete local Alice ↔ Bob encrypted conversation — the whole M2 flow
//! with no network: bundle publication, session establishment, both-direction
//! messaging, a restart proving the sealed ratchet store resumes.
//!
//! The "transport" here is a variable holding bytes. A real transport (M2b+)
//! moves the same bytes; nothing about the crypto changes.
//!
//! Run with: `cargo run -p prism-core --example local_chat`

use prism_core::bundle::DEFAULT_ONE_TIME_KEYS;
use prism_core::session::{OtkChoice, SessionManager};
use prism_core::IdentityKeypair;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;

    // Two identities (in real use these come from the sealed M1 keystore).
    let alice_id = IdentityKeypair::generate()?;
    let bob_id = IdentityKeypair::generate()?;
    println!("alice: {}", alice_id.public().handle("alice"));
    println!("bob:   {}\n", bob_id.public().handle("bob"));

    let mut alice = SessionManager::open(&alice_id, dir.path().join("alice.prs"))?;
    let mut bob = SessionManager::open(&bob_id, dir.path().join("bob.prs"))?;

    // Bob publishes his identity-signed prekey bundle (the artifact a
    // directory / the DHT will serve in M4). Alice got Bob's identity out of
    // band — his handle — and will accept no other signer.
    let bundle: Vec<u8> = bob.publish_bundle(DEFAULT_ONE_TIME_KEYS)?;
    println!("bob published a signed bundle ({} bytes)", bundle.len());

    // Alice establishes and sends — Bob is "offline" until delivery.
    let session = alice.establish_outbound(&bob_id.public(), &bundle, OtkChoice::Auto)?;
    let wire1 = alice.encrypt(&session, b"hello bob, this is alice")?;
    println!("alice -> bob: {} bytes of ciphertext", wire1.len());

    // Delivery. Bob learns and verifies alice's identity from the message
    // itself (the in-channel binding envelope).
    let received = bob.decrypt(&wire1)?;
    println!(
        "bob decrypted: {:?} (from {})",
        String::from_utf8_lossy(&received.plaintext),
        received.peer.handle("alice"),
    );

    // Bob replies on the same session.
    let wire2 = bob.encrypt(&received.session, b"hi alice, ratchet looks good")?;
    let reply = alice.decrypt(&wire2)?;
    println!(
        "alice decrypted: {:?}",
        String::from_utf8_lossy(&reply.plaintext)
    );

    // Restart both ends: the sealed stores resume the SAME session.
    drop(alice);
    drop(bob);
    let mut alice = SessionManager::open(&alice_id, dir.path().join("alice.prs"))?;
    let mut bob = SessionManager::open(&bob_id, dir.path().join("bob.prs"))?;

    let wire3 = alice.encrypt(&session, b"still the same ratchet after a restart")?;
    let resumed = bob.decrypt(&wire3)?;
    println!(
        "after restart, bob decrypted: {:?}",
        String::from_utf8_lossy(&resumed.plaintext)
    );

    println!("\nlocal end-to-end encrypted chat: OK");
    Ok(())
}
