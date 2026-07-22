// SPDX-License-Identifier: AGPL-3.0-or-later
//! The identity ↔ libp2p bridge.
//!
//! # The single transport-key exception
//!
//! prism-net holds **no application cryptography** — it never parses bundles,
//! validates keys, runs the ratchet, or sees plaintext (all of that is
//! `prism-core`). The one unavoidable exception is that running a libp2p Swarm
//! requires the **Noise static keypair**, and spec §6 mandates that this be the
//! *same* Ed25519 key as the application identity (so the libp2p `PeerId` binds
//! to the Prism identity). The identity seed therefore crosses into prism-net
//! here — and **only** here — solely to construct that Noise keypair. It is
//! copied into a [`Zeroizing`] buffer, consumed by libp2p (which zeroizes the
//! input in place), and the copy is wiped on drop. No seed or private key is
//! retained. This is documented as the one narrow exception in `docs/net.md`.
//!
//! Elsewhere Prism separates key usages via HKDF domains; reusing the identity
//! key for Noise is a deliberate, spec-mandated consequence of the
//! identity↔PeerId binding requirement, not a usage-separation oversight.

use libp2p::identity::{self, ed25519};
use libp2p::{multihash::Multihash, PeerId};
use prism_core::Seed32;
use zeroize::Zeroizing;

use crate::NetError;

/// Multihash code for an identity (inlined) multihash. Ed25519 public keys are
/// small enough that libp2p always inlines them into the `PeerId`, so the key
/// can be recovered from the `PeerId` for the identity check.
const MULTIHASH_IDENTITY_CODE: u64 = 0;

/// A peer's raw Ed25519 public key (32 bytes) — its transport *and* application
/// identity. Public material: freely comparable and printable.
///
/// This is prism-net's only notion of "who a peer is"; the daemon maps it to a
/// `prism_core::PublicIdentity` (with strict validation) to derive the Prism
/// fingerprint. prism-net never treats these bytes as a cryptographic key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PeerKey([u8; 32]);

impl PeerKey {
    /// Wrap raw Ed25519 public-key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw 32 public-key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Build the libp2p Noise keypair from the identity seed (see the module docs:
/// the one transport-key exception). The seed copy is zeroized immediately.
pub(crate) fn keypair_from_seed(seed: &Seed32) -> Result<identity::Keypair, NetError> {
    // Copy into a zeroizing buffer; `ed25519_from_bytes` zeroizes it in place
    // on success, and `Zeroizing` wipes it again on drop — no un-wiped copy of
    // the seed is left behind inside prism-net.
    let mut material = Zeroizing::new(*seed.expose());
    identity::Keypair::ed25519_from_bytes(material.as_mut()).map_err(|_| NetError::KeyDecode)
}

/// Recover a peer's Ed25519 public key from its (Noise-authenticated) `PeerId`.
///
/// Returns `None` for any `PeerId` that is not an inlined Ed25519 key (a peer
/// we then cannot identity-check, and therefore reject).
pub(crate) fn peer_key_from_id(peer_id: &PeerId) -> Option<PeerKey> {
    let multihash: &Multihash<64> = peer_id.as_ref();
    if multihash.code() != MULTIHASH_IDENTITY_CODE {
        return None;
    }
    let public = identity::PublicKey::try_decode_protobuf(multihash.digest()).ok()?;
    let ed = public.try_into_ed25519().ok()?;
    Some(PeerKey(ed.to_bytes()))
}

/// Derive the libp2p `PeerId` for a peer's Ed25519 public key, so we can dial
/// or address exactly that peer. `None` if the bytes are not a valid key.
pub(crate) fn peer_id_from_key(key: &PeerKey) -> Option<PeerId> {
    let ed = ed25519::PublicKey::try_from_bytes(&key.0).ok()?;
    let public: identity::PublicKey = ed.into();
    Some(public.to_peer_id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_round_trips_through_key() {
        // A keypair built from a fixed seed yields a PeerId from which we can
        // recover the exact Ed25519 public-key bytes.
        let seed = Seed32::from_bytes([0x33; 32]);
        let keypair = keypair_from_seed(&seed).expect("keypair");
        let peer_id = keypair.public().to_peer_id();

        let key = peer_key_from_id(&peer_id).expect("extractable");
        // The recovered key must rebuild the same PeerId.
        assert_eq!(peer_id_from_key(&key), Some(peer_id));

        // And it must equal the identity's own public key bytes.
        let expected = prism_core::IdentityKeypair::from_seed(&seed);
        assert_eq!(key.as_bytes(), expected.public().as_bytes());
    }
}
