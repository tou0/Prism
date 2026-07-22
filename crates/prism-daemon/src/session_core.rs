// SPDX-License-Identifier: AGPL-3.0-or-later
//! The core session thread: the single owner of the [`SessionManager`].
//!
//! Session cryptography is synchronous and does a durable `fsync` on every
//! ratchet advance, so it runs on a **dedicated OS thread**, never on the async
//! executor. All access is serialized through one command channel, which makes
//! the persist-before-transmit ordering structural: `encrypt`/`decrypt` return
//! only *after* the advanced ratchet state is durably written, so the daemon
//! can hand ciphertext to the network only once persistence has completed.
//!
//! The thread owns the in-RAM inbox of decrypted messages. **No decrypted
//! plaintext is ever written to disk** — message history is a later milestone;
//! the inbox lives only for the process's lifetime.

use std::path::PathBuf;

use prism_core::session::{OtkChoice, SessionManager};
use prism_core::{IdentityKeypair, PublicIdentity};
use prism_net::InboundOutcome;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;
use zeroize::Zeroizing;

/// A decrypted message held in RAM until the client drains it.
pub struct InboxEntry {
    /// The verified sender's full fingerprint (base58).
    pub from_fingerprint: String,
    /// The decrypted body, zeroized on drop.
    pub body: Zeroizing<Vec<u8>>,
}

/// Commands processed serially by the core thread.
pub enum CoreMsg {
    /// Is there an established session with this peer? (cheap; no persist)
    HasSession {
        peer: [u8; 32],
        reply: oneshot::Sender<bool>,
    },
    /// Encrypt `body` for `peer`, establishing a session from `bundle` first if
    /// none exists. Persists the advanced state **before** returning the
    /// sealed bytes (persist-before-transmit).
    Deliver {
        peer: [u8; 32],
        bundle: Option<Vec<u8>>,
        body: Zeroizing<Vec<u8>>,
        reply: oneshot::Sender<Result<Vec<u8>, String>>,
    },
    /// Decrypt a received message, verify its identity against the
    /// Noise-authenticated sender key, and buffer it. Persists before acking.
    Inbound {
        from: [u8; 32],
        sealed: Vec<u8>,
        reply: oneshot::Sender<InboundOutcome>,
    },
    /// Drain the in-RAM inbox.
    Inbox {
        reply: oneshot::Sender<Vec<InboxEntry>>,
    },
    /// (Re)publish a signed prekey bundle of `count` one-time keys; returns the
    /// wire bytes to advertise.
    PublishBundle {
        count: usize,
        reply: oneshot::Sender<Result<Vec<u8>, String>>,
    },
}

/// Async-side handle to the core thread.
#[derive(Clone)]
pub struct CoreHandle {
    tx: mpsc::Sender<CoreMsg>,
}

impl CoreHandle {
    /// The raw sender, for building the [`prism_net::InboundSink`].
    pub fn sender(&self) -> mpsc::Sender<CoreMsg> {
        self.tx.clone()
    }

    /// `true` if a session with `peer` already exists.
    pub async fn has_session(&self, peer: [u8; 32]) -> bool {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(CoreMsg::HasSession { peer, reply })
            .await
            .is_err()
        {
            return false;
        }
        rx.await.unwrap_or(false)
    }

    /// Encrypt-and-persist for `peer` (establishing from `bundle` if needed).
    /// Returns the sealed wire bytes only after the ratchet state is durable.
    pub async fn deliver(
        &self,
        peer: [u8; 32],
        bundle: Option<Vec<u8>>,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Vec<u8>, String> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CoreMsg::Deliver {
                peer,
                bundle,
                body,
                reply,
            })
            .await
            .map_err(|_| "core session thread is not running".to_owned())?;
        rx.await
            .map_err(|_| "core session thread dropped the reply".to_owned())?
    }

    /// Drain the in-RAM inbox.
    pub async fn inbox(&self) -> Vec<InboxEntry> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(CoreMsg::Inbox { reply }).await.is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// (Re)publish a bundle and return its wire bytes.
    pub async fn publish_bundle(&self, count: usize) -> Result<Vec<u8>, String> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CoreMsg::PublishBundle { count, reply })
            .await
            .map_err(|_| "core session thread is not running".to_owned())?;
        rx.await
            .map_err(|_| "core session thread dropped the reply".to_owned())?
    }
}

/// Spawn the core thread, taking ownership of an already-opened
/// [`SessionManager`]. Building the manager (which does file I/O) is the
/// caller's job — on a blocking task — so open errors surface synchronously.
///
/// Fails only if the OS refuses to create the thread.
pub fn spawn_core(manager: SessionManager) -> std::io::Result<CoreHandle> {
    let (tx, rx) = mpsc::channel(64);
    std::thread::Builder::new()
        .name("prism-core-session".to_owned())
        .spawn(move || run(manager, rx))?;
    Ok(CoreHandle { tx })
}

/// The core thread's serial command loop.
fn run(mut manager: SessionManager, mut rx: mpsc::Receiver<CoreMsg>) {
    let mut inbox: Vec<InboxEntry> = Vec::new();
    while let Some(msg) = rx.blocking_recv() {
        match msg {
            CoreMsg::HasSession { peer, reply } => {
                let exists = PublicIdentity::from_bytes(&peer)
                    .ok()
                    .and_then(|id| manager.find_session(&id))
                    .is_some();
                let _ = reply.send(exists);
            }
            CoreMsg::Deliver {
                peer,
                bundle,
                body,
                reply,
            } => {
                let _ = reply.send(deliver(&mut manager, peer, bundle, &body));
            }
            CoreMsg::Inbound {
                from,
                sealed,
                reply,
            } => {
                let _ = reply.send(inbound(&mut manager, from, &sealed, &mut inbox));
            }
            CoreMsg::Inbox { reply } => {
                let _ = reply.send(std::mem::take(&mut inbox));
            }
            CoreMsg::PublishBundle { count, reply } => {
                let _ = reply.send(manager.publish_bundle(count).map_err(|e| e.to_string()));
            }
        }
    }
}

/// Find-or-establish a session with `peer`, then encrypt `body`. The
/// `SessionManager` persists the advanced ratchet state before returning.
fn deliver(
    manager: &mut SessionManager,
    peer: [u8; 32],
    bundle: Option<Vec<u8>>,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let peer = PublicIdentity::from_bytes(&peer).map_err(|e| e.to_string())?;
    let session = match manager.find_session(&peer) {
        Some(session) => session,
        None => {
            let bundle =
                bundle.ok_or_else(|| "no session and no bundle to establish".to_owned())?;
            manager
                .establish_outbound(&peer, &bundle, OtkChoice::Auto)
                .map_err(|e| e.to_string())?
        }
    };
    manager.encrypt(&session, body).map_err(|e| e.to_string())
}

/// Decrypt an inbound message and enforce the transport↔crypto identity bind.
fn inbound(
    manager: &mut SessionManager,
    from: [u8; 32],
    sealed: &[u8],
    inbox: &mut Vec<InboxEntry>,
) -> InboundOutcome {
    // The Noise-authenticated sender key must be a valid identity key.
    let Ok(from_identity) = PublicIdentity::from_bytes(&from) else {
        return InboundOutcome::Rejected;
    };
    let decrypted = match manager.decrypt(sealed) {
        Ok(decrypted) => decrypted,
        Err(_) => return InboundOutcome::Rejected,
    };
    // Two-layer identity check: the crypto-proven message identity must equal
    // the transport (Noise) identity. A peer cannot deliver a message
    // cryptographically bound to someone else.
    if decrypted.peer != from_identity {
        warn!("rejected inbound: transport identity does not match message identity");
        return InboundOutcome::Rejected;
    }
    inbox.push(InboxEntry {
        from_fingerprint: decrypted.peer.fingerprint().full(),
        body: decrypted.plaintext,
    });
    InboundOutcome::Accepted
}

/// Open (or create) the session store for `identity` at `path`, on the calling
/// (blocking) thread. Kept here so the daemon builds the manager with the same
/// module that owns it.
pub fn open_manager(
    identity: &IdentityKeypair,
    path: PathBuf,
) -> Result<SessionManager, prism_core::session::SessionError> {
    SessionManager::open(identity, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_core::session::OtkChoice;
    use prism_core::Seed32;

    fn manager(dir: &tempfile::TempDir, fill: u8) -> (IdentityKeypair, SessionManager) {
        let id = IdentityKeypair::from_seed(&Seed32::from_bytes([fill; 32]));
        let m = SessionManager::open(&id, dir.path().join(format!("{fill}.prs"))).unwrap();
        (id, m)
    }

    /// A sealed message from Alice, delivered but claimed to come from a peer
    /// key that is not Alice's, must be rejected — this is the two-layer check
    /// (Noise-authenticated transport key must equal the crypto identity).
    #[test]
    fn inbound_rejects_transport_identity_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let (_alice_id, mut alice) = manager(&dir, 0xA1);
        let (bob_id, mut bob) = manager(&dir, 0xB0);

        let bundle = bob.publish_bundle(4).unwrap();
        let sid = alice
            .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Auto)
            .unwrap();
        let sealed = alice.encrypt(&sid, b"hello").unwrap();

        // Delivered as if it came from Carol's key, not Alice's.
        let carol_key = *IdentityKeypair::from_seed(&Seed32::from_bytes([0xCC; 32]))
            .public()
            .as_bytes();
        let mut inbox = Vec::new();
        assert_eq!(
            inbound(&mut bob, carol_key, &sealed, &mut inbox),
            InboundOutcome::Rejected
        );
        assert!(
            inbox.is_empty(),
            "a mismatched delivery must not reach the inbox"
        );
    }

    /// The same message, delivered from Alice's real key, is accepted and lands
    /// in the inbox tagged with her fingerprint.
    #[test]
    fn inbound_accepts_matching_identity() {
        let dir = tempfile::tempdir().unwrap();
        let (alice_id, mut alice) = manager(&dir, 0xA1);
        let (bob_id, mut bob) = manager(&dir, 0xB0);

        let bundle = bob.publish_bundle(4).unwrap();
        let sid = alice
            .establish_outbound(&bob_id.public(), &bundle, OtkChoice::Auto)
            .unwrap();
        let sealed = alice.encrypt(&sid, b"hello").unwrap();

        let alice_key = *alice_id.public().as_bytes();
        let mut inbox = Vec::new();
        assert_eq!(
            inbound(&mut bob, alice_key, &sealed, &mut inbox),
            InboundOutcome::Accepted
        );
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].body.as_slice(), b"hello");
        assert_eq!(
            inbox[0].from_fingerprint,
            alice_id.public().fingerprint().full()
        );
    }

    /// Garbage bytes delivered as a message are a clean rejection, never a panic.
    #[test]
    fn inbound_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let (_bob_id, mut bob) = manager(&dir, 0xB0);
        let some_key = *IdentityKeypair::from_seed(&Seed32::from_bytes([0x11; 32]))
            .public()
            .as_bytes();
        let mut inbox = Vec::new();
        assert_eq!(
            inbound(&mut bob, some_key, &[0xde, 0xad, 0xbe, 0xef], &mut inbox),
            InboundOutcome::Rejected
        );
        assert!(inbox.is_empty());
    }
}
