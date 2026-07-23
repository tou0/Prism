// SPDX-License-Identifier: AGPL-3.0-or-later
//! IPC server: accept loop, peer-credential check, and request dispatch.
//!
//! Identity handlers run their Argon2id/keygen work on the blocking pool
//! (`spawn_blocking`) — never on the async executor (CLAUDE.md absolute
//! rule). Error responses are honest but never carry secret material.

use std::sync::Arc;

use prism_core::keystore::{self, KeystoreContents};
use prism_core::recovery::RecoveryPhrase;
use prism_core::{validate_nick, IdentityKeypair, Passphrase, Seed32};
use prism_proto::{
    read_message_opt, write_message, Envelope, Event, ProtoError, RecoveryMode, Request, Response,
    Sensitive, PROTOCOL_VERSION,
};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc};
use tokio::task::{JoinError, JoinHandle};
use tracing::{debug, warn};

use crate::state::{AppState, UnlockedIdentity};
use crate::DaemonError;

/// Accept connections on `listener` forever, serving each authorized client.
///
/// Every incoming connection is checked with `SO_PEERCRED`: only a peer whose
/// UID matches the daemon's own UID is served. Any other peer, or a peer whose
/// credentials cannot be read, is dropped. Authorized connections are handled
/// on their own task.
///
/// Deferred (M2+, network threat model): there is no per-connection read
/// timeout and no cap on concurrent connections, so a same-UID peer could
/// stall a spawned task by sending a partial frame, or open many at once.
/// Acceptable for M1 — the socket is `0600`/`0700` and `SO_PEERCRED`-gated to
/// this user; a hostile *local same-UID* process is out of the M1 model.
/// Add an idle/read timeout and an in-flight-connection bound alongside the
/// network transport, when untrusted peers first reach the daemon.
pub async fn serve(listener: UnixListener, state: Arc<AppState>) -> Result<(), DaemonError> {
    let our_uid = rustix::process::getuid().as_raw();

    loop {
        let (stream, _addr) = listener.accept().await?;
        match stream.peer_cred() {
            Ok(cred) if cred.uid() == our_uid => {
                debug!("accepted IPC connection from the owning user");
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, state).await {
                        warn!(error = %e, "IPC connection ended with an error");
                    }
                });
            }
            Ok(cred) => {
                warn!(
                    peer_uid = cred.uid(),
                    "rejected IPC connection from a different user"
                );
            }
            Err(e) => {
                warn!(error = %e, "rejected IPC connection: could not read peer credentials");
            }
        }
    }
}

/// Serve a single connection until the peer closes it.
///
/// The read and write halves are split so a subscribed connection can carry two
/// concurrent flows — solicited request→response and unsolicited pushes —
/// without either blocking the other. **All writes funnel through one writer
/// task** fed by an mpsc, so the two flows never interleave a torn frame on the
/// socket. A one-shot client that never subscribes still sees exactly one
/// response per request, in order: its behaviour on the wire is unchanged.
async fn handle_connection(stream: UnixStream, state: Arc<AppState>) -> Result<(), ProtoError> {
    let (mut read_half, write_half) = stream.into_split();
    let (out_tx, out_rx) = mpsc::channel::<Envelope<Response>>(64);
    let writer = tokio::spawn(writer_task(write_half, out_rx));

    // Started on `Subscribe`; kept so it can be torn down when the read side
    // ends (dropping its broadcast receiver auto-unsubscribes).
    let mut forwarder: Option<JoinHandle<()>> = None;

    let outcome = run_requests(&state, &mut read_half, &out_tx, &mut forwarder).await;

    if let Some(handle) = forwarder {
        handle.abort();
    }
    drop(out_tx); // let the writer task finish
    let _ = writer.await;
    outcome
}

/// The sole owner of the write half: serializes every outbound frame (solicited
/// responses and pushes alike) so they never interleave on the socket.
async fn writer_task(
    mut write_half: OwnedWriteHalf,
    mut out_rx: mpsc::Receiver<Envelope<Response>>,
) {
    while let Some(envelope) = out_rx.recv().await {
        if write_message(&mut write_half, &envelope).await.is_err() {
            break; // peer went away; stop writing
        }
    }
}

/// Read and answer requests until the peer closes the connection.
///
/// A version-correct `Subscribe` is intercepted here (it upgrades the
/// connection to a push stream) rather than dispatched; every other request is
/// a plain request→response routed through the writer.
async fn run_requests(
    state: &Arc<AppState>,
    read_half: &mut OwnedReadHalf,
    out_tx: &mpsc::Sender<Envelope<Response>>,
    forwarder: &mut Option<JoinHandle<()>>,
) -> Result<(), ProtoError> {
    while let Some(envelope) = read_message_opt::<_, Envelope<Request>>(read_half).await? {
        if envelope.version == PROTOCOL_VERSION && matches!(envelope.message, Request::Subscribe) {
            if out_tx
                .send(Envelope::new(Response::Subscribed))
                .await
                .is_err()
            {
                break;
            }
            // A repeat Subscribe restarts the forwarder (fresh backlog flush).
            if let Some(previous) = forwarder.take() {
                previous.abort();
            }
            *forwarder = Some(spawn_event_forwarder(Arc::clone(state), out_tx.clone()));
            continue;
        }

        let response = dispatch(state, envelope).await;
        if out_tx.send(Envelope::new(response)).await.is_err() {
            break;
        }
    }
    Ok(())
}

/// Forward push events to one subscribed connection until it disconnects.
///
/// Subscribes to the broadcast **first** (so no live event is missed), then
/// flushes any buffered inbox (messages that arrived while nobody was
/// subscribed), then streams live events. A slow subscriber that lags is
/// noted and continues — never fatal, never blocking the sender.
fn spawn_event_forwarder(
    state: Arc<AppState>,
    out_tx: mpsc::Sender<Envelope<Response>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut rx = state.events.subscribe();

        let buffered = match state.net.read().await.as_ref() {
            Some(handles) => handles.core.inbox().await,
            None => Vec::new(),
        };
        for entry in buffered {
            let event = Response::Event(Event::Message {
                from_fingerprint: entry.from_fingerprint,
                // Lossy UTF-8 for display, mirroring the `Inbox` drain; the
                // body never touched disk and is re-wrapped in `Sensitive`.
                body: Sensitive::new(String::from_utf8_lossy(&entry.body).into_owned()),
            });
            if out_tx.send(Envelope::new(event)).await.is_err() {
                return;
            }
        }

        loop {
            match rx.recv().await {
                Ok(event) => {
                    let wire = Envelope::new(Response::Event(event.to_wire()));
                    if out_tx.send(wire).await.is_err() {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(dropped)) => {
                    debug!(dropped, "push subscriber lagged; some events skipped");
                }
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

/// Map a versioned request to a response, rejecting unsupported versions.
async fn dispatch(state: &AppState, envelope: Envelope<Request>) -> Response {
    if envelope.version != PROTOCOL_VERSION {
        return Response::Error {
            message: format!(
                "unsupported IPC protocol version {} (this daemon speaks {})",
                envelope.version, PROTOCOL_VERSION
            ),
        };
    }

    match envelope.message {
        Request::Ping => Response::Pong,
        Request::Init {
            nick,
            passphrase,
            recovery,
            force,
        } => handle_init(state, nick, passphrase, recovery, force).await,
        Request::Restore {
            nick,
            passphrase,
            mnemonic,
            force,
        } => handle_restore(state, nick, passphrase, Some(mnemonic), force).await,
        Request::Unlock { passphrase } => handle_unlock(state, passphrase).await,
        Request::Whoami => handle_whoami(state).await,
        Request::Send { to, body } => crate::networking::handle_send(state, to, body).await,
        Request::Inbox => crate::networking::handle_inbox(state).await,
        Request::Peers => crate::networking::handle_peers(state).await,
        Request::Status => crate::networking::handle_status(state).await,
        // Subscription is not a plain request→response: `run_requests`
        // intercepts a version-correct `Subscribe` and upgrades the connection
        // to a push stream, so this arm is unreachable in practice. Kept as a
        // defensive fallback (a version-mismatched `Subscribe` is caught by the
        // version check above, never reaching here).
        Request::Subscribe => Response::Error {
            message: "subscription must be issued on a live connection".to_owned(),
        },
    }
}

/// After a successful unlock/init, bring the networking subsystem up bound to
/// the now-unlocked identity. A bring-up failure leaves the daemon unlocked
/// but offline (logged, not fatal): the identity operation itself succeeded.
async fn bring_up_networking(state: &AppState) {
    let seed = match state.unlocked.read().await.as_ref() {
        Some(identity) => identity.seed(),
        None => return,
    };
    if let Err(e) = crate::networking::ensure_up(state, seed).await {
        warn!(error = %e, "networking failed to start; the daemon is unlocked but offline");
    }
}

/// Turn any displayable error into an error response. Error text never
/// contains secrets (keystore/recovery errors carry paths and reasons only).
fn error_response(e: impl std::fmt::Display) -> Response {
    Response::Error {
        message: e.to_string(),
    }
}

/// A `spawn_blocking` join failure (panic or shutdown) — reported without
/// detail, since panic payloads are not under our control.
fn join_error(_: JoinError) -> Response {
    Response::Error {
        message: "internal error: a background task failed".to_owned(),
    }
}

/// `Init`: generate (or derive) the identity daemon-side, seal the keystore,
/// and leave it unlocked. The mnemonic, if any, is returned exactly once.
async fn handle_init(
    state: &AppState,
    nick: String,
    passphrase: Sensitive,
    recovery: RecoveryMode,
    force: bool,
) -> Response {
    if let Err(e) = validate_nick(&nick) {
        return error_response(e);
    }

    // Write lock across the whole operation: serializes concurrent
    // init/restore/unlock attempts on the same keystore.
    let mut unlocked = state.unlocked.write().await;
    let path = state.keystore_path.clone();
    let task_nick = nick.clone();
    let result = tokio::task::spawn_blocking(move || {
        let pass = Passphrase::new(passphrase.into_secret());
        let (seed, mnemonic) = match recovery {
            RecoveryMode::None => (Seed32::generate().map_err(error_response)?, None),
            RecoveryMode::Phrase => {
                let phrase = RecoveryPhrase::generate().map_err(error_response)?;
                let seed = phrase.derive_identity_seed().map_err(error_response)?;
                // The one-time exposure: shown to the user, never stored.
                (seed, Some(phrase.expose_phrase()))
            }
        };
        let keypair = IdentityKeypair::from_seed(&seed);
        let contents = KeystoreContents::new(task_nick, seed);
        keystore::seal_to_path(&path, &contents, &pass, force).map_err(error_response)?;
        Ok((keypair, mnemonic))
    })
    .await;

    let response = match result {
        Ok(Ok((keypair, mnemonic))) => {
            let identity = UnlockedIdentity::new(keypair, nick);
            let response = Response::Created {
                handle: identity.handle(),
                fingerprint: identity.fingerprint(),
                mnemonic: mnemonic.map(Sensitive::from_zeroizing),
            };
            *unlocked = Some(identity);
            response
        }
        Ok(Err(response)) => response,
        Err(join) => join_error(join),
    };
    drop(unlocked); // release before networking bring-up reads it
    if matches!(response, Response::Created { .. }) {
        bring_up_networking(state).await;
    }
    response
}

/// `Restore`: like `Init`, but the seed is derived from the given recovery
/// phrase — deterministically the same identity as when it was created.
async fn handle_restore(
    state: &AppState,
    nick: String,
    passphrase: Sensitive,
    mnemonic: Option<Sensitive>,
    force: bool,
) -> Response {
    if let Err(e) = validate_nick(&nick) {
        return error_response(e);
    }
    let Some(mnemonic) = mnemonic else {
        return Response::Error {
            message: "a recovery phrase is required to restore".to_owned(),
        };
    };

    let mut unlocked = state.unlocked.write().await;
    let path = state.keystore_path.clone();
    let task_nick = nick.clone();
    let result = tokio::task::spawn_blocking(move || {
        let pass = Passphrase::new(passphrase.into_secret());
        let phrase = RecoveryPhrase::parse(mnemonic.expose()).map_err(error_response)?;
        let seed = phrase.derive_identity_seed().map_err(error_response)?;
        let keypair = IdentityKeypair::from_seed(&seed);
        let contents = KeystoreContents::new(task_nick, seed);
        keystore::seal_to_path(&path, &contents, &pass, force).map_err(error_response)?;
        Ok(keypair)
    })
    .await;

    let response = match result {
        Ok(Ok(keypair)) => {
            let identity = UnlockedIdentity::new(keypair, nick);
            let response = Response::Created {
                handle: identity.handle(),
                fingerprint: identity.fingerprint(),
                // Restoring never echoes the phrase back.
                mnemonic: None,
            };
            *unlocked = Some(identity);
            response
        }
        Ok(Err(response)) => response,
        Err(join) => join_error(join),
    };
    drop(unlocked); // release before networking bring-up reads it
    if matches!(response, Response::Created { .. }) {
        bring_up_networking(state).await;
    }
    response
}

/// `Unlock`: decrypt the keystore and load the identity into RAM. Always
/// runs the full KDF + AEAD verification, even if already unlocked — a
/// wrong passphrase never succeeds by riding an existing unlock.
async fn handle_unlock(state: &AppState, passphrase: Sensitive) -> Response {
    let mut unlocked = state.unlocked.write().await;
    let path = state.keystore_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        let pass = Passphrase::new(passphrase.into_secret());
        keystore::open_from_path(&path, &pass).map_err(error_response)
    })
    .await;

    let response = match result {
        Ok(Ok(contents)) => {
            let keypair = IdentityKeypair::from_seed(contents.seed());
            let identity = UnlockedIdentity::new(keypair, contents.nick().to_owned());
            let response = Response::Identity {
                handle: identity.handle(),
                fingerprint: identity.fingerprint(),
            };
            *unlocked = Some(identity);
            response
        }
        Ok(Err(response)) => response,
        Err(join) => join_error(join),
    };
    drop(unlocked); // release before networking bring-up reads it
    if matches!(response, Response::Identity { .. }) {
        bring_up_networking(state).await;
    }
    response
}

/// `Whoami`: report the unlocked identity, or `Locked`.
async fn handle_whoami(state: &AppState) -> Response {
    match state.unlocked.read().await.as_ref() {
        Some(identity) => Response::Identity {
            handle: identity.handle(),
            fingerprint: identity.fingerprint(),
        },
        None => Response::Locked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> AppState {
        AppState::new(
            std::path::PathBuf::from("/nonexistent/test/keystore.pks"),
            std::path::PathBuf::from("/nonexistent/test/sessions.prs"),
            "/ip4/127.0.0.1/tcp/0".to_owned(),
        )
    }

    #[tokio::test]
    async fn ping_is_answered_with_pong() {
        let response = dispatch(&test_state(), Envelope::new(Request::Ping)).await;
        assert!(matches!(response, Response::Pong));
    }

    #[tokio::test]
    async fn unsupported_version_is_rejected() {
        let envelope = Envelope {
            version: PROTOCOL_VERSION.wrapping_add(1),
            message: Request::Ping,
        };
        assert!(matches!(
            dispatch(&test_state(), envelope).await,
            Response::Error { .. }
        ));
    }

    #[tokio::test]
    async fn whoami_starts_locked() {
        let response = dispatch(&test_state(), Envelope::new(Request::Whoami)).await;
        assert!(matches!(response, Response::Locked));
    }
}
