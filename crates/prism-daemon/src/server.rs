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
    read_message_opt, write_message, Envelope, ProtoError, RecoveryMode, Request, Response,
    Sensitive, PROTOCOL_VERSION,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinError;
use tracing::{debug, warn};

use crate::state::{AppState, UnlockedIdentity};
use crate::DaemonError;

/// Accept connections on `listener` forever, serving each authorized client.
///
/// Every incoming connection is checked with `SO_PEERCRED`: only a peer whose
/// UID matches the daemon's own UID is served. Any other peer, or a peer whose
/// credentials cannot be read, is dropped. Authorized connections are handled
/// on their own task.
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

/// Serve requests on a single connection until the peer closes it.
async fn handle_connection(mut stream: UnixStream, state: Arc<AppState>) -> Result<(), ProtoError> {
    while let Some(envelope) = read_message_opt::<_, Envelope<Request>>(&mut stream).await? {
        let response = dispatch(&state, envelope).await;
        write_message(&mut stream, &Envelope::new(response)).await?;
    }
    Ok(())
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

    match result {
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
    }
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

    match result {
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
    }
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

    match result {
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
    }
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
        AppState::new(std::path::PathBuf::from("/nonexistent/test/keystore.pks"))
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
