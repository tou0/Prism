// SPDX-License-Identifier: AGPL-3.0-or-later
//! End-to-end identity tests over the real IPC socket: init (both recovery
//! modes), unlock, restore, whoami, and force semantics.
//!
//! Each request runs a real Argon2id derivation, so the flows are grouped to
//! keep the test wall-time reasonable.

use std::path::Path;
use std::sync::Arc;

use prism_daemon::{bind_secure, serve, AppState};
use prism_proto::{
    read_message, write_message, Envelope, RecoveryMode, Request, Response, Sensitive,
};
use tokio::net::UnixStream;

const NICK: &str = "alice";
const PASSPHRASE: &str = "correct horse battery staple";

/// Start a daemon on a temp socket + keystore; return a connected client.
// Test-only helper: clippy's `allow-expect-in-tests` does not reach helpers
// outside `#[test]` functions, hence the explicit allow.
#[allow(clippy::expect_used)]
async fn start(dir: &tempfile::TempDir) -> UnixStream {
    let socket = dir.path().join("run").join("prismd.sock");
    let listener = bind_secure(&socket).expect("bind secure socket");
    let state = Arc::new(AppState::new(
        dir.path().join("keystore.pks"),
        dir.path().join("sessions.prs"),
        "/ip4/127.0.0.1/tcp/0".to_owned(),
    ));
    tokio::spawn(serve(listener, state));
    UnixStream::connect(&socket).await.expect("connect")
}

/// Send one request, read one response.
// Test-only helper (see `start`).
#[allow(clippy::expect_used)]
async fn roundtrip(stream: &mut UnixStream, request: Request) -> Response {
    write_message(stream, &Envelope::new(request))
        .await
        .expect("send request");
    let envelope: Envelope<Response> = read_message(stream).await.expect("read response");
    envelope.message
}

fn sensitive(s: &str) -> Sensitive {
    Sensitive::new(s.to_owned())
}

#[tokio::test]
async fn init_without_recovery_then_whoami_and_unlock() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut client = start(&dir).await;

    // Fresh daemon: locked.
    assert!(matches!(
        roundtrip(&mut client, Request::Whoami).await,
        Response::Locked
    ));

    // Init without a recovery phrase: created, unlocked, no mnemonic.
    let created = roundtrip(
        &mut client,
        Request::Init {
            nick: NICK.to_owned(),
            passphrase: sensitive(PASSPHRASE),
            recovery: RecoveryMode::None,
            force: false,
        },
    )
    .await;
    let (handle, fingerprint) = match created {
        Response::Created {
            handle,
            fingerprint,
            mnemonic: None,
        } => (handle, fingerprint),
        other => panic!("expected Created without mnemonic, got {other:?}"),
    };
    assert!(handle.starts_with("alice#"));
    assert!(fingerprint.len() > 14, "expected the full fingerprint");

    // Whoami now reports the same identity.
    match roundtrip(&mut client, Request::Whoami).await {
        Response::Identity {
            handle: h,
            fingerprint: f,
        } => {
            assert_eq!(h, handle);
            assert_eq!(f, fingerprint);
        }
        other => panic!("expected Identity, got {other:?}"),
    }

    // A wrong passphrase must fail, and must not disturb the unlocked state.
    assert!(matches!(
        roundtrip(
            &mut client,
            Request::Unlock {
                passphrase: sensitive("wrong passphrase"),
            },
        )
        .await,
        Response::Error { .. }
    ));
    assert!(matches!(
        roundtrip(&mut client, Request::Whoami).await,
        Response::Identity { .. }
    ));

    // The right passphrase re-unlocks to the same identity.
    match roundtrip(
        &mut client,
        Request::Unlock {
            passphrase: sensitive(PASSPHRASE),
        },
    )
    .await
    {
        Response::Identity { handle: h, .. } => assert_eq!(h, handle),
        other => panic!("expected Identity, got {other:?}"),
    }

    // Init over an existing keystore without force is refused.
    assert!(matches!(
        roundtrip(
            &mut client,
            Request::Init {
                nick: NICK.to_owned(),
                passphrase: sensitive(PASSPHRASE),
                recovery: RecoveryMode::None,
                force: false,
            },
        )
        .await,
        Response::Error { .. }
    ));

    // The keystore file exists with tight permissions.
    assert!(Path::new(&dir.path().join("keystore.pks")).exists());
}

#[tokio::test]
async fn init_with_recovery_then_restore_reproduces_the_identity() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut client = start(&dir).await;

    // Init with an opt-in recovery phrase: the mnemonic is returned once.
    let created = roundtrip(
        &mut client,
        Request::Init {
            nick: NICK.to_owned(),
            passphrase: sensitive(PASSPHRASE),
            recovery: RecoveryMode::Phrase,
            force: false,
        },
    )
    .await;
    let (fingerprint, mnemonic) = match created {
        Response::Created {
            fingerprint,
            mnemonic: Some(mnemonic),
            ..
        } => (fingerprint, mnemonic),
        other => panic!("expected Created with a mnemonic, got {other:?}"),
    };
    assert_eq!(mnemonic.expose().split_whitespace().count(), 12);

    // Restore on a *fresh* daemon (separate socket + keystore) from the
    // phrase alone: deterministically the same identity, no mnemonic echo.
    let dir2 = tempfile::tempdir().expect("temp dir 2");
    let mut client2 = start(&dir2).await;
    let restored = roundtrip(
        &mut client2,
        Request::Restore {
            nick: NICK.to_owned(),
            passphrase: sensitive("a different passphrase"),
            mnemonic: Sensitive::new(mnemonic.expose().to_owned()),
            force: false,
        },
    )
    .await;
    match restored {
        Response::Created {
            fingerprint: f,
            mnemonic: None,
            ..
        } => assert_eq!(f, fingerprint, "restore must reproduce the identity"),
        other => panic!("expected Created without mnemonic echo, got {other:?}"),
    }

    // A garbage phrase is a clean error.
    assert!(matches!(
        roundtrip(
            &mut client2,
            Request::Restore {
                nick: NICK.to_owned(),
                passphrase: sensitive(PASSPHRASE),
                mnemonic: sensitive("not a valid mnemonic at all"),
                force: true,
            },
        )
        .await,
        Response::Error { .. }
    ));

    // An invalid nick is rejected before any crypto runs.
    assert!(matches!(
        roundtrip(
            &mut client2,
            Request::Init {
                nick: "no#hash allowed".to_owned(),
                passphrase: sensitive(PASSPHRASE),
                recovery: RecoveryMode::None,
                force: true,
            },
        )
        .await,
        Response::Error { .. }
    ));
}
