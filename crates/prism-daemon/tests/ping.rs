// SPDX-License-Identifier: AGPL-3.0-or-later
//! End-to-end IPC test: drive `serve()` in-process over a temporary socket and
//! verify the `ping` -> `pong` exchange and the socket's permissions.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use prism_daemon::{bind_secure, serve, AppState};
use prism_proto::{read_message, write_message, Envelope, Request, Response, PROTOCOL_VERSION};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

/// State pointing at a keystore path that does not exist: fine for tests that
/// never touch identity requests.
fn test_state(dir: &tempfile::TempDir) -> Arc<AppState> {
    Arc::new(AppState::new(
        dir.path().join("keystore.pks"),
        dir.path().join("sessions.prs"),
        "/ip4/127.0.0.1/tcp/0".to_owned(),
    ))
}

#[tokio::test]
async fn ping_pong_end_to_end() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let socket = dir.path().join("run").join("prismd.sock");

    let listener = bind_secure(&socket).expect("bind secure socket");
    tokio::spawn(serve(listener, test_state(&dir)));

    let mut stream = UnixStream::connect(&socket)
        .await
        .expect("connect to daemon");
    write_message(&mut stream, &Envelope::new(Request::Ping))
        .await
        .expect("send ping");

    let response: Envelope<Response> = read_message(&mut stream).await.expect("read response");
    assert!(matches!(response.message, Response::Pong));
}

#[tokio::test]
async fn socket_and_directory_have_locked_down_permissions() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let socket = dir.path().join("run").join("prismd.sock");

    let _listener = bind_secure(&socket).expect("bind secure socket");

    let dir_mode = std::fs::metadata(socket.parent().expect("socket has parent"))
        .expect("read dir metadata")
        .permissions()
        .mode()
        & 0o777;
    let socket_mode = std::fs::metadata(&socket)
        .expect("read socket metadata")
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(dir_mode, 0o700, "runtime directory must be 0700");
    assert_eq!(socket_mode, 0o600, "socket file must be 0600");
}

#[tokio::test]
async fn unknown_protocol_version_gets_error_response() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let socket = dir.path().join("run").join("prismd.sock");

    let listener = bind_secure(&socket).expect("bind secure socket");
    tokio::spawn(serve(listener, test_state(&dir)));

    let mut stream = UnixStream::connect(&socket)
        .await
        .expect("connect to daemon");
    // Hand-craft an envelope carrying a version the daemon does not speak.
    let envelope = Envelope {
        version: PROTOCOL_VERSION.wrapping_add(99),
        message: Request::Ping,
    };
    write_message(&mut stream, &envelope)
        .await
        .expect("send request");

    // The daemon must answer with an error, not panic or hang.
    let response: Envelope<Response> = read_message(&mut stream).await.expect("read response");
    assert!(matches!(response.message, Response::Error { .. }));
}

#[tokio::test]
async fn truncated_frame_does_not_crash_the_daemon() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let socket = dir.path().join("run").join("prismd.sock");

    let listener = bind_secure(&socket).expect("bind secure socket");
    tokio::spawn(serve(listener, test_state(&dir)));

    // A hostile client announces a length, sends fewer bytes, then disconnects.
    {
        let mut bad = UnixStream::connect(&socket)
            .await
            .expect("connect (bad client)");
        bad.write_all(&64u32.to_be_bytes())
            .await
            .expect("write len prefix");
        bad.write_all(&[0xff, 0xff])
            .await
            .expect("write partial body");
        // Dropped here: the connection closes mid-frame.
    }

    // The daemon must survive that and still serve a well-formed client.
    let mut good = UnixStream::connect(&socket)
        .await
        .expect("connect (good client)");
    write_message(&mut good, &Envelope::new(Request::Ping))
        .await
        .expect("send ping");
    let response: Envelope<Response> = read_message(&mut good).await.expect("read response");
    assert!(matches!(response.message, Response::Pong));
}
