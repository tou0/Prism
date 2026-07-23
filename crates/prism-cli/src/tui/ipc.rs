// SPDX-License-Identifier: AGPL-3.0-or-later
//! The subscribed IPC client for the TUI.
//!
//! Opens one connection, subscribes to push events, and splits it: a **writer**
//! task owns the write half and drains outbound requests; a **reader** task owns
//! the read half and demultiplexes incoming frames — [`Response::Event`] frames
//! go to the push channel, everything else to the solicited-reply channel.
//! Splitting the socket off the render loop is what keeps a keystroke from ever
//! blocking on I/O and a push from ever freezing input.

use std::path::Path;

use anyhow::{Context, Result};
use prism_proto::{read_message, write_message, Envelope, Event, Request, Response};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

/// Channels connecting the TUI loop to the daemon over one subscribed socket.
pub struct IpcHandles {
    /// Outbound requests (send, fetches).
    pub requests: mpsc::Sender<Request>,
    /// Solicited replies (Identity, Status, Peers, Sent, …).
    pub responses: mpsc::Receiver<Response>,
    /// Unsolicited push events (messages, peer discovery).
    pub pushes: mpsc::Receiver<Event>,
}

/// Connect, subscribe to pushes, and spawn the reader/writer tasks.
pub async fn connect_subscribed(socket_path: &Path) -> Result<IpcHandles> {
    let stream = UnixStream::connect(socket_path)
        .await
        .context("connecting to prismd (is it running and unlocked?)")?;
    let (read_half, write_half) = stream.into_split();

    let (req_tx, req_rx) = mpsc::channel::<Request>(32);
    let (resp_tx, resp_rx) = mpsc::channel::<Response>(64);
    let (push_tx, push_rx) = mpsc::channel::<Event>(256);

    tokio::spawn(writer(write_half, req_rx));
    tokio::spawn(reader(read_half, resp_tx, push_tx));

    // Subscribe first; the daemon replies Subscribed (ignored by the reducer)
    // then flushes any buffered inbox as Message pushes.
    req_tx
        .send(Request::Subscribe)
        .await
        .context("subscribing to daemon push events")?;

    Ok(IpcHandles {
        requests: req_tx,
        responses: resp_rx,
        pushes: push_rx,
    })
}

/// Drain outbound requests to the socket until the channel or socket closes.
async fn writer(
    mut write_half: tokio::net::unix::OwnedWriteHalf,
    mut req_rx: mpsc::Receiver<Request>,
) {
    while let Some(request) = req_rx.recv().await {
        if write_message(&mut write_half, &Envelope::new(request))
            .await
            .is_err()
        {
            break;
        }
    }
}

/// Read frames and route pushes vs solicited replies to their channels.
async fn reader(
    mut read_half: tokio::net::unix::OwnedReadHalf,
    resp_tx: mpsc::Sender<Response>,
    push_tx: mpsc::Sender<Event>,
) {
    while let Ok(envelope) = read_message::<_, Envelope<Response>>(&mut read_half).await {
        match envelope.message {
            Response::Event(event) => {
                if push_tx.send(event).await.is_err() {
                    break;
                }
            }
            other => {
                if resp_tx.send(other).await.is_err() {
                    break;
                }
            }
        }
    }
}
