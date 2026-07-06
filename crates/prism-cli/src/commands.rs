// SPDX-License-Identifier: AGPL-3.0-or-later
//! One-shot commands: connect, send a single request, print the response.

use std::path::Path;

use anyhow::{bail, Context, Result};
use tokio::net::UnixStream;

use prism_proto::{read_message, write_message, Envelope, Request, Response};

use crate::{prompt, text};

/// Connect to the daemon's IPC socket.
async fn connect(socket_path: &Path) -> Result<UnixStream> {
    UnixStream::connect(socket_path).await.with_context(|| {
        format!(
            "connecting to the daemon at {} (is prismd running?)",
            socket_path.display()
        )
    })
}

/// Send one request and read one response.
async fn roundtrip(socket_path: &Path, request: Request) -> Result<Response> {
    let mut stream = connect(socket_path).await?;
    write_message(&mut stream, &Envelope::new(request))
        .await
        .context("sending the request to the daemon")?;
    let response: Envelope<Response> = read_message(&mut stream)
        .await
        .context("reading the daemon's response")?;
    Ok(response.message)
}

/// `prism ping`
pub async fn ping(socket_path: &Path) -> Result<()> {
    match roundtrip(socket_path, Request::Ping).await? {
        Response::Pong => {
            println!("{}", text::PONG);
            Ok(())
        }
        other => fail(other),
    }
}

/// `prism init` — prompts (nick, passphrase, recovery mode) run *before*
/// connecting; key generation happens daemon-side.
pub async fn init(socket_path: &Path, force: bool) -> Result<()> {
    let nick = prompt::nick()?;
    let passphrase = prompt::passphrase_new()?;
    let recovery = prompt::recovery_mode()?;

    let request = Request::Init {
        nick,
        passphrase,
        recovery,
        force,
    };
    match roundtrip(socket_path, request).await? {
        Response::Created {
            handle,
            fingerprint,
            mnemonic,
        } => {
            if let Some(mnemonic) = mnemonic {
                prompt::display_mnemonic(&mnemonic)?;
            }
            println!("{}", text::CREATED_HEADER);
            print_identity(&handle, &fingerprint);
            Ok(())
        }
        other => fail(other),
    }
}

/// `prism restore` — the phrase is validated client-side (typo feedback),
/// derivation and sealing happen daemon-side.
pub async fn restore(socket_path: &Path, force: bool) -> Result<()> {
    let nick = prompt::nick()?;
    let passphrase = prompt::passphrase_new()?;
    let mnemonic = prompt::mnemonic()?;

    let request = Request::Restore {
        nick,
        passphrase,
        mnemonic,
        force,
    };
    match roundtrip(socket_path, request).await? {
        Response::Created {
            handle,
            fingerprint,
            ..
        } => {
            println!("{}", text::RESTORED_HEADER);
            print_identity(&handle, &fingerprint);
            Ok(())
        }
        other => fail(other),
    }
}

/// `prism unlock`
pub async fn unlock(socket_path: &Path) -> Result<()> {
    let passphrase = prompt::passphrase()?;
    match roundtrip(socket_path, Request::Unlock { passphrase }).await? {
        Response::Identity {
            handle,
            fingerprint,
        } => {
            println!("{}", text::UNLOCKED_HEADER);
            print_identity(&handle, &fingerprint);
            Ok(())
        }
        other => fail(other),
    }
}

/// `prism whoami`
pub async fn whoami(socket_path: &Path) -> Result<()> {
    match roundtrip(socket_path, Request::Whoami).await? {
        Response::Identity {
            handle,
            fingerprint,
        } => {
            print_identity(&handle, &fingerprint);
            Ok(())
        }
        Response::Locked => {
            println!("{}", text::LOCKED);
            Ok(())
        }
        other => fail(other),
    }
}

fn print_identity(handle: &str, fingerprint: &str) {
    println!("  handle:      {handle}");
    println!("  fingerprint: {fingerprint}");
}

/// An error or unexpected response, reported honestly. `Response`'s `Debug`
/// never exposes secrets (`Sensitive` prints redacted).
fn fail(response: Response) -> Result<()> {
    match response {
        Response::Error { message } => bail!("daemon returned an error: {message}"),
        other => bail!("unexpected response from the daemon: {other:?}"),
    }
}
