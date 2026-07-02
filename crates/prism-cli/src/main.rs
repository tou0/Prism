// SPDX-License-Identifier: AGPL-3.0-or-later
//! `prism` — the Prism thin client binary.
//!
//! Talks to the local `prismd` daemon over the IPC socket. For milestone M0 it
//! offers a single `ping` command that proves the IPC round-trip works.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::net::UnixStream;

use prism_proto::{read_message, write_message, Envelope, Request, Response};

#[derive(Debug, Parser)]
#[command(
    name = "prism",
    version,
    about = "Prism client: talks to the local prismd daemon over IPC."
)]
struct Cli {
    /// Path to the IPC socket (defaults to the per-user runtime directory).
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Ping the daemon; prints "pong" on success.
    Ping,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Build the runtime by hand rather than via #[tokio::main] so that no
    // macro-generated `.expect()` bypasses the workspace-wide
    // `clippy::expect_used = "deny"` lint; runtime setup errors go through `?`.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;
    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    let socket_path = match cli.socket {
        Some(path) => path,
        None => {
            prism_core::default_socket_path().context("resolving the default IPC socket path")?
        }
    };

    match cli.command {
        Command::Ping => ping(&socket_path).await,
    }
}

/// Send a `Ping` to the daemon and print `pong` on success.
async fn ping(socket_path: &Path) -> Result<()> {
    let mut stream = UnixStream::connect(socket_path).await.with_context(|| {
        format!(
            "connecting to the daemon at {} (is prismd running?)",
            socket_path.display()
        )
    })?;

    write_message(&mut stream, &Envelope::new(Request::Ping))
        .await
        .context("sending ping to the daemon")?;

    let response: Envelope<Response> = read_message(&mut stream)
        .await
        .context("reading the daemon's response")?;

    match response.message {
        Response::Pong => {
            println!("pong");
            Ok(())
        }
        Response::Error { message } => anyhow::bail!("daemon returned an error: {message}"),
    }
}
