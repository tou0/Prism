// SPDX-License-Identifier: AGPL-3.0-or-later
//! `prism` — the Prism thin client binary.
//!
//! Talks to the local `prismd` daemon over the IPC socket. The client never
//! holds a private key: key material is generated, sealed, and unlocked
//! daemon-side; this binary only collects input and displays results.

mod commands;
mod prompt;
mod text;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

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
    /// Create a new identity (interactive; requires a running daemon).
    Init {
        /// Overwrite an existing keystore. DESTROYS the current identity.
        #[arg(long)]
        force: bool,
    },
    /// Recreate an identity from a recovery phrase (interactive).
    Restore {
        /// Overwrite an existing keystore. DESTROYS the current identity.
        #[arg(long)]
        force: bool,
    },
    /// Unlock the keystore (interactive).
    Unlock,
    /// Show the currently unlocked identity.
    Whoami,
    /// Send an encrypted message to a contact on the local network.
    Send {
        /// The recipient's handle, `nick#fingerprint`.
        to: String,
        /// The message text.
        message: String,
    },
    /// Show and drain received messages.
    Inbox,
    /// List peers discovered on the local network.
    Peers,
    /// Show network and identity status.
    Status,
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
        Command::Ping => commands::ping(&socket_path).await,
        Command::Init { force } => commands::init(&socket_path, force).await,
        Command::Restore { force } => commands::restore(&socket_path, force).await,
        Command::Unlock => commands::unlock(&socket_path).await,
        Command::Whoami => commands::whoami(&socket_path).await,
        Command::Send { to, message } => commands::send(&socket_path, to, message).await,
        Command::Inbox => commands::inbox(&socket_path).await,
        Command::Peers => commands::peers(&socket_path).await,
        Command::Status => commands::status(&socket_path).await,
    }
}
