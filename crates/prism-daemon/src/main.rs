// SPDX-License-Identifier: AGPL-3.0-or-later
//! `prismd` — the Prism daemon binary.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use prism_daemon::{bind_secure, serve, SocketGuard};

#[derive(Debug, Parser)]
#[command(
    name = "prismd",
    version,
    about = "Prism daemon: holds keys, runs the network, and exposes the local IPC socket."
)]
struct Args {
    /// Path to the IPC socket (defaults to the per-user runtime directory).
    #[arg(long)]
    socket: Option<PathBuf>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).try_init().ok();

    let args = Args::parse();

    // Build the runtime by hand rather than via #[tokio::main] so that no
    // macro-generated `.expect()` bypasses the workspace-wide
    // `clippy::expect_used = "deny"` lint; runtime setup errors go through `?`.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;
    runtime.block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
    let socket_path = match args.socket {
        Some(path) => path,
        None => {
            prism_core::default_socket_path().context("resolving the default IPC socket path")?
        }
    };

    let listener = bind_secure(&socket_path)
        .with_context(|| format!("binding IPC socket at {}", socket_path.display()))?;
    // Unlink the socket file on shutdown.
    let _guard = SocketGuard::new(socket_path.clone());
    info!(socket = %socket_path.display(), "prismd is listening");

    tokio::select! {
        result = serve(listener) => result.context("IPC server stopped unexpectedly")?,
        _ = shutdown_signal() => info!("shutdown signal received; exiting"),
    }

    Ok(())
}

/// Resolve when the process is asked to shut down: Ctrl-C on any platform, or
/// `SIGTERM` additionally on Unix.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = term.recv() => {}
                }
            }
            // If SIGTERM cannot be registered, fall back to Ctrl-C only.
            Err(_) => ctrl_c.await,
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}
