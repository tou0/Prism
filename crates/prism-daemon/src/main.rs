// SPDX-License-Identifier: AGPL-3.0-or-later
//! `prismd` — the Prism daemon binary.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use prism_daemon::{bind_secure, serve, AppState, SocketGuard};

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
    /// Path to the encrypted keystore (defaults to the per-user data directory).
    #[arg(long)]
    keystore: Option<PathBuf>,
    /// Path to the sealed ratchet-state store (defaults next to the keystore).
    #[arg(long)]
    sessions: Option<PathBuf>,
    /// Multiaddr the swarm listens on for LAN peers.
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/0")]
    listen: String,
    /// A DHT bootstrap node, `…/p2p/<peer-id>` (repeatable). No bootstrap nodes
    /// are hard-coded; supply your own (e.g. a self-hosted node) to join a DHT.
    #[arg(long = "bootstrap")]
    bootstrap: Vec<String>,
    /// A globally-routable multiaddr to advertise as ours (repeatable). Set on a
    /// public/VPS node so it publishes a reachable, server-mode DHT locator.
    #[arg(long = "external-address")]
    external_address: Vec<String>,
    /// Disable mDNS LAN discovery. Recommended on WAN-exposed / headless nodes
    /// (a public bootstrap node has no LAN peers); also removes the mDNS socket.
    #[arg(long = "no-mdns")]
    no_mdns: bool,
    /// Disable the Kademlia DHT (LAN-only node, mDNS only).
    #[arg(long = "no-dht")]
    no_dht: bool,
    /// Disable NAT traversal (AutoNAT reachability detection, hole punching, and
    /// relay use). Leaves the node with direct connectivity only — it will not
    /// reach peers behind NAT, nor be reachable if it is itself behind one.
    #[arg(long = "no-nat-traversal")]
    no_nat_traversal: bool,
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

    let keystore_path = match args.keystore {
        Some(path) => path,
        None => {
            prism_core::default_keystore_path().context("resolving the default keystore path")?
        }
    };

    // The ratchet store sits next to the keystore by default.
    let sessions_path = args.sessions.unwrap_or_else(|| {
        keystore_path
            .parent()
            .map(|dir| dir.join("sessions.prs"))
            .unwrap_or_else(|| PathBuf::from("sessions.prs"))
    });

    let net_config = prism_net::NetConfig {
        enable_mdns: !args.no_mdns,
        enable_dht: !args.no_dht,
        bootstrap: args.bootstrap,
        external_addrs: args.external_address,
        enable_nat_traversal: !args.no_nat_traversal,
        relay_server: None,
    };

    let listener = bind_secure(&socket_path)
        .with_context(|| format!("binding IPC socket at {}", socket_path.display()))?;
    // Unlink the socket file on shutdown.
    let _guard = SocketGuard::new(socket_path.clone());
    let state = Arc::new(AppState::with_net_config(
        keystore_path,
        sessions_path,
        args.listen,
        net_config,
    ));
    info!(socket = %socket_path.display(), "prismd is listening");

    tokio::select! {
        result = serve(listener, state) => result.context("IPC server stopped unexpectedly")?,
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
