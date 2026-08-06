// SPDX-License-Identifier: AGPL-3.0-or-later
//! `prismd` — the Prism daemon binary.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};

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
    /// Act as a relay for NAT-bound peers (Circuit Relay v2). Opt-in, capped —
    /// see --relay-max-circuits / --relay-max-reservations.
    #[arg(long = "relay")]
    relay: bool,
    /// A relay this node may route through, `…/p2p/<peer-id>` (repeatable).
    /// Used automatically when a peer cannot be reached directly.
    #[arg(long = "relay-addr")]
    relay_addr: Vec<String>,
    /// Maximum simultaneous relayed circuits when running as a relay.
    #[arg(long = "relay-max-circuits")]
    relay_max_circuits: Option<usize>,
    /// Maximum simultaneous relay reservations when running as a relay.
    #[arg(long = "relay-max-reservations")]
    relay_max_reservations: Option<usize>,
    /// Unlock the keystore at startup from --passphrase-file, with no human
    /// present (for an always-on bootstrap/relay node).
    ///
    /// SECURITY TRADE-OFF: the passphrase then lives on this machine, so anyone
    /// who can read that file — root, a backup, a snapshot, a stolen disk — owns
    /// this identity. Use only on a dedicated node holding no personal
    /// conversations. Never the default; interactive `prism unlock` is unaffected.
    #[arg(long = "unattended")]
    unattended: bool,
    /// File holding the keystore passphrase for --unattended. Must be mode 0600
    /// and owned by the user running the daemon, or the daemon refuses to use it.
    #[arg(long = "passphrase-file")]
    passphrase_file: Option<PathBuf>,
    /// Disable NAT traversal (AutoNAT reachability detection, hole punching, and
    /// relay use). Leaves the node with direct connectivity only — it will not
    /// reach peers behind NAT, nor be reachable if it is itself behind one.
    #[arg(long = "no-nat-traversal")]
    no_nat_traversal: bool,
}

/// Default log filter when `RUST_LOG` is unset.
///
/// `info` matches the previous behaviour. The AutoNAT v2 **server** is pinned to
/// `error` because it warns once per inbound dial-request that cannot be
/// completed (`inbound request handle timed out`, a 10 s budget in
/// libp2p-autonat), and a dial-back to a NAT-bound client *cannot* complete —
/// clients re-probe every 5 s, so a public node serving NAT-bound peers logs that
/// warning forever. The behaviour is correct (AutoNAT is concluding "Private",
/// which is true); only the noise is a problem. Whether a node whose peers are
/// mostly NAT-bound should run the AutoNAT server at all is a separate question,
/// deliberately left for later.
const DEFAULT_LOG_FILTER: &str = "info,libp2p_autonat::v2::server=error";

fn main() -> Result<()> {
    // Honour RUST_LOG. Without this the daemon ignored it entirely (no
    // `EnvFilter` was installed), so an operator could not raise the log level to
    // diagnose anything — `RUST_LOG=debug` produced no extra output at all.
    //
    // When the operator has asked for detail, show event targets too: knowing a
    // line came from `libp2p_relay` rather than `prism_net` is most of its value
    // when debugging. The default output stays target-free, as before.
    let (filter, show_target) = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => (filter, true),
        Err(_) => (
            tracing_subscriber::EnvFilter::new(DEFAULT_LOG_FILTER),
            false,
        ),
    };
    tracing_subscriber::fmt()
        .with_target(show_target)
        .with_env_filter(filter)
        .try_init()
        .ok();

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
        relays: args.relay_addr,
        relay_server: if args.relay {
            let mut limits = prism_net::RelayLimits::default();
            if let Some(n) = args.relay_max_circuits {
                limits.max_circuits = n;
            }
            if let Some(n) = args.relay_max_reservations {
                limits.max_reservations = n;
            }
            Some(limits)
        } else {
            None
        },
    };

    // Unattended unlock (M5): read and validate the passphrase file *before*
    // binding the socket, so a misconfigured node fails fast and loudly rather
    // than coming up silently locked.
    let unattended = prism_daemon::unattended::UnattendedConfig {
        enabled: args.unattended,
        passphrase_file: args.passphrase_file,
    };
    let unattended_passphrase = unattended
        .load_passphrase()
        .context("unattended unlock configuration")?;

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

    // Auto-unlock before serving, so an always-on node publishes its locator and
    // can relay immediately after a restart. The passphrase is consumed here and
    // never held beyond it; it is never logged.
    if let Some(passphrase) = unattended_passphrase {
        if prism_daemon::server::unlock_with_passphrase(&state, passphrase).await {
            info!("unattended unlock succeeded (keystore passphrase read from file)");
        } else {
            warn!("unattended unlock failed: check the passphrase file contents");
        }
    }

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
