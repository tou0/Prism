# Prism

**Prism** is an end-to-end encrypted, peer-to-peer messenger — CLI/TUI,
decentralized, with no central server. It is written in Rust.

Privacy is structural, not an option: two people exchange directly, their
messages end-to-end encrypted, over a network the users run themselves. Prism
does **not** promise "100% secure" or "untraceable" — it maximizes protection
and communicates its limits honestly. See [`docs/specification.md`](docs/specification.md)
for the full design.

> **Status: milestone M5 (NAT traversal & relays) — in progress.** Two users
> **both behind NAT** can now talk. A node detects its own reachability
> (AutoNAT), punches through NATs for a **direct** connection when it can
> (DCUtR, over QUIC as well as TCP), and falls back **automatically** to a
> **Circuit Relay v2** relay when it cannot — the user just experiences "it
> connects", and `peers`/`status` always show which path was used. Running a
> relay is **opt-in and capped** (`--relay`), and a relay **cannot read**
> anything it carries. **Honest limits:** a relay does see who-talks-to-whom in
> real time (it keeps no record); one relay is not anonymity; traffic
> correlation remains possible; network-level anonymity needs Tor (M5b). An
> always-on node can unlock itself from a passphrase file (`--unattended`) — a
> documented at-rest trade-off, never the default. See
> [`docs/net.md`](docs/net.md).
>
> **Previously: milestone M4 (DHT discovery).** Nodes now find each other **off the
> LAN** through a libp2p **Kademlia DHT**, coexisting with mDNS. A node publishes
> a **signed locator record** (its identity key + globally-routable addresses,
> Ed25519-signed) keyed by fingerprint; another node resolves it by fingerprint
> — `prism resolve <handle>`, and automatically as a fallback in `send`. A DHT is
> joined via `--bootstrap` entry points (**no bootstrap nodes are hard-coded**;
> the manual path stands alone). **Honest posture:** joining the public DHT
> exposes your IP to DHT peers — P2P removes the central server, it does **not**
> anonymize you (Tor is a later milestone); only globally-routable addresses are
> published, and `status` shows exactly what. **After M4, two nodes may
> _discover_ each other yet not always _connect_** — NAT traversal / relays are
> M5. The M3 `prism chat` TUI (arrow-first, real-time push) and M2b LAN messaging
> are unchanged. Still **no NAT traversal, relays, offline delivery, or message
> history** — those are later milestones.

## Workspace layout

| Crate | Role |
|---|---|
| `prism-core` | Core types, identity, encrypted sessions (vodozemac), keystore, ratchet store (no network/UI deps). |
| `prism-proto` | IPC message types and the framed serde codec. |
| `prism-net` | libp2p networking layer: mDNS + Kademlia DHT discovery, Noise request/response (opaque bytes only; no application crypto — it validates locator *shape*, and delegates signature/key checks to `prism-core`). |
| `prism-daemon` | Background daemon `prismd`: holds keys, runs the network, exposes the IPC socket. |
| `prism-cli` | Thin client `prism`: one-shot commands and the interactive TUI (`chat`), over IPC. |

The daemon holds the secrets; the client never holds a private key in plaintext.

## Build & test

Requires a recent stable Rust toolchain (see `rust-toolchain.toml`).

```sh
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Run

The daemon listens on a Unix socket in the per-user runtime directory
(`$XDG_RUNTIME_DIR/prism/prismd.sock`), created inside a `0700` directory with
`0600` permissions and guarded by a peer-credential (UID) check. The encrypted
keystore lives in the per-user data directory
(`~/.local/share/prism/keystore.pks`; format: `docs/keystore.md`).

In one terminal, start the daemon (it must be running for every command,
including `init` — keys are generated daemon-side):

```sh
cargo run --bin prismd
```

In another:

```sh
cargo run --bin prism -- ping             # liveness check -> pong
cargo run --bin prism -- init             # create an identity (interactive)
cargo run --bin prism -- whoami           # show the unlocked identity
cargo run --bin prism -- unlock           # unlock after a daemon restart
cargo run --bin prism -- restore          # recreate an identity from a recovery phrase
cargo run --bin prism -- status           # network + identity status (incl. DHT)
cargo run --bin prism -- peers            # discovered peers (mDNS / DHT / manual)
cargo run --bin prism -- resolve <handle> # find a peer off-LAN via the DHT
cargo run --bin prism -- send <handle> "hi"  # send an encrypted message
cargo run --bin prism -- inbox            # show and drain received messages
cargo run --bin prism -- chat             # interactive TUI (also the default: bare `prism`)
```

`init` asks for a nickname, a passphrase, and whether to generate an optional
12-word recovery phrase (shown once, never stored — anyone who reads it owns
your identity; without it, a lost passphrase means a lost identity, which is
the point). `init`/`restore` refuse to overwrite an existing keystore unless
`--force` is given.

To message on a LAN: run two unlocked daemons on the same network; each sees the
other under `peers`, then `send <nick#fingerprint> "..."` delivers an
end-to-end-encrypted message that appears in the recipient's `inbox`. Both peers
must be online — delivery is synchronous and nothing is queued (offline delivery
is a later milestone).

To discover **off-LAN** via the DHT, point nodes at one or more bootstrap entry
points (no bootstrap nodes are baked in):

```sh
# A public entry point (a VPS with a routable IP): DHT server, no LAN peers.
cargo run --bin prismd -- --listen /ip4/0.0.0.0/tcp/4001 \
  --external-address /ip4/<PUBLIC_IP>/tcp/4001 --no-mdns

# Another node joins by bootstrapping to it, then resolves a handle:
cargo run --bin prismd -- --bootstrap /ip4/<PUBLIC_IP>/tcp/4001/p2p/<PEER_ID>
cargo run --bin prism  -- resolve <nick#fingerprint>
```

`resolve` finds and validates the peer's signed locator and prints the addresses
it publishes (or says plainly when it advertises none — discoverable but not yet
directly connectable, since NAT traversal is M5). Bootstrap addresses are **IP
multiaddrs only** (no `/dns/`).

Two things a bootstrap node needs: its **public address advertised**
(`--external-address`, else it never stores others' records) and an **unlocked
keystore** (the identity is held in RAM only after `prism unlock`, so a locked
node publishes nothing and joins no DHT). See [`docs/net.md`](docs/net.md) for
the locator format, IP-hygiene rules, running a bootstrap node, and the honest
IP posture.

Or just run `prism chat` (or bare `prism`) for the interactive TUI: pick a peer
from the discovered list, open a conversation, and type — incoming messages
appear in real time. It is keyboard-first (arrow keys, `Enter`, `Tab`, `i` to
write, `?` for help, `q` to quit) with mouse as a complement, and it keeps your
terminal's own background (transparent/light/dark all work). Messages live in
memory only and are gone when you quit.

Both binaries accept `--socket <PATH>`; the daemon also accepts
`--keystore <PATH>`, `--sessions <PATH>`, `--listen <MULTIADDR>`, and the M4 DHT
flags `--bootstrap <MULTIADDR/p2p/ID>` (repeatable), `--external-address
<MULTIADDR>` (repeatable), `--no-mdns`, and `--no-dht`.

## License

Licensed under the **GNU Affero General Public License v3.0 or later**
(AGPL-3.0-or-later). See [`LICENSE`](LICENSE).
