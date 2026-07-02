# Prism

**Prism** is an end-to-end encrypted, peer-to-peer messenger — CLI/TUI,
decentralized, with no central server. It is written in Rust.

Privacy is structural, not an option: two people exchange directly, their
messages end-to-end encrypted, over a network the users run themselves. Prism
does **not** promise "100% secure" or "untraceable" — it maximizes protection
and communicates its limits honestly. See [`docs/specification.md`](docs/specification.md)
for the full design.

> **Status: milestone M0 (Foundations).** This is a compiling, testable
> skeleton: a five-crate workspace, a securely permissioned IPC socket, and an
> end-to-end `ping`/`pong` between the client and the daemon. **There is no real
> cryptography or networking yet** — those arrive in later milestones.

## Workspace layout

| Crate | Role |
|---|---|
| `prism-core` | Core types, identity, cryptography, keystore (no network/UI deps). |
| `prism-proto` | IPC message types and the framed serde codec. |
| `prism-net` | libp2p networking layer (placeholder until M2). |
| `prism-daemon` | Background daemon `prismd`: holds keys, runs the network, exposes the IPC socket. |
| `prism-cli` | Thin client `prism`: talks to the daemon over IPC. |

The daemon holds the secrets; the client never holds a private key in plaintext.

## Build & test

Requires a recent stable Rust toolchain (see `rust-toolchain.toml`).

```sh
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Run: `ping` the daemon

The daemon listens on a Unix socket in the per-user runtime directory
(`$XDG_RUNTIME_DIR/prism/prismd.sock`), created inside a `0700` directory with
`0600` permissions and guarded by a peer-credential (UID) check.

In one terminal, start the daemon:

```sh
cargo run --bin prismd
```

In another, ping it:

```sh
cargo run --bin prism -- ping
# -> pong
```

Both binaries accept `--socket <PATH>` to override the socket location (useful
for running several instances or for scripting).

## License

Licensed under the **GNU Affero General Public License v3.0 or later**
(AGPL-3.0-or-later). See [`LICENSE`](LICENSE).
