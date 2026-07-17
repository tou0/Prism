# Prism

**Prism** is an end-to-end encrypted, peer-to-peer messenger — CLI/TUI,
decentralized, with no central server. It is written in Rust.

Privacy is structural, not an option: two people exchange directly, their
messages end-to-end encrypted, over a network the users run themselves. Prism
does **not** promise "100% secure" or "untraceable" — it maximizes protection
and communicates its limits honestly. See [`docs/specification.md`](docs/specification.md)
for the full design.

> **Status: milestone M2 (Encrypted sessions — crypto core).** On top of the
> M1 identities (Ed25519 `nick#fingerprint` handles, sealed Argon2id +
> ChaCha20-Poly1305 keystore, opt-in BIP-39 recovery), Prism now has complete
> encrypted 1:1 sessions: Olm 3DH establishment + Double Ratchet via the
> audited `vodozemac`, identity-signed prekey bundles, strict public-key
> validation on ingestion, and a sealed ratchet-state store with a
> persist-before-transmit crash-safety contract (`docs/sessions.md`).
> Sessions are exercised **locally** (see
> `cargo run -p prism-core --example local_chat`) — **there is no networking
> yet**; mDNS discovery and `send`/`inbox` arrive with M2b.

## Workspace layout

| Crate | Role |
|---|---|
| `prism-core` | Core types, identity, encrypted sessions (vodozemac), keystore, ratchet store (no network/UI deps). |
| `prism-proto` | IPC message types and the framed serde codec. |
| `prism-net` | libp2p networking layer (placeholder until M2b). |
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
cargo run --bin prism -- ping     # liveness check -> pong
cargo run --bin prism -- init     # create an identity (interactive)
cargo run --bin prism -- whoami   # show the unlocked identity
cargo run --bin prism -- unlock   # unlock after a daemon restart
cargo run --bin prism -- restore  # recreate an identity from a recovery phrase
```

`init` asks for a nickname, a passphrase, and whether to generate an optional
12-word recovery phrase (shown once, never stored — anyone who reads it owns
your identity; without it, a lost passphrase means a lost identity, which is
the point). `init`/`restore` refuse to overwrite an existing keystore unless
`--force` is given.

Both binaries accept `--socket <PATH>`; the daemon also accepts
`--keystore <PATH>`.

## License

Licensed under the **GNU Affero General Public License v3.0 or later**
(AGPL-3.0-or-later). See [`LICENSE`](LICENSE).
