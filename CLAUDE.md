# CLAUDE.md — Prism

## Project
Prism: an **end-to-end encrypted P2P messenger**, CLI/TUI, **decentralized, no central server**. Written in Rust.
Ethos: privacy by design, a user-run network, **no authority over the network**, honest security communication (never claim "100% secure" or "untraceable").
**Full specification: `docs/specification.md` — read it before any architecture decision.**

## Language
- **All repository artifacts are in English**: code, identifiers, comments, doc-comments, commit messages, README, and in-repo documentation. This is an open project for international contributors.
- User-facing strings are in English for now; keep them isolated (a single module) so i18n can be added later.
- (Design discussions with the maintainer may happen in French, but nothing French lands in the repo.)

## License
- **AGPL-3.0-or-later.** Add `// SPDX-License-Identifier: AGPL-3.0-or-later` at the top of every source file, and set `license = "AGPL-3.0-or-later"` in each crate's `Cargo.toml`. A `LICENSE` file with the full AGPL-3.0 text lives at the repo root.

## Absolute rules (NEVER violate)
- **Never roll your own crypto.** Protocol = `vodozemac` (Olm/Megolm). Primitives = RustCrypto / `*-dalek`. No manual implementation of X3DH, the ratchet, AEAD, or KDF.
- **Validate every external public key on ingestion**: reject the zero point, low-order points, off-curve points. Never use a received key without validating it.
- **Secrets**: wrapped types (`Zeroizing` / `secrecy`), **no derived `Clone` / `Debug` / `Display`** on them, fixed-size pre-allocated buffers, `mlock`, minimize holding them across `.await` points.
- **PoW / Argon2 never on the async executor thread**: use `spawn_blocking` or a dedicated pool.
- **IPC socket**: `0600` permissions inside a `0700` directory, `SO_PEERCRED` (caller UID) check, named-pipe ACL on Windows.
- **No `unwrap()` / `expect()` / `panic!`** on any production path. Explicit errors (`thiserror` in libraries, `anyhow` in binaries).
- **Never log** secrets, keys, passphrases, or sensitive content/metadata.
- **Everything coming from the network is hostile**: parse defensively, no implicit trust.
- **Every message carries a version**; version negotiation is **authenticated** (anti-downgrade).
- **Build only the current milestone** (see below). Do not code out-of-scope features.

## Mandated stack (do not deviate without approval)
- Rust (edition 2021+), async **`tokio`**.
- Network: **`rust-libp2p`** (Noise, QUIC/TCP, Kademlia, mDNS, Rendezvous, Gossipsub, Circuit Relay v2, DCUtR, AutoNAT). Optional Tor transport via **`arti-client`** (Arti).
- Crypto: **`vodozemac`**; `ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `hkdf`, `argon2`; `blake3`; `zeroize` / `secrecy`.
- TUI: **`ratatui`** + **`crossterm`**. CLI: `clap`.
- IPC: Unix socket / named pipe, `serde`. Wire format: **`prost`** (protobuf).
- Storage: `rusqlite` (encrypted) + atomic writes. Paths: `directories`.
- Errors / logging: `thiserror`, `anyhow`, `tracing` (never secrets).

## Architecture
Cargo workspace, separate crates:
- **`prism-core`**: types, identity, crypto (wraps `vodozemac`), keystore. No network/UI dependencies.
- **`prism-proto`**: protobuf schemas + (de)serialization of network and IPC messages.
- **`prism-net`**: libp2p layer (transport, discovery, sessions).
- **`prism-daemon`**: background process — holds keys in RAM, runs the network, exposes the IPC.
- **`prism-cli`**: thin client (one-shot + TUI) talking to the daemon over IPC.

The **daemon holds the secrets**; the **client never holds a private key in plaintext**.

## Roadmap (milestones)
- **M0 — Foundations** <- *CURRENT*: workspace, crates, CI (fmt / clippy `-D warnings` / audit / deny), error handling, daemon+client skeleton, **secure** IPC socket, end-to-end `ping` command. **No real crypto or networking.**
- **M1** — Identity & keystore (Ed25519/X25519 keys, handle `nick#fingerprint` base58 ~14 chars, Argon2id + ChaCha20-Poly1305, atomic writes, `init` / `unlock`).
- **M2** — Local 1:1 encryption (mDNS + `vodozemac`, `send` / `inbox`, protobuf, key validation, version negotiation).
- **M3** — TUI (`ratatui`, `chat`).
- **M4** — DHT & discovery (Kademlia + prekeys + S/Kademlia hardening).
- **M5** — NAT & relays (DCUtR / AutoNAT / Relay v2, capped opt-in relaying).
- **M5b (v1.x)** — Optional Tor transport via **Arti** (`arti-client`): opt-in onion transport; solves symmetric-NAT reachability and hides IPs. (Verify onion-service hosting maturity.)
- **M6** — Offline (store-and-forward, ACK / resend, TTL, redundancy).
- **M7** — Anti-spam (memory-hard PoW, difficulty by local history).
- **M8** — Hardening (kill switch, ephemeral messages, fuzzing, audit prep).

## Out of scope (DO NOT build now)
Groups, channels, whisper, roles; DHT / relays / offline before their milestone; anti-spam PoW (M7); onion routing / metadata privacy; advanced anti-coercion (plausible deniability, dead-man's switch); identity-key succession; post-quantum. **Do not anticipate these.**

## Conventions
- `cargo fmt` + `cargo clippy -- -D warnings` **must pass**.
- Tests next to the code; **test vectors** for all crypto; `cargo test` green before a milestone is considered done.
- `cargo audit` + `cargo deny` in CI.
- Small, atomic commits with clear messages.
- **Ask before** any destructive action or any dependency outside the stack above.
- Propose a file plan **before** coding a milestone, then wait for approval.
