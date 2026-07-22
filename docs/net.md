# Prism networking — M2b (local networked messaging)

M2b makes two `prismd` instances on the **same LAN** discover each other and
exchange real end-to-end-encrypted messages. Discovery is mDNS only; delivery
is synchronous (both peers online); there is no DHT, no NAT traversal, no
relays, and no offline store-and-forward (all later milestones).

Crates: `prism-net` (libp2p transport, this document), `prism-daemon` (wiring),
`prism-proto` (IPC messages), `prism-cli` (`send` / `inbox` / `peers` /
`status`). The session cryptography is entirely `prism-core` (see
`docs/sessions.md`).

## Task architecture (the actor model)

The daemon runs the minimum number of owners, communicating over channels:

```
   prism (CLI) ──IPC──▶ IPC accept-loop ──┬── channel ──▶ core session thread
                                          │                (owns SessionManager;
                                          │                 synchronous, fsyncs)
                                          └── channel ──▶ swarm task
                                                          (owns the libp2p Swarm)
        swarm task ──InboundSink (non-blocking)──▶ core session thread
```

1. **Swarm task** (async) — the sole owner of the libp2p `Swarm`: mDNS
   discovery, the request/response protocol, the peer table. It never blocks
   its poll loop.
2. **IPC accept-loop** (async) — unchanged from M0; each connection handler
   translates a request into channel round-trips.
3. **Core session thread** (a dedicated OS thread) — the sole owner of the
   `SessionManager`. Session crypto is synchronous and fsyncs on every ratchet
   advance, so it runs off the async executor; one command channel serializes
   all access.

**No deadlock.** The outbound `send` is orchestrated by the async IPC handler:
it asks the core thread to encrypt (which persists), *then* asks the swarm to
transmit. The core thread never calls the swarm; the swarm never awaits the
core thread inline — inbound deliveries are handed off via a non-blocking sink
and answered later from a `FuturesUnordered` when the core verdict resolves. So
a slow disk write in the core thread cannot stall discovery or the IPC loop,
and there is no channel cycle.

## Persist-before-transmit (correctness, preserved over the network)

The Double Ratchet derives a unique key per message; emitting a ciphertext
whose advanced ratchet state was not yet saved would risk key reuse after a
crash. The ordering is therefore a hard barrier, enforced by the `send` flow:

```
core.deliver(peer, bundle?, body)   // encrypt + DURABLE fsync, returns sealed bytes
  ── then ──▶ net.deliver(peer, sealed)   // transmit only now
```

`prism-core`'s `SessionManager` owns this ordering (it persists inside
`encrypt`/`decrypt` before returning); the network layer only moves
already-sealed bytes. This is a required ordering, **not** a removable
synchronous round-trip, and it is deliberately *not* fire-and-forget. If the
transmit fails after persisting, the message key is simply spent (a harmless
chain gap) and nothing is queued — M2b is synchronous-only.

## Identity: PeerId ↔ Ed25519, and the two-layer check

The libp2p `PeerId` is derived from the **M1 Ed25519 identity key** (spec §6),
so it binds the transport identity to the application identity. Ed25519 keys
are small enough that libp2p inlines them into the `PeerId`, so a peer's raw
key is recovered from its (Noise-authenticated) `PeerId` for identity checks.

- **Outbound**: `send <nick#fingerprint>` resolves by matching the handle's
  fingerprint against discovered peers' keys. libp2p delivers only to the
  `PeerId` derived from that key, and Noise proves the remote holds its private
  half — so we transmit to exactly the intended identity or not at all.
- **Inbound**: the core thread checks that the **Noise-authenticated sender
  key equals the crypto-proven message identity** (`prism-core`'s binding
  envelope / session peer). A peer cannot deliver a message cryptographically
  bound to someone else; a mismatch is dropped and never reaches the inbox
  (unit-tested).

Every external key crossing the wire is validated with `prism-core`'s strict
ingestion checks (spec §5.3) before use — there is no unvalidated path.

## The single transport-key exception to "prism-net holds no keys"

`prism-net` performs **no application cryptography**: it never parses prekey
bundles, validates keys, runs the ratchet, or sees plaintext — all of that is
`prism-core`. The **one** unavoidable exception is the Noise static keypair:
running a libp2p Swarm requires it, and spec §6 mandates it be the *same*
Ed25519 key as the application identity (so the `PeerId` binds to the Prism
identity). The identity seed therefore crosses into `prism-net` in exactly one
place — `identity::keypair_from_seed` — copied into a `Zeroizing` buffer that
libp2p zeroizes in place while building the keypair, and wiped again on drop.
No seed or private key is retained.

This reuse of the identity key for Noise is a **deliberate, spec-mandated
consequence** of the identity↔PeerId binding requirement — not a
usage-separation oversight. Everywhere else Prism separates key usages via
HKDF domains (identity signing, the session-store vault key); this is the one
justified exception, and it is confined to a single function.

## Transport & wire protocol

- **Transport**: TCP + **Noise** + Yamux. (No QUIC in M2b — QUIC uses TLS, not
  Noise, and earns its place with NAT traversal in a later milestone.)
- **Discovery**: `libp2p-mdns` on the local network. A manual
  `add_peer_address` hint also exists (used by tests and a future
  designated-peer feature); it adds no automatic discovery mechanism.
- **Protocol** `/prism/msg/1.0.0`, negotiated by multistream-select *inside*
  the Noise channel (so it is authenticated against an external downgrade
  attacker). A CBOR request/response with explicit size bounds carries two
  message kinds, both with **opaque** payloads (`prism-core` bytes):
  - `GetBundle` → `Bundle` (the responder's signed prekey bundle);
  - `Deliver(sealed)` → `Ack` (a sealed message; acked only after the core
    thread decrypts, identity-verifies, and buffers it).
- First contact fetches the peer's bundle (to establish a session); subsequent
  messages skip it. A bundle with 20 one-time keys is served; exhaustion falls
  back to the reusable fallback key (`docs/sessions.md`).

## No plaintext on disk

Decrypted messages live only in the core thread's RAM inbox for the process's
lifetime; `inbox` drains it. Message history (on-disk) is a later milestone.
The ratchet store (`sessions.prs`) persists ratchet state only.

## MSRV

M2b raises the workspace MSRV to **1.88** (was 1.85 through M2). This is forced
by libp2p 0.56's transitive dependencies: `base45` (via `multiaddr` →
`multibase`) uses `slice_as_chunks`, stabilized in 1.88; `icu_*` (via `url` →
`idna`) require 1.86. Verified by the CI `msrv` job.

## Supply chain (documented risk-acceptances — PENDING RATIFICATION)

libp2p 0.56's `libp2p-mdns 0.48` hard-pins `hickory-proto 0.25.2`, for which
two advisories exist with **no in-semver fix** (upgrading needs an upstream
libp2p bump). They are ignored, with rationale, in `deny.toml` and
`.cargo/audit.toml`, and must be re-audited when libp2p bumps hickory:

- **RUSTSEC-2026-0118** (hickory NSEC3/DNSSEC unbounded loop) — assessed
  **unreachable**: `libp2p-mdns` pulls `hickory-proto` with
  `default-features = false, features = ["mdns"]`; the DNSSEC/NSEC3 resolver
  path is not compiled or exercised by mDNS.
- **RUSTSEC-2026-0119** (hickory O(n²) name compression on message *encoding*)
  — a CPU-only DoS, LAN-scoped (M2b is local mDNS, no global exposure),
  confined to the swarm task; no memory-safety or confidentiality impact.
- **RUSTSEC-2024-0436** (`paste` unmaintained) — a compile-time-only
  proc-macro with no runtime surface and no maintained drop-in replacement.

`ring` (via `snow`/`libp2p-noise`, license `Apache-2.0 AND ISC`) and all other
resolved crates are within the `deny.toml` license allow-list.
