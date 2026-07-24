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

## Known limitations — connection robustness (deferred to M4/M5)

M2b's networking is **synchronous and best-effort**: it delivers over whatever
connection currently exists, with no reconnection machinery. Several consequences
are known and **deliberately deferred** to the M4/M5 networking-robustness work —
they are *documented*, not fixed, in M3:

- **`connected` means "an open connection exists right now", not "reachable".**
  The swarm sets `idle_connection_timeout = 60 s`, so an idle connection closes
  and `connected` flips to `false` on **both** peers **even though both are alive
  and reachable**. Concretely: a peer you have not exchanged with for a minute
  will show as *not connected* (grey) in the TUI. **This is expected, not a
  bug** — the next message re-dials and reconnects. The UI therefore uses the
  neutral wording "connected / not connected" and never claims "reachable"
  (honest-communication rule: we do not assert reachability we cannot prove).
  Whether 60 s is the right idle timeout (vs a keep-alive) is an open M4/M5
  tuning question.

- **No reconnection / retry / address persistence.** Addresses are learned only
  from mDNS (`Discovered`) and dropped on `Expired`; a single send failure
  surfaces as "not reachable" with no retry. There is no redial-on-drop loop and
  no persisted address book.

- **A send is refused when the local address list for a peer is empty — even if a
  connection to that peer is already open.** `Deliver`/`FetchBundle` require a
  non-empty address list and do not fall back to reusing an existing (peer-
  initiated) connection. This produces an **asymmetry**: if A's addresses for B
  have expired but B still holds a route to A, B→A succeeds while A→B fails,
  despite an open connection between them. Healing this (reuse open connections,
  refresh/persist addresses, reconnect, retry) is genuine networking-robustness
  work and belongs to M4/M5 — it is **not** a display bug and is intentionally
  **not** patched in M3 (a partial fix would mask the symptom without addressing
  the cause). See the roadmap note at M4/M5.

None of this changes correctness or security — it is availability/UX robustness.
"Nothing is queued on a failed send" remains correct (store-and-forward is M6).

## MSRV

M2b raises the workspace MSRV to **1.88** (was 1.85 through M2). This is forced
by libp2p 0.56's transitive dependencies: `base45` (via `multiaddr` →
`multibase`) uses `slice_as_chunks`, stabilized in 1.88; `icu_*` (via `url` →
`idna`) require 1.86. Verified by the CI `msrv` job.

## Supply chain (documented risk-acceptances)

> The consolidated index of *all* deferred advisories (networking and beyond)
> lives in [`docs/security-debt.md`](security-debt.md); the networking ones are
> detailed below.

> **M4 gate — RESOLVED (investigated 2026-07-24).** The M2b acceptance of the
> two hickory advisories was scoped to a LAN-only perimeter, with a standing
> requirement to re-open them before M4's DHT exposes the node to the WAN. That
> re-investigation is done, **from the actual `libp2p-mdns 0.48` source**, and
> the conclusion is evidence-based (not a re-assumption): **neither advisory is
> reachable from the DHT or the WAN.** The ignores remain, with a corrected
> rationale and drop condition.

### Why the DHT does not widen the hickory surface (evidence)

`hickory-proto` enters the build through **exactly one** crate — `libp2p-mdns`
(`cargo tree -i hickory-proto`), pulled `default-features = false,
features = ["mdns"]`. Kademlia (`libp2p-kad`) speaks libp2p's own
protobuf-over-Noise protocol and has **no** hickory/DNS dependency, and we do
**not** enable libp2p's `dns` transport (no `hickory-resolver` in the tree), so
adding the DHT introduces no new path into hickory. A post-`kad` verification
gate (below) re-checks this once `kad` lands.

Within `libp2p-mdns 0.48`, hickory is touched in exactly two places:

- **Decode** — `MdnsPacket::new_from_bytes` → `Message::from_vec` (a `BinDecoder`),
  fed solely by `recv_socket`, a UDP socket that `join_multicast`es the mDNS
  group (224.0.0.251 / ff02::fb). This is the only hickory path reachable by
  inbound data — but it is **not** the vulnerable one: RUSTSEC-2026-0119 is an
  *encoding* (`BinEncoder`) bug, and RUSTSEC-2026-0118's NSEC3/DNSSEC code is
  not compiled (no `dnssec-*` feature). A hostile inbound packet triggers
  **neither** ignored advisory.
- **Encode** — `build_query` / `build_query_response` /
  `build_service_discovery_response` (`BinEncoder`, where -0119 lives). At
  `iface.rs:279` the response is built from **our own** data only
  (`this.local_peer_id`, `this.listen_addresses`, plus the query's 16-bit id).
  A remote query **cannot inject records** into what we encode, so the record
  count — the multiplier in the O(n²) name compression — is bounded by **our
  own listen-address count**, never by attacker input.

**Explicit conclusion:** a normal user running **mDNS + DHT** does **not**
expose RUSTSEC-2026-0119 to the WAN. The DHT never reaches hickory; the mDNS
encode path (where the bug is) processes only our own bounded records; the mDNS
decode path (reachable by inbound packets) triggers neither ignored advisory.
We are genuinely covered with no per-user action.

Two honest caveats, and the mitigation for exposed nodes:

- The mDNS UDP socket binds `0.0.0.0:5353`, so besides link-local multicast it
  can also receive **unicast** to the host at :5353 — including from the WAN if
  UDP/5353 is open (unfirewalled) on a public IP. That reaches only the
  **decoder** (neither ignored advisory), but it would expose hickory's DNS
  parser to arbitrary internet input — relevant to any *future* hickory decode
  bug.
- Therefore **bootstrap / public-IP / headless nodes run with `--no-mdns`**
  (M4): the mDNS socket is not opened at all, so hickory is never invoked on
  those (WAN-exposed) nodes. A home client behind NAT keeps mDNS for LAN
  discovery; its :5353 is not WAN-reachable and its -0119 exposure is nil
  regardless (the encode is self-bounded).

The three ignored networking advisories, then:

- **RUSTSEC-2026-0118** (hickory NSEC3/DNSSEC unbounded loop) — **not compiled**:
  reachable only with the `dnssec-ring`/`dnssec-aws-lc-rs` feature (the
  advisory's own condition); `libp2p-mdns` builds hickory with
  `features = ["mdns"]` only. Unaffected from hickory ≥ 0.26.0-beta.1.
- **RUSTSEC-2026-0119** (hickory O(n²) name compression on message *encoding*) —
  CPU-only DoS; the encode path processes only our own records (above), so it is
  not reachable by DHT / WAN / on-LAN attacker input. Fixed in hickory 0.26.1.
- **RUSTSEC-2024-0436** (`paste` unmaintained) — compile-time-only proc-macro,
  no runtime surface, no maintained drop-in replacement.

**Drop condition (both hickory advisories):** when `libp2p-mdns` adopts
`hickory-proto ≥ 0.26.1`. This is a breaking 0.25 → 0.26 bump that only an
upstream libp2p release can make — not consumable via `[patch]` without breaking
`libp2p-mdns`'s own compile — so it does not gate M4.

**Post-`kad` verification gate (run when kad lands):** confirm `cargo tree -i
hickory-proto` still shows the sole path is `libp2p-mdns`, and that `cargo audit`
+ `cargo deny check advisories` stay green with the ignore set unchanged.

`ring` (via `snow`/`libp2p-noise`, license `Apache-2.0 AND ISC`) and all other
resolved crates are within the `deny.toml` license allow-list.
