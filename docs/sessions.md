# Prism sessions — M2 crypto core (Olm 3DH + Double Ratchet)

M2 delivers complete encrypted 1:1 sessions, exercised locally (no network):
establishment against a signed prekey bundle, bidirectional messaging with
forward secrecy and post-compromise recovery via vodozemac's Double Ratchet,
and ratchet-state persistence in a sealed store. Implementation:
`crates/prism-core/src/{session,bundle,session_store,validate}.rs`; a runnable
demo lives in `examples/local_chat.rs`.

## Honest terminology: Olm 3DH, not X3DH

vodozemac implements **Olm**, whose establishment is a **triple
Diffie-Hellman**: `DH(IK_A, K_B) ‖ DH(E_A, IK_B) ‖ DH(E_A, K_B)`, where `K_B`
is one of Bob's one-time keys (or his fallback key). There is **no signed
prekey inside the DH computation**, unlike Signal's X3DH. Prism compensates at
the authentication layer:

- **one Ed25519 identity signature covers the entire published bundle** —
  every key a peer publishes is identity-signed (stronger than Matrix, which
  signs keys individually);
- the reusable **fallback key plays the signed-prekey role operationally**
  (the always-available establishment key once one-time keys run out);
- the **initiator proves its identity inside the encrypted channel** (binding
  envelope, below).

Session configuration: `SessionConfig::version_1` — the audited, production
Olm configuration. vodozemac 0.10 gates `version_2` (whose only difference is
an untruncated MAC) behind the `experimental-session-config` cargo feature;
an experimental flag of the crypto library has no place here. The wire
envelope, the store format, and per-session configs are all versioned, so
adopting v2 when it stabilizes is a compatible evolution.

## Identity anchoring (the M1 key stays the only root)

The vodozemac account has an internal Ed25519 key: it is **never published
and never trusted**. Only the account's Curve25519 identity key is used, and
it is subordinated to the M1 identity in both directions:

**Outbound.** `establish_outbound(expected, bundle, …)` verifies the bundle
under the identity the caller already expects (from the contact's handle,
out of band). The embedded identity key is self-description for directories —
there is deliberately **no trust-the-embedded-key path**. Checks, in order:
shape → embedded-key validation → identity match (`WrongIdentity`) →
`verify_strict` signature (`BadSignature`) → strict validation of every
curve key. A validly-signed bundle carrying a hostile key still fails.

**Inbound.** Olm pre-key messages carry only Curve25519 keys, so every
pre-reply plaintext carries a **binding envelope**: `sender_ed25519[32] ‖
sig[64]`, where the signature (domain `"prism v1 session identity binding"`)
covers `sender_ed ‖ sender_curve ‖ recipient_ed ‖ recipient_curve`. The
responder checks that `sender_curve` equals the key that actually ran the
3DH and verifies with `verify_strict`. Signing both parties' identity and
curve keys is full channel binding: a binding minted for one channel cannot
be spliced onto another (unknown-key-share defense — covered by
crafted-attacker tests). A first message without a valid binding never
creates a session.

**Responder authenticity** needs no reverse binding: only the holder of the
private keys behind the bundle Alice verified can complete the 3DH, and that
bundle was signed by Bob's identity.

## Prekey bundle (canonical, identity-signed)

```text
signed payload                          wire bundle = payload ‖ sig[64]
  0        version        u8 = 1
  1..33    ik_ed25519     [32]  M1 identity key (self-description)
  33..65   ik_curve25519  [32]  vodozemac account identity key
  65..97   fallback_key   [32]  reusable last resort ("signed prekey" role)
  97..99   otk_count      u16 BE (parse cap 64)
  99..     otk_i          [32] × count, strictly ascending bytewise
```

Hand-rolled fixed layout because **signed bytes must be deterministic**
(protobuf is not canonical); M4 can wrap this in prost without re-signing
ambiguity. The ascending-order rule makes encodings canonical and rejects
duplicates; exact-length checks reject truncation and trailing bytes. Default
**20 one-time keys** (~803-byte bundle — DHT-friendly for M4). Signature
domain: `"prism v1 prekey bundle"`, via the domain-framed signing API
(`blake3(domain) ‖ message`, `verify_strict` only).

**One-time-key lifecycle.** `publish_bundle(n)` generates the fallback key
(once) and `n` fresh one-time keys, signs, marks published, persists, and
re-serves the bundle from the store. Inbound establishment consumes the
private one-time key — a replayed first message fails (`OneTimeKeyMissing`),
as does a second sender racing for the same key (tested). A bundle with zero
one-time keys still establishes via the fallback key (exhaustion path).
Because the signature covers the whole set, M2 hands out **full bundles**;
per-key claiming (and per-key signatures) is an M4 directory concern.

## Wire formats (every message carries a version)

```text
wire message   = version u8 (=1) ‖ kind u8 (0 prekey, 1 normal)
                 ‖ sid_len u8 ‖ session id ‖ olm bytes          (cap 128 KiB)
plaintext body = version u8 (=1) ‖ flags u8 (bit0 = binding)
                 ‖ [binding 96] ‖ payload                       (payload cap 64 KiB)
```

Olm normal messages carry no session id of their own, so the envelope routes
them; for pre-key messages the envelope id is cross-checked against the
message's own. All bounds are checked before allocation; unknown versions,
kinds, and flags are typed errors. (Authenticated *network* version
negotiation is an M2b+ concern, per the milestone scope.)

## Strict key validation on ingestion (spec §5.3)

`prism_core::validate` runs **before any library call**, at every boundary:

| Boundary | Keys validated |
|---|---|
| bundle parse | embedded Ed25519, curve identity, fallback, every one-time key |
| pre-key message | curve identity, ephemeral base, referenced one-time key |
| normal message | ratchet key |
| binding envelope | claimed Ed25519 identity |

X25519: reject non-canonical encodings (bit 255 set, u ≥ p), then the
canonical small-order blocklist (libsodium's list: 0, 1, the two 8-torsion
generators, p−1) — the zero-point / low-order / invalid-curve class. For
Montgomery-u, every canonical u is on the curve or its DH-safe twist, so
"off-curve" concretely means the non-canonical encodings. Ed25519: dalek
parse (off-curve), round-trip canonicality, `is_weak()`; signatures only via
`verify_strict`. Every blocklist entry is a test vector.

**Defense-in-depth split**: vodozemac itself checks contributory behavior on
*every* DH (3DH and each ratchet advance). Our layer rejects hostile keys
before they reach the library; vodozemac's checks back-stop the one key its
API does not expose pre-use (the initial ratchet key inside a pre-key
message).

## Ratchet-state persistence: `sessions.prs` (PRISMRS v1)

```text
header (20 B, all AEAD AAD): "PRISMRS" [7] ‖ version 0x01 ‖ nonce [12]
body: ChaCha20-Poly1305(vault_key, nonce, payload) ‖ tag[16]
payload: account pickle ‖ session records (id, peer identity, role,
         pre-reply binding, session pickle) ‖ published-bundle bookkeeping
```

**Why a second file.** The ratchet advances on every message; the keystore's
Argon2id-per-write discipline (~330 ms + 64 MiB) is three orders of magnitude
too slow for that, and putting the identity seed file on the hot rewrite path
maximizes blast radius. The store instead uses a **vault key**:

```text
vault_key = HKDF-SHA512(ikm = identity seed, salt = none,
                        info = "prism v1 session-store key")
```

derived once in RAM at unlock — keystore v1 stays frozen, nothing new rests
on disk, and a store written by a different identity fails (`AuthFailed`)
instead of being adopted. Restore-on-new-device (same seed, no file) starts
with fresh sessions, the correct semantics. HKDF domain separation makes the
vault key computationally independent of the Ed25519 signing scalar.

**Honest residual**: a holder of the **recovery phrase alone** (no
passphrase) can derive the seed and therefore the vault key — `sessions.prs`
is protected exactly to the extent the seed is (the attacker still needs the
file). Accepted for M2; a random vault key inside a keystore-v2 payload would
remove this at the cost of a format bump — deferred.

Writes are atomic (temp `0600` → fsync → rename → fsync dir, in a `0700`
directory) via the same helpers as the keystore; reads are bounded
(64 MiB cap). Same key + fresh random 96-bit nonce per write is the standard
AEAD model (collision bound ≈ 2⁻³⁷ after 2³⁰ writes).

**Persist-before-transmit (correctness, not preference).** Every mutating
operation persists the advanced state **before** its output escapes:

- a crash right after `encrypt` returns cannot reuse a message key — the
  advance was durable before the ciphertext existed outside the call
  (tested, including a negative control demonstrating the chain-index
  collision stale state would produce);
- a crash right after `decrypt` returns cannot reopen the replay window —
  the consumed receiving key was durable before the plaintext escaped
  (tested across restart);
- if persisting fails, the output is withheld and the message key burns
  unused — a harmless skipped index, never a reuse. A withheld *inbound*
  message is recoverable only by sender retry (M6's ACK/resend).

**No plaintext on disk.** The store persists ratchet state only; decrypted
message content cannot structurally reach `StorePayload`, and a test scans
every file under the test root for plaintext canaries after a full
conversation. Message history is a later milestone.

## Memory & storage hygiene (honest notes)

- Serialization of pickles goes into a **pre-sized `Zeroizing` buffer** whose
  capacity hint is tracked across writes, so growth-reallocation (which
  strews un-wiped fragments — the M1 `expose_phrase` bug class) is rare
  rather than per-write. **Residuals**: serde's internal scratch during
  (de)serialization, and the rare write that outgrows the hint. vodozemac's
  pickle types zeroize their key material on drop.
- **"Wipe superseded state on rewrite" is not portably achievable at the
  block level**: an atomic rename frees the old inode's blocks without
  wiping, and journaling filesystems / SSD wear-leveling keep ghosts
  regardless. What Prism does: atomic replacement, best-effort cleanup of
  failed temp files, rigorous in-RAM zeroization — and superseded state on
  disk remains ciphertext under the vault key. Residual risk: disk forensics
  plus captured old ciphertexts could decrypt messages the ratchet has since
  passed. The honest answer, as with the M1 swap note, is **full-disk
  encryption**.
- `mlock` remains deferred to M8 (zero-unsafe policy).

## Forward notes (deliberately not built in M2)

- **M2b**: mDNS discovery, `send`/`inbox`, protobuf wire wrapping,
  authenticated network version negotiation; the daemon will own a
  `SessionManager` next to the unlocked identity and run store writes off
  the async executor.
- **M4**: a claiming directory for one-time keys (atomic hand-out), per-key
  signatures if bundles are served in slices, fallback-key rotation policy,
  bundle TTLs.
- **M7**: rate/section caps on inbound session creation (anti-spam PoW).
- vodozemac `version_2` sessions once no longer experimental.
