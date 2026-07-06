# Prism keystore — on-disk format (v1)

The keystore is a single encrypted file holding the user's identity at rest:
the 32-byte Ed25519 identity seed and the chosen nickname. It is created by
`prism init`, decrypted by `prism unlock`, and only ever handled by the daemon
(the client never sees a plaintext private key).

Default location: `~/.local/share/prism/keystore.pks` (per-platform via
`directories`), file `0600` inside a `0700` directory. Implementation:
`crates/prism-core/src/keystore.rs`.

## File layout

```text
┌─ Header (45 bytes, plaintext, authenticated as AEAD associated data) ─┐
│ off len                                                               │
│ 0   7   magic  = "PRISMKS"                                            │
│ 7   1   format version = 0x01                                         │
│ 8   4   Argon2id m_cost, KiB (u32 BE)                                 │
│ 12  4   Argon2id t_cost      (u32 BE)                                 │
│ 16  1   Argon2id p_cost      (u8)                                     │
│ 17  16  Argon2id salt   (OS CSPRNG, fresh on every write)             │
│ 33  12  AEAD nonce      (OS CSPRNG, fresh on every write)             │
├─ Body ────────────────────────────────────────────────────────────────┤
│ 45  ..  ChaCha20-Poly1305 ciphertext (payload ‖ 16-byte Poly1305 tag) │
└───────────────────────────────────────────────────────────────────────┘

plaintext payload = seed (32 bytes) ‖ nick_len (u16 BE) ‖ nick (UTF-8, 1–128 bytes)
```

Key derivation: `AEAD key (32 bytes) = Argon2id(passphrase, salt, m, t, p)`
with the parameters taken from the header. The **entire 45-byte header is the
AEAD associated data**, so any tampering — version byte, KDF parameters, salt,
nonce — fails the Poly1305 tag. A wrong passphrase and a corrupted file are
deliberately indistinguishable (`AuthFailed`); the error message says so
honestly.

## KDF parameters live in the header (crypto agility)

The Argon2id parameters are **stored per file**, not hard-coded (spec §14.1:
crypto agility). Raising the default difficulty later requires **no format
version bump and no migration**: old keystores keep opening with their own
recorded parameters, new writes (including any re-seal) embed the new
defaults. The parameters are identical for every user and both recovery
modes, so they leak nothing (see indistinguishability below).

**Defensive bounds.** The parameters steer the KDF itself, so the AEAD tag can
only vouch for them *after* the KDF has run. To keep a forged header from
demanding absurd work (a memory/CPU DoS), they are bounds-checked **before**
the KDF, and rejected with `KdfParamsOutOfRange`:

| Parameter | Accepted on open | Default written (v1) |
|---|---|---|
| `m_cost` | ≤ 512 MiB (`ARGON2_MAX_M_COST_KIB`) | 65536 KiB (64 MiB) |
| `t_cost` | 1..=16 (`ARGON2_MAX_T_COST`) | 8 |
| `p_cost` | 1..=8 (`ARGON2_MAX_P_COST`) | 1 |

Worst case a hostile file can demand is therefore bounded (~512 MiB, 16
passes) — a forged header cannot OOM-kill the daemon — and the tag check right
after exposes the forgery. The ceilings still leave 8×/2× headroom over the
defaults for a future difficulty raise; because parameters are header-carried,
raising them needs no format bump. These are open-time validation bounds only:
the on-disk v1 format is unchanged.

## Calibration of the defaults (measured 2026-07-06)

Target from the specification (§5.2): **~0.5–1 s on a modest machine**. The
reference machine used for calibration is a *fast* laptop (AMD Ryzen 7 PRO
5850U, 8c/16t), roughly **3–5× faster than the modest hardware the target is
written for** — so the defaults were tuned to land at **~250–400 ms on the
reference machine**, extrapolating to roughly 1–2 s on modest hardware.

Measured single-derivation times, `argon2 0.5.3`, release build, m = 64 MiB,
p = 1 (average of 5, then median of 9 for the finalists):

| t_cost | time (reference machine) |
|---|---|
| 3 | ~145 ms |
| 5 | ~220 ms |
| 6 | ~255 ms |
| 7 | ~295 ms |
| **8** | **~330 ms ← chosen** |
| 9–12 | 290–360 ms (thermal-throttle noise) |

`t = 8` sits mid-target with stable measurements; memory stays at 64 MiB —
already the dominant brute-force cost, and safe on low-RAM machines. Passes
beyond ~10 bought no reliable extra wall-time on this CPU (frequency scaling),
which is itself a hint that raising `m` — not `t` — is the right lever for a
future difficulty bump. Thanks to the header-carried parameters, that bump
needs no migration.

## Recovery chain (opt-in, spec §4.2)

```text
12-word BIP-39 mnemonic (128-bit entropy, English wordlist)
  --BIP-39 seed derivation (empty passphrase)--> 64-byte seed
  --HKDF-SHA512(salt = none, info = "prism v1 identity ed25519")--> 32-byte identity seed
```

Deterministic: the phrase alone regenerates the identity on any device. The
golden test vector is frozen in `crates/prism-core/tests/kat_vectors.rs`.

## Recovery-mode indistinguishability

By default there is **no recovery phrase** (nothing to reveal under coercion);
the phrase is an explicit opt-in. The keystore must not betray which mode was
chosen:

- The payload is exactly `seed ‖ nick` in both modes — the seed is either
  CSPRNG-drawn or recovery-derived, and 32 uniform bytes either way. The
  mnemonic itself is **never stored**.
- `KeystoreContents` has no mode field, so the distinction cannot even be
  expressed at the type level.
- The KDF parameters are the same defaults in both modes; salt and nonce are
  uniformly random; ciphertext length depends only on the nick length.

Result: two keystores with the same nick differ only in uniformly random
material. This is asserted structurally by
`keystores_are_indistinguishable_between_recovery_modes`.

## Atomic writes (crash safety)

Every write is: temp sibling (`keystore.pks.tmp`, created `0600`,
`create_new`) → write → `fsync` → `rename` over the final path → `fsync` of
the directory. A crash at any point leaves either the old file or the new
file, never a torn one. Stale temp files from a crashed attempt are removed on
the next write. Overwriting an existing keystore requires `force`.

## Memory-hygiene limits (honest notes)

- Secrets live in `Zeroizing`/`secrecy` wrappers without `Clone`/`Debug`, and
  the KDF output, decrypted payload, and seed buffers are zeroized on drop.
- **`mlock` is deferred to M8** (hardening): locking pages currently requires
  either `unsafe` or a heavier dependency, and the codebase is zero-unsafe by
  policy. Until M8, **secret material may reach swap** if the system swaps —
  use full-disk encryption or encrypted swap if that is in your threat model.
- Argon2id derivation is blocking and CPU/RAM-heavy **by design**; the daemon
  must always run it via `spawn_blocking`, never on the async executor
  (CLAUDE.md absolute rule).
