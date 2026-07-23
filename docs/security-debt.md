# Security debt — deferred advisories

A single index of every advisory Prism currently **ignores**, so none is lost
track of. This file is a *consolidated view*, not the source of truth: the
ignores are enforced in [`deny.toml`](../deny.toml) and
[`.cargo/audit.toml`](../.cargo/audit.toml), and the networking rationale is in
[`docs/net.md`](net.md) §Supply chain. Update this table whenever an ignore is
added, dropped, or its status changes.

All entries are **transitive** dependencies with **no in-semver fix** at the
time of acceptance. Each was surfaced and ratified explicitly (never silently
suppressed).

| Advisory | Crate (via) | What it is | Why accepted now | M4 blocker? | Drop when |
|---|---|---|---|---|---|
| **RUSTSEC-2026-0118** | `hickory-proto` 0.25 (libp2p-mdns 0.48) | NSEC3/DNSSEC closest-encloser proof enters an unbounded loop on cross-zone responses | **Unreachable**: libp2p-mdns pulls hickory with `default-features = false, features = ["mdns"]` — the DNSSEC/NSEC3 resolver path is not compiled or exercised by mDNS | No (re-check at M4) | libp2p bumps its hickory dependency |
| **RUSTSEC-2026-0119** | `hickory-proto` 0.25 (libp2p-mdns 0.48) | O(n²) name compression during DNS message *encoding* → CPU exhaustion | CPU-only DoS, **LAN-scoped** in M2b (local mDNS, no global exposure), confined to the swarm task; no memory-safety/confidentiality impact | **YES** | libp2p bumps its hickory dependency |
| **RUSTSEC-2024-0436** | `paste` 1.0 (proc-macro, transitive) | Crate unmaintained | Compile-time only, no runtime surface, no maintained drop-in replacement | No | a maintained replacement path exists |
| **RUSTSEC-2026-0002** | `lru` 0.12 (ratatui 0.29) | `IterMut` violates Stacked Borrows (unsound) | A Miri-level soundness lint, not a known exploit (`cargo audit` treats it as a warning); **local-client-only** surface (the TUI's render cache); ratatui 0.29 pins `lru = "0.12"`, fix is in lru 0.13 | No | ratatui bumps its `lru` dependency to 0.13+ |

## The M4 blocker, spelled out

**RUSTSEC-2026-0119 must be re-opened and resolved before M4 ships.** M4 puts
the node on a public Kademlia DHT: a denial-of-service that today only a
same-LAN peer can attempt becomes reachable by **anyone on the internet**. A
LAN-scoped acceptance does not survive WAN exposure. Re-audit the whole
networking dependency tree at M4 and either upgrade hickory (once libp2p allows
it) or otherwise mitigate before the DHT is enabled by default.

The other three are not gated on M4, but should still be revisited whenever
their drop condition becomes available.

## Ratification log

- **2026-07-22 (M2b):** RUSTSEC-2026-0118, -0119, and -2024-0436 accepted;
  -0119 flagged as the M4 blocker.
- **2026-07-23 (M3):** RUSTSEC-2026-0002 accepted (arrived with the ratatui/
  crossterm TUI dependency), explicitly *not* an M4 blocker.
