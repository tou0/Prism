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
| **RUSTSEC-2026-0118** | `hickory-proto` 0.25 (libp2p-mdns 0.48) | NSEC3/DNSSEC closest-encloser proof enters an unbounded loop on cross-zone responses | **Not compiled**: reachable only with the `dnssec-ring`/`dnssec-aws-lc-rs` feature; libp2p-mdns builds hickory with `features = ["mdns"]` only | No | libp2p-mdns adopts hickory ≥ 0.26.0-beta.1 |
| **RUSTSEC-2026-0119** | `hickory-proto` 0.25 (libp2p-mdns 0.48) | O(n²) name compression during DNS message *encoding* → CPU exhaustion | **Not WAN/DHT-reachable** (verified 2026-07-24): DHT never touches hickory; the encode path builds only our *own* records (record count is self-bounded, not attacker-controlled); the decode path triggers neither advisory. See [`net.md`](net.md) §Supply chain | No (resolved — was flagged at M2b) | libp2p-mdns adopts hickory ≥ 0.26.1 |
| **RUSTSEC-2024-0436** | `paste` 1.0 (proc-macro, transitive) | Crate unmaintained | Compile-time only, no runtime surface, no maintained drop-in replacement | No | a maintained replacement path exists |
| **RUSTSEC-2026-0002** | `lru` 0.12 (ratatui 0.29) | `IterMut` violates Stacked Borrows (unsound) | A Miri-level soundness lint, not a known exploit (`cargo audit` treats it as a warning); **local-client-only** surface (the TUI's render cache); ratatui 0.29 pins `lru = "0.12"`, fix is in lru 0.13 | No | ratatui bumps its `lru` dependency to 0.13+ |

## The M4 gate, resolved (2026-07-24)

RUSTSEC-2026-0119 was flagged at M2b as *the* M4 blocker, on the assumption that
"the DHT exposes the node globally, so a LAN-only DoS becomes internet-wide."
That assumption was **re-investigated from the `libp2p-mdns 0.48` source before
any DHT code**, and it does **not** hold:

- `hickory-proto` is reached **only** through `libp2p-mdns` (`cargo tree -i`);
  `libp2p-kad` has no hickory/DNS dependency and we do not enable libp2p's `dns`
  transport, so the DHT adds no path into hickory.
- The **vulnerable path is encoding** (`BinEncoder`), and libp2p-mdns encodes
  only **our own** records (`local_peer_id` + `listen_addresses`) — a remote
  query cannot inflate the record count that drives the O(n²). The **decode**
  path (fed by the mDNS multicast socket) is a *different* code path and
  triggers neither -0119 (encode-only) nor -0118 (not compiled).

**Conclusion:** a normal user (mDNS + DHT) does not expose -0119 to the WAN.
Full evidence in [`net.md`](net.md) §Supply chain. Mitigation for WAN-exposed
nodes (bootstrap / public-IP / headless): run **`--no-mdns`**, which never opens
the mDNS socket → hickory is never invoked there. A post-`kad` gate re-confirms
`cargo tree -i hickory-proto` stays `libp2p-mdns`-only.

The other advisories are not gated on M4; revisit each at its drop condition.

## Ratification log

- **2026-07-22 (M2b):** RUSTSEC-2026-0118, -0119, and -2024-0436 accepted;
  -0119 flagged as the (then-presumed) M4 blocker.
- **2026-07-23 (M3):** RUSTSEC-2026-0002 accepted (arrived with the ratatui/
  crossterm TUI dependency), explicitly *not* an M4 blocker.
- **2026-07-24 (M4 gate):** -0119 re-investigated and **resolved** — evidence
  shows it is not WAN/DHT-reachable (encode path is self-bounded); -0118 confirmed
  not compiled. Ignores retained with corrected rationale + drop conditions;
  `--no-mdns` mitigation for WAN-exposed nodes. No libp2p fork.
