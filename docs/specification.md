# Prism — Specification (CLI end-to-end encrypted P2P messenger)

**Project name:** Prism *(note: shares its name with the NSA surveillance program "PRISM" — a deliberate choice, to keep in mind for communication)*
**Document version:** 0.1 (working draft, a living baseline to iterate on)
**Language:** Rust

---

## 0. How to read this document

This specification consolidates every decision made during the design phase. **Section 1** is a validation pass: it recaps the locked-in choices so they can be confirmed or corrected at a glance. The rest details each building block. Still-open points are listed in **section 18**.

---

## 1. Locked-in decisions (validation pass)

| Topic | Decision |
|---|---|
| **Nature** | Peer-to-peer (P2P) end-to-end encrypted messenger, CLI/TUI, decentralized, no central server. |
| **Philosophy** | Fully private, user-run, no dependency on Big Tech. "Blockchain" spirit: rules enforced by everyone, no authority over users. |
| **Identity** | Key pair (Ed25519). Free nickname + suffix = public-key fingerprint, Discord-style (`Alice#3f9a…`), compactly encoded (base58). No email, no password. |
| **Local access** | A passphrase decrypts the local keystore (it is never sent anywhere). |
| **Recovery** | No recovery by default (nothing to reveal under coercion); a recovery phrase as an explicit opt-in. |
| **Encryption** | X3DH + Double Ratchet via **vodozemac** (audited). Forward secrecy + post-compromise recovery. Strict public-key validation. Crypto agility (PQXDH migration possible). |
| **Network** | `rust-libp2p`: Kademlia DHT + mDNS + Rendezvous; NAT via hole punching + Circuit Relay v2. **Optional Tor transport (v1.x)** via Arti. |
| **Discovery** | No global enumeration of users. Resolution of a known identity via the DHT; private groups via rendezvous. |
| **Right to contact** | Contacts-only by default. **Sharing a group grants the right to whisper a member** (Minecraft `/whisper` style) — a **v2** capability (tied to groups), subject to anti-spam. |
| **Offline** | Deferred delivery via peer relays (encrypted messages transit through other peers). |
| **Reliability** | Decentralization/reliability hybrid: helper nodes allowed **but run by individuals**, never mandatory. Any user can fill any role. |
| **Anti-spam** | Open by default but proof-of-work + rate limiting; tightenable to "contacts only". Broadcast = publish/subscribe (opt-in). |
| **Interface** | Daemon + client model. TUI (ratatui/crossterm), keyboard-first + mouse. Scriptable one-shot commands as a complement. |
| **Groups** | Out of scope for v1; v2 roadmap (Megolm/MLS). Admin authority **within a group only**. |
| **Anti-coercion** | v1: kill switch + ephemeral messages by default + robust at-rest encryption. v2: duress passphrase, plausible deniability, dead-man's switch. |
| **Metadata** | Architecture designed for anonymity (onion / sealed sender / cover traffic), implemented in v2. |
| **Versions** | Compatibility window + hard floor (reject versions with a known flaw). Active CVE monitoring. |
| **Updates** | Releases signed by maintainer keys, verified before installation, reproducible builds, notify without forcing. |
| **Governance** | Zero power over the network and users (invariant). Code stewardship by maintainers, bounded by open source, reproducible builds, right to fork, multi-signature. |

---

## 2. Vision & guiding principles

A messenger where **privacy is structural, not an option**. No central server, no account, no collection: two people exchange directly, their messages end-to-end encrypted, over a network the users run themselves.

**Non-negotiable principles:**

1. **End-to-end encryption** — nobody in the middle (relays, peers, maintainers) can read a message.
2. **No dependency on central infrastructure** — no mandatory single point of failure.
3. **No authority over users** — nobody can ban, censor, or read.
4. **Self-governance** — any user can become a bootstrap or relay node; the network survives the disappearance of any actor, including its creators.
5. **Honest security** — no promise of "100% secure" or "untraceable". We maximize protection and communicate its limits.

---

## 3. Scope

### v1 (MVP)
- Key-based identity + nickname/fingerprint.
- Encrypted **1:1** conversations (X3DH + Double Ratchet).
- Peer discovery (DHT + mDNS), NAT traversal, peer relaying.
- Offline delivery (encrypted store-and-forward via peers).
- Passphrase → encrypted local keystore; no recovery by default.
- TUI + scriptable commands; daemon + client.
- Anti-spam (proof-of-work + rate limiting), opt-in pub/sub broadcast.
- Kill switch, ephemeral messages, robust storage.
- Version management (window + floor), signed releases.
- **Optional Tor transport (v1.x)** — opt-in; hosting an onion service makes a peer reachable behind symmetric NAT with no open ports, and hides its IP (Briar-style). Solves the #1 reachability risk and the main v1 metadata leak at once.

### v2 and beyond
- **Groups & channels** (Megolm/MLS), in-group admin.
- **In-group whisper**: members of a shared group can message privately without being contacts (co-membership acts as an introduction). Still a **full 1:1 encrypted session** (X3DH + Double Ratchet); **configurable** (allow/deny DMs from co-members), in the anti-spam "tightenable" spirit.
- **Channel roles**: the admin restricts discussion rights (read-only vs read + write). Enforced via **signed messages + admin-signed channel policy** (see §14.4); holds against honest clients, not against a modified client.
- **Metadata privacy**: onion routing, sealed sender, cover traffic.
- **Advanced anti-coercion**: duress passphrase, plausible deniability, dead-man's switch.
- **Memorable names** (optional registry).
- **Identity-key succession**: keeping one's nickname/identity across a key change (statement signed by the old key, contact warning à la Signal).
- **Post-quantum migration** (PQXDH or equivalent).
- **Multi-device**, **multi-signature releases**.
- **Mobile port** — a *hard, separate target*, not a simple recompile: mobile OSes aggressively kill background processes (the daemon), and memory-hard PoW is CPU/RAM-heavy → needs push-wake, background-execution handling, and a lighter anti-spam scheme. **Prism is desktop-first**; mobile is deliberately out of scope for now.

---

## 4. Identity & access

### 4.1 Identity
- Each user has an **Ed25519 key pair** (stable identity). An X25519 key is used for Diffie-Hellman exchanges.
- The **public identity** = `nickname` (free, non-unique) + `#` + **public-key fingerprint** encoded in base58 (e.g. `Alice#3f9a…`).
- Uniqueness comes from **mathematics** (fingerprint derived from a 256-bit key), not a central registry.
- **Displayed fingerprint length**: **~14 base58 characters (~82 bits)** — a robust choice: forging a look-alike fingerprint by grinding requires ~2⁸² operations, out of reach. **SAS / full-fingerprint** verification retained for the most sensitive exchanges.

### 4.2 Local access
- **No email, no server password.** A **passphrase** decrypts the local keystore. It never leaves the device and authenticates no one remotely.
- **Recovery**: by default **none** (the secret exists only in the user's head — nothing to reveal under coercion). A **recovery phrase** (12–24 words, BIP-39 style) is offered as an **explicit opt-in** for profiles favoring convenience. The choice is made at `init`, and the **on-disk keystore is indistinguishable between the two modes** — seizing the device must not reveal whether a recovery phrase exists.

---

## 5. Encryption

### 5.1 In transit (end-to-end)
- **Protocol: X3DH + Double Ratchet**, via **vodozemac** (audited Rust implementation of Olm/Megolm).
- **Asynchronous establishment**: the recipient publishes **signed prekey bundles** (on the DHT/rendezvous); the sender can start a session and send without the other being online.
- **Forward secrecy**: each message has a unique ephemeral key; a compromised key does not expose the others.
- **Post-compromise recovery**: the Diffie-Hellman ratchet reinjects randomness and locks out an attacker after a key theft.
- **Anti-impersonation**: prekeys signed by the identity key; out-of-band verification via SAS (short authentication strings).

### 5.2 At rest
- **Passphrase → encryption key via Argon2id** (slow, memory-hard, GPU/ASIC-resistant; calibrated ~0.5–1 s).
- **Encrypted keystore** (identity keys, ratchet state, prekeys, contacts, history) with an AEAD (**ChaCha20-Poly1305**), salt and nonce stored alongside.
- **Two distinct layers**: at rest (passphrase) + in transit (ratchet).

### 5.3 Hard crypto requirements
- **Generate all keys via a CSPRNG** (never a guessable seed).
- **Validate every received public key**: reject the zero point, low-order points, off-curve points (defense against the "invalid-curve / small-subgroup" class — vodozemac's typical flaw from early 2026). The `*-dalek`/X25519 libraries (RFC 7748) cover part of these checks (X25519 returns an all-zero result on a low-order point), but **explicit rejection on ingestion** of any external key is still required, along with handling of Ed25519 verification edge cases (malleability, cofactor).
- **Never implement homemade crypto**: audited primitives (RustCrypto/dalek) + proven protocol (vodozemac).
- **Crypto agility**: a version field + a negotiable cipher suite in every message, to migrate (e.g. PQXDH) without a break. **Size headroom**: post-quantum primitives (ML-KEM, ML-DSA) are much larger than Ed25519/X25519 (Ed25519 key = 32 B; ML-KEM-768 public key ≈ 1.2 KB; Dilithium signature ≈ 2–4 KB), and PQXDH is *hybrid* → heavier prekey bundles and DHT records, fragmentation (QUIC/UDP MTU), relay latency. Design the wire format, DHT records, and relay handling with **size headroom and fragmentation tolerance** from the start.
- **Memory hygiene**: wipe secrets (`zeroize`), forbid swap (`mlock`). Under `tokio`, "use zeroize" is not enough — the executor may move/copy values across `await` points, and a `Vec` that reallocates leaves un-wiped copies. **Design secret types to avoid copies**: `Zeroizing`/`secrecy` wrappers, no `Clone`/`Debug`, **fixed-size pre-allocated** buffers, minimize holding plaintext secrets across `await`.

---

## 6. P2P network architecture

Built on **`rust-libp2p`**:

- **Transports**: TCP + QUIC; channel encryption via **Noise**.
- **Network identity**: the libp2p `PeerId` is bound to the application identity key (ideally the same Ed25519 key).
- **Discovery**:
  - **Kademlia (DHT)** — distributed directory; each node stores only a slice. Prekey publication and resolution of known identities.
  - **Eclipse/Sybil hardening (S/Kademlia)**: public Kademlia tables are vulnerable to Eclipse attacks (an adversary inserts itself around a target's fingerprint to intercept/isolate). Defenses: **PeerId bound to a proof-of-work** (generating a node identity costs computation — pairs with "costly identities", §9), **IP/subnet diversity** (cap on PeerIds per IP), and **disjoint-path lookups** (resolution over several independent paths → a few malicious nodes cannot control the result).
  - **mDNS** — local-network discovery.
  - **Rendezvous** — discovery segmented by private groups/communities.
- **NAT traversal**: hole punching (**DCUtR**, **AutoNAT**); fallback via relays.
- **Relays**: **Circuit Relay v2** — volunteer peers relay traffic (a decentralized TURN) and also serve offline delivery.
- **Voluntary, capped, capability-aware relaying**: relaying is an **opt-in** role, with **operator-set caps** (bandwidth, storage); nodes **advertise their capacity** and heavy tasks are routed preferentially to large volunteers. A low-bandwidth node (e.g. mobile) is never drained against its will: it **consumes** the network without being forced to **carry** it.
- **Structural dependency on relays (the project's #1 viability risk)**: hole punching (**DCUtR**) statistically **fails against symmetric NATs / CGNAT**, very common on cellular (4G/5G) and some ISPs — those peers can *only* connect via relays, so relaying is **load-bearing, not a minority fallback**. Too few public-relay volunteers → high latency, connection failures, or **de-facto centralization** on a few nodes. Mitigations: make running a relay trivial (one flag, good defaults); the designated mailbox (§8); **non-monetary reciprocity** (relaying peers get better service) — deliberately *not* a paid/crypto service-node model (cf. Session), an accepted ethos trade-off; and an **optional Tor transport** which sidesteps symmetric NAT (onion services need no open ports) and hides IPs (see §13).
- **Optional Tor transport (v1.x — decided)**: run libp2p over Tor via **Arti** (`arti-client`, the Tor Project's Rust implementation), opt-in per the privacy profiles (§13). Hosting an **onion service** makes a peer reachable behind symmetric NAT/CGNAT with **no open ports** and hides its IP — closing the #1 reachability risk and the main v1 metadata leak together. Caveats: added latency / reduced throughput; may need **bridges** where Tor is blocked; Arti client support is mature but **onion-service hosting maturity must be verified at implementation time**.

---

## 7. Communication initiation & discovery

- To reach someone, their **full identity** (`nickname#fingerprint`) is required, shared **out of band** (link, QR, in person). There is **no enumerable global directory**: users cannot be harvested.
- Adding a contact via `add <identity>`; fingerprint verification via `verify`.
- **Contact requests from strangers** (if allowed) go through a proof-of-work (see §9).
- **In-group contact (v2)**: sharing a group grants the right to start a private exchange (whisper) with a member without having them as a contact. The group acts as a **scoped, opt-in** directory (joined voluntarily), without global exposure. Whispers toward non-contacts remain subject to anti-spam (§9), and the group admin can moderate.

---

## 8. Offline delivery

- When the recipient is offline, **relay peers** store the **encrypted** message and deliver it when the recipient returns (store-and-forward).
- Relays read nothing (end-to-end encryption).
- **Redundancy**: send to **several relays** (2–3, no more) to survive one dropping before delivery — balanced against multiplying ciphertext copies in the wild.
- **Reliability/availability score (not "trust")**: prefer often-online relays so cached messages aren't lost. Availability measures *presence*, not *honesty* → **random selection** among good relays + redundancy so metadata isn't concentrated on a few nodes (otherwise a honeypot + Sybil target). Gossiped measurement, treated as a heuristic (self-reporting is gameable).
- **Designated mailbox** (option): the user can designate *their own* relay (an always-online friend's node, a personal server) as a priority cache. Note: this is *per-user, opt-in, encrypted* centralization (the node reads nothing) — not the systemic centralization the project fights; residual risk = metadata collection on *your* inbound traffic → reserve for a trusted node.
- **Acknowledgement + resend (defense against silent loss)**: the **sender keeps the message until it receives an ACK**. If relays churn and the TTL expires without delivery, the sender **knows** and resends. Loss is **never silent**; relays are only an opportunistic cache, the sender is the ultimate safety net.
- **Retention**: set by the **sender**, **short default** (a few days), **1-month ceiling**. The longer a copy lingers, the more it feeds a potential recorder (§16).
- **Forward-secrecy window on pending messages**: an un-received message is, by nature, **decryptable by the recipient's device** (the corresponding prekeys/ratchet state are still present); if the device is seized *before* receipt, that message falls. Inherent to any asynchronous messenger (true of Signal too). Mitigation: **short TTL** + one-time-prekey hygiene. Symmetric: a sender holding an un-ACKed message also has a small window (see §12).
- **Deletion on confirmed delivery** (nothing kept after handoff).
- **Anti-abuse**: proof-of-work (§9), per-relay quotas.

---

## 9. Anti-spam & anti-abuse

Context: free identities + no authority to ban → Sybil risk.

- **Default posture: open but protected** — anyone may reach out, but:
  - **Proof-of-work** (Hashcash concept — a compute token attached to the message) on a **memory-hard function** (Argon2/Equihash type, to level the field against GPU/ASIC): negligible per unit, ruinous at scale.
  - **Difficulty is a function of context, never of the sender's self-declared hardware** (self-declaration is bypassable: a spammer would claim to be weak). Scale by **local history** (from the recipient's viewpoint): established contact / key with good past behavior → none or low; member of a shared group → low; **new/unknown key → full price**. Sybil-resistant by construction: a fresh fake identity has no history → always pays full price (*local pairwise* reputation is not manipulable, unlike global reputation).
  - **Difficulty published by the recipient** in a **signed difficulty record, decoupled from the prekey bundle and short-TTL** (updated independently and cheaply, without republishing the whole bundle): the sender reads it and does the PoW *upfront*, with no round-trip or probing (avoids the "someone is looking for you" leak and DoS on an interactive query). The recipient **verifies** the attached proof; a stale (too-low) published difficulty just makes the sender redo the PoW — no flaw.
  - **Load-adaptive** as a complement. The sender's hardware only serves to *locally estimate* the duration (UX).
  - **Robustness of adaptivity**: the required difficulty is **decided and verified by the recipient** (or via authenticated measurements), not from a manipulable global signal → an attacker cannot lower it by faking "load". Reversing the algorithm doesn't help (PoW does not rely on secrecy). The remaining lever is hardware (GPU/ASIC) → **memory-hard PoW** (Argon2/Equihash type) to level.
  - **Memory cost & responsiveness (mobile/low-resource)**: Argon2 is RAM-heavy. PoW **must never run on the async executor thread** (`spawn_blocking` or dedicated pool, otherwise the daemon freezes), and the **memory parameter is calibrated for the weakest supported device** (an explicit ASIC-resistance ↔ mobile-feasibility trade-off — possibly *moderate* memory). Concrete target: solvable in **< ~5 s on a modest machine**, yet heavy enough to deter automated attacks.
  - **Rate limiting** at relays, per sending key.
- **Tightenable**: the user can switch to **"contacts only"** with one setting.
- **Broadcast = publish/subscribe**: broadcast to **voluntary subscribers** (a channel), never to strangers. Scripting is for pushing to those subscribers.
- **In-group whisper (v2)**: allowed between members of a shared group, but still subject to proof-of-work + rate limiting for non-contacts; the group admin can expel, the receiver can block.
- **(Option) Costly identities**: fingerprint required to start with a few zeros → a compute cost per identity, curbing mass creation.

---

## 10. Interface (CLI / TUI)

### 10.1 Daemon + client architecture
- A background **daemon** keeps the network connection open and the keystore unlocked (needed to receive asynchronously and to relay).
- A thin **client** (TUI or one-shot) talks to the daemon via a **Unix domain socket** (named pipe on Windows), a framed protocol (`serde`).
- **Socket security (critical local attack vector)**: since the daemon holds unlocked keys, the socket is *the* local attack surface. **`0600` permissions inside a `0700` directory** (e.g. `XDG_RUNTIME_DIR`), **calling-process credential check via `SO_PEERCRED`** (UID control, beyond file permissions alone), strict **ACL** on the named pipe on Windows, ideally a per-client **session token**. Prevents any unprivileged local process from injecting commands or extracting data via the daemon's API.

### 10.2 TUI
- **`ratatui` + `crossterm`**: keyboard-first, mouse-capable, cross-platform, robust (neovim / Claude Code style).
- Goal: sending a message is trivial; everything else is handled by the daemon.

### 10.3 Commands (sketch)
| Command | Role |
|---|---|
| `init` | Generate keys, choose the nickname, set the passphrase → create the keystore, show the identity |
| `unlock` | Unlock (passphrase) |
| `add <id>` | Add a contact |
| `verify <contact>` | Compare the full fingerprint (anti-impersonation) |
| `send <contact> "msg"` | Send (scriptable) |
| `chat <contact>` | Interactive session |
| `whisper <member>` / `/w` | Privately message a member of a shared group (v2) |
| `inbox` | Received messages |
| `status` | Network state (peers, DHT) |
| `relay --on` | Become a voluntary relay node |
| `panic` / kill switch | Immediate key wipe |

---

## 11. Local storage

- **Keystore**: encrypted blob (§5.2), **atomic writes** (temp file + rename) so a crash never corrupts it.
- **History**: **SQLite** (`rusqlite`) for ACID / crash-safe robustness, **encrypted** (SQLCipher or application-level encryption).
- **User-chosen retention**: encrypted history kept **or** **ephemeral** messages configurable **per conversation** (ephemeral recommended for sensitive exchanges).
- Cross-platform paths via `directories`.

---

## 12. Anti-coercion security

- **v1**: **kill switch** (immediate wipe), **ephemeral messages by default**, **robust at-rest encryption**. Founding principle: *the best defense is not having the data* — forward secrecy + ephemerality limit what a seized device can reveal.
- **v2 (with warnings)**: **duress passphrase** (decoy/wipe), **plausible deniability** (hidden volume), **dead-man's switch**.
- **Honest limit**: against physical coercion, no crypto protects directly; a poorly designed anti-coercion feature can worsen the danger. Careful design, adversarial testing, honest communication.

---

## 13. Metadata privacy

- **Crucial observation**: P2P decentralizes control, **not** anonymity. A network observer sees who is sending. "P2P = anonymous" is **false**.
- **v1 exposure via the public DHT**: taking part in a public Kademlia DHT exposes your **IP and network activity** to any participating DHT peer (unlike Briar, which forces all traffic through Tor to hide the topology). This is the main v1 metadata weakness — an **optional Tor transport (decided for v1.x, see §6)** largely closes it *and* solves symmetric-NAT reachability at the same time.
- **v2**: **onion routing** (multi-relay, each hop ignores the full chain), **sealed sender**, **cover traffic**. Alternative: transit over Tor.
- **Privacy / bandwidth trade-off**: these defenses (onion, especially **cover traffic**) are bandwidth-expensive — unsuitable as-is for weak/mobile links. Hence **graduated, opt-in** privacy: **profiles** *direct/fast* → *private (onion)* → *maximum (onion + cover)*, the user choosing per need and bandwidth. **Bounded spreading** (~3 hops, Tor-style). A lighter alternative to cover traffic: **batch/delay mixing** (cost in latency rather than bandwidth).
- **v1**: architecture **designed to accommodate** these layers (an extensible relay layer).
- **Honest limit**: even done well, anonymity is never guaranteed against an adversary observing the whole network. **Never promise untraceability to an at-risk user.**
- **User-facing wording (v1)**: "your messages are strongly encrypted and unreadable; however your network activity — presence, IP address, correspondents, timing — is **not** anonymized." The content is protected, not the metadata.

---

## 14. Versions, updates & governance

### 14.1 Version compatibility
- **Negotiation** of the protocol version at each connection (multistream-select), **authenticated**: supported versions are signed into the handshake to prevent a **downgrade** (an intermediary forcing two recent clients to speak an old weak version).
- **Compatibility window** (support the N recent versions) + **hard floor**: reject versions carrying a **known flaw**, with an explicit message.
- **Explicit UX**: "your client is outdated" (invitation to update); "this contact uses an obsolete version" (warning, or refusal if there's a flaw).
- **Version every protocol message** (crypto agility). **Scope & limit**: agility protects **future** messages (migration to a stronger algorithm) and the floor cuts off new messages on a broken version — but **already-recorded ciphertext stays frozen with its algorithm**: if a CVE breaks that algorithm, that ciphertext becomes decryptable retroactively, and **forward secrecy can't help** (it protects against *key* theft, not a broken algorithm). The only real defense for the past: **minimize retained ciphertext** (ephemeral messages) — the same "harvest now, decrypt later" logic that motivates post-quantum.

### 14.2 Security monitoring & response
- **`cargo audit` / `cargo deny`** in CI (breaks the build on a dependency CVE).
- Subscription to upstream advisories (vodozemac/Matrix, rust-libp2p, RustSec, GitHub Security Advisories).
- **Defined response process**: triage, patch deadline, fix release, raising the version floor.
- A commitment to **ongoing maintenance** (a security role/team).

### 14.3 Update distribution
- **Signed releases**; **signature verification before installation** (installation impossible without a valid signature).
- **Multiple maintainers** (via GitHub), each with their public key. **Threshold signing: 2 signatures required** — a single stolen key isn't enough to publish.
- **Multi-channel key anchoring**: authentic public keys do **not** rest solely on the release page (a hacked GitHub account would swap release + key). They are embedded in previous builds, published on the site, in the sources, cross-signed.
- **Mirrors**: signed releases available off GitHub — **propagation over the P2P network** (signed manifest) **+ an independent self-hosted git mirror (datura)** — to avoid a single point of censorship/failure.
- **Reproducible builds** (the community verifies the binary matches the source).
- **Notify, not force**: discovery via a **signed version manifest** gossiped over the network; download out-of-band or P2P with signature verification; installation triggered by the user.
- **Manifest at CLI startup**: the day's manifest (version announcements, any revocations) is shown on launch; older ones remain viewable (a small signed log).
- **Custody**: keys protected to the maximum (hardware token/HSM, offline).
- **Maintainer key rotation**: **scheduled (e.g. annual) AND on suspicion of compromise**; the new key signed by the old one (continuity chain).
- **Revocation**: a **signed revocation notice** ("key X revoked on D") distributed via the manifest and all channels.
- Candidate tools: **minisign/signify** or **Sigstore/cosign** (transparency log).

### 14.4 Governance
- **Two distinct powers, not to be conflated:**
  - **Over the network/users**: **none** (design invariant). No global admin, moderator, censorship, or bans.
  - **Over the code/project**: **stewardship** by maintainers (signing releases, CVE response, version floor), **bounded by**: open source, reproducible builds, **the right to fork** (exit power), multi-signature, transparency of decisions.
- **License = AGPL-3.0-or-later**: the legal enforcement of the anti-capture invariant — any modified version that is distributed *or offered as a network service* must publish its source under the same terms. No one can capture Prism into a closed product; the right to fork stays real because forks must also stay open.
- **Group admin (v2)**: authority **limited to their own group** (never the network) — member validation, assignment of **roles** (read-only / read + write). Enforced via a **signed channel policy** distributed to members: each message is signed by the sender's identity, and clients reject messages from a member not allowed to write. This enforcement holds **against honest clients**; a modified client holding the group key could bypass it (a limit of decentralization — mitigable via key rotation on revocation).
- **In-group whisper (v2)**: a Minecraft-style command (`/w <member> <msg>`) usable from a group's view. By default one writes **to the group**; a whisper goes **privately** to a member. **Delivery**: a separate 1:1 encrypted session (other members never receive it). **Display**: interleaved **inline in the same group view** (no window switching) — "it goes through the group" concerns local display only, not delivery. **Bidirectional** (the target replies with `/w`). Refusable by the recipient.

---

## 15. Reliability & assurance requirements

- **No known vulnerability at release** + a fast fix process.
- **Independent security audit before any real deployment** (non-negotiable).
- **Explicit threat model** (see §16).
- **Defense in depth**: a single bug doesn't bring everything down.
- **Tests**: protocol test vectors, `proptest` (property-based), `cargo-fuzz` (fuzzing), security CI.
- **Rust** leveraged to eliminate whole classes of memory bugs by construction.
- **Honest communication**: never announce "100% secure" or "untraceable".

---

## 16. Threat model (to be formalized)

Adversaries to consider explicitly (in/out of scope per version):
- **Passive network eavesdropper** — content protected by E2E (v1); metadata protected in v2.
- **Malicious relay/peer** — cannot read (E2E); key validation against degeneracies.
- **Adversary recording everything that transits ("harvest now, decrypt later")** — content unusable (E2E + forward secrecy) except for a *future* algorithm break → mitigated by ephemerality + agility/PQ migration; **metadata exposed** → mitigated in v2 (onion, sealed sender, cover traffic, padding). Reduction as early as v1: prefer direct connections, spread relays, short store-and-forward retention.
- **Identity impersonator** — blocked by signatures + fingerprint/SAS verification.
- **Spammer / Sybil** — memory-hard proof-of-work + difficulty by local history + rate limiting.
- **Eclipse/Sybil attack on the DHT** — isolate or intercept a target via malicious PeerIds → S/Kademlia hardening (PeerId bound to PoW, IP diversity, disjoint-path lookups), §6.
- **Local attacker (same machine)** — targets the daemon socket (keys in RAM) → `0600`/`0700` permissions, `SO_PEERCRED`, session token, §10.1.
- **Supply-chain attack** (malicious update) — threshold-signed releases + reproducible builds + multi-channel key anchoring.
- **Physical coercion / device seizure** — ephemerality + kill switch (v1), plausible deniability (v2); honest limits. **Includes pending messages** (not yet received/ACKed) that remain decryptable on the device → short TTL (§8).
- **Global adversary observing the whole network** — beyond any guarantee; to be documented as a limit.

---

## 17. Technical stack

- **Language / async**: Rust (recent edition), `tokio`.
- **Network**: `rust-libp2p` (Kademlia, mDNS, Rendezvous, Gossipsub, Circuit Relay v2, DCUtR, AutoNAT, Noise, QUIC).
- **Optional Tor transport (v1.x)**: `arti-client` (Arti — the Tor Project's Rust implementation), for opt-in onion transport.
- **Crypto**: `vodozemac` (protocol); `ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `hkdf` (complementary primitives); `argon2` (Argon2id); `blake3`/`sha2`; `zeroize` (+ `secrecy`).
- **TUI / CLI**: `ratatui`, `crossterm`, `clap`.
- **Daemon↔client IPC**: Unix socket / named pipe, `serde`.
- **Wire format**: `prost` (protobuf).
- **Storage**: `rusqlite` (+ SQLCipher), `directories`.
- **Release signing**: minisign/signify or Sigstore/cosign.
- **Assurance**: `cargo-audit`, `cargo-deny`, `proptest`, `cargo-fuzz`, reproducible builds.

---

## 18. Open points to decide

1. **Name**: ✅ **Prism** (NSA-surveillance caveat accepted). **License**: ✅ **AGPL-3.0-or-later** (copyleft with network clause — the legal embodiment of the anti-capture invariant). Functional obligations to implement later (**not M0**): §13 source-offer to network peers (e.g. `prism --source` → repo + exact commit), §6(e) peer notice on P2P self-distribution, and "Appropriate Legal Notices" in the interactive UI (`prism license` / startup notice).
2. **Fingerprint length**: ✅ ~14 base58 characters (~82 bits) + SAS.
3. **Wire format**: ✅ **protobuf** (`prost`).
4. **Offline relays**: ✅ 2–3 relays, reliability score + designated mailbox, configurable TTL (short default, 1-month ceiling), deletion on delivery, Hashcash.
5. **Proof-of-work calibration**: ✅ context-based scale + recipient-verified adaptivity + memory-hard PoW; concrete difficulty levels still to set.
6. **Argon2id parameters**: ✅ **fixed constants**, documented, calibrated ~0.5–1 s on a modest machine (not user-configurable). Keystore = a single encrypted file; its on-disk format MUST be **indistinguishable between recovery modes** (no field reveals whether a BIP-39 recovery phrase exists — otherwise device seizure would betray that a phrase is extractable, defeating the at-risk case).
7. **Daemon↔client IPC protocol details.**
8. **Test strategy**: to be completed later.
9. **Maintainer keys**: ✅ 2-signature threshold, scheduled + on-suspicion rotation, revocation by signed notice, manifest at startup.
10. **User identity-key succession**: ✅ deferred to **v2**.
11. **Channel-role enforcement (v2)**: how far to harden "read-only" against modified clients (group-key rotation/revocation)?
12. **Whisper (v2)**: ✅ Minecraft-style, inline, private, bidirectional.
13. **Optional Tor transport**: ✅ decided — **v1.x**, via Arti (`arti-client`). Onion-service hosting maturity to verify at implementation.
14. **Network edge cases**: partitions, TCP/QUIC instability, **clock skew** — rule: never rest security-critical logic on synchronized wall-clocks; tolerate skew in TTLs (prekeys, difficulty records, retention, revocation).
15. **Relay availability / incentives**: ✅ decided — **pure volunteering + non-monetary reciprocity** + easy relay hosting + designated mailbox (deliberately no paid/crypto model); accepted strategic risk.

*Points 6, 7, 8, 11 and the license are implementation calibrations/choices, to be fixed during development — no longer blocking architecture decisions.*

---

*Working document — meant to evolve as decisions are made.*
