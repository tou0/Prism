// SPDX-License-Identifier: AGPL-3.0-or-later
//! All user-facing strings, in one place (CLAUDE.md language rule: English
//! for now, isolated so i18n can be added later).

pub const PROMPT_NICK: &str = "Choose a nickname: ";
pub const PROMPT_PASSPHRASE_NEW: &str = "Choose a passphrase (it never leaves this machine): ";
pub const PROMPT_PASSPHRASE_CONFIRM: &str = "Confirm the passphrase: ";
pub const PROMPT_PASSPHRASE: &str = "Passphrase: ";
pub const PROMPT_MNEMONIC: &str = "Enter your recovery phrase (12 words, input hidden): ";

pub const RECOVERY_MENU: &str = "\
Recovery mode:
  1) No recovery phrase (default) — nothing exists outside your head to
     reveal under coercion; a lost passphrase means a lost identity.
  2) Recovery phrase — a 12-word phrase, shown once, can recreate your
     identity on any device. Anyone who reads it owns your identity.
Select [1/2] (default 1): ";

pub const ERR_PASSPHRASE_EMPTY: &str = "the passphrase must not be empty";
pub const ERR_PASSPHRASE_MISMATCH: &str = "the passphrases do not match";
pub const ERR_TOO_MANY_ATTEMPTS: &str = "too many invalid attempts, aborting";
pub const ERR_RECOVERY_CHOICE: &str = "please answer 1 or 2";

pub const MNEMONIC_HEADER: &str = "\
Your recovery phrase — write it down on paper, in order. It is shown ONCE
and never stored. Anyone who reads it owns your identity.";
pub const MNEMONIC_CONFIRM: &str = "Press Enter once you have written it down... ";
/// Best-effort terminal clear (screen + scrollback + home), so the phrase
/// does not linger on screen or in the scrollback buffer.
pub const CLEAR_SCREEN: &str = "\x1b[2J\x1b[3J\x1b[H";

pub const CREATED_HEADER: &str = "Identity created and unlocked.";
pub const RESTORED_HEADER: &str = "Identity restored and unlocked.";
pub const UNLOCKED_HEADER: &str = "Keystore unlocked.";
pub const LOCKED: &str = "Locked: no identity is unlocked (run `prism unlock`, or `prism init`).";
pub const PONG: &str = "pong";

pub const SENT: &str = "sent";
pub const INBOX_EMPTY: &str = "(no messages)";
pub const NO_PEERS: &str = "(no peers discovered on the local network yet)";

/// The recipient is offline; nothing was queued (synchronous delivery only).
pub fn not_reachable(handle: &str) -> String {
    format!("{handle} is not reachable on the local network; nothing was queued")
}

// ── DHT resolve / status (M4) ────────────────────────────────────────────────

/// No valid signed locator was found on the DHT for this handle.
pub fn resolve_not_found(handle: &str) -> String {
    format!("{handle} was not found on the DHT (no valid locator published)")
}

/// A locator was found but advertises no reachable address (NAT-bound peer).
pub const RESOLVE_NO_ADDRS: &str =
    "  (no reachable address published — discovered, but not directly connectable until relays, M5)";

/// Short label for how a connection is carried. Shown so the user always knows
/// whether a third party is carrying their traffic.
pub fn peer_path_label(path: Option<prism_proto::PeerPath>) -> &'static str {
    match path {
        Some(prism_proto::PeerPath::Direct) => "direct",
        Some(prism_proto::PeerPath::Relayed) => "relayed",
        None => "no connection",
    }
}

/// Reachability, phrased so "unknown" is never dressed up as reachable.
pub fn reachability_label(r: prism_proto::ReachabilityInfo) -> &'static str {
    match r {
        prism_proto::ReachabilityInfo::Public => "reachable from the internet",
        prism_proto::ReachabilityInfo::Private => "behind NAT (relays needed)",
        prism_proto::ReachabilityInfo::Unknown => "not determined yet",
    }
}

/// No relay is configured, so this node cannot be reached inbound while behind a
/// NAT. Phrased as the actionable fact, since it is a common misconfiguration:
/// `--relay-addr` is **required** to route through a relay.
pub const NO_RELAYS: &str =
    "  relays:    none configured (a NAT-bound node needs --relay-addr to be reachable)";

/// Whether we hold a reservation on a relay, and if not, why not yet.
pub fn reservation_state_label(state: &prism_proto::ReservationStateInfo) -> String {
    match state {
        prism_proto::ReservationStateInfo::Active => {
            "reserved — reachable via this relay".to_owned()
        }
        prism_proto::ReservationStateInfo::Pending => "requesting…".to_owned(),
        prism_proto::ReservationStateInfo::Retrying {
            attempts,
            retry_in_secs,
        } => format!("NOT reserved after {attempts} attempt(s); retrying in {retry_in_secs}s"),
    }
}

/// Short label for how a peer was discovered.
pub fn peer_source_label(source: prism_proto::PeerSource) -> &'static str {
    match source {
        prism_proto::PeerSource::Mdns => "mDNS",
        prism_proto::PeerSource::Dht => "DHT",
        prism_proto::PeerSource::Manual => "manual",
    }
}

// ── TUI (M3) ────────────────────────────────────────────────────────────────

pub const TUI_TITLE: &str = "Prism";
pub const TUI_CONVERSATIONS: &str = "CONVERSATIONS";
pub const TUI_PEERS: &str = "PEERS";
pub const TUI_NET: &str = "NET";
pub const TUI_NO_CONVERSATIONS: &str = "no conversations yet — open a peer";
pub const TUI_NO_PEERS: &str = "no peers discovered yet";
pub const TUI_NO_MESSAGES: &str = "no messages yet — press i to write one";
pub const TUI_NO_CONVERSATION_SELECTED: &str = "select a conversation (↑↓, Enter) or a peer";
pub const TUI_INPUT_HINT: &str = "type a message…";
pub const TUI_YOU: &str = "you";
pub const TUI_MODE_NORMAL: &str = "NORMAL";
pub const TUI_MODE_INSERT: &str = "INSERT";
// Connection state — deliberately neutral. `connected` means an open
// connection exists right now, NOT reachability (a reachable peer idle for
// >60s shows "not connected"). We do not claim reachability we can't prove.
pub const TUI_STAT_CONNECTED: &str = "connected";
pub const TUI_STAT_SEEN: &str = "seen";
pub const TUI_CONNECTING: &str = "connecting to the daemon…";
pub const TUI_TOO_SMALL: &str = "terminal too small";

pub const TUI_HELP_TITLE: &str = "Keys (press ? or Esc to close)";
pub const TUI_HELP_BODY: &str = "\
Navigation is arrow-first; the bar at the bottom always shows what is live.

  ↑ / ↓        move selection, or scroll messages
  Enter        open the selected conversation / peer; in messages, start typing
  Tab / S-Tab  switch pane (conversations · peers · messages)
  i            write a message (Insert mode)
  Esc          leave Insert / close this help
  ?            toggle this help
  q            quit        Ctrl-C  quit from anywhere

Mouse: click a conversation or peer to open it; wheel scrolls messages.
Messages are end-to-end encrypted and kept in memory only — they are gone
when you quit.";

/// Keyhint bar text for the current mode/focus.
pub const TUI_HINT_INSERT: &str = "Enter send · Esc cancel";
pub const TUI_HINT_CONVERSATIONS: &str =
    "↑↓ move · Enter open · Tab pane · i write · ? help · q quit";
pub const TUI_HINT_PEERS: &str = "↑↓ move · Enter chat · Tab pane · i write · ? help · q quit";
pub const TUI_HINT_MESSAGES: &str = "↑↓ scroll · i write · Tab pane · ? help · q quit";
