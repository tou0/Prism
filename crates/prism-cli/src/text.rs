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

// ── TUI (M3) ────────────────────────────────────────────────────────────────

pub const TUI_TITLE: &str = "Prism";
pub const TUI_CONVERSATIONS: &str = "CONVERSATIONS";
pub const TUI_PEERS: &str = "PEERS (mDNS)";
pub const TUI_NET: &str = "NET";
pub const TUI_NO_CONVERSATIONS: &str = "no conversations yet — open a peer";
pub const TUI_NO_PEERS: &str = "no peers on the LAN yet";
pub const TUI_NO_MESSAGES: &str = "no messages yet — press i to write one";
pub const TUI_NO_CONVERSATION_SELECTED: &str = "select a conversation (↑↓, Enter) or a peer";
pub const TUI_INPUT_HINT: &str = "type a message…";
pub const TUI_YOU: &str = "you";
pub const TUI_MODE_NORMAL: &str = "NORMAL";
pub const TUI_MODE_INSERT: &str = "INSERT";
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
