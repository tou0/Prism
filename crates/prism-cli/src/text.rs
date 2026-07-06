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
