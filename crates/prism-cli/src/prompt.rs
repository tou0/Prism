// SPDX-License-Identifier: AGPL-3.0-or-later
//! Interactive prompts. All input is collected *synchronously, before* any
//! async work: a one-shot client has no reason to hold secrets across
//! `.await` points.
//!
//! Secrets (passphrases, mnemonic) are read without echo via `rpassword` and
//! wrapped in zeroizing containers immediately. The recovery-mode choice and
//! the mnemonic are deliberately **interactive-only** — no CLI flag — so no
//! secret or security-relevant choice ever lands in shell history.

use std::io::{BufRead, Write};

use anyhow::{bail, Context, Result};
use prism_core::recovery::RecoveryPhrase;
use prism_core::validate_nick;
use prism_proto::{RecoveryMode, Sensitive};
use zeroize::Zeroizing;

use crate::text;

/// Attempts allowed for each interactive input before aborting.
const MAX_ATTEMPTS: usize = 3;

/// Print `prompt` without a newline and flush, so the cursor waits after it.
fn show(prompt: &str) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(prompt.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

/// Read one trimmed line from stdin (echoing input; not for secrets).
fn read_line() -> Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("reading from standard input")?;
    Ok(line.trim().to_owned())
}

/// Prompt for a nickname until it passes `validate_nick`.
pub fn nick() -> Result<String> {
    for _ in 0..MAX_ATTEMPTS {
        show(text::PROMPT_NICK)?;
        let nick = read_line()?;
        match validate_nick(&nick) {
            Ok(()) => return Ok(nick),
            Err(e) => eprintln!("{e}"),
        }
    }
    bail!(text::ERR_TOO_MANY_ATTEMPTS)
}

/// Prompt for a new passphrase: no echo, non-empty, entered twice.
pub fn passphrase_new() -> Result<Sensitive> {
    for _ in 0..MAX_ATTEMPTS {
        let first = Zeroizing::new(
            rpassword::prompt_password(text::PROMPT_PASSPHRASE_NEW)
                .context("reading the passphrase")?,
        );
        if first.is_empty() {
            eprintln!("{}", text::ERR_PASSPHRASE_EMPTY);
            continue;
        }
        let second = Zeroizing::new(
            rpassword::prompt_password(text::PROMPT_PASSPHRASE_CONFIRM)
                .context("reading the passphrase confirmation")?,
        );
        if *first != *second {
            eprintln!("{}", text::ERR_PASSPHRASE_MISMATCH);
            continue;
        }
        return Ok(Sensitive::new(first.to_string()));
    }
    bail!(text::ERR_TOO_MANY_ATTEMPTS)
}

/// Prompt for an existing passphrase: no echo, non-empty, single entry.
pub fn passphrase() -> Result<Sensitive> {
    for _ in 0..MAX_ATTEMPTS {
        let entered = Zeroizing::new(
            rpassword::prompt_password(text::PROMPT_PASSPHRASE)
                .context("reading the passphrase")?,
        );
        if entered.is_empty() {
            eprintln!("{}", text::ERR_PASSPHRASE_EMPTY);
            continue;
        }
        return Ok(Sensitive::new(entered.to_string()));
    }
    bail!(text::ERR_TOO_MANY_ATTEMPTS)
}

/// Interactive recovery-mode menu (deliberately not a CLI flag).
pub fn recovery_mode() -> Result<RecoveryMode> {
    for _ in 0..MAX_ATTEMPTS {
        show(text::RECOVERY_MENU)?;
        match read_line()?.as_str() {
            "" | "1" => return Ok(RecoveryMode::None),
            "2" => return Ok(RecoveryMode::Phrase),
            _ => eprintln!("{}", text::ERR_RECOVERY_CHOICE),
        }
    }
    bail!(text::ERR_TOO_MANY_ATTEMPTS)
}

/// Prompt for a recovery phrase: no echo, parsed client-side so typos are
/// caught immediately (with the failing word's position) instead of after a
/// round-trip. The normalized phrase is what gets sent.
pub fn mnemonic() -> Result<Sensitive> {
    for _ in 0..MAX_ATTEMPTS {
        let entered = Zeroizing::new(
            rpassword::prompt_password(text::PROMPT_MNEMONIC)
                .context("reading the recovery phrase")?,
        );
        match RecoveryPhrase::parse(&entered) {
            Ok(phrase) => return Ok(Sensitive::new(phrase.expose_phrase().to_string())),
            Err(e) => eprintln!("{e}"),
        }
    }
    bail!(text::ERR_TOO_MANY_ATTEMPTS)
}

/// Show the one-time mnemonic, numbered, wait for Enter, then best-effort
/// clear the screen and scrollback so it does not linger in the terminal.
pub fn display_mnemonic(mnemonic: &Sensitive) -> Result<()> {
    println!("\n{}\n", text::MNEMONIC_HEADER);
    for (i, word) in mnemonic.expose().split_whitespace().enumerate() {
        println!("  {:2}. {word}", i + 1);
    }
    println!();
    show(text::MNEMONIC_CONFIRM)?;
    let _ = read_line()?;
    show(text::CLEAR_SCREEN)?;
    Ok(())
}
