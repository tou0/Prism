// SPDX-License-Identifier: AGPL-3.0-or-later
//! The interactive TUI: terminal setup, the async event loop, and the IPC I/O
//! task. The interaction logic lives in [`update`] (pure) and rendering in
//! [`view`]; this module is the thin async shell that wires them to the
//! terminal and the daemon.
//!
//! Two input sources are multiplexed with `select!` so neither blocks the
//! other: terminal events (an async `EventStream`) and daemon replies (an mpsc
//! fed by a dedicated I/O task that owns the socket). A keystroke never waits
//! on the socket; a reply never freezes input.

mod state;
mod update;
mod view;

use std::io::Stdout;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures::StreamExt;
use prism_proto::{read_message, write_message, Envelope, Request, Response, Sensitive};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use state::AppState;
use update::{Action, Effect};

/// How often to refresh peers/status and drain the inbox.
const REFRESH: Duration = Duration::from_secs(2);

/// Restores the terminal on drop — even on error or panic unwind — so the
/// user's shell is never left in raw mode or the alternate screen.
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("enabling raw mode")?;
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
            .context("entering the alternate screen")?;
        let terminal =
            Terminal::new(CrosstermBackend::new(stdout)).context("initializing the terminal")?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        let _ = self.terminal.show_cursor();
    }
}

/// Launch the interactive chat TUI against the daemon at `socket_path`.
pub async fn run(socket_path: &Path) -> Result<()> {
    // Connect before taking over the terminal, so a failure prints normally.
    let stream = UnixStream::connect(socket_path)
        .await
        .context("connecting to prismd (is it running and unlocked?)")?;

    let (req_tx, req_rx) = mpsc::channel::<Request>(32);
    let (resp_tx, mut resp_rx) = mpsc::channel::<Response>(64);
    tokio::spawn(io_task(stream, req_rx, resp_tx));

    // Initial fetch of identity, status, and peers.
    let _ = req_tx.send(Request::Whoami).await;
    let _ = req_tx.send(Request::Status).await;
    let _ = req_tx.send(Request::Peers).await;

    let mut guard = TerminalGuard::enter()?;
    let size = guard.terminal.size().context("reading terminal size")?;
    let mut state = AppState::new(size.width, size.height);

    let mut events = EventStream::new();
    let mut refresh = tokio::time::interval(REFRESH);

    guard
        .terminal
        .draw(|frame| view::render(frame, &mut state))
        .context("drawing the initial frame")?;

    loop {
        let action = tokio::select! {
            event = events.next() => match event {
                Some(Ok(Event::Key(key))) => {
                    // Ignore key-release events (some terminals emit them).
                    if key.kind == KeyEventKind::Press {
                        Action::Key(key)
                    } else {
                        continue;
                    }
                }
                Some(Ok(Event::Mouse(mouse))) => Action::Mouse(mouse),
                Some(Ok(Event::Resize(w, h))) => Action::Resize(w, h),
                Some(Ok(_)) => continue,
                Some(Err(_)) | None => break,
            },
            Some(response) = resp_rx.recv() => Action::Reply(response),
            _ = refresh.tick() => {
                // Poll peers/status/inbox on the request connection.
                let _ = req_tx.send(Request::Peers).await;
                let _ = req_tx.send(Request::Status).await;
                let _ = req_tx.send(Request::Inbox).await;
                Action::Tick
            }
        };

        for effect in update::update(&mut state, action) {
            match effect {
                Effect::Send { to, body } => {
                    let _ = req_tx
                        .send(Request::Send {
                            to,
                            body: Sensitive::from_zeroizing(body),
                        })
                        .await;
                }
                Effect::Quit => state.should_quit = true,
            }
        }

        if state.should_quit {
            break;
        }

        guard
            .terminal
            .draw(|frame| view::render(frame, &mut state))
            .context("drawing a frame")?;
    }
    Ok(())
}

/// Owns the IPC connection: forwards requests from the loop and streams
/// responses back. Runs until either channel closes or the socket errors.
async fn io_task(
    mut stream: UnixStream,
    mut req_rx: mpsc::Receiver<Request>,
    resp_tx: mpsc::Sender<Response>,
) {
    while let Some(request) = req_rx.recv().await {
        if write_message(&mut stream, &Envelope::new(request))
            .await
            .is_err()
        {
            break;
        }
        match read_message::<_, Envelope<Response>>(&mut stream).await {
            Ok(envelope) => {
                if resp_tx.send(envelope.message).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}
