// SPDX-License-Identifier: AGPL-3.0-or-later
//! The "V" of Model/Update/View: renders [`AppState`] into a ratatui frame.
//!
//! **Never sets a background** (all backgrounds stay `Color::Reset`, so a
//! transparent or light terminal is preserved); color lives on text and
//! borders only. Body text uses the terminal's default foreground (`Reset`) so
//! it is legible on any theme; accents are the 16 *named* ANSI colors (remapped
//! by the user's theme), never fixed RGB. Selection is shown with
//! `Modifier::REVERSED` (which swaps the terminal's own colors) plus a gutter
//! marker — not a painted block. The layout is recomputed from the frame width
//! each draw so it degrades on narrow terminals instead of garbling.
//!
//! This is the only place a message body is exposed (via `.expose()`), straight
//! into terminal cells; it is never logged.

use ratatui::layout::{Alignment, Constraint, Direction as RDirection, Layout as RLayout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use super::state::{AppState, Conversation, Delivery, Direction, Focus, Layout, Mode};
use crate::text;

/// The primary accent — active borders, selection, own messages.
const ACCENT: Color = Color::Cyan;
/// Deterministic per-peer name colors (named ANSI so they adapt to the theme).
const PALETTE: [Color; 6] = [
    Color::Green,
    Color::Yellow,
    Color::Blue,
    Color::Magenta,
    Color::Cyan,
    Color::LightGreen,
];

/// A stable color for a peer, derived from its fingerprint.
fn peer_color(fingerprint: &str) -> Color {
    let sum: u32 = fingerprint.bytes().map(u32::from).sum();
    PALETTE[(sum as usize) % PALETTE.len()]
}

/// Border style for a pane, brighter when focused.
fn border_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

/// Truncate `s` to `width` columns, appending an ellipsis if cut.
fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_owned()
    } else if width == 0 {
        String::new()
    } else {
        let keep = width.saturating_sub(1);
        let mut out: String = s.chars().take(keep).collect();
        out.push('…');
        out
    }
}

/// Render the whole UI. Records clickable regions into `state.regions`.
pub fn render(frame: &mut Frame, state: &mut AppState) {
    let area = frame.area();
    state.regions = Default::default();
    match state.layout {
        Layout::TooSmall => render_too_small(frame, area),
        Layout::Narrow => render_narrow(frame, state, area),
        Layout::Medium => render_cockpit(frame, state, area, 22),
        Layout::Wide => render_cockpit(frame, state, area, 30),
    }
    if state.show_help {
        render_help(frame, area);
    }
}

fn render_too_small(frame: &mut Frame, area: Rect) {
    let p = Paragraph::new(text::TUI_TOO_SMALL)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
    frame.render_widget(p, area);
}

/// The full cockpit: title bar, [nav column | messages], input, keyhints.
fn render_cockpit(frame: &mut Frame, state: &mut AppState, area: Rect, nav_width: u16) {
    let rows = RLayout::default()
        .direction(RDirection::Vertical)
        .constraints([
            Constraint::Length(1), // title
            Constraint::Min(3),    // body
            Constraint::Length(1), // input
            Constraint::Length(1), // keyhints
        ])
        .split(area);

    render_title(frame, state, rows[0]);

    let body = RLayout::default()
        .direction(RDirection::Horizontal)
        .constraints([Constraint::Length(nav_width), Constraint::Min(10)])
        .split(rows[1]);

    render_nav_column(frame, state, body[0]);
    render_messages(frame, state, body[1]);

    render_input(frame, state, rows[2]);
    render_keyhints(frame, state, rows[3]);
}

/// Narrow layout: no nav column. The focused pane fills the width as a "tab".
fn render_narrow(frame: &mut Frame, state: &mut AppState, area: Rect) {
    let rows = RLayout::default()
        .direction(RDirection::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

    render_title(frame, state, rows[0]);
    match state.focus {
        Focus::Conversations => render_conversations(frame, state, rows[1]),
        Focus::Peers => render_peers(frame, state, rows[1]),
        Focus::Messages => render_messages(frame, state, rows[1]),
    }
    render_input(frame, state, rows[2]);
    render_keyhints(frame, state, rows[3]);
}

fn render_title(frame: &mut Frame, state: &AppState, area: Rect) {
    let handle = if state.own_handle.is_empty() {
        text::TUI_CONNECTING
    } else {
        &state.own_handle
    };
    let mode = match state.mode {
        Mode::Normal => Span::styled(
            format!(" {} ", text::TUI_MODE_NORMAL),
            Style::default().fg(ACCENT).add_modifier(Modifier::REVERSED),
        ),
        Mode::Insert => Span::styled(
            format!(" {} ", text::TUI_MODE_INSERT),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::REVERSED),
        ),
    };
    let line = Line::from(vec![
        Span::styled(
            format!(" {} ", text::TUI_TITLE),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::raw(handle.to_owned()),
        Span::raw("  "),
        Span::styled(
            format!("● {} peers", state.status.peer_count),
            Style::default().fg(Color::Green),
        ),
        Span::raw("  "),
        mode,
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn render_nav_column(frame: &mut Frame, state: &mut AppState, area: Rect) {
    let parts = RLayout::default()
        .direction(RDirection::Vertical)
        .constraints([
            Constraint::Min(3),    // conversations
            Constraint::Length(7), // peers
            Constraint::Length(5), // net
        ])
        .split(area);
    render_conversations(frame, state, parts[0]);
    render_peers(frame, state, parts[1]);
    render_net(frame, state, parts[2]);
}

fn render_conversations(frame: &mut Frame, state: &mut AppState, area: Rect) {
    let focused = matches!(state.focus, Focus::Conversations);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(focused))
        .title(Span::styled(
            text::TUI_CONVERSATIONS,
            Style::default().add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    state.regions.conversations = Some(inner);

    if state.conversations.is_empty() {
        frame.render_widget(dim(text::TUI_NO_CONVERSATIONS), inner);
        return;
    }
    let width = inner.width as usize;
    let lines: Vec<Line> = state
        .conversations
        .iter()
        .enumerate()
        .map(|(i, conv)| {
            let selected = state.selected_conversation == Some(i);
            let color = peer_color(&conv.fingerprint);
            let short = AppState::short_fingerprint(&conv.fingerprint);
            let unread = if conv.unread > 0 {
                format!(" ({})", conv.unread)
            } else {
                String::new()
            };
            let label = truncate(&format!("{short}{unread}"), width.saturating_sub(2));
            selectable_line("● ", &label, color, selected)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_peers(frame: &mut Frame, state: &mut AppState, area: Rect) {
    let focused = matches!(state.focus, Focus::Peers);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(focused))
        .title(Span::styled(
            text::TUI_PEERS,
            Style::default().add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    state.regions.peers = Some(inner);

    if state.peers.is_empty() {
        frame.render_widget(dim(text::TUI_NO_PEERS), inner);
        return;
    }
    let width = inner.width as usize;
    let lines: Vec<Line> = state
        .peers
        .iter()
        .enumerate()
        .map(|(i, peer)| {
            let selected = focused && state.selected_peer == i;
            let color = peer_color(&peer.fingerprint);
            let marker = if peer.connected { "● " } else { "○ " };
            let label = truncate(
                AppState::short_fingerprint(&peer.fingerprint),
                width.saturating_sub(2),
            );
            selectable_line(marker, &label, color, selected)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_net(frame: &mut Frame, state: &AppState, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(false))
        .title(Span::styled(
            text::TUI_NET,
            Style::default().add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let width = inner.width as usize;
    let mut lines = vec![Line::from(format!("peers: {}", state.status.peer_count))];
    if !state.status.peer_id.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("id ", dim_style()),
            Span::raw(truncate(&state.status.peer_id, width.saturating_sub(3))),
        ]));
    }
    let remaining = (inner.height as usize).saturating_sub(lines.len());
    for addr in state.status.listen_addrs.iter().take(remaining) {
        lines.push(Line::from(truncate(addr, width)));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_messages(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = matches!(state.focus, Focus::Messages);
    let title = match state.current_conversation() {
        Some(conv) => {
            let short = AppState::short_fingerprint(&conv.fingerprint);
            let dot = "● ";
            format!("{dot}{short}")
        }
        None => text::TUI_NO_CONVERSATION_SELECTED.to_owned(),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(focused))
        .title(Span::styled(
            title,
            Style::default().add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(conv) = state.current_conversation() else {
        frame.render_widget(dim(text::TUI_NO_CONVERSATION_SELECTED), inner);
        return;
    };
    if conv.messages.is_empty() {
        frame.render_widget(dim(text::TUI_NO_MESSAGES), inner);
        return;
    }

    let lines = message_lines(conv);
    // Bottom-anchor: show the newest lines, offset upward by state.scroll.
    let viewport = inner.height as usize;
    let max_offset = lines.len().saturating_sub(viewport);
    let offset = max_offset.saturating_sub(state.scroll as usize) as u16;
    let paragraph = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((offset, 0));
    frame.render_widget(paragraph, inner);
}

/// Build the display lines for a conversation's messages.
fn message_lines(conv: &Conversation) -> Vec<Line<'static>> {
    conv.messages
        .iter()
        .map(|msg| {
            let color = peer_color(&conv.fingerprint);
            let (label, label_style) = match msg.direction {
                Direction::Outgoing => (
                    text::TUI_YOU.to_owned(),
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ),
                Direction::Incoming => (
                    AppState::short_fingerprint(&conv.fingerprint).to_owned(),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
            };
            let marker = match msg.delivery {
                Delivery::Pending => " ·",
                Delivery::Sent => " ✓",
                Delivery::Failed => " ✗",
                Delivery::Received => "",
            };
            Line::from(vec![
                Span::styled(format!("{label}{marker} "), label_style),
                // The one place plaintext is exposed — into terminal cells.
                Span::raw(msg.body.expose().to_owned()),
            ])
        })
        .collect()
}

fn render_input(frame: &mut Frame, state: &mut AppState, area: Rect) {
    state.regions.input = Some(area);
    let composing = matches!(state.mode, Mode::Insert);
    let prompt = "› ";
    let content = if state.input.is_empty() && !composing {
        Span::styled(text::TUI_INPUT_HINT, dim_style())
    } else {
        Span::raw(state.input.as_str())
    };
    let prompt_style = if composing {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let line = Line::from(vec![Span::styled(prompt, prompt_style), content]);
    frame.render_widget(Paragraph::new(line), area);

    if composing {
        let cursor_x = area.x + prompt.chars().count() as u16 + state.input.chars().count() as u16;
        let cursor_x = cursor_x.min(area.x + area.width.saturating_sub(1));
        frame.set_cursor_position((cursor_x, area.y));
    }
}

fn render_keyhints(frame: &mut Frame, state: &AppState, area: Rect) {
    let hint = match state.mode {
        Mode::Insert => text::TUI_HINT_INSERT,
        Mode::Normal => match state.focus {
            Focus::Conversations => text::TUI_HINT_CONVERSATIONS,
            Focus::Peers => text::TUI_HINT_PEERS,
            Focus::Messages => text::TUI_HINT_MESSAGES,
        },
    };
    let mut spans = vec![Span::styled(hint, dim_style())];
    if let Some(notice) = &state.notice {
        spans = vec![Span::styled(
            truncate(notice, area.width as usize),
            Style::default().fg(Color::Yellow),
        )];
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_help(frame: &mut Frame, area: Rect) {
    let popup = centered(area, 66, 16);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))
        .title(Span::styled(
            text::TUI_HELP_TITLE,
            Style::default().add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    frame.render_widget(
        Paragraph::new(text::TUI_HELP_BODY).wrap(Wrap { trim: false }),
        inner,
    );
}

/// A line with a colored marker + label, reversed when selected (theme-safe:
/// REVERSED uses the terminal's own colors, never a painted background).
fn selectable_line(marker: &str, label: &str, color: Color, selected: bool) -> Line<'static> {
    let gutter = if selected { "▌" } else { " " };
    let mut style = Style::default().fg(color);
    if selected {
        style = style.add_modifier(Modifier::REVERSED | Modifier::BOLD);
    }
    Line::from(vec![
        Span::styled(gutter.to_owned(), Style::default().fg(ACCENT)),
        Span::styled(format!("{marker}{label}"), style),
    ])
}

fn dim_style() -> Style {
    Style::default()
        .fg(Color::DarkGray)
        .add_modifier(Modifier::DIM)
}

fn dim(s: &str) -> Paragraph<'static> {
    Paragraph::new(s.to_owned())
        .style(dim_style())
        .wrap(Wrap { trim: true })
}

/// A centered rect of at most `width` × `height`, clamped to `area`.
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect {
        x,
        y,
        width: w,
        height: h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// Render a fresh state at the given size/focus and return the flattened
    /// buffer text (no real terminal involved).
    fn render_text(width: u16, height: u16, focus: Focus) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        let mut state = AppState::new(width, height);
        state.focus = focus;
        state.own_handle = "alice#abcdefghijklmn".to_owned();
        terminal
            .draw(|frame| render(frame, &mut state))
            .expect("draw");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn wide_layout_shows_all_nav_panes() {
        let text = render_text(120, 40, Focus::Conversations);
        assert!(text.contains("Prism"));
        assert!(text.contains("CONVERSATIONS"));
        assert!(text.contains("PEERS"));
        assert!(text.contains("NET"));
    }

    #[test]
    fn narrow_layout_hides_the_nav_column() {
        // 40 cols -> Narrow; focused on Messages, so only that pane shows.
        let text = render_text(40, 20, Focus::Messages);
        assert!(!text.contains("PEERS (mDNS)"));
    }

    #[test]
    fn too_small_shows_a_notice_not_a_crash() {
        let text = render_text(10, 4, Focus::Conversations);
        assert!(text.contains("small"));
    }

    #[test]
    fn a_range_of_sizes_never_panics() {
        for (w, h) in [(200, 60), (100, 30), (90, 24), (60, 12), (30, 8), (24, 6)] {
            let _ = render_text(w, h, Focus::Conversations);
            let _ = render_text(w, h, Focus::Messages);
        }
    }

    #[test]
    fn peer_color_is_stable_per_fingerprint() {
        assert_eq!(peer_color("3R95oF6ZdppUsD"), peer_color("3R95oF6ZdppUsD"));
    }

    #[test]
    fn truncate_adds_ellipsis_when_cutting() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 5), "hell…");
        assert_eq!(truncate("hello", 0), "");
    }
}
