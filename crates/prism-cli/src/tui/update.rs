// SPDX-License-Identifier: AGPL-3.0-or-later
//! The "U" of Model/Update/View: a pure reducer over the TUI state.
//!
//! [`update`] takes the current [`AppState`] and one [`Action`] (a keystroke,
//! mouse event, resize, daemon reply, or tick), mutates the state, and returns
//! the [`Effect`]s the async loop must perform (send a message, quit). It has
//! **no terminal or socket dependency**, so the entire interaction logic —
//! including "keyboard-only reaches every action" and "narrow width degrades" —
//! is unit-tested without a real terminal.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use prism_proto::{Event, Response, Sensitive};
use zeroize::Zeroizing;

use super::state::{AppState, ChatMessage, Delivery, Direction, Focus, Layout, Mode, StatusInfo};

/// A side effect the async loop must carry out after a state update.
pub enum Effect {
    /// Send an encrypted message to `to` (a `nick#fingerprint` handle).
    Send {
        /// Recipient handle understood by the daemon.
        to: String,
        /// The plaintext, zeroized on drop.
        body: Zeroizing<String>,
    },
    /// Tear down and exit.
    Quit,
}

/// An input to the reducer.
pub enum Action {
    /// A key press.
    Key(KeyEvent),
    /// A mouse event (wheel scroll, left click).
    Mouse(MouseEvent),
    /// The terminal was resized to `(width, height)`.
    Resize(u16, u16),
    /// A solicited reply from the daemon.
    Reply(Response),
    /// An unsolicited push from the daemon (subscribed connection).
    Push(Event),
    /// A periodic tick (drives the status clock; no state change by itself).
    Tick,
}

/// Apply one action to the state, returning any effects to perform.
pub fn update(state: &mut AppState, action: Action) -> Vec<Effect> {
    match action {
        Action::Resize(width, height) => {
            state.width = width;
            state.height = height;
            state.layout = Layout::from_size(width, height);
            Vec::new()
        }
        Action::Tick => Vec::new(),
        Action::Reply(response) => {
            apply_reply(state, response);
            Vec::new()
        }
        Action::Push(event) => {
            apply_push(state, event);
            Vec::new()
        }
        Action::Mouse(event) => handle_mouse(state, event),
        Action::Key(key) => handle_key(state, key),
    }
}

/// Fold a decrypted incoming message into the right conversation. Shared by the
/// inbox drain (and, later, live pushes).
pub fn ingest_incoming(state: &mut AppState, from_fingerprint: String, body: Sensitive) {
    let index = state.ensure_conversation(&from_fingerprint);
    state.conversations[index].messages.push(ChatMessage {
        direction: Direction::Incoming,
        delivery: Delivery::Received,
        body,
    });
    if state.selected_conversation != Some(index) {
        state.conversations[index].unread += 1;
    } else {
        state.scroll = 0; // viewing it: stay pinned to the newest line
    }
}

fn handle_key(state: &mut AppState, key: KeyEvent) -> Vec<Effect> {
    // Ctrl-C always exits, in any mode.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        state.should_quit = true;
        return vec![Effect::Quit];
    }
    match state.mode {
        Mode::Insert => handle_key_insert(state, key),
        Mode::Normal => handle_key_normal(state, key),
    }
}

fn handle_key_insert(state: &mut AppState, key: KeyEvent) -> Vec<Effect> {
    match key.code {
        KeyCode::Esc => state.mode = Mode::Normal,
        KeyCode::Enter => return send_current(state),
        KeyCode::Backspace => {
            state.input.pop();
        }
        KeyCode::Char(c) => state.input.push(c),
        _ => {}
    }
    Vec::new()
}

fn handle_key_normal(state: &mut AppState, key: KeyEvent) -> Vec<Effect> {
    state.notice = None;
    match key.code {
        KeyCode::Char('q') => {
            state.should_quit = true;
            return vec![Effect::Quit];
        }
        KeyCode::Char('?') => state.show_help = !state.show_help,
        KeyCode::Esc => {
            state.show_help = false;
        }
        KeyCode::Char('i') => enter_insert(state),
        KeyCode::Tab => cycle_focus(state, true),
        KeyCode::BackTab => cycle_focus(state, false),
        // Arrows are primary; j/k are optional aliases.
        KeyCode::Up | KeyCode::Char('k') => move_selection(state, -1),
        KeyCode::Down | KeyCode::Char('j') => move_selection(state, 1),
        KeyCode::Enter => return activate(state),
        _ => {}
    }
    Vec::new()
}

/// Enter compose mode, if a conversation is open.
fn enter_insert(state: &mut AppState) {
    if state.selected_conversation.is_some() {
        state.mode = Mode::Insert;
        state.focus = Focus::Messages;
    } else {
        state.notice = Some("open a conversation first (Enter on a peer)".to_owned());
    }
}

/// Cycle focus across the panes.
fn cycle_focus(state: &mut AppState, forward: bool) {
    state.focus = match (state.focus, forward) {
        (Focus::Conversations, true) => Focus::Peers,
        (Focus::Peers, true) => Focus::Messages,
        (Focus::Messages, true) => Focus::Conversations,
        (Focus::Conversations, false) => Focus::Messages,
        (Focus::Peers, false) => Focus::Conversations,
        (Focus::Messages, false) => Focus::Peers,
    };
}

/// Move the selection (or scroll) in the focused pane. `delta` is -1 (up) or
/// +1 (down).
fn move_selection(state: &mut AppState, delta: i32) {
    match state.focus {
        Focus::Conversations => {
            let len = state.conversations.len();
            if len == 0 {
                return;
            }
            let current = state.selected_conversation.unwrap_or(0) as i32;
            let next = (current + delta).clamp(0, len as i32 - 1) as usize;
            state.selected_conversation = Some(next);
            state.conversations[next].unread = 0;
            state.scroll = 0;
        }
        Focus::Peers => {
            let len = state.peers.len();
            if len == 0 {
                return;
            }
            let current = state.selected_peer as i32;
            state.selected_peer = (current + delta).clamp(0, len as i32 - 1) as usize;
        }
        Focus::Messages => {
            // scroll counts lines up from the bottom.
            if delta < 0 {
                state.scroll = state.scroll.saturating_add(1);
            } else {
                state.scroll = state.scroll.saturating_sub(1);
            }
        }
    }
}

/// Enter/activate the focused item.
fn activate(state: &mut AppState) -> Vec<Effect> {
    match state.focus {
        Focus::Conversations => {
            if state.selected_conversation.is_none() && !state.conversations.is_empty() {
                state.selected_conversation = Some(0);
            }
            if let Some(i) = state.selected_conversation {
                state.conversations[i].unread = 0;
                state.focus = Focus::Messages;
                state.scroll = 0;
            }
        }
        Focus::Peers => {
            if let Some(peer) = state.peers.get(state.selected_peer) {
                let fingerprint = peer.fingerprint.clone();
                let index = state.ensure_conversation(&fingerprint);
                state.selected_conversation = Some(index);
                state.conversations[index].unread = 0;
                state.focus = Focus::Messages;
                state.scroll = 0;
            }
        }
        Focus::Messages => enter_insert(state),
    }
    Vec::new()
}

/// Send the compose buffer to the selected conversation.
fn send_current(state: &mut AppState) -> Vec<Effect> {
    let body = Zeroizing::new(std::mem::take(&mut *state.input));
    if body.trim().is_empty() {
        return Vec::new();
    }
    let Some(index) = state.selected_conversation else {
        state.notice = Some("open a conversation first".to_owned());
        return Vec::new();
    };
    let fingerprint = state.conversations[index].fingerprint.clone();
    // Local echo, pending until the daemon confirms.
    state.conversations[index].messages.push(ChatMessage {
        direction: Direction::Outgoing,
        delivery: Delivery::Pending,
        body: Sensitive::new(body.to_string()),
    });
    state.scroll = 0;
    // The daemon resolves the recipient by the fingerprint after '#'.
    vec![Effect::Send {
        to: format!("#{fingerprint}"),
        body,
    }]
}

fn handle_mouse(state: &mut AppState, event: MouseEvent) -> Vec<Effect> {
    match event.kind {
        MouseEventKind::ScrollUp => state.scroll = state.scroll.saturating_add(1),
        MouseEventKind::ScrollDown => state.scroll = state.scroll.saturating_sub(1),
        MouseEventKind::Down(MouseButton::Left) => hit_test(state, event.column, event.row),
        _ => {}
    }
    Vec::new()
}

/// Resolve a left click to a selection, using the regions the last render
/// recorded. Clicks outside any known region are ignored.
fn hit_test(state: &mut AppState, column: u16, row: u16) {
    if let Some(area) = state.regions.conversations {
        if contains(area, column, row) {
            let index = (row - area.y) as usize;
            if index < state.conversations.len() {
                state.selected_conversation = Some(index);
                state.conversations[index].unread = 0;
                state.focus = Focus::Messages;
                state.scroll = 0;
            }
            return;
        }
    }
    if let Some(area) = state.regions.peers {
        if contains(area, column, row) {
            let index = (row - area.y) as usize;
            if index < state.peers.len() {
                state.selected_peer = index;
                state.focus = Focus::Peers;
                let fingerprint = state.peers[index].fingerprint.clone();
                let conv = state.ensure_conversation(&fingerprint);
                state.selected_conversation = Some(conv);
                state.conversations[conv].unread = 0;
                state.scroll = 0;
            }
            return;
        }
    }
    if let Some(area) = state.regions.input {
        if contains(area, column, row) {
            enter_insert(state);
        }
    }
}

fn contains(area: ratatui::layout::Rect, column: u16, row: u16) -> bool {
    column >= area.x && column < area.x + area.width && row >= area.y && row < area.y + area.height
}

fn apply_reply(state: &mut AppState, response: Response) {
    match response {
        Response::Identity { handle, .. } => state.own_handle = handle,
        Response::Status {
            handle,
            peer_id,
            listen_addrs,
            peer_count,
        } => {
            if state.own_handle.is_empty() {
                state.own_handle = handle;
            }
            state.status = StatusInfo {
                peer_id,
                listen_addrs,
                peer_count,
            };
        }
        Response::Peers { peers } => {
            state.status.peer_count = peers.len();
            state.peers = peers;
            if state.selected_peer >= state.peers.len() {
                state.selected_peer = state.peers.len().saturating_sub(1);
            }
        }
        Response::Sent => mark_oldest_pending(state, Delivery::Sent),
        Response::NotReachable { .. } => {
            mark_oldest_pending(state, Delivery::Failed);
            state.notice = Some("peer not reachable; nothing was queued".to_owned());
        }
        Response::Inbox { messages } => {
            for item in messages {
                ingest_incoming(state, item.from_fingerprint, item.body);
            }
        }
        Response::Error { message } => state.notice = Some(message),
        // Pong / Locked / Created / Subscribed / Event are not solicited here.
        _ => {}
    }
}

/// Apply a server-initiated push to the state.
fn apply_push(state: &mut AppState, event: Event) {
    match event {
        Event::Message {
            from_fingerprint,
            body,
        } => ingest_incoming(state, from_fingerprint, body),
        Event::PeerDiscovered { peer } => {
            // Idempotent: update in place if we already know this fingerprint
            // (the initial Peers snapshot and a push can overlap), else append.
            match state
                .peers
                .iter_mut()
                .find(|p| p.fingerprint == peer.fingerprint)
            {
                Some(existing) => *existing = peer,
                None => state.peers.push(peer),
            }
            state.status.peer_count = state.peers.len();
        }
        Event::PeerLost { fingerprint } => {
            state.peers.retain(|p| p.fingerprint != fingerprint);
            if state.selected_peer >= state.peers.len() {
                state.selected_peer = state.peers.len().saturating_sub(1);
            }
            state.status.peer_count = state.peers.len();
        }
    }
}

/// Mark the oldest still-pending outgoing message with `delivery`. Sends are
/// serialized over the connection, so oldest-pending correlates to the reply.
fn mark_oldest_pending(state: &mut AppState, delivery: Delivery) {
    for conversation in &mut state.conversations {
        for message in &mut conversation.messages {
            if message.direction == Direction::Outgoing && message.delivery == Delivery::Pending {
                message.delivery = delivery;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEvent, KeyModifiers};
    use prism_proto::PeerInfo;

    fn key(code: KeyCode) -> Action {
        Action::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn state_with_peer() -> AppState {
        let mut s = AppState::new(120, 40);
        update(
            &mut s,
            Action::Reply(Response::Peers {
                peers: vec![PeerInfo {
                    fingerprint: "FPALICE1234567890".to_owned(),
                    peer_id: "pid".to_owned(),
                    connected: true,
                }],
            }),
        );
        s
    }

    /// Arrows + Tab + Enter alone reach a peer and open its conversation — no
    /// vim keys needed.
    #[test]
    fn arrows_tab_enter_open_a_peer_conversation() {
        let mut s = state_with_peer();
        update(&mut s, key(KeyCode::Tab)); // Conversations -> Peers
        assert!(matches!(s.focus, Focus::Peers));
        update(&mut s, key(KeyCode::Down)); // move within the peer list
        update(&mut s, key(KeyCode::Enter)); // open a conversation with it
        assert!(s.selected_conversation.is_some());
        assert!(matches!(s.focus, Focus::Messages));
    }

    #[test]
    fn typing_then_enter_sends_and_echoes() {
        let mut s = state_with_peer();
        update(&mut s, key(KeyCode::Tab));
        update(&mut s, key(KeyCode::Enter)); // open conversation
        update(&mut s, key(KeyCode::Char('i'))); // insert mode
        assert!(matches!(s.mode, Mode::Insert));
        for c in "hi".chars() {
            update(&mut s, key(KeyCode::Char(c)));
        }
        let effects = update(&mut s, key(KeyCode::Enter));
        assert_eq!(effects.len(), 1);
        match &effects[0] {
            Effect::Send { to, body } => {
                assert!(to.contains("FPALICE"));
                assert_eq!(body.as_str(), "hi");
            }
            _ => panic!("expected a Send effect"),
        }
        // Local echo, pending until the daemon confirms.
        let conv = s.current_conversation().expect("a conversation");
        assert_eq!(conv.messages.len(), 1);
        assert!(matches!(conv.messages[0].delivery, Delivery::Pending));
        // The compose buffer was cleared.
        assert!(s.input.is_empty());
    }

    #[test]
    fn sent_reply_marks_the_message_delivered() {
        let mut s = state_with_peer();
        update(&mut s, key(KeyCode::Tab));
        update(&mut s, key(KeyCode::Enter));
        update(&mut s, key(KeyCode::Char('i')));
        for c in "yo".chars() {
            update(&mut s, key(KeyCode::Char(c)));
        }
        update(&mut s, key(KeyCode::Enter));
        update(&mut s, Action::Reply(Response::Sent));
        let conv = s.current_conversation().expect("a conversation");
        assert!(matches!(conv.messages[0].delivery, Delivery::Sent));
    }

    #[test]
    fn not_reachable_marks_failed_and_notices() {
        let mut s = state_with_peer();
        update(&mut s, key(KeyCode::Tab));
        update(&mut s, key(KeyCode::Enter));
        update(&mut s, key(KeyCode::Char('i')));
        update(&mut s, key(KeyCode::Char('x')));
        update(&mut s, key(KeyCode::Enter));
        update(
            &mut s,
            Action::Reply(Response::NotReachable {
                handle: "#x".to_owned(),
            }),
        );
        let conv = s.current_conversation().expect("a conversation");
        assert!(matches!(conv.messages[0].delivery, Delivery::Failed));
        assert!(s.notice.is_some());
    }

    #[test]
    fn resize_switches_layout_bands() {
        let mut s = AppState::new(120, 40);
        assert_eq!(s.layout, Layout::Wide);
        update(&mut s, Action::Resize(70, 30));
        assert_eq!(s.layout, Layout::Medium);
        update(&mut s, Action::Resize(40, 20));
        assert_eq!(s.layout, Layout::Narrow);
        update(&mut s, Action::Resize(10, 4));
        assert_eq!(s.layout, Layout::TooSmall);
    }

    #[test]
    fn incoming_message_creates_conversation_with_unread() {
        let mut s = AppState::new(120, 40);
        ingest_incoming(&mut s, "FPBOB".to_owned(), Sensitive::new("yo".to_owned()));
        assert_eq!(s.conversations.len(), 1);
        assert_eq!(s.conversations[0].unread, 1);
        // A second message from the same peer joins the same conversation.
        ingest_incoming(
            &mut s,
            "FPBOB".to_owned(),
            Sensitive::new("again".to_owned()),
        );
        assert_eq!(s.conversations.len(), 1);
        assert_eq!(s.conversations[0].messages.len(), 2);
    }

    #[test]
    fn scroll_only_moves_in_message_focus() {
        let mut s = state_with_peer();
        update(&mut s, key(KeyCode::Up)); // focus Conversations: no scroll
        assert_eq!(s.scroll, 0);
        update(&mut s, key(KeyCode::Tab)); // Peers
        update(&mut s, key(KeyCode::Enter)); // open -> Messages focus
        update(&mut s, key(KeyCode::Up)); // scroll back
        assert_eq!(s.scroll, 1);
        update(&mut s, key(KeyCode::Down));
        assert_eq!(s.scroll, 0);
    }

    #[test]
    fn help_toggles_and_q_and_ctrl_c_quit() {
        let mut s = AppState::new(120, 40);
        update(&mut s, key(KeyCode::Char('?')));
        assert!(s.show_help);
        update(&mut s, key(KeyCode::Esc));
        assert!(!s.show_help);

        let effects = update(&mut s, key(KeyCode::Char('q')));
        assert!(s.should_quit);
        assert!(matches!(effects.first(), Some(Effect::Quit)));

        let mut s = AppState::new(120, 40);
        let ctrl_c = Action::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        let effects = update(&mut s, ctrl_c);
        assert!(s.should_quit);
        assert!(matches!(effects.first(), Some(Effect::Quit)));
    }

    #[test]
    fn push_message_appears_live() {
        let mut s = AppState::new(120, 40);
        update(
            &mut s,
            Action::Push(Event::Message {
                from_fingerprint: "FPCAROL".to_owned(),
                body: Sensitive::new("live!".to_owned()),
            }),
        );
        assert_eq!(s.conversations.len(), 1);
        assert_eq!(s.conversations[0].messages.len(), 1);
    }

    #[test]
    fn push_peer_discovered_then_lost_is_idempotent() {
        let mut s = AppState::new(120, 40);
        let peer = PeerInfo {
            fingerprint: "FPDAVE".to_owned(),
            peer_id: "pid".to_owned(),
            connected: true,
        };
        update(
            &mut s,
            Action::Push(Event::PeerDiscovered { peer: peer.clone() }),
        );
        update(&mut s, Action::Push(Event::PeerDiscovered { peer }));
        assert_eq!(s.peers.len(), 1, "re-discovery must not duplicate");
        assert_eq!(s.status.peer_count, 1);
        update(
            &mut s,
            Action::Push(Event::PeerLost {
                fingerprint: "FPDAVE".to_owned(),
            }),
        );
        assert!(s.peers.is_empty());
        assert_eq!(s.status.peer_count, 0);
    }

    #[test]
    fn click_on_peer_region_opens_conversation() {
        use ratatui::layout::Rect;
        let mut s = state_with_peer();
        s.regions.peers = Some(Rect::new(0, 5, 20, 6));
        // Click the first row inside the peers region.
        update(
            &mut s,
            Action::Mouse(MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 2,
                row: 5,
                modifiers: KeyModifiers::NONE,
            }),
        );
        assert!(s.selected_conversation.is_some());
    }
}
