// SPDX-License-Identifier: AGPL-3.0-or-later
//! The TUI model: all interactive state, with **no terminal or I/O types**.
//!
//! This is the "M" of a Model/Update/View split. It is pure data plus small
//! queries, so the whole interaction logic ([`super::update`]) is unit-testable
//! without a real terminal. Rendering ([`super::view`]) reads this and never
//! mutates it.
//!
//! Message bodies are kept in [`Sensitive`] and the compose buffer in
//! [`Zeroizing`]: plaintext stays wrapped end to end, is exposed only at the
//! moment of rendering, and is zeroized on drop. Nothing here derives `Debug`
//! over a body.

use prism_proto::{PeerInfo, Sensitive};
use ratatui::layout::Rect;
use zeroize::Zeroizing;

/// The short fingerprint length used in handles (`nick#fingerprint`), spec §4.1.
/// Used only to abbreviate a full fingerprint for display.
const SHORT_FP_LEN: usize = 14;

/// Interaction mode. The split exists because the compose line consumes text:
/// in [`Mode::Insert`] a keystroke is input, in [`Mode::Normal`] it navigates.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Navigate and select (arrow keys move, Enter opens).
    Normal,
    /// Type into the compose line (Enter sends, Esc leaves).
    Insert,
}

/// Which pane currently has focus in [`Mode::Normal`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    /// The conversation list (left, top).
    Conversations,
    /// The discovered-peers list (left, middle).
    Peers,
    /// The message area (center) — scrolls the selected conversation.
    Messages,
}

/// Layout density, derived from the terminal width so the UI degrades on
/// narrow terminals instead of garbling.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Layout {
    /// Full three-region cockpit (nav column + center + input).
    Wide,
    /// Narrower nav column, abbreviated fingerprints.
    Medium,
    /// Nav column hidden; the focused pane fills the width as a "tab".
    Narrow,
    /// Too small to render meaningfully — show a notice, never crash.
    TooSmall,
}

impl Layout {
    /// Choose a layout for a terminal of the given size.
    pub fn from_size(width: u16, height: u16) -> Layout {
        if width < 24 || height < 6 {
            Layout::TooSmall
        } else if width < 60 {
            Layout::Narrow
        } else if width < 90 {
            Layout::Medium
        } else {
            Layout::Wide
        }
    }
}

/// Direction of a chat message relative to us.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Received from the peer.
    Incoming,
    /// Sent by us.
    Outgoing,
}

/// Delivery state of an outgoing message (incoming messages are always
/// [`Delivery::Received`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Received from a peer.
    Received,
    /// Sent by us, awaiting the daemon's acknowledgement.
    Pending,
    /// The daemon confirmed encryption + transmission.
    Sent,
    /// The peer was not reachable, or the send failed.
    Failed,
}

/// One message in a conversation. The body stays wrapped in [`Sensitive`].
pub struct ChatMessage {
    /// Whether we sent or received it.
    pub direction: Direction,
    /// Delivery state (meaningful mainly for outgoing messages).
    pub delivery: Delivery,
    /// The plaintext, exposed only at render time, never logged.
    pub body: Sensitive,
}

/// A 1:1 conversation, keyed by the peer's full fingerprint. Ephemeral: it
/// lives only for this TUI session (no history persistence in M3).
pub struct Conversation {
    /// The peer's full identity fingerprint (base58).
    pub fingerprint: String,
    /// Messages, oldest first.
    pub messages: Vec<ChatMessage>,
    /// Count of unread incoming messages (cleared when the conversation is
    /// the selected one).
    pub unread: usize,
}

impl Conversation {
    /// A new, empty conversation with a peer.
    pub fn new(fingerprint: String) -> Self {
        Self {
            fingerprint,
            messages: Vec::new(),
            unread: 0,
        }
    }
}

/// Clickable regions recorded by the last render, so mouse hit-testing lives
/// in the reducer (geometry only — [`Rect`] is plain data, not a terminal
/// handle). The *inner* (content) area of each list is stored, so a click row
/// maps directly to an item index.
#[derive(Default, Clone, Copy)]
pub struct Regions {
    /// Inner area of the conversation list.
    pub conversations: Option<Rect>,
    /// Inner area of the peer list.
    pub peers: Option<Rect>,
    /// Area of the compose line.
    pub input: Option<Rect>,
}

/// Network/identity summary shown in the status pane and bar.
#[derive(Default)]
pub struct StatusInfo {
    /// Our libp2p peer id (base58), once known.
    pub peer_id: String,
    /// Our bound listen addresses.
    pub listen_addrs: Vec<String>,
    /// Number of currently discovered peers.
    pub peer_count: usize,
}

/// The whole interactive state.
pub struct AppState {
    /// Our handle, `nick#fingerprint`, once `Whoami` resolves.
    pub own_handle: String,
    /// Current interaction mode.
    pub mode: Mode,
    /// Focused pane in normal mode.
    pub focus: Focus,
    /// Layout chosen from the last known terminal size.
    pub layout: Layout,
    /// Open conversations, in most-recently-active-first order.
    pub conversations: Vec<Conversation>,
    /// Index of the selected conversation, if any.
    pub selected_conversation: Option<usize>,
    /// Discovered peers (from mDNS), most-recent-first.
    pub peers: Vec<PeerInfo>,
    /// Selected index in the peer list.
    pub selected_peer: usize,
    /// Scroll offset (in lines from the bottom) of the message area.
    pub scroll: u16,
    /// Network/identity summary.
    pub status: StatusInfo,
    /// The compose buffer (zeroized on drop).
    pub input: Zeroizing<String>,
    /// Whether the help overlay is shown.
    pub show_help: bool,
    /// A transient one-line notice (e.g. "not reachable"), shown until the
    /// next action clears it.
    pub notice: Option<String>,
    /// Whether the loop should exit.
    pub should_quit: bool,
    /// Last known terminal width/height.
    pub width: u16,
    pub height: u16,
    /// Clickable regions from the last render (for mouse hit-testing).
    pub regions: Regions,
}

impl AppState {
    /// A fresh state for a terminal of the given size.
    pub fn new(width: u16, height: u16) -> Self {
        Self {
            own_handle: String::new(),
            mode: Mode::Normal,
            focus: Focus::Conversations,
            layout: Layout::from_size(width, height),
            conversations: Vec::new(),
            selected_conversation: None,
            peers: Vec::new(),
            selected_peer: 0,
            scroll: 0,
            status: StatusInfo::default(),
            input: Zeroizing::new(String::new()),
            show_help: false,
            notice: None,
            should_quit: false,
            width,
            height,
            regions: Regions::default(),
        }
    }

    /// The selected conversation, if any.
    pub fn current_conversation(&self) -> Option<&Conversation> {
        self.selected_conversation
            .and_then(|i| self.conversations.get(i))
    }

    /// Find the index of a conversation by full fingerprint.
    pub fn conversation_index(&self, fingerprint: &str) -> Option<usize> {
        self.conversations
            .iter()
            .position(|c| c.fingerprint == fingerprint)
    }

    /// Ensure a conversation exists for `fingerprint`, returning its index.
    /// A newly created conversation is appended.
    pub fn ensure_conversation(&mut self, fingerprint: &str) -> usize {
        match self.conversation_index(fingerprint) {
            Some(i) => i,
            None => {
                self.conversations
                    .push(Conversation::new(fingerprint.to_owned()));
                self.conversations.len() - 1
            }
        }
    }

    /// Abbreviate a full fingerprint to its short (handle) form for display.
    pub fn short_fingerprint(fingerprint: &str) -> &str {
        if fingerprint.len() > SHORT_FP_LEN {
            &fingerprint[..SHORT_FP_LEN]
        } else {
            fingerprint
        }
    }
}
