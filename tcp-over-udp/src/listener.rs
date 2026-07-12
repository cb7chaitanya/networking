//! Listen backlog with SYN flood protection.
//!
//! # Architecture
//!
//! ```text
//!  Incoming SYN
//!      │
//!      ▼
//!  Listener ── syn_queue (bounded) ── half-open entries
//!      │
//!      │  handle_ack()
//!      ▼
//!  established_queue ──▶ accept() ──▶ Connection
//! ```
//!
//! SYN flood protection is achieved by simply dropping SYNs when the
//! half-open queue is full — no per-SYN state is allocated beyond the
//! backlog limit.

use std::collections::VecDeque;
use std::net::SocketAddr;

use tokio::sync::mpsc;

use crate::connection::{Connection, DEFAULT_WINDOW_SCALE};
use crate::packet::{TcpOption, Packet, DEFAULT_MSS};
use crate::socket::Socket;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ListenerError {
    /// The internal established-connection channel was closed unexpectedly.
    ChannelClosed,
}

impl std::fmt::Display for ListenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChannelClosed => write!(f, "listener channel closed"),
        }
    }
}

impl std::error::Error for ListenerError {}

// ---------------------------------------------------------------------------
// Half-open entry
// ---------------------------------------------------------------------------

/// State stored for a SYN that has been received but not yet ACKed.
struct HalfOpen {
    /// Remote address that sent the SYN.
    peer: SocketAddr,
    /// ISN advertised by the client in the SYN.
    client_isn: u32,
    /// ISN we chose for our SYN-ACK.
    server_isn: u32,
    /// MSS negotiated during the SYN exchange.
    negotiated_mss: u16,
    /// Our window-scale shift (None if scaling not negotiated).
    snd_wscale: Option<u8>,
    /// Peer's window-scale shift (None if scaling not negotiated).
    rcv_wscale: Option<u8>,
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

/// A passive-open listener with a bounded SYN backlog.
///
/// # Usage
///
/// ```ignore
/// let socket = Socket::bind("127.0.0.1:8080".parse().unwrap()).await?;
/// let mut listener = Listener::new(socket, /* backlog */ 128);
///
/// // Drive from an I/O loop:
/// listener.handle_syn(syn_packet, client_addr);
/// listener.handle_ack(ack_packet, client_addr);
///
/// // Block until a fully established Connection is ready:
/// let conn = listener.accept().await?;
/// ```
pub struct Listener {
    /// Shared UDP socket (must be Clone — backed by Arc internally).
    socket: Socket,
    /// Maximum number of half-open connections allowed simultaneously.
    backlog: usize,
    /// Half-open connections: SYN received, SYN-ACK sent, waiting for ACK.
    syn_queue: VecDeque<HalfOpen>,
    /// Producer side of the established-connection channel.
    established_tx: mpsc::UnboundedSender<Connection>,
    /// Consumer side — drained by `accept()`.
    established_rx: mpsc::UnboundedReceiver<Connection>,
}

impl Listener {
    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /// Create a new `Listener` wrapping `socket` with the given `backlog` limit.
    ///
    /// `backlog` is the maximum number of *half-open* connections that may
    /// be queued simultaneously.  Any SYN that arrives when the queue is
    /// full is silently dropped (SYN flood protection).
    pub fn new(socket: Socket, backlog: usize) -> Self {
        let (established_tx, established_rx) = mpsc::unbounded_channel();
        Self {
            socket,
            backlog,
            syn_queue: VecDeque::new(),
            established_tx,
            established_rx,
        }
    }

    // -----------------------------------------------------------------------
    // SYN handling
    // -----------------------------------------------------------------------

    /// Process an incoming SYN packet from `peer`.
    ///
    /// If the half-open queue is at capacity the packet is **silently
    /// dropped** — this is the primary SYN-flood defence: no state is
    /// allocated, so an attacker cannot exhaust memory by sending many SYNs.
    pub fn handle_syn(&mut self, packet: Packet, peer: SocketAddr) {
        // Backlog full → drop, do not allocate any state.
        if self.syn_queue.len() >= self.backlog {
            log::debug!("[listener] SYN from {peer} dropped — backlog full ({}/{})", self.syn_queue.len(), self.backlog);
            return;
        }

        let client_isn = packet.header.seq;
        let server_isn = rand_isn();
        let peer_mss = extract_mss(&packet.options).unwrap_or(DEFAULT_MSS);
        let negotiated_mss = DEFAULT_MSS.min(peer_mss);
        let (snd_wscale, rcv_wscale) = match extract_window_scale(&packet.options) {
            Some(peer_shift) => (Some(DEFAULT_WINDOW_SCALE), Some(peer_shift)),
            None => (None, None),
        };

        log::debug!(
            "[listener] SYN from {peer} seq={client_isn} mss={peer_mss} \
             → queued (server_isn={server_isn}, negotiated_mss={negotiated_mss})"
        );

        self.syn_queue.push_back(HalfOpen {
            peer,
            client_isn,
            server_isn,
            negotiated_mss,
            snd_wscale,
            rcv_wscale,
        });
    }

    // -----------------------------------------------------------------------
    // ACK handling
    // -----------------------------------------------------------------------

    /// Process an incoming ACK packet from `peer`.
    ///
    /// If a matching half-open entry exists for `peer`, it is removed from
    /// the SYN queue and a fully [`Established`][crate::state::ConnectionState]
    /// [`Connection`] is pushed onto the accept queue.
    ///
    /// Unknown ACKs (no matching half-open entry) are silently ignored.
    pub fn handle_ack(&mut self, _packet: Packet, peer: SocketAddr) {
        let Some(pos) = self.syn_queue.iter().position(|e| e.peer == peer) else {
            log::debug!("[listener] ACK from {peer} — no matching half-open entry, ignoring");
            return;
        };

        let entry = self.syn_queue.remove(pos).unwrap();

        log::debug!(
            "[listener] ACK from {peer} — promoting to Established \
             (server_isn={}, client_isn={})",
            entry.server_isn,
            entry.client_isn
        );

        let conn = Connection::established_with_mss(
            self.socket.clone(),
            entry.peer,
            entry.server_isn,
            entry.client_isn,
            entry.negotiated_mss,
            entry.snd_wscale,
            entry.rcv_wscale,
        );

        // If the receiver has already dropped, the connection is simply lost.
        let _ = self.established_tx.send(conn);
    }

    // -----------------------------------------------------------------------
    // Accept
    // -----------------------------------------------------------------------

    /// Return the next fully established [`Connection`].
    ///
    /// Awaits asynchronously until one is available.
    pub async fn accept(&mut self) -> Result<Connection, ListenerError> {
        self.established_rx
            .recv()
            .await
            .ok_or(ListenerError::ChannelClosed)
    }

    // -----------------------------------------------------------------------
    // Introspection (used by tests)
    // -----------------------------------------------------------------------

    /// Number of half-open connections currently waiting for the final ACK.
    pub fn syn_queue_len(&self) -> usize {
        self.syn_queue.len()
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Pseudo-random ISN from the system clock (same approach as `connection.rs`).
fn rand_isn() -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut h);
    std::thread::current().id().hash(&mut h);
    h.finish() as u32
}

/// Extract the MSS value from an options list, if present.
fn extract_mss(options: &[TcpOption]) -> Option<u16> {
    options.iter().find_map(|o| {
        if let TcpOption::Mss(m) = o {
            Some(*m)
        } else {
            None
        }
    })
}

/// Extract the WindowScale shift from an options list, if present.
fn extract_window_scale(options: &[TcpOption]) -> Option<u8> {
    options.iter().find_map(|o| {
        if let TcpOption::WindowScale(shift) = o {
            Some((*shift).min(14))
        } else {
            None
        }
    })
}