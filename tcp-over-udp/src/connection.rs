//! Per-connection lifecycle: handshake, stop-and-wait data transfer, teardown.
//!
//! # Architecture
//!
//! ```text
//!  Application
//!      │  send(data) / recv()
//!      ▼
//!  Connection   ←── FSM state, RTO, peer addr
//!    ├── Sender    ← sequence numbers, retransmit slot
//!    ├── Receiver  ← RCV.NXT, application buffer
//!    └── Socket    ← encode/decode, UDP I/O
//! ```
//!
//! Protocol logic (sequencing, retransmits, FSM transitions) lives here.
//! Raw I/O lives in [`crate::socket`].
//!
//! # Stop-and-Wait
//!
//! Only one segment is outstanding at a time.  The sender waits for an ACK
//! before transmitting the next segment.  On timeout the segment is
//! retransmitted with exponential back-off, up to `MAX_RETRIES` attempts.
//!
//! # 3-Way Handshake
//!
//! ```text
//!  Client                        Server
//!   │── SYN  (seq=C_ISN)  ──────▶│
//!   │◀─ SYN-ACK (seq=S_ISN,      │
//!   │          ack=C_ISN+1) ──── │
//!   │── ACK  (ack=S_ISN+1) ─────▶│
//!                            ESTABLISHED
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use tokio::time::timeout;

use crate::packet::{flags, Header, Packet};
use crate::receiver::Receiver;
use crate::sender::Sender;
use crate::socket::{Socket, SocketError};
use crate::state::ConnectionState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Initial retransmit timeout before any RTT sample.
const INITIAL_RTO: Duration = Duration::from_millis(1000);
/// RTO doubles on each timeout; never exceeds this.
const MAX_RTO: Duration = Duration::from_secs(60);
/// Number of retransmissions before giving up.
const MAX_RETRIES: u32 = 6;
/// Default advertised window (stop-and-wait; not really used for flow control).
const DEFAULT_WINDOW: u16 = 8192;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by [`Connection`] operations.
#[derive(Debug)]
pub enum ConnError {
    /// Underlying socket I/O failed.
    Socket(SocketError),
    /// No ACK received within the retransmit budget.
    MaxRetriesExceeded,
    /// Handshake did not complete (peer silent or sent RST).
    HandshakeFailed,
    /// Operation not valid in the current FSM state.
    BadState,
    /// Peer sent RST.
    Reset,
    /// Peer closed the connection (FIN received); no more data.
    Eof,
}

impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socket(e) => write!(f, "socket error: {e}"),
            Self::MaxRetriesExceeded => write!(f, "max retransmits exceeded"),
            Self::HandshakeFailed => write!(f, "handshake failed"),
            Self::BadState => write!(f, "operation invalid in current connection state"),
            Self::Reset => write!(f, "connection reset by peer"),
            Self::Eof => write!(f, "connection closed by peer"),
        }
    }
}

impl std::error::Error for ConnError {}

impl From<SocketError> for ConnError {
    fn from(e: SocketError) -> Self {
        Self::Socket(e)
    }
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

#[derive(Debug)]
/// A single reliable connection over UDP.
pub struct Connection {
    /// Current FSM state.
    pub state: ConnectionState,
    /// Outbound segment state (sequence numbers, retransmit slot).
    pub sender: Sender,
    /// Inbound delivery state (RCV.NXT, application buffer).
    pub receiver: Receiver,
    /// Packet-oriented UDP socket.
    socket: Socket,
    /// Remote peer address.
    peer: SocketAddr,
    /// Current retransmit timeout (doubles on each miss, resets on ACK).
    rto: Duration,
}

impl Connection {
    // -----------------------------------------------------------------------
    // Internal constructor
    // -----------------------------------------------------------------------

    fn established(socket: Socket, peer: SocketAddr, isn: u32, peer_isn: u32) -> Self {
        Self {
            state: ConnectionState::Established,
            // SYN consumed one sequence number; data starts at ISN+1.
            sender: Sender::new(isn),
            receiver: Receiver::new(peer_isn.wrapping_add(1)),
            socket,
            peer,
            rto: INITIAL_RTO,
        }
    }

    // -----------------------------------------------------------------------
    // Handshake — active open (client)
    // -----------------------------------------------------------------------

    /// Initiate an active open to `peer`.
    ///
    /// Sends SYN, waits for SYN-ACK, sends ACK.  Retransmits the SYN up to
    /// `MAX_RETRIES` times on timeout.
    pub async fn connect(socket: Socket, peer: SocketAddr) -> Result<Self, ConnError> {
        let isn = rand_isn();
        let syn = make_syn(isn);
        let mut rto = INITIAL_RTO;

        for attempt in 0..=MAX_RETRIES {
            socket.send_to(&syn, peer).await?;
            log::debug!("[client] → SYN seq={isn} (attempt {attempt})");

            // Wait for SYN-ACK.
            'wait: loop {
                match timeout(rto, socket.recv_from()).await {
                    Ok(Ok((pkt, from))) => {
                        if from != peer {
                            continue 'wait; // datagram from unknown source
                        }
                        let h = &pkt.header;
                        let is_syn_ack = h.flags & (flags::SYN | flags::ACK)
                            == (flags::SYN | flags::ACK);
                        if is_syn_ack && h.ack == isn.wrapping_add(1) {
                            let peer_isn = h.seq;
                            // Send ACK to complete the handshake.
                            let ack = make_ack(isn.wrapping_add(1), peer_isn.wrapping_add(1));
                            socket.send_to(&ack, peer).await?;
                            log::debug!(
                                "[client] ← SYN-ACK peer_isn={peer_isn}; → ACK"
                            );
                            return Ok(Self::established(socket, peer, isn, peer_isn));
                        }
                        // Wrong packet (e.g. stale datagram) — keep waiting.
                    }
                    Ok(Err(e)) => return Err(ConnError::Socket(e)),
                    Err(_elapsed) => {
                        // Timeout — retransmit SYN with back-off.
                        rto = (rto * 2).min(MAX_RTO);
                        break 'wait;
                    }
                }
            }
        }

        Err(ConnError::HandshakeFailed)
    }

    // -----------------------------------------------------------------------
    // Handshake — passive open (server)
    // -----------------------------------------------------------------------

    /// Accept an incoming connection on `socket`.
    ///
    /// Blocks until a SYN arrives, replies with SYN-ACK, and waits for the
    /// final ACK.  Retransmits SYN-ACK up to `MAX_RETRIES` times on timeout.
    pub async fn accept(socket: Socket) -> Result<Self, ConnError> {
        let isn = rand_isn();

        // Step 1: wait for SYN (no timeout — passive open).
        let (client_addr, client_isn) = loop {
            let (pkt, addr) = socket.recv_from().await?;
            let h = &pkt.header;
            // A pure SYN has SYN set and ACK clear.
            if h.flags & flags::SYN != 0 && h.flags & flags::ACK == 0 {
                log::debug!("[server] ← SYN seq={} from {addr}", h.seq);
                break (addr, h.seq);
            }
        };

        // Step 2: send SYN-ACK, then wait for the final ACK.
        let syn_ack = make_syn_ack(isn, client_isn.wrapping_add(1));
        let mut rto = INITIAL_RTO;

        for attempt in 0..=MAX_RETRIES {
            socket.send_to(&syn_ack, client_addr).await?;
            log::debug!("[server] → SYN-ACK seq={isn} ack={} (attempt {attempt})",
                client_isn.wrapping_add(1));

            'wait: loop {
                match timeout(rto, socket.recv_from()).await {
                    Ok(Ok((pkt, from))) => {
                        if from != client_addr {
                            continue 'wait;
                        }
                        let h = &pkt.header;
                        let is_ack = h.flags & flags::ACK != 0
                            && h.flags & flags::SYN == 0
                            && h.ack == isn.wrapping_add(1);
                        if is_ack {
                            log::debug!("[server] ← ACK — handshake complete");
                            return Ok(Self::established(
                                socket, client_addr, isn, client_isn,
                            ));
                        }
                        // Could be a retransmitted SYN — keep waiting.
                    }
                    Ok(Err(e)) => return Err(ConnError::Socket(e)),
                    Err(_elapsed) => {
                        rto = (rto * 2).min(MAX_RTO);
                        break 'wait;
                    }
                }
            }
        }

        Err(ConnError::HandshakeFailed)
    }

    // -----------------------------------------------------------------------
    // Data transfer — send
    // -----------------------------------------------------------------------

    /// Send `data` to the peer using stop-and-wait.
    ///
    /// Blocks until the peer ACKs the segment.  Retransmits up to
    /// `MAX_RETRIES` times with exponential back-off before returning
    /// [`ConnError::MaxRetriesExceeded`].
    pub async fn send(&mut self, data: &[u8]) -> Result<(), ConnError> {
        if self.state != ConnectionState::Established {
            return Err(ConnError::BadState);
        }

        let packet = self.sender.build_data_packet(
            data.to_vec(),
            self.receiver.ack_number(),
            self.receiver.window_size(),
        );
        self.sender.record_sent(packet);
        let mut rto = self.rto;

        for _attempt in 0..=MAX_RETRIES {
            // Clone the in-flight packet for the send call (can't hold &self.sender
            // across the await while also mutating self later).
            let in_flight = self.sender.unacked.as_ref().unwrap().packet.clone();
            self.socket.send_to(&in_flight, self.peer).await?;
            log::debug!("→ DATA seq={} len={}", in_flight.header.seq, data.len());

            // Wait for an ACK.
            'wait: loop {
                match timeout(rto, self.socket.recv_from()).await {
                    Ok(Ok((pkt, addr))) => {
                        if addr != self.peer {
                            continue 'wait;
                        }
                        if pkt.header.flags & flags::ACK != 0
                            && self.sender.on_ack(pkt.header.ack)
                        {
                            // Our segment was acknowledged.
                            log::debug!("← ACK ack={}", pkt.header.ack);
                            self.rto = INITIAL_RTO; // reset after success
                            return Ok(());
                        }
                        // May be a data segment from the peer arriving while we
                        // wait; ACK it so their stop-and-wait doesn't stall.
                        if !pkt.payload.is_empty() {
                            self.receiver.on_segment(pkt.header.seq, &pkt.payload);
                            let ack = self.make_ack();
                            let _ = self.socket.send_to(&ack, self.peer).await;
                        }
                    }
                    Ok(Err(e)) => return Err(ConnError::Socket(e)),
                    Err(_elapsed) => {
                        // Timeout — retransmit with back-off.
                        rto = (rto * 2).min(MAX_RTO);
                        self.sender.on_retransmit();
                        log::debug!(
                            "timeout — retransmitting (count={})",
                            self.sender.retransmit_count()
                        );
                        break 'wait;
                    }
                }
            }
        }

        Err(ConnError::MaxRetriesExceeded)
    }

    // -----------------------------------------------------------------------
    // Data transfer — receive
    // -----------------------------------------------------------------------

    /// Receive the next in-order data chunk from the peer.
    ///
    /// Blocks until a valid segment arrives.  Duplicate or out-of-order
    /// segments are re-ACKed and discarded.  Returns [`ConnError::Eof`] when
    /// the peer sends FIN, and [`ConnError::Reset`] on RST.
    pub async fn recv(&mut self) -> Result<Vec<u8>, ConnError> {
        if self.state != ConnectionState::Established {
            return Err(ConnError::BadState);
        }

        loop {
            let (pkt, addr) = self.socket.recv_from().await?;
            if addr != self.peer {
                continue;
            }

            let h = &pkt.header;

            if h.flags & flags::RST != 0 {
                self.state = ConnectionState::Closed;
                return Err(ConnError::Reset);
            }

            if h.flags & flags::FIN != 0 {
                // FIN consumes one sequence number; ACK it.
                self.receiver.on_fin(h.seq);
                let ack = self.make_ack();
                let _ = self.socket.send_to(&ack, self.peer).await;
                self.state = ConnectionState::CloseWait;
                log::debug!("← FIN seq={}; → ACK ack={}", h.seq, self.receiver.ack_number());
                return Err(ConnError::Eof);
            }

            if pkt.payload.is_empty() {
                // Pure ACK (e.g. from our own previous send) — ignore.
                continue;
            }

            let accepted = self.receiver.on_segment(h.seq, &pkt.payload);
            let ack = self.make_ack();
            self.socket.send_to(&ack, self.peer).await?;
            log::debug!(
                "← DATA seq={} len={} accepted={}; → ACK ack={}",
                h.seq,
                pkt.payload.len(),
                accepted,
                self.receiver.ack_number()
            );

            if accepted {
                // Drain the application buffer into an owned Vec.
                let mut buf = vec![0u8; self.receiver.app_buffer.len()];
                let n = self.receiver.read(&mut buf);
                buf.truncate(n);
                return Ok(buf);
            }
            // Duplicate/out-of-order: re-ACKed above; wait for the right one.
        }
    }

    // -----------------------------------------------------------------------
    // Teardown
    // -----------------------------------------------------------------------

    /// Initiate a graceful close (send FIN, wait for ACK).
    ///
    /// After this call the connection transitions to `Closed` and the socket
    /// is no longer usable.
    pub async fn close(&mut self) -> Result<(), ConnError> {
        if matches!(self.state, ConnectionState::Closed) {
            return Ok(());
        }

        let fin = Packet {
            header: Header {
                seq: self.sender.next_seq,
                ack: self.receiver.ack_number(),
                flags: flags::FIN | flags::ACK,
                window: self.receiver.window_size(),
                checksum: 0,
            },
            payload: vec![],
        };
        let mut rto = self.rto;

        for _attempt in 0..=MAX_RETRIES {
            self.socket.send_to(&fin, self.peer).await?;
            log::debug!("→ FIN seq={}", fin.header.seq);
            self.state = ConnectionState::FinWait1;

            match timeout(rto, self.socket.recv_from()).await {
                Ok(Ok((pkt, addr))) if addr == self.peer => {
                    if pkt.header.flags & flags::ACK != 0
                        && pkt.header.ack == fin.header.seq.wrapping_add(1)
                    {
                        log::debug!("← ACK of FIN — connection closed");
                        self.state = ConnectionState::Closed;
                        return Ok(());
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(ConnError::Socket(e)),
                Err(_elapsed) => {
                    rto = (rto * 2).min(MAX_RTO);
                }
            }
        }

        // Force-close after exhausting retries.
        log::warn!("FIN not ACKed; force-closing");
        self.state = ConnectionState::Closed;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Decomposition
    // -----------------------------------------------------------------------

    /// Consume this connection and return its internal components.
    ///
    /// Intended for upgrading a stop-and-wait [`Connection`] (after the
    /// 3-way handshake) to a higher-level protocol layer such as
    /// [`crate::gbn_connection::GbnConnection`].
    ///
    /// Returns `(state, socket, peer, next_seq, rcv_nxt, rto)`.
    pub fn into_parts(
        self,
    ) -> (
        ConnectionState,
        Socket,
        SocketAddr,
        u32,  // sender.next_seq
        u32,  // receiver.rcv_nxt
        Duration,
    ) {
        (
            self.state,
            self.socket,
            self.peer,
            self.sender.next_seq,
            self.receiver.rcv_nxt,
            self.rto,
        )
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a pure ACK packet reflecting current send/receive state.
    fn make_ack(&self) -> Packet {
        Packet {
            header: Header {
                seq: self.sender.next_seq,
                ack: self.receiver.ack_number(),
                flags: flags::ACK,
                window: self.receiver.window_size(),
                checksum: 0,
            },
            payload: vec![],
        }
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Generate a pseudo-random Initial Sequence Number from the system clock.
///
/// No external crate required; good enough for testing.  Production code
/// should use a cryptographically secure source (RFC 6528).
fn rand_isn() -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut h);
    // Mix in the thread ID for uniqueness when many connections open at once.
    std::thread::current().id().hash(&mut h);
    h.finish() as u32
}

/// Pure SYN packet (active open, no ACK).
fn make_syn(isn: u32) -> Packet {
    Packet {
        header: Header {
            seq: isn,
            ack: 0,
            flags: flags::SYN,
            window: DEFAULT_WINDOW,
            checksum: 0,
        },
        payload: vec![],
    }
}

/// SYN-ACK packet (passive open response).
fn make_syn_ack(seq: u32, ack: u32) -> Packet {
    Packet {
        header: Header {
            seq,
            ack,
            flags: flags::SYN | flags::ACK,
            window: DEFAULT_WINDOW,
            checksum: 0,
        },
        payload: vec![],
    }
}

/// Pure ACK packet (handshake completion or data acknowledgement).
fn make_ack(seq: u32, ack: u32) -> Packet {
    Packet {
        header: Header {
            seq,
            ack,
            flags: flags::ACK,
            window: DEFAULT_WINDOW,
            checksum: 0,
        },
        payload: vec![],
    }
}
