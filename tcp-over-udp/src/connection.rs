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
//! # 3-Way Handshake with MSS Negotiation
//!
//! ```text
//!  Client                              Server
//!   │── SYN  (seq=C_ISN,  MSS=X) ──▶│
//!   │◀─ SYN-ACK (seq=S_ISN,          │
//!   │          ack=C_ISN+1, MSS=Y) ──│
//!   │── ACK  (ack=S_ISN+1)  ────────▶│
//!                               ESTABLISHED
//!            negotiated_mss = min(X, Y)
//! ```
//!
//! The MSS option is carried in the TCP-style options area that immediately
//! follows the fixed 15-byte header on SYN / SYN-ACK packets.  Peers that
//! predate this extension ignore the SYN payload, so the negotiation is
//! fully backward-compatible.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::time::timeout;

use crate::discovery::GossipDiscovery;
use crate::packet::{flags, Header, Packet, TcpOption, DEFAULT_MSS};
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

/// Default window scale shift count for new connections.
///
/// A shift of 7 allows windows up to 8 MiB (65535 << 7 = 8,388,480 bytes),
/// which is sufficient for most high-BDP paths.  This matches common OS
/// defaults (Linux uses 7, Windows uses 8).
pub const DEFAULT_WINDOW_SCALE: u8 = 7;

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
    /// Gossip discovery did not return a usable peer.
    DiscoveryFailed,
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
            Self::DiscoveryFailed => write!(f, "no peer available from gossip discovery"),
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
    /// MSS negotiated during the 3-way handshake: `min(local_mss, peer_mss)`.
    ///
    /// Defaults to [`DEFAULT_MSS`] when the peer does not advertise an MSS.
    pub negotiated_mss: u16,
    /// Most recent TSval received from the peer (echoed in our ACKs as TSecr).
    last_peer_tsval: u32,
    /// Window scale shift count to apply when sending our window (local shift).
    ///
    /// When advertising our receive window in outgoing packets, we must shift
    /// our true window size right by this amount: `advertised = true_window >> snd_wscale`.
    /// This is `None` if window scaling was not negotiated.
    snd_wscale: Option<u8>,
    /// Window scale shift count to apply to peer's advertised window (peer shift).
    ///
    /// When interpreting the peer's advertised window in incoming packets, we
    /// must shift left by this amount: `true_window = advertised << rcv_wscale`.
    /// This is `None` if window scaling was not negotiated.
    rcv_wscale: Option<u8>,
}

impl Connection {
    // -----------------------------------------------------------------------
    // Internal constructors
    // -----------------------------------------------------------------------

    pub(crate) fn established_with_mss(
        socket: Socket,
        peer: SocketAddr,
        isn: u32,
        peer_isn: u32,
        negotiated_mss: u16,
        snd_wscale: Option<u8>,
        rcv_wscale: Option<u8>,
    ) -> Self {
        Self {
            state: ConnectionState::Established,
            // SYN consumed one sequence number; data starts at ISN+1.
            sender: Sender::new(isn),
            receiver: Receiver::new(peer_isn.wrapping_add(1)),
            socket,
            peer,
            rto: INITIAL_RTO,
            negotiated_mss,
            last_peer_tsval: 0,
            snd_wscale,
            rcv_wscale,
        }
    }

    // -----------------------------------------------------------------------
    // Handshake — active open (client)
    // -----------------------------------------------------------------------

    /// Initiate an active open to `peer` using [`DEFAULT_MSS`].
    ///
    /// Sends SYN (with MSS option), waits for SYN-ACK, sends ACK.
    /// Retransmits the SYN up to `MAX_RETRIES` times on timeout.
    pub async fn connect(socket: Socket, peer: SocketAddr) -> Result<Self, ConnError> {
        Self::connect_with_mss(socket, peer, DEFAULT_MSS).await
    }

    /// Discover a peer via gossip and then perform an active open.
    pub async fn connect_via_discovery(
        socket: Socket,
        discovery: &GossipDiscovery,
    ) -> Result<Self, ConnError> {
        let peer = discovery.pick_peer().ok_or(ConnError::DiscoveryFailed)?;
        Self::connect(socket, peer).await
    }

    /// Like [`connect`] but with an explicit local MSS to advertise.
    ///
    /// The negotiated MSS is `min(local_mss, peer_mss)`.  When the peer does
    /// not advertise an MSS (backward-compatible peer), `peer_mss` is taken
    /// as [`DEFAULT_MSS`].
    ///
    /// This function also advertises window scaling with [`DEFAULT_WINDOW_SCALE`].
    /// Window scaling is enabled only if the peer also includes a WindowScale
    /// option in the SYN-ACK (per RFC 7323).
    ///
    /// [`connect`]: Self::connect
    pub async fn connect_with_mss(
        socket: Socket,
        peer: SocketAddr,
        local_mss: u16,
    ) -> Result<Self, ConnError> {
      let isn = rand_isn();
      let tsval = now_tsval();
      let local_wscale = DEFAULT_WINDOW_SCALE;
      let syn = make_syn_with_opts(
        isn,
        &[
          TcpOption::Mss(local_mss),
          TcpOption::WindowScale(local_wscale),
          TcpOption::Timestamp(tsval, 0),
        ],
      );
      let mut rto = INITIAL_RTO;
      
      for attempt in 0..=MAX_RETRIES {
            socket.send_to(&syn, peer).await?;
            log::debug!(
                "[client] → SYN seq={isn} mss={local_mss} wscale={local_wscale} (attempt {attempt})"
            );

            // Wait for SYN-ACK.
            'wait: loop {
                match timeout(rto, socket.recv_from()).await {
                    Ok(Ok((pkt, from))) => {
                        if from != peer {
                            continue 'wait;
                        }
                        let h = &pkt.header;
                        let is_syn_ack = h.flags & (flags::SYN | flags::ACK)
                            == (flags::SYN | flags::ACK);
                        if is_syn_ack && h.ack == isn.wrapping_add(1) {
                            let peer_isn = h.seq;
                            let peer_mss = extract_mss(&pkt.options).unwrap_or(DEFAULT_MSS);
                            let negotiated = local_mss.min(peer_mss);
                            let peer_tsval = extract_tsval(&pkt.options).unwrap_or(0);
                            if let Some(tsecr) = extract_tsecr(&pkt.options) {
                                let rtt = Duration::from_millis(now_tsval().wrapping_sub(tsecr) as u64);
                                log::debug!("[client] RTT sample from timestamp: {rtt:?}");
                            }
                            // snd_wscale = our shift (for outgoing window advertisements)
                            // rcv_wscale = peer's shift (for interpreting peer's window)
                            let (snd_wscale, rcv_wscale) =
                                match extract_window_scale(&pkt.options) {
                                    Some(peer_shift) => (Some(local_wscale), Some(peer_shift)),
                                    None => (None, None),
                                };

                            // Send ACK to complete the handshake.
                            let ack =
                                make_ack(isn.wrapping_add(1), peer_isn.wrapping_add(1));
                            socket.send_to(&ack, peer).await?;
                            log::debug!(
                                "[client] ← SYN-ACK peer_isn={peer_isn} peer_mss={peer_mss} \
                                 negotiated_mss={negotiated} snd_wscale={snd_wscale:?} \
                                 rcv_wscale={rcv_wscale:?}; → ACK"
                            );
                            let mut conn = Self::established_with_mss(
                              socket,
                              peer,
                              isn,
                              peer_isn,
                              negotiated,
                              snd_wscale,
                              rcv_wscale,
                          );
                          conn.last_peer_tsval = peer_tsval;
                          return Ok(conn);
                        }
                        // Wrong packet — keep waiting.
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
    // Handshake — passive open (server)
    // -----------------------------------------------------------------------

    /// Accept an incoming connection on `socket` using [`DEFAULT_MSS`].
    ///
    /// Blocks until a SYN arrives, replies with SYN-ACK (carrying own MSS),
    /// and waits for the final ACK.  Retransmits SYN-ACK up to `MAX_RETRIES`
    /// times on timeout.
    pub async fn accept(socket: Socket) -> Result<Self, ConnError> {
        Self::accept_with_mss(socket, DEFAULT_MSS).await
    }

    /// Like [`accept`] but with an explicit local MSS to advertise.
    ///
    /// This function also supports window scaling (RFC 7323).  If the client's
    /// SYN includes a WindowScale option, the server replies with its own
    /// WindowScale in the SYN-ACK.  Window scaling is enabled only if both
    /// sides include the option.
    ///
    /// [`accept`]: Self::accept
    pub async fn accept_with_mss(
        socket: Socket,
        local_mss: u16,
    ) -> Result<Self, ConnError> {
        let isn = rand_isn();
        let local_wscale = DEFAULT_WINDOW_SCALE;

        // Step 1: wait for SYN (no timeout — passive open).
        let (client_addr, client_isn, peer_mss, peer_wscale, client_tsval) = loop {
          let (pkt, addr) = socket.recv_from().await?;
          let h = &pkt.header;
          let client_tsval = extract_tsval(&pkt.options).unwrap_or(0);

          if h.flags & flags::SYN != 0 && h.flags & flags::ACK == 0 {
            let peer_mss = extract_mss(&pkt.options).unwrap_or(DEFAULT_MSS);
            let peer_wscale = extract_window_scale(&pkt.options);

            log::debug!(
              "[server] ← SYN seq={} peer_mss={peer_mss} peer_wscale={peer_wscale:?} from {addr}",
              h.seq
            );

            break (addr, h.seq, peer_mss, peer_wscale, client_tsval);
          }
      };

        let negotiated = local_mss.min(peer_mss);

        // Step 2: send SYN-ACK (advertising our own MSS), then wait for final ACK.
        // Window scaling: echo back our scale only if client sent one.
        // server must not send WindowScale unless client did.
        let (snd_wscale, rcv_wscale, syn_ack_opts) = match peer_wscale {
          Some(peer_shift) => (
            Some(local_wscale),
            Some(peer_shift),
            vec![
              TcpOption::Mss(local_mss),
              TcpOption::WindowScale(local_wscale),
              TcpOption::Timestamp(now_tsval(), client_tsval),
            ],
          ),
          None => (
            None,
            None,
            vec![
              TcpOption::Mss(local_mss),
              TcpOption::Timestamp(now_tsval(), client_tsval),
            ],
          ),
      };

        // Step 2: send SYN-ACK (advertising our own MSS and optionally WindowScale),
        // then wait for final ACK.
        let syn_ack = make_syn_ack_with_opts(isn, client_isn.wrapping_add(1), &syn_ack_opts);
        let mut rto = INITIAL_RTO;

        for attempt in 0..=MAX_RETRIES {
            socket.send_to(&syn_ack, client_addr).await?;
            log::debug!(
                "[server] → SYN-ACK seq={isn} ack={} mss={local_mss} negotiated={negotiated} \
                 snd_wscale={snd_wscale:?} rcv_wscale={rcv_wscale:?} (attempt {attempt})",
                client_isn.wrapping_add(1)
            );

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
                            log::debug!(
                                "[server] ← ACK — handshake complete negotiated_mss={negotiated} \
                                 snd_wscale={snd_wscale:?} rcv_wscale={rcv_wscale:?}"
                            );
                            let ack_tsval = extract_tsval(&pkt.options).unwrap_or(0);
                            let mut conn = Self::established_with_mss(
                              socket,
                              client_addr,
                              isn,
                              client_isn,
                              negotiated,
                              snd_wscale,
                              rcv_wscale,
                          );
                          conn.last_peer_tsval = ack_tsval;
                          return Ok(conn);
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
                            let ack = Self::make_ack(self);
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
                let ack = Self::make_ack(self);
                let _ = self.socket.send_to(&ack, self.peer).await;
                self.state = ConnectionState::CloseWait;
                log::debug!("← FIN seq={}; → ACK ack={}", h.seq, self.receiver.ack_number());
                return Err(ConnError::Eof);
            }

            if pkt.payload.is_empty() {
                // Pure ACK (e.g. from our own previous send) — ignore.
                continue;
            }

            if let Some(tsval) = extract_tsval(&pkt.options) {
                self.last_peer_tsval = tsval;
            }

            let accepted = self.receiver.on_segment(h.seq, &pkt.payload);
            let ack = Self::make_ack(self);
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
            options: vec![],
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
    // Abort (RST)
    // -----------------------------------------------------------------------

    /// Abort the connection immediately by sending RST.
    ///
    /// Transitions to `Closed` without the graceful FIN handshake.  The peer
    /// will observe [`ConnError::Reset`] on its next socket operation.
    pub async fn abort(&mut self) -> Result<(), ConnError> {
        if matches!(self.state, ConnectionState::Closed) {
            return Ok(());
        }
        let rst = Packet {
            header: Header {
                seq: self.sender.next_seq,
                ack: 0,
                flags: flags::RST,
                window: 0,
                checksum: 0,
            },
            options: vec![],
            payload: vec![],
        };
        self.socket.send_to(&rst, self.peer).await?;
        log::debug!("→ RST (abort) seq={}", rst.header.seq);
        self.state = ConnectionState::Closed;
        Ok(())
    }
    // Window Scale Accessors
    // -----------------------------------------------------------------------

    /// Returns the local window scale shift count (`snd_wscale`).
    ///
    /// This is used when advertising our receive window in outgoing packets:
    /// `advertised = true_window >> snd_wscale`.
    ///
    /// Returns `None` if window scaling was not negotiated.
    pub fn snd_wscale(&self) -> Option<u8> {
        self.snd_wscale
    }

    /// Returns the peer's window scale shift count (`rcv_wscale`).
    ///
    /// This is used when interpreting the peer's advertised window:
    /// `true_window = advertised << rcv_wscale`.
    ///
    /// Returns `None` if window scaling was not negotiated.
    pub fn rcv_wscale(&self) -> Option<u8> {
        self.rcv_wscale
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
    /// Returns `(state, socket, peer, next_seq, rcv_nxt, rto, negotiated_mss, snd_wscale, rcv_wscale)`.
    ///
    /// # Window scale factors
    ///
    /// - `snd_wscale`: Our local shift count, used when advertising our receive
    ///   window in outgoing packets (`advertised = true_window >> snd_wscale`).
    /// - `rcv_wscale`: Peer's shift count, used when interpreting the peer's
    ///   advertised window (`true_window = advertised << rcv_wscale`).
    ///
    /// Both are `None` if window scaling was not negotiated (peer did not
    /// include WindowScale option in SYN/SYN-ACK).
    pub fn into_parts(
        self,
    ) -> (
        ConnectionState,
        Socket,
        SocketAddr,
        u32,         // sender.next_seq
        u32,         // receiver.rcv_nxt
        Duration,    // rto
        u16,         // negotiated_mss
        Option<u8>,  // snd_wscale
        Option<u8>,  // rcv_wscale
    ) {
        (
            self.state,
            self.socket,
            self.peer,
            self.sender.next_seq,
            self.receiver.rcv_nxt,
            self.rto,
            self.negotiated_mss,
            self.snd_wscale,
            self.rcv_wscale,
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
            options: vec![TcpOption::Timestamp(now_tsval(), self.last_peer_tsval)],
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

/// Extract the MSS value from a parsed options list.
///
/// Returns `None` when no MSS option is present (backward-compatible peer).
fn extract_mss(options: &[TcpOption]) -> Option<u16> {
    options.iter().find_map(|o| {
        if let TcpOption::Mss(m) = o {
            Some(*m)
        } else {
            None
        }
    })
}

/// Returns a millisecond timestamp for use as TSval.
/// Wraps at u32::MAX — matches RFC 1323 behaviour.
fn now_tsval() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u32
}

fn extract_tsval(options: &[TcpOption]) -> Option<u32> {
    options.iter().find_map(|o| {
        if let TcpOption::Timestamp(tsval, _) = o { Some(*tsval) } else { None }
    })
}

fn extract_tsecr(options: &[TcpOption]) -> Option<u32> {
    options.iter().find_map(|o| {
        if let TcpOption::Timestamp(_, tsecr) = o {
            Some(*tsecr)
        } else {
            None
        }
    })
}
/// Extract the window scale shift count from a parsed options list.
///
/// Returns `None` when no WindowScale option is present (peer does not
/// support RFC 7323 window scaling).  The shift count is clamped to 14
/// per RFC 7323 §2.3.
fn extract_window_scale(options: &[TcpOption]) -> Option<u8> {
    options.iter().find_map(|o| {
        if let TcpOption::WindowScale(shift) = o {
            // RFC 7323: shift counts > 14 are treated as 14.
            Some((*shift).min(14))
        } else {
            None
        }
    })
}

/// SYN packet with TCP-style options (active open).
fn make_syn_with_opts(isn: u32, opts: &[TcpOption]) -> Packet {
    Packet {
        header: Header {
            seq: isn,
            ack: 0,
            flags: flags::SYN,
            window: DEFAULT_WINDOW,
            checksum: 0,
        },
        options: opts.to_vec(),
        payload: vec![],
    }
}

/// SYN-ACK packet with TCP-style options (passive open response).
fn make_syn_ack_with_opts(seq: u32, ack: u32, opts: &[TcpOption]) -> Packet {
    Packet {
        header: Header {
            seq,
            ack,
            flags: flags::SYN | flags::ACK,
            window: DEFAULT_WINDOW,
            checksum: 0,
        },
        options: opts.to_vec(),
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
        options: vec![],
        payload: vec![],
    }
}
