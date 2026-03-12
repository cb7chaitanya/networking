//! Go-Back-N connection: handshake + GBN data transfer + adaptive RTO.
//!
//! # Architecture
//!
//! ```text
//!  Application
//!      │  send(data) / recv()         GbnSession (concurrent mode)
//!      │                               ┌─────────────────────┐
//!      │  ─── or ───────────────────▶  │  send_tx (channel)  │
//!      │                               │  recv_rx (channel)  │
//!      ▼                               └──────────┬──────────┘
//!  GbnConnection                                  │ event_loop task
//!    ├── GbnSender    (sliding window, seq nums)  │
//!    ├── GbnReceiver  (cumulative ACKs, app buf)  │
//!    ├── RttEstimator (adaptive RTO via RFC 6298) │
//!    └── Arc<Socket>  (shared with background task)┘
//! ```
//!
//! # RTT estimation
//!
//! Every ACK is routed through [`GbnConnection::on_ack_received`], which:
//!
//! 1. Calls [`GbnSender::on_ack`] to slide the window and optionally obtain
//!    a raw RTT sample (via [`AckResult::rtt_sample`]).
//! 2. If the sample is `Some` (segment was never retransmitted — Karn's
//!    algorithm is enforced inside `GbnSender`), feeds it into
//!    [`RttEstimator::record_sample`].
//! 3. On timeout, calls [`RttEstimator::back_off`] to double the RTO.
//!
//! The retransmit timer uses `rtt.rto()` instead of a fixed constant,
//! so it shrinks as the estimator observes short round trips.
//!
//! # Two usage modes
//!
//! **Sequential** — call `send` / `recv` / `flush` directly:
//! ```ignore
//! let mut conn = GbnConnection::connect(socket, peer, 4).await?;
//! conn.send(b"hello").await?;
//! let reply = conn.recv().await?;
//! conn.close().await?;
//! ```
//!
//! **Concurrent** — spawn a background event loop via `run()`:
//! ```ignore
//! let mut session = GbnConnection::connect(socket, peer, 4).await?.run();
//! session.send_tx.send(b"msg1".to_vec()).await.unwrap();
//! let data = session.recv().await?;
//! session.close().await;
//! ```

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::congestion_control::{CongestionControl, RenoCC};
use crate::connection::{ConnError, Connection};
use crate::gbn_receiver::GbnReceiver;
use crate::gbn_sender::{AckResult, GbnSender};
use crate::packet::{flags, Header, Packet, SackBlock, TcpOption};
use crate::persist_timer::PersistTransition;
use crate::rtt::RttEstimator;
use crate::socket::Socket;
use crate::state::ConnectionState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_RETRIES: u32 = 6;

/// Default Maximum Segment Lifetime used for `TIME_WAIT` (2 × MSL total).
///
/// Defaults to zero so that connections behave correctly in tests and demos
/// without any linger delay.  Callers that want real TIME_WAIT protection
/// call `.with_msl(Duration::from_secs(30))` (or similar) before `close()`
/// or `run()`.  Note: `#[cfg(test)]` inside a library crate is **not** set
/// for integration tests in `tests/`, so we cannot use it here.
const DEFAULT_MSL: Duration = Duration::ZERO;

/// Maximum time we linger in `FIN_WAIT_2` waiting for the peer's FIN.
/// (Linux uses 60 s; we match that.)
const FIN_WAIT_2_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// GbnConnection
// ---------------------------------------------------------------------------

/// A reliable connection using Go-Back-N sliding-window flow control with
/// adaptive retransmission timeout.
///
/// The congestion-control algorithm is a type parameter with a default of
/// [`RenoCC`] (TCP Reno).  Existing callers need no changes; callers that
/// want a different algorithm can use turbofish:
/// ```ignore
/// GbnConnection::<CubicCC>::connect(socket, peer, 4).await?
/// ```
pub struct GbnConnection<CC: CongestionControl = RenoCC> {
    /// Current FSM state.
    pub state: ConnectionState,

    /// Outbound GBN window (sequence numbers, in-flight queue).
    pub sender: GbnSender<CC>,

    /// Inbound state (cumulative ACKs, application buffer).
    pub receiver: GbnReceiver,

    /// RFC 6298 RTT estimator — tracks SRTT, RTTVAR, and the current RTO.
    ///
    /// Inspect after exchanges to observe how the RTO has adapted:
    /// ```ignore
    /// println!("SRTT={:?}  RTO={:?}", conn.rtt.srtt(), conn.rtt.rto());
    /// ```
    pub rtt: RttEstimator,

    /// Shared UDP socket.  `Arc` lets a clone be handed to the event loop.
    socket: Arc<Socket>,

    /// Remote peer address.
    peer: SocketAddr,

    /// Maximum Segment Lifetime used for the `TIME_WAIT` timer (2 × MSL total).
    /// Override with [`with_msl`] before calling `close()` or `run()`.
    ///
    /// [`with_msl`]: Self::with_msl
    msl: Duration,

    /// Negotiated Maximum Segment Size from the 3-way handshake.
    ///
    /// `send()` segments application data into chunks of at most this many
    /// bytes before queuing each chunk as an independent packet.  Set by
    /// `min(local_mss, peer_mss)` during the handshake.
    mss: u16,

    /// Window scale shift count for sending our window (local shift).
    ///
    /// When advertising our receive window, we shift right by this amount:
    /// `advertised = true_window >> snd_wscale`.  `None` if window scaling
    /// was not negotiated.
    snd_wscale: Option<u8>,

    /// Window scale shift count for interpreting peer's window (peer shift).
    ///
    /// When interpreting the peer's advertised window, we shift left:
    /// `true_window = advertised << rcv_wscale`.  `None` if window scaling
    /// was not negotiated.
    rcv_wscale: Option<u8>,
}

// Constructors use GbnSender::new() which is only available for RenoCC.
// All other methods are generic over any CongestionControl.
impl GbnConnection {
    /// Build a [`GbnConnection`] from an already-established [`Connection`].
    ///
    /// The 3-way handshake must be complete.  `window_size` sets the GBN
    /// window N.  A fresh [`RttEstimator`] is started — RTT history from
    /// the handshake is not carried over.
    ///
    /// Uses the default receive-buffer capacity (64 KiB).  For a custom
    /// capacity use [`from_connection_with_recv_buf`].
    ///
    /// [`from_connection_with_recv_buf`]: Self::from_connection_with_recv_buf
    pub fn from_connection(conn: Connection, window_size: usize) -> Self {
        Self::from_connection_with_recv_buf(conn, window_size, 65536)
    }

    /// Like [`from_connection`] but with an explicit receive-buffer capacity.
    ///
    /// Use a small `recv_buf_bytes` value in tests to exercise flow control
    /// with limited buffer space.
    ///
    /// [`from_connection`]: Self::from_connection
    pub fn from_connection_with_recv_buf(
        conn: Connection,
        window_size: usize,
        recv_buf_bytes: usize,
    ) -> Self {
        let (state, socket, peer, next_seq, rcv_nxt, _rto, negotiated_mss, snd_wscale, rcv_wscale) =
            conn.into_parts();
        Self {
            state,
            socket: Arc::new(socket),
            peer,
            sender: GbnSender::new(next_seq, window_size),
            receiver: GbnReceiver::with_capacity(rcv_nxt, recv_buf_bytes),
            rtt: RttEstimator::new(),
            msl: DEFAULT_MSL,
            mss: negotiated_mss,
            snd_wscale,
            rcv_wscale,
        }
    }

    /// Active open (client): run the 3-way handshake then return a GBN connection.
    ///
    /// Uses the default receive-buffer capacity (64 KiB).
    pub async fn connect(
        socket: Socket,
        peer: SocketAddr,
        window_size: usize,
    ) -> Result<Self, ConnError> {
        let conn = Connection::connect(socket, peer).await?;
        Ok(Self::from_connection(conn, window_size))
    }

    /// Like [`connect`] but with an explicit receive-buffer capacity.
    ///
    /// [`connect`]: Self::connect
    pub async fn connect_with_recv_buf(
        socket: Socket,
        peer: SocketAddr,
        window_size: usize,
        recv_buf_bytes: usize,
    ) -> Result<Self, ConnError> {
        let conn = Connection::connect(socket, peer).await?;
        Ok(Self::from_connection_with_recv_buf(conn, window_size, recv_buf_bytes))
    }

    /// Passive open (server): accept one incoming connection and return GBN.
    ///
    /// Uses the default receive-buffer capacity (64 KiB).
    pub async fn accept(socket: Socket, window_size: usize) -> Result<Self, ConnError> {
        let conn = Connection::accept(socket).await?;
        Ok(Self::from_connection(conn, window_size))
    }

    /// Like [`accept`] but with an explicit receive-buffer capacity.
    ///
    /// [`accept`]: Self::accept
    pub async fn accept_with_recv_buf(
        socket: Socket,
        window_size: usize,
        recv_buf_bytes: usize,
    ) -> Result<Self, ConnError> {
        let conn = Connection::accept(socket).await?;
        Ok(Self::from_connection_with_recv_buf(conn, window_size, recv_buf_bytes))
    }
}

impl<CC: CongestionControl> GbnConnection<CC> {
    /// The Maximum Segment Size negotiated during the 3-way handshake.
    ///
    /// Data passed to [`send`] is split into chunks of at most this many bytes.
    ///
    /// [`send`]: Self::send
    pub fn mss(&self) -> u16 {
        self.mss
    }

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

    /// Override the Maximum Segment Lifetime used for `TIME_WAIT`.
    ///
    /// The connection lingers in `TIME_WAIT` for `2 × msl` after the active
    /// close completes, absorbing stale segments that might otherwise corrupt a
    /// subsequent connection on the same port.
    ///
    /// ```ignore
    /// let conn = GbnConnection::connect(sock, peer, 4).await?.with_msl(Duration::from_secs(30));
    /// ```
    pub fn with_msl(mut self, msl: Duration) -> Self {
        self.msl = msl;
        self
    }

    /// Enable or disable Nagle write-coalescing (RFC 896).
    ///
    /// When `enabled` is `true`, small writes passed to [`send`] are buffered
    /// until either the buffer reaches one MSS **or** no data is currently in
    /// flight.  When `false` (the default), every [`send`] call transmits its
    /// payload immediately as a separate segment (`TCP_NODELAY` semantics).
    ///
    /// **Interaction with other operations:**
    /// - [`flush`] and [`close`] always force-drain the Nagle buffer before
    ///   blocking, so no data is ever silently stuck.
    /// - [`recv`], when called while the Nagle buffer is non-empty, also
    ///   force-drains it first to prevent request/response deadlock.
    ///
    /// [`send`]: Self::send
    /// [`flush`]: Self::flush
    /// [`close`]: Self::close
    /// [`recv`]: Self::recv
    pub fn with_nagle(mut self, enabled: bool) -> Self {
        self.sender.set_nagle(enabled);
        self
    }

    // -----------------------------------------------------------------------
    // Window scaling helpers
    // -----------------------------------------------------------------------

    /// Scale the peer's advertised window using the negotiated `rcv_wscale`.
    ///
    /// When window scaling is enabled, the 16-bit window field in incoming
    /// packets represents `true_window >> peer_shift`.  This method applies
    /// the reverse transformation: `true_window = advertised << rcv_wscale`.
    ///
    /// When window scaling is not negotiated (`rcv_wscale` is `None`), the
    /// raw header value is returned unchanged (as `usize`).
    #[inline]
    fn scale_peer_window(&self, advertised: u16) -> usize {
        match self.rcv_wscale {
            Some(shift) => (advertised as usize) << shift,
            None => advertised as usize,
        }
    }

    /// Scale our receive window for advertisement in outgoing packets.
    ///
    /// When window scaling is enabled, we must shift our true receive window
    /// right by `snd_wscale` before placing it in the 16-bit header field:
    /// `advertised = true_window >> snd_wscale`.
    ///
    /// When window scaling is not negotiated, the window is clamped to 65535
    /// (the maximum 16-bit value).
    #[inline]
    fn scale_our_window(&self, true_window: usize) -> u16 {
        match self.snd_wscale {
            Some(shift) => {
                let scaled = true_window >> shift;
                // Clamp to u16::MAX in case of overflow (defensive).
                scaled.min(u16::MAX as usize) as u16
            }
            None => true_window.min(u16::MAX as usize) as u16,
        }
    }

    // -----------------------------------------------------------------------
    // Sequential data transfer
    // -----------------------------------------------------------------------

    /// Send `data` to the peer, segmenting into MSS-sized chunks as needed.
    ///
    /// Data larger than the negotiated MSS is automatically split into
    /// multiple segments, each queued separately through the GBN window.
    /// Empty slices produce a single zero-length segment (matching existing
    /// test expectations).
    ///
    /// **Pipeline pattern**: call `send` in a tight loop to fill the window,
    /// then call [`flush`] to wait for all in-flight segments to be ACKed.
    ///
    /// [`flush`]: Self::flush
    pub async fn send(&mut self, data: &[u8]) -> Result<(), ConnError> {
        if self.state != ConnectionState::Established {
            return Err(ConnError::BadState);
        }

        let mss = self.mss as usize;

        if data.is_empty() {
            // Preserve existing behaviour for zero-length sends.
            return self.send_segment(data).await;
        }

        // Push data through the Nagle buffer.
        //
        // When Nagle is disabled (default), `nagle_push` returns MSS-sized
        // chunks immediately — identical to the previous `data.chunks(mss)` loop.
        // When Nagle is enabled, sub-MSS writes may be held until the pipe
        // empties or a full segment accumulates.
        let ready = self.sender.nagle_push(data, mss);
        for seg in ready {
            self.send_segment(&seg).await?;
            // After `send_segment` blocks and returns, ACKs may have been
            // processed and the pipe may now be empty.  Pump the Nagle buffer
            // so any coalesced data held while the pipe was busy is released.
            for more in self.sender.nagle_pump(mss) {
                self.send_segment(&more).await?;
            }
        }
        Ok(())
    }

    /// Queue one pre-sized segment for delivery (internal).
    ///
    /// Blocks — processing incoming ACKs and retransmitting on timeout — when
    /// the window is full.  The caller is responsible for MSS-sized chunking.
    async fn send_segment(&mut self, data: &[u8]) -> Result<(), ConnError> {
        let mut rto = self.rtt.rto();
        let mut retries = 0u32;

        // Wait until the window has room, processing inbound packets meanwhile.
        while !self.sender.can_send() {
            // Persist timer drives the sleep when stalled on rwnd==0;
            // the retransmit RTO governs in all other cases.
            let timeout = if self.sender.persist.is_active() {
                self.sender.persist.interval()
            } else {
                rto
            };
            let sleep = tokio::time::sleep(timeout);
            tokio::pin!(sleep);

            tokio::select! {
                result = self.socket.recv_from() => {
                    let (pkt, addr) = result?;
                    match self.process_incoming(pkt, addr).await {
                        Ok(window_advanced) => {
                            if window_advanced {
                                // RTT estimator already updated in process_incoming.
                                rto = self.rtt.rto();
                                retries = 0;
                            }
                            // persist state is updated inside process_incoming
                            // (via update_peer_rwnd); no extra work needed here.
                        }
                        Err(e) => return Err(e),
                    }
                }
                _ = &mut sleep => {
                    if self.sender.persist.is_active() {
                        // Flow-control stall: probe without CC penalty.
                        // Persist probes do NOT count against retries.
                        self.probe_zero_window().await?;
                        self.sender.persist.on_probe_sent();
                        log::debug!(
                            "[gbn] persist probe #{} next={:?}",
                            self.sender.persist.probe_count(),
                            self.sender.persist.interval()
                        );
                    } else {
                        // Selective Repeat: retransmit only the oldest segment.
                        retries += 1;
                        if retries > MAX_RETRIES {
                            return Err(ConnError::MaxRetriesExceeded);
                        }
                        self.retransmit_oldest_pkt().await?;
                        self.sender.on_timeout_cc();
                        self.rtt.back_off();
                        rto = self.rtt.rto();
                        log::debug!(
                            "[gbn] SR timeout #{} — rto={:?} cwnd={}",
                            retries, rto, self.sender.cwnd()
                        );
                    }
                }
            }
        }

        // Send the new segment (with scaled window if negotiated).
        let pkt = self.sender.build_data_packet(
            data.to_vec(),
            self.receiver.ack_number(),
            self.scale_our_window(self.receiver.window_size()),
        );
        self.socket.send_to(&pkt, self.peer).await?;
        self.sender.record_sent(pkt);
        log::debug!(
            "[gbn] → DATA seq={} len={} in_flight={}",
            self.sender.next_seq.wrapping_sub(data.len() as u32),
            data.len(),
            self.sender.in_flight()
        );
        Ok(())
    }

    /// Receive the next in-order data chunk from the peer.
    ///
    /// Blocks until a valid in-order segment arrives.  Out-of-order segments
    /// are re-ACKed with the cumulative ACK and discarded (GBN semantics).
    /// Piggybacked ACKs are fed into the RTT estimator as they arrive.
    /// Returns [`ConnError::Eof`] on FIN.
    pub async fn recv(&mut self) -> Result<Vec<u8>, ConnError> {
        // Drain previously buffered data first (no need to flush Nagle when
        // there's already data ready to return to the caller).
        if !self.receiver.app_buffer.is_empty() {
            return Ok(self.drain_app_buffer());
        }

        // About to block waiting for the peer.  Force-drain the Nagle buffer
        // so the peer receives any pending data before we wait for its reply.
        // This prevents request/response deadlock when the caller does:
        //   send(small_request)   → held by Nagle
        //   recv()                → blocks here, peer never receives request
        if let Some(buffered) = self.sender.nagle_force_flush() {
            let mss = self.mss as usize;
            for chunk in buffered.chunks(mss) {
                self.send_segment(chunk).await?;
            }
        }

        loop {
            let (pkt, addr) = self.socket.recv_from().await?;
            if addr != self.peer {
                continue;
            }

            let h = &pkt.header;

            // RST received → abort immediately.
            if h.flags & flags::RST != 0 {
                self.state = ConnectionState::Closed;
                return Err(ConnError::Reset);
            }

            // Unexpected SYN in a synchronised state → half-open detection.
            if is_unexpected_syn(h.flags, self.state) {
                let rst = build_rst_for(&pkt);
                let _ = self.socket.send_to(&rst, self.peer).await;
                log::debug!("[gbn] recv: ← unexpected SYN in {:?}; → RST", self.state);
                self.state = ConnectionState::Closed;
                return Err(ConnError::Reset);
            }

            // Sequence number validation for data segments.
            if !pkt.payload.is_empty() && !self.receiver.is_seq_plausible(h.seq) {
                let rst = build_rst_for(&pkt);
                let _ = self.socket.send_to(&rst, self.peer).await;
                log::debug!(
                    "[gbn] recv: ← implausible seq={} (rcv_nxt={}); → RST",
                    h.seq,
                    self.receiver.ack_number()
                );
                self.state = ConnectionState::Closed;
                return Err(ConnError::Reset);
            }

            if h.flags & flags::FIN != 0 {
                self.receiver.on_fin(h.seq);
                let ack = self.make_ack_pkt();
                let _ = self.socket.send_to(&ack, self.peer).await;
                self.state = ConnectionState::CloseWait;
                log::debug!("[gbn] ← FIN; → ACK ack={}", self.receiver.ack_number());
                return Err(ConnError::Eof);
            }

            // Piggybacked ACK: slide window, update RTT and congestion control.
            if h.flags & flags::ACK != 0 {
                let sack_blocks = extract_sack_blocks(&pkt);
                let n = self.on_ack_received(h.ack, h.window, &sack_blocks);
                if n > 0 {
                    log::debug!(
                        "[gbn] ← ACK ack={} slid={} srtt={:?} rto={:?} peer_rwnd={}",
                        h.ack, n, self.rtt.srtt(), self.rtt.rto(), self.sender.peer_rwnd()
                    );
                }
                // Reno fast retransmit on 3 consecutive duplicate ACKs.
                if self.sender.dup_ack_count() == 3 {
                    self.sender.on_triple_dup_ack_cc();
                    self.fast_retransmit().await.ok();
                }
            }

            if pkt.payload.is_empty() {
                continue; // pure ACK
            }

            let accepted = self.receiver.on_segment(h.seq, &pkt.payload);
            let ack = self.make_ack_pkt();
            self.socket.send_to(&ack, self.peer).await?;
            log::debug!(
                "[gbn] ← DATA seq={} len={} accepted={}; → ACK ack={}",
                h.seq,
                pkt.payload.len(),
                accepted,
                self.receiver.ack_number()
            );

            if accepted {
                return Ok(self.drain_app_buffer());
            }
        }
    }

    /// Drain the send window: block until all in-flight segments are ACKed.
    ///
    /// Uses the adaptive RTO for timeouts; performs Go-Back-N retransmit on
    /// each expiry and doubles the RTO (exponential back-off).
    pub async fn flush(&mut self) -> Result<(), ConnError> {
        // Force-drain any Nagle-buffered data before waiting for the send
        // window to drain.  Without this, a caller that writes small chunks
        // and then calls flush() would block forever if Nagle is holding the
        // last sub-MSS write.
        if let Some(buffered) = self.sender.nagle_force_flush() {
            let mss = self.mss as usize;
            for chunk in buffered.chunks(mss) {
                self.send_segment(chunk).await?;
            }
        }

        let mut rto = self.rtt.rto();
        let mut retries = 0u32;

        while self.sender.has_unacked() {
            // Use persist interval when stalled on rwnd==0; RTO otherwise.
            let timeout = if self.sender.persist.is_active() {
                self.sender.persist.interval()
            } else {
                rto
            };
            let sleep = tokio::time::sleep(timeout);
            tokio::pin!(sleep);

            tokio::select! {
                result = self.socket.recv_from() => {
                    let (pkt, addr) = result?;
                    match self.process_incoming(pkt, addr).await {
                        Ok(window_advanced) => {
                            if window_advanced {
                                rto = self.rtt.rto();
                                retries = 0;
                            }
                        }
                        Err(ConnError::Eof) => break,
                        Err(e) => return Err(e),
                    }
                }
                _ = &mut sleep => {
                    if self.sender.persist.is_active() {
                        // Flow-control stall: probe without CC penalty.
                        // Persist probes do NOT count against retries.
                        self.probe_zero_window().await?;
                        self.sender.persist.on_probe_sent();
                        log::debug!(
                            "[gbn] flush persist probe #{} next={:?}",
                            self.sender.persist.probe_count(),
                            self.sender.persist.interval()
                        );
                    } else {
                        // Selective Repeat: retransmit only the oldest segment.
                        retries += 1;
                        if retries > MAX_RETRIES {
                            return Err(ConnError::MaxRetriesExceeded);
                        }
                        self.retransmit_oldest_pkt().await?;
                        self.sender.on_timeout_cc();
                        self.rtt.back_off();
                        rto = self.rtt.rto();
                        log::debug!(
                            "[gbn] SR flush timeout #{} — rto={:?} cwnd={}",
                            retries, rto, self.sender.cwnd()
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Graceful close: flush pending data, then perform the full TCP teardown.
    ///
    /// # State machine
    ///
    /// **Active closer** (called from `Established`):
    /// ```text
    /// Established → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT (2×MSL) → Closed
    /// ```
    /// A combined FIN+ACK from the peer collapses FIN_WAIT_1 + FIN_WAIT_2 into
    /// a direct transition to TIME_WAIT.  A simultaneous FIN takes the Closing
    /// path (RFC 793 §3.5).
    ///
    /// **Passive closer** (called from `CloseWait`, after `recv()` returned `Eof`):
    /// ```text
    /// CloseWait → LAST_ACK → Closed   (no TIME_WAIT)
    /// ```
    pub async fn close(&mut self) -> Result<(), ConnError> {
        if matches!(self.state, ConnectionState::Closed) {
            return Ok(());
        }

        // Passive-close path: peer already sent FIN; we just need to send ours.
        if matches!(self.state, ConnectionState::CloseWait) {
            return self.close_passive().await;
        }

        // Active-close path (state == Established).
        match self.flush().await {
            Ok(()) | Err(ConnError::Eof) => {}
            Err(e) => return Err(e),
        }

        let fin_seq = self.sender.next_seq;
        let fin = Packet {
            header: Header {
                seq: fin_seq,
                ack: self.receiver.ack_number(),
                flags: flags::FIN | flags::ACK,
                window: self.scale_our_window(self.receiver.window_size()),
                checksum: 0,
            },
            options: vec![],
            payload: vec![],
        };
        let mut rto = self.rtt.rto();

        // ── Phase 1: FIN_WAIT_1 ────────────────────────────────────────────
        // Transmit our FIN and wait for a reply.  Three outcomes:
        //   a) ACK covers our FIN → FIN_WAIT_2
        //   b) FIN+ACK (combined) → TIME_WAIT directly
        //   c) FIN only (simultaneous close) → Closing
        let mut fin_acked = false;
        'fw1: for _attempt in 0..=MAX_RETRIES {
            self.socket.send_to(&fin, self.peer).await?;
            self.state = ConnectionState::FinWait1;
            log::debug!("[gbn] active close → FIN_WAIT_1; → FIN seq={}", fin_seq);

            match timeout(rto, self.socket.recv_from()).await {
                Ok(Ok((pkt, addr))) if addr == self.peer => {
                    let h = &pkt.header;

                    if h.flags & flags::RST != 0 {
                        log::debug!("[gbn] FIN_WAIT_1 ← RST → CLOSED");
                        self.state = ConnectionState::Closed;
                        return Ok(());
                    }

                    let acks_our_fin = h.flags & flags::ACK != 0
                        && h.ack == fin_seq.wrapping_add(1);
                    let has_fin = h.flags & flags::FIN != 0;

                    if acks_our_fin && has_fin {
                        // FIN+ACK: peer closed simultaneously with ACKing ours.
                        // → TIME_WAIT directly (skip FIN_WAIT_2).
                        self.receiver.on_fin(h.seq);
                        let ack = self.make_ack_pkt();
                        let _ = self.socket.send_to(&ack, self.peer).await;
                        log::debug!("[gbn] FIN_WAIT_1 ← FIN+ACK → TIME_WAIT");
                        self.state = ConnectionState::TimeWait;
                        self.do_time_wait(ack).await;
                        self.state = ConnectionState::Closed;
                        return Ok(());
                    }

                    if acks_our_fin {
                        // Normal path: our FIN was ACKed; wait for peer's FIN.
                        log::debug!("[gbn] FIN_WAIT_1 ← ACK of FIN → FIN_WAIT_2");
                        self.state = ConnectionState::FinWait2;
                        fin_acked = true;
                        break 'fw1;
                    }

                    if has_fin {
                        // Simultaneous close: peer sent FIN before ACKing ours.
                        self.receiver.on_fin(h.seq);
                        let ack = self.make_ack_pkt();
                        let _ = self.socket.send_to(&ack, self.peer).await;
                        log::debug!("[gbn] FIN_WAIT_1 ← simultaneous FIN → CLOSING");
                        self.state = ConnectionState::Closing;
                        return self.close_from_closing(fin_seq, rto).await;
                    }
                }
                Ok(Ok(_)) => {} // wrong peer or unexpected packet
                Ok(Err(e)) => return Err(ConnError::Socket(e)),
                Err(_elapsed) => {
                    self.rtt.back_off();
                    rto = self.rtt.rto();
                }
            }
        }

        if !fin_acked {
            log::warn!("[gbn] FIN not ACKed after {} retries; force-closing", MAX_RETRIES);
            self.state = ConnectionState::Closed;
            return Ok(());
        }

        // ── Phase 2: FIN_WAIT_2 ────────────────────────────────────────────
        // Wait for the peer's FIN.  A 60 s deadline guards against a peer that
        // never sends its FIN (e.g. crashed after ACKing ours).
        let last_ack = match timeout(FIN_WAIT_2_TIMEOUT, self.recv_peer_fin_in_fw2()).await {
            Ok(Ok(ack)) => ack,
            Ok(Err(e)) => return Err(e),
            Err(_elapsed) => {
                log::warn!("[gbn] FIN_WAIT_2 timed out; force-closing");
                self.state = ConnectionState::Closed;
                return Ok(());
            }
        };

        // ── Phase 3: TIME_WAIT ─────────────────────────────────────────────
        self.state = ConnectionState::TimeWait;
        self.do_time_wait(last_ack).await;
        self.state = ConnectionState::Closed;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Abort (RST)
    // -----------------------------------------------------------------------

    /// Abort the connection immediately by sending RST.
    ///
    /// Transitions to `Closed` without the graceful FIN handshake.  Any data
    /// in the send/receive buffers is discarded.  The peer will observe
    /// [`ConnError::Reset`] on its next socket operation.
    pub async fn abort(&mut self) -> Result<(), ConnError> {
        if matches!(self.state, ConnectionState::Closed) {
            return Ok(());
        }
        let rst = build_rst_from(&self.sender);
        self.socket.send_to(&rst, self.peer).await?;
        log::debug!("[gbn] → RST (abort) seq={}", rst.header.seq);
        self.state = ConnectionState::Closed;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Concurrent mode
    // -----------------------------------------------------------------------

    /// Spawn a background event loop and return a [`GbnSession`] handle.
    ///
    /// The event loop multiplexes outbound data (from `send_tx`), inbound
    /// packets, and adaptive retransmit timeouts with `tokio::select!`.
    pub fn run(self) -> GbnSession {
        let (send_tx, send_rx) = mpsc::channel::<Vec<u8>>(64);
        let (recv_tx, recv_rx) = mpsc::channel::<Result<Vec<u8>, ConnError>>(64);

        let handle = tokio::spawn(event_loop(
            self.socket,
            self.peer,
            self.sender,
            self.receiver,
            self.rtt,
            send_rx,
            recv_tx,
            self.msl,
            self.mss as usize,
            self.snd_wscale,
            self.rcv_wscale,
        ));

        GbnSession {
            send_tx,
            recv_rx,
            handle,
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Process a cumulative ACK: slide the window, update peer rwnd, RTT, and
    /// congestion control.  Returns the number of newly-acked segments so
    /// callers know whether the window has opened.
    ///
    /// This centralises all ACK handling so that every code path — `send`,
    /// `flush`, `recv`, and the event loop — updates the flow-control state,
    /// the RTT estimator, and the Reno congestion window.
    ///
    /// The `peer_rwnd` parameter is the raw 16-bit window from the header;
    /// window scaling (if negotiated) is applied internally.
    fn on_ack_received(&mut self, ack_num: u32, peer_rwnd: u16, sack_blocks: &[SackBlock]) -> usize {
        let AckResult { acked_count, rtt_sample, dup_ack: _ } = self.sender.on_ack(ack_num);
        // Apply SACK information so the sender knows which segments are already
        // held by the receiver and can skip them on retransmission.
        self.sender.process_sack(sack_blocks);
        // Always update the peer's advertised receive window, even for dup-ACKs,
        // because the window field in the ACK reflects the peer's current buffer.
        // Apply window scaling if negotiated.
        // PersistTransition is managed by callers that own the timer futures.
        let scaled_rwnd = self.scale_peer_window(peer_rwnd);
        let _ = self.sender.update_peer_rwnd(scaled_rwnd);
        if let Some(sample) = rtt_sample {
            self.rtt.record_sample(sample);
            log::debug!(
                "[gbn] RTT sample={:?} srtt={:?} rttvar={:?} rto={:?}",
                sample,
                self.rtt.srtt(),
                self.rtt.rttvar(),
                self.rtt.rto()
            );
        }
        if acked_count > 0 {
            self.sender.on_ack_cc(acked_count);
            log::debug!(
                "[gbn] cwnd={} peer_rwnd={}",
                self.sender.cwnd(),
                self.sender.peer_rwnd()
            );
        }
        acked_count
    }

    /// Send a zero-window probe to elicit an updated `rwnd` from the peer.
    ///
    /// Called when the send timeout fires but `peer_rwnd == 0` (a flow-control
    /// stall rather than congestion).  Retransmitting data causes the peer to
    /// respond with a fresh ACK that carries its current buffer size.
    ///
    /// When there are no in-flight segments (the last batch was ACKed just as
    /// the peer's buffer filled) a pure ACK is sent instead; this keeps the
    /// peer's socket alive and may prompt it to re-advertise its window.
    async fn probe_zero_window(&self) -> Result<(), ConnError> {
        if let Some(pkt) = self.sender.window_entries().next().map(|e| e.packet.clone()) {
            log::debug!("[gbn] zero-window probe seq={}", pkt.header.seq);
            self.socket.send_to(&pkt, self.peer).await?;
        } else {
            // No unacked segments — send a pure ACK as a keepalive probe.
            let ack = self.make_ack_pkt();
            log::debug!("[gbn] zero-window keepalive (empty window)");
            self.socket.send_to(&ack, self.peer).await?;
        }
        Ok(())
    }

    /// Retransmit the oldest unsacked segment (Reno fast retransmit).
    ///
    /// Called after 3 consecutive duplicate ACKs have been detected.
    /// Delegates to [`GbnSender::retransmit_oldest`] which skips any entries
    /// already covered by a SACK block and increments `tx_count` to suppress
    /// the RTT sample on the next ACK (Karn's algorithm).
    async fn fast_retransmit(&mut self) -> Result<(), ConnError> {
        if let Some(pkt) = self.sender.retransmit_oldest() {
            log::debug!("[gbn] fast-retransmit seq={}", pkt.header.seq);
            self.socket.send_to(&pkt, self.peer).await?;
        }
        Ok(())
    }

    /// Handle one incoming packet: dispatch ACK, data payload, FIN, RST.
    ///
    /// Returns `Ok(true)` when the send window advanced (useful for callers
    /// waiting to send more data).
    async fn process_incoming(
        &mut self,
        pkt: Packet,
        addr: SocketAddr,
    ) -> Result<bool, ConnError> {
        if addr != self.peer {
            return Ok(false);
        }

        let h = &pkt.header;
        let mut window_advanced = false;

        // RST received → abort immediately.
        if h.flags & flags::RST != 0 {
            self.state = ConnectionState::Closed;
            return Err(ConnError::Reset);
        }

        // Unexpected SYN in a synchronised state → half-open detection.
        if is_unexpected_syn(h.flags, self.state) {
            let rst = build_rst_for(&pkt);
            let _ = self.socket.send_to(&rst, self.peer).await;
            log::debug!("[gbn] ← unexpected SYN in {:?}; → RST", self.state);
            self.state = ConnectionState::Closed;
            return Err(ConnError::Reset);
        }

        // Sequence number validation: reject segments with wildly implausible
        // seq values (likely from a stale or spoofed connection).
        if !pkt.payload.is_empty() && !self.receiver.is_seq_plausible(h.seq) {
            let rst = build_rst_for(&pkt);
            let _ = self.socket.send_to(&rst, self.peer).await;
            log::debug!(
                "[gbn] ← implausible seq={} (rcv_nxt={}); → RST",
                h.seq,
                self.receiver.ack_number()
            );
            self.state = ConnectionState::Closed;
            return Err(ConnError::Reset);
        }

        if h.flags & flags::FIN != 0 {
            self.receiver.on_fin(h.seq);
            let ack = self.make_ack_pkt();
            let _ = self.socket.send_to(&ack, self.peer).await;
            self.state = ConnectionState::CloseWait;
            return Err(ConnError::Eof);
        }

        if h.flags & flags::ACK != 0 {
            let sack_blocks = extract_sack_blocks(&pkt);
            let newly_acked = self.on_ack_received(h.ack, h.window, &sack_blocks);
            window_advanced = newly_acked > 0;

            // Reno fast retransmit: 3 consecutive duplicate ACKs signal loss.
            if self.sender.dup_ack_count() == 3 {
                self.sender.on_triple_dup_ack_cc();
                self.fast_retransmit().await.ok();
            }
        }

        if !pkt.payload.is_empty() {
            let accepted = self.receiver.on_segment(h.seq, &pkt.payload);
            let ack = self.make_ack_pkt();
            let _ = self.socket.send_to(&ack, self.peer).await;
            if accepted {
                log::debug!(
                    "[gbn] ← DATA seq={} len={} buffered",
                    h.seq,
                    pkt.payload.len()
                );
            }
        }

        Ok(window_advanced)
    }

    fn make_ack_pkt(&self) -> Packet {
        let sack_blocks = self.receiver.sack_blocks();
        let options = if sack_blocks.is_empty() {
            vec![]
        } else {
            vec![TcpOption::Sack(sack_blocks)]
        };
        Packet {
            header: Header {
                seq: self.sender.next_seq,
                ack: self.receiver.ack_number(),
                flags: flags::ACK, // OPT is auto-set by encode() when options is non-empty
                window: self.scale_our_window(self.receiver.window_size()),
                checksum: 0,
            },
            options,
            payload: vec![],
        }
    }

    fn drain_app_buffer(&mut self) -> Vec<u8> {
        let mut buf = vec![0u8; self.receiver.app_buffer.len()];
        let n = self.receiver.read(&mut buf);
        buf.truncate(n);
        buf
    }

    /// Selective Repeat timeout helper: retransmit only the oldest in-flight
    /// segment and mark it so Karn's algorithm suppresses its RTT sample.
    async fn retransmit_oldest_pkt(&mut self) -> Result<(), ConnError> {
        if let Some(pkt) = self.sender.retransmit_oldest() {
            log::debug!("[gbn] SR retransmit oldest seq={}", pkt.header.seq);
            self.socket.send_to(&pkt, self.peer).await?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Active-close helpers
    // -----------------------------------------------------------------------

    /// Passive-close path (entry state = `CloseWait`): send our FIN and wait
    /// for the peer to ACK it.  No TIME_WAIT — the passive closer goes directly
    /// to `Closed` per RFC 793.
    async fn close_passive(&mut self) -> Result<(), ConnError> {
        let fin = Packet {
            header: Header {
                seq: self.sender.next_seq,
                ack: self.receiver.ack_number(),
                flags: flags::FIN | flags::ACK,
                window: self.scale_our_window(self.receiver.window_size()),
                checksum: 0,
            },
            options: vec![],
            payload: vec![],
        };
        let fin_seq = fin.header.seq;
        let mut rto = self.rtt.rto();
        self.state = ConnectionState::LastAck;
        log::debug!("[gbn] passive close → LAST_ACK; → FIN seq={}", fin_seq);

        for _attempt in 0..=MAX_RETRIES {
            self.socket.send_to(&fin, self.peer).await?;

            match timeout(rto, self.socket.recv_from()).await {
                Ok(Ok((pkt, addr))) if addr == self.peer => {
                    if pkt.header.flags & flags::RST != 0 {
                        log::debug!("[gbn] passive close ← RST → CLOSED");
                        self.state = ConnectionState::Closed;
                        return Ok(());
                    }
                    if pkt.header.flags & flags::ACK != 0
                        && pkt.header.ack == fin_seq.wrapping_add(1)
                    {
                        log::debug!("[gbn] passive close ← ACK of FIN → CLOSED");
                        self.state = ConnectionState::Closed;
                        return Ok(());
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(ConnError::Socket(e)),
                Err(_elapsed) => {
                    self.rtt.back_off();
                    rto = self.rtt.rto();
                }
            }
        }

        log::warn!("[gbn] passive close: FIN not ACKed; force-closing");
        self.state = ConnectionState::Closed;
        Ok(())
    }

    /// `FIN_WAIT_2`: consume incoming packets until the peer sends its FIN.
    ///
    /// Stray ACKs and data segments are processed normally (updating the RTT
    /// estimator and ACKing data) so that the peer can finish flushing.  Returns
    /// the ACK packet we sent in response to the peer's FIN; that packet becomes
    /// `last_ack` for the subsequent `TIME_WAIT` phase.
    async fn recv_peer_fin_in_fw2(&mut self) -> Result<Packet, ConnError> {
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

            if is_unexpected_syn(h.flags, self.state) {
                let rst = build_rst_for(&pkt);
                let _ = self.socket.send_to(&rst, self.peer).await;
                log::debug!("[gbn] FIN_WAIT_2 ← unexpected SYN; → RST");
                self.state = ConnectionState::Closed;
                return Err(ConnError::Reset);
            }

            if h.flags & flags::FIN != 0 {
                self.receiver.on_fin(h.seq);
                let ack = self.make_ack_pkt();
                let _ = self.socket.send_to(&ack, self.peer).await;
                log::debug!(
                    "[gbn] FIN_WAIT_2 ← FIN seq={} → ACK ack={} → TIME_WAIT",
                    h.seq,
                    self.receiver.ack_number()
                );
                return Ok(ack);
            }

            // Piggybacked ACK or stray cumulative ACK.
            if h.flags & flags::ACK != 0 {
                let sack_blocks = extract_sack_blocks(&pkt);
                self.on_ack_received(h.ack, h.window, &sack_blocks);
            }

            // Data segment: the peer might still be sending before it closes.
            if !pkt.payload.is_empty() {
                self.receiver.on_segment(h.seq, &pkt.payload);
                let ack = self.make_ack_pkt();
                let _ = self.socket.send_to(&ack, self.peer).await;
            }
        }
    }

    /// `TIME_WAIT`: linger for 2×MSL, absorbing any stale or duplicate packets.
    ///
    /// - Duplicate FINs are re-ACKed using `last_ack` (the packet already sent).
    /// - All other segments are silently discarded.
    /// - `biased` polling ensures the timer fires on schedule even under packet
    ///   storms; TIME_WAIT cannot be extended by incoming traffic.
    async fn do_time_wait(&self, last_ack: Packet) {
        let two_msl = 2 * self.msl;
        let timer = tokio::time::sleep(two_msl);
        tokio::pin!(timer);
        log::debug!("[gbn] TIME_WAIT start; 2×MSL={:?}", two_msl);

        loop {
            tokio::select! {
                biased;
                _ = &mut timer => {
                    log::debug!("[gbn] TIME_WAIT expired → CLOSED");
                    break;
                }
                result = self.socket.recv_from() => {
                    if let Ok((pkt, addr)) = result {
                        if addr == self.peer && pkt.header.flags & flags::FIN != 0 {
                            log::debug!("[gbn] TIME_WAIT: re-ACK duplicate FIN");
                            let _ = self.socket.send_to(&last_ack, self.peer).await;
                        }
                        // All other segments: silently discard.
                    }
                }
            }
        }
    }

    /// Simultaneous-close path (entry state = `Closing`): wait for the peer's
    /// ACK of our FIN, then enter TIME_WAIT.
    async fn close_from_closing(&mut self, fin_seq: u32, mut rto: Duration) -> Result<(), ConnError> {
        log::debug!("[gbn] simultaneous close → CLOSING; waiting for ACK of our FIN");

        for _attempt in 0..=MAX_RETRIES {
            match timeout(rto, self.socket.recv_from()).await {
                Ok(Ok((pkt, addr))) if addr == self.peer => {
                    if pkt.header.flags & flags::RST != 0 {
                        log::debug!("[gbn] CLOSING ← RST → CLOSED");
                        self.state = ConnectionState::Closed;
                        return Ok(());
                    }
                    if pkt.header.flags & flags::ACK != 0
                        && pkt.header.ack == fin_seq.wrapping_add(1)
                    {
                        log::debug!("[gbn] CLOSING ← ACK of FIN → TIME_WAIT");
                        self.state = ConnectionState::TimeWait;
                        let ack = self.make_ack_pkt();
                        self.do_time_wait(ack).await;
                        self.state = ConnectionState::Closed;
                        return Ok(());
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(ConnError::Socket(e)),
                Err(_elapsed) => {
                    self.rtt.back_off();
                    rto = self.rtt.rto();
                }
            }
        }

        log::warn!("[gbn] CLOSING: ACK of FIN not received; force-closing");
        self.state = ConnectionState::Closed;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// GbnSession — concurrent handle
// ---------------------------------------------------------------------------

/// Handle returned by [`GbnConnection::run`] for concurrent send/receive.
pub struct GbnSession {
    /// Send data to the remote peer.
    pub send_tx: mpsc::Sender<Vec<u8>>,

    /// Receive data from the remote peer.
    pub recv_rx: mpsc::Receiver<Result<Vec<u8>, ConnError>>,

    handle: JoinHandle<()>,
}

impl GbnSession {
    /// Push a payload to the peer (non-blocking when channel has capacity).
    pub async fn send(&self, data: Vec<u8>) -> Result<(), ConnError> {
        self.send_tx.send(data).await.map_err(|_| ConnError::Reset)
    }

    /// Pull the next chunk from the peer.  Returns [`ConnError::Eof`] on close.
    pub async fn recv(&mut self) -> Result<Vec<u8>, ConnError> {
        self.recv_rx.recv().await.unwrap_or(Err(ConnError::Eof))
    }

    /// Close the session: drop `send_tx` (signals FIN) and await the task.
    pub async fn close(self) {
        drop(self.send_tx);
        let _ = self.handle.await;
    }
}

// ---------------------------------------------------------------------------
// Background event loop (concurrent mode)
// ---------------------------------------------------------------------------

async fn event_loop<CC: CongestionControl>(
    socket: Arc<Socket>,
    peer: SocketAddr,
    mut sender: GbnSender<CC>,
    mut receiver: GbnReceiver,
    mut rtt: RttEstimator,
    mut app_rx: mpsc::Receiver<Vec<u8>>,
    app_tx: mpsc::Sender<Result<Vec<u8>, ConnError>>,
    msl: Duration,
    mss: usize,
    snd_wscale: Option<u8>,
    rcv_wscale: Option<u8>,
) {
    // Window scaling helpers (closures capturing the negotiated shift counts).
    let scale_peer_window = |advertised: u16| -> usize {
        match rcv_wscale {
            Some(shift) => (advertised as usize) << shift,
            None => advertised as usize,
        }
    };
    let scale_our_window = |true_window: usize| -> u16 {
        match snd_wscale {
            Some(shift) => {
                let scaled = true_window >> shift;
                scaled.min(u16::MAX as usize) as u16
            }
            None => true_window.min(u16::MAX as usize) as u16,
        }
    };

    let mut rto = rtt.rto();
    let mut retries = 0u32;

    let far_future = Duration::from_secs(365 * 24 * 3600);

    // ── Retransmit timer ─────────────────────────────────────────────────────
    // Fires when the oldest in-flight segment exceeds RTO.  Only armed when
    // there is unacked data AND the peer window is open (persist not active).
    let retransmit_tmr = tokio::time::sleep(far_future);
    tokio::pin!(retransmit_tmr);
    let mut retransmit_armed = false;

    // ── Persist timer ─────────────────────────────────────────────────────────
    // Fires when peer_rwnd == 0 to send a probe and elicit a window update.
    // Only active while sender.persist.is_active() — the bool lives inside the
    // sender so that ACK processing can flip it atomically with peer_rwnd.
    let persist_tmr = tokio::time::sleep(far_future);
    tokio::pin!(persist_tmr);

    // Staging queue: holds segments ready to send when the window is shut
    // or when Nagle has coalesced multiple writes into a batch.  Replaces
    // the previous single-slot `Option<Vec<u8>>` so that `nagle_push` can
    // return multiple segments (e.g. when data > MSS) without losing them.
    let mut staged: VecDeque<Vec<u8>> = VecDeque::new();

    // Pending payload: holds a single payload received from the app channel
    // when the staging queue is not empty.  This decouples channel closure
    // detection from flow-control gating: we always poll the channel (to see
    // `None`), but we only consume `Some(payload)` when staging is empty.
    // When staging is non-empty and we receive `Some(payload)`, we stash it
    // here and stop polling until staging drains.
    let mut pending_payload: Option<Vec<u8>> = None;

    // `fin_pending` becomes true as soon as app_rx returns None (send_tx
    // dropped).  The actual FIN wire packet is sent by the drain phase once
    // the staging slot is empty and all in-flight data is acknowledged.
    let mut fin_pending = false;

    // `half_closed` is set after we have transmitted our FIN.  The loop
    // stays alive so Branch 2 can receive and ACK the peer's FIN.
    let mut half_closed = false;

    // Sequence number of our FIN packet; set when `half_closed` fires.
    // Used to detect the ACK that covers our FIN (FIN_WAIT_1 → FIN_WAIT_2).
    let mut fin_seq: u32 = 0;

    // Set once the peer ACKs our FIN; we then know we are in FIN_WAIT_2.
    #[allow(unused_variables)]
    let mut fin_acked = false;

    loop {
        // ── Drain phase ────────────────────────────────────────────────────
        //
        // Run at the top of every iteration so that progress made by any
        // branch (ACK opening the window, timer probe) is acted upon
        // immediately without an extra round-trip through select!.

        // 1. Try to drain staged segments into the send window.
        //    Loop so that multiple segments produced by nagle_push can all
        //    be dispatched in one drain phase if the window permits.
        while !staged.is_empty() {
            if !sender.can_send() {
                // Window shut — leave the rest in the queue and arm the
                // appropriate stall timer.
                if sender.persist.is_active() {
                    persist_tmr.as_mut().reset(tok_now() + sender.persist.interval());
                } else if !retransmit_armed {
                    retransmit_tmr.as_mut().reset(tok_now() + rto);
                    retransmit_armed = true;
                }
                break;
            }
            let data = staged.pop_front().unwrap();
            let pkt = sender.build_data_packet(
                data,
                receiver.ack_number(),
                scale_our_window(receiver.window_size()),
            );
            if socket.send_to(&pkt, peer).await.is_err() {
                break;
            }
            sender.record_sent(pkt);
            retries = 0;
            // Arm retransmit timer (persist cannot be active when can_send is true).
            if !retransmit_armed {
                retransmit_tmr.as_mut().reset(tok_now() + rto);
                retransmit_armed = true;
            }
            log::debug!("[gbn:loop] staged → DATA in_flight={}", sender.in_flight());
        }

        // 1b. If staging is now empty and we have a pending payload, process it.
        //     This ensures forward progress when the app channel delivered data
        //     while staging was non-empty.
        if staged.is_empty() {
            if let Some(payload) = pending_payload.take() {
                let mut ready = sender.nagle_push(&payload, mss);

                if ready.is_empty() {
                    // Nagle is coalescing: data sits in nagle_buf.
                } else if sender.can_send() {
                    // Fast path: window open — send the first segment inline.
                    let first = ready.remove(0);
                    let pkt = sender.build_data_packet(
                        first,
                        receiver.ack_number(),
                        scale_our_window(receiver.window_size()),
                    );
                    if socket.send_to(&pkt, peer).await.is_err() {
                        // Don't break entirely; let outer loop handle the error.
                    } else {
                        sender.record_sent(pkt);
                        retries = 0;
                        if !retransmit_armed {
                            retransmit_tmr.as_mut().reset(tok_now() + rto);
                            retransmit_armed = true;
                        }
                        log::debug!("[gbn:loop] pending → DATA in_flight={}", sender.in_flight());
                    }
                    // Overflow segments go to staged.
                    staged.extend(ready);
                } else {
                    // Slow path: window shut — queue all ready segments.
                    staged.extend(ready);
                    if sender.persist.is_active() {
                        persist_tmr.as_mut().reset(tok_now() + sender.persist.interval());
                    } else if !retransmit_armed {
                        retransmit_tmr.as_mut().reset(tok_now() + rto);
                        retransmit_armed = true;
                    }
                }
            }
        }

        // 2. Send our FIN once: app closed + staging queue empty + no pending + window drained.
        //    Decoupling FIN from can_send() is the whole point of this
        //    restructure: FIN is a lifecycle event, not a data segment.
        //    Also force-drain the Nagle buffer so held data is sent before FIN.
        if fin_pending && !half_closed && staged.is_empty() && pending_payload.is_none() && !sender.has_unacked() {
            // If Nagle is holding any data, flush it into the staging queue
            // and let the drain phase send it before we emit the FIN.
            if let Some(buffered) = sender.nagle_force_flush() {
                staged.push_back(buffered);
                // Loop again: drain phase will send it, then we reach here with
                // an empty queue and actually emit the FIN.
            } else {
                let fin = build_fin(&sender, &receiver, snd_wscale);
                fin_seq = fin.header.seq; // Save for ACK-of-FIN detection below.
                let _ = socket.send_to(&fin, peer).await;
                log::debug!("[gbn:loop] → FIN seq={} (data drained); waiting for peer FIN", fin_seq);
                half_closed = true;
            }
        }

        // ── Event wait ─────────────────────────────────────────────────────
        tokio::select! {
            // ── Branch 1: application data or channel close ───────────────
            //
            // Guard: Poll channel when:
            //   - No pending_payload (haven't consumed a payload we can't process)
            //   - Not already fin_pending
            //   - Not already half_closed
            //
            // This decouples channel closure detection from flow-control:
            // we always poll the channel to observe `None`, but we stash
            // `Some(payload)` in `pending_payload` if staging is non-empty.
            // This prevents unbounded staging growth while ensuring FIN is
            // never blocked by window state.
            msg = app_rx.recv(), if pending_payload.is_none() && !fin_pending && !half_closed => {
                match msg {
                    Some(payload) => {
                        // Check if we can accept this payload now (staging empty)
                        // or need to stash it for later.
                        if staged.is_empty() {
                            // Process immediately.
                            let mut ready = sender.nagle_push(&payload, mss);

                            if ready.is_empty() {
                                // Nagle is coalescing: data sits in nagle_buf.
                            } else if sender.can_send() {
                                // Fast path: window open — send the first segment inline.
                                let first = ready.remove(0);
                                let pkt = sender.build_data_packet(
                                    first,
                                    receiver.ack_number(),
                                    scale_our_window(receiver.window_size()),
                                );
                                if socket.send_to(&pkt, peer).await.is_err() {
                                    break;
                                }
                                sender.record_sent(pkt);
                                retries = 0;
                                if !retransmit_armed {
                                    retransmit_tmr.as_mut().reset(tok_now() + rto);
                                    retransmit_armed = true;
                                }
                                log::debug!("[gbn:loop] → DATA in_flight={}", sender.in_flight());
                                // Overflow segments (data > MSS) go to staged.
                                staged.extend(ready);
                            } else {
                                // Slow path: window shut — queue all ready segments.
                                staged.extend(ready);
                                if sender.persist.is_active() {
                                    persist_tmr.as_mut().reset(tok_now() + sender.persist.interval());
                                } else if !retransmit_armed {
                                    retransmit_tmr.as_mut().reset(tok_now() + rto);
                                    retransmit_armed = true;
                                }
                            }
                        } else {
                            // Staging is non-empty: stash this payload for later.
                            // The drain phase will process it once staging empties.
                            pending_payload = Some(payload);
                        }
                    }
                    None => {
                        // send_tx dropped.  Queue the FIN; the drain phase at
                        // the top of the next iteration will emit it once all
                        // in-flight data has been acknowledged.
                        fin_pending = true;
                        log::debug!(
                            "[gbn:loop] app closed; FIN pending \
                             (in_flight={} staged={} pending={})",
                            sender.in_flight(),
                            staged.len(),
                            pending_payload.is_some()
                        );
                    }
                }
            }

            // ── Branch 2: incoming UDP packet ─────────────────────────────
            result = socket.recv_from() => {
                let (pkt, addr) = match result {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if addr != peer {
                    continue;
                }

                let h = &pkt.header;

                // RST received → notify app and shut down.
                if h.flags & flags::RST != 0 {
                    let _ = app_tx.send(Err(ConnError::Reset)).await;
                    break;
                }

                // Unexpected SYN in a synchronised state → half-open detection.
                if is_unexpected_syn(h.flags, ConnectionState::Established) {
                    let rst = build_rst_for(&pkt);
                    let _ = socket.send_to(&rst, peer).await;
                    log::debug!("[gbn:loop] ← unexpected SYN; → RST");
                    let _ = app_tx.send(Err(ConnError::Reset)).await;
                    break;
                }

                // Sequence number validation for data segments.
                if !pkt.payload.is_empty() && !receiver.is_seq_plausible(h.seq) {
                    let rst = build_rst_for(&pkt);
                    let _ = socket.send_to(&rst, peer).await;
                    log::debug!(
                        "[gbn:loop] ← implausible seq={} (rcv_nxt={}); → RST",
                        h.seq,
                        receiver.ack_number()
                    );
                    let _ = app_tx.send(Err(ConnError::Reset)).await;
                    break;
                }

                if h.flags & flags::FIN != 0 {
                    receiver.on_fin(h.seq);
                    let ack = build_ack(&sender, &receiver, snd_wscale);
                    let _ = socket.send_to(&ack, peer).await;
                    if half_closed {
                        // Active closer: our FIN was already sent; peer confirmed
                        // by closing its side.  Enter TIME_WAIT for 2×MSL.
                        log::debug!("[gbn:loop] ← FIN (active close) → TIME_WAIT; ACK sent");
                        run_time_wait(&socket, peer, ack, msl).await;
                        log::debug!("[gbn:loop] TIME_WAIT expired → CLOSED");
                    } else {
                        // Passive closer: peer initiated close; notify the app.
                        let _ = app_tx.send(Err(ConnError::Eof)).await;
                        log::debug!("[gbn:loop] ← FIN (passive close); ACK sent → Eof");
                    }
                    break;
                }

                // Cumulative ACK — slide window, update peer rwnd, RTT estimator, Reno CC.
                if h.flags & flags::ACK != 0 {
                    let sack_blocks = extract_sack_blocks(&pkt);
                    let AckResult { acked_count, rtt_sample, dup_ack } = sender.on_ack(h.ack);
                    sender.process_sack(&sack_blocks);
                    // Track whether the peer has ACKed our FIN (FIN_WAIT_1 → FIN_WAIT_2).
                    if half_closed && !fin_acked && h.ack == fin_seq.wrapping_add(1) {
                        fin_acked = true;
                        log::debug!("[gbn:loop] ← ACK of our FIN → FIN_WAIT_2");
                    }
                    // Update peer rwnd (with window scaling) and handle persist timer transitions.
                    let scaled_rwnd = scale_peer_window(h.window);
                    let persist_transition = sender.update_peer_rwnd(scaled_rwnd);
                    match persist_transition {
                        PersistTransition::Activated => {
                            // peer_rwnd just dropped to 0: stop retransmit, start persist.
                            retransmit_armed = false;
                            retransmit_tmr.as_mut().reset(tok_now() + far_future);
                            persist_tmr.as_mut().reset(tok_now() + sender.persist.interval());
                            log::debug!(
                                "[gbn:loop] peer_rwnd=0 → persist armed interval={:?}",
                                sender.persist.interval()
                            );
                        }
                        PersistTransition::Deactivated => {
                            // peer_rwnd reopened (possibly mid-backoff): stop persist,
                            // re-arm retransmit if there is still unacked data.
                            persist_tmr.as_mut().reset(tok_now() + far_future);
                            if sender.has_unacked() {
                                retransmit_tmr.as_mut().reset(tok_now() + rto);
                                retransmit_armed = true;
                            }
                            log::debug!(
                                "[gbn:loop] peer_rwnd>0 → persist disarmed; retransmit re-armed={}",
                                sender.has_unacked()
                            );
                        }
                        PersistTransition::Unchanged => {}
                    }

                    if let Some(sample) = rtt_sample {
                        rtt.record_sample(sample);
                        log::debug!(
                            "[gbn:loop] RTT sample={:?} srtt={:?} rto={:?}",
                            sample, rtt.srtt(), rtt.rto()
                        );
                    }

                    if acked_count > 0 {
                        sender.on_ack_cc(acked_count);
                        retries = 0;
                        rto = rtt.rto();
                        log::debug!(
                            "[gbn:loop] ← ACK ack={} slid={} rto={:?} cwnd={} peer_rwnd={}",
                            h.ack, acked_count, rto, sender.cwnd(), sender.peer_rwnd()
                        );

                        // Update retransmit timer state (persist transition already handled above).
                        if sender.has_unacked() && !sender.persist.is_active() {
                            retransmit_tmr.as_mut().reset(tok_now() + rto);
                            retransmit_armed = true;
                        } else if !sender.has_unacked() {
                            retransmit_armed = false;
                            retransmit_tmr.as_mut().reset(tok_now() + far_future);
                        }

                        // Post-ACK Nagle pump: the pipe may have just emptied,
                        // releasing data that was held by the Nagle condition.
                        // Queue any newly-ready segments for the drain phase.
                        let pumped = sender.nagle_pump(mss);
                        staged.extend(pumped);

                        // The drain phase at the top of the next iteration will
                        // send any staged segment and/or emit FIN if warranted.
                    } else if dup_ack && sender.dup_ack_count() == 3 {
                        // Reno fast retransmit: retransmit oldest unacked segment.
                        sender.on_triple_dup_ack_cc();
                        if let Some(pkt) = sender.retransmit_oldest() {
                            log::debug!("[gbn:loop] fast-retransmit seq={}", pkt.header.seq);
                            let _ = socket.send_to(&pkt, peer).await;
                        }
                        log::debug!(
                            "[gbn:loop] 3-dup-ACK → FR cwnd={}",
                            sender.cwnd()
                        );
                    }
                }

                // Data payload.
                if !pkt.payload.is_empty() {
                    let accepted = receiver.on_segment(h.seq, &pkt.payload);
                    let ack = build_ack(&sender, &receiver, snd_wscale);
                    let _ = socket.send_to(&ack, peer).await;
                    if accepted {
                        let mut buf = vec![0u8; receiver.app_buffer.len()];
                        let n = receiver.read(&mut buf);
                        buf.truncate(n);
                        if app_tx.send(Ok(buf)).await.is_err() {
                            break;
                        }
                    }
                }
            }

            // ── Branch 3: SR retransmit timeout ──────────────────────────
            //
            // Only fires when there is unacked data AND the peer window is
            // open.  Persist stalls are handled exclusively by Branch 4.
            _ = &mut retransmit_tmr, if retransmit_armed => {
                retries += 1;
                if retries > MAX_RETRIES {
                    let _ = app_tx.send(Err(ConnError::MaxRetriesExceeded)).await;
                    break;
                }
                // Selective Repeat: retransmit only the oldest unacked segment.
                if let Some(pkt) = sender.retransmit_oldest() {
                    log::debug!("[gbn:loop] SR timeout — retransmit oldest seq={}", pkt.header.seq);
                    let _ = socket.send_to(&pkt, peer).await;
                }
                sender.on_timeout_cc();
                rtt.back_off();
                rto = rtt.rto();
                retransmit_tmr.as_mut().reset(tok_now() + rto);
                log::debug!(
                    "[gbn:loop] SR timeout #{} rto={:?} cwnd={}",
                    retries, rto, sender.cwnd()
                );
            }

            // ── Branch 4: persist probe (zero-window stall) ───────────────
            //
            // Fires only while sender.persist.is_active() (peer_rwnd == 0).
            // Probes do NOT increment tx_count (Karn's algorithm unaffected),
            // do NOT trigger CC penalties, and do NOT count against retries.
            _ = &mut persist_tmr, if sender.persist.is_active() => {
                if let Some(pkt) = sender.window_entries().next().map(|e| e.packet.clone()) {
                    // Re-send the oldest in-flight segment as the probe.
                    log::debug!("[gbn:loop] persist probe seq={}", pkt.header.seq);
                    let _ = socket.send_to(&pkt, peer).await;
                } else {
                    // No in-flight segments (staged data blocked on rwnd==0):
                    // send a pure ACK to elicit a window update from the peer.
                    let ack = build_ack(&sender, &receiver, snd_wscale);
                    log::debug!("[gbn:loop] persist keepalive (no in-flight)");
                    let _ = socket.send_to(&ack, peer).await;
                }
                sender.persist.on_probe_sent();
                persist_tmr.as_mut().reset(tok_now() + sender.persist.interval());
                log::debug!(
                    "[gbn:loop] persist probe #{} next={:?}",
                    sender.persist.probe_count(), sender.persist.interval()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TIME_WAIT (concurrent mode)
// ---------------------------------------------------------------------------

/// Linger in `TIME_WAIT` for `2 × msl`, re-ACKing duplicate FINs.
///
/// Called from the event loop after the active-close FIN exchange completes.
/// `last_ack` is the ACK we sent in response to the peer's FIN; it is resent
/// verbatim for each duplicate FIN without re-invoking `on_fin`.
///
/// `biased` polling gives the timer priority so that an adversarial FIN flood
/// cannot prevent the connection from ever reaching `Closed`.
async fn run_time_wait(
    socket: &Arc<Socket>,
    peer: SocketAddr,
    last_ack: Packet,
    msl: Duration,
) {
    let two_msl = 2 * msl;
    let timer = tokio::time::sleep(two_msl);
    tokio::pin!(timer);
    log::debug!("[gbn:loop] TIME_WAIT start; 2×MSL={:?}", two_msl);

    loop {
        tokio::select! {
            biased;
            _ = &mut timer => break,
            result = socket.recv_from() => {
                if let Ok((pkt, addr)) = result {
                    if addr == peer && pkt.header.flags & flags::FIN != 0 {
                        log::debug!("[gbn:loop] TIME_WAIT: re-ACK duplicate FIN");
                        let _ = socket.send_to(&last_ack, peer).await;
                    }
                    // All other segments: silently discard.
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Packet builders
// ---------------------------------------------------------------------------

fn build_ack<CC: CongestionControl>(
    sender: &GbnSender<CC>, 
    receiver: &GbnReceiver, 
    snd_wscale: Option<u8>,
) -> Packet {
    let true_window = receiver.window_size();
    let window = match snd_wscale {
        Some(shift) => (true_window >> shift).min(u16::MAX as usize) as u16,
        None => true_window.min(u16::MAX as usize) as u16,
    };
    let sack_blocks = receiver.sack_blocks();
    let options = if sack_blocks.is_empty() {
        vec![]
    } else {
        vec![TcpOption::Sack(sack_blocks)]
    };
    Packet {
        header: Header {
            seq: sender.next_seq,
            ack: receiver.ack_number(),
            flags: flags::ACK,
            window,
            checksum: 0,
        },
        options,
        payload: vec![],
    }
}

fn build_fin<CC: CongestionControl>(
    sender: &GbnSender<CC>,
    receiver: &GbnReceiver,
    snd_wscale: Option<u8>,
) -> Packet {
    let true_window = receiver.window_size();
    let window = match snd_wscale {
        Some(shift) => (true_window >> shift).min(u16::MAX as usize) as u16,
        None => true_window.min(u16::MAX as usize) as u16,
    };
    Packet {
        header: Header {
            seq: sender.next_seq,
            ack: receiver.ack_number(),
            flags: flags::FIN | flags::ACK,
            window,
            checksum: 0,
        },
        options: vec![],
        payload: vec![],
    }
}

#[inline]
fn tok_now() -> tokio::time::Instant {
    tokio::time::Instant::now()
}

/// Extract SACK blocks from an incoming packet's options list.
///
/// Returns a flat `Vec<SackBlock>` combining all `TcpOption::Sack` entries.
/// In practice a packet carries at most one SACK option, but this handles
/// the degenerate case of multiple entries gracefully.
fn extract_sack_blocks(pkt: &Packet) -> Vec<SackBlock> {
    pkt.options
        .iter()
        .filter_map(|o| {
            if let TcpOption::Sack(b) = o {
                Some(b.as_slice())
            } else {
                None
            }
        })
        .flat_map(|b| b.iter().cloned())
        .collect()
}

/// Build an RST packet in response to an incoming segment (RFC 793 §3.4).
///
/// If the incoming segment has ACK set, the RST carries `seq = incoming.ack`
/// so the peer considers it in-window.  Otherwise the RST carries `seq = 0`
/// with `ack = seg.seq + seg.len` and the ACK flag set.
fn build_rst_for(incoming: &Packet) -> Packet {
    if incoming.header.flags & flags::ACK != 0 {
        Packet {
            header: Header {
                seq: incoming.header.ack,
                ack: 0,
                flags: flags::RST,
                window: 0,
                checksum: 0,
            },
            options: vec![],
            payload: vec![],
        }
    } else {
        let seg_len = incoming.payload.len() as u32
            + if incoming.header.flags & (flags::SYN | flags::FIN) != 0 { 1 } else { 0 };
        Packet {
            header: Header {
                seq: 0,
                ack: incoming.header.seq.wrapping_add(seg_len),
                flags: flags::RST | flags::ACK,
                window: 0,
                checksum: 0,
            },
            options: vec![],
            payload: vec![],
        }
    }
}

/// Build an RST originating from our side (for `abort()`).
fn build_rst_from<CC: CongestionControl>(sender: &GbnSender<CC>) -> Packet {
    Packet {
        header: Header {
            seq: sender.next_seq,
            ack: 0,
            flags: flags::RST,
            window: 0,
            checksum: 0,
        },
        options: vec![],
        payload: vec![],
    }
}

/// Returns `true` if the incoming packet carries a SYN in a state where it
/// is unexpected (any synchronised state: Established, FinWait*, etc.).
///
/// Receiving SYN in a synchronised state indicates a half-open connection
/// (peer has restarted) and must be answered with RST per RFC 793 §3.4.
fn is_unexpected_syn(flags: u8, state: ConnectionState) -> bool {
    flags & flags::SYN != 0
        && !matches!(
            state,
            ConnectionState::Closed | ConnectionState::SynSent | ConnectionState::SynReceived
        )
}
