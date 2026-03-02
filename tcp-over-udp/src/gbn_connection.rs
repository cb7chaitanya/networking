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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::connection::{ConnError, Connection};
use crate::gbn_receiver::GbnReceiver;
use crate::gbn_sender::{AckResult, GbnSender};
use crate::packet::{flags, Header, Packet};
use crate::rtt::RttEstimator;
use crate::socket::Socket;
use crate::state::ConnectionState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_RETRIES: u32 = 6;

// ---------------------------------------------------------------------------
// GbnConnection
// ---------------------------------------------------------------------------

/// A reliable connection using Go-Back-N sliding-window flow control with
/// adaptive retransmission timeout.
pub struct GbnConnection {
    /// Current FSM state.
    pub state: ConnectionState,

    /// Outbound GBN window (sequence numbers, in-flight queue).
    pub sender: GbnSender,

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
}

impl GbnConnection {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Build a [`GbnConnection`] from an already-established [`Connection`].
    ///
    /// The 3-way handshake must be complete.  `window_size` sets the GBN
    /// window N.  A fresh [`RttEstimator`] is started — RTT history from
    /// the handshake is not carried over.
    pub fn from_connection(conn: Connection, window_size: usize) -> Self {
        let (state, socket, peer, next_seq, rcv_nxt, _rto) = conn.into_parts();
        Self {
            state,
            socket: Arc::new(socket),
            peer,
            sender: GbnSender::new(next_seq, window_size),
            receiver: GbnReceiver::new(rcv_nxt),
            rtt: RttEstimator::new(),
        }
    }

    /// Active open (client): run the 3-way handshake then return a GBN connection.
    pub async fn connect(
        socket: Socket,
        peer: SocketAddr,
        window_size: usize,
    ) -> Result<Self, ConnError> {
        let conn = Connection::connect(socket, peer).await?;
        Ok(Self::from_connection(conn, window_size))
    }

    /// Passive open (server): accept one incoming connection and return GBN.
    pub async fn accept(socket: Socket, window_size: usize) -> Result<Self, ConnError> {
        let conn = Connection::accept(socket).await?;
        Ok(Self::from_connection(conn, window_size))
    }

    // -----------------------------------------------------------------------
    // Sequential data transfer
    // -----------------------------------------------------------------------

    /// Queue one segment for delivery.
    ///
    /// Returns immediately when the window has space.  Blocks — processing
    /// incoming ACKs and retransmitting on timeout — when the window is full.
    ///
    /// **Pipeline pattern**: call `send` in a tight loop to fill the window,
    /// then call [`flush`] to wait for all in-flight segments to be ACKed.
    ///
    /// [`flush`]: Self::flush
    pub async fn send(&mut self, data: &[u8]) -> Result<(), ConnError> {
        if self.state != ConnectionState::Established {
            return Err(ConnError::BadState);
        }

        let mut rto = self.rtt.rto();
        let mut retries = 0u32;

        // Wait until the window has room, processing inbound packets meanwhile.
        while !self.sender.can_send() {
            let sleep = tokio::time::sleep(rto);
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
                        }
                        Err(e) => return Err(e),
                    }
                }
                _ = &mut sleep => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(ConnError::MaxRetriesExceeded);
                    }
                    self.retransmit_window().await?;
                    self.sender.on_retransmit();
                    self.sender.on_timeout_cc();
                    self.rtt.back_off();
                    rto = self.rtt.rto();
                    log::debug!(
                        "[gbn] timeout — back-off rto={:?} cwnd={} ssthresh={}",
                        rto, self.sender.cwnd(), self.sender.ssthresh()
                    );
                }
            }
        }

        // Send the new segment.
        let pkt = self.sender.build_data_packet(
            data.to_vec(),
            self.receiver.ack_number(),
            self.receiver.window_size(),
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
        // Drain previously buffered data first.
        if !self.receiver.app_buffer.is_empty() {
            return Ok(self.drain_app_buffer());
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
                self.receiver.on_fin(h.seq);
                let ack = self.make_ack_pkt();
                let _ = self.socket.send_to(&ack, self.peer).await;
                self.state = ConnectionState::CloseWait;
                log::debug!("[gbn] ← FIN; → ACK ack={}", self.receiver.ack_number());
                return Err(ConnError::Eof);
            }

            // Piggybacked ACK: slide window, update RTT and congestion control.
            if h.flags & flags::ACK != 0 {
                let n = self.on_ack_received(h.ack);
                if n > 0 {
                    log::debug!(
                        "[gbn] ← ACK ack={} slid={} srtt={:?} rto={:?}",
                        h.ack, n, self.rtt.srtt(), self.rtt.rto()
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
        let mut rto = self.rtt.rto();
        let mut retries = 0u32;

        while self.sender.has_unacked() {
            let sleep = tokio::time::sleep(rto);
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
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(ConnError::MaxRetriesExceeded);
                    }
                    self.retransmit_window().await?;
                    self.sender.on_retransmit();
                    self.sender.on_timeout_cc();
                    self.rtt.back_off();
                    rto = self.rtt.rto();
                    log::debug!(
                        "[gbn] flush timeout — back-off rto={:?} cwnd={} ssthresh={}",
                        rto, self.sender.cwnd(), self.sender.ssthresh()
                    );
                }
            }
        }

        Ok(())
    }

    /// Graceful close: flush pending data, then exchange FIN/ACK.
    pub async fn close(&mut self) -> Result<(), ConnError> {
        if matches!(self.state, ConnectionState::Closed) {
            return Ok(());
        }

        match self.flush().await {
            Ok(()) | Err(ConnError::Eof) => {}
            Err(e) => return Err(e),
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
        let mut rto = self.rtt.rto();

        for _attempt in 0..=MAX_RETRIES {
            self.socket.send_to(&fin, self.peer).await?;
            self.state = ConnectionState::FinWait1;
            log::debug!("[gbn] → FIN seq={}", fin.header.seq);

            match timeout(rto, self.socket.recv_from()).await {
                Ok(Ok((pkt, addr))) if addr == self.peer => {
                    if pkt.header.flags & flags::ACK != 0
                        && pkt.header.ack == fin.header.seq.wrapping_add(1)
                    {
                        log::debug!("[gbn] ← ACK of FIN — closed");
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

        log::warn!("[gbn] FIN not ACKed; force-closing");
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

    /// Process a cumulative ACK: slide the window, update RTT and congestion
    /// control.  Returns the number of newly-acked segments so callers know
    /// whether the window has opened.
    ///
    /// This centralises all ACK handling so that every code path — `send`,
    /// `flush`, `recv`, and the event loop — updates the RTT estimator and
    /// the Reno congestion window.
    fn on_ack_received(&mut self, ack_num: u32) -> usize {
        let AckResult { acked_count, rtt_sample, dup_ack: _ } = self.sender.on_ack(ack_num);
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
                "[gbn] cwnd={} ssthresh={} state={:?}",
                self.sender.cwnd(),
                self.sender.ssthresh(),
                self.sender.cc_state()
            );
        }
        acked_count
    }

    /// Retransmit only the oldest unacked segment (Reno fast retransmit).
    ///
    /// Called after 3 consecutive duplicate ACKs have been detected.
    async fn fast_retransmit(&mut self) -> Result<(), ConnError> {
        if let Some(entry) = self.sender.window_entries().next() {
            let pkt = entry.packet.clone();
            log::debug!("[gbn] fast-retransmit seq={}", pkt.header.seq);
            self.socket.send_to(&pkt, self.peer).await?;
        }
        // Mark the retransmitted segment so Karn's algorithm suppresses its
        // RTT sample on the next ACK.
        if let Some(e) = self.sender.window.front_mut() {
            e.tx_count += 1;
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

        if h.flags & flags::RST != 0 {
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
            let newly_acked = self.on_ack_received(h.ack);
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

    fn drain_app_buffer(&mut self) -> Vec<u8> {
        let mut buf = vec![0u8; self.receiver.app_buffer.len()];
        let n = self.receiver.read(&mut buf);
        buf.truncate(n);
        buf
    }

    async fn retransmit_window(&self) -> Result<(), ConnError> {
        let pkts: Vec<Packet> = self
            .sender
            .window_entries()
            .map(|e| e.packet.clone())
            .collect();
        log::debug!("[gbn] retransmitting {} segment(s)", pkts.len());
        for pkt in pkts {
            self.socket.send_to(&pkt, self.peer).await?;
        }
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

async fn event_loop(
    socket: Arc<Socket>,
    peer: SocketAddr,
    mut sender: GbnSender,
    mut receiver: GbnReceiver,
    mut rtt: RttEstimator,
    mut app_rx: mpsc::Receiver<Vec<u8>>,
    app_tx: mpsc::Sender<Result<Vec<u8>, ConnError>>,
) {
    // Use the estimator's current RTO as the timer interval.
    let mut rto = rtt.rto();
    let mut retries = 0u32;

    // The retransmit timer: "disarmed" means we reset it to a far-future
    // deadline.  The `timer_armed` guard prevents acting on a disarmed timer.
    let far_future = Duration::from_secs(365 * 24 * 3600);
    let timer = tokio::time::sleep(far_future);
    tokio::pin!(timer);
    let mut timer_armed = false;

    loop {
        tokio::select! {
            // ── Branch 1: new data from the application ───────────────────
            maybe_data = app_rx.recv(), if sender.can_send() => {
                match maybe_data {
                    None => {
                        // App closed send_tx → send FIN.
                        let fin = build_fin(&sender, &receiver);
                        let _ = socket.send_to(&fin, peer).await;
                        log::debug!("[gbn:loop] → FIN (app closed)");
                        break;
                    }
                    Some(payload) => {
                        let pkt = sender.build_data_packet(
                            payload,
                            receiver.ack_number(),
                            receiver.window_size(),
                        );
                        if socket.send_to(&pkt, peer).await.is_err() {
                            break;
                        }
                        sender.record_sent(pkt);
                        retries = 0;
                        if !timer_armed {
                            timer.as_mut().reset(tok_now() + rto);
                            timer_armed = true;
                        }
                        log::debug!("[gbn:loop] → DATA in_flight={}", sender.in_flight());
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

                if h.flags & flags::RST != 0 {
                    let _ = app_tx.send(Err(ConnError::Reset)).await;
                    break;
                }

                if h.flags & flags::FIN != 0 {
                    receiver.on_fin(h.seq);
                    let ack = build_ack(&sender, &receiver);
                    let _ = socket.send_to(&ack, peer).await;
                    let _ = app_tx.send(Err(ConnError::Eof)).await;
                    log::debug!("[gbn:loop] ← FIN; → ACK");
                    break;
                }

                // Cumulative ACK — slide window, update RTT estimator, Reno CC.
                if h.flags & flags::ACK != 0 {
                    let AckResult { acked_count, rtt_sample, dup_ack } = sender.on_ack(h.ack);
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
                            "[gbn:loop] ← ACK ack={} slid={} rto={:?} cwnd={} ssthresh={}",
                            h.ack, acked_count, rto, sender.cwnd(), sender.ssthresh()
                        );

                        if sender.has_unacked() {
                            timer.as_mut().reset(tok_now() + rto);
                        } else {
                            timer_armed = false;
                            timer.as_mut().reset(tok_now() + far_future);
                        }
                    } else if dup_ack && sender.dup_ack_count() == 3 {
                        // Reno fast retransmit: retransmit oldest unacked segment.
                        sender.on_triple_dup_ack_cc();
                        if let Some(entry) = sender.window_entries().next() {
                            let pkt = entry.packet.clone();
                            log::debug!("[gbn:loop] fast-retransmit seq={}", pkt.header.seq);
                            let _ = socket.send_to(&pkt, peer).await;
                        }
                        if let Some(e) = sender.window.front_mut() {
                            e.tx_count += 1;
                        }
                        log::debug!(
                            "[gbn:loop] 3-dup-ACK → FR cwnd={} ssthresh={}",
                            sender.cwnd(), sender.ssthresh()
                        );
                    }
                }

                // Data payload.
                if !pkt.payload.is_empty() {
                    let accepted = receiver.on_segment(h.seq, &pkt.payload);
                    let ack = build_ack(&sender, &receiver);
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

            // ── Branch 3: retransmit timeout ─────────────────────────────
            _ = &mut timer, if timer_armed => {
                retries += 1;
                if retries > MAX_RETRIES {
                    let _ = app_tx.send(Err(ConnError::MaxRetriesExceeded)).await;
                    break;
                }

                // Go-Back-N: retransmit every unacked segment.
                let pkts: Vec<Packet> = sender.window_entries()
                    .map(|e| e.packet.clone())
                    .collect();
                log::debug!("[gbn:loop] timeout — retransmitting {} pkt(s)", pkts.len());
                for p in pkts {
                    let _ = socket.send_to(&p, peer).await;
                }
                sender.on_retransmit();

                // Reno: halve ssthresh, reset cwnd to 1, re-enter slow start.
                sender.on_timeout_cc();

                // Exponential back-off via the RTT estimator.
                rtt.back_off();
                rto = rtt.rto();
                timer.as_mut().reset(tok_now() + rto);
                log::debug!(
                    "[gbn:loop] timeout → SS rto={:?} cwnd={} ssthresh={}",
                    rto, sender.cwnd(), sender.ssthresh()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Packet builders
// ---------------------------------------------------------------------------

fn build_ack(sender: &GbnSender, receiver: &GbnReceiver) -> Packet {
    Packet {
        header: Header {
            seq: sender.next_seq,
            ack: receiver.ack_number(),
            flags: flags::ACK,
            window: receiver.window_size(),
            checksum: 0,
        },
        payload: vec![],
    }
}

fn build_fin(sender: &GbnSender, receiver: &GbnReceiver) -> Packet {
    Packet {
        header: Header {
            seq: sender.next_seq,
            ack: receiver.ack_number(),
            flags: flags::FIN | flags::ACK,
            window: receiver.window_size(),
            checksum: 0,
        },
        payload: vec![],
    }
}

#[inline]
fn tok_now() -> tokio::time::Instant {
    tokio::time::Instant::now()
}
