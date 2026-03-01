//! Go-Back-N connection: handshake + GBN data transfer + concurrent session.
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
//!    ├── GbnSender   (sliding window, seq nums)   │
//!    ├── GbnReceiver (cumulative ACKs, app buf)   │
//!    └── Arc<Socket> (shared with background task)┘
//! ```
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
//! session.send_tx.send(b"msg2".to_vec()).await.unwrap();
//! let data = session.recv().await?;
//! session.close().await?;
//! ```
//!
//! # Integration with the existing handshake
//!
//! Use [`Connection::connect`] / [`Connection::accept`] for the 3-way
//! handshake (they are already well-tested), then convert the result:
//!
//! ```ignore
//! let conn = Connection::connect(socket, peer).await?;
//! let mut gbn = GbnConnection::from_connection(conn, window_size);
//! ```

use std::sync::Arc;
use std::time::Duration;
use std::net::SocketAddr;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::connection::{ConnError, Connection};
use crate::gbn_receiver::GbnReceiver;
use crate::gbn_sender::GbnSender;
use crate::packet::{flags, Header, Packet};
use crate::socket::Socket;
use crate::state::ConnectionState;

// ---------------------------------------------------------------------------
// Constants (mirror connection.rs)
// ---------------------------------------------------------------------------

const INITIAL_RTO: Duration = Duration::from_millis(1000);
const MAX_RTO: Duration = Duration::from_secs(60);
const MAX_RETRIES: u32 = 6;

// ---------------------------------------------------------------------------
// GbnConnection
// ---------------------------------------------------------------------------

/// A reliable connection using Go-Back-N sliding-window flow control.
///
/// Obtain one via [`GbnConnection::connect`], [`GbnConnection::accept`], or
/// [`GbnConnection::from_connection`] (after completing the 3-way handshake
/// with the existing [`Connection`] API).
pub struct GbnConnection {
    /// Current FSM state.
    pub state: ConnectionState,

    /// Outbound GBN window (sequence numbers, in-flight queue).
    pub sender: GbnSender,

    /// Inbound state (cumulative ACKs, application buffer).
    pub receiver: GbnReceiver,

    /// Shared UDP socket.  `Arc` allows handing a clone to the event loop.
    socket: Arc<Socket>,

    /// Remote peer address.
    peer: SocketAddr,

    /// Baseline RTO (reset to this after a successful ACK).
    rto: Duration,
}

impl GbnConnection {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Build a [`GbnConnection`] from an already-established [`Connection`].
    ///
    /// The 3-way handshake must be complete.  `window_size` sets the GBN
    /// window (N); typical values are 4–16.
    pub fn from_connection(conn: Connection, window_size: usize) -> Self {
        let (state, socket, peer, next_seq, rcv_nxt, rto) = conn.into_parts();
        Self {
            state,
            socket: Arc::new(socket),
            peer,
            sender: GbnSender::new(next_seq, window_size),
            receiver: GbnReceiver::new(rcv_nxt),
            rto,
        }
    }

    /// Perform an active open (client) and return a GBN-ready connection.
    ///
    /// Equivalent to `Connection::connect` followed by `from_connection`.
    pub async fn connect(
        socket: Socket,
        peer: SocketAddr,
        window_size: usize,
    ) -> Result<Self, ConnError> {
        let conn = Connection::connect(socket, peer).await?;
        Ok(Self::from_connection(conn, window_size))
    }

    /// Perform a passive open (server) and return a GBN-ready connection.
    ///
    /// Equivalent to `Connection::accept` followed by `from_connection`.
    pub async fn accept(socket: Socket, window_size: usize) -> Result<Self, ConnError> {
        let conn = Connection::accept(socket).await?;
        Ok(Self::from_connection(conn, window_size))
    }

    // -----------------------------------------------------------------------
    // Sequential data transfer
    // -----------------------------------------------------------------------

    /// Queue one segment for delivery using Go-Back-N.
    ///
    /// If the window has space the segment is sent immediately and the call
    /// returns.  If the window is full the call blocks until an ACK arrives
    /// (or a timeout triggers a full retransmit) to make room.
    ///
    /// This enables **pipelining**: successive `send` calls fill the window
    /// without waiting for individual acknowledgements.  Call [`flush`] after
    /// all sends to guarantee delivery.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), ConnError> {
        if self.state != ConnectionState::Established {
            return Err(ConnError::BadState);
        }

        let mut rto = self.rto;
        let mut retries = 0u32;

        // Block until the window has room.
        while !self.sender.can_send() {
            let sleep = tokio::time::sleep(rto);
            tokio::pin!(sleep);

            tokio::select! {
                result = self.socket.recv_from() => {
                    let (pkt, addr) = result?;
                    match self.process_incoming(pkt, addr).await {
                        Ok(window_advanced) => {
                            if window_advanced {
                                rto = self.rto;
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
                    rto = (rto * 2).min(MAX_RTO);
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
    /// are re-ACKed with the current cumulative ACK and discarded (GBN
    /// semantics).  Returns [`ConnError::Eof`] when the peer sends FIN.
    pub async fn recv(&mut self) -> Result<Vec<u8>, ConnError> {
        if self.state != ConnectionState::Established
            && self.state != ConnectionState::CloseWait
        {
            // Still allow reads in CloseWait (data may have arrived before FIN).
            if self.state != ConnectionState::CloseWait {
                return Err(ConnError::BadState);
            }
        }

        // Drain any data already buffered from previous receive cycles.
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

            // Piggybacked ACK — slide our send window.
            if h.flags & flags::ACK != 0 {
                let n = self.sender.on_ack(h.ack);
                if n > 0 {
                    log::debug!("[gbn] ← ACK ack={} (slid {} seg)", h.ack, n);
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
            // Out-of-order: cumulative ACK sent above; keep waiting.
        }
    }

    /// Wait for all in-flight segments to be acknowledged.
    ///
    /// After `flush` returns `Ok(())` the send window is empty and all data
    /// passed to previous [`send`] calls has been confirmed by the peer.
    pub async fn flush(&mut self) -> Result<(), ConnError> {
        let mut rto = self.rto;
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
                                rto = self.rto;
                                retries = 0;
                            }
                        }
                        Err(ConnError::Eof) => break, // peer closed; stop flushing
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
                    rto = (rto * 2).min(MAX_RTO);
                }
            }
        }

        if !self.sender.has_unacked() {
            self.rto = INITIAL_RTO; // reset after clean flush
        }
        Ok(())
    }

    /// Graceful connection close: flush in-flight data, then send FIN.
    pub async fn close(&mut self) -> Result<(), ConnError> {
        if matches!(self.state, ConnectionState::Closed) {
            return Ok(());
        }

        // Ensure all queued data is delivered first.
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
        let mut rto = self.rto;

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
                Err(_elapsed) => rto = (rto * 2).min(MAX_RTO),
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
    /// packets, and retransmit timeouts with `tokio::select!`.  The
    /// application interacts via channel operations on the returned
    /// [`GbnSession`].
    ///
    /// # Shutdown
    ///
    /// Drop (or close) `send_tx` to signal end-of-stream; the event loop will
    /// send FIN and terminate.  Await [`GbnSession::close`] to wait for the
    /// loop to finish.
    pub fn run(self) -> GbnSession {
        let (send_tx, send_rx) = mpsc::channel::<Vec<u8>>(64);
        let (recv_tx, recv_rx) = mpsc::channel::<Result<Vec<u8>, ConnError>>(64);

        let handle = tokio::spawn(event_loop(
            self.socket,
            self.peer,
            self.sender,
            self.receiver,
            self.rto,
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

    /// Build a pure ACK packet reflecting the current send/receive state.
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

    /// Drain the receiver's application buffer into an owned `Vec`.
    fn drain_app_buffer(&mut self) -> Vec<u8> {
        let mut buf = vec![0u8; self.receiver.app_buffer.len()];
        let n = self.receiver.read(&mut buf);
        buf.truncate(n);
        buf
    }

    /// Retransmit every in-flight segment (Go-Back-N step).
    async fn retransmit_window(&self) -> Result<(), ConnError> {
        let pkts: Vec<Packet> = self
            .sender
            .window_entries()
            .map(|e| e.packet.clone())
            .collect();
        log::debug!("[gbn] timeout — retransmitting {} segment(s)", pkts.len());
        for pkt in pkts {
            self.socket.send_to(&pkt, self.peer).await?;
        }
        Ok(())
    }

    /// Handle an inbound packet: process ACK, data, FIN/RST.
    ///
    /// Returns `Ok(true)` when the send window advanced (new ACKs), so the
    /// caller knows it may be able to send more.
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
            let newly_acked = self.sender.on_ack(h.ack);
            window_advanced = newly_acked > 0;
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
}

// ---------------------------------------------------------------------------
// GbnSession — concurrent handle
// ---------------------------------------------------------------------------

/// Handle returned by [`GbnConnection::run`] for concurrent send/receive.
pub struct GbnSession {
    /// Send data to the remote peer (push `Vec<u8>` into this).
    pub send_tx: mpsc::Sender<Vec<u8>>,

    /// Receive data from the remote peer.
    pub recv_rx: mpsc::Receiver<Result<Vec<u8>, ConnError>>,

    handle: JoinHandle<()>,
}

impl GbnSession {
    /// Send a payload to the peer (non-blocking when channel has capacity).
    pub async fn send(&self, data: Vec<u8>) -> Result<(), ConnError> {
        self.send_tx
            .send(data)
            .await
            .map_err(|_| ConnError::Reset) // channel closed means event loop died
    }

    /// Receive the next chunk of data delivered by the peer.
    ///
    /// Returns [`ConnError::Eof`] when the peer closes the connection.
    pub async fn recv(&mut self) -> Result<Vec<u8>, ConnError> {
        self.recv_rx
            .recv()
            .await
            .unwrap_or(Err(ConnError::Eof))
    }

    /// Signal end-of-stream and wait for the background task to finish.
    pub async fn close(self) {
        // Dropping send_tx signals the event loop to send FIN and exit.
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
    initial_rto: Duration,
    mut app_rx: mpsc::Receiver<Vec<u8>>,
    app_tx: mpsc::Sender<Result<Vec<u8>, ConnError>>,
) {
    let mut rto = initial_rto;
    let mut retries = 0u32;

    // A "disarmed" timer fires very far in the future.  The `timer_armed`
    // guard in select! prevents acting on it when the window is empty.
    let far_future = Duration::from_secs(365 * 24 * 3600);
    let timer = tokio::time::sleep(far_future);
    tokio::pin!(timer);
    let mut timer_armed = false;

    loop {
        tokio::select! {
            // ── Branch 1: new data from the application ──────────────────
            // Only eligible when the GBN window has space.
            maybe_data = app_rx.recv(), if sender.can_send() => {
                match maybe_data {
                    None => {
                        // Application closed the send channel → send FIN.
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
                        // Arm the retransmit timer when the first segment enters.
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

                // Cumulative ACK — slide the send window.
                if h.flags & flags::ACK != 0 {
                    let newly_acked = sender.on_ack(h.ack);
                    if newly_acked > 0 {
                        retries = 0;
                        rto = initial_rto;
                        log::debug!("[gbn:loop] ← ACK ack={} slid={}", h.ack, newly_acked);

                        if sender.has_unacked() {
                            // Restart the timer for the new oldest segment.
                            timer.as_mut().reset(tok_now() + rto);
                        } else {
                            // Window drained — disarm the timer.
                            timer_armed = false;
                            timer.as_mut().reset(tok_now() + far_future);
                        }
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

                // Go-Back-N: retransmit every unacked segment from send_base.
                let pkts: Vec<Packet> = sender.window_entries()
                    .map(|e| e.packet.clone())
                    .collect();
                log::debug!("[gbn:loop] timeout — retransmitting {} pkt(s)", pkts.len());
                for p in pkts {
                    let _ = socket.send_to(&p, peer).await;
                }
                sender.on_retransmit();
                rto = (rto * 2).min(MAX_RTO);
                timer.as_mut().reset(tok_now() + rto);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Packet builders (free functions for the event loop)
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

/// `tokio::time::Instant::now()` — a convenience alias to avoid the long path.
#[inline]
fn tok_now() -> tokio::time::Instant {
    tokio::time::Instant::now()
}
