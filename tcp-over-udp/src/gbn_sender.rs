//! Go-Back-N send-side state machine with TCP Reno congestion control.
//!
//! [`GbnSender`] maintains a sliding window of up to `N` in-flight segments
//! **and** a Reno-style congestion window that limits how many segments are
//! injected into the network regardless of the configured window size.
//!
//! # Protocol contract
//!
//! - The effective send window is `min(window_size, cwnd)` segments.
//! - ACKs are **cumulative**: `ack_num = K` means the receiver has accepted
//!   all bytes up to (but not including) sequence number `K`.
//! - On timeout the caller retransmits **all** unacked segments (go back to N)
//!   and calls [`GbnSender::on_timeout_cc`] to collapse the congestion window.
//!
//! # TCP Reno congestion control
//!
//! Three phases governed by [`CongestionState`]:
//!
//! | Phase | `cwnd` growth |
//! |---|---|
//! | **Slow Start** | +1 segment per newly-acked segment (≈ doubles per RTT) |
//! | **Congestion Avoidance** | +1 segment per RTT (additive increase via fractional counter) |
//! | **Fast Recovery** | hold at `ssthresh + 3`; collapse to `ssthresh` on new ACK |
//!
//! **On timeout** (`on_timeout_cc`): `ssthresh ← max(2, in_flight/2)`, `cwnd ← 1`,
//! re-enter Slow Start.
//!
//! **On 3 duplicate ACKs** (`on_triple_dup_ack_cc`): `ssthresh ← max(2, in_flight/2)`,
//! `cwnd ← ssthresh + 3`, enter Fast Recovery (Reno fast retransmit).
//!
//! # RTT sampling (Karn's algorithm)
//!
//! [`on_ack`] returns an [`AckResult`] that includes an optional RTT sample.
//! The sample is taken from the **oldest** newly-acked segment but only when
//! that segment was sent exactly once (`tx_count == 1`).  If the segment was
//! ever retransmitted the sample is `None` — it would be ambiguous which
//! transmission the ACK is responding to (Karn's algorithm, RFC 6298 §4).
//!
//! [`on_ack`]: GbnSender::on_ack

use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::congestion_control::{CongestionControl, LossKind, RenoCC};
use crate::metrics;
use crate::packet::{flags, Header, Packet, SackBlock};
use crate::persist_timer::{PersistTimer, PersistTransition};

// Re-export so existing code that imports from gbn_sender continues to compile.
pub use crate::congestion_control::{
    CongestionState, INITIAL_CWND, INITIAL_SSTHRESH,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` when sequence number `a` is ≤ `b` in wrap-around space.
///
/// Correct as long as the two values differ by less than `u32::MAX / 2`,
/// which is always the case for a window of reasonable size.
#[inline]
pub(crate) fn seq_le(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) <= (u32::MAX / 2)
}

// ---------------------------------------------------------------------------
// AckResult
// ---------------------------------------------------------------------------

/// Result returned by [`GbnSender::on_ack`].
#[derive(Debug)]
pub struct AckResult {
    /// Number of segments newly acknowledged by this ACK.
    pub acked_count: usize,

    /// RTT sample from the oldest newly-acked segment.
    ///
    /// `None` when nothing was newly acknowledged, or when the oldest
    /// newly-acked segment was retransmitted (`tx_count > 1`).  Callers
    /// must not feed a `None` sample into the RTT estimator (Karn's algorithm).
    pub rtt_sample: Option<Duration>,

    /// `true` when this ACK is a pure duplicate (same `ack_num` as the
    /// current `send_base`; `acked_count` will be 0).
    ///
    /// Three consecutive `dup_ack == true` results indicate a loss event and
    /// should trigger fast retransmit via [`GbnSender::on_triple_dup_ack_cc`].
    pub dup_ack: bool,
}

// ---------------------------------------------------------------------------
// GbnEntry
// ---------------------------------------------------------------------------

/// A single in-flight segment occupying one slot in the retransmit window.
#[derive(Debug, Clone)]
pub struct GbnEntry {
    /// The segment ready to hand to the socket.
    pub packet: Packet,
    /// Total number of times this segment has been transmitted (1 = first send).
    pub tx_count: u32,
    /// Wall-clock time of the most recent transmission.
    pub sent_at: Instant,
    /// `true` when a SACK block from the receiver covers this segment's entire
    /// byte range.  [`GbnSender::retransmit_oldest`] skips sacked entries so
    /// that only genuinely missing segments are retransmitted.
    pub sacked: bool,
}

// ---------------------------------------------------------------------------
// GbnSender
// ---------------------------------------------------------------------------

/// Go-Back-N send-side state for one connection, with pluggable congestion control.
///
/// # Sequence-number layout
///
/// ```text
///  send_base          next_seq
///      │                  │
///  ────┼──────────────────┼──────────────────▶ seq space
///      │ <── in flight ──▶│ <── sendable ───▶
/// ```
///
/// # Effective send window
///
/// ```text
///  effective_window = min(window_size, cwnd)
/// ```
///
/// `window_size` is the maximum allowed (e.g. from the receiver's advertised
/// window); `cwnd` comes from the [`CongestionControl`] implementation.
///
/// The default congestion-control algorithm is [`RenoCC`] (TCP Reno).  To
/// use a different algorithm, specify it as the type parameter:
/// ```ignore
/// let sender = GbnSender::<CubicCC>::new(seq, window_size);
/// ```
pub struct GbnSender<CC: CongestionControl = RenoCC> {
    /// Sequence number of the **oldest** unacked segment (left window edge).
    pub send_base: u32,

    /// Sequence number to use for the **next** new segment.
    pub next_seq: u32,

    /// Hard upper bound on in-flight segments (receiver window / config).
    window_size: usize,

    /// In-flight segments ordered by sequence number (front = oldest).
    pub(crate) window: VecDeque<GbnEntry>,

    // ── Receiver-side flow control ───────────────────────────────────────
    
    /// Peer's advertised receive window in bytes (`rwnd`).
    ///
    /// Updated each time an ACK is received via [`update_peer_rwnd`].
    /// Initialised to `u16::MAX` so the congestion window governs until the
    /// first ACK arrives carrying the peer's actual buffer size.
    ///
    /// [`update_peer_rwnd`]: Self::update_peer_rwnd
    peer_rwnd: usize,

    // ── Congestion control ───────────────────────────────────────────────
    
    /// Pluggable congestion-control algorithm.
    ///
    /// Exposes `cwnd()`, `on_ack()`, and `on_loss()`.  For TCP Reno the
    /// concrete type is [`RenoCC`]; fields such as `ssthresh` and `cc_state`
    /// are accessible directly via `sender.cc.ssthresh` / `sender.cc.cc_state`.
    pub cc: CC,

    /// Consecutive duplicate ACK counter (resets on any new ACK).
    ///
    /// Kept on [`GbnSender`] (not inside `cc`) because counting duplicate
    /// ACKs is a windowing concern shared by all CC algorithms.
    pub dup_ack_count: u32,

    // ── Persist timer ────────────────────────────────────────────────────
    
    /// RFC 793 persist timer state — active only while `peer_rwnd == 0`.
    ///
    /// The actual `tokio::time::Sleep` future lives in the connection layer;
    /// this struct owns the activation state and back-off interval so that the
    /// connection can arm/disarm the tokio timer in response to [`PersistTransition`]
    /// values returned by [`update_peer_rwnd`].
    ///
    /// [`update_peer_rwnd`]: Self::update_peer_rwnd
    pub persist: PersistTimer,

    /// Cumulative count of SR retransmissions (i.e. calls to
    /// [`retransmit_oldest`] that found a segment to retransmit).
    ///
    /// Used by tests to verify that the persist timer, not the retransmit
    /// timer, handled a flow-control stall.
    ///
    /// [`retransmit_oldest`]: Self::retransmit_oldest
    sr_retransmit_count: u64,

    // ── Nagle's algorithm ─────────────────────────────────────────────────
    
    /// Write-coalescing buffer (RFC 896 Nagle algorithm).
    ///
    /// Small writes are appended here.  The buffer is drained into actual
    /// segments only when the Nagle drain condition is met:
    ///   - buffer ≥ MSS (full segment ready), **or**
    ///   - pipe is empty (no unacknowledged segments in flight).
    ///
    /// Force-flushed (entire buffer sent regardless) by `flush()`, `recv()`
    /// (before blocking), and `close()`.
    nagle_buf: Vec<u8>,

    /// Whether Nagle coalescing is active.
    ///
    /// Defaults to `false` (TCP_NODELAY semantics) so that all existing
    /// tests continue to observe one segment per write, unchanged.
    /// Opt in via [`set_nagle`].
    ///
    /// [`set_nagle`]: Self::set_nagle
    nagle_enabled: bool,
}

impl<CC: CongestionControl + fmt::Debug> fmt::Debug for GbnSender<CC> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GbnSender")
            .field("send_base", &self.send_base)
            .field("next_seq", &self.next_seq)
            .field("window_size", &self.window_size)
            .field("peer_rwnd", &self.peer_rwnd)
            .field("cc", &self.cc)
            .field("dup_ack_count", &self.dup_ack_count)
            .finish_non_exhaustive()
    }
}

impl GbnSender<RenoCC> {
    /// Create a new [`GbnSender`] with the default TCP Reno congestion control.
    ///
    /// `seq_start` is the first data sequence number (typically `ISN + 1`).
    /// `window_size` is the maximum in-flight window N (≥ 1).
    ///
    /// The congestion window starts at [`INITIAL_CWND`] (1 segment) and
    /// grows via slow start until [`INITIAL_SSTHRESH`].
    pub fn new(seq_start: u32, window_size: usize) -> Self {
        assert!(window_size >= 1, "window_size must be at least 1");
        Self {
            send_base: seq_start,
            next_seq: seq_start,
            window_size,
            window: VecDeque::with_capacity(window_size),
            peer_rwnd: u16::MAX as usize,
            cc: RenoCC::new(window_size),
            dup_ack_count: 0,
            persist: PersistTimer::new(),
            sr_retransmit_count: 0,
            nagle_buf: Vec::new(),
            nagle_enabled: false,
        }
    }
}

impl<CC: CongestionControl> GbnSender<CC> {
    // -----------------------------------------------------------------------
    // Window predicates
    // -----------------------------------------------------------------------

    /// `true` when there is room for at least one more in-flight segment.
    ///
    /// Three constraints must all be satisfied simultaneously:
    ///
    /// 1. **Segment count**: `in_flight < min(window_size, cwnd)`
    /// 2. **Byte budget**: `bytes_in_flight < peer_rwnd` (receiver flow control)
    ///
    /// When `peer_rwnd == 0` the sender pauses regardless of cwnd; it will
    /// resume once the peer ACKs with a non-zero window (or after a
    /// zero-window probe triggers an updated ACK).
    pub fn can_send(&self) -> bool {
        let effective = self.window_size.min(self.cc.cwnd());
        self.window.len() < effective && self.bytes_in_flight() < self.peer_rwnd
    }

    /// Total payload bytes currently in the send window (in flight).
    pub fn bytes_in_flight(&self) -> usize {
        self.window.iter().map(|e| e.packet.payload.len()).sum()
    }

    /// Number of segments currently awaiting acknowledgement.
    pub fn in_flight(&self) -> usize {
        self.window.len()
    }

    /// `true` when at least one segment is awaiting acknowledgement.
    pub fn has_unacked(&self) -> bool {
        !self.window.is_empty()
    }

    // -----------------------------------------------------------------------
    // Send path
    // -----------------------------------------------------------------------

    /// Build a data segment using the current `next_seq`.
    ///
    /// Call [`record_sent`] immediately after to advance `next_seq` and
    /// register the segment in the window.
    ///
    /// [`record_sent`]: Self::record_sent
    pub fn build_data_packet(&self, payload: Vec<u8>, ack: u32, window: u16) -> Packet {
        Packet {
            header: Header {
                seq: self.next_seq,
                ack,
                flags: flags::ACK, // data segments piggyback the receiver's ACK
                window,
                checksum: 0,
            },
            options: vec![],
            payload,
        }
    }

    /// Register a just-transmitted segment in the window and advance `next_seq`.
    ///
    /// The `sent_at` timestamp is set to `Instant::now()` here and used later
    /// to compute the RTT sample when the segment is acknowledged.
    ///
    /// # Panics
    ///
    /// Panics in debug mode when the window is already full.  Check
    /// [`can_send`] first.
    ///
    /// [`can_send`]: Self::can_send
    pub fn record_sent(&mut self, packet: Packet) {
        debug_assert!(
            self.can_send(),
            "record_sent on a full window ({}/{})",
            self.window.len(),
            self.window_size.min(self.cc.cwnd())
        );
        let payload_len = packet.payload.len() as u32;
        self.window.push_back(GbnEntry {
            packet,
            tx_count: 1,
            sent_at: Instant::now(),
            sacked: false,
        });
        self.next_seq = self.next_seq.wrapping_add(payload_len);
    }

    // -----------------------------------------------------------------------
    // ACK path
    // -----------------------------------------------------------------------

    /// Process a cumulative ACK.
    ///
    /// Removes all window entries whose data ends at or before `ack_num`,
    /// advances `send_base`, and returns an [`AckResult`] containing:
    ///
    /// - `acked_count`: how many segments were newly acknowledged.
    /// - `rtt_sample`: elapsed time since the oldest acked segment was sent,
    ///   or `None` when nothing was newly acked or the oldest segment was
    ///   retransmitted (Karn's algorithm).
    /// - `dup_ack`: `true` when this ACK duplicates the current `send_base`
    ///   (nothing newly acked because a segment was lost or reordered).
    ///
    /// **Does not update the congestion window.**  Call [`on_ack_cc`] with
    /// the returned `acked_count` to drive the Reno state machine.
    ///
    /// [`on_ack_cc`]: Self::on_ack_cc
    pub fn on_ack(&mut self, ack_num: u32) -> AckResult {
        let mut result = AckResult {
            acked_count: 0,
            rtt_sample: None,
            dup_ack: false,
        };

        // Reject ACKs behind send_base or beyond next_seq.
        if !seq_le(self.send_base, ack_num) || !seq_le(ack_num, self.next_seq) {
            return result;
        }

        // ack_num == send_base means nothing new.
        if ack_num == self.send_base {
            // Count as duplicate ACK only when there are unacked segments
            // (i.e. we're actually waiting for an ACK for this segment).
            if self.has_unacked() {
                result.dup_ack = true;
                self.dup_ack_count += 1;
                metrics::DUPLICATE_ACKS.inc();
            }
            return result;
        }

        // New ACK — reset dup-ACK counter.
        self.dup_ack_count = 0;

        let mut is_oldest = true;

        while let Some(front) = self.window.front() {
            // `seg_end` is the sequence number of the first byte AFTER this segment.
            let seg_end = front
                .packet
                .header
                .seq
                .wrapping_add(front.packet.payload.len() as u32);

            if !seq_le(seg_end, ack_num) {
                break;
            }

            // Capture RTT sample from the oldest newly-acked segment only.
            // Karn's algorithm: discard the sample if the segment was retransmitted.
            if is_oldest {
                if front.tx_count == 1 {
                    result.rtt_sample = Some(front.sent_at.elapsed());
                }
                is_oldest = false;
            }

            self.send_base = seg_end;
            self.window.pop_front();
            result.acked_count += 1;
        }

        result
    }

    // -----------------------------------------------------------------------
    // Congestion control
    // -----------------------------------------------------------------------

    /// Update the congestion window after `acked_count` new segments are ACKed.
    ///
    /// Delegates to [`CongestionControl::on_ack`].  Call this **after**
    /// [`on_ack`] returns a positive `acked_count`.
    ///
    /// [`on_ack`]: Self::on_ack
    pub fn on_ack_cc(&mut self, acked_count: usize) {
        self.cc.on_ack(acked_count);
    }

    /// Handle a retransmit timeout: delegate to the CC algorithm and reset
    /// the duplicate-ACK counter (RFC 5681 §3.1).
    ///
    /// Call this **after** retransmitting the window and calling
    /// [`on_retransmit`] so that `in_flight()` still reflects the correct
    /// count before the window is slid.
    ///
    /// [`on_retransmit`]: Self::on_retransmit
    pub fn on_timeout_cc(&mut self) {
        let in_flight = self.window.len();
        self.cc.on_loss(in_flight, LossKind::Timeout);
        self.dup_ack_count = 0;
    }

    /// Handle three duplicate ACKs: enter Fast Recovery (Reno fast retransmit).
    ///
    /// Delegates to the CC algorithm with [`LossKind::TripleDupAck`].  The
    /// caller is responsible for retransmitting the oldest unacked segment
    /// immediately after.
    ///
    /// # Note
    /// Only call when [`dup_ack_count`] has just reached 3.
    pub fn on_triple_dup_ack_cc(&mut self) {
        let in_flight = self.window.len();
        self.cc.on_loss(in_flight, LossKind::TripleDupAck);
    }

    // -----------------------------------------------------------------------
    // Retransmit helpers
    // -----------------------------------------------------------------------

    /// Iterate over all in-flight segments from oldest to newest.
    ///
    /// Used by the connection layer to inspect the window (e.g. for
    /// zero-window probing or diagnostics).
    pub fn window_entries(&self) -> impl Iterator<Item = &GbnEntry> {
        self.window.iter()
    }

    /// Selective Repeat retransmit: resend only the **oldest** unacked segment.
    ///
    /// Increments `tx_count` and refreshes `sent_at` for that entry only
    /// (so Karn's algorithm suppresses its RTT sample on the next ACK).
    /// Returns a clone of the retransmitted packet, or `None` when the window
    /// is empty.
    ///
    /// Call [`on_timeout_cc`] separately to adjust the congestion window.
    ///
    /// [`on_timeout_cc`]: Self::on_timeout_cc
    pub fn retransmit_oldest(&mut self) -> Option<Packet> {
        // Skip SACK-covered entries: only retransmit the first segment the
        // receiver has NOT yet acknowledged (either cumulatively or via SACK).
        if let Some(entry) = self.window.iter_mut().find(|e| !e.sacked) {
            entry.tx_count += 1;
            entry.sent_at = Instant::now();
            self.sr_retransmit_count += 1;
            metrics::RETRANSMISSIONS.inc();
            Some(entry.packet.clone())
        } else {
            None
        }
    }

    /// Cumulative number of SR retransmissions (segments re-sent by the
    /// retransmit timer path).  Does **not** include persist probes.
    pub fn sr_retransmit_count(&self) -> u64 {
        self.sr_retransmit_count
    }

    /// Increment the transmission count and refresh `sent_at` for every
    /// in-flight segment.
    ///
    /// Used by the fast-retransmit path when the caller wants to mark *all*
    /// segments as retransmitted (e.g. after a Go-Back-N style probe).
    pub fn on_retransmit(&mut self) {
        let now = Instant::now();
        for entry in self.window.iter_mut() {
            entry.tx_count += 1;
            entry.sent_at = now;
        }
    }

    /// Wall-clock time when the oldest in-flight segment was last sent.
    ///
    /// Returns `None` when the window is empty.
    pub fn oldest_sent_at(&self) -> Option<Instant> {
        self.window.front().map(|e| e.sent_at)
    }

    // -----------------------------------------------------------------------
    // Flow-control methods
    // -----------------------------------------------------------------------

    /// Update the sender's view of the peer's receive window.
    ///
    /// Call this every time an ACK arrives — the ACK's `window` field carries
    /// the peer's current free buffer space in bytes.
    ///
    /// The `rwnd` parameter should be the **scaled** receive window when window
    /// scaling is in effect: `raw_header_window << rcv_wscale`.  Callers that
    /// have not negotiated window scaling should pass the raw header value.
    ///
    /// Returns a [`PersistTransition`] indicating whether the persist timer
    /// should be armed (`Activated`), disarmed (`Deactivated`), or left
    /// unchanged.  The connection layer uses this to manage the underlying
    /// `tokio::time::Sleep` futures.
    pub fn update_peer_rwnd(&mut self, rwnd: usize) -> PersistTransition {
        self.peer_rwnd = rwnd;
        let t = self.persist.on_rwnd_update(self.peer_rwnd);
        log::trace!("[sender] peer_rwnd={} persist_transition={:?}", self.peer_rwnd, t);
        t
    }

    /// Peer's current advertised receive window in bytes.
    pub fn peer_rwnd(&self) -> usize {
        self.peer_rwnd
    }

    // -----------------------------------------------------------------------
    // Congestion control accessors (for tests and diagnostics)
    // -----------------------------------------------------------------------

    /// Current congestion window in segments.
    ///
    /// Delegates to the underlying [`CongestionControl`] implementation.
    /// Algorithm-specific state (e.g. `ssthresh`, `cc_state` for Reno) is
    /// accessible directly via `sender.cc.ssthresh` / `sender.cc.cc_state`.
    pub fn cwnd(&self) -> usize {
        self.cc.cwnd()
    }

    /// Number of consecutive duplicate ACKs seen since the last new ACK.
    pub fn dup_ack_count(&self) -> u32 {
        self.dup_ack_count
    }

    // -----------------------------------------------------------------------
    // SACK processing
    // -----------------------------------------------------------------------

    /// Mark window entries covered by the receiver's SACK blocks.
    ///
    /// A segment is considered SACKed when its entire byte range
    /// `[seq, seq+len)` is contained within one of the supplied blocks.
    /// Already-marked entries are skipped (idempotent).
    ///
    /// Sacked entries are skipped by [`retransmit_oldest`] so that only
    /// genuinely missing segments are retransmitted on timeout or fast
    /// retransmit.  The `sacked` flag is cleared automatically when the
    /// entry is popped from the window by a cumulative ACK.
    ///
    /// [`retransmit_oldest`]: Self::retransmit_oldest
    pub fn process_sack(&mut self, blocks: &[SackBlock]) {
        if blocks.is_empty() {
            return;
        }
        for entry in self.window.iter_mut() {
            if entry.sacked {
                continue;
            }
            let seq = entry.packet.header.seq;
            let end = seq.wrapping_add(entry.packet.payload.len() as u32);
            for block in blocks {
                if seq_le(block.left, seq) && seq_le(end, block.right) {
                    entry.sacked = true;
                    break;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Nagle's algorithm
    // -----------------------------------------------------------------------

    /// Enable or disable Nagle write-coalescing.
    ///
    /// When `true`, small writes are held in an internal buffer until either
    /// the buffer reaches one MSS or the pipe (send window) is empty.  When
    /// `false` (the default), every write is dispatched immediately as a
    /// separate segment (`TCP_NODELAY` semantics).
    pub fn set_nagle(&mut self, enabled: bool) {
        self.nagle_enabled = enabled;
    }

    /// Whether Nagle coalescing is currently active.
    pub fn nagle_enabled(&self) -> bool {
        self.nagle_enabled
    }

    /// Bytes currently held in the Nagle buffer.
    pub fn nagle_pending(&self) -> usize {
        self.nagle_buf.len()
    }

    /// Append `data` to the Nagle buffer and return all segments that are
    /// ready to transmit, each at most `mss` bytes long.
    ///
    /// The Nagle drain condition is:
    /// - buffer ≥ MSS (a full segment is available), **or**
    /// - pipe is empty (`!has_unacked()`).
    ///
    /// When Nagle is disabled, all data is returned immediately (TCP_NODELAY).
    /// The caller must call [`record_sent`] for each returned segment after
    /// transmitting it to update the send window and sequence numbers.
    ///
    /// [`record_sent`]: Self::record_sent
    pub fn nagle_push(&mut self, data: &[u8], mss: usize) -> Vec<Vec<u8>> {
        self.nagle_buf.extend_from_slice(data);
        self.nagle_drain_ready(mss)
    }

    /// Drain ready segments from the Nagle buffer **without** adding new data.
    ///
    /// Call this after an ACK advances `send_base` and potentially empties
    /// the pipe, so that any coalesced data held by Nagle is released.
    pub fn nagle_pump(&mut self, mss: usize) -> Vec<Vec<u8>> {
        self.nagle_drain_ready(mss)
    }

    /// Force-drain the entire Nagle buffer regardless of Nagle conditions.
    ///
    /// Returns the concatenated buffered bytes, or `None` when empty.
    /// Use this in `flush()`, `recv()` (before blocking), and `close()` to
    /// ensure all pending data is transmitted before waiting for ACKs or
    /// sending a FIN.
    ///
    /// The returned bytes may exceed one MSS; the caller must chunk them into
    /// MSS-sized segments before transmission.
    pub fn nagle_force_flush(&mut self) -> Option<Vec<u8>> {
        if self.nagle_buf.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.nagle_buf))
        }
    }

    /// Core Nagle drain: emit segments that satisfy the send condition.
    ///
    /// Drains full MSS-sized chunks first; the final sub-MSS remainder is
    /// held when Nagle is enabled and the pipe is non-empty.
    fn nagle_drain_ready(&mut self, mss: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            if self.nagle_buf.is_empty() {
                break;
            }
            let should_send = if self.nagle_enabled {
                // RFC 896 Nagle condition.
                self.nagle_buf.len() >= mss || !self.has_unacked()
            } else {
                true // TCP_NODELAY: always send.
            };
            if !should_send {
                break;
            }
            let len = self.nagle_buf.len().min(mss);
            out.push(self.nagle_buf.drain(..len).collect());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pkt(seq: u32, payload_len: usize) -> Packet {
        Packet {
            header: Header {
                seq,
                ack: 0,
                flags: flags::ACK,
                window: 8192,
                checksum: 0,
            },
            options: vec![],
            payload: vec![0u8; payload_len],
        }
    }

    #[test]
    fn initial_state() {
        let s = GbnSender::new(100, 4);
        assert_eq!(s.send_base, 100);
        assert_eq!(s.next_seq, 100);
        assert!(s.can_send());
        assert!(!s.has_unacked());
        assert_eq!(s.in_flight(), 0);
        assert_eq!(s.cwnd(), INITIAL_CWND);
        assert_eq!(s.cc.ssthresh, INITIAL_SSTHRESH);
        assert_eq!(s.cc.cc_state, CongestionState::SlowStart);
    }

    #[test]
    fn record_sent_advances_next_seq() {
        let mut s = GbnSender::new(0, 4);
        let pkt = s.build_data_packet(vec![1, 2, 3], 0, 8192);
        s.record_sent(pkt);

        assert_eq!(s.next_seq, 3);
        assert_eq!(s.send_base, 0);
        assert_eq!(s.in_flight(), 1);
        assert!(s.has_unacked());
    }

    #[test]
    fn window_full_blocks_send() {
        let mut s = GbnSender::new(0, 2);
        s.cc.cwnd = 2; // open cwnd so window_size is the binding constraint
        let p1 = make_pkt(0, 5);
        let p2 = make_pkt(5, 5);
        s.record_sent(p1);
        s.next_seq = 5;
        s.record_sent(p2);
        s.next_seq = 10;

        assert!(!s.can_send());
        assert_eq!(s.in_flight(), 2);
    }

    #[test]
    fn ack_slides_window_by_one() {
        let mut s = GbnSender::new(0, 4);
        let p = s.build_data_packet(vec![0u8; 10], 0, 8192);
        s.record_sent(p);

        let r = s.on_ack(10);
        assert_eq!(r.acked_count, 1);
        assert_eq!(s.send_base, 10);
        assert!(!s.has_unacked());
    }

    #[test]
    fn cumulative_ack_slides_multiple() {
        let mut s = GbnSender::new(0, 4);
        s.cc.cwnd = 4; // bypass cwnd so window_size governs
        for _ in 0..3 {
            let pkt = s.build_data_packet(vec![0u8; 5], 0, 8192);
            s.record_sent(pkt);
        }
        assert_eq!(s.next_seq, 15);

        let r = s.on_ack(15);
        assert_eq!(r.acked_count, 3);
        assert_eq!(s.send_base, 15);
        assert!(!s.has_unacked());
    }

    #[test]
    fn duplicate_ack_returns_zero() {
        let mut s = GbnSender::new(0, 4);
        let p = s.build_data_packet(vec![0u8; 5], 0, 8192);
        s.record_sent(p);

        let first = s.on_ack(5);
        assert_eq!(first.acked_count, 1);

        let dup = s.on_ack(5);
        assert_eq!(dup.acked_count, 0);
        assert!(dup.rtt_sample.is_none());
    }

    #[test]
    fn spurious_ack_beyond_next_seq_ignored() {
        let mut s = GbnSender::new(0, 4);
        let p = s.build_data_packet(vec![0u8; 5], 0, 8192);
        s.record_sent(p);

        let r = s.on_ack(1000);
        assert_eq!(r.acked_count, 0);
        assert_eq!(s.send_base, 0);
    }

    #[test]
    fn partial_cumulative_ack() {
        let mut s = GbnSender::new(0, 4);
        s.cc.cwnd = 4;
        for _ in 0..3 {
            let pkt = s.build_data_packet(vec![0u8; 5], 0, 8192);
            s.record_sent(pkt);
        }
        let r = s.on_ack(10);
        assert_eq!(r.acked_count, 2);
        assert_eq!(s.send_base, 10);
        assert_eq!(s.in_flight(), 1);
    }

    #[test]
    fn on_retransmit_increments_tx_count() {
        let mut s = GbnSender::new(0, 4);
        let p = s.build_data_packet(vec![0u8; 5], 0, 8192);
        s.record_sent(p);

        assert_eq!(s.window.front().unwrap().tx_count, 1);
        s.on_retransmit();
        assert_eq!(s.window.front().unwrap().tx_count, 2);
    }

    #[test]
    fn seq_wrap_around() {
        let start = u32::MAX - 5;
        let mut s = GbnSender::new(start, 4);
        let p = s.build_data_packet(vec![0u8; 10], 0, 8192);
        s.record_sent(p);

        let expected_ack = start.wrapping_add(10);
        let r = s.on_ack(expected_ack);
        assert_eq!(r.acked_count, 1);
        assert_eq!(s.send_base, expected_ack);
    }

    // ── Karn's algorithm ────────────────────────────────────────────────────

    #[test]
    fn clean_segment_yields_rtt_sample() {
        let mut s = GbnSender::new(0, 1);
        let p = s.build_data_packet(vec![0u8; 5], 0, 8192);
        s.record_sent(p);

        // tx_count == 1 (never retransmitted) → sample must be present.
        let r = s.on_ack(5);
        assert_eq!(r.acked_count, 1);
        assert!(
            r.rtt_sample.is_some(),
            "tx_count==1 segment must produce an RTT sample"
        );
        // Sample should be tiny (measured in this test process).
        assert!(
            r.rtt_sample.unwrap() < Duration::from_millis(100),
            "sample should be near-zero in a unit test"
        );
    }

    #[test]
    fn retransmitted_segment_yields_no_rtt_sample() {
        let mut s = GbnSender::new(0, 1);
        let p = s.build_data_packet(vec![0u8; 5], 0, 8192);
        s.record_sent(p);

        // Simulate one retransmit: tx_count becomes 2.
        s.on_retransmit();
        assert_eq!(s.window.front().unwrap().tx_count, 2);

        // Karn's algorithm: ACK for a retransmitted segment → no RTT sample.
        let r = s.on_ack(5);
        assert_eq!(r.acked_count, 1);
        assert!(
            r.rtt_sample.is_none(),
            "tx_count>1 segment must NOT produce an RTT sample (Karn's algorithm)"
        );
    }

    #[test]
    fn rtt_sample_taken_from_oldest_only() {
        // With 3 segments in the window, a cumulative ACK for all three
        // should yield the sample from segment 0 only (the oldest).
        let mut s = GbnSender::new(0, 4);
        s.cc.cwnd = 4;
        for _ in 0..3 {
            let pkt = s.build_data_packet(vec![0u8; 4], 0, 8192);
            s.record_sent(pkt);
        }

        // Retransmit only the middle segment by manually bumping its tx_count.
        s.window[1].tx_count = 2;

        // Cumulative ACK for all three: oldest (index 0) has tx_count==1 → sample present.
        let r = s.on_ack(12);
        assert_eq!(r.acked_count, 3);
        assert!(
            r.rtt_sample.is_some(),
            "oldest segment tx_count==1 → sample expected"
        );
    }

    #[test]
    fn karn_oldest_retransmitted_no_sample_even_if_later_clean() {
        // Even when later segments are clean, if the OLDEST was retransmitted
        // the sample must be None.
        let mut s = GbnSender::new(0, 4);
        s.cc.cwnd = 4;
        for _ in 0..3 {
            let pkt = s.build_data_packet(vec![0u8; 4], 0, 8192);
            s.record_sent(pkt);
        }

        // Mark the OLDEST segment as retransmitted.
        s.window[0].tx_count = 2;

        let r = s.on_ack(12);
        assert_eq!(r.acked_count, 3);
        assert!(
            r.rtt_sample.is_none(),
            "oldest segment retransmitted → no RTT sample (Karn's algorithm)"
        );
    }

    // ── Congestion control ──────────────────────────────────────────────────

    #[test]
    fn can_send_limited_by_cwnd() {
        // window_size = 8, cwnd starts at 1 → only 1 slot available.
        let mut s = GbnSender::new(0, 8);
        assert_eq!(s.cwnd(), 1);
        assert!(s.can_send());

        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);
        // cwnd=1, in_flight=1 → full.
        assert!(!s.can_send());

        // ACK the segment, grow cwnd to 2.
        s.on_ack(4);
        s.on_ack_cc(1);
        assert_eq!(s.cwnd(), 2);
        assert!(s.can_send()); // in_flight=0 < cwnd=2
    }

    #[test]
    fn slow_start_doubles_cwnd_per_rtt() {
        // With ssthresh=32, slow start should grow cwnd exponentially.
        let mut s = GbnSender::new(0, 32);
        s.cc.ssthresh = 32; // keep SS going
        assert_eq!(s.cwnd(), 1);

        // RTT 1: 1 segment in flight, gets ACKed → cwnd = 2
        for _ in 0..1 {
            let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
            s.record_sent(p);
        }
        let r = s.on_ack(4);
        s.on_ack_cc(r.acked_count);
        assert_eq!(s.cwnd(), 2, "SS: cwnd should double after 1st ACK");

        // RTT 2: 2 segments in flight, get ACKed → cwnd = 4
        for _ in 0..2 {
            let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
            s.record_sent(p);
        }
        let r = s.on_ack(s.next_seq);
        s.on_ack_cc(r.acked_count);
        assert_eq!(s.cwnd(), 4, "SS: cwnd should double after 2nd RTT");
    }

    #[test]
    fn slow_start_transitions_to_ca_at_ssthresh() {
        let mut s = GbnSender::new(0, 32);
        s.cc.ssthresh = 4;
        assert_eq!(s.cc.cc_state, CongestionState::SlowStart);

        // 4 ACKs at cwnd=1 → cwnd = 1+4 = 5 ≥ ssthresh → transition to CA.
        // cwnd is allowed to overshoot ssthresh during the slow-start step.
        s.on_ack_cc(4);
        assert_eq!(s.cc.cc_state, CongestionState::CongestionAvoidance);
        assert!(
            s.cwnd() >= s.cc.ssthresh,
            "cwnd ({}) must be ≥ ssthresh ({}) after SS→CA transition",
            s.cwnd(), s.cc.ssthresh
        );
    }

    #[test]
    fn congestion_avoidance_grows_by_one_per_rtt() {
        let mut s = GbnSender::new(0, 32);
        s.cc.ssthresh = 4;
        s.cc.cwnd = 4;
        s.cc.cc_state = CongestionState::CongestionAvoidance;

        // First "RTT": 4 ACKs come in (one per in-flight segment).
        s.on_ack_cc(4);
        assert_eq!(s.cwnd(), 5, "CA: cwnd should increase by 1 after 4 ACKs (one RTT)");

        // Second "RTT": 5 ACKs → cwnd = 6.
        s.on_ack_cc(5);
        assert_eq!(s.cwnd(), 6, "CA: cwnd should increase by 1 per RTT");
    }

    #[test]
    fn timeout_halves_ssthresh_and_resets_cwnd() {
        let mut s = GbnSender::new(0, 32);
        s.cc.cwnd = 8;
        s.cc.ssthresh = 16;
        s.cc.cc_state = CongestionState::CongestionAvoidance;

        // Put 6 segments in flight (manually, to avoid cwnd restriction).
        for i in 0..6u32 {
            s.window.push_back(GbnEntry {
                packet: make_pkt(i * 4, 4),
                tx_count: 1,
                sent_at: Instant::now(),
                sacked: false,
            });
        }
        assert_eq!(s.in_flight(), 6);

        s.on_timeout_cc();

        assert_eq!(s.cc.ssthresh, 3, "ssthresh = max(2, 6/2) = 3");
        assert_eq!(s.cwnd(), 1, "cwnd resets to 1 on timeout");
        assert_eq!(s.cc.cc_state, CongestionState::SlowStart);
    }

    #[test]
    fn timeout_ssthresh_floors_at_two() {
        let mut s = GbnSender::new(0, 32);
        // Only 1 segment in flight when timeout fires.
        s.window.push_back(GbnEntry {
            packet: make_pkt(0, 4),
            tx_count: 1,
            sent_at: Instant::now(),
            sacked: false,
        });

        s.on_timeout_cc();
        assert_eq!(s.cc.ssthresh, 2, "ssthresh floor is 2 even when in_flight/2 < 2");
        assert_eq!(s.cwnd(), 1);
    }

    #[test]
    fn triple_dup_ack_enters_fast_recovery() {
        let mut s = GbnSender::new(0, 8);
        // Manually place 4 segments in the window.
        for i in 0..4u32 {
            s.window.push_back(GbnEntry {
                packet: make_pkt(i * 4, 4),
                tx_count: 1,
                sent_at: Instant::now(),
                sacked: false,
            });
        }
        s.next_seq = 16;

        // 3 duplicate ACKs for seq=0 (send_base).
        for _ in 0..3 {
            let r = s.on_ack(0);
            assert!(r.dup_ack, "should be flagged as dup-ACK");
        }
        assert_eq!(s.dup_ack_count(), 3);

        s.on_triple_dup_ack_cc();

        // ssthresh = max(2, 4/2) = 2; cwnd = ssthresh + 3 = 5.
        assert_eq!(s.cc.ssthresh, 2);
        assert_eq!(s.cwnd(), 5);
        assert_eq!(s.cc.cc_state, CongestionState::FastRecovery);
    }

    #[test]
    fn fast_recovery_exits_on_new_ack() {
        let mut s = GbnSender::new(0, 16);
        s.cc.ssthresh = 4;
        s.cc.cwnd = 7; // ssthresh + 3
        s.cc.cc_state = CongestionState::FastRecovery;

        // New ACK arrives: exit fast recovery, cwnd = ssthresh.
        s.on_ack_cc(1);

        assert_eq!(s.cwnd(), 4, "exit FR: cwnd ← ssthresh");
        assert_eq!(s.cc.cc_state, CongestionState::CongestionAvoidance);
    }

    // ── Nagle's algorithm ───────────────────────────────────────────────────

    #[test]
    fn nagle_disabled_drains_immediately() {
        let mut s = GbnSender::new(0, 4);
        assert!(!s.nagle_enabled(), "Nagle must be off by default (TCP_NODELAY)");

        // Even with a segment in flight, TCP_NODELAY drains immediately.
        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);
        assert!(s.has_unacked());

        let ready = s.nagle_push(b"hi", 1460);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], b"hi");
        assert_eq!(s.nagle_pending(), 0, "buffer must be empty after drain");
    }

    #[test]
    fn nagle_enabled_holds_small_write_when_pipe_nonempty() {
        let mut s = GbnSender::new(0, 4);
        s.set_nagle(true);

        // Put a segment in flight.
        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);
        assert!(s.has_unacked());

        let ready = s.nagle_push(b"small", 1460);
        assert!(ready.is_empty(), "Nagle should hold small write when pipe is non-empty");
        assert_eq!(s.nagle_pending(), 5);
    }

    #[test]
    fn nagle_enabled_sends_when_pipe_empty() {
        let mut s = GbnSender::new(0, 4);
        s.set_nagle(true);
        assert!(!s.has_unacked(), "pipe must be empty at start");

        let ready = s.nagle_push(b"hello", 1460);
        assert_eq!(ready.len(), 1, "pipe empty → drain immediately");
        assert_eq!(&ready[0], b"hello");
    }

    #[test]
    fn nagle_enabled_sends_full_segment_even_when_pipe_nonempty() {
        let mut s = GbnSender::new(0, 4);
        s.set_nagle(true);

        // Pipe nonempty.
        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);

        // Write exactly one MSS — should flush even though pipe is non-empty.
        let data = vec![0xABu8; 100];
        let ready = s.nagle_push(&data, 100);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].len(), 100);
        assert_eq!(s.nagle_pending(), 0);
    }

    #[test]
    fn nagle_pump_drains_after_ack_empties_pipe() {
        let mut s = GbnSender::new(0, 4);
        s.set_nagle(true);

        // Send a segment → pipe nonempty.
        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);

        // Small write: held by Nagle.
        let held = s.nagle_push(b"buffered", 1460);
        assert!(held.is_empty(), "Nagle should hold while pipe is non-empty");
        assert_eq!(s.nagle_pending(), 8);

        // ACK clears the pipe.
        s.on_ack(4);
        assert!(!s.has_unacked(), "pipe must be empty after ACK");

        // Pump: pipe empty → Nagle condition met → drain.
        let drained = s.nagle_pump(1460);
        assert_eq!(drained.len(), 1);
        assert_eq!(&drained[0], b"buffered");
        assert_eq!(s.nagle_pending(), 0);
    }

    #[test]
    fn nagle_coalesces_multiple_small_pushes() {
        let mut s = GbnSender::new(0, 4);
        s.set_nagle(true);

        // Pipe nonempty: segment in flight.
        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);

        // Two sub-MSS pushes; neither alone reaches MSS=6.
        let r1 = s.nagle_push(b"abc", 6); // 3 bytes < mss=6 → held
        assert!(r1.is_empty(), "first sub-MSS push should be held");
        assert_eq!(s.nagle_pending(), 3);

        // Second push: 3+3 = 6 ≥ mss=6 → drain as one coalesced segment.
        let r2 = s.nagle_push(b"def", 6);
        assert_eq!(r2.len(), 1, "should produce exactly one coalesced segment");
        assert_eq!(&r2[0], b"abcdef", "segments should be coalesced");
        assert_eq!(s.nagle_pending(), 0);
    }

    #[test]
    fn nagle_force_flush_releases_held_data() {
        let mut s = GbnSender::new(0, 4);
        s.set_nagle(true);

        // Pipe nonempty.
        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);

        // Two sub-MSS pushes — both held.
        s.nagle_push(b"part1", 1460);
        s.nagle_push(b"part2", 1460);
        assert_eq!(s.nagle_pending(), 10);

        // Force-flush: bypasses Nagle hold, returns all buffered bytes.
        let flushed = s.nagle_force_flush();
        assert!(flushed.is_some());
        assert_eq!(flushed.unwrap(), b"part1part2");
        assert_eq!(s.nagle_pending(), 0);
    }

    #[test]
    fn nagle_force_flush_returns_none_when_empty() {
        let mut s = GbnSender::new(0, 4);
        s.set_nagle(true);
        assert!(s.nagle_force_flush().is_none());
    }

    #[test]
    fn nagle_drains_remainder_after_mss_aligned_chunks() {
        let mut s = GbnSender::new(0, 4);
        s.set_nagle(true);
        // Pipe is empty → all data drains immediately, even the sub-MSS tail.
        let data = vec![0u8; 250];
        let ready = s.nagle_push(&data, 100);
        // 250 bytes / 100 = 2 full + 50 remainder.  Pipe was empty → all drain.
        assert_eq!(ready.len(), 3, "pipe empty: all chunks drain, including remainder");
        assert_eq!(ready[0].len(), 100);
        assert_eq!(ready[1].len(), 100);
        assert_eq!(ready[2].len(), 50);
    }

    #[test]
    fn nagle_holds_remainder_when_pipe_nonempty() {
        let mut s = GbnSender::new(0, 4);
        s.set_nagle(true);

        // Pipe nonempty.
        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);

        // 250 bytes with mss=100: two full chunks drain, 50-byte tail is held.
        let data = vec![0u8; 250];
        let ready = s.nagle_push(&data, 100);
        assert_eq!(ready.len(), 2, "two full MSS chunks should drain");
        assert_eq!(ready[0].len(), 100);
        assert_eq!(ready[1].len(), 100);
        assert_eq!(s.nagle_pending(), 50, "50-byte tail held by Nagle");
    }

    #[test]
    fn dup_ack_flag_set_correctly() {
        let mut s = GbnSender::new(0, 4);
        let p = s.build_data_packet(vec![0u8; 8], 0, 8192);
        s.record_sent(p);

        // Genuine ACK → not a dup.
        let r = s.on_ack(8);
        assert!(!r.dup_ack);

        // Now window is empty; a re-ACK of send_base is NOT treated as a dup.
        let r2 = s.on_ack(8);
        assert!(!r2.dup_ack, "dup-ACK only counted when there are unacked segments");
    }

    // ── SACK processing ──────────────────────────────────────────────────────

    #[test]
    fn process_sack_marks_covered_entry() {
        let mut s = GbnSender::new(0, 4);
        s.cc.cwnd = 4;
        // Send two segments: seq=0 len=10, seq=10 len=10.
        let p1 = s.build_data_packet(vec![0u8; 10], 0, 8192);
        s.record_sent(p1);
        let p2 = s.build_data_packet(vec![0u8; 10], 0, 8192);
        s.record_sent(p2);
        // seq=10..20 is SACKed.
        s.process_sack(&[SackBlock { left: 10, right: 20 }]);
        assert!(!s.window[0].sacked, "seq=0..10 not in SACK block");
        assert!(s.window[1].sacked,  "seq=10..20 covered by SACK block");
    }

    #[test]
    fn retransmit_oldest_skips_sacked_entry() {
        let mut s = GbnSender::new(0, 4);
        s.cc.cwnd = 4;
        // Two segments in flight.
        let p1 = s.build_data_packet(vec![0u8; 10], 0, 8192);
        s.record_sent(p1);
        let p2 = s.build_data_packet(vec![0u8; 10], 0, 8192);
        s.record_sent(p2);
        // SACK the oldest entry (seq=0..10).
        s.window[0].sacked = true;
        // retransmit_oldest must skip it and return the second segment (seq=10).
        let pkt = s.retransmit_oldest().expect("should find unsacked segment");
        assert_eq!(pkt.header.seq, 10, "should skip sacked seq=0 and retransmit seq=10");
        assert_eq!(s.sr_retransmit_count, 1);
    }

    #[test]
    fn retransmit_oldest_returns_none_when_all_sacked() {
        let mut s = GbnSender::new(0, 4);
        s.cc.cwnd = 4;
        let p1 = s.build_data_packet(vec![0u8; 10], 0, 8192);
        s.record_sent(p1);
        s.window[0].sacked = true;
        assert!(
            s.retransmit_oldest().is_none(),
            "no retransmit when all in-flight segments are sacked"
        );
    }

    #[test]
    fn process_sack_is_idempotent() {
        let mut s = GbnSender::new(0, 4);
        s.cc.cwnd = 4;
        let p = s.build_data_packet(vec![0u8; 10], 0, 8192);
        s.record_sent(p);
        let block = SackBlock { left: 0, right: 10 };
        s.process_sack(&[block.clone()]);
        s.process_sack(&[block]);
        assert!(s.window[0].sacked);
        assert_eq!(s.window.len(), 1, "window unchanged after repeated SACK");
    }

    #[test]
    fn sacked_flag_cleared_when_entry_cumulatively_acked() {
        let mut s = GbnSender::new(0, 4);
        s.cc.cwnd = 4;
        // Three segments: sack the middle one, then cumulative ACK past it.
        let p1 = s.build_data_packet(vec![0u8; 5], 0, 8192);
        s.record_sent(p1);
        let p2 = s.build_data_packet(vec![0u8; 5], 0, 8192);
        s.record_sent(p2);
        let p3 = s.build_data_packet(vec![0u8; 5], 0, 8192);
        s.record_sent(p3);
        // SACK p2 (seq=5..10).
        s.process_sack(&[SackBlock { left: 5, right: 10 }]);
        assert!(s.window[1].sacked);
        // Cumulative ACK through seq=15 (covers all three).
        let r = s.on_ack(15);
        assert_eq!(r.acked_count, 3);
        assert!(!s.has_unacked(), "all entries acked and removed from window");
    }
}
