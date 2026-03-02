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
use std::time::{Duration, Instant};

use crate::packet::{flags, Header, Packet};

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
// Congestion control constants
// ---------------------------------------------------------------------------

/// Initial congestion window: 1 segment (RFC 5681 §3.1).
pub const INITIAL_CWND: usize = 1;

/// Initial slow-start threshold: effectively unlimited until the first loss.
pub const INITIAL_SSTHRESH: usize = 64;

// ---------------------------------------------------------------------------
// CongestionState
// ---------------------------------------------------------------------------

/// Current phase of the TCP Reno congestion control state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CongestionState {
    /// `cwnd` grows by 1 per newly-acked segment (exponential until `ssthresh`).
    SlowStart,
    /// `cwnd` grows by 1 per RTT (additive increase).
    CongestionAvoidance,
    /// Entered on 3 duplicate ACKs; exits to CA when a new ACK advances the window.
    FastRecovery,
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
}

// ---------------------------------------------------------------------------
// GbnSender
// ---------------------------------------------------------------------------

/// Go-Back-N send-side state for one connection, with TCP Reno congestion control.
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
/// window); `cwnd` is the congestion window managed by Reno.
#[derive(Debug)]
pub struct GbnSender {
    /// Sequence number of the **oldest** unacked segment (left window edge).
    pub send_base: u32,

    /// Sequence number to use for the **next** new segment.
    pub next_seq: u32,

    /// Hard upper bound on in-flight segments (receiver window / config).
    window_size: usize,

    /// In-flight segments ordered by sequence number (front = oldest).
    pub(crate) window: VecDeque<GbnEntry>,

    // ── Reno congestion control ──────────────────────────────────────────

    /// Congestion window in segments (Reno-managed).
    pub cwnd: usize,

    /// Slow-start threshold in segments.
    pub ssthresh: usize,

    /// Current Reno phase.
    pub cc_state: CongestionState,

    /// Consecutive duplicate ACK counter (resets on any new ACK).
    dup_ack_count: u32,

    /// Partial-increment accumulator for the congestion-avoidance phase.
    /// Incremented by `acked_count` on every ACK; when it reaches `cwnd`,
    /// `cwnd` is increased by 1 and the counter resets.
    cwnd_ca_counter: usize,
}

impl GbnSender {
    /// Create a new [`GbnSender`].
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
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            cc_state: CongestionState::SlowStart,
            dup_ack_count: 0,
            cwnd_ca_counter: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Window predicates
    // -----------------------------------------------------------------------

    /// `true` when there is room for at least one more in-flight segment.
    ///
    /// The effective window is `min(window_size, cwnd)`, so both the receiver
    /// window and the congestion window must have capacity.
    pub fn can_send(&self) -> bool {
        let effective = self.window_size.min(self.cwnd);
        self.window.len() < effective
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
            self.window_size.min(self.cwnd)
        );
        let payload_len = packet.payload.len() as u32;
        self.window.push_back(GbnEntry {
            packet,
            tx_count: 1,
            sent_at: Instant::now(),
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
    /// Call this **after** [`on_ack`] returns a positive `acked_count`.
    /// Implements the Reno growth rules for all three phases.
    ///
    /// [`on_ack`]: Self::on_ack
    pub fn on_ack_cc(&mut self, acked_count: usize) {
        match self.cc_state {
            CongestionState::SlowStart => {
                // Exponential growth: +1 segment per newly-acked segment.
                self.cwnd = (self.cwnd + acked_count).min(self.window_size);
                if self.cwnd >= self.ssthresh {
                    self.cc_state = CongestionState::CongestionAvoidance;
                    self.cwnd_ca_counter = 0;
                    log::debug!("[cc] SS→CA cwnd={} ssthresh={}", self.cwnd, self.ssthresh);
                }
            }
            CongestionState::CongestionAvoidance => {
                // Additive increase: +1 segment per RTT.
                // Accumulate fractional increments; raise cwnd when the
                // accumulator reaches the current cwnd.
                self.cwnd_ca_counter += acked_count;
                if self.cwnd_ca_counter >= self.cwnd {
                    self.cwnd_ca_counter = 0;
                    self.cwnd = (self.cwnd + 1).min(self.window_size);
                    log::debug!("[cc] CA cwnd={}", self.cwnd);
                }
            }
            CongestionState::FastRecovery => {
                // A new (non-duplicate) ACK exits fast recovery.
                self.cwnd = self.ssthresh;
                self.cc_state = CongestionState::CongestionAvoidance;
                self.cwnd_ca_counter = 0;
                log::debug!("[cc] FR→CA cwnd=ssthresh={}", self.cwnd);
            }
        }
    }

    /// Handle a retransmit timeout: halve `ssthresh`, reset `cwnd` to 1,
    /// and re-enter Slow Start (RFC 5681 §3.1).
    ///
    /// Call this **after** retransmitting the window and calling
    /// [`on_retransmit`] so that `in_flight()` still reflects the correct
    /// count before the window is slid.
    ///
    /// [`on_retransmit`]: Self::on_retransmit
    pub fn on_timeout_cc(&mut self) {
        let in_flight = self.window.len();
        self.ssthresh = (in_flight / 2).max(2);
        self.cwnd = 1;
        self.dup_ack_count = 0;
        self.cwnd_ca_counter = 0;
        self.cc_state = CongestionState::SlowStart;
        log::debug!(
            "[cc] timeout → SS  ssthresh={}  cwnd=1  in_flight={}",
            self.ssthresh, in_flight
        );
    }

    /// Handle three duplicate ACKs: enter Fast Recovery (Reno fast retransmit).
    ///
    /// Sets `ssthresh ← max(2, in_flight / 2)` and inflates `cwnd` by 3
    /// (the three segments that triggered the dup-ACKs are assumed to have
    /// left the network).  The caller is responsible for retransmitting the
    /// oldest unacked segment immediately after.
    ///
    /// # Note
    /// Only call when [`dup_ack_count`] has just reached 3.
    ///
    /// [`dup_ack_count`]: Self::dup_ack_count
    pub fn on_triple_dup_ack_cc(&mut self) {
        let in_flight = self.window.len();
        self.ssthresh = (in_flight / 2).max(2);
        self.cwnd = self.ssthresh + 3; // Reno inflation
        self.cc_state = CongestionState::FastRecovery;
        log::debug!(
            "[cc] 3-dup-ACK → FR  ssthresh={}  cwnd={}  in_flight={}",
            self.ssthresh, self.cwnd, in_flight
        );
    }

    // -----------------------------------------------------------------------
    // Retransmit helpers
    // -----------------------------------------------------------------------

    /// Iterate over all in-flight segments from oldest to newest.
    ///
    /// Used by the connection layer to retransmit the full window on timeout
    /// (the "go back N" step).
    pub fn window_entries(&self) -> impl Iterator<Item = &GbnEntry> {
        self.window.iter()
    }

    /// Increment the transmission count and refresh `sent_at` for every
    /// in-flight segment.
    ///
    /// Call this immediately **after** retransmitting the entire window so
    /// subsequent RTT samples from these retransmitted segments will be
    /// suppressed by Karn's algorithm.
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
    // Congestion control accessors (for tests and diagnostics)
    // -----------------------------------------------------------------------

    /// Current congestion window in segments.
    pub fn cwnd(&self) -> usize {
        self.cwnd
    }

    /// Current slow-start threshold in segments.
    pub fn ssthresh(&self) -> usize {
        self.ssthresh
    }

    /// Current Reno phase.
    pub fn cc_state(&self) -> &CongestionState {
        &self.cc_state
    }

    /// Number of consecutive duplicate ACKs seen since the last new ACK.
    pub fn dup_ack_count(&self) -> u32 {
        self.dup_ack_count
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
        assert_eq!(s.ssthresh(), INITIAL_SSTHRESH);
        assert_eq!(*s.cc_state(), CongestionState::SlowStart);
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
        s.cwnd = 2; // open cwnd so window_size is the binding constraint
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
        s.cwnd = 4; // bypass cwnd so window_size governs
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
        s.cwnd = 4;
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
        s.cwnd = 4;
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
        s.cwnd = 4;
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
        s.ssthresh = 32; // keep SS going
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
        s.ssthresh = 4;
        assert_eq!(*s.cc_state(), CongestionState::SlowStart);

        // 4 ACKs at cwnd=1 → cwnd = 1+4 = 5 ≥ ssthresh → transition to CA.
        // cwnd is allowed to overshoot ssthresh during the slow-start step.
        s.on_ack_cc(4);
        assert_eq!(*s.cc_state(), CongestionState::CongestionAvoidance);
        assert!(
            s.cwnd() >= s.ssthresh(),
            "cwnd ({}) must be ≥ ssthresh ({}) after SS→CA transition",
            s.cwnd(), s.ssthresh()
        );
    }

    #[test]
    fn congestion_avoidance_grows_by_one_per_rtt() {
        let mut s = GbnSender::new(0, 32);
        s.ssthresh = 4;
        s.cwnd = 4;
        s.cc_state = CongestionState::CongestionAvoidance;

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
        s.cwnd = 8;
        s.ssthresh = 16;
        s.cc_state = CongestionState::CongestionAvoidance;

        // Put 6 segments in flight (manually, to avoid cwnd restriction).
        for i in 0..6u32 {
            s.window.push_back(GbnEntry {
                packet: make_pkt(i * 4, 4),
                tx_count: 1,
                sent_at: Instant::now(),
            });
        }
        assert_eq!(s.in_flight(), 6);

        s.on_timeout_cc();

        assert_eq!(s.ssthresh(), 3, "ssthresh = max(2, 6/2) = 3");
        assert_eq!(s.cwnd(), 1, "cwnd resets to 1 on timeout");
        assert_eq!(*s.cc_state(), CongestionState::SlowStart);
    }

    #[test]
    fn timeout_ssthresh_floors_at_two() {
        let mut s = GbnSender::new(0, 32);
        // Only 1 segment in flight when timeout fires.
        s.window.push_back(GbnEntry {
            packet: make_pkt(0, 4),
            tx_count: 1,
            sent_at: Instant::now(),
        });

        s.on_timeout_cc();
        assert_eq!(s.ssthresh(), 2, "ssthresh floor is 2 even when in_flight/2 < 2");
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
        assert_eq!(s.ssthresh(), 2);
        assert_eq!(s.cwnd(), 5);
        assert_eq!(*s.cc_state(), CongestionState::FastRecovery);
    }

    #[test]
    fn fast_recovery_exits_on_new_ack() {
        let mut s = GbnSender::new(0, 16);
        s.ssthresh = 4;
        s.cwnd = 7; // ssthresh + 3
        s.cc_state = CongestionState::FastRecovery;

        // New ACK arrives: exit fast recovery, cwnd = ssthresh.
        s.on_ack_cc(1);

        assert_eq!(s.cwnd(), 4, "exit FR: cwnd ← ssthresh");
        assert_eq!(*s.cc_state(), CongestionState::CongestionAvoidance);
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
}
