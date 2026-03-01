//! Go-Back-N send-side state machine.
//!
//! [`GbnSender`] maintains a sliding window of up to `N` in-flight segments.
//! Unlike stop-and-wait, multiple segments may be outstanding simultaneously.
//!
//! # Protocol contract
//!
//! - At most `window_size` segments may be in-flight at once.
//! - ACKs are **cumulative**: `ack_num = K` means the receiver has accepted
//!   all bytes up to (but not including) sequence number `K`.
//! - On timeout, the caller retransmits **all** unacked segments from
//!   `send_base` onwards (go back to N).
//! - Sequence numbers are u32 and wrap around using standard modular arithmetic;
//!   wrap-around comparisons use the convention that two sequence numbers are
//!   "close" when their difference is less than `u32::MAX / 2`.
//!
//! This module only manages state; all socket I/O is the caller's responsibility.

use std::collections::VecDeque;
use std::time::Instant;

use crate::packet::{flags, Header, Packet};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` when sequence number `a` is ≤ `b` in wrap-around space.
///
/// The comparison works correctly as long as the two values are less than
/// `u32::MAX / 2` apart, which is always the case for a reasonable window.
#[inline]
fn seq_le(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) <= (u32::MAX / 2)
}

// ---------------------------------------------------------------------------
// GbnEntry
// ---------------------------------------------------------------------------

/// A single in-flight segment occupying one slot in the retransmit window.
#[derive(Debug, Clone)]
pub struct GbnEntry {
    /// The encoded segment (ready to hand to the socket).
    pub packet: Packet,
    /// Total number of times this segment has been transmitted.
    pub tx_count: u32,
    /// Wall-clock time of the most recent transmission (for RTT sampling).
    pub sent_at: Instant,
}

// ---------------------------------------------------------------------------
// GbnSender
// ---------------------------------------------------------------------------

/// Go-Back-N send-side state for one connection.
///
/// # Sequence-number layout
///
/// ```text
///  send_base          next_seq
///      │                  │
///  ────┼──────────────────┼──────────────────▶ seq space
///      │ <── in flight ──▶│ <── sendable ───▶
/// ```
#[derive(Debug)]
pub struct GbnSender {
    /// Sequence number of the **oldest** unacked segment (left window edge).
    pub send_base: u32,

    /// Sequence number to use for the **next** new segment.
    pub next_seq: u32,

    /// Maximum number of segments that may be in flight simultaneously (N).
    window_size: usize,

    /// In-flight segments ordered by sequence number (front = oldest).
    window: VecDeque<GbnEntry>,
}

impl GbnSender {
    /// Create a new [`GbnSender`].
    ///
    /// `seq_start` is the first data sequence number (typically `ISN + 1`
    /// after the handshake).  `window_size` is the GBN window size N (≥ 1).
    pub fn new(seq_start: u32, window_size: usize) -> Self {
        assert!(window_size >= 1, "window_size must be at least 1");
        Self {
            send_base: seq_start,
            next_seq: seq_start,
            window_size,
            window: VecDeque::with_capacity(window_size),
        }
    }

    /// `true` when there is room for at least one more in-flight segment.
    pub fn can_send(&self) -> bool {
        self.window.len() < self.window_size
    }

    /// Number of segments currently awaiting acknowledgement.
    pub fn in_flight(&self) -> usize {
        self.window.len()
    }

    /// `true` when at least one segment is awaiting acknowledgement.
    pub fn has_unacked(&self) -> bool {
        !self.window.is_empty()
    }

    /// Build a data segment with the correct next sequence number.
    ///
    /// Call [`record_sent`] immediately after to advance `next_seq` and place
    /// the segment into the window.
    pub fn build_data_packet(&self, payload: Vec<u8>, ack: u32, window: u16) -> Packet {
        Packet {
            header: Header {
                seq: self.next_seq,
                ack,
                flags: flags::ACK, // data segments piggyback the receiver's ACK
                window,
                checksum: 0, // filled in by Packet::encode
            },
            payload,
        }
    }

    /// Place a just-transmitted segment into the window and advance `next_seq`.
    ///
    /// # Panics
    ///
    /// Panics in debug mode if the window is already full.  Check [`can_send`]
    /// before calling.
    pub fn record_sent(&mut self, packet: Packet) {
        debug_assert!(
            self.can_send(),
            "record_sent called on a full GBN window ({} / {})",
            self.window.len(),
            self.window_size
        );
        let payload_len = packet.payload.len() as u32;
        self.window.push_back(GbnEntry {
            packet,
            tx_count: 1,
            sent_at: Instant::now(),
        });
        self.next_seq = self.next_seq.wrapping_add(payload_len);
    }

    /// Process a cumulative ACK.
    ///
    /// Removes all window entries whose data ends at or before `ack_num`,
    /// advances `send_base`, and returns the number of newly-acknowledged
    /// segments.  Returns `0` for a duplicate or out-of-range ACK.
    pub fn on_ack(&mut self, ack_num: u32) -> usize {
        // Reject ACKs that are behind send_base or beyond next_seq.
        if !seq_le(self.send_base, ack_num) || !seq_le(ack_num, self.next_seq) {
            return 0;
        }
        // If ack_num == send_base there is nothing new to acknowledge.
        if ack_num == self.send_base {
            return 0;
        }

        let mut acked = 0usize;
        while let Some(front) = self.window.front() {
            // seg_end is the first sequence number AFTER this segment's payload.
            let seg_end = front
                .packet
                .header
                .seq
                .wrapping_add(front.packet.payload.len() as u32);

            // This segment is fully covered by ack_num when seg_end ≤ ack_num.
            if seq_le(seg_end, ack_num) {
                self.send_base = seg_end;
                self.window.pop_front();
                acked += 1;
            } else {
                break;
            }
        }
        acked
    }

    /// Iterate over all in-flight segments from oldest to newest.
    ///
    /// Used by the connection layer to retransmit all unacked segments on
    /// timeout (the "go back N" step).
    pub fn window_entries(&self) -> impl Iterator<Item = &GbnEntry> {
        self.window.iter()
    }

    /// Increment the transmission count and refresh `sent_at` for every
    /// in-flight segment.
    ///
    /// Call this immediately after retransmitting the entire window.
    pub fn on_retransmit(&mut self) {
        let now = Instant::now();
        for entry in self.window.iter_mut() {
            entry.tx_count += 1;
            entry.sent_at = now;
        }
    }

    /// Wall-clock time when the oldest in-flight segment was last sent.
    ///
    /// Returns `None` when the window is empty (sender is idle).
    pub fn oldest_sent_at(&self) -> Option<Instant> {
        self.window.front().map(|e| e.sent_at)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::flags;

    /// Helper: build a minimal data packet.
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
    }

    #[test]
    fn record_sent_advances_next_seq() {
        let mut s = GbnSender::new(0, 4);
        let pkt = s.build_data_packet(vec![1, 2, 3], 0, 8192);
        s.record_sent(pkt);

        assert_eq!(s.next_seq, 3);
        assert_eq!(s.send_base, 0); // not acked yet
        assert_eq!(s.in_flight(), 1);
        assert!(s.has_unacked());
    }

    #[test]
    fn window_full_blocks_send() {
        let mut s = GbnSender::new(0, 2);

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
        let p = s.build_data_packet(vec![0u8; 10], 0, 8192); // seq=0, len=10
        s.record_sent(p);

        let acked = s.on_ack(10);
        assert_eq!(acked, 1);
        assert_eq!(s.send_base, 10);
        assert!(!s.has_unacked());
    }

    #[test]
    fn cumulative_ack_slides_multiple() {
        let mut s = GbnSender::new(0, 4);

        for _ in 0..3u32 {
            let pkt = s.build_data_packet(vec![0u8; 5], 0, 8192);
            s.record_sent(pkt);
            // next_seq auto-advances in record_sent
        }
        assert_eq!(s.next_seq, 15);

        // ACK for all three packets at once.
        let acked = s.on_ack(15);
        assert_eq!(acked, 3);
        assert_eq!(s.send_base, 15);
        assert!(!s.has_unacked());
    }

    #[test]
    fn duplicate_ack_returns_zero() {
        let mut s = GbnSender::new(0, 4);
        let p = s.build_data_packet(vec![0u8; 5], 0, 8192);
        s.record_sent(p);

        let first = s.on_ack(5);
        assert_eq!(first, 1);

        // Duplicate ACK for already-acknowledged data.
        let dup = s.on_ack(5);
        assert_eq!(dup, 0);
    }

    #[test]
    fn spurious_ack_beyond_next_seq_ignored() {
        let mut s = GbnSender::new(0, 4);
        let p = s.build_data_packet(vec![0u8; 5], 0, 8192);
        s.record_sent(p);

        // ACK for data we haven't sent yet.
        let acked = s.on_ack(1000);
        assert_eq!(acked, 0);
        assert_eq!(s.send_base, 0); // unchanged
    }

    #[test]
    fn partial_cumulative_ack() {
        let mut s = GbnSender::new(0, 4);
        for _ in 0..3 {
            let pkt = s.build_data_packet(vec![0u8; 5], 0, 8192);
            s.record_sent(pkt);
        }
        // ACK only the first two.
        let acked = s.on_ack(10);
        assert_eq!(acked, 2);
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
        // Start close to u32::MAX so that the sequence number wraps.
        let start = u32::MAX - 5;
        let mut s = GbnSender::new(start, 4);

        let p = s.build_data_packet(vec![0u8; 10], 0, 8192); // seq wraps after 5
        s.record_sent(p);

        // ack_num wraps past 0
        let expected_ack = start.wrapping_add(10);
        let acked = s.on_ack(expected_ack);
        assert_eq!(acked, 1);
        assert_eq!(s.send_base, expected_ack);
    }
}
