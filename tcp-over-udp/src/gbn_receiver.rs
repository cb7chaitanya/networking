//! Go-Back-N receive-side state machine.
//!
//! [`GbnReceiver`] implements the receiver side of Go-Back-N:
//!
//! - Only **in-order** segments are accepted (seq == `rcv_nxt`).
//! - Out-of-order or duplicate segments are **silently discarded**.
//! - After every segment (accepted or not) the caller should send a
//!   **cumulative ACK** containing [`ack_number`] = `rcv_nxt`, which tells
//!   the sender the highest contiguous sequence number received.
//!
//! This module only manages state; all socket I/O is the caller's
//! responsibility (same pattern as [`crate::receiver::Receiver`]).

use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// GbnReceiver
// ---------------------------------------------------------------------------

/// Go-Back-N receive-side state for one connection.
#[derive(Debug)]
pub struct GbnReceiver {
    /// Next expected sequence number (`RCV.NXT`).
    ///
    /// Advances by `payload.len()` each time an in-order segment is accepted.
    pub rcv_nxt: u32,

    /// In-order payload bytes buffered for the application.
    pub app_buffer: VecDeque<u8>,

    /// Advertised receive window (constant for GBN; no flow control needed).
    window: u16,
}

impl GbnReceiver {
    /// Create a new [`GbnReceiver`].
    ///
    /// `rcv_nxt` is the first sequence number expected from the peer.  After
    /// a completed 3-way handshake this is `peer_isn + 1`.
    pub fn new(rcv_nxt: u32) -> Self {
        Self {
            rcv_nxt,
            app_buffer: VecDeque::new(),
            window: 8192,
        }
    }

    /// Process an inbound segment.
    ///
    /// Returns `true` if the segment was **accepted** (seq == `rcv_nxt`) and
    /// its payload was appended to the application buffer.
    ///
    /// Returns `false` for an out-of-order (seq > `rcv_nxt`) or duplicate
    /// (seq < `rcv_nxt`) segment — GBN discards both without buffering.  The
    /// caller should still send a cumulative ACK with the unchanged
    /// [`ack_number`] in both cases.
    pub fn on_segment(&mut self, seq: u32, payload: &[u8]) -> bool {
        if seq == self.rcv_nxt {
            self.app_buffer.extend(payload.iter().copied());
            self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
            true
        } else {
            // Out-of-order or duplicate: drop (GBN does not buffer OOO data).
            false
        }
    }

    /// Advance `RCV.NXT` past a received FIN (which consumes one sequence
    /// number) without delivering any payload bytes.
    pub fn on_fin(&mut self, fin_seq: u32) {
        if fin_seq == self.rcv_nxt {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        }
    }

    /// Cumulative ACK number to place in the next outbound packet (`RCV.NXT`).
    ///
    /// This value tells the sender "I have received all bytes up to, but not
    /// including, this sequence number."
    pub fn ack_number(&self) -> u32 {
        self.rcv_nxt
    }

    /// Advertised receive window to place in outbound packets.
    pub fn window_size(&self) -> u16 {
        self.window
    }

    /// Copy up to `buf.len()` in-order bytes from the application buffer into
    /// `buf`.  Returns the number of bytes actually copied.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.app_buffer.len());
        for (dst, src) in buf[..n].iter_mut().zip(self.app_buffer.drain(..n)) {
            *dst = src;
        }
        n
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state() {
        let r = GbnReceiver::new(42);
        assert_eq!(r.rcv_nxt, 42);
        assert!(r.app_buffer.is_empty());
        assert_eq!(r.ack_number(), 42);
    }

    #[test]
    fn in_order_segment_accepted() {
        let mut r = GbnReceiver::new(100);
        let accepted = r.on_segment(100, b"hello");
        assert!(accepted);
        assert_eq!(r.rcv_nxt, 105);
        assert_eq!(r.ack_number(), 105);
        assert_eq!(r.app_buffer.len(), 5);
    }

    #[test]
    fn out_of_order_segment_discarded() {
        let mut r = GbnReceiver::new(100);
        let accepted = r.on_segment(110, b"future"); // gap: seq 100-109 missing
        assert!(!accepted);
        assert_eq!(r.rcv_nxt, 100); // rcv_nxt must not advance
        assert!(r.app_buffer.is_empty());
        // Cumulative ACK should still advertise 100 (not 110).
        assert_eq!(r.ack_number(), 100);
    }

    #[test]
    fn duplicate_segment_discarded() {
        let mut r = GbnReceiver::new(100);
        r.on_segment(100, b"hello"); // accepted

        let dup = r.on_segment(100, b"hello"); // duplicate
        assert!(!dup);
        // Buffer should have only the first copy.
        assert_eq!(r.app_buffer.len(), 5);
    }

    #[test]
    fn sequential_segments_advance_rcv_nxt() {
        let mut r = GbnReceiver::new(0);
        assert!(r.on_segment(0, b"abc"));  // rcv_nxt → 3
        assert!(r.on_segment(3, b"de"));   // rcv_nxt → 5
        assert!(r.on_segment(5, b"fghi")); // rcv_nxt → 9
        assert_eq!(r.rcv_nxt, 9);
        assert_eq!(r.app_buffer.len(), 9);
    }

    #[test]
    fn read_drains_buffer() {
        let mut r = GbnReceiver::new(0);
        r.on_segment(0, b"hello world");

        let mut buf = [0u8; 5];
        let n = r.read(&mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
        assert_eq!(r.app_buffer.len(), 6); // " world" remains
    }

    #[test]
    fn read_partial_when_buffer_smaller_than_buf() {
        let mut r = GbnReceiver::new(0);
        r.on_segment(0, b"hi");

        let mut buf = [0u8; 100];
        let n = r.read(&mut buf);
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"hi");
        assert!(r.app_buffer.is_empty());
    }

    #[test]
    fn fin_advances_rcv_nxt() {
        let mut r = GbnReceiver::new(50);
        r.on_fin(50);
        assert_eq!(r.rcv_nxt, 51);
    }

    #[test]
    fn fin_out_of_order_ignored() {
        let mut r = GbnReceiver::new(50);
        r.on_fin(99); // wrong seq — ignored
        assert_eq!(r.rcv_nxt, 50);
    }

    #[test]
    fn seq_wrap_around() {
        let start = u32::MAX - 2;
        let mut r = GbnReceiver::new(start);
        // Payload of 5 bytes wraps past u32::MAX.
        let accepted = r.on_segment(start, b"abcde");
        assert!(accepted);
        assert_eq!(r.rcv_nxt, start.wrapping_add(5));
    }
}
