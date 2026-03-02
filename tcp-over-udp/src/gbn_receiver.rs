//! Selective-Repeat receive-side state machine with receiver-side flow control.
//!
//! [`GbnReceiver`] implements the receiver side of Selective Repeat (SR):
//!
//! - **In-order** segments (seq == `rcv_nxt`) are appended to the application
//!   buffer and `rcv_nxt` advances.  Any previously buffered out-of-order
//!   segments that now fill the gap are also delivered immediately.
//! - **Out-of-order** segments (seq > `rcv_nxt`) are buffered in an internal
//!   out-of-order map (`ooo_buffer`) for later delivery, rather than discarded.
//! - **Duplicate** segments (seq < `rcv_nxt`, or already in `ooo_buffer`) are
//!   silently dropped.
//! - Segments are also rejected when the receive buffer is full (no space).
//! - After every segment (accepted or not) the caller should send a
//!   **cumulative ACK** containing [`ack_number`] = `rcv_nxt` **and**
//!   [`window_size`] = free bytes, which together implement RFC 793
//!   receive-window flow control.
//!
//! This module only manages state; all socket I/O is the caller's
//! responsibility (same pattern as [`crate::receiver::Receiver`]).

use std::collections::{BTreeMap, VecDeque};

// ---------------------------------------------------------------------------
// GbnReceiver
// ---------------------------------------------------------------------------

/// Selective-Repeat receive-side state for one connection.
///
/// The advertised window (`rwnd`) is computed dynamically as
/// `capacity − (app_buffer_bytes + ooo_buffer_bytes)`.  Every ACK the
/// connection layer sends reflects the current free space, enabling
/// receiver-side flow control.
#[derive(Debug)]
pub struct GbnReceiver {
    /// Next expected sequence number (`RCV.NXT`).
    ///
    /// Advances by `payload.len()` each time an in-order segment is accepted.
    pub rcv_nxt: u32,

    /// In-order payload bytes buffered for the application.
    pub app_buffer: VecDeque<u8>,

    /// Maximum number of bytes the receive buffers (`app_buffer` +
    /// `ooo_buffer`) may hold in total.
    ///
    /// `window_size()` returns `capacity − used`, clamped to [`u16::MAX`].
    /// When the buffer is full `window_size()` returns 0.
    capacity: usize,

    /// Out-of-order segments buffered until the gap is filled.
    ///
    /// Keyed by first sequence number; value is the raw payload bytes.
    /// Entries are flushed into `app_buffer` by [`deliver_ooo`] as soon as
    /// the missing in-order prefix arrives.
    ///
    /// [`deliver_ooo`]: Self::deliver_ooo
    ooo_buffer: BTreeMap<u32, Vec<u8>>,
}

impl GbnReceiver {
    /// Create a new [`GbnReceiver`] with a 64 KiB receive buffer.
    ///
    /// `rcv_nxt` is the first sequence number expected from the peer.  After
    /// a completed 3-way handshake this is `peer_isn + 1`.
    pub fn new(rcv_nxt: u32) -> Self {
        Self::with_capacity(rcv_nxt, 65536)
    }

    /// Create a [`GbnReceiver`] with a custom receive-buffer capacity.
    ///
    /// Use a small `capacity` in tests to exercise flow control with limited
    /// buffer space.
    ///
    /// # Panics
    ///
    /// Panics if `capacity == 0`.
    pub fn with_capacity(rcv_nxt: u32, capacity: usize) -> Self {
        assert!(capacity > 0, "recv buffer capacity must be at least 1 byte");
        Self {
            rcv_nxt,
            app_buffer: VecDeque::new(),
            capacity,
            ooo_buffer: BTreeMap::new(),
        }
    }

    /// Process an inbound segment (Selective Repeat semantics).
    ///
    /// Returns `true` if the segment was **delivered to the application buffer**
    /// (i.e. it was the next expected segment).  Returns `false` in any of
    /// these cases:
    ///
    /// - **Out-of-order** (seq > `rcv_nxt`) — buffered for later delivery;
    ///   the cumulative ACK still points to the gap.
    /// - **Duplicate** (seq < `rcv_nxt`) — already received, discard.
    /// - **Buffer full** — no free space; payload would exceed `capacity`.
    ///
    /// After accepting an in-order segment, any previously buffered
    /// out-of-order segments that now extend the contiguous prefix are
    /// flushed into the application buffer automatically.
    ///
    /// In every case the caller should send a cumulative ACK with the
    /// current [`ack_number`] and [`window_size`].
    pub fn on_segment(&mut self, seq: u32, payload: &[u8]) -> bool {
        let used = self.app_buffer.len() + self.ooo_bytes();
        let free = self.capacity.saturating_sub(used);

        if seq == self.rcv_nxt && payload.len() <= free {
            // In-order segment: deliver immediately, then flush OOO chain.
            self.app_buffer.extend(payload.iter().copied());
            self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
            self.deliver_ooo();
            true
        } else if self.is_future(seq) && payload.len() <= free {
            // Out-of-order segment: buffer it.  Use entry() so a duplicate
            // OOO retransmission does not overwrite an already-buffered copy.
            self.ooo_buffer.entry(seq).or_insert_with(|| payload.to_vec());
            false
        } else {
            // Duplicate (seq < rcv_nxt) or no buffer space.
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

    /// Advertised receive window (free bytes) to place in outbound packets.
    ///
    /// Returns the number of bytes the receive buffers can still accept
    /// (accounting for both the application buffer and the out-of-order
    /// buffer), clamped to [`u16::MAX`].  A return value of `0` (buffer
    /// full) tells the sender to stop transmitting until a later ACK opens
    /// the window.
    pub fn window_size(&self) -> u16 {
        let used = self.app_buffer.len() + self.ooo_bytes();
        let free = self.capacity.saturating_sub(used);
        free.min(u16::MAX as usize) as u16
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

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Flush any buffered out-of-order segments that now extend the
    /// contiguous in-order prefix.
    ///
    /// Called every time `rcv_nxt` advances so that the gap-fill cascade
    /// runs automatically after each accepted in-order segment.
    fn deliver_ooo(&mut self) {
        while let Some(payload) = self.ooo_buffer.remove(&self.rcv_nxt) {
            self.app_buffer.extend(payload.iter().copied());
            self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
        }
    }

    /// Total bytes held in the out-of-order buffer.
    fn ooo_bytes(&self) -> usize {
        self.ooo_buffer.values().map(|v| v.len()).sum()
    }

    /// `true` when `seq` is strictly ahead of `rcv_nxt` in wrap-around space.
    ///
    /// Uses half-range arithmetic (same as `seq_le` in `gbn_sender`) to
    /// correctly handle wrap-around as long as the gap is less than 2 GiB.
    #[inline]
    fn is_future(&self, seq: u32) -> bool {
        let d = seq.wrapping_sub(self.rcv_nxt);
        d > 0 && d <= (u32::MAX / 2)
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
        // Default capacity is 65536.
        assert_eq!(r.window_size(), 65535); // clamped to u16::MAX
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
    fn out_of_order_segment_buffered_not_delivered() {
        let mut r = GbnReceiver::new(100);
        // OOO segment is buffered; returns false (not yet delivered to app).
        let accepted = r.on_segment(110, b"future"); // gap: seq 100-109 missing
        assert!(!accepted);
        assert_eq!(r.rcv_nxt, 100); // rcv_nxt must not advance
        assert!(r.app_buffer.is_empty());
        // Cumulative ACK should still advertise 100 (not 110).
        assert_eq!(r.ack_number(), 100);
        // But the segment is buffered (not discarded like GBN would do).
        assert_eq!(r.ooo_buffer.len(), 1);
    }

    #[test]
    fn ooo_segment_delivered_when_gap_filled() {
        let mut r = GbnReceiver::new(100);
        // Buffer OOO segment at seq=105.
        assert!(!r.on_segment(105, b"world"));
        assert_eq!(r.ack_number(), 100);
        // In-order segment fills the gap: triggers OOO chain delivery.
        assert!(r.on_segment(100, b"hello"));
        // Both segments now delivered: rcv_nxt = 105 + 5 = 110.
        assert_eq!(r.ack_number(), 110);
        assert_eq!(r.app_buffer.len(), 10);
        assert!(r.ooo_buffer.is_empty());
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

    // ── Selective Repeat OOO delivery ────────────────────────────────────────

    #[test]
    fn ooo_chain_delivery_reverse_order() {
        // Segments arrive in reverse: last first, then second, then first.
        let mut r = GbnReceiver::new(0);
        assert!(!r.on_segment(6, b"ccc")); // buffered
        assert!(!r.on_segment(3, b"bbb")); // buffered
        assert_eq!(r.ack_number(), 0);

        // In-order fill triggers full chain.
        assert!(r.on_segment(0, b"aaa"));
        assert_eq!(r.ack_number(), 9, "all three delivered after gap fill");
        assert!(r.ooo_buffer.is_empty());

        let mut buf = [0u8; 9];
        r.read(&mut buf);
        assert_eq!(&buf, b"aaabbbccc");
    }

    #[test]
    fn ooo_buffer_counts_toward_capacity() {
        // capacity=20; buffer an OOO segment of 15 bytes; window shrinks.
        let mut r = GbnReceiver::with_capacity(0, 20);
        assert!(!r.on_segment(5, &[0u8; 15])); // OOO, buffered
        // window_size accounts for OOO bytes.
        assert_eq!(r.window_size(), 5, "ooo bytes must count toward capacity");

        // In-order segment of 5 bytes: accepted, then OOO delivered.
        assert!(r.on_segment(0, &[0u8; 5]));
        assert_eq!(r.ack_number(), 20);
        assert_eq!(r.window_size(), 0, "buffer now full after OOO delivery");
    }

    // ── Flow control ────────────────────────────────────────────────────────

    #[test]
    fn window_size_reflects_free_space() {
        let mut r = GbnReceiver::with_capacity(0, 100);
        assert_eq!(r.window_size(), 100, "full capacity advertised when empty");

        r.on_segment(0, &[0u8; 40]);
        assert_eq!(r.window_size(), 60, "window shrinks by bytes buffered");

        let mut buf = [0u8; 20];
        r.read(&mut buf);
        assert_eq!(r.window_size(), 80, "window grows after app drains");
    }

    #[test]
    fn full_buffer_rejects_segment() {
        let mut r = GbnReceiver::with_capacity(0, 20);
        assert!(r.on_segment(0, &[0u8; 20]), "exact fill must be accepted");
        assert_eq!(r.window_size(), 0, "window must be 0 when full");

        // Next in-order segment must be rejected (buffer full).
        let rejected = r.on_segment(20, &[0u8; 1]);
        assert!(!rejected, "segment must be rejected when buffer full");
        assert_eq!(r.rcv_nxt, 20, "rcv_nxt must not advance on rejection");

        // After draining, the segment fits.
        let mut drain = [0u8; 20];
        r.read(&mut drain);
        assert_eq!(r.window_size(), 20);
        assert!(r.on_segment(20, &[0u8; 1]), "segment accepted after drain");
    }
}
