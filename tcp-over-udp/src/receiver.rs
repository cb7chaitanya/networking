//! Inbound segment delivery for stop-and-wait reliability.
//!
//! [`Receiver`] tracks `RCV.NXT` (the next expected sequence number) and
//! buffers in-order payload bytes for the application.  Out-of-order or
//! duplicate segments are silently rejected; the caller re-ACKs with the
//! current `ack_number()` in both cases, prompting the sender to retransmit.
//!
//! The module does **not** send ACKs — it only supplies the values that
//! [`crate::connection::Connection`] puts into outbound ACK packets.

use std::collections::VecDeque;

/// Stop-and-wait receive-side state for one connection.
#[derive(Debug)]
pub struct Receiver {
    /// Next expected sequence number (`RCV.NXT`).
    ///
    /// Advances by `payload.len()` each time an in-order segment is accepted.
    pub rcv_nxt: u32,

    /// Bytes received in order, ready for the application to consume.
    pub app_buffer: VecDeque<u8>,

    /// Advertised receive window (fixed for stop-and-wait; no flow control).
    window: u16,
}

impl Receiver {
    /// Create a new [`Receiver`].
    ///
    /// `rcv_nxt` is the first sequence number expected from the peer.  For a
    /// freshly completed handshake this is `peer_isn + 1` (the SYN consumed
    /// one sequence number).
    pub fn new(rcv_nxt: u32) -> Self {
        Self {
            rcv_nxt,
            app_buffer: VecDeque::new(),
            window: 8192,
        }
    }

    /// Process an inbound segment.
    ///
    /// Returns `true` if the segment was accepted (seq == RCV.NXT) and its
    /// payload appended to the application buffer.  Returns `false` for a
    /// duplicate (seq < RCV.NXT) or out-of-order (seq > RCV.NXT) segment;
    /// the caller should still send an ACK with the current `ack_number()`.
    pub fn on_segment(&mut self, seq: u32, payload: &[u8]) -> bool {
        if seq == self.rcv_nxt {
            self.app_buffer.extend(payload.iter().copied());
            self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
            true
        } else {
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

    /// The ACK number to place in the next outbound packet (`RCV.NXT`).
    pub fn ack_number(&self) -> u32 {
        self.rcv_nxt
    }

    /// The advertised receive window to place in the next outbound packet.
    pub fn window_size(&self) -> u16 {
        self.window
    }

    /// Copy up to `buf.len()` bytes of in-order application data into `buf`.
    ///
    /// Returns the number of bytes actually copied.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.app_buffer.len());
        for (dst, src) in buf[..n].iter_mut().zip(self.app_buffer.drain(..n)) {
            *dst = src;
        }
        n
    }
}
