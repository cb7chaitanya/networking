//! Inbound segment reassembly and receive-window management.
//!
//! The [`Receiver`] is responsible for everything that happens *after* a raw
//! datagram is decoded into a [`crate::packet::Packet`] and *before* the
//! application reads contiguous bytes:
//! - Validating that a segment's sequence number falls within the receive window.
//! - Buffering out-of-order segments until gaps are filled (resequencing).
//! - Delivering in-order data to the application receive buffer.
//! - Computing the ACK number and advertised window for outbound ACK packets.
//! - Detecting and discarding duplicate segments.
//!
//! The [`Receiver`] does **not** send ACKs itself; it provides the values
//! that [`crate::connection::Connection`] uses when constructing ACK packets.

/// Manages the receive side of a single connection.
///
/// TODO: add fields for receive buffer (`VecDeque<u8>`), RCV.NXT, RCV.WND,
///       and an out-of-order segment store (e.g. `BTreeMap<u32, Vec<u8>>`).
pub struct Receiver {
    /// Bytes ready to be consumed by the application, in order.
    pub app_buffer: Vec<u8>,
}

impl Receiver {
    /// Create a new [`Receiver`].
    ///
    /// TODO: accept initial receive sequence number (IRS) as parameter.
    pub fn new() -> Self {
        todo!("construct Receiver")
    }

    /// Process an inbound segment.
    ///
    /// Validates sequence number against the receive window, stores the
    /// payload, and advances `RCV.NXT` as far as possible.
    ///
    /// TODO: handle wrap-around arithmetic for 32-bit sequence numbers.
    pub fn on_segment(&mut self, _seq: u32, _payload: &[u8]) {
        todo!("accept inbound segment")
    }

    /// Return the next ACK number the connection should send.
    ///
    /// This is `RCV.NXT` — the sequence number of the first byte not yet
    /// received in order.
    ///
    /// TODO: return stored `RCV.NXT`.
    pub fn ack_number(&self) -> u32 {
        todo!("return RCV.NXT")
    }

    /// Return the current advertised receive window size.
    ///
    /// Computed as `RCV.WND - bytes_buffered_but_not_read`.
    ///
    /// TODO: implement based on app_buffer capacity.
    pub fn window_size(&self) -> u16 {
        todo!("return available window")
    }

    /// Read up to `buf.len()` bytes of ordered application data.
    ///
    /// Returns the number of bytes copied.
    ///
    /// TODO: drain from app_buffer into `buf`.
    pub fn read(&mut self, _buf: &mut [u8]) -> usize {
        todo!("drain app_buffer")
    }
}
