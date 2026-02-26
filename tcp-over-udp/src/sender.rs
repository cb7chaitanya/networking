//! Outbound segment management and retransmit queue.
//!
//! The [`Sender`] is responsible for everything that happens *after* the
//! application hands data to the connection layer and *before* bytes hit the
//! wire:
//! - Buffering unsent application data.
//! - Segmenting data into [`crate::packet::Packet`]s that fit the MSS.
//! - Assigning sequence numbers and populating packet headers.
//! - Maintaining the retransmit queue (sent-but-unacknowledged segments).
//! - Advancing `SND.UNA` and `SND.NXT` as ACKs arrive.
//! - Respecting the send window (`SND.WND`) advertised by the receiver.
//!
//! The [`Sender`] does **not** talk to the socket directly; it hands finished
//! [`crate::packet::Packet`]s back to [`crate::connection::Connection`] for
//! dispatch.

use crate::packet::Packet;

/// An entry in the retransmit queue.
///
/// TODO: add `sent_at: std::time::Instant` for RTT measurement.
pub struct RetransmitEntry {
    /// The segment awaiting acknowledgement.
    pub packet: Packet,
    /// Number of times this segment has been transmitted (for backoff).
    pub tx_count: u32,
}

/// Manages the send side of a single connection.
///
/// TODO: add fields for send buffer (`Vec<u8>`), SND.UNA, SND.NXT, SND.WND,
///       maximum segment size (MSS), and congestion window (cwnd).
pub struct Sender {
    /// Segments sent but not yet acknowledged, in sequence-number order.
    pub retransmit_queue: Vec<RetransmitEntry>,
}

impl Sender {
    /// Create a new [`Sender`] with an empty buffer.
    ///
    /// TODO: accept initial sequence number (ISN) as parameter.
    pub fn new() -> Self {
        todo!("construct Sender")
    }

    /// Accept application data into the send buffer.
    ///
    /// TODO: append `data` to internal ring buffer; do not send yet.
    pub fn buffer_data(&mut self, _data: &[u8]) {
        todo!("buffer outbound data")
    }

    /// Produce the next segment(s) to transmit, if the window allows.
    ///
    /// Returns a list of packets ready to be handed to the socket.
    ///
    /// TODO: segment send buffer respecting MSS and SND.WND.
    pub fn poll_segments(&mut self) -> Vec<Packet> {
        todo!("produce sendable segments")
    }

    /// Process an incoming ACK, advancing the unacknowledged window.
    ///
    /// TODO: remove acknowledged entries from `retransmit_queue`, update
    ///       `SND.UNA`, update `SND.WND` from the ACK's window field.
    pub fn on_ack(&mut self, _ack_num: u32, _window: u16) {
        todo!("advance send window on ACK")
    }

    /// Retransmit the oldest unacknowledged segment (triggered by timer).
    ///
    /// TODO: implement exponential back-off via `RetransmitEntry::tx_count`.
    pub fn retransmit_oldest(&mut self) -> Option<Packet> {
        todo!("retransmit head of queue")
    }
}
