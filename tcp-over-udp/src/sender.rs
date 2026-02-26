//! Outbound segment state for stop-and-wait reliability.
//!
//! [`Sender`] tracks sequence numbers and the single in-flight segment.
//! It does **not** touch the socket; [`crate::connection::Connection`] calls
//! these methods and owns the actual send/receive loop.
//!
//! # Stop-and-Wait contract
//! - At most **one** segment is in flight at any moment (`unacked`).
//! - A new segment may only be sent once `unacked` is `None`.
//! - On ACK: advance `next_seq`; clear `unacked`.
//! - On timeout: increment `tx_count`; resend the same packet unchanged.

use std::time::Instant;

use crate::packet::{flags, Header, Packet};

// ---------------------------------------------------------------------------
// RetransmitEntry
// ---------------------------------------------------------------------------

/// A segment that has been sent but not yet acknowledged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetransmitEntry {
    /// The segment on the wire.
    pub packet: Packet,
    /// How many times this segment has been transmitted (1 = first send).
    pub tx_count: u32,
    /// Wall-clock time of the most recent transmission (for RTT sampling).
    pub sent_at: Instant,
}

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

/// Stop-and-wait send-side state for one connection.
#[derive(Debug)]
pub struct Sender {
    /// Sequence number of the **next** segment to send.
    ///
    /// Advances by `payload.len()` each time an ACK is received.
    /// Remains unchanged while a segment is in flight.
    pub next_seq: u32,

    /// The in-flight segment, or `None` when the sender is idle.
    pub unacked: Option<RetransmitEntry>,
}

impl Sender {
    /// Create a new [`Sender`].
    ///
    /// `isn` is the Initial Sequence Number chosen during the handshake.
    /// The SYN itself consumes one sequence number, so the first data segment
    /// will carry `isn + 1`.
    pub fn new(isn: u32) -> Self {
        Self {
            next_seq: isn.wrapping_add(1),
            unacked: None,
        }
    }

    /// Build a data packet ready to send.
    ///
    /// The caller must subsequently call [`record_sent`] to place the packet
    /// into the retransmit slot before calling the socket.
    pub fn build_data_packet(&self, payload: Vec<u8>, ack: u32, window: u16) -> Packet {
        Packet {
            header: Header {
                seq: self.next_seq,
                ack,
                flags: flags::ACK, // data segments carry ACK of the peer's data
                window,
                checksum: 0, // filled in by Packet::encode
            },
            payload,
        }
    }

    /// Move `packet` into the in-flight slot (first transmission).
    ///
    /// Panics in debug mode if a segment is already in flight.
    pub fn record_sent(&mut self, packet: Packet) {
        debug_assert!(
            self.unacked.is_none(),
            "record_sent called while a segment is already in flight"
        );
        self.unacked = Some(RetransmitEntry {
            packet,
            tx_count: 1,
            sent_at: Instant::now(),
        });
    }

    /// Process an inbound ACK number.
    ///
    /// Returns `true` if this ACK covers the in-flight segment (new data
    /// acknowledged).  Returns `false` for a duplicate or unexpected ACK.
    ///
    /// On success: `next_seq` advances and the retransmit slot is cleared.
    pub fn on_ack(&mut self, ack_num: u32) -> bool {
        if let Some(ref entry) = self.unacked {
            // The ACK we expect is seq + payload_len.
            let expected =
                entry.packet.header.seq.wrapping_add(entry.packet.payload.len() as u32);
            if ack_num == expected {
                self.next_seq = ack_num;
                self.unacked = None;
                return true;
            }
        }
        false
    }

    /// Increment the retransmit count for the in-flight segment.
    ///
    /// Called by the connection loop before each retransmission.
    pub fn on_retransmit(&mut self) {
        if let Some(ref mut e) = self.unacked {
            e.tx_count += 1;
            e.sent_at = Instant::now();
        }
    }

    /// Returns the number of times the in-flight segment has been sent,
    /// or `0` if the sender is idle.
    pub fn retransmit_count(&self) -> u32 {
        self.unacked.as_ref().map_or(0, |e| e.tx_count)
    }

    /// `true` when a segment is waiting for an ACK.
    pub fn has_unacked(&self) -> bool {
        self.unacked.is_some()
    }
}
