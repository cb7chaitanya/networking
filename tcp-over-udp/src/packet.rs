//! Wire-format definitions for protocol segments.
//!
//! Every datagram exchanged between peers is a [`Packet`].  This module is
//! responsible for:
//! - Defining the on-wire binary layout (header fields, flags, payload).
//! - Serialising a [`Packet`] into a byte buffer ready for transmission.
//! - Deserialising a raw byte slice back into a [`Packet`], returning errors
//!   for malformed or truncated input.
//!
//! No I/O happens here — this is pure data transformation.

/// Bit-flag constants for the `flags` header field.
pub mod flags {
    /// Synchronise sequence numbers (handshake initiation).
    pub const SYN: u8 = 0b0000_0001;
    /// Acknowledgement field is valid.
    pub const ACK: u8 = 0b0000_0010;
    /// Finish — sender has no more data to send.
    pub const FIN: u8 = 0b0000_0100;
    /// Reset the connection.
    pub const RST: u8 = 0b0000_1000;
}

/// Fixed-size protocol header.
///
/// TODO: decide final field widths and byte order (big-endian assumed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Sequence number of the first payload byte in this segment.
    pub seq: u32,
    /// Acknowledgement number (next expected sequence number from the peer).
    pub ack: u32,
    /// Bitmask of [`flags`] constants.
    pub flags: u8,
    /// Advertised receive-window size in bytes.
    pub window: u16,
    /// Length of the payload in bytes (derived field; validates on parse).
    pub payload_len: u16,
}

/// A complete protocol datagram: header + payload bytes.
///
/// TODO: add checksum field to [`Header`] and implement verification here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    pub payload: Vec<u8>,
}

impl Packet {
    /// Serialise this packet into a newly allocated byte vector.
    ///
    /// TODO: implement binary encoding (big-endian field layout).
    pub fn encode(&self) -> Vec<u8> {
        todo!("encode packet to bytes")
    }

    /// Parse a [`Packet`] from a raw byte slice.
    ///
    /// Returns `Err` if the buffer is too short or fields are inconsistent.
    ///
    /// TODO: implement binary decoding and checksum verification.
    pub fn decode(_buf: &[u8]) -> Result<Self, PacketError> {
        todo!("decode bytes to packet")
    }
}

/// Errors that can arise when parsing a raw datagram.
#[derive(Debug)]
pub enum PacketError {
    /// Buffer shorter than the fixed header size.
    BufferTooShort,
    /// `payload_len` field does not match the actual remaining bytes.
    LengthMismatch,
    /// Checksum did not match recomputed value.
    ChecksumFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        // TODO: construct a Packet, encode it, decode it, assert equality.
    }

    #[test]
    fn decode_empty_buffer_returns_error() {
        // TODO: assert that Packet::decode(&[]) returns BufferTooShort.
    }

    #[test]
    fn decode_truncated_payload_returns_error() {
        // TODO: build a valid header with payload_len > actual buffer remainder.
    }

    #[test]
    fn syn_flag_is_set_correctly() {
        // TODO: verify flags::SYN appears in encoded header byte.
    }
}
