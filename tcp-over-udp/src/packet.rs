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
//!
//! # Wire format
//!
//! All multi-byte integers are **big-endian**.
//!
//! ```text
//!  0               1               2               3
//!  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Sequence Number                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Acknowledgment Number                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Flags     |            Window Size        |               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
//! |         Payload Length        |            Checksum           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Payload ...                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Total header size: [`HEADER_LEN`] = 15 bytes.
//! seq(4) + ack(4) + flags(1) + window(2) + payload_len(2) + checksum(2)

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

/// Byte length of the fixed-size header on the wire.
pub const HEADER_LEN: usize = 15;

// Byte offsets of each field within the serialised header.
const OFF_SEQ: usize = 0;
const OFF_ACK: usize = 4;
const OFF_FLAGS: usize = 8;
const OFF_WINDOW: usize = 9;
const OFF_PAYLOAD_LEN: usize = 11;
const OFF_CHECKSUM: usize = 13;

/// Fixed-size protocol header.
///
/// Fields are in host byte order; [`Packet::encode`] converts to big-endian
/// on the wire and [`Packet::decode`] converts back.
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
    /// Length of the payload in bytes.
    ///
    /// On encode this is computed from the actual payload length.
    /// On decode this is validated against the remaining buffer bytes.
    pub payload_len: u16,
    /// Internet checksum (RFC 1071) over the entire serialised packet.
    ///
    /// On encode this is computed and written last.
    /// On decode this is verified before the packet is returned.
    pub checksum: u16,
}

/// A complete protocol datagram: header + payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    pub payload: Vec<u8>,
}

impl Packet {
    /// Serialise this packet into a newly allocated byte vector.
    ///
    /// `header.payload_len` and `header.checksum` are computed from the actual
    /// payload; any values already stored in those fields are ignored.
    pub fn encode(&self) -> Vec<u8> {
        let payload_len = self.payload.len();
        let mut buf = vec![0u8; HEADER_LEN + payload_len];

        buf[OFF_SEQ..OFF_SEQ + 4].copy_from_slice(&self.header.seq.to_be_bytes());
        buf[OFF_ACK..OFF_ACK + 4].copy_from_slice(&self.header.ack.to_be_bytes());
        buf[OFF_FLAGS] = self.header.flags;
        buf[OFF_WINDOW..OFF_WINDOW + 2].copy_from_slice(&self.header.window.to_be_bytes());
        buf[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 2]
            .copy_from_slice(&(payload_len as u16).to_be_bytes());
        // Checksum field is zero while computing the checksum.
        buf[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&0u16.to_be_bytes());

        buf[HEADER_LEN..].copy_from_slice(&self.payload);

        let csum = internet_checksum(&buf);
        buf[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&csum.to_be_bytes());

        buf
    }

    /// Parse a [`Packet`] from a raw byte slice.
    ///
    /// Returns [`Err`] if:
    /// - `buf` is shorter than [`HEADER_LEN`],
    /// - the `payload_len` field disagrees with `buf.len()`, or
    /// - the checksum does not verify.
    pub fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        if buf.len() < HEADER_LEN {
            return Err(PacketError::BufferTooShort);
        }

        let seq = u32::from_be_bytes(buf[OFF_SEQ..OFF_SEQ + 4].try_into().unwrap());
        let ack = u32::from_be_bytes(buf[OFF_ACK..OFF_ACK + 4].try_into().unwrap());
        let flags = buf[OFF_FLAGS];
        let window = u16::from_be_bytes(buf[OFF_WINDOW..OFF_WINDOW + 2].try_into().unwrap());
        let payload_len =
            u16::from_be_bytes(buf[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 2].try_into().unwrap());
        let checksum =
            u16::from_be_bytes(buf[OFF_CHECKSUM..OFF_CHECKSUM + 2].try_into().unwrap());

        if buf.len() != HEADER_LEN + payload_len as usize {
            return Err(PacketError::LengthMismatch);
        }

        // Verify checksum: zero the stored field, recompute, compare.
        let mut scratch = buf.to_vec();
        scratch[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&0u16.to_be_bytes());
        if internet_checksum(&scratch) != checksum {
            return Err(PacketError::ChecksumFailed);
        }

        Ok(Packet {
            header: Header {
                seq,
                ack,
                flags,
                window,
                payload_len,
                checksum,
            },
            payload: buf[HEADER_LEN..].to_vec(),
        })
    }
}

/// Errors that can arise when parsing a raw datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum PacketError {
    /// Buffer shorter than the fixed header size.
    BufferTooShort,
    /// `payload_len` field does not match the actual remaining bytes.
    LengthMismatch,
    /// Checksum did not match recomputed value.
    ChecksumFailed,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::BufferTooShort => write!(f, "buffer too short to contain a header"),
            PacketError::LengthMismatch => {
                write!(f, "payload_len field does not match remaining bytes")
            }
            PacketError::ChecksumFailed => write!(f, "checksum verification failed"),
        }
    }
}

impl std::error::Error for PacketError {}

/// Compute the Internet checksum (RFC 1071) over `data`.
///
/// Sum consecutive 16-bit big-endian words, fold the carry, return the
/// one's-complement.  The caller must zero any checksum field within `data`
/// before calling this function.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    // Odd trailing byte — pad with a zero byte on the right.
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }

    // Fold 32-bit sum into 16 bits.
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet(seq: u32, ack: u32, flags: u8, window: u16, payload: &[u8]) -> Packet {
        Packet {
            header: Header {
                seq,
                ack,
                flags,
                window,
                payload_len: 0, // overwritten by encode
                checksum: 0,    // overwritten by encode
            },
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let pkt = make_packet(42, 0, flags::SYN, 4096, b"hello");
        let decoded = Packet::decode(&pkt.encode()).unwrap();
        assert_eq!(decoded.header.seq, pkt.header.seq);
        assert_eq!(decoded.header.ack, pkt.header.ack);
        assert_eq!(decoded.header.flags, pkt.header.flags);
        assert_eq!(decoded.header.window, pkt.header.window);
        assert_eq!(decoded.header.payload_len, pkt.payload.len() as u16);
        assert_eq!(decoded.payload, pkt.payload);
    }

    #[test]
    fn encode_sets_correct_payload_len() {
        let pkt = make_packet(1, 2, flags::ACK, 8192, b"world");
        let bytes = pkt.encode();
        let len_field = u16::from_be_bytes([bytes[OFF_PAYLOAD_LEN], bytes[OFF_PAYLOAD_LEN + 1]]);
        assert_eq!(len_field, pkt.payload.len() as u16);
    }

    #[test]
    fn decode_empty_buffer_returns_error() {
        assert_eq!(Packet::decode(&[]), Err(PacketError::BufferTooShort));
    }

    #[test]
    fn decode_short_header_returns_error() {
        assert_eq!(
            Packet::decode(&[0u8; HEADER_LEN - 1]),
            Err(PacketError::BufferTooShort)
        );
    }

    #[test]
    fn decode_truncated_payload_returns_error() {
        let mut bytes = make_packet(0, 0, 0, 0, b"data").encode();
        bytes.pop(); // payload_len still claims 4 bytes, but buf is one short
        assert_eq!(Packet::decode(&bytes), Err(PacketError::LengthMismatch));
    }

    #[test]
    fn decode_corrupt_byte_returns_checksum_error() {
        let mut bytes = make_packet(99, 0, flags::SYN, 1024, b"test").encode();
        bytes[0] ^= 0xff;
        assert_eq!(Packet::decode(&bytes), Err(PacketError::ChecksumFailed));
    }

    #[test]
    fn syn_flag_is_set_correctly() {
        let bytes = make_packet(0, 0, flags::SYN, 0, b"").encode();
        assert_eq!(bytes[OFF_FLAGS] & flags::SYN, flags::SYN);
    }

    #[test]
    fn empty_payload_roundtrip() {
        let pkt = make_packet(0, 1000, flags::ACK, 65535, b"");
        let decoded = Packet::decode(&pkt.encode()).unwrap();
        assert_eq!(decoded.payload, Vec::<u8>::new());
        assert_eq!(decoded.header.payload_len, 0);
    }

    #[test]
    fn header_len_constant_is_correct() {
        // seq(4) + ack(4) + flags(1) + window(2) + payload_len(2) + checksum(2) = 15
        assert_eq!(HEADER_LEN, 15);
    }

    #[test]
    fn encoded_length_equals_header_plus_payload() {
        let payload = b"exactly twelve!";
        let bytes = make_packet(0, 0, 0, 0, payload).encode();
        assert_eq!(bytes.len(), HEADER_LEN + payload.len());
    }

    #[test]
    fn multiple_flag_bits() {
        let f = flags::SYN | flags::ACK;
        let bytes = make_packet(1, 2, f, 512, b"").encode();
        assert_eq!(bytes[OFF_FLAGS], f);
    }

    #[test]
    fn seq_ack_big_endian_on_wire() {
        let bytes = make_packet(0x0102_0304, 0x0506_0708, 0, 0, b"").encode();
        assert_eq!(&bytes[OFF_SEQ..OFF_SEQ + 4], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&bytes[OFF_ACK..OFF_ACK + 4], &[0x05, 0x06, 0x07, 0x08]);
    }
}
