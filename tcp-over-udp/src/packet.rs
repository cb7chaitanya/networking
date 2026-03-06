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
//! ## Fixed header (15 bytes — unchanged)
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
//! ```
//!
//! Total fixed header size: [`HEADER_LEN`] = 15 bytes.
//! seq(4) + ack(4) + flags(1) + window(2) + payload_len(2) + checksum(2)
//!
//! ## TCP-style options (variable length)
//!
//! Options are TLV-encoded and placed **immediately after the fixed header**
//! (i.e. they contribute to `payload_len`).  The [`flags::OPT`] bit in the
//! header signals that options are present; [`Packet::encode`] sets it
//! automatically when the options list is non-empty.  Data segments always
//! have an empty options list so the OPT bit is never set on them, preventing
//! the decoder from mis-parsing user payload bytes as options.
//!
//! ```text
//!  +--------+--------+--------...+
//!  |  Kind  | Length |   Data    |
//!  +--------+--------+--------...+
//! ```
//!
//! | Kind | Length | Description |
//! |------|--------|-------------|
//! | 0x00 | —      | End-of-options-list (EOL) — stops parsing |
//! | 0x01 | —      | No-operation (NOP) — 1 byte |
//! | 0x02 | 4      | Maximum Segment Size (`u16` big-endian) |
//! | 0x05 | 2+8n   | Selective ACK — n×(left:u32, right:u32) half-open ranges |
//!
//! ## Backward compatibility
//!
//! Peers that do not set OPT see no options in incoming packets.  When talking
//! to a peer whose SYN carries no options, the new peer falls back to the
//! configured [`DEFAULT_MSS`].

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
    /// Options-present marker — automatically set by [`Packet::encode`] when
    /// the options list is non-empty.  [`Packet::decode`] uses this to decide
    /// whether to invoke the option parser on the payload area.
    pub const OPT: u8 = 0b0001_0000;
    /// Mask of all defined flag bits; any bit outside this mask is invalid.
    pub const VALID_FLAGS: u8 = SYN | ACK | FIN | RST | OPT;
}

/// Well-known option kind bytes (TCP-compatible numbering).
pub mod option_kind {
    /// End-of-options-list marker — terminates option parsing (no Length byte).
    pub const EOL: u8 = 0;
    /// No-operation padding — 1 byte, no Length or Data (no-op).
    pub const NOP: u8 = 1;
    /// Maximum Segment Size — Kind=2, Length=4, Data=u16 big-endian.
    pub const MSS: u8 = 2;
    /// Window Scale — Kind=3, Length=3, Data=u8 shift count (RFC 7323).
    pub const WSCALE: u8 = 3;
    /// Selective Acknowledgement blocks — Kind=5, Length=2+8n, Data=n×(left:u32,right:u32).
    pub const SACK: u8 = 5;
}

/// Default MSS when the peer does not advertise one.
///
/// Matches the common TCP default over Ethernet (1500 byte MTU minus IP+UDP
/// overhead).  Override by calling the `*_with_mss` constructor variants.
pub const DEFAULT_MSS: u16 = 1460;

/// Byte length of the fixed-size header on the wire.
pub const HEADER_LEN: usize = 15;

// Byte offsets of each field within the serialised header.
const OFF_SEQ: usize = 0;
const OFF_ACK: usize = 4;
const OFF_FLAGS: usize = 8;
const OFF_WINDOW: usize = 9;
const OFF_PAYLOAD_LEN: usize = 11;
const OFF_CHECKSUM: usize = 13;

// ---------------------------------------------------------------------------
// SackBlock
// ---------------------------------------------------------------------------

/// A single SACK block: the half-open byte range `[left, right)` that the
/// receiver has already buffered out-of-order.
///
/// `left` is the first sequence number in the block; `right` is the first
/// sequence number **not** in the block (exclusive upper bound).  This
/// matches the TCP SACK convention from RFC 2018.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SackBlock {
    /// First sequence number covered by this block (inclusive).
    pub left: u32,
    /// First sequence number **not** covered (exclusive).
    pub right: u32,
}

// ---------------------------------------------------------------------------
// TcpOption
// ---------------------------------------------------------------------------

/// A single TCP-style option that may appear in any packet.
///
/// Options are serialised in TLV format immediately after the fixed 15-byte
/// header and terminated with an [`option_kind::EOL`] byte.  The
/// [`flags::OPT`] bit in the header signals that the options area is present;
/// [`Packet::encode`] sets it automatically when the options list is
/// non-empty, and [`Packet::decode`] uses it to decide whether to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOption {
    /// Maximum Segment Size — the largest payload this sender can accept.
    ///
    /// Carried in SYN and SYN-ACK; the connection layer negotiates
    /// `min(local_mss, peer_mss)` and enforces it on every data segment.
    Mss(u16),

    /// No-operation padding byte (kind = 1, no length/data field).
    Nop,

    /// Window Scale factor (kind = 3, RFC 7323).
    ///
    /// Carried **only** in SYN and SYN-ACK packets.  The value is a shift
    /// count (0–14); the true receive window is `header.window << shift`.
    /// A peer that does not include this option in its SYN has an implicit
    /// scale of 0 (no scaling).
    WindowScale(u8),

    /// Selective Acknowledgement blocks (kind = 5).
    ///
    /// Each block describes a half-open range `[left, right)` of bytes the
    /// receiver has already buffered out-of-order.  Carried on pure ACK
    /// packets to inform the sender which segments can be skipped on
    /// retransmission.
    Sack(Vec<SackBlock>),
}

impl TcpOption {
    /// Number of bytes this option occupies on the wire (including kind and
    /// length bytes where applicable).
    pub fn wire_len(&self) -> usize {
        match self {
            TcpOption::Nop => 1,
            TcpOption::Mss(_) => 4,         // kind(1) + length(1) + value(2)
            TcpOption::WindowScale(_) => 3, // kind(1) + length(1) + shift(1)
            TcpOption::Sack(b) => 2 + 8 * b.len(), // kind(1) + length(1) + n×8
        }
    }
}

// ---------------------------------------------------------------------------
// Header / Packet
// ---------------------------------------------------------------------------

/// Fixed-size protocol header (in-memory representation).
///
/// Fields are in host byte order; [`Packet::encode`] converts to big-endian
/// on the wire and [`Packet::decode`] converts back.
///
/// `payload_len` is intentionally absent: it exists on the wire for framing
/// and is validated during [`Packet::decode`], but the canonical length is
/// always `options_wire_len() + packet.payload.len()`.
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
    /// Internet checksum (RFC 1071) over the entire serialised packet.
    ///
    /// On encode this is computed and written last.
    /// On decode this is verified before the packet is returned.
    pub checksum: u16,
}

/// A complete protocol datagram: fixed header + options + payload bytes.
///
/// `options` is non-empty for SYN/SYN-ACK (MSS negotiation) and for pure
/// ACKs that carry SACK blocks.  Data segments always have `options: vec![]`.
/// During [`encode`] the options are serialised before `payload` and the
/// [`flags::OPT`] bit is set automatically; during [`decode`] options are
/// parsed when the OPT flag is set.
///
/// [`encode`]: Packet::encode
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    /// TCP-style options.  Non-empty for SYN/SYN-ACK and for ACKs with SACK.
    pub options: Vec<TcpOption>,
    pub payload: Vec<u8>,
}

impl Packet {
    /// Serialise this packet into a newly allocated byte vector.
    ///
    /// Options (if any) are serialised before `payload`.  The `payload_len`
    /// wire field covers both.  `checksum` is computed from the full buffer
    /// and any value already stored in `header.checksum` is ignored.
    ///
    /// Options are only emitted when the SYN flag is set.  If options are
    /// present on a non-SYN packet they are silently dropped.
    ///
    /// Returns [`Err`] if the combined options + payload exceeds 65 535 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        // Emit options whenever the list is non-empty (not just for SYN).
        let opts_bytes: Vec<u8> = if !self.options.is_empty() {
            encode_options(&self.options)
        } else {
            Vec::new()
        };

        let total_payload_len = opts_bytes.len() + self.payload.len();
        if total_payload_len > u16::MAX as usize {
            return Err(PacketError::PayloadTooLarge);
        }

        let mut buf = vec![0u8; HEADER_LEN + total_payload_len];

        buf[OFF_SEQ..OFF_SEQ + 4].copy_from_slice(&self.header.seq.to_be_bytes());
        buf[OFF_ACK..OFF_ACK + 4].copy_from_slice(&self.header.ack.to_be_bytes());
        // Auto-set the OPT flag when options are present so the decoder knows
        // to invoke the option parser, without relying on the SYN flag.
        let flags_wire = self.header.flags
            | if !self.options.is_empty() { flags::OPT } else { 0 };
        buf[OFF_FLAGS] = flags_wire;
        buf[OFF_WINDOW..OFF_WINDOW + 2].copy_from_slice(&self.header.window.to_be_bytes());
        buf[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 2]
            .copy_from_slice(&(total_payload_len as u16).to_be_bytes());
        // Checksum field is zero while computing.
        buf[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&0u16.to_be_bytes());

        // Options area (present whenever options list is non-empty).
        let opts_end = HEADER_LEN + opts_bytes.len();
        buf[HEADER_LEN..opts_end].copy_from_slice(&opts_bytes);
        // Data payload.
        buf[opts_end..].copy_from_slice(&self.payload);

        let csum = internet_checksum(&buf);
        buf[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&csum.to_be_bytes());

        Ok(buf)
    }

    /// Parse a [`Packet`] from a raw byte slice.
    ///
    /// When the SYN flag is set, leading option bytes are extracted from the
    /// payload area and placed in [`Packet::options`].  Unknown option kinds
    /// terminate option parsing; any remaining bytes become [`Packet::payload`].
    ///
    /// Returns [`Err`] if:
    /// - `buf` is shorter than [`HEADER_LEN`],
    /// - the wire `payload_len` field disagrees with `buf.len()`,
    /// - the `flags` field contains bits outside [`flags::VALID_FLAGS`], or
    /// - the checksum does not verify.
    pub fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        if buf.len() < HEADER_LEN {
            return Err(PacketError::BufferTooShort);
        }

        let seq = u32::from_be_bytes(
            buf[OFF_SEQ..OFF_SEQ + 4]
                .try_into()
                .map_err(|_| PacketError::BufferTooShort)?,
        );
        let ack = u32::from_be_bytes(
            buf[OFF_ACK..OFF_ACK + 4]
                .try_into()
                .map_err(|_| PacketError::BufferTooShort)?,
        );
        let raw_flags = buf[OFF_FLAGS];
        if raw_flags & !flags::VALID_FLAGS != 0 {
            return Err(PacketError::InvalidFlags);
        }
        let window = u16::from_be_bytes(
            buf[OFF_WINDOW..OFF_WINDOW + 2]
                .try_into()
                .map_err(|_| PacketError::BufferTooShort)?,
        );
        // payload_len covers options + data for SYN; pure data otherwise.
        let payload_len = u16::from_be_bytes(
            buf[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 2]
                .try_into()
                .map_err(|_| PacketError::BufferTooShort)?,
        );
        let checksum = u16::from_be_bytes(
            buf[OFF_CHECKSUM..OFF_CHECKSUM + 2]
                .try_into()
                .map_err(|_| PacketError::BufferTooShort)?,
        );

        if buf.len() != HEADER_LEN + payload_len as usize {
            return Err(PacketError::LengthMismatch);
        }

        // Verify checksum: zero the stored field, recompute, compare.
        let mut scratch = buf.to_vec();
        scratch[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&0u16.to_be_bytes());
        if internet_checksum(&scratch) != checksum {
            return Err(PacketError::ChecksumFailed);
        }

        // Parse options when the OPT flag is set.  This prevents treating the
        // start of a data payload as option bytes (OPT is only set when the
        // sender explicitly included options).
        let raw_after_header = &buf[HEADER_LEN..];
        let (options, payload_bytes) = if raw_flags & flags::OPT != 0 {
            decode_options_from(raw_after_header)
        } else {
            (Vec::new(), raw_after_header)
        };

        Ok(Packet {
            header: Header {
                seq,
                ack,
                flags: raw_flags,
                window,
                checksum,
            },
            options,
            payload: payload_bytes.to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// Option encode / decode helpers
// ---------------------------------------------------------------------------

/// Serialise a slice of options into TLV bytes, appending an EOL terminator.
///
/// Called by [`Packet::encode`] for SYN / SYN-ACK packets.
fn encode_options(options: &[TcpOption]) -> Vec<u8> {
    let total: usize = options.iter().map(TcpOption::wire_len).sum::<usize>() + 1; // +1 EOL
    let mut buf = Vec::with_capacity(total);
    for opt in options {
        match opt {
            TcpOption::Nop => buf.push(option_kind::NOP),
            TcpOption::Mss(mss) => {
                buf.push(option_kind::MSS);
                buf.push(4); // total option length (kind + length + 2-byte value)
                buf.extend_from_slice(&mss.to_be_bytes());
            }
            TcpOption::WindowScale(shift) => {
                buf.push(option_kind::WSCALE);
                buf.push(3); // total option length (kind + length + 1-byte shift)
                buf.push(*shift);
            }
            TcpOption::Sack(blocks) => {
                buf.push(option_kind::SACK);
                buf.push((2 + 8 * blocks.len()) as u8); // kind(1)+len(1)+n*8
                for block in blocks {
                    buf.extend_from_slice(&block.left.to_be_bytes());
                    buf.extend_from_slice(&block.right.to_be_bytes());
                }
            }
        }
    }
    buf.push(option_kind::EOL);
    buf
}

/// Parse TLV-encoded options from `data`, returning `(options, remaining)`.
///
/// Parsing stops at the first [`option_kind::EOL`] byte, after consuming it,
/// or at the first unrecognised kind byte (which is **not** consumed — the
/// remainder, including that byte, becomes the data payload).  This ensures
/// forward compatibility: unknown future options are treated as the start of
/// the application payload.
///
/// Called by [`Packet::decode`] when the SYN flag is set.
fn decode_options_from(data: &[u8]) -> (Vec<TcpOption>, &[u8]) {
    let mut options = Vec::new();
    let mut i = 0usize;

    while i < data.len() {
        match data[i] {
            option_kind::EOL => {
                i += 1;
                break;
            }
            option_kind::NOP => {
                options.push(TcpOption::Nop);
                i += 1;
            }
            option_kind::MSS => {
                // Need kind(1) + length(1) + value(2) = 4 bytes.
                if i + 4 > data.len() {
                    break; // truncated option — stop, treat rest as payload
                }
                let len = data[i + 1];
                if len != 4 {
                    break; // malformed length — stop
                }
                let mss = u16::from_be_bytes([data[i + 2], data[i + 3]]);
                options.push(TcpOption::Mss(mss));
                i += 4;
            }
            option_kind::WSCALE => {
                // Need kind(1) + length(1) + shift(1) = 3 bytes.
                if i + 3 > data.len() {
                    break; // truncated option — stop, treat rest as payload
                }
                let len = data[i + 1];
                if len != 3 {
                    break; // malformed length — stop
                }
                let shift = data[i + 2];
                options.push(TcpOption::WindowScale(shift));
                i += 3;
            }
            option_kind::SACK => {
                // Need at least kind(1) + length(1).
                if i + 2 > data.len() {
                    break;
                }
                let len = data[i + 1] as usize;
                // Length must be >= 2 (kind+len) and data portion divisible by 8.
                if len < 2 || (len - 2) % 8 != 0 || i + len > data.len() {
                    break;
                }
                let n = (len - 2) / 8;
                let mut blocks = Vec::with_capacity(n);
                for j in 0..n {
                    let off = i + 2 + j * 8;
                    let left = u32::from_be_bytes(data[off..off + 4].try_into().unwrap());
                    let right = u32::from_be_bytes(data[off + 4..off + 8].try_into().unwrap());
                    blocks.push(SackBlock { left, right });
                }
                options.push(TcpOption::Sack(blocks));
                i += len;
            }
            _ => break, // unknown kind — stop and leave byte in payload
        }
    }

    (options, &data[i..])
}

// ---------------------------------------------------------------------------
// PacketError
// ---------------------------------------------------------------------------

/// Errors that can arise when encoding or parsing a datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum PacketError {
    /// Buffer shorter than the fixed header size.
    BufferTooShort,
    /// `payload_len` field does not match the actual remaining bytes.
    LengthMismatch,
    /// Checksum did not match recomputed value.
    ChecksumFailed,
    /// `flags` field contains bits outside the defined set.
    InvalidFlags,
    /// Payload exceeds the 65 535-byte wire limit.
    PayloadTooLarge,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::BufferTooShort => write!(f, "buffer too short to contain a header"),
            PacketError::LengthMismatch => {
                write!(f, "payload_len field does not match remaining bytes")
            }
            PacketError::ChecksumFailed => write!(f, "checksum verification failed"),
            PacketError::InvalidFlags => write!(f, "flags field contains undefined bits"),
            PacketError::PayloadTooLarge => write!(f, "payload exceeds 65535-byte wire limit"),
        }
    }
}

impl std::error::Error for PacketError {}

// ---------------------------------------------------------------------------
// Internet checksum (RFC 1071)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
                checksum: 0, // overwritten by encode
            },
            options: vec![],
            payload: payload.to_vec(),
        }
    }

    fn make_syn_with_mss(seq: u32, mss: u16) -> Packet {
        Packet {
            header: Header {
                seq,
                ack: 0,
                flags: flags::SYN,
                window: 8192,
                checksum: 0,
            },
            options: vec![TcpOption::Mss(mss)],
            payload: vec![],
        }
    }

    // ── Existing regression tests ────────────────────────────────────────────

    #[test]
    fn encode_decode_roundtrip() {
        let pkt = make_packet(42, 0, flags::SYN, 4096, b"hello");
        let decoded = Packet::decode(&pkt.encode().unwrap()).unwrap();
        assert_eq!(decoded.header.seq, pkt.header.seq);
        assert_eq!(decoded.header.ack, pkt.header.ack);
        assert_eq!(decoded.header.flags, pkt.header.flags);
        assert_eq!(decoded.header.window, pkt.header.window);
        assert_eq!(decoded.payload, pkt.payload);
    }

    #[test]
    fn encode_sets_correct_payload_len() {
        let pkt = make_packet(1, 2, flags::ACK, 8192, b"world");
        let bytes = pkt.encode().unwrap();
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
        let mut bytes = make_packet(0, 0, 0, 0, b"data").encode().unwrap();
        bytes.pop(); // payload_len still claims 4 bytes, but buf is one short
        assert_eq!(Packet::decode(&bytes), Err(PacketError::LengthMismatch));
    }

    #[test]
    fn decode_corrupt_byte_returns_checksum_error() {
        let mut bytes = make_packet(99, 0, flags::SYN, 1024, b"test").encode().unwrap();
        bytes[0] ^= 0xff;
        assert_eq!(Packet::decode(&bytes), Err(PacketError::ChecksumFailed));
    }

    #[test]
    fn syn_flag_is_set_correctly() {
        let bytes = make_packet(0, 0, flags::SYN, 0, b"").encode().unwrap();
        assert_eq!(bytes[OFF_FLAGS] & flags::SYN, flags::SYN);
    }

    #[test]
    fn empty_payload_roundtrip() {
        let pkt = make_packet(0, 1000, flags::ACK, 65535, b"");
        let decoded = Packet::decode(&pkt.encode().unwrap()).unwrap();
        assert_eq!(decoded.payload, Vec::<u8>::new());
    }

    #[test]
    fn header_len_constant_is_correct() {
        // seq(4) + ack(4) + flags(1) + window(2) + payload_len(2) + checksum(2) = 15
        assert_eq!(HEADER_LEN, 15);
    }

    #[test]
    fn encoded_length_equals_header_plus_payload() {
        let payload = b"exactly twelve!";
        let bytes = make_packet(0, 0, 0, 0, payload).encode().unwrap();
        assert_eq!(bytes.len(), HEADER_LEN + payload.len());
    }

    #[test]
    fn multiple_flag_bits() {
        let f = flags::SYN | flags::ACK;
        let bytes = make_packet(1, 2, f, 512, b"").encode().unwrap();
        assert_eq!(bytes[OFF_FLAGS], f);
    }

    #[test]
    fn seq_ack_big_endian_on_wire() {
        let bytes = make_packet(0x0102_0304, 0x0506_0708, 0, 0, b"")
            .encode()
            .unwrap();
        assert_eq!(&bytes[OFF_SEQ..OFF_SEQ + 4], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&bytes[OFF_ACK..OFF_ACK + 4], &[0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn decode_invalid_flags_returns_error() {
        // Build a valid packet, then flip bits that are still undefined (5-7).
        // Bit 4 (OPT) is now a valid flag.
        let mut bytes = make_packet(0, 0, flags::SYN, 0, b"").encode().unwrap();
        bytes[OFF_FLAGS] |= 0b1110_0000; // bits 5–7 are undefined
        assert_eq!(Packet::decode(&bytes), Err(PacketError::InvalidFlags));
    }

    #[test]
    fn encode_payload_too_large_returns_error() {
        let oversized = vec![0u8; u16::MAX as usize + 1];
        let pkt = Packet {
            header: Header { seq: 0, ack: 0, flags: 0, window: 0, checksum: 0 },
            options: vec![],
            payload: oversized,
        };
        assert_eq!(pkt.encode(), Err(PacketError::PayloadTooLarge));
    }

    // ── Options: MSS encode / decode ─────────────────────────────────────────

    #[test]
    fn mss_option_encode_roundtrip() {
        let syn = make_syn_with_mss(100, 1460);
        let bytes = syn.encode().unwrap();
        let decoded = Packet::decode(&bytes).unwrap();

        // OPT is auto-set by encode() because options are non-empty.
        assert_eq!(decoded.header.flags, flags::SYN | flags::OPT);
        assert_eq!(decoded.options, vec![TcpOption::Mss(1460)]);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn mss_option_wire_length_correct() {
        // SYN with MSS: wire = HEADER_LEN + kind(1)+len(1)+val(2) + EOL(1) = HEADER_LEN + 5
        let syn = make_syn_with_mss(0, 512);
        let bytes = syn.encode().unwrap();
        assert_eq!(bytes.len(), HEADER_LEN + 5);
    }

    #[test]
    fn mss_payload_len_field_covers_options() {
        let syn = make_syn_with_mss(0, 1200);
        let bytes = syn.encode().unwrap();
        let payload_len_wire =
            u16::from_be_bytes([bytes[OFF_PAYLOAD_LEN], bytes[OFF_PAYLOAD_LEN + 1]]);
        // Options: MSS(4) + EOL(1) = 5 bytes; no data payload.
        assert_eq!(payload_len_wire, 5);
    }

    #[test]
    fn non_syn_options_are_encoded() {
        // Options on any packet (including non-SYN) are now encoded when non-empty.
        // The OPT flag is auto-set by encode() so the decoder knows to parse.
        let pkt = Packet {
            header: Header { seq: 0, ack: 0, flags: flags::ACK, window: 0, checksum: 0 },
            options: vec![TcpOption::Mss(1460)],
            payload: b"data".to_vec(),
        };
        let bytes = pkt.encode().unwrap();
        // options: MSS(4) + EOL(1) = 5 bytes; payload: "data" = 4 bytes.
        assert_eq!(bytes.len(), HEADER_LEN + 5 + 4);

        let decoded = Packet::decode(&bytes).unwrap();
        // OPT flag triggers option parsing; MSS and payload both survive.
        assert_eq!(decoded.options, vec![TcpOption::Mss(1460)]);
        assert_eq!(decoded.payload, b"data");
        // OPT flag is set in the decoded header.
        assert_ne!(decoded.header.flags & flags::OPT, 0);
    }

    #[test]
    fn syn_with_no_options_roundtrip() {
        // A bare SYN (no options) should decode with empty options vec.
        let syn = make_packet(42, 0, flags::SYN, 4096, b"");
        let decoded = Packet::decode(&syn.encode().unwrap()).unwrap();
        assert!(decoded.options.is_empty());
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn syn_with_arbitrary_payload_not_mistaken_for_options() {
        // A SYN carrying legacy payload (e.g. from an old peer) — bytes that
        // don't start with a recognised option kind stop option parsing
        // immediately, leaving the full payload intact.
        let syn = make_packet(1, 0, flags::SYN, 0, b"hello");
        let decoded = Packet::decode(&syn.encode().unwrap()).unwrap();
        // 'h' = 0x68 — unknown kind, stops immediately.
        assert!(decoded.options.is_empty());
        assert_eq!(decoded.payload, b"hello");
    }

    #[test]
    fn mss_checksum_covers_options() {
        // Corrupt one byte inside the MSS option; checksum must fail.
        let syn = make_syn_with_mss(77, 1460);
        let mut bytes = syn.encode().unwrap();
        // Byte at HEADER_LEN+2 is the high byte of the MSS value.
        bytes[HEADER_LEN + 2] ^= 0xff;
        assert_eq!(Packet::decode(&bytes), Err(PacketError::ChecksumFailed));
    }

    #[test]
    fn nop_option_roundtrip() {
        let pkt = Packet {
            header: Header {
                seq: 5,
                ack: 0,
                flags: flags::SYN,
                window: 1024,
                checksum: 0,
            },
            options: vec![TcpOption::Nop, TcpOption::Mss(800)],
            payload: vec![],
        };
        let decoded = Packet::decode(&pkt.encode().unwrap()).unwrap();
        assert_eq!(decoded.options, vec![TcpOption::Nop, TcpOption::Mss(800)]);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn syn_ack_carries_mss() {
        let syn_ack = Packet {
            header: Header {
                seq: 200,
                ack: 101,
                flags: flags::SYN | flags::ACK,
                window: 8192,
                checksum: 0,
            },
            options: vec![TcpOption::Mss(536)],
            payload: vec![],
        };
        let decoded = Packet::decode(&syn_ack.encode().unwrap()).unwrap();
        assert_eq!(decoded.options, vec![TcpOption::Mss(536)]);
        assert!(decoded.payload.is_empty());
    }

    // ── SACK option ──────────────────────────────────────────────────────────

    #[test]
    fn sack_option_single_block_roundtrip() {
        let pkt = Packet {
            header: Header {
                seq: 100,
                ack: 50,
                flags: flags::ACK,
                window: 8192,
                checksum: 0,
            },
            options: vec![TcpOption::Sack(vec![SackBlock {
                left: 110,
                right: 120,
            }])],
            payload: vec![],
        };
        let bytes = pkt.encode().unwrap();
        // OPT flag must be set on the wire.
        assert_ne!(bytes[OFF_FLAGS] & flags::OPT, 0);
        let decoded = Packet::decode(&bytes).unwrap();
        assert_eq!(
            decoded.options,
            vec![TcpOption::Sack(vec![SackBlock {
                left: 110,
                right: 120
            }])]
        );
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn sack_option_multiple_blocks_roundtrip() {
        let blocks = vec![
            SackBlock {
                left: 10,
                right: 20,
            },
            SackBlock {
                left: 30,
                right: 40,
            },
            SackBlock {
                left: 50,
                right: 60,
            },
        ];
        let pkt = Packet {
            header: Header {
                seq: 0,
                ack: 5,
                flags: flags::ACK,
                window: 4096,
                checksum: 0,
            },
            options: vec![TcpOption::Sack(blocks.clone())],
            payload: vec![],
        };
        let decoded = Packet::decode(&pkt.encode().unwrap()).unwrap();
        assert_eq!(decoded.options, vec![TcpOption::Sack(blocks)]);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn sack_wire_length_correct() {
        // 1 block: kind(1) + len(1) + 8 bytes + EOL(1) = 11 bytes of options.
        let opt = TcpOption::Sack(vec![SackBlock { left: 0, right: 8 }]);
        assert_eq!(opt.wire_len(), 10); // kind(1)+len(1)+1*8
        let pkt = Packet {
            header: Header {
                seq: 0,
                ack: 0,
                flags: flags::ACK,
                window: 0,
                checksum: 0,
            },
            options: vec![opt],
            payload: vec![],
        };
        // Wire: HEADER_LEN + options(10) + EOL(1) = HEADER_LEN + 11.
        assert_eq!(pkt.encode().unwrap().len(), HEADER_LEN + 11);
    }

    #[test]
    fn no_options_means_no_opt_flag() {
        // Packets without options must NOT have OPT set on the wire.
        let pkt = make_packet(1, 2, flags::ACK, 512, b"hello");
        let bytes = pkt.encode().unwrap();
        assert_eq!(bytes[OFF_FLAGS] & flags::OPT, 0);
    }

    #[test]
    fn sack_zero_blocks_roundtrip() {
        // Sack(vec![]) is a degenerate option: kind(1)+len(1)+EOL(1) = 3 bytes.
        let pkt = Packet {
            header: Header {
                seq: 0,
                ack: 0,
                flags: flags::ACK,
                window: 0,
                checksum: 0,
            },
            options: vec![TcpOption::Sack(vec![])],
            payload: vec![],
        };
        let decoded = Packet::decode(&pkt.encode().unwrap()).unwrap();
        assert_eq!(decoded.options, vec![TcpOption::Sack(vec![])]);
    }

    // ── Window Scale option ──────────────────────────────────────────────────

    #[test]
    fn window_scale_option_roundtrip() {
        let pkt = Packet {
            header: Header {
                seq: 100,
                ack: 0,
                flags: flags::SYN,
                window: 8192,
                checksum: 0,
            },
            options: vec![TcpOption::WindowScale(7)],
            payload: vec![],
        };
        let bytes = pkt.encode().unwrap();
        let decoded = Packet::decode(&bytes).unwrap();
        assert_eq!(decoded.options, vec![TcpOption::WindowScale(7)]);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn window_scale_wire_length_correct() {
        // WindowScale: kind(1) + length(1) + shift(1) = 3 bytes.
        let opt = TcpOption::WindowScale(14);
        assert_eq!(opt.wire_len(), 3);
        let pkt = Packet {
            header: Header {
                seq: 0,
                ack: 0,
                flags: flags::SYN,
                window: 0,
                checksum: 0,
            },
            options: vec![opt],
            payload: vec![],
        };
        // Wire: HEADER_LEN + options(3) + EOL(1) = HEADER_LEN + 4.
        assert_eq!(pkt.encode().unwrap().len(), HEADER_LEN + 4);
    }

    #[test]
    fn window_scale_with_mss_roundtrip() {
        // Typical SYN: MSS + WindowScale together.
        let pkt = Packet {
            header: Header {
                seq: 42,
                ack: 0,
                flags: flags::SYN,
                window: 65535,
                checksum: 0,
            },
            options: vec![TcpOption::Mss(1460), TcpOption::WindowScale(7)],
            payload: vec![],
        };
        let decoded = Packet::decode(&pkt.encode().unwrap()).unwrap();
        assert_eq!(
            decoded.options,
            vec![TcpOption::Mss(1460), TcpOption::WindowScale(7)]
        );
    }

    #[test]
    fn window_scale_max_shift_roundtrip() {
        // RFC 7323 allows shift values 0–14.
        let pkt = Packet {
            header: Header {
                seq: 0,
                ack: 0,
                flags: flags::SYN,
                window: 0,
                checksum: 0,
            },
            options: vec![TcpOption::WindowScale(14)],
            payload: vec![],
        };
        let decoded = Packet::decode(&pkt.encode().unwrap()).unwrap();
        assert_eq!(decoded.options, vec![TcpOption::WindowScale(14)]);
    }

    #[test]
    fn window_scale_zero_shift_roundtrip() {
        // Shift of 0 means no scaling (1:1).
        let pkt = Packet {
            header: Header {
                seq: 0,
                ack: 0,
                flags: flags::SYN,
                window: 0,
                checksum: 0,
            },
            options: vec![TcpOption::WindowScale(0)],
            payload: vec![],
        };
        let decoded = Packet::decode(&pkt.encode().unwrap()).unwrap();
        assert_eq!(decoded.options, vec![TcpOption::WindowScale(0)]);
    }
}
