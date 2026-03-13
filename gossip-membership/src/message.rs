/// Wire format for gossip messages.
///
/// Fixed 18-byte header followed by a variable-length payload.
///
/// Header layout (big-endian):
/// ```text
///  Byte  0       : kind         (u8)   — GOSSIP / PING / PING_REQ / ACK
///  Bytes 1-2     : payload_len  (u16)  — number of bytes after the header
///  Bytes 3-10    : sender_id    (u64)  — originating node identity
///  Bytes 11-14   : heartbeat    (u32)  — sender's current heartbeat counter
///  Byte  15      : flags        (u8)   — bit-0 = REQUEST_ACK
///  Bytes 16-17   : checksum     (u16)  — RFC 1071 over entire buffer (zeroed for calc)
/// ```
///
/// All multi-byte integers are big-endian (network byte order).
use std::net::{Ipv4Addr, SocketAddrV4};

// ── Header byte offsets ──────────────────────────────────────────────────────
pub const OFF_KIND: usize = 0;
pub const OFF_PLEN: usize = 1; // 2 bytes
pub const OFF_SENDER_ID: usize = 3; // 8 bytes
pub const OFF_HEARTBEAT: usize = 11; // 4 bytes
pub const OFF_FLAGS: usize = 15;
pub const OFF_CHECKSUM: usize = 16; // 2 bytes
pub const HEADER_LEN: usize = 18;

// ── Message kinds ────────────────────────────────────────────────────────────
pub mod kind {
    pub const GOSSIP: u8 = 0x01;
    pub const PING: u8 = 0x02;
    pub const PING_REQ: u8 = 0x03;
    pub const ACK: u8 = 0x04;
}

// ── Flags ────────────────────────────────────────────────────────────────────
pub mod flags {
    pub const REQUEST_ACK: u8 = 0b0000_0001;
}

// ── Status byte values (also used in NodeStatus::to_wire / from_wire) ────────
pub mod status {
    pub const ALIVE: u8 = 0;
    pub const SUSPECT: u8 = 1;
    pub const DEAD: u8 = 2;
}

// ── Wire-level node entry ────────────────────────────────────────────────────
/// One membership record on the wire (23 bytes, IPv4 only).
///
/// ```text
///  Bytes  0-7  : node_id     (u64)
///  Bytes  8-11 : heartbeat   (u32)
///  Bytes 12-15 : incarnation (u32) — SWIM incarnation number
///  Byte   16   : status      (u8)  — 0=Alive, 1=Suspect, 2=Dead
///  Bytes 17-20 : ip          (u32) — IPv4 address, big-endian
///  Bytes 21-22 : port        (u16)
/// ```
pub const NODE_ENTRY_LEN: usize = 23;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireNodeEntry {
    pub node_id: u64,
    pub heartbeat: u32,
    pub incarnation: u32,
    pub status: u8,
    pub ip: u32,
    pub port: u16,
}

impl WireNodeEntry {
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.node_id.to_be_bytes());
        buf.extend_from_slice(&self.heartbeat.to_be_bytes());
        buf.extend_from_slice(&self.incarnation.to_be_bytes());
        buf.push(self.status);
        buf.extend_from_slice(&self.ip.to_be_bytes());
        buf.extend_from_slice(&self.port.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < NODE_ENTRY_LEN {
            return None;
        }
        Some(Self {
            node_id: u64::from_be_bytes(buf[0..8].try_into().ok()?),
            heartbeat: u32::from_be_bytes(buf[8..12].try_into().ok()?),
            incarnation: u32::from_be_bytes(buf[12..16].try_into().ok()?),
            status: buf[16],
            ip: u32::from_be_bytes(buf[17..21].try_into().ok()?),
            port: u16::from_be_bytes(buf[21..23].try_into().ok()?),
        })
    }

    pub fn addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(self.ip), self.port)
    }
}

// ── PING_REQ payload ─────────────────────────────────────────────────────────
/// Carries the address of the node we want an intermediary to probe (14 bytes).
pub const PING_REQ_PAYLOAD_LEN: usize = 14;

#[derive(Debug, Clone)]
pub struct PingReqPayload {
    pub target_id: u64,
    pub target_addr: SocketAddrV4,
}

impl PingReqPayload {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.target_id.to_be_bytes());
        let ip: u32 = (*self.target_addr.ip()).into();
        buf.extend_from_slice(&ip.to_be_bytes());
        buf.extend_from_slice(&self.target_addr.port().to_be_bytes());
    }

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < PING_REQ_PAYLOAD_LEN {
            return None;
        }
        let target_id = u64::from_be_bytes(buf[0..8].try_into().ok()?);
        let ip = u32::from_be_bytes(buf[8..12].try_into().ok()?);
        let port = u16::from_be_bytes(buf[12..14].try_into().ok()?);
        Some(Self {
            target_id,
            target_addr: SocketAddrV4::new(Ipv4Addr::from(ip), port),
        })
    }
}

// ── Message payload ───────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub enum MessagePayload {
    Gossip(Vec<WireNodeEntry>),
    /// Direct probe.  Carries piggybacked membership entries (may be empty).
    Ping(Vec<WireNodeEntry>),
    PingReq(PingReqPayload),
    /// Probe acknowledgement.  Carries piggybacked membership entries (may be empty).
    Ack(Vec<WireNodeEntry>),
}

/// Parse a payload buffer into a vector of `WireNodeEntry`.
/// Returns `Err` if the buffer length is not a multiple of `NODE_ENTRY_LEN`.
fn parse_node_entries(buf: &[u8]) -> Result<Vec<WireNodeEntry>, MessageError> {
    if buf.len() % NODE_ENTRY_LEN != 0 {
        return Err(MessageError::MalformedPayload);
    }
    let mut entries = Vec::with_capacity(buf.len() / NODE_ENTRY_LEN);
    let mut off = 0;
    while off + NODE_ENTRY_LEN <= buf.len() {
        let entry =
            WireNodeEntry::decode(&buf[off..]).ok_or(MessageError::MalformedPayload)?;
        entries.push(entry);
        off += NODE_ENTRY_LEN;
    }
    Ok(entries)
}

/// Encode a slice of `WireNodeEntry` into a byte vector.
fn encode_node_entries(entries: &[WireNodeEntry], buf: &mut Vec<u8>) {
    for e in entries {
        e.encode_into(buf);
    }
}

// ── Full message ──────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct Message {
    pub kind: u8,
    pub sender_id: u64,
    pub sender_heartbeat: u32,
    pub flags: u8,
    pub payload: MessagePayload,
}

// ── Errors ────────────────────────────────────────────────────────────────────
#[derive(Debug)]
pub enum MessageError {
    BufferTooShort,
    LengthMismatch,
    ChecksumFailed,
    UnknownKind(u8),
    MalformedPayload,
    PayloadTooLarge,
}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooShort => write!(f, "buffer too short"),
            Self::LengthMismatch => write!(f, "payload length mismatch"),
            Self::ChecksumFailed => write!(f, "checksum verification failed"),
            Self::UnknownKind(k) => write!(f, "unknown message kind 0x{k:02x}"),
            Self::MalformedPayload => write!(f, "malformed payload"),
            Self::PayloadTooLarge => write!(f, "payload too large for UDP MTU"),
        }
    }
}

impl std::error::Error for MessageError {}

// ── RFC 1071 checksum (same algorithm as tcp-over-udp's packet.rs) ────────────
pub fn internet_checksum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        sum += u32::from(u16::from_be_bytes([buf[i], buf[i + 1]]));
        i += 2;
    }
    if i < buf.len() {
        sum += u32::from(buf[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ── Encode / Decode ───────────────────────────────────────────────────────────
impl Message {
    /// Encode into a wire buffer.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        // Build payload bytes first so we know the length.
        let mut payload_bytes: Vec<u8> = Vec::new();
        match &self.payload {
            MessagePayload::Gossip(entries) | MessagePayload::Ping(entries) | MessagePayload::Ack(entries) => {
                encode_node_entries(entries, &mut payload_bytes);
            }
            MessagePayload::PingReq(p) => {
                p.encode_into(&mut payload_bytes);
            }
        }

        let payload_len = payload_bytes.len();
        if payload_len > 1400 {
            return Err(MessageError::PayloadTooLarge);
        }

        let total = HEADER_LEN + payload_len;
        let mut buf = vec![0u8; total];

        // Header fields.
        buf[OFF_KIND] = self.kind;
        buf[OFF_PLEN..OFF_PLEN + 2].copy_from_slice(&(payload_len as u16).to_be_bytes());
        buf[OFF_SENDER_ID..OFF_SENDER_ID + 8].copy_from_slice(&self.sender_id.to_be_bytes());
        buf[OFF_HEARTBEAT..OFF_HEARTBEAT + 4]
            .copy_from_slice(&self.sender_heartbeat.to_be_bytes());
        buf[OFF_FLAGS] = self.flags;
        // Checksum field stays zero for computation.
        buf[HEADER_LEN..].copy_from_slice(&payload_bytes);

        let cksum = internet_checksum(&buf);
        buf[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&cksum.to_be_bytes());

        Ok(buf)
    }

    /// Decode from a wire buffer, verifying the checksum.
    pub fn decode(buf: &[u8]) -> Result<Self, MessageError> {
        if buf.len() < HEADER_LEN {
            return Err(MessageError::BufferTooShort);
        }

        let payload_len =
            u16::from_be_bytes(buf[OFF_PLEN..OFF_PLEN + 2].try_into().unwrap()) as usize;

        if buf.len() != HEADER_LEN + payload_len {
            return Err(MessageError::LengthMismatch);
        }

        // RFC 1071 verification: the one's complement sum of all 16-bit words
        // in a valid datagram — including the stored checksum field — must be
        // all-ones (0xFFFF).  Because `internet_checksum` returns the one's
        // complement of that sum, a valid buffer produces exactly 0x0000.
        // No zeroing of the checksum field is required.
        if internet_checksum(buf) != 0x0000 {
            return Err(MessageError::ChecksumFailed);
        }

        let msg_kind = buf[OFF_KIND];
        let sender_id =
            u64::from_be_bytes(buf[OFF_SENDER_ID..OFF_SENDER_ID + 8].try_into().unwrap());
        let sender_heartbeat =
            u32::from_be_bytes(buf[OFF_HEARTBEAT..OFF_HEARTBEAT + 4].try_into().unwrap());
        let flags = buf[OFF_FLAGS];

        let payload_buf = &buf[HEADER_LEN..];

        let payload = match msg_kind {
            kind::GOSSIP => {
                MessagePayload::Gossip(parse_node_entries(payload_buf)?)
            }
            kind::PING => {
                MessagePayload::Ping(parse_node_entries(payload_buf)?)
            }
            kind::PING_REQ => {
                if payload_len != PING_REQ_PAYLOAD_LEN {
                    return Err(MessageError::MalformedPayload);
                }
                let p =
                    PingReqPayload::decode(payload_buf).ok_or(MessageError::MalformedPayload)?;
                MessagePayload::PingReq(p)
            }
            kind::ACK => {
                MessagePayload::Ack(parse_node_entries(payload_buf)?)
            }
            other => return Err(MessageError::UnknownKind(other)),
        };

        Ok(Self {
            kind: msg_kind,
            sender_id,
            sender_heartbeat,
            flags,
            payload,
        })
    }
}

// ── Builder helpers ────────────────────────────────────────────────────────────
pub fn build_gossip(
    sender_id: u64,
    sender_heartbeat: u32,
    entries: Vec<WireNodeEntry>,
) -> Message {
    Message {
        kind: kind::GOSSIP,
        sender_id,
        sender_heartbeat,
        flags: 0,
        payload: MessagePayload::Gossip(entries),
    }
}

pub fn build_ping(
    sender_id: u64,
    sender_heartbeat: u32,
    entries: Vec<WireNodeEntry>,
) -> Message {
    Message {
        kind: kind::PING,
        sender_id,
        sender_heartbeat,
        flags: 0,
        payload: MessagePayload::Ping(entries),
    }
}

pub fn build_ping_req(
    sender_id: u64,
    sender_heartbeat: u32,
    target_id: u64,
    target_addr: SocketAddrV4,
) -> Message {
    Message {
        kind: kind::PING_REQ,
        sender_id,
        sender_heartbeat,
        flags: 0,
        payload: MessagePayload::PingReq(PingReqPayload {
            target_id,
            target_addr,
        }),
    }
}

pub fn build_ack(
    sender_id: u64,
    sender_heartbeat: u32,
    entries: Vec<WireNodeEntry>,
) -> Message {
    Message {
        kind: kind::ACK,
        sender_id,
        sender_heartbeat,
        flags: 0,
        payload: MessagePayload::Ack(entries),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn roundtrip_gossip_empty() {
        let msg = build_gossip(42, 7, vec![]);
        let buf = msg.encode().unwrap();
        let decoded = Message::decode(&buf).unwrap();
        assert_eq!(decoded.sender_id, 42);
        assert_eq!(decoded.sender_heartbeat, 7);
        assert!(matches!(decoded.payload, MessagePayload::Gossip(e) if e.is_empty()));
    }

    #[test]
    fn roundtrip_gossip_with_entries() {
        let entry = WireNodeEntry {
            node_id: 999,
            heartbeat: 5,
            incarnation: 0,
            status: status::ALIVE,
            ip: u32::from(Ipv4Addr::new(127, 0, 0, 1)),
            port: 8080,
        };
        let msg = build_gossip(1, 2, vec![entry.clone()]);
        let buf = msg.encode().unwrap();
        let decoded = Message::decode(&buf).unwrap();
        match decoded.payload {
            MessagePayload::Gossip(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0], entry);
            }
            _ => panic!("wrong payload kind"),
        }
    }

    #[test]
    fn roundtrip_ping() {
        let msg = build_ping(1, 3, vec![]);
        let buf = msg.encode().unwrap();
        let decoded = Message::decode(&buf).unwrap();
        assert!(matches!(decoded.payload, MessagePayload::Ping(ref e) if e.is_empty()));
        assert_eq!(decoded.sender_id, 1);
    }

    #[test]
    fn roundtrip_ping_with_piggyback() {
        let entry = WireNodeEntry {
            node_id: 55,
            heartbeat: 3,
            incarnation: 1,
            status: status::SUSPECT,
            ip: u32::from(Ipv4Addr::new(10, 0, 0, 1)),
            port: 7000,
        };
        let msg = build_ping(1, 3, vec![entry.clone()]);
        let buf = msg.encode().unwrap();
        let decoded = Message::decode(&buf).unwrap();
        match decoded.payload {
            MessagePayload::Ping(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0], entry);
            }
            _ => panic!("wrong payload kind"),
        }
    }

    #[test]
    fn roundtrip_ping_req() {
        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9000);
        let msg = build_ping_req(1, 2, 77, addr);
        let buf = msg.encode().unwrap();
        let decoded = Message::decode(&buf).unwrap();
        match decoded.payload {
            MessagePayload::PingReq(p) => {
                assert_eq!(p.target_id, 77);
                assert_eq!(p.target_addr, addr);
            }
            _ => panic!("wrong payload kind"),
        }
    }

    #[test]
    fn roundtrip_ack() {
        let msg = build_ack(5, 10, vec![]);
        let buf = msg.encode().unwrap();
        let decoded = Message::decode(&buf).unwrap();
        assert!(matches!(decoded.payload, MessagePayload::Ack(ref e) if e.is_empty()));
    }

    #[test]
    fn roundtrip_ack_with_piggyback() {
        let entry = WireNodeEntry {
            node_id: 88,
            heartbeat: 12,
            incarnation: 2,
            status: status::DEAD,
            ip: u32::from(Ipv4Addr::new(192, 168, 1, 1)),
            port: 5000,
        };
        let msg = build_ack(5, 10, vec![entry.clone()]);
        let buf = msg.encode().unwrap();
        let decoded = Message::decode(&buf).unwrap();
        match decoded.payload {
            MessagePayload::Ack(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0], entry);
            }
            _ => panic!("wrong payload kind"),
        }
    }

    #[test]
    fn checksum_catches_corruption() {
        let msg = build_ping(1, 1, vec![]);
        let mut buf = msg.encode().unwrap();
        // Flip a bit in the sender ID field.
        buf[OFF_SENDER_ID] ^= 0xFF;
        let result = Message::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn buffer_too_short() {
        let result = Message::decode(&[0u8; 5]);
        assert!(matches!(result, Err(MessageError::BufferTooShort)));
    }

    #[test]
    fn unknown_kind() {
        let mut msg = build_ping(1, 1, vec![]);
        msg.kind = 0xFF;
        let mut buf = msg.encode().unwrap();
        // Fix the checksum after changing kind in buf.
        buf[OFF_KIND] = 0xFF;
        buf[OFF_CHECKSUM] = 0;
        buf[OFF_CHECKSUM + 1] = 0;
        let cksum = internet_checksum(&buf);
        buf[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&cksum.to_be_bytes());
        let result = Message::decode(&buf);
        assert!(matches!(result, Err(MessageError::UnknownKind(0xFF))));
    }

    // ── Checksum-specific tests ───────────────────────────────────────────────

    /// A correctly encoded packet must always be accepted.
    #[test]
    fn checksum_valid_packet_accepted() {
        for msg in [
            build_ping(1, 0, vec![]),
            build_ping(u64::MAX, u32::MAX, vec![]),
            build_ack(42, 100, vec![]),
            build_gossip(7, 3, vec![WireNodeEntry {
                node_id: 1,
                heartbeat: 0,
                incarnation: 0,
                status: status::ALIVE,
                ip: u32::from(Ipv4Addr::new(127, 0, 0, 1)),
                port: 9000,
            }]),
        ] {
            let buf = msg.encode().unwrap();
            assert!(
                Message::decode(&buf).is_ok(),
                "valid encoded packet must be accepted"
            );
        }
    }

    /// Every single-byte corruption must be detected.
    #[test]
    fn checksum_single_byte_corruption_rejected() {
        let buf = build_ping(0xDEADBEEF_CAFEBABE, 42, vec![])
            .encode()
            .unwrap();
        // Flip each byte individually; every flip must cause a decode failure.
        for i in 0..buf.len() {
            // Flipping the checksum field itself is a special case: the stored
            // value is wrong, so the full-buffer sum will no longer be 0x0000.
            let mut corrupted = buf.clone();
            corrupted[i] ^= 0xFF;
            assert!(
                Message::decode(&corrupted).is_err(),
                "corruption at byte {i} must be rejected"
            );
        }
    }

    /// A packet with a zero stored checksum is only valid if the data happens
    /// to sum to 0xFFFF (i.e. the correct checksum really is 0x0000).
    /// A zero checksum on arbitrary data must be rejected.
    #[test]
    fn checksum_zero_stored_value_rejected_when_data_nonzero() {
        let msg = build_ping(1, 1, vec![]);
        let mut buf = msg.encode().unwrap();
        // Overwrite the stored checksum with 0x0000.
        buf[OFF_CHECKSUM] = 0x00;
        buf[OFF_CHECKSUM + 1] = 0x00;
        // The data is non-trivial, so the full-buffer sum won't be 0x0000.
        assert!(
            Message::decode(&buf).is_err(),
            "zero checksum on non-zero data must be rejected"
        );
    }

    /// Edge case: sender_id = 0, heartbeat = 0 (all-zero fields).
    /// encode() must produce a non-trivial checksum and decode() must accept it.
    #[test]
    fn checksum_all_zero_fields_roundtrip() {
        let msg = build_ping(0, 0, vec![]);
        let buf = msg.encode().unwrap();
        // Checksum must be non-zero (kind byte = PING = 0x02, so data ≠ 0).
        let stored =
            u16::from_be_bytes(buf[OFF_CHECKSUM..OFF_CHECKSUM + 2].try_into().unwrap());
        assert_ne!(stored, 0, "checksum of a non-zero buffer must not be 0");
        assert!(Message::decode(&buf).is_ok());
    }

    #[test]
    fn multiple_gossip_entries_roundtrip() {
        let entries: Vec<WireNodeEntry> = (0..10)
            .map(|i| WireNodeEntry {
                node_id: i,
                heartbeat: i as u32 * 3,
                incarnation: i as u32,
                status: (i % 3) as u8,
                ip: u32::from(Ipv4Addr::new(192, 168, 1, i as u8)),
                port: 9000 + i as u16,
            })
            .collect();
        let msg = build_gossip(7, 42, entries.clone());
        let buf = msg.encode().unwrap();
        assert_eq!(buf.len(), HEADER_LEN + 10 * NODE_ENTRY_LEN);
        let decoded = Message::decode(&buf).unwrap();
        match decoded.payload {
            MessagePayload::Gossip(got) => assert_eq!(got, entries),
            _ => panic!("wrong payload"),
        }
    }
}
