/// Wire format for gossip messages.
///
/// Fixed 24-byte header followed by a variable-length payload.
///
/// Header layout (big-endian):
/// ```text
///  Byte  0       : version      (u8)   — protocol version (currently 1)
///  Byte  1       : kind         (u8)   — GOSSIP / PING / PING_REQ / ACK / LEAVE
///  Bytes 2-3     : payload_len  (u16)  — number of bytes after the header
///  Bytes 4-11    : sender_id    (u64)  — originating node identity
///  Bytes 12-15   : heartbeat    (u32)  — sender's current heartbeat counter
///  Bytes 16-19   : incarnation  (u32)  — sender's current incarnation number
///  Byte  20      : flags        (u8)   — bit-0 = REQUEST_ACK
///  Byte  21      : reserved     (u8)   — must be 0 (keeps header 16-bit aligned)
///  Bytes 22-23   : checksum     (u16)  — RFC 1071 over entire buffer (zeroed for calc)
/// ```
///
/// All multi-byte integers are big-endian (network byte order).
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// ── Protocol version ─────────────────────────────────────────────────────────
/// Current wire format version. Incremented when the header layout or
/// payload encoding changes in a backwards-incompatible way.
pub const VERSION: u8 = 1;

// ── Header byte offsets ──────────────────────────────────────────────────────
pub const OFF_VERSION: usize = 0;
pub const OFF_KIND: usize = 1;
pub const OFF_PLEN: usize = 2; // 2 bytes
pub const OFF_SENDER_ID: usize = 4; // 8 bytes
pub const OFF_HEARTBEAT: usize = 12; // 4 bytes
pub const OFF_INCARNATION: usize = 16; // 4 bytes
pub const OFF_FLAGS: usize = 20;
pub const OFF_RESERVED: usize = 21; // reserved for future use, keeps header even
pub const OFF_CHECKSUM: usize = 22; // 2 bytes
pub const HEADER_LEN: usize = 24;

// ── Message kinds ────────────────────────────────────────────────────────────
pub mod kind {
    pub const GOSSIP: u8 = 0x01;
    pub const PING: u8 = 0x02;
    pub const PING_REQ: u8 = 0x03;
    pub const ACK: u8 = 0x04;
    pub const LEAVE: u8 = 0x05;
    pub const ANTI_ENTROPY: u8 = 0x06;
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

// ── Address family tags ──────────────────────────────────────────────────────
pub mod addr_family {
    pub const V4: u8 = 4;
    pub const V6: u8 = 6;
}

// ── Wire-level node entry ────────────────────────────────────────────────────
/// One membership record on the wire (variable length: 24 bytes for IPv4,
/// 36 bytes for IPv6).
///
/// ```text
///  Bytes  0-7  : node_id      (u64)
///  Bytes  8-11 : heartbeat    (u32)
///  Bytes 12-15 : incarnation  (u32) — SWIM incarnation number
///  Byte   16   : status       (u8)  — 0=Alive, 1=Suspect, 2=Dead
///  Byte   17   : addr_family  (u8)  — 4=IPv4, 6=IPv6
///  Bytes 18+   : addr bytes
///    IPv4: 4 bytes IP + 2 bytes port  = 6 bytes  → total 24
///    IPv6: 16 bytes IP + 2 bytes port = 18 bytes → total 36
/// ```

/// Fixed prefix before the address family tag.
const NODE_ENTRY_PREFIX: usize = 18;
/// Total wire length of an IPv4 node entry.
pub const NODE_ENTRY_V4_LEN: usize = 24;
/// Total wire length of an IPv6 node entry.
pub const NODE_ENTRY_V6_LEN: usize = 36;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireNodeEntry {
    pub node_id: u64,
    pub heartbeat: u32,
    pub incarnation: u32,
    pub status: u8,
    pub addr: SocketAddr,
}

impl WireNodeEntry {
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.node_id.to_be_bytes());
        buf.extend_from_slice(&self.heartbeat.to_be_bytes());
        buf.extend_from_slice(&self.incarnation.to_be_bytes());
        buf.push(self.status);
        encode_addr(&self.addr, buf);
    }

    /// Decode from the start of `buf`. Returns the entry and number of bytes
    /// consumed, or `None` if the buffer is too short or the address family
    /// is unrecognised.
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < NODE_ENTRY_PREFIX {
            return None;
        }
        let node_id = u64::from_be_bytes(buf[0..8].try_into().ok()?);
        let heartbeat = u32::from_be_bytes(buf[8..12].try_into().ok()?);
        let incarnation = u32::from_be_bytes(buf[12..16].try_into().ok()?);
        let status_byte = buf[16];
        let af = buf[17];
        let (addr, total) = match af {
            addr_family::V4 => {
                if buf.len() < NODE_ENTRY_V4_LEN {
                    return None;
                }
                let ip = Ipv4Addr::new(buf[18], buf[19], buf[20], buf[21]);
                let port = u16::from_be_bytes(buf[22..24].try_into().ok()?);
                (SocketAddr::new(IpAddr::V4(ip), port), NODE_ENTRY_V4_LEN)
            }
            addr_family::V6 => {
                if buf.len() < NODE_ENTRY_V6_LEN {
                    return None;
                }
                let octets: [u8; 16] = buf[18..34].try_into().ok()?;
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes(buf[34..36].try_into().ok()?);
                (SocketAddr::new(IpAddr::V6(ip), port), NODE_ENTRY_V6_LEN)
            }
            _ => return None,
        };
        Some((
            Self {
                node_id,
                heartbeat,
                incarnation,
                status: status_byte,
                addr,
            },
            total,
        ))
    }

    /// Wire length of this entry (depends on address family).
    pub fn wire_len(&self) -> usize {
        match self.addr {
            SocketAddr::V4(_) => NODE_ENTRY_V4_LEN,
            SocketAddr::V6(_) => NODE_ENTRY_V6_LEN,
        }
    }
}

// ── PING_REQ payload ─────────────────────────────────────────────────────────
/// Carries the target node ID + target socket address.
///
/// ```text
///  Bytes 0-7  : target_id    (u64)
///  Byte  8    : addr_family  (u8)
///  Bytes 9+   : addr bytes   (IPv4: 6 bytes → total 15, IPv6: 18 bytes → total 27)
/// ```

#[derive(Debug, Clone)]
pub struct PingReqPayload {
    pub target_id: u64,
    pub target_addr: SocketAddr,
}

impl PingReqPayload {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.target_id.to_be_bytes());
        encode_addr(&self.target_addr, buf);
    }

    fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 9 {
            return None;
        }
        let target_id = u64::from_be_bytes(buf[0..8].try_into().ok()?);
        let (addr, addr_len) = decode_addr(&buf[8..])?;
        Some((
            Self { target_id, target_addr: addr },
            8 + addr_len,
        ))
    }
}

// ── Address encode / decode helpers ─────────────────────────────────────────
fn encode_addr(addr: &SocketAddr, buf: &mut Vec<u8>) {
    match addr {
        SocketAddr::V4(a) => {
            buf.push(addr_family::V4);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            buf.push(addr_family::V6);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
    }
}

/// Decode an address from `buf`. Returns `(SocketAddr, bytes_consumed)`.
fn decode_addr(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    if buf.is_empty() {
        return None;
    }
    match buf[0] {
        addr_family::V4 => {
            if buf.len() < 7 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes(buf[5..7].try_into().ok()?);
            Some((SocketAddr::new(IpAddr::V4(ip), port), 7))
        }
        addr_family::V6 => {
            if buf.len() < 19 {
                return None;
            }
            let octets: [u8; 16] = buf[1..17].try_into().ok()?;
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes(buf[17..19].try_into().ok()?);
            Some((SocketAddr::new(IpAddr::V6(ip), port), 19))
        }
        _ => None,
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
    /// Graceful leave notification.  No payload — the header's sender_id
    /// identifies the departing node.  Receivers immediately mark the node
    /// as Dead, bypassing the Suspect phase.
    Leave,
    /// Anti-entropy chunk: one fragment of a full membership table sync.
    AntiEntropyChunk(AntiEntropyChunkPayload),
}

/// One chunk of a multi-part anti-entropy full table sync.
///
/// ```text
///  Bytes 0-7   : table_version  (u64)  — monotonic snapshot id
///  Bytes 8-9   : chunk_index    (u16)  — 0-based index of this chunk
///  Bytes 10-11 : total_chunks   (u16)  — how many chunks make up the full table
///  Bytes 12+   : entries        (variable) — WireNodeEntry sequence
/// ```
#[derive(Debug, Clone)]
pub struct AntiEntropyChunkPayload {
    pub table_version: u64,
    pub chunk_index: u16,
    pub total_chunks: u16,
    pub entries: Vec<WireNodeEntry>,
}

pub const AE_CHUNK_HEADER: usize = 12; // 8 + 2 + 2

impl AntiEntropyChunkPayload {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.table_version.to_be_bytes());
        buf.extend_from_slice(&self.chunk_index.to_be_bytes());
        buf.extend_from_slice(&self.total_chunks.to_be_bytes());
        encode_node_entries(&self.entries, buf);
    }

    fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < AE_CHUNK_HEADER {
            return None;
        }
        let table_version = u64::from_be_bytes(buf[0..8].try_into().ok()?);
        let chunk_index = u16::from_be_bytes(buf[8..10].try_into().ok()?);
        let total_chunks = u16::from_be_bytes(buf[10..12].try_into().ok()?);
        let entries = parse_node_entries(&buf[AE_CHUNK_HEADER..]).ok()?;
        Some((
            Self { table_version, chunk_index, total_chunks, entries },
            buf.len(),
        ))
    }
}

/// Parse a payload buffer into a vector of `WireNodeEntry`.
/// Entries are variable-length (IPv4 vs IPv6), so we consume one at a time.
fn parse_node_entries(buf: &[u8]) -> Result<Vec<WireNodeEntry>, MessageError> {
    let mut entries = Vec::new();
    let mut off = 0;
    while off < buf.len() {
        let (entry, consumed) =
            WireNodeEntry::decode(&buf[off..]).ok_or(MessageError::MalformedPayload)?;
        entries.push(entry);
        off += consumed;
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
    pub version: u8,
    pub kind: u8,
    pub sender_id: u64,
    pub sender_heartbeat: u32,
    pub sender_incarnation: u32,
    pub flags: u8,
    pub payload: MessagePayload,
}

impl Message {
    /// Set the REQUEST_ACK flag so the receiver responds with an ACK.
    pub fn with_request_ack(mut self) -> Self {
        self.flags |= flags::REQUEST_ACK;
        self
    }

    /// Returns `true` if the REQUEST_ACK flag is set.
    pub fn requests_ack(&self) -> bool {
        self.flags & flags::REQUEST_ACK != 0
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────
#[derive(Debug)]
pub enum MessageError {
    BufferTooShort,
    LengthMismatch,
    ChecksumFailed,
    UnknownKind(u8),
    UnsupportedVersion(u8),
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
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version {v}"),
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
            MessagePayload::Leave => {
                // No payload body — header is sufficient.
            }
            MessagePayload::AntiEntropyChunk(c) => {
                c.encode_into(&mut payload_bytes);
            }
        }

        let payload_len = payload_bytes.len();
        if payload_len > 1400 {
            return Err(MessageError::PayloadTooLarge);
        }

        let total = HEADER_LEN + payload_len;
        let mut buf = vec![0u8; total];

        // Header fields.
        buf[OFF_VERSION] = self.version;
        buf[OFF_KIND] = self.kind;
        buf[OFF_PLEN..OFF_PLEN + 2].copy_from_slice(&(payload_len as u16).to_be_bytes());
        buf[OFF_SENDER_ID..OFF_SENDER_ID + 8].copy_from_slice(&self.sender_id.to_be_bytes());
        buf[OFF_HEARTBEAT..OFF_HEARTBEAT + 4]
            .copy_from_slice(&self.sender_heartbeat.to_be_bytes());
        buf[OFF_INCARNATION..OFF_INCARNATION + 4]
            .copy_from_slice(&self.sender_incarnation.to_be_bytes());
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

        // ── Version check ─────────────────────────────────────────────────
        // The version byte is read before the checksum so that we can
        // produce a specific error for unsupported versions.  Future
        // versions may change the header layout, so we gate on the
        // version before interpreting any other field.
        let wire_version = buf[OFF_VERSION];
        match wire_version {
            VERSION => { /* current version — proceed */ }
            v => {
                log::debug!(
                    "[message] rejecting message with unsupported version {v} (expected {VERSION})"
                );
                return Err(MessageError::UnsupportedVersion(v));
            }
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
        let sender_incarnation =
            u32::from_be_bytes(buf[OFF_INCARNATION..OFF_INCARNATION + 4].try_into().unwrap());
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
                let (p, consumed) =
                    PingReqPayload::decode(payload_buf).ok_or(MessageError::MalformedPayload)?;
                if consumed != payload_len {
                    return Err(MessageError::MalformedPayload);
                }
                MessagePayload::PingReq(p)
            }
            kind::ACK => {
                MessagePayload::Ack(parse_node_entries(payload_buf)?)
            }
            kind::LEAVE => {
                MessagePayload::Leave
            }
            kind::ANTI_ENTROPY => {
                let (c, consumed) = AntiEntropyChunkPayload::decode(payload_buf)
                    .ok_or(MessageError::MalformedPayload)?;
                if consumed != payload_len {
                    return Err(MessageError::MalformedPayload);
                }
                MessagePayload::AntiEntropyChunk(c)
            }
            other => return Err(MessageError::UnknownKind(other)),
        };

        Ok(Self {
            version: wire_version,
            kind: msg_kind,
            sender_id,
            sender_heartbeat,
            sender_incarnation,
            flags,
            payload,
        })
    }
}

// ── Builder helpers ────────────────────────────────────────────────────────────
pub fn build_gossip(
    sender_id: u64,
    sender_heartbeat: u32,
    sender_incarnation: u32,
    entries: Vec<WireNodeEntry>,
) -> Message {
    Message {
        version: VERSION,
        kind: kind::GOSSIP,
        sender_id,
        sender_heartbeat,
        sender_incarnation,
        flags: 0,
        payload: MessagePayload::Gossip(entries),
    }
}

pub fn build_ping(
    sender_id: u64,
    sender_heartbeat: u32,
    sender_incarnation: u32,
    entries: Vec<WireNodeEntry>,
) -> Message {
    Message {
        version: VERSION,
        kind: kind::PING,
        sender_id,
        sender_heartbeat,
        sender_incarnation,
        flags: 0,
        payload: MessagePayload::Ping(entries),
    }
}

pub fn build_ping_req(
    sender_id: u64,
    sender_heartbeat: u32,
    sender_incarnation: u32,
    target_id: u64,
    target_addr: SocketAddr,
) -> Message {
    Message {
        version: VERSION,
        kind: kind::PING_REQ,
        sender_id,
        sender_heartbeat,
        sender_incarnation,
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
    sender_incarnation: u32,
    entries: Vec<WireNodeEntry>,
) -> Message {
    Message {
        version: VERSION,
        kind: kind::ACK,
        sender_id,
        sender_heartbeat,
        sender_incarnation,
        flags: 0,
        payload: MessagePayload::Ack(entries),
    }
}

pub fn build_anti_entropy_chunk(
    sender_id: u64,
    sender_heartbeat: u32,
    sender_incarnation: u32,
    table_version: u64,
    chunk_index: u16,
    total_chunks: u16,
    entries: Vec<WireNodeEntry>,
) -> Message {
    Message {
        version: VERSION,
        kind: kind::ANTI_ENTROPY,
        sender_id,
        sender_heartbeat,
        sender_incarnation,
        flags: 0,
        payload: MessagePayload::AntiEntropyChunk(AntiEntropyChunkPayload {
            table_version,
            chunk_index,
            total_chunks,
            entries,
        }),
    }
}

pub fn build_leave(
    sender_id: u64,
    sender_heartbeat: u32,
    sender_incarnation: u32,
) -> Message {
    Message {
        version: VERSION,
        kind: kind::LEAVE,
        sender_id,
        sender_heartbeat,
        sender_incarnation,
        flags: 0,
        payload: MessagePayload::Leave,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn v4(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port)
    }

    fn v6(ip: [u8; 16], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
    }

    #[test]
    fn roundtrip_gossip_empty() {
        let msg = build_gossip(42, 7, 0, vec![]);
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
            addr: v4([127, 0, 0, 1], 8080),
        };
        let msg = build_gossip(1, 2, 0, vec![entry.clone()]);
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
    fn roundtrip_gossip_ipv6_entry() {
        let entry = WireNodeEntry {
            node_id: 42,
            heartbeat: 10,
            incarnation: 1,
            status: status::ALIVE,
            addr: v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 7000),
        };
        let msg = build_gossip(1, 2, 0, vec![entry.clone()]);
        let buf = msg.encode().unwrap();
        assert_eq!(buf.len(), HEADER_LEN + NODE_ENTRY_V6_LEN);
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
    fn roundtrip_mixed_v4_v6_entries() {
        let v4_entry = WireNodeEntry {
            node_id: 1,
            heartbeat: 5,
            incarnation: 0,
            status: status::ALIVE,
            addr: v4([10, 0, 0, 1], 8000),
        };
        let v6_entry = WireNodeEntry {
            node_id: 2,
            heartbeat: 3,
            incarnation: 0,
            status: status::SUSPECT,
            addr: v6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 9000),
        };
        let entries = vec![v4_entry.clone(), v6_entry.clone()];
        let msg = build_gossip(7, 42, 0, entries.clone());
        let buf = msg.encode().unwrap();
        assert_eq!(buf.len(), HEADER_LEN + NODE_ENTRY_V4_LEN + NODE_ENTRY_V6_LEN);
        let decoded = Message::decode(&buf).unwrap();
        match decoded.payload {
            MessagePayload::Gossip(got) => assert_eq!(got, entries),
            _ => panic!("wrong payload"),
        }
    }

    #[test]
    fn roundtrip_ping() {
        let msg = build_ping(1, 3, 0, vec![]);
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
            addr: v4([10, 0, 0, 1], 7000),
        };
        let msg = build_ping(1, 3, 0, vec![entry.clone()]);
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
    fn roundtrip_ping_req_v4() {
        let addr = v4([10, 0, 0, 1], 9000);
        let msg = build_ping_req(1, 2, 0, 77, addr);
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
    fn roundtrip_ping_req_v6() {
        let addr = v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 8000);
        let msg = build_ping_req(1, 2, 0, 88, addr);
        let buf = msg.encode().unwrap();
        let decoded = Message::decode(&buf).unwrap();
        match decoded.payload {
            MessagePayload::PingReq(p) => {
                assert_eq!(p.target_id, 88);
                assert_eq!(p.target_addr, addr);
            }
            _ => panic!("wrong payload kind"),
        }
    }

    #[test]
    fn roundtrip_ack() {
        let msg = build_ack(5, 10, 0, vec![]);
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
            addr: v4([192, 168, 1, 1], 5000),
        };
        let msg = build_ack(5, 10, 0, vec![entry.clone()]);
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
        let msg = build_ping(1, 1, 0, vec![]);
        let mut buf = msg.encode().unwrap();
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
        let mut msg = build_ping(1, 1, 0, vec![]);
        msg.kind = 0xFF;
        let mut buf = msg.encode().unwrap();
        // Patch the kind byte and recompute checksum.
        buf[OFF_KIND] = 0xFF;
        buf[OFF_CHECKSUM] = 0;
        buf[OFF_CHECKSUM + 1] = 0;
        let cksum = internet_checksum(&buf);
        buf[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&cksum.to_be_bytes());
        let result = Message::decode(&buf);
        assert!(matches!(result, Err(MessageError::UnknownKind(0xFF))));
    }

    // ── Checksum-specific tests ───────────────────────────────────────────────

    #[test]
    fn checksum_valid_packet_accepted() {
        for msg in [
            build_ping(1, 0, 0, vec![]),
            build_ping(u64::MAX, u32::MAX, 0, vec![]),
            build_ack(42, 100, 0, vec![]),
            build_gossip(7, 3, 0, vec![WireNodeEntry {
                node_id: 1,
                heartbeat: 0,
                incarnation: 0,
                status: status::ALIVE,
                addr: v4([127, 0, 0, 1], 9000),
            }]),
        ] {
            let buf = msg.encode().unwrap();
            assert!(
                Message::decode(&buf).is_ok(),
                "valid encoded packet must be accepted"
            );
        }
    }

    #[test]
    fn checksum_single_byte_corruption_rejected() {
        let buf = build_ping(0xDEADBEEF_CAFEBABE, 42, 0, vec![])
            .encode()
            .unwrap();
        for i in 0..buf.len() {
            let mut corrupted = buf.clone();
            corrupted[i] ^= 0xFF;
            assert!(
                Message::decode(&corrupted).is_err(),
                "corruption at byte {i} must be rejected"
            );
        }
    }

    #[test]
    fn checksum_zero_stored_value_rejected_when_data_nonzero() {
        let msg = build_ping(1, 1, 0, vec![]);
        let mut buf = msg.encode().unwrap();
        buf[OFF_CHECKSUM] = 0x00;
        buf[OFF_CHECKSUM + 1] = 0x00;
        assert!(
            Message::decode(&buf).is_err(),
            "zero checksum on non-zero data must be rejected"
        );
    }

    #[test]
    fn checksum_all_zero_fields_roundtrip() {
        let msg = build_ping(0, 0, 0, vec![]);
        let buf = msg.encode().unwrap();
        let stored =
            u16::from_be_bytes(buf[OFF_CHECKSUM..OFF_CHECKSUM + 2].try_into().unwrap());
        assert_ne!(stored, 0, "checksum of a non-zero buffer must not be 0");
        assert!(Message::decode(&buf).is_ok());
    }

    #[test]
    fn roundtrip_leave() {
        let msg = build_leave(99, 42, 3);
        let buf = msg.encode().unwrap();
        assert_eq!(buf.len(), HEADER_LEN); // no payload
        let decoded = Message::decode(&buf).unwrap();
        assert_eq!(decoded.sender_id, 99);
        assert_eq!(decoded.sender_heartbeat, 42);
        assert_eq!(decoded.sender_incarnation, 3);
        assert!(matches!(decoded.payload, MessagePayload::Leave));
    }

    // ── Version tests ─────────────────────────────────────────────────────

    #[test]
    fn encode_preserves_version() {
        let msg = build_ping(1, 0, 0, vec![]);
        let buf = msg.encode().unwrap();
        assert_eq!(buf[OFF_VERSION], VERSION);
    }

    #[test]
    fn decode_correct_version_succeeds() {
        let msg = build_ping(42, 7, 0, vec![]);
        let buf = msg.encode().unwrap();
        let decoded = Message::decode(&buf).unwrap();
        assert_eq!(decoded.version, VERSION);
        assert_eq!(decoded.sender_id, 42);
    }

    #[test]
    fn decode_unsupported_version_rejected() {
        let msg = build_ping(1, 0, 0, vec![]);
        let mut buf = msg.encode().unwrap();
        // Patch version to a future value and recompute checksum.
        buf[OFF_VERSION] = 99;
        buf[OFF_CHECKSUM] = 0;
        buf[OFF_CHECKSUM + 1] = 0;
        let cksum = internet_checksum(&buf);
        buf[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&cksum.to_be_bytes());
        let result = Message::decode(&buf);
        assert!(
            matches!(result, Err(MessageError::UnsupportedVersion(99))),
            "future version must be rejected"
        );
    }

    #[test]
    fn decode_version_zero_rejected() {
        let msg = build_ping(1, 0, 0, vec![]);
        let mut buf = msg.encode().unwrap();
        buf[OFF_VERSION] = 0;
        buf[OFF_CHECKSUM] = 0;
        buf[OFF_CHECKSUM + 1] = 0;
        let cksum = internet_checksum(&buf);
        buf[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&cksum.to_be_bytes());
        let result = Message::decode(&buf);
        assert!(matches!(result, Err(MessageError::UnsupportedVersion(0))));
    }

    #[test]
    fn all_message_kinds_encode_with_version() {
        for msg in [
            build_gossip(1, 0, 0, vec![]),
            build_ping(1, 0, 0, vec![]),
            build_ping_req(1, 0, 0, 2, v4([127, 0, 0, 1], 9000)),
            build_ack(1, 0, 0, vec![]),
            build_leave(1, 0, 0),
        ] {
            let buf = msg.encode().unwrap();
            assert_eq!(buf[OFF_VERSION], VERSION, "kind={} must encode version", msg.kind);
            let decoded = Message::decode(&buf).unwrap();
            assert_eq!(decoded.version, VERSION);
        }
    }

    #[test]
    fn multiple_gossip_entries_roundtrip() {
        let entries: Vec<WireNodeEntry> = (0..10)
            .map(|i| WireNodeEntry {
                node_id: i,
                heartbeat: i as u32 * 3,
                incarnation: i as u32,
                status: (i % 3) as u8,
                addr: v4([192, 168, 1, i as u8], 9000 + i as u16),
            })
            .collect();
        let msg = build_gossip(7, 42, 0, entries.clone());
        let buf = msg.encode().unwrap();
        assert_eq!(buf.len(), HEADER_LEN + 10 * NODE_ENTRY_V4_LEN);
        let decoded = Message::decode(&buf).unwrap();
        match decoded.payload {
            MessagePayload::Gossip(got) => assert_eq!(got, entries),
            _ => panic!("wrong payload"),
        }
    }
}
