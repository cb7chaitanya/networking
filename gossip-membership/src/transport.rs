/// UDP transport layer.
///
/// A thin wrapper around `tokio::net::UdpSocket` that encodes/decodes
/// `Message` values.  When a `ClusterKey` is configured, all outgoing
/// datagrams are encrypted with ChaCha20-Poly1305 and incoming datagrams
/// are decrypted and authenticated before being returned.
///
/// Malformed, corrupted, or unauthenticated datagrams are silently
/// discarded (the call loops and waits for the next datagram), matching
/// the behaviour of `SimulatedSocket` in tcp-over-udp.
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;

use crate::compression::PeerCompressionMap;
use crate::crypto::{ClusterKey, CryptoError};
use crate::message::{flags, Message, MessageError};
use crate::rate_limit::{InboundRateLimiter, RateLimitConfig};
use crate::simulator::NetSim;

/// Practical UDP MTU ceiling — avoids fragmentation on most Ethernet paths.
const MAX_DATAGRAM: usize = 1_472;

// ── Errors ────────────────────────────────────────────────────────────────────
#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    Message(MessageError),
    Crypto(CryptoError),
    /// Cleartext sender_id (AAD) does not match the sender_id inside the
    /// decrypted message — possible replay or forgery attempt.
    AuthenticationFailed,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Message(e) => write!(f, "message: {e}"),
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::AuthenticationFailed => write!(f, "sender authentication failed"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ── Transport ─────────────────────────────────────────────────────────────────
pub struct Transport {
    pub local_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    key: Option<ClusterKey>,
    sim: Option<Arc<Mutex<NetSim>>>,
    rate_limiter: Option<Mutex<InboundRateLimiter>>,
    /// Count of packets dropped by rate limiting (caller reads this).
    pub rate_limited_count: std::sync::atomic::AtomicU64,
    /// Whether this node has compression enabled.
    compression_enabled: bool,
    /// Tracks which peers support compression (sent us compressed messages).
    peer_compression: PeerCompressionMap,
}

impl Transport {
    /// Bind a UDP socket to `addr` (plaintext mode — no encryption).
    pub async fn bind(addr: SocketAddr) -> Result<Self, TransportError> {
        Self::bind_with_compression(addr, false).await
    }

    /// Bind a UDP socket with explicit compression setting.
    pub async fn bind_with_compression(
        addr: SocketAddr,
        compression_enabled: bool,
    ) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        Ok(Self {
            local_addr,
            socket: Arc::new(socket),
            key: None,
            sim: None,
            rate_limiter: None,
            rate_limited_count: std::sync::atomic::AtomicU64::new(0),
            compression_enabled,
            peer_compression: PeerCompressionMap::new(),
        })
    }

    /// Attach a cluster key, enabling encryption on all subsequent I/O.
    pub fn with_key(mut self, key: ClusterKey) -> Self {
        self.key = Some(key);
        self
    }

    /// Attach a network simulator for testing under adverse conditions.
    pub fn with_sim(mut self, sim: Arc<Mutex<NetSim>>) -> Self {
        self.sim = Some(sim);
        self
    }

    /// Attach an inbound rate limiter.
    pub fn with_rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limiter = Some(Mutex::new(InboundRateLimiter::new(&config)));
        self
    }

    /// Clone the underlying socket handle (cheap — it's an `Arc`).
    pub fn clone_socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// Returns `true` if encryption is enabled.
    pub fn is_encrypted(&self) -> bool {
        self.key.is_some()
    }

    /// Whether compression is enabled on this transport.
    pub fn compression_enabled(&self) -> bool {
        self.compression_enabled
    }

    /// Access the peer compression capability map.
    pub fn peer_compression(&self) -> &PeerCompressionMap {
        &self.peer_compression
    }

    /// Mutable access to the peer compression capability map.
    pub fn peer_compression_mut(&mut self) -> &mut PeerCompressionMap {
        &mut self.peer_compression
    }

    /// Encode `msg` and transmit to `dest`.
    ///
    /// If compression is enabled and the peer is known to support it,
    /// the payload will be LZ4-compressed.  When a cluster key is configured
    /// the encoded bytes are then encrypted with ChaCha20-Poly1305.
    pub async fn send_to(&self, msg: &Message, dest: SocketAddr) -> Result<(), TransportError> {
        // Encode (with optional compression) first so we have wire bytes.
        let use_compression =
            self.compression_enabled && self.peer_compression.is_capable(&dest);
        let encoded = msg.encode_opts(use_compression).map_err(TransportError::Message)?;
        let wire_bytes = match &self.key {
            Some(key) => key
                .encrypt(&encoded, msg.sender_id)
                .map_err(TransportError::Crypto)?,
            None => encoded,
        };

        // Consult the network simulator (if any) before sending.
        // Extract decisions while holding the lock, then drop the guard
        // before any .await to keep the future Send.
        if let Some(sim) = &self.sim {
            let (deliver, delay, reorder, flush) = {
                let mut s = sim.lock().unwrap();
                let deliver = s.should_deliver(self.local_addr, dest);
                let delay = s.delay_ms();
                if !deliver {
                    (false, 0, false, None)
                } else if s.should_reorder() {
                    let released = s.stash(wire_bytes.clone(), dest);
                    (false, delay, true, released)
                } else {
                    let released = s.flush_one();
                    (true, delay, false, released)
                }
            };

            if !deliver && !reorder {
                return Ok(()); // dropped by loss/partition
            }

            if delay > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }

            if let Some((buf, dst)) = flush {
                self.socket.send_to(&buf, dst).await?;
            }

            if !reorder {
                self.socket.send_to(&wire_bytes, dest).await?;
            }
            return Ok(());
        }

        // No simulator — send directly.
        self.socket.send_to(&wire_bytes, dest).await?;
        Ok(())
    }

    /// Wait for the next well-formed (and, if encrypted, authenticated) datagram.
    ///
    /// Datagrams that fail decryption, checksum verification, or structural
    /// validation are silently dropped and the loop continues — gossip is
    /// best-effort.
    ///
    /// If a compressed message is received from a peer, that peer is marked
    /// as compression-capable for future sends.
    pub async fn recv_from(&mut self) -> Result<(Message, SocketAddr), TransportError> {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let (n, from) = self.socket.recv_from(&mut buf).await?;

            // Rate-limit check before spending CPU on decode.
            if let Some(rl) = &self.rate_limiter {
                if !rl.lock().unwrap().allow(from, std::time::Instant::now()) {
                    self.rate_limited_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    log::trace!("[transport] rate-limited datagram from {from}");
                    continue;
                }
            }

            // Peek at flags to track compression capability.
            if n >= crate::message::HEADER_LEN {
                let msg_flags = buf[crate::message::OFF_FLAGS];
                if (msg_flags & flags::COMPRESSED) != 0 {
                    self.peer_compression.mark_capable(from);
                }
            }

            match self.decode_datagram(&buf[..n]) {
                Ok(msg) => return Ok((msg, from)),
                Err(e) => {
                    log::debug!("[transport] dropped datagram from {from}: {e}");
                }
            }
        }
    }

    /// Decrypt (if needed) and decode a raw datagram.  Public for testing.
    pub fn decode_datagram(&self, raw: &[u8]) -> Result<Message, TransportError> {
        match &self.key {
            Some(key) => {
                let (plaintext, aad_sender_id) =
                    key.decrypt(raw).map_err(TransportError::Crypto)?;
                let msg = Message::decode(&plaintext).map_err(TransportError::Message)?;
                // Verify the AAD-authenticated sender_id matches the one
                // inside the decrypted message.  A mismatch means either a
                // bug or an attempted forgery.
                if msg.sender_id != aad_sender_id {
                    return Err(TransportError::AuthenticationFailed);
                }
                Ok(msg)
            }
            None => Message::decode(raw).map_err(TransportError::Message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::message::{build_ping, build_gossip, kind, WireNodeEntry,
                         status, HEADER_LEN, OFF_CHECKSUM, OFF_KIND, NODE_ENTRY_V4_LEN};

    fn localhost_any() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    /// Encode a valid PING message into raw bytes.
    fn valid_ping_bytes(sender_id: u64) -> Vec<u8> {
        build_ping(sender_id, 1, 0, vec![]).encode().unwrap()
    }

    // ── MTU / payload size tests ────────────────────────────────────────────

    #[test]
    fn max_datagram_constant_fits_ethernet() {
        // Ethernet MTU=1500, IP=20, UDP=8 → 1472 bytes max payload.
        assert_eq!(MAX_DATAGRAM, 1_472);
    }

    #[test]
    fn payload_too_large_returns_error() {
        // 60 IPv4 entries × 24 bytes = 1440 > 1400 payload limit.
        let entries: Vec<WireNodeEntry> = (0..60)
            .map(|i| WireNodeEntry {
                node_id: i,
                heartbeat: 0,
                incarnation: 0,
                status: status::ALIVE,
                addr: make_addr(9000 + i as u16),
            })
            .collect();
        assert!(60 * NODE_ENTRY_V4_LEN > 1400);
        let msg = build_gossip(1, 0, 0, entries);
        assert!(msg.encode().is_err());
    }

    // ── decode_datagram: plaintext mode ──────────────────────────────────────

    #[tokio::test]
    async fn decode_valid_plaintext() {
        let t = Transport::bind(localhost_any()).await.unwrap();
        let buf = valid_ping_bytes(42);
        let msg = t.decode_datagram(&buf).unwrap();
        assert_eq!(msg.sender_id, 42);
        assert_eq!(msg.kind, kind::PING);
    }

    #[tokio::test]
    async fn decode_empty_buffer_fails() {
        let t = Transport::bind(localhost_any()).await.unwrap();
        assert!(t.decode_datagram(&[]).is_err());
    }

    #[tokio::test]
    async fn decode_truncated_header_fails() {
        let t = Transport::bind(localhost_any()).await.unwrap();
        assert!(t.decode_datagram(&[0u8; HEADER_LEN - 1]).is_err());
    }

    #[tokio::test]
    async fn decode_corrupted_checksum_fails() {
        let t = Transport::bind(localhost_any()).await.unwrap();
        let mut buf = valid_ping_bytes(1);
        buf[5] ^= 0xFF;
        assert!(t.decode_datagram(&buf).is_err());
    }

    #[tokio::test]
    async fn decode_zeroed_checksum_fails() {
        let t = Transport::bind(localhost_any()).await.unwrap();
        let mut buf = valid_ping_bytes(1);
        buf[OFF_CHECKSUM] = 0;
        buf[OFF_CHECKSUM + 1] = 0;
        assert!(t.decode_datagram(&buf).is_err());
    }

    #[tokio::test]
    async fn decode_unknown_kind_fails() {
        let t = Transport::bind(localhost_any()).await.unwrap();
        let mut buf = valid_ping_bytes(1);
        buf[OFF_KIND] = 0xFF;
        // Recompute checksum so it passes verification, exposing the unknown-kind error.
        buf[OFF_CHECKSUM] = 0;
        buf[OFF_CHECKSUM + 1] = 0;
        let cksum = crate::message::internet_checksum(&buf);
        buf[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&cksum.to_be_bytes());
        assert!(t.decode_datagram(&buf).is_err());
    }

    #[tokio::test]
    async fn decode_random_garbage_fails() {
        let t = Transport::bind(localhost_any()).await.unwrap();
        let garbage: Vec<u8> = (0..100).map(|i| (i * 37 + 13) as u8).collect();
        assert!(t.decode_datagram(&garbage).is_err());
    }

    #[tokio::test]
    async fn decode_single_byte_corruption_all_positions() {
        let t = Transport::bind(localhost_any()).await.unwrap();
        let buf = valid_ping_bytes(0xDEAD_BEEF);
        for i in 0..buf.len() {
            let mut corrupted = buf.clone();
            corrupted[i] ^= 0xFF;
            assert!(
                t.decode_datagram(&corrupted).is_err(),
                "corruption at byte {i} should be rejected"
            );
        }
    }

    // ── decode_datagram: encrypted mode ──────────────────────────────────────

    #[tokio::test]
    async fn decode_encrypted_valid() {
        let key = ClusterKey::generate();
        let t = Transport::bind(localhost_any()).await.unwrap().with_key(key.clone());
        let msg = build_ping(42, 1, 0, vec![]);
        let encoded = msg.encode().unwrap();
        let ciphertext = key.encrypt(&encoded, 42).unwrap();
        let decoded = t.decode_datagram(&ciphertext).unwrap();
        assert_eq!(decoded.sender_id, 42);
    }

    #[tokio::test]
    async fn decode_encrypted_wrong_key_fails() {
        let key1 = ClusterKey::generate();
        let key2 = ClusterKey::generate();
        let t = Transport::bind(localhost_any()).await.unwrap().with_key(key1);
        let msg = build_ping(42, 1, 0, vec![]);
        let encoded = msg.encode().unwrap();
        let ciphertext = key2.encrypt(&encoded, 42).unwrap();
        assert!(t.decode_datagram(&ciphertext).is_err());
    }

    #[tokio::test]
    async fn decode_encrypted_sender_id_mismatch_fails() {
        let key = ClusterKey::generate();
        let t = Transport::bind(localhost_any()).await.unwrap().with_key(key.clone());
        // Encrypt with AAD sender_id=42 but message has sender_id=99.
        let msg = build_ping(99, 1, 0, vec![]);
        let encoded = msg.encode().unwrap();
        let ciphertext = key.encrypt(&encoded, 42).unwrap();
        let result = t.decode_datagram(&ciphertext);
        assert!(
            matches!(result, Err(TransportError::AuthenticationFailed)),
            "AAD sender_id mismatch must return AuthenticationFailed"
        );
    }

    #[tokio::test]
    async fn decode_plaintext_on_encrypted_transport_fails() {
        let key = ClusterKey::generate();
        let t = Transport::bind(localhost_any()).await.unwrap().with_key(key);
        let buf = valid_ping_bytes(1);
        assert!(t.decode_datagram(&buf).is_err());
    }

    #[tokio::test]
    async fn decode_encrypted_corrupted_ciphertext_fails() {
        let key = ClusterKey::generate();
        let t = Transport::bind(localhost_any()).await.unwrap().with_key(key.clone());
        let msg = build_ping(42, 1, 0, vec![]);
        let encoded = msg.encode().unwrap();
        let mut ciphertext = key.encrypt(&encoded, 42).unwrap();
        let mid = ciphertext.len() / 2;
        ciphertext[mid] ^= 0xFF;
        assert!(t.decode_datagram(&ciphertext).is_err());
    }

    // ── send_to / recv_from integration ──────────────────────────────────────

    #[tokio::test]
    async fn send_and_recv_plaintext_roundtrip() {
        let t1 = Transport::bind(localhost_any()).await.unwrap();
        let mut t2 = Transport::bind(localhost_any()).await.unwrap();
        let msg = build_ping(1, 42, 3, vec![]);
        t1.send_to(&msg, t2.local_addr).await.unwrap();

        let (received, from) = t2.recv_from().await.unwrap();
        assert_eq!(received.sender_id, 1);
        assert_eq!(received.sender_heartbeat, 42);
        assert_eq!(received.sender_incarnation, 3);
        assert_eq!(from, t1.local_addr);
    }

    #[tokio::test]
    async fn send_and_recv_encrypted_roundtrip() {
        let key = ClusterKey::generate();
        let t1 = Transport::bind(localhost_any()).await.unwrap().with_key(key.clone());
        let mut t2 = Transport::bind(localhost_any()).await.unwrap().with_key(key);
        let msg = build_ping(1, 99, 0, vec![]);
        t1.send_to(&msg, t2.local_addr).await.unwrap();

        let (received, _) = t2.recv_from().await.unwrap();
        assert_eq!(received.sender_id, 1);
        assert_eq!(received.sender_heartbeat, 99);
    }

    #[tokio::test]
    async fn recv_drops_corrupted_then_accepts_valid() {
        let t1 = Transport::bind(localhost_any()).await.unwrap();
        let mut t2 = Transport::bind(localhost_any()).await.unwrap();
        let raw_socket = t1.clone_socket();

        // Send corrupted bytes first (silently dropped by recv_from).
        let mut bad = valid_ping_bytes(1);
        bad[5] ^= 0xFF;
        raw_socket.send_to(&bad, t2.local_addr).await.unwrap();

        // Then send a valid message.
        let good = build_ping(2, 77, 0, vec![]);
        t1.send_to(&good, t2.local_addr).await.unwrap();

        // recv_from should skip the bad datagram and return the good one.
        let (msg, _) = t2.recv_from().await.unwrap();
        assert_eq!(msg.sender_id, 2);
        assert_eq!(msg.sender_heartbeat, 77);
    }

    #[tokio::test]
    async fn recv_drops_truncated_then_accepts_valid() {
        let t1 = Transport::bind(localhost_any()).await.unwrap();
        let mut t2 = Transport::bind(localhost_any()).await.unwrap();
        let raw_socket = t1.clone_socket();

        raw_socket.send_to(&[0u8; 5], t2.local_addr).await.unwrap();

        let good = build_ping(3, 0, 0, vec![]);
        t1.send_to(&good, t2.local_addr).await.unwrap();

        let (msg, _) = t2.recv_from().await.unwrap();
        assert_eq!(msg.sender_id, 3);
    }

    #[tokio::test]
    async fn recv_drops_garbage_then_accepts_valid() {
        let t1 = Transport::bind(localhost_any()).await.unwrap();
        let mut t2 = Transport::bind(localhost_any()).await.unwrap();
        let raw_socket = t1.clone_socket();

        let garbage: Vec<u8> = (0..100).map(|i| (i * 37) as u8).collect();
        raw_socket.send_to(&garbage, t2.local_addr).await.unwrap();

        let good = build_ping(4, 0, 0, vec![]);
        t1.send_to(&good, t2.local_addr).await.unwrap();

        let (msg, _) = t2.recv_from().await.unwrap();
        assert_eq!(msg.sender_id, 4);
    }

    #[tokio::test]
    async fn recv_drops_multiple_bad_then_accepts_valid() {
        let t1 = Transport::bind(localhost_any()).await.unwrap();
        let mut t2 = Transport::bind(localhost_any()).await.unwrap();
        let raw_socket = t1.clone_socket();

        // Send several varieties of bad datagrams.
        raw_socket.send_to(&[0xFF; 3], t2.local_addr).await.unwrap();   // too short
        let mut bad_cksum = valid_ping_bytes(1);
        bad_cksum[10] ^= 0x01;
        raw_socket.send_to(&bad_cksum, t2.local_addr).await.unwrap();   // bad checksum

        // Valid message last.
        let good = build_ping(5, 55, 0, vec![]);
        t1.send_to(&good, t2.local_addr).await.unwrap();

        let (msg, _) = t2.recv_from().await.unwrap();
        assert_eq!(msg.sender_id, 5);
        assert_eq!(msg.sender_heartbeat, 55);
    }

    // ── is_encrypted ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn plaintext_transport_not_encrypted() {
        let t = Transport::bind(localhost_any()).await.unwrap();
        assert!(!t.is_encrypted());
    }

    #[tokio::test]
    async fn encrypted_transport_is_encrypted() {
        let t = Transport::bind(localhost_any()).await.unwrap()
            .with_key(ClusterKey::generate());
        assert!(t.is_encrypted());
    }
}
