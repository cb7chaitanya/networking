/// Optional LZ4 compression layer for gossip payloads.
///
/// Only GOSSIP messages benefit from compression — PING/ACK/PING_REQ have
/// tiny payloads. Compression is signalled via the `COMPRESSED` flag bit
/// in the message header so receivers can detect and decompress.
///
/// Capability negotiation is implicit: a node tracks which peers have sent
/// compressed messages and only sends compressed payloads to those peers.
use std::collections::HashMap;
use std::net::SocketAddr;

/// Minimum payload size (bytes) below which compression is skipped.
/// LZ4 framing overhead can increase size for very small inputs.
pub const COMPRESS_THRESHOLD: usize = 60;

/// Safety limit for decompressed output to prevent decompression bombs.
const MAX_DECOMPRESSED: usize = 65_536;

// ── Compress / Decompress ────────────────────────────────────────────────────

/// LZ4 block-compress `payload`. Returns compressed bytes.
pub fn compress(payload: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(payload)
}

/// LZ4 block-decompress `data`. Returns original payload.
///
/// Fails if the decompressed output would exceed `MAX_DECOMPRESSED` bytes
/// or the data is malformed.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    // lz4_flex::decompress_size_prepended reads the original size from
    // the first 4 bytes. We verify it doesn't exceed our safety limit.
    if data.len() >= 4 {
        let orig_size = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        if orig_size > MAX_DECOMPRESSED {
            return Err(CompressionError::DecompressedTooLarge);
        }
    }
    lz4_flex::decompress_size_prepended(data).map_err(|_| CompressionError::DecompressFailed)
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum CompressionError {
    DecompressFailed,
    DecompressedTooLarge,
}

impl std::fmt::Display for CompressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecompressFailed => write!(f, "LZ4 decompression failed"),
            Self::DecompressedTooLarge => write!(f, "decompressed payload exceeds safety limit"),
        }
    }
}

impl std::error::Error for CompressionError {}

// ── Peer capability tracking ─────────────────────────────────────────────────

/// Tracks which peers are known to support compression.
///
/// When we receive a compressed message from a peer, we mark them as
/// compression-capable. We only send compressed messages to peers that
/// have demonstrated support — this enables backward compatibility with
/// older nodes that don't understand compression.
pub struct PeerCompressionMap {
    capable: HashMap<SocketAddr, bool>,
}

impl PeerCompressionMap {
    pub fn new() -> Self {
        Self {
            capable: HashMap::new(),
        }
    }

    /// Mark a peer as compression-capable (called when receiving a compressed msg).
    pub fn mark_capable(&mut self, addr: SocketAddr) {
        self.capable.insert(addr, true);
    }

    /// Check whether a peer is known to support compression.
    pub fn is_capable(&self, addr: &SocketAddr) -> bool {
        self.capable.get(addr).copied().unwrap_or(false)
    }

    /// Remove a peer (e.g. when they are declared dead).
    pub fn remove(&mut self, addr: &SocketAddr) {
        self.capable.remove(addr);
    }
}

impl Default for PeerCompressionMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn compress_decompress_roundtrip() {
        let original = vec![1u8; 200]; // repetitive data — compresses well
        let compressed = compress(&original);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn compress_small_payload() {
        let original = vec![42u8; 10];
        let compressed = compress(&original);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn decompress_garbage_fails() {
        let garbage = vec![0xFF, 0x00, 0x00, 0x00, 0xDE, 0xAD];
        assert!(decompress(&garbage).is_err());
    }

    #[test]
    fn decompress_bomb_rejected() {
        // Craft a header claiming a huge decompressed size.
        let mut data = vec![0u8; 100];
        let huge: u32 = (MAX_DECOMPRESSED + 1) as u32;
        data[0..4].copy_from_slice(&huge.to_le_bytes());
        assert!(matches!(
            decompress(&data),
            Err(CompressionError::DecompressedTooLarge)
        ));
    }

    #[test]
    fn peer_capability_tracking() {
        let mut map = PeerCompressionMap::new();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 7000));

        assert!(!map.is_capable(&addr));
        map.mark_capable(addr);
        assert!(map.is_capable(&addr));
        map.remove(&addr);
        assert!(!map.is_capable(&addr));
    }
}
