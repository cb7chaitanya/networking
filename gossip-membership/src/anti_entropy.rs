/// Anti-entropy chunking and reassembly.
///
/// When the membership table is too large for a single UDP datagram, the
/// anti-entropy round splits entries into MTU-safe chunks, each sent as
/// an `AntiEntropyChunk` message.  The receiver reassembles chunks keyed
/// by `(sender_id, table_version)` and applies merge rules once all
/// chunks have arrived.
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::message::{
    build_anti_entropy_chunk, Message, WireNodeEntry, HEADER_LEN, AE_CHUNK_HEADER,
};
use crate::node::NodeId;

/// Safe payload budget per chunk (bytes).  The message header + chunk
/// header overhead is subtracted from a conservative 1200-byte UDP
/// payload limit.
const CHUNK_PAYLOAD_BUDGET: usize = 1200 - HEADER_LEN - AE_CHUNK_HEADER;

/// Split a list of wire entries into MTU-safe chunks.
///
/// Each chunk's serialised entries must fit within `CHUNK_PAYLOAD_BUDGET`.
/// Returns a `Vec<Vec<WireNodeEntry>>` where each inner vec is one chunk.
pub fn chunk_entries(entries: &[WireNodeEntry]) -> Vec<Vec<WireNodeEntry>> {
    if entries.is_empty() {
        return vec![vec![]];
    }

    let mut chunks: Vec<Vec<WireNodeEntry>> = Vec::new();
    let mut current: Vec<WireNodeEntry> = Vec::new();
    let mut current_bytes: usize = 0;

    for entry in entries {
        let entry_len = entry.wire_len();
        if !current.is_empty() && current_bytes + entry_len > CHUNK_PAYLOAD_BUDGET {
            chunks.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current.push(entry.clone());
        current_bytes += entry_len;
    }

    if !current.is_empty() {
        chunks.push(current);
    }

    chunks
}

/// Build all anti-entropy chunk messages for a full table sync.
pub fn build_chunks(
    entries: &[WireNodeEntry],
    sender_id: NodeId,
    sender_heartbeat: u32,
    sender_incarnation: u32,
    table_version: u64,
) -> Vec<Message> {
    let chunked = chunk_entries(entries);
    let total = chunked.len() as u16;
    chunked
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            build_anti_entropy_chunk(
                sender_id,
                sender_heartbeat,
                sender_incarnation,
                table_version,
                i as u16,
                total,
                chunk,
            )
        })
        .collect()
}

// ── Chunk assembler ──────────────────────────────────────────────────────────

/// Key for an in-progress chunk assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AssemblyKey {
    sender_id: NodeId,
    table_version: u64,
}

/// In-progress assembly of chunks from one sender's table snapshot.
struct Assembly {
    total_chunks: u16,
    received: HashMap<u16, Vec<WireNodeEntry>>,
    created: Instant,
}

/// Buffers incoming anti-entropy chunks and produces the full entry list
/// once all chunks for a `(sender_id, table_version)` have arrived.
pub struct ChunkAssembler {
    assemblies: HashMap<AssemblyKey, Assembly>,
    timeout: Duration,
}

impl ChunkAssembler {
    pub fn new(timeout: Duration) -> Self {
        Self {
            assemblies: HashMap::new(),
            timeout,
        }
    }

    /// Feed a chunk into the assembler.  Returns `Some(entries)` if this
    /// chunk completed the assembly (all chunks received).
    pub fn feed(
        &mut self,
        sender_id: NodeId,
        table_version: u64,
        chunk_index: u16,
        total_chunks: u16,
        entries: Vec<WireNodeEntry>,
    ) -> Option<Vec<WireNodeEntry>> {
        let key = AssemblyKey { sender_id, table_version };
        let asm = self.assemblies.entry(key).or_insert_with(|| Assembly {
            total_chunks,
            received: HashMap::new(),
            created: Instant::now(),
        });

        // If total_chunks changed (shouldn't happen), reset.
        if asm.total_chunks != total_chunks {
            *asm = Assembly {
                total_chunks,
                received: HashMap::new(),
                created: Instant::now(),
            };
        }

        asm.received.insert(chunk_index, entries);

        if asm.received.len() == total_chunks as usize {
            let asm = self.assemblies.remove(&key).unwrap();
            let mut all_entries = Vec::new();
            for i in 0..asm.total_chunks {
                if let Some(chunk) = asm.received.get(&i) {
                    all_entries.extend(chunk.iter().cloned());
                }
            }
            Some(all_entries)
        } else {
            None
        }
    }

    /// Remove assemblies that have been pending longer than the timeout.
    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.assemblies.len();
        self.assemblies.retain(|_, asm| {
            now.duration_since(asm.created) < self.timeout
        });
        before - self.assemblies.len()
    }

    /// Number of in-progress assemblies.
    pub fn pending(&self) -> usize {
        self.assemblies.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use crate::message::status;

    fn v4_entry(id: u64) -> WireNodeEntry {
        WireNodeEntry {
            node_id: id,
            heartbeat: id as u32,
            incarnation: 0,
            status: status::ALIVE,
            addr: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, (id >> 8) as u8, id as u8)),
                9000 + id as u16,
            ),
        }
    }

    fn v6_entry(id: u64) -> WireNodeEntry {
        WireNodeEntry {
            node_id: id,
            heartbeat: id as u32,
            incarnation: 0,
            status: status::ALIVE,
            addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                9000 + id as u16,
            ),
        }
    }

    // ── chunk_entries tests ──────────────────────────────────────────────

    #[test]
    fn empty_entries_produces_one_empty_chunk() {
        let chunks = chunk_entries(&[]);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].is_empty());
    }

    #[test]
    fn small_table_fits_in_one_chunk() {
        let entries: Vec<_> = (0..10).map(v4_entry).collect();
        let chunks = chunk_entries(&entries);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 10);
    }

    #[test]
    fn large_table_split_into_multiple_chunks() {
        // Budget ~1152 bytes. IPv4 entry = 24 bytes → ~48 entries per chunk.
        // 200 entries → should produce ~4-5 chunks.
        let entries: Vec<_> = (0..200).map(v4_entry).collect();
        let chunks = chunk_entries(&entries);
        assert!(chunks.len() > 1, "200 entries should require multiple chunks");
        // Verify all entries present.
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, 200);
    }

    #[test]
    fn chunks_respect_budget() {
        let entries: Vec<_> = (0..200).map(v4_entry).collect();
        let chunks = chunk_entries(&entries);
        for (i, chunk) in chunks.iter().enumerate() {
            let bytes: usize = chunk.iter().map(|e| e.wire_len()).sum();
            assert!(
                bytes <= CHUNK_PAYLOAD_BUDGET,
                "chunk {i} is {bytes} bytes, exceeds budget {CHUNK_PAYLOAD_BUDGET}"
            );
        }
    }

    #[test]
    fn mixed_v4_v6_entries_chunked_correctly() {
        // Mix of 24-byte and 36-byte entries.
        let mut entries = Vec::new();
        for i in 0..100 {
            if i % 3 == 0 {
                entries.push(v6_entry(i));
            } else {
                entries.push(v4_entry(i));
            }
        }
        let chunks = chunk_entries(&entries);
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, 100);
        for chunk in &chunks {
            let bytes: usize = chunk.iter().map(|e| e.wire_len()).sum();
            assert!(bytes <= CHUNK_PAYLOAD_BUDGET);
        }
    }

    // ── build_chunks tests ──────────────────────────────────────────────

    #[test]
    fn build_chunks_roundtrip() {
        let entries: Vec<_> = (0..5).map(v4_entry).collect();
        let msgs = build_chunks(&entries, 1, 0, 0, 42);
        assert_eq!(msgs.len(), 1);
        let buf = msgs[0].encode().unwrap();
        let decoded = crate::message::Message::decode(&buf).unwrap();
        match decoded.payload {
            crate::message::MessagePayload::AntiEntropyChunk(c) => {
                assert_eq!(c.table_version, 42);
                assert_eq!(c.chunk_index, 0);
                assert_eq!(c.total_chunks, 1);
                assert_eq!(c.entries.len(), 5);
            }
            _ => panic!("expected AntiEntropyChunk"),
        }
    }

    #[test]
    fn build_chunks_large_table() {
        let entries: Vec<_> = (0..200).map(v4_entry).collect();
        let msgs = build_chunks(&entries, 1, 0, 0, 99);
        assert!(msgs.len() > 1);
        // Each message should encode successfully (within MTU).
        for msg in &msgs {
            assert!(msg.encode().is_ok(), "chunk should fit in UDP MTU");
        }
    }

    // ── ChunkAssembler tests ────────────────────────────────────────────

    #[test]
    fn assembler_single_chunk_completes_immediately() {
        let mut asm = ChunkAssembler::new(Duration::from_secs(10));
        let entries: Vec<_> = (0..5).map(v4_entry).collect();
        let result = asm.feed(1, 42, 0, 1, entries.clone());
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 5);
        assert_eq!(asm.pending(), 0);
    }

    #[test]
    fn assembler_multi_chunk_in_order() {
        let mut asm = ChunkAssembler::new(Duration::from_secs(10));
        let chunk0: Vec<_> = (0..3).map(v4_entry).collect();
        let chunk1: Vec<_> = (3..5).map(v4_entry).collect();

        assert!(asm.feed(1, 42, 0, 2, chunk0).is_none());
        assert_eq!(asm.pending(), 1);

        let result = asm.feed(1, 42, 1, 2, chunk1);
        assert!(result.is_some());
        let all = result.unwrap();
        assert_eq!(all.len(), 5);
        // Entries should be in chunk order: 0,1,2,3,4.
        for (i, e) in all.iter().enumerate() {
            assert_eq!(e.node_id, i as u64);
        }
        assert_eq!(asm.pending(), 0);
    }

    #[test]
    fn assembler_multi_chunk_out_of_order() {
        let mut asm = ChunkAssembler::new(Duration::from_secs(10));
        let chunk0: Vec<_> = (0..2).map(v4_entry).collect();
        let chunk1: Vec<_> = (2..4).map(v4_entry).collect();
        let chunk2: Vec<_> = (4..6).map(v4_entry).collect();

        // Deliver out of order: 2, 0, 1.
        assert!(asm.feed(1, 42, 2, 3, chunk2).is_none());
        assert!(asm.feed(1, 42, 0, 3, chunk0).is_none());
        let result = asm.feed(1, 42, 1, 3, chunk1);
        assert!(result.is_some());
        let all = result.unwrap();
        assert_eq!(all.len(), 6);
        // Reassembled in chunk-index order.
        for (i, e) in all.iter().enumerate() {
            assert_eq!(e.node_id, i as u64);
        }
    }

    #[test]
    fn assembler_partial_loss_stays_pending() {
        let mut asm = ChunkAssembler::new(Duration::from_secs(10));
        // Only deliver 2 of 3 chunks.
        let chunk0: Vec<_> = (0..2).map(v4_entry).collect();
        let chunk2: Vec<_> = (4..6).map(v4_entry).collect();

        assert!(asm.feed(1, 42, 0, 3, chunk0).is_none());
        assert!(asm.feed(1, 42, 2, 3, chunk2).is_none());
        assert_eq!(asm.pending(), 1);
    }

    #[test]
    fn assembler_expire_removes_stale() {
        let mut asm = ChunkAssembler::new(Duration::from_millis(100));
        let chunk: Vec<_> = (0..2).map(v4_entry).collect();
        asm.feed(1, 42, 0, 3, chunk);
        assert_eq!(asm.pending(), 1);

        let later = Instant::now() + Duration::from_millis(200);
        let expired = asm.expire(later);
        assert_eq!(expired, 1);
        assert_eq!(asm.pending(), 0);
    }

    #[test]
    fn assembler_different_senders_independent() {
        let mut asm = ChunkAssembler::new(Duration::from_secs(10));
        let e1: Vec<_> = (0..2).map(v4_entry).collect();
        let e2: Vec<_> = (10..12).map(v4_entry).collect();

        asm.feed(1, 42, 0, 2, e1);
        asm.feed(2, 42, 0, 2, e2);
        assert_eq!(asm.pending(), 2);

        // Complete sender 1.
        let r = asm.feed(1, 42, 1, 2, (2..4).map(v4_entry).collect());
        assert!(r.is_some());
        assert_eq!(asm.pending(), 1); // sender 2 still pending
    }

    #[test]
    fn assembler_different_versions_independent() {
        let mut asm = ChunkAssembler::new(Duration::from_secs(10));
        asm.feed(1, 1, 0, 2, (0..2).map(v4_entry).collect());
        asm.feed(1, 2, 0, 2, (10..12).map(v4_entry).collect());
        assert_eq!(asm.pending(), 2);
    }

    #[test]
    fn assembler_duplicate_chunk_idempotent() {
        let mut asm = ChunkAssembler::new(Duration::from_secs(10));
        let chunk: Vec<_> = (0..2).map(v4_entry).collect();
        asm.feed(1, 42, 0, 2, chunk.clone());
        asm.feed(1, 42, 0, 2, chunk); // duplicate
        assert_eq!(asm.pending(), 1);

        let r = asm.feed(1, 42, 1, 2, (2..4).map(v4_entry).collect());
        assert!(r.is_some());
        assert_eq!(r.unwrap().len(), 4);
    }

    #[test]
    fn large_table_chunk_and_reassemble() {
        let entries: Vec<_> = (0..250).map(v4_entry).collect();
        let msgs = build_chunks(&entries, 1, 0, 0, 100);
        let total_chunks = msgs.len();
        assert!(total_chunks > 1);

        let mut asm = ChunkAssembler::new(Duration::from_secs(10));
        let mut result = None;
        for msg in msgs {
            let buf = msg.encode().unwrap();
            let decoded = crate::message::Message::decode(&buf).unwrap();
            match decoded.payload {
                crate::message::MessagePayload::AntiEntropyChunk(c) => {
                    result = asm.feed(
                        decoded.sender_id,
                        c.table_version,
                        c.chunk_index,
                        c.total_chunks,
                        c.entries,
                    );
                }
                _ => panic!("expected AntiEntropyChunk"),
            }
        }
        let all = result.expect("all chunks should complete assembly");
        assert_eq!(all.len(), 250);
        // Verify order preserved.
        for (i, e) in all.iter().enumerate() {
            assert_eq!(e.node_id, i as u64);
        }
    }
}
