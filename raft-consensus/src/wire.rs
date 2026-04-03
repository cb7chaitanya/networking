//! Compact binary wire codec for Raft RPC messages.
//!
//! Hand-rolled encoder/decoder with zero external dependencies (no protobuf,
//! no bincode). All integers are big-endian, all variable-length fields are
//! length-prefixed. This format is designed for learning — a production system
//! would likely use serde + bincode or a schema-driven format like flatbuffers.
//!
//! ## Wire format
//!
//! Every message starts with a 1-byte type tag followed by a fixed layout:
//!
//! ```text
//! Tag 1 — RequestVote:
//!   [1: u8] [term: u64] [candidate_id: u64] [last_log_index: u64] [last_log_term: u64]
//!
//! Tag 2 — RequestVoteResponse:
//!   [2: u8] [term: u64] [vote_granted: u8]
//!
//! Tag 3 — AppendEntries:
//!   [3: u8] [term: u64] [leader_id: u64] [prev_log_index: u64] [prev_log_term: u64]
//!   [leader_commit: u64] [entry_count: u32] [entries...]
//!   Each entry: [term: u64] [data_len: u32] [data: bytes]
//!
//! Tag 4 — AppendEntriesResponse:
//!   [4: u8] [term: u64] [success: u8] [match_index: u64]
//! ```

use crate::log::LogEntry;
use crate::message::*;

/// Wire format error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Not enough bytes to decode the expected field.
    UnexpectedEof,
    /// Unknown message type tag.
    UnknownTag(u8),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::UnexpectedEof => write!(f, "unexpected end of input"),
            WireError::UnknownTag(t) => write!(f, "unknown message tag: {t}"),
        }
    }
}

impl std::error::Error for WireError {}

// ── Tags ──

const TAG_REQUEST_VOTE: u8 = 1;
const TAG_REQUEST_VOTE_RESPONSE: u8 = 2;
const TAG_APPEND_ENTRIES: u8 = 3;
const TAG_APPEND_ENTRIES_RESPONSE: u8 = 4;

// ════════════════════════════════════════════════════════════════════════════
//  Encoder
// ════════════════════════════════════════════════════════════════════════════

/// Encode an `Rpc` message to a byte vector.
pub fn encode(rpc: &Rpc) -> Vec<u8> {
    match rpc {
        Rpc::RequestVote(args) => encode_request_vote(args),
        Rpc::RequestVoteResponse(reply) => encode_request_vote_response(reply),
        Rpc::AppendEntries(args) => encode_append_entries(args),
        Rpc::AppendEntriesResponse(reply) => encode_append_entries_response(reply),
    }
}

fn encode_request_vote(args: &RequestVoteArgs) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 4 * 8);
    buf.push(TAG_REQUEST_VOTE);
    buf.extend_from_slice(&args.term.to_be_bytes());
    buf.extend_from_slice(&args.candidate_id.to_be_bytes());
    buf.extend_from_slice(&args.last_log_index.to_be_bytes());
    buf.extend_from_slice(&args.last_log_term.to_be_bytes());
    buf
}

fn encode_request_vote_response(reply: &RequestVoteReply) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 8 + 1);
    buf.push(TAG_REQUEST_VOTE_RESPONSE);
    buf.extend_from_slice(&reply.term.to_be_bytes());
    buf.push(reply.vote_granted as u8);
    buf
}

fn encode_append_entries(args: &AppendEntriesArgs) -> Vec<u8> {
    // Pre-calculate size: tag(1) + 5*u64(40) + count(4) + entries
    let entry_size: usize = args
        .entries
        .iter()
        .map(|e| 8 + 4 + e.data.len()) // term + data_len + data
        .sum();
    let mut buf = Vec::with_capacity(1 + 40 + 4 + entry_size);

    buf.push(TAG_APPEND_ENTRIES);
    buf.extend_from_slice(&args.term.to_be_bytes());
    buf.extend_from_slice(&args.leader_id.to_be_bytes());
    buf.extend_from_slice(&args.prev_log_index.to_be_bytes());
    buf.extend_from_slice(&args.prev_log_term.to_be_bytes());
    buf.extend_from_slice(&args.leader_commit.to_be_bytes());
    buf.extend_from_slice(&(args.entries.len() as u32).to_be_bytes());

    for entry in &args.entries {
        buf.extend_from_slice(&entry.term.to_be_bytes());
        buf.extend_from_slice(&(entry.data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&entry.data);
    }
    buf
}

fn encode_append_entries_response(reply: &AppendEntriesReply) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 8 + 1 + 8);
    buf.push(TAG_APPEND_ENTRIES_RESPONSE);
    buf.extend_from_slice(&reply.term.to_be_bytes());
    buf.push(reply.success as u8);
    buf.extend_from_slice(&reply.match_index.to_be_bytes());
    buf
}

// ════════════════════════════════════════════════════════════════════════════
//  Decoder
// ════════════════════════════════════════════════════════════════════════════

/// Decode an `Rpc` message from bytes.
pub fn decode(data: &[u8]) -> Result<Rpc, WireError> {
    if data.is_empty() {
        return Err(WireError::UnexpectedEof);
    }
    let mut cursor = Cursor::new(data);
    let tag = cursor.read_u8()?;

    match tag {
        TAG_REQUEST_VOTE => {
            let term = cursor.read_u64()?;
            let candidate_id = cursor.read_u64()?;
            let last_log_index = cursor.read_u64()?;
            let last_log_term = cursor.read_u64()?;
            Ok(Rpc::RequestVote(RequestVoteArgs {
                term,
                candidate_id,
                last_log_index,
                last_log_term,
            }))
        }
        TAG_REQUEST_VOTE_RESPONSE => {
            let term = cursor.read_u64()?;
            let vote_granted = cursor.read_u8()? != 0;
            Ok(Rpc::RequestVoteResponse(RequestVoteReply {
                term,
                vote_granted,
            }))
        }
        TAG_APPEND_ENTRIES => {
            let term = cursor.read_u64()?;
            let leader_id = cursor.read_u64()?;
            let prev_log_index = cursor.read_u64()?;
            let prev_log_term = cursor.read_u64()?;
            let leader_commit = cursor.read_u64()?;
            let entry_count = cursor.read_u32()? as usize;

            let mut entries = Vec::with_capacity(entry_count);
            for _ in 0..entry_count {
                let entry_term = cursor.read_u64()?;
                let data_len = cursor.read_u32()? as usize;
                let data = cursor.read_bytes(data_len)?;
                entries.push(LogEntry {
                    term: entry_term,
                    data,
                });
            }
            Ok(Rpc::AppendEntries(AppendEntriesArgs {
                term,
                leader_id,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            }))
        }
        TAG_APPEND_ENTRIES_RESPONSE => {
            let term = cursor.read_u64()?;
            let success = cursor.read_u8()? != 0;
            let match_index = cursor.read_u64()?;
            Ok(Rpc::AppendEntriesResponse(AppendEntriesReply {
                term,
                success,
                match_index,
            }))
        }
        other => Err(WireError::UnknownTag(other)),
    }
}

// ── Cursor helper ──

/// Minimal zero-copy read cursor over a byte slice.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, WireError> {
        if self.pos >= self.data.len() {
            return Err(WireError::UnexpectedEof);
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, WireError> {
        if self.pos + 4 > self.data.len() {
            return Err(WireError::UnexpectedEof);
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_u64(&mut self) -> Result<u64, WireError> {
        if self.pos + 8 > self.data.len() {
            return Err(WireError::UnexpectedEof);
        }
        let v = u64::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, WireError> {
        if self.pos + len > self.data.len() {
            return Err(WireError::UnexpectedEof);
        }
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_vote_roundtrip() {
        let rpc = Rpc::RequestVote(RequestVoteArgs {
            term: 42,
            candidate_id: 7,
            last_log_index: 100,
            last_log_term: 41,
        });
        let bytes = encode(&rpc);
        let decoded = decode(&bytes).unwrap();
        if let Rpc::RequestVote(args) = decoded {
            assert_eq!(args.term, 42);
            assert_eq!(args.candidate_id, 7);
            assert_eq!(args.last_log_index, 100);
            assert_eq!(args.last_log_term, 41);
        } else {
            panic!("expected RequestVote");
        }
    }

    #[test]
    fn request_vote_response_roundtrip() {
        let rpc = Rpc::RequestVoteResponse(RequestVoteReply {
            term: 5,
            vote_granted: true,
        });
        let bytes = encode(&rpc);
        let decoded = decode(&bytes).unwrap();
        if let Rpc::RequestVoteResponse(reply) = decoded {
            assert_eq!(reply.term, 5);
            assert!(reply.vote_granted);
        } else {
            panic!("expected RequestVoteResponse");
        }
    }

    #[test]
    fn append_entries_roundtrip() {
        let rpc = Rpc::AppendEntries(AppendEntriesArgs {
            term: 3,
            leader_id: 1,
            prev_log_index: 10,
            prev_log_term: 2,
            entries: vec![
                LogEntry {
                    term: 3,
                    data: vec![0],
                },
                LogEntry {
                    term: 3,
                    data: vec![1, 2, 3, 4, 5],
                },
            ],
            leader_commit: 9,
        });
        let bytes = encode(&rpc);
        let decoded = decode(&bytes).unwrap();
        if let Rpc::AppendEntries(args) = decoded {
            assert_eq!(args.term, 3);
            assert_eq!(args.leader_id, 1);
            assert_eq!(args.prev_log_index, 10);
            assert_eq!(args.prev_log_term, 2);
            assert_eq!(args.leader_commit, 9);
            assert_eq!(args.entries.len(), 2);
            assert_eq!(args.entries[0].data, vec![0]);
            assert_eq!(args.entries[1].data, vec![1, 2, 3, 4, 5]);
        } else {
            panic!("expected AppendEntries");
        }
    }

    #[test]
    fn append_entries_empty_heartbeat_roundtrip() {
        let rpc = Rpc::AppendEntries(AppendEntriesArgs {
            term: 1,
            leader_id: 1,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        });
        let bytes = encode(&rpc);
        let decoded = decode(&bytes).unwrap();
        if let Rpc::AppendEntries(args) = decoded {
            assert!(args.entries.is_empty());
        } else {
            panic!("expected AppendEntries");
        }
    }

    #[test]
    fn append_entries_response_roundtrip() {
        let rpc = Rpc::AppendEntriesResponse(AppendEntriesReply {
            term: 10,
            success: false,
            match_index: 5,
        });
        let bytes = encode(&rpc);
        let decoded = decode(&bytes).unwrap();
        if let Rpc::AppendEntriesResponse(reply) = decoded {
            assert_eq!(reply.term, 10);
            assert!(!reply.success);
            assert_eq!(reply.match_index, 5);
        } else {
            panic!("expected AppendEntriesResponse");
        }
    }

    #[test]
    fn decode_empty_returns_error() {
        assert!(matches!(decode(&[]), Err(WireError::UnexpectedEof)));
    }

    #[test]
    fn decode_unknown_tag_returns_error() {
        assert!(matches!(decode(&[255]), Err(WireError::UnknownTag(255))));
    }

    #[test]
    fn decode_truncated_returns_eof() {
        // RequestVote needs 33 bytes total (1 tag + 4*8 fields), give it only 10.
        let rpc = Rpc::RequestVote(RequestVoteArgs {
            term: 1,
            candidate_id: 1,
            last_log_index: 0,
            last_log_term: 0,
        });
        let bytes = encode(&rpc);
        let truncated = &bytes[..10];
        assert!(matches!(decode(truncated), Err(WireError::UnexpectedEof)));
    }

    #[test]
    fn wire_sizes_are_compact() {
        // RequestVote: 1 + 4*8 = 33 bytes
        let rv = encode(&Rpc::RequestVote(RequestVoteArgs {
            term: 1,
            candidate_id: 1,
            last_log_index: 0,
            last_log_term: 0,
        }));
        assert_eq!(rv.len(), 33);

        // RequestVoteResponse: 1 + 8 + 1 = 10 bytes
        let rvr = encode(&Rpc::RequestVoteResponse(RequestVoteReply {
            term: 1,
            vote_granted: true,
        }));
        assert_eq!(rvr.len(), 10);

        // AppendEntriesResponse: 1 + 8 + 1 + 8 = 18 bytes
        let aer = encode(&Rpc::AppendEntriesResponse(AppendEntriesReply {
            term: 1,
            success: true,
            match_index: 5,
        }));
        assert_eq!(aer.len(), 18);

        // Empty heartbeat: 1 + 5*8 + 4 = 45 bytes
        let hb = encode(&Rpc::AppendEntries(AppendEntriesArgs {
            term: 1,
            leader_id: 1,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        }));
        assert_eq!(hb.len(), 45);
    }
}
