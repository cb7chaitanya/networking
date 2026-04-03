//! Replicated log: entries, trait, and in-memory implementation.
//!
//! The log is the backbone of Raft consensus. Every state mutation flows through
//! the log: the leader appends an entry, replicates it, and only applies it to
//! the state machine once a majority of nodes have durably stored it.
//!
//! Indices are **1-based** following the Raft paper. Index 0 is a virtual
//! sentinel representing "before any entry" — it is never stored.

use serde::{Deserialize, Serialize};

use crate::state::{LogIndex, Term};

// ── LogEntry ──

/// A single entry in the replicated log.
///
/// The Raft layer treats the command payload as an **opaque byte vector**.
/// Only the application layer interprets it. This keeps the consensus engine
/// decoupled from any particular state machine.
///
/// The `index` is NOT part of the entry — it is a positional property assigned
/// by the log when the entry is appended. This matches the wire format: on the
/// network, only `(term, data)` is transmitted, and the receiver determines the
/// index from `prev_log_index + offset`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// The term when the entry was created by the leader.
    pub term: Term,
    /// Opaque command bytes. The Raft layer never inspects this — it is passed
    /// through to the application's state machine on commit.
    pub data: Vec<u8>,
}

// ── Command (application-level convenience) ──

/// Application-level command enum with serialization helpers.
///
/// This is NOT part of the Raft protocol — it is a convenience for the
/// key-value state machine we use in testing and simulation. Real applications
/// would define their own command format and use `LogEntry.data` directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// No-op entry appended by a newly elected leader to commit entries from
    /// prior terms (Raft §5.4.2 — a leader cannot determine commitment of
    /// entries from previous terms until it commits an entry from its own term).
    Noop,
    /// Application-level key-value put.
    Put { key: String, value: Vec<u8> },
    /// Application-level key-value delete.
    Delete { key: String },
}

/// Wire tag bytes for command variants.
const TAG_NOOP: u8 = 0;
const TAG_PUT: u8 = 1;
const TAG_DELETE: u8 = 2;

impl Command {
    /// Serialize the command to bytes suitable for `LogEntry.data`.
    ///
    /// Format (simple length-prefixed encoding):
    /// - Noop:   `[0]`
    /// - Put:    `[1][key_len: u32][key_bytes][value_bytes]`
    /// - Delete: `[2][key_len: u32][key_bytes]`
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Command::Noop => vec![TAG_NOOP],
            Command::Put { key, value } => {
                let key_bytes = key.as_bytes();
                let mut buf = Vec::with_capacity(1 + 4 + key_bytes.len() + value.len());
                buf.push(TAG_PUT);
                buf.extend_from_slice(&(key_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(key_bytes);
                buf.extend_from_slice(value);
                buf
            }
            Command::Delete { key } => {
                let key_bytes = key.as_bytes();
                let mut buf = Vec::with_capacity(1 + 4 + key_bytes.len());
                buf.push(TAG_DELETE);
                buf.extend_from_slice(&(key_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(key_bytes);
                buf
            }
        }
    }

    /// Deserialize a command from bytes. Returns `None` if the data is malformed.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        match data[0] {
            TAG_NOOP => Some(Command::Noop),
            TAG_PUT => {
                if data.len() < 5 {
                    return None;
                }
                let key_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
                if data.len() < 5 + key_len {
                    return None;
                }
                let key = String::from_utf8(data[5..5 + key_len].to_vec()).ok()?;
                let value = data[5 + key_len..].to_vec();
                Some(Command::Put { key, value })
            }
            TAG_DELETE => {
                if data.len() < 5 {
                    return None;
                }
                let key_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
                if data.len() < 5 + key_len {
                    return None;
                }
                let key = String::from_utf8(data[5..5 + key_len].to_vec()).ok()?;
                Some(Command::Delete { key })
            }
            _ => None,
        }
    }
}

// ── RaftLog trait ──

/// Abstraction over the replicated log storage.
///
/// Indices are 1-based and assigned by the log, not by the caller. The log
/// is append-only from the perspective of normal operation; truncation only
/// happens when a follower must discard entries that conflict with the leader.
pub trait RaftLog {
    /// Append an entry at the end of the log. The entry's index is implicitly
    /// `self.last_index() + 1`.
    fn append(&mut self, entry: LogEntry);

    /// Retrieve the entry at `index`, or `None` if out of range.
    fn get(&self, index: LogIndex) -> Option<&LogEntry>;

    /// The index of the last entry in the log, or 0 if the log is empty.
    fn last_index(&self) -> LogIndex;

    /// The term of the last entry in the log, or 0 if the log is empty.
    fn last_term(&self) -> Term;

    /// Return entries in the range `[from, to]` (inclusive on both ends).
    /// Returns an empty vec if the range is invalid.
    fn slice(&self, from: LogIndex, to: LogIndex) -> Vec<&LogEntry>;

    /// Remove all entries from `index` onward (inclusive). Used when a follower
    /// discovers its log conflicts with the leader's — the conflicting suffix
    /// must be discarded so the leader's entries can replace it.
    ///
    /// Raft Log Matching Property guarantee: if two logs contain an entry with
    /// the same index and term, all preceding entries are identical. So
    /// truncating from the first conflict point is always safe.
    fn truncate_from(&mut self, index: LogIndex);

    /// Return the term of the entry at `index`, or `None` if no such entry exists.
    fn term_at(&self, index: LogIndex) -> Option<Term>;

    /// Number of entries in the log.
    fn len(&self) -> usize;

    /// Whether the log is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── InMemoryLog ──

/// Simple in-memory log backed by a `Vec`. Suitable for testing and simulation.
/// For production, this would be replaced with a write-ahead log on disk.
#[derive(Debug, Clone)]
pub struct InMemoryLog {
    entries: Vec<LogEntry>,
}

impl InMemoryLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl Default for InMemoryLog {
    fn default() -> Self {
        Self::new()
    }
}

impl RaftLog for InMemoryLog {
    fn append(&mut self, entry: LogEntry) {
        self.entries.push(entry);
    }

    fn get(&self, index: LogIndex) -> Option<&LogEntry> {
        if index == 0 || index as usize > self.entries.len() {
            return None;
        }
        Some(&self.entries[(index - 1) as usize])
    }

    fn last_index(&self) -> LogIndex {
        self.entries.len() as LogIndex
    }

    fn last_term(&self) -> Term {
        self.entries.last().map_or(0, |e| e.term)
    }

    fn slice(&self, from: LogIndex, to: LogIndex) -> Vec<&LogEntry> {
        if from == 0 || from > to || from as usize > self.entries.len() {
            return Vec::new();
        }
        let start = (from - 1) as usize;
        let end = std::cmp::min(to as usize, self.entries.len());
        self.entries[start..end].iter().collect()
    }

    fn truncate_from(&mut self, index: LogIndex) {
        if index == 0 {
            return;
        }
        let pos = (index - 1) as usize;
        if pos < self.entries.len() {
            self.entries.truncate(pos);
        }
    }

    fn term_at(&self, index: LogIndex) -> Option<Term> {
        self.get(index).map(|e| e.term)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_noop_roundtrip() {
        let cmd = Command::Noop;
        let bytes = cmd.encode();
        assert_eq!(Command::decode(&bytes), Some(Command::Noop));
    }

    #[test]
    fn command_put_roundtrip() {
        let cmd = Command::Put {
            key: "hello".into(),
            value: vec![1, 2, 3],
        };
        let bytes = cmd.encode();
        assert_eq!(Command::decode(&bytes), Some(cmd));
    }

    #[test]
    fn command_delete_roundtrip() {
        let cmd = Command::Delete {
            key: "gone".into(),
        };
        let bytes = cmd.encode();
        assert_eq!(Command::decode(&bytes), Some(cmd));
    }

    #[test]
    fn command_decode_empty_returns_none() {
        assert_eq!(Command::decode(&[]), None);
    }

    #[test]
    fn command_decode_invalid_tag_returns_none() {
        assert_eq!(Command::decode(&[255]), None);
    }

    #[test]
    fn log_append_and_get() {
        let mut log = InMemoryLog::new();
        assert_eq!(log.last_index(), 0);
        assert_eq!(log.last_term(), 0);

        log.append(LogEntry {
            term: 1,
            data: Command::Noop.encode(),
        });
        assert_eq!(log.last_index(), 1);
        assert_eq!(log.last_term(), 1);
        assert_eq!(log.get(1).unwrap().term, 1);
        assert!(log.get(0).is_none());
        assert!(log.get(2).is_none());
    }

    #[test]
    fn log_truncate() {
        let mut log = InMemoryLog::new();
        for i in 1..=5 {
            log.append(LogEntry {
                term: i,
                data: vec![],
            });
        }
        assert_eq!(log.last_index(), 5);

        log.truncate_from(3);
        assert_eq!(log.last_index(), 2);
        assert!(log.get(3).is_none());
    }
}
