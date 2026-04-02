//! Replicated log: entries, trait, and in-memory implementation.
//!
//! The log is the backbone of Raft consensus. Every state mutation flows through
//! the log: the leader appends an entry, replicates it, and only applies it to
//! the state machine once a majority of nodes have durably stored it.
//!
//! Indices are **1-based** following the Raft paper. Index 0 is a virtual
//! sentinel representing "before any entry" — it is never stored.

use crate::state::{LogIndex, Term};

// ── Command ──

/// An opaque command to be applied to the replicated state machine.
/// The Raft layer treats this as an opaque blob; only the application layer
/// interprets it.
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

// ── LogEntry ──

/// A single entry in the replicated log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// The term when the entry was created by the leader.
    pub term: Term,
    /// 1-based position in the log.
    pub index: LogIndex,
    /// The command to apply to the state machine.
    pub command: Command,
}

// ── RaftLog trait ──

/// Abstraction over the replicated log storage.
///
/// Callers must ensure indices are valid; out-of-range accesses return `None`
/// rather than panicking, so the node layer can handle mismatches gracefully.
pub trait RaftLog {
    /// Append an entry at the end of the log. The caller must set `entry.index`
    /// to `self.last_index() + 1`.
    fn append(&mut self, entry: LogEntry);

    /// Retrieve the entry at `index`, or `None` if out of range.
    fn get(&self, index: LogIndex) -> Option<&LogEntry>;

    /// The index of the last entry in the log, or 0 if the log is empty.
    fn last_index(&self) -> LogIndex;

    /// The term of the last entry in the log, or 0 if the log is empty.
    fn last_term(&self) -> Term;

    /// Return a slice of entries in the range `[from, to]` (inclusive on both ends).
    /// Returns an empty slice if the range is invalid.
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
        debug_assert_eq!(
            entry.index,
            self.last_index() + 1,
            "append index must be contiguous"
        );
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
