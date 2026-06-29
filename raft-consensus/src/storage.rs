//! Persistent storage abstraction for Raft.
//!
//! Raft's safety guarantees require that three things survive crashes:
//!
//! 1. **`current_term`** — must never go backward. If a node restarts and
//!    forgets its term, it could vote twice in the same term, violating
//!    Election Safety.
//!
//! 2. **`voted_for`** — must be durable before granting a vote. Otherwise a
//!    crash-and-restart could let a node vote for two different candidates
//!    in the same term.
//!
//! 3. **Log entries** — committed entries must never be lost. If a node
//!    acknowledges an entry to the leader and then loses it on crash, the
//!    leader might count a majority that doesn't actually exist.
//!
//! ## Ordering invariant
//!
//! Every mutation to persistent state must be durable **before** the node
//! sends any RPC response that depends on the new state. The `Storage` trait
//! methods are assumed to be synchronous and durable on return.
//!
//! ## Designing for disk
//!
//! The trait is designed so a file-based implementation can be efficient:
//!
//! - `save_term()` / `save_vote()` are separate so a disk backend can write
//!   a small fixed-size header without touching the log.
//! - `append_log_entries()` enables sequential appends to a write-ahead log.
//! - `truncate_log()` enables efficient truncation (just update a length marker).
//! - `load_state()` returns everything needed to reconstruct node state on boot.

use crate::log::LogEntry;
use crate::state::{LogIndex, NodeId, Term};

// ════════════════════════════════════════════════════════════════════════════
//  Error type
// ════════════════════════════════════════════════════════════════════════════

/// Errors that can occur during storage operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// The storage backend failed (e.g., disk I/O error).
    Io(String),
    /// Data on disk is corrupted or unreadable.
    Corrupted(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Io(msg) => write!(f, "storage I/O error: {msg}"),
            StorageError::Corrupted(msg) => write!(f, "storage corrupted: {msg}"),
        }
    }
}

impl std::error::Error for StorageError {}

pub type Result<T> = std::result::Result<T, StorageError>;

// ════════════════════════════════════════════════════════════════════════════
//  Recovered state (returned by load_state)
// ════════════════════════════════════════════════════════════════════════════

/// Everything needed to reconstruct a Raft node after a crash.
///
/// Returned by `Storage::load_state()`. A fresh node (no prior state) returns
/// the defaults: term 0, no vote, empty log.
#[derive(Debug, Clone)]
pub struct HardState {
    /// The latest term this server has seen.
    pub current_term: Term,
    /// Who we voted for in `current_term`, or `None`.
    pub voted_for: Option<NodeId>,
    /// All persisted log entries, in index order.
    pub log: Vec<LogEntry>,
}

impl HardState {
    /// Default state for a brand-new node.
    pub fn new() -> Self {
        Self {
            current_term: 0,
            voted_for: None,
            log: Vec::new(),
        }
    }
}

impl Default for HardState {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Snapshot
// ════════════════════════════════════════════════════════════════════════════

/// Lightweight snapshot header — index and term without the data blob.
///
/// Useful for deciding whether an incoming snapshot is newer than the one
/// already held, without deserializing the full application state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotMetadata {
    /// Index of the last log entry covered by this snapshot.
    pub last_included_index: LogIndex,
    /// Term of the last log entry covered by this snapshot.
    pub last_included_term: Term,
}

/// A point-in-time snapshot of the application state machine.
///
/// Snapshots compress the Raft log: once a prefix of log entries has been
/// applied, that prefix can be replaced by the resulting state. Any follower
/// that has fallen too far behind receives the snapshot directly via
/// `InstallSnapshot` (not yet implemented — this module covers storage only).
///
/// The `data` field is opaque to the Raft layer; the application owns its
/// serialization format.
///
/// Invariant: `last_included_index >= 1` (a snapshot always covers at least
/// one applied entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Index of the last log entry included in this snapshot. Log entries up
    /// to and including this index can be discarded after the snapshot is
    /// durably saved.
    pub last_included_index: LogIndex,
    /// Term of the last log entry included in this snapshot. Needed to answer
    /// AppendEntries consistency checks that probe the snapshot boundary.
    pub last_included_term: Term,
    /// Serialized application state. The Raft layer never inspects this.
    pub data: Vec<u8>,
}

impl Snapshot {
    /// Return lightweight metadata without cloning the data blob.
    pub fn metadata(&self) -> SnapshotMetadata {
        SnapshotMetadata {
            last_included_index: self.last_included_index,
            last_included_term: self.last_included_term,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Storage trait
// ════════════════════════════════════════════════════════════════════════════

/// Trait abstracting durable storage for Raft persistent state.
///
/// Implementations must guarantee that data is durable (fsync'd) before
/// returning from any mutating method. The node will send RPC responses
/// immediately after these calls return.
///
/// # Error handling
///
/// All methods return `Result`. In a production system, a storage failure
/// is typically fatal — the node should stop accepting RPCs and alert an
/// operator. The `RaftNode` propagates errors to the caller.
pub trait Storage {
    // ── Term ──

    /// Persist the current term. Must be durable before the node acts on
    /// the new term (sends votes, accepts entries, etc.).
    ///
    /// A disk backend would write this to a small fixed-size header file
    /// or the first bytes of a WAL segment.
    fn save_term(&mut self, term: Term) -> Result<()>;

    // ── Vote ──

    /// Persist who we voted for in the current term. Must be durable before
    /// the vote response is sent.
    ///
    /// Passing `None` clears the vote (new term, haven't voted yet).
    fn save_vote(&mut self, voted_for: Option<NodeId>) -> Result<()>;

    // ── Log ──

    /// Append one or more entries to the end of the persisted log.
    ///
    /// The entries are appended starting at the current log length + 1.
    /// The implementation must not reorder entries.
    ///
    /// A disk backend would sequentially write to a WAL file.
    fn append_log_entries(&mut self, entries: &[LogEntry]) -> Result<()>;

    /// Append a single entry. Convenience wrapper — default implementation
    /// delegates to `append_log_entries`.
    fn append_log_entry(&mut self, entry: LogEntry) -> Result<()> {
        self.append_log_entries(&[entry])
    }

    /// Remove all log entries from `index` onward (inclusive). Used when a
    /// follower discovers its log conflicts with the leader's.
    ///
    /// `index` is 1-based. Truncating at index 1 clears the entire log.
    /// Truncating beyond the log length is a no-op.
    ///
    /// A disk backend would update a length marker or truncate the file.
    fn truncate_log(&mut self, from_index: LogIndex) -> Result<()>;

    // ── Full state recovery ──

    /// Load all persisted state needed to reconstruct a node after crash.
    ///
    /// Returns `HardState` with term, vote, and log. A fresh node (no prior
    /// persisted data) returns `HardState::default()`.
    fn load_state(&self) -> Result<HardState>;

    // ── Snapshot ──

    /// Persist a snapshot. Overwrites any previously saved snapshot.
    ///
    /// Must be durable before returning. A disk backend would write the data
    /// atomically (e.g., write-then-rename) so a partial write can never
    /// replace a good snapshot.
    ///
    /// After this returns, log entries up to `snapshot.last_included_index`
    /// may be discarded. The caller is responsible for calling
    /// `truncate_log()` at the appropriate time.
    fn save_snapshot(&mut self, snapshot: &Snapshot) -> Result<()>;

    /// Load the most recently saved snapshot, or `None` if none exists.
    ///
    /// Called during node restore so the state machine can be fast-forwarded
    /// to the snapshot before replaying any remaining log entries.
    fn load_snapshot(&self) -> Result<Option<Snapshot>>;
}

// ════════════════════════════════════════════════════════════════════════════
//  In-memory implementation
// ════════════════════════════════════════════════════════════════════════════

/// Non-durable storage for testing and simulation.
///
/// All data lives in memory and is lost on drop — which is exactly what we
/// want for simulation, where "crash" means constructing a fresh
/// `MemoryStorage` and verifying recovery logic.
///
/// Can optionally be pre-loaded with state (via `from_hard_state`) to
/// simulate a node restarting from persisted data.
#[derive(Debug, Clone)]
pub struct MemoryStorage {
    current_term: Term,
    voted_for: Option<NodeId>,
    log: Vec<LogEntry>,
    snapshot: Option<Snapshot>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            current_term: 0,
            voted_for: None,
            log: Vec::new(),
            snapshot: None,
        }
    }

    /// Create a `MemoryStorage` pre-loaded with recovered state.
    /// Used to simulate a node restarting from persisted data.
    pub fn from_hard_state(state: HardState) -> Self {
        Self {
            current_term: state.current_term,
            voted_for: state.voted_for,
            log: state.log,
            snapshot: None,
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl Storage for MemoryStorage {
    fn save_term(&mut self, term: Term) -> Result<()> {
        self.current_term = term;
        Ok(())
    }

    fn save_vote(&mut self, voted_for: Option<NodeId>) -> Result<()> {
        self.voted_for = voted_for;
        Ok(())
    }

    fn append_log_entries(&mut self, entries: &[LogEntry]) -> Result<()> {
        self.log.extend_from_slice(entries);
        Ok(())
    }

    fn truncate_log(&mut self, from_index: LogIndex) -> Result<()> {
        if from_index == 0 {
            return Ok(());
        }
        let pos = (from_index - 1) as usize;
        if pos < self.log.len() {
            self.log.truncate(pos);
        }
        Ok(())
    }

    fn load_state(&self) -> Result<HardState> {
        Ok(HardState {
            current_term: self.current_term,
            voted_for: self.voted_for,
            log: self.log.clone(),
        })
    }

    fn save_snapshot(&mut self, snapshot: &Snapshot) -> Result<()> {
        self.snapshot = Some(snapshot.clone());
        Ok(())
    }

    fn load_snapshot(&self) -> Result<Option<Snapshot>> {
        Ok(self.snapshot.clone())
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Failing storage (for testing error paths)
// ════════════════════════════════════════════════════════════════════════════

/// A storage backend that fails every operation. Useful for testing that the
/// node correctly propagates storage errors.
#[derive(Debug, Clone)]
pub struct FailingStorage;

impl Storage for FailingStorage {
    fn save_term(&mut self, _term: Term) -> Result<()> {
        Err(StorageError::Io("simulated disk failure".into()))
    }

    fn save_vote(&mut self, _voted_for: Option<NodeId>) -> Result<()> {
        Err(StorageError::Io("simulated disk failure".into()))
    }

    fn append_log_entries(&mut self, _entries: &[LogEntry]) -> Result<()> {
        Err(StorageError::Io("simulated disk failure".into()))
    }

    fn truncate_log(&mut self, _from_index: LogIndex) -> Result<()> {
        Err(StorageError::Io("simulated disk failure".into()))
    }

    fn load_state(&self) -> Result<HardState> {
        Err(StorageError::Io("simulated disk failure".into()))
    }

    fn save_snapshot(&mut self, _snapshot: &Snapshot) -> Result<()> {
        Err(StorageError::Io("simulated disk failure".into()))
    }

    fn load_snapshot(&self) -> Result<Option<Snapshot>> {
        Err(StorageError::Io("simulated disk failure".into()))
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(term: Term, data: u8) -> LogEntry {
        LogEntry {
            term,
            data: vec![data],
        }
    }

    // ── MemoryStorage basics ──

    #[test]
    fn fresh_storage_returns_default_state() {
        let storage = MemoryStorage::new();
        let state = storage.load_state().unwrap();
        assert_eq!(state.current_term, 0);
        assert_eq!(state.voted_for, None);
        assert!(state.log.is_empty());
    }

    #[test]
    fn save_and_load_term() {
        let mut storage = MemoryStorage::new();
        storage.save_term(5).unwrap();
        let state = storage.load_state().unwrap();
        assert_eq!(state.current_term, 5);
    }

    #[test]
    fn save_and_load_vote() {
        let mut storage = MemoryStorage::new();
        storage.save_vote(Some(3)).unwrap();
        let state = storage.load_state().unwrap();
        assert_eq!(state.voted_for, Some(3));
    }

    #[test]
    fn clear_vote() {
        let mut storage = MemoryStorage::new();
        storage.save_vote(Some(3)).unwrap();
        storage.save_vote(None).unwrap();
        let state = storage.load_state().unwrap();
        assert_eq!(state.voted_for, None);
    }

    #[test]
    fn term_and_vote_are_independent() {
        let mut storage = MemoryStorage::new();
        storage.save_term(10).unwrap();
        storage.save_vote(Some(7)).unwrap();

        // Updating term doesn't clear vote (that's the node's job).
        storage.save_term(11).unwrap();
        let state = storage.load_state().unwrap();
        assert_eq!(state.current_term, 11);
        assert_eq!(state.voted_for, Some(7));
    }

    // ── Log operations ──

    #[test]
    fn append_single_entry() {
        let mut storage = MemoryStorage::new();
        storage.append_log_entry(make_entry(1, 0xAA)).unwrap();

        let state = storage.load_state().unwrap();
        assert_eq!(state.log.len(), 1);
        assert_eq!(state.log[0].term, 1);
        assert_eq!(state.log[0].data, vec![0xAA]);
    }

    #[test]
    fn append_multiple_entries() {
        let mut storage = MemoryStorage::new();
        storage
            .append_log_entries(&[make_entry(1, 1), make_entry(1, 2), make_entry(2, 3)])
            .unwrap();

        let state = storage.load_state().unwrap();
        assert_eq!(state.log.len(), 3);
        assert_eq!(state.log[0].data, vec![1]);
        assert_eq!(state.log[1].data, vec![2]);
        assert_eq!(state.log[2].data, vec![3]);
        assert_eq!(state.log[2].term, 2);
    }

    #[test]
    fn append_preserves_order() {
        let mut storage = MemoryStorage::new();
        storage.append_log_entry(make_entry(1, 10)).unwrap();
        storage.append_log_entry(make_entry(1, 20)).unwrap();
        storage.append_log_entry(make_entry(2, 30)).unwrap();

        let state = storage.load_state().unwrap();
        assert_eq!(state.log.len(), 3);
        assert_eq!(state.log[0].data, vec![10]);
        assert_eq!(state.log[1].data, vec![20]);
        assert_eq!(state.log[2].data, vec![30]);
    }

    #[test]
    fn truncate_log_from_middle() {
        let mut storage = MemoryStorage::new();
        storage
            .append_log_entries(&[
                make_entry(1, 1),
                make_entry(1, 2),
                make_entry(1, 3),
                make_entry(1, 4),
                make_entry(1, 5),
            ])
            .unwrap();

        // Truncate from index 3 (1-based) → keep entries 1-2.
        storage.truncate_log(3).unwrap();

        let state = storage.load_state().unwrap();
        assert_eq!(state.log.len(), 2);
        assert_eq!(state.log[0].data, vec![1]);
        assert_eq!(state.log[1].data, vec![2]);
    }

    #[test]
    fn truncate_from_index_1_clears_log() {
        let mut storage = MemoryStorage::new();
        storage
            .append_log_entries(&[make_entry(1, 1), make_entry(1, 2)])
            .unwrap();

        storage.truncate_log(1).unwrap();

        let state = storage.load_state().unwrap();
        assert!(state.log.is_empty());
    }

    #[test]
    fn truncate_beyond_log_is_noop() {
        let mut storage = MemoryStorage::new();
        storage.append_log_entry(make_entry(1, 1)).unwrap();

        storage.truncate_log(100).unwrap(); // way past end

        let state = storage.load_state().unwrap();
        assert_eq!(state.log.len(), 1);
    }

    #[test]
    fn truncate_index_0_is_noop() {
        let mut storage = MemoryStorage::new();
        storage.append_log_entry(make_entry(1, 1)).unwrap();

        storage.truncate_log(0).unwrap();

        let state = storage.load_state().unwrap();
        assert_eq!(state.log.len(), 1);
    }

    #[test]
    fn truncate_then_append() {
        let mut storage = MemoryStorage::new();
        storage
            .append_log_entries(&[make_entry(1, 1), make_entry(1, 2), make_entry(1, 3)])
            .unwrap();

        storage.truncate_log(2).unwrap(); // keep entry 1
        storage.append_log_entry(make_entry(2, 20)).unwrap(); // new entry at index 2

        let state = storage.load_state().unwrap();
        assert_eq!(state.log.len(), 2);
        assert_eq!(state.log[0].data, vec![1]);
        assert_eq!(state.log[1].term, 2);
        assert_eq!(state.log[1].data, vec![20]);
    }

    // ── from_hard_state ──

    #[test]
    fn from_hard_state_pre_loads_data() {
        let storage = MemoryStorage::from_hard_state(HardState {
            current_term: 42,
            voted_for: Some(7),
            log: vec![make_entry(1, 1), make_entry(2, 2)],
        });

        let state = storage.load_state().unwrap();
        assert_eq!(state.current_term, 42);
        assert_eq!(state.voted_for, Some(7));
        assert_eq!(state.log.len(), 2);
    }

    // ── Combined operations ──

    #[test]
    fn full_lifecycle() {
        let mut storage = MemoryStorage::new();

        // Boot: empty.
        let s = storage.load_state().unwrap();
        assert_eq!(s.current_term, 0);
        assert!(s.log.is_empty());

        // Term 1: vote for node 3, append noop.
        storage.save_term(1).unwrap();
        storage.save_vote(Some(3)).unwrap();
        storage.append_log_entry(make_entry(1, 0)).unwrap();

        // Term 2: new election, clear vote, append entries.
        storage.save_term(2).unwrap();
        storage.save_vote(None).unwrap();
        storage
            .append_log_entries(&[make_entry(2, 10), make_entry(2, 20)])
            .unwrap();

        // Conflict: truncate index 3, re-append.
        storage.truncate_log(3).unwrap();
        storage.append_log_entry(make_entry(2, 30)).unwrap();

        let final_state = storage.load_state().unwrap();
        assert_eq!(final_state.current_term, 2);
        assert_eq!(final_state.voted_for, None);
        assert_eq!(final_state.log.len(), 3);
        assert_eq!(final_state.log[0].data, vec![0]);
        assert_eq!(final_state.log[1].data, vec![10]);
        assert_eq!(final_state.log[2].data, vec![30]);
    }

    // ── FailingStorage ──

    #[test]
    fn failing_storage_returns_errors() {
        let mut storage = FailingStorage;
        assert!(storage.save_term(1).is_err());
        assert!(storage.save_vote(Some(1)).is_err());
        assert!(storage.append_log_entry(make_entry(1, 0)).is_err());
        assert!(storage.truncate_log(1).is_err());
        assert!(storage.load_state().is_err());
    }

    // ── Snapshot helpers ──

    fn make_snapshot(last_included_index: LogIndex, last_included_term: Term, data: u8) -> Snapshot {
        Snapshot {
            last_included_index,
            last_included_term,
            data: vec![data; 4],
        }
    }

    // ── Snapshot: fresh storage ──

    #[test]
    fn fresh_storage_has_no_snapshot() {
        let storage = MemoryStorage::new();
        let snap = storage.load_snapshot().unwrap();
        assert!(snap.is_none());
    }

    #[test]
    fn from_hard_state_has_no_snapshot() {
        let storage = MemoryStorage::from_hard_state(HardState {
            current_term: 5,
            voted_for: Some(1),
            log: vec![make_entry(1, 0)],
        });
        // Snapshot is not part of HardState; must be saved separately.
        assert!(storage.load_snapshot().unwrap().is_none());
    }

    // ── Snapshot: save and load ──

    #[test]
    fn save_and_load_snapshot_roundtrip() {
        let mut storage = MemoryStorage::new();
        let snap = make_snapshot(10, 2, 0xAB);
        storage.save_snapshot(&snap).unwrap();

        let loaded = storage.load_snapshot().unwrap().expect("snapshot should exist");
        assert_eq!(loaded, snap);
    }

    #[test]
    fn snapshot_fields_are_preserved() {
        let mut storage = MemoryStorage::new();
        let snap = Snapshot {
            last_included_index: 42,
            last_included_term: 7,
            data: vec![1, 2, 3, 4, 5],
        };
        storage.save_snapshot(&snap).unwrap();

        let loaded = storage.load_snapshot().unwrap().unwrap();
        assert_eq!(loaded.last_included_index, 42);
        assert_eq!(loaded.last_included_term, 7);
        assert_eq!(loaded.data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn snapshot_with_empty_data() {
        let mut storage = MemoryStorage::new();
        let snap = Snapshot {
            last_included_index: 1,
            last_included_term: 1,
            data: vec![],
        };
        storage.save_snapshot(&snap).unwrap();

        let loaded = storage.load_snapshot().unwrap().unwrap();
        assert!(loaded.data.is_empty());
    }

    // ── Snapshot: overwrite ──

    #[test]
    fn save_snapshot_overwrites_previous() {
        let mut storage = MemoryStorage::new();
        storage.save_snapshot(&make_snapshot(5, 1, 0x11)).unwrap();
        storage.save_snapshot(&make_snapshot(20, 3, 0x22)).unwrap();

        let loaded = storage.load_snapshot().unwrap().unwrap();
        assert_eq!(loaded.last_included_index, 20);
        assert_eq!(loaded.last_included_term, 3);
        assert_eq!(loaded.data, vec![0x22; 4]);
    }

    #[test]
    fn multiple_saves_always_returns_latest() {
        let mut storage = MemoryStorage::new();
        for i in 1u64..=5 {
            let snap = make_snapshot(i * 10, i, i as u8);
            storage.save_snapshot(&snap).unwrap();
        }
        let loaded = storage.load_snapshot().unwrap().unwrap();
        assert_eq!(loaded.last_included_index, 50);
        assert_eq!(loaded.last_included_term, 5);
    }

    // ── Snapshot: independence from log/term/vote ──

    #[test]
    fn snapshot_does_not_affect_log() {
        let mut storage = MemoryStorage::new();
        storage.append_log_entries(&[make_entry(1, 1), make_entry(1, 2)]).unwrap();
        storage.save_snapshot(&make_snapshot(1, 1, 0)).unwrap();

        // Log is unchanged after saving a snapshot.
        let state = storage.load_state().unwrap();
        assert_eq!(state.log.len(), 2);
    }

    #[test]
    fn log_does_not_affect_snapshot() {
        let mut storage = MemoryStorage::new();
        storage.save_snapshot(&make_snapshot(5, 1, 0xFF)).unwrap();
        storage.append_log_entry(make_entry(2, 99)).unwrap();

        // Snapshot is unchanged after appending a log entry.
        let loaded = storage.load_snapshot().unwrap().unwrap();
        assert_eq!(loaded.last_included_index, 5);
    }

    #[test]
    fn snapshot_does_not_affect_term_or_vote() {
        let mut storage = MemoryStorage::new();
        storage.save_term(7).unwrap();
        storage.save_vote(Some(3)).unwrap();
        storage.save_snapshot(&make_snapshot(10, 3, 0)).unwrap();

        let state = storage.load_state().unwrap();
        assert_eq!(state.current_term, 7);
        assert_eq!(state.voted_for, Some(3));
    }

    #[test]
    fn term_and_vote_do_not_affect_snapshot() {
        let mut storage = MemoryStorage::new();
        storage.save_snapshot(&make_snapshot(8, 2, 0xBB)).unwrap();
        storage.save_term(10).unwrap();
        storage.save_vote(None).unwrap();

        let loaded = storage.load_snapshot().unwrap().unwrap();
        assert_eq!(loaded.last_included_index, 8);
        assert_eq!(loaded.last_included_term, 2);
    }

    // ── SnapshotMetadata ──

    #[test]
    fn metadata_matches_snapshot_fields() {
        let snap = Snapshot {
            last_included_index: 99,
            last_included_term: 4,
            data: vec![0u8; 1024],
        };
        let meta = snap.metadata();
        assert_eq!(meta.last_included_index, snap.last_included_index);
        assert_eq!(meta.last_included_term, snap.last_included_term);
    }

    #[test]
    fn metadata_does_not_include_data() {
        // SnapshotMetadata is cheap to copy — it contains only two u64 fields.
        let snap = make_snapshot(7, 2, 0xCC);
        let meta = snap.metadata();
        // Verify the metadata struct only has the two index/term fields.
        assert_eq!(meta, SnapshotMetadata { last_included_index: 7, last_included_term: 2 });
    }

    // ── Snapshot: full lifecycle ──

    #[test]
    fn snapshot_full_lifecycle() {
        let mut storage = MemoryStorage::new();

        // No snapshot on a fresh node.
        assert!(storage.load_snapshot().unwrap().is_none());

        // Append some log entries and set term/vote.
        storage.save_term(1).unwrap();
        storage.save_vote(Some(1)).unwrap();
        storage.append_log_entries(&[
            make_entry(1, 1),
            make_entry(1, 2),
            make_entry(1, 3),
        ]).unwrap();

        // Take a snapshot at index 2 (entries 1-2 are now covered).
        let snap = Snapshot { last_included_index: 2, last_included_term: 1, data: vec![42] };
        storage.save_snapshot(&snap).unwrap();

        // Verify everything coexists correctly.
        let loaded_snap = storage.load_snapshot().unwrap().unwrap();
        assert_eq!(loaded_snap.last_included_index, 2);

        let state = storage.load_state().unwrap();
        assert_eq!(state.current_term, 1);
        assert_eq!(state.log.len(), 3); // caller is responsible for truncating

        // Newer snapshot replaces the old one.
        let snap2 = Snapshot { last_included_index: 3, last_included_term: 1, data: vec![99] };
        storage.save_snapshot(&snap2).unwrap();

        let latest = storage.load_snapshot().unwrap().unwrap();
        assert_eq!(latest.last_included_index, 3);
        assert_eq!(latest.data, vec![99]);
    }

    // ── FailingStorage: snapshot ──

    #[test]
    fn failing_storage_snapshot_save_fails() {
        let mut storage = FailingStorage;
        let snap = make_snapshot(1, 1, 0);
        assert!(storage.save_snapshot(&snap).is_err());
    }

    #[test]
    fn failing_storage_snapshot_load_fails() {
        let storage = FailingStorage;
        assert!(storage.load_snapshot().is_err());
    }
}
