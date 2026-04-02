//! Persistent storage abstraction.
//!
//! Raft's safety guarantees require that `current_term`, `voted_for`, and the log
//! survive crashes. The `Storage` trait provides the persistence seam: tests use
//! `MemoryStorage`, while a production system would use a write-ahead log on disk.
//!
//! Invariant: `save_state` must be called (and durable) *before* the node sends
//! any RPC response that depends on the new state. In practice this means the node
//! calls `save_state` every time it updates `current_term` or `voted_for`.

use crate::log::LogEntry;
use crate::state::PersistentState;

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

/// Trait abstracting durable storage for Raft persistent state.
pub trait Storage {
    /// Persist the current term and voted_for to stable storage.
    fn save_state(&mut self, state: &PersistentState) -> Result<()>;

    /// Load the most recently persisted state, or default state if none exists.
    fn load_state(&self) -> Result<PersistentState>;

    /// Persist log entries to stable storage. The implementation may append
    /// or overwrite as needed.
    fn save_log(&mut self, entries: &[LogEntry]) -> Result<()>;

    /// Load all persisted log entries, ordered by index.
    fn load_log(&self) -> Result<Vec<LogEntry>>;
}

// ── In-memory implementation ──

/// Non-durable storage for testing. All data lives in memory and is lost
/// on drop — which is exactly what we want for simulation, where "crash"
/// means constructing a fresh `MemoryStorage` and verifying recovery logic.
#[derive(Debug, Clone)]
pub struct MemoryStorage {
    state: PersistentState,
    log: Vec<LogEntry>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            state: PersistentState::new(),
            log: Vec::new(),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl Storage for MemoryStorage {
    fn save_state(&mut self, state: &PersistentState) -> Result<()> {
        self.state = state.clone();
        Ok(())
    }

    fn load_state(&self) -> Result<PersistentState> {
        Ok(self.state.clone())
    }

    fn save_log(&mut self, entries: &[LogEntry]) -> Result<()> {
        self.log = entries.to_vec();
        Ok(())
    }

    fn load_log(&self) -> Result<Vec<LogEntry>> {
        Ok(self.log.clone())
    }
}
