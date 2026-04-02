//! Core Raft types and state definitions.
//!
//! Follows the state described in Figure 2 of the Raft paper (Ongaro & Ousterhout, 2014).
//! Every Raft node maintains persistent state (survives crashes), volatile state
//! (rebuilt on restart), and — when acting as leader — per-follower replication state.

use std::collections::{HashMap, HashSet};

// ── Fundamental types ──

/// Unique identifier for a node in the cluster.
pub type NodeId = u64;

/// Monotonically increasing term number. Terms act as a logical clock in Raft:
/// every message carries a term, and any node that sees a higher term immediately
/// updates its own and reverts to follower.
pub type Term = u64;

/// 1-based index into the replicated log. Index 0 is a sentinel meaning
/// "before the first entry" and is never stored.
pub type LogIndex = u64;

// ── Role ──

/// The three mutually exclusive roles a Raft node can occupy.
///
/// Raft guarantee: at most one leader per term. This is enforced by the voting
/// rule — each node votes for at most one candidate per term, and a candidate
/// needs a strict majority to win.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    /// Passive: responds to RPCs from leaders and candidates.
    /// Converts to Candidate if election timeout elapses without hearing
    /// from a current leader or granting a vote.
    Follower,

    /// Actively seeking election. Holds the set of nodes that have granted
    /// their vote in this term. Converts to Leader on majority, or back to
    /// Follower if it discovers a higher term or a legitimate leader.
    Candidate {
        votes_received: HashSet<NodeId>,
    },

    /// Manages the cluster: sends heartbeats, replicates log entries, and
    /// advances the commit index. Maintains per-follower replication cursors.
    ///
    /// `next_index[peer]`:  index of the *next* entry to send to that peer.
    ///                      Initialized to leader's last log index + 1.
    /// `match_index[peer]`: highest index known to be replicated on that peer.
    ///                      Initialized to 0 (no entries confirmed yet).
    Leader {
        next_index: HashMap<NodeId, LogIndex>,
        match_index: HashMap<NodeId, LogIndex>,
    },
}

// ── Persistent state ──

/// State that MUST be persisted to stable storage before responding to any RPC.
/// If a node crashes and restarts, it reloads this to resume correctly.
///
/// Raft safety depends on:
/// - `current_term` never going backward.
/// - `voted_for` preventing double-votes within a single term.
/// - The log being durable so committed entries are never lost.
#[derive(Debug, Clone)]
pub struct PersistentState {
    /// Latest term this server has seen. Starts at 0, increases monotonically.
    pub current_term: Term,

    /// Candidate that received our vote in `current_term`, or `None` if we
    /// haven't voted yet this term. Reset to `None` whenever `current_term`
    /// advances (a new term is a fresh election epoch).
    pub voted_for: Option<NodeId>,
}

impl PersistentState {
    pub fn new() -> Self {
        Self {
            current_term: 0,
            voted_for: None,
        }
    }
}

impl Default for PersistentState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Volatile state ──

/// State that is safe to lose on crash — it can be reconstructed by replaying
/// the log from the beginning.
#[derive(Debug, Clone)]
pub struct VolatileState {
    /// Index of the highest log entry known to be committed (replicated on a
    /// majority). Entries up to this index are safe to apply. Starts at 0,
    /// increases monotonically.
    pub commit_index: LogIndex,

    /// Index of the highest log entry applied to the state machine. Always
    /// satisfies `last_applied <= commit_index`. The gap between the two is
    /// the set of entries waiting to be applied.
    pub last_applied: LogIndex,
}

impl VolatileState {
    pub fn new() -> Self {
        Self {
            commit_index: 0,
            last_applied: 0,
        }
    }
}

impl Default for VolatileState {
    fn default() -> Self {
        Self::new()
    }
}
