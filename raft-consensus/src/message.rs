//! RPC message definitions for Raft.
//!
//! These correspond directly to the two RPCs defined in Figure 2 of the Raft paper:
//! - **RequestVote**: sent by candidates during elections.
//! - **AppendEntries**: sent by leaders for both heartbeats and log replication.
//!
//! Messages are wrapped in an `Envelope` that carries routing metadata (from, to)
//! and the sender's term. The transport layer delivers envelopes; the Raft node
//! never deals with serialization or networking.

use crate::log::LogEntry;
use crate::state::{LogIndex, NodeId, Term};

/// Routable message wrapper.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub from: NodeId,
    pub to: NodeId,
    /// The sender's current term at the time of sending. Every Raft RPC carries
    /// a term; the receiver uses it to detect stale leaders/candidates.
    pub term: Term,
    pub payload: Rpc,
}

/// The set of all Raft RPCs.
#[derive(Debug, Clone)]
pub enum Rpc {
    RequestVote(RequestVoteArgs),
    RequestVoteResponse(RequestVoteReply),
    AppendEntries(AppendEntriesArgs),
    AppendEntriesResponse(AppendEntriesReply),
}

// ── RequestVote RPC (§5.2) ──

/// Sent by a candidate to request a vote from a peer.
#[derive(Debug, Clone)]
pub struct RequestVoteArgs {
    /// The candidate requesting the vote.
    pub candidate_id: NodeId,
    /// Index of the candidate's last log entry — used for the "at least as
    /// up-to-date" check (§5.4.1).
    pub last_log_index: LogIndex,
    /// Term of the candidate's last log entry.
    pub last_log_term: Term,
}

/// Response to a RequestVote RPC.
#[derive(Debug, Clone)]
pub struct RequestVoteReply {
    /// True if the peer granted its vote.
    pub vote_granted: bool,
}

// ── AppendEntries RPC (§5.3) ──

/// Sent by the leader to replicate log entries and serve as a heartbeat.
/// An empty `entries` vec is a heartbeat.
#[derive(Debug, Clone)]
pub struct AppendEntriesArgs {
    /// So followers can redirect clients.
    pub leader_id: NodeId,
    /// Index of the log entry immediately preceding the new ones. The follower
    /// uses this + `prev_log_term` to verify log consistency.
    pub prev_log_index: LogIndex,
    /// Term of the entry at `prev_log_index`.
    pub prev_log_term: Term,
    /// Log entries to replicate (empty for heartbeat).
    pub entries: Vec<LogEntry>,
    /// The leader's commit index. Followers use this to advance their own
    /// commit index: `min(leader_commit, index of last new entry)`.
    pub leader_commit: LogIndex,
}

/// Response to an AppendEntries RPC.
#[derive(Debug, Clone)]
pub struct AppendEntriesReply {
    /// True if the follower's log matched at `prev_log_index` and the entries
    /// were successfully appended.
    pub success: bool,
    /// Optimization (§5.3): on failure, the follower tells the leader the
    /// index of the first entry in the conflicting term so the leader can
    /// skip backward faster than one entry at a time.
    pub conflict_index: Option<LogIndex>,
    /// The term of the conflicting entry, if any.
    pub conflict_term: Option<Term>,
}
