//! RPC message definitions for Raft.
//!
//! These correspond directly to the two RPCs defined in Figure 2 of the Raft paper:
//! - **RequestVote**: sent by candidates during elections.
//! - **AppendEntries**: sent by leaders for both heartbeats and log replication.
//!
//! Each RPC struct carries its own `term` field, making it self-contained for
//! wire serialization. The `Envelope` wrapper adds routing metadata (`from`, `to`)
//! for in-process message delivery; the transport layer adds or strips it as needed.
//!
//! ## Serialization
//!
//! All types derive `serde::Serialize` / `serde::Deserialize` for easy integration
//! with any serde-compatible format (bincode, JSON, MessagePack, etc.). For a
//! hand-rolled compact binary encoding see the `wire` module.

use serde::{Deserialize, Serialize};

use crate::log::LogEntry;
use crate::state::{LogIndex, NodeId, Term};

// ── Envelope (internal routing) ──

/// Routable message wrapper used for in-process delivery between Raft nodes.
///
/// The `Envelope` itself is NOT part of the Raft wire protocol. It is a local
/// transport abstraction: the simulator and test harness use it to route messages
/// between nodes. A real network transport would serialize only the `Rpc` payload
/// and reconstruct the envelope on the receiving end.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub from: NodeId,
    pub to: NodeId,
    pub payload: Rpc,
}

impl Envelope {
    /// Extract the term from the inner RPC payload. Every Raft RPC carries a
    /// term; the receiver uses it to detect stale leaders/candidates.
    pub fn term(&self) -> Term {
        self.payload.term()
    }
}

// ── Rpc ──

/// The set of all Raft RPCs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Rpc {
    RequestVote(RequestVoteArgs),
    RequestVoteResponse(RequestVoteReply),
    AppendEntries(AppendEntriesArgs),
    AppendEntriesResponse(AppendEntriesReply),
    PreVote(PreVoteArgs),
    PreVoteResponse(PreVoteReply),
}

impl Rpc {
    /// Return the term carried by this RPC, regardless of variant.
    pub fn term(&self) -> Term {
        match self {
            Rpc::RequestVote(args) => args.term,
            Rpc::RequestVoteResponse(reply) => reply.term,
            Rpc::AppendEntries(args) => args.term,
            Rpc::AppendEntriesResponse(reply) => reply.term,
            Rpc::PreVote(args) => args.term,
            Rpc::PreVoteResponse(reply) => reply.term,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  RequestVote RPC (§5.2)
// ════════════════════════════════════════════════════════════════════════════

/// Sent by a candidate to request a vote from a peer.
///
/// Wire layout (see `wire` module):
/// ```text
/// [term: u64] [candidate_id: u64] [last_log_index: u64] [last_log_term: u64]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteArgs {
    /// The candidate's current term.
    pub term: Term,
    /// The candidate requesting the vote.
    pub candidate_id: NodeId,
    /// Index of the candidate's last log entry — used for the "at least as
    /// up-to-date" check (§5.4.1).
    pub last_log_index: LogIndex,
    /// Term of the candidate's last log entry.
    pub last_log_term: Term,
}

/// Response to a RequestVote RPC.
///
/// Wire layout:
/// ```text
/// [term: u64] [vote_granted: u8]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteReply {
    /// The responder's current term, so the candidate can update itself.
    pub term: Term,
    /// True if the peer granted its vote.
    pub vote_granted: bool,
}

// ════════════════════════════════════════════════════════════════════════════
//  AppendEntries RPC (§5.3)
// ════════════════════════════════════════════════════════════════════════════

/// Sent by the leader to replicate log entries and serve as a heartbeat.
/// An empty `entries` vec is a heartbeat.
///
/// Wire layout:
/// ```text
/// [term: u64] [leader_id: u64] [prev_log_index: u64] [prev_log_term: u64]
/// [leader_commit: u64] [entry_count: u32] [entries...]
/// ```
///
/// Each entry: `[term: u64] [data_len: u32] [data: bytes]`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesArgs {
    /// The leader's current term.
    pub term: Term,
    /// So followers can redirect clients to the leader.
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
///
/// On **success**, `match_index` reports the highest log index the follower has
/// replicated — the leader uses this to advance its `match_index[peer]` and
/// check for new commits.
///
/// On **failure**, `match_index` is a hint: the highest index where the follower
/// believes its log matches the leader's. The leader sets
/// `next_index[peer] = match_index + 1` and retries. This allows the follower
/// to skip entire conflicting terms in a single round trip rather than
/// decrementing one entry at a time.
///
/// Wire layout:
/// ```text
/// [term: u64] [success: u8] [match_index: u64]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesReply {
    /// The responder's current term, so the leader can update itself.
    pub term: Term,
    /// True if the follower's log matched at `prev_log_index` and the entries
    /// were successfully appended.
    pub success: bool,
    /// On success: index of the last replicated entry.
    /// On failure: hint for the leader — highest index the follower can confirm
    /// as matching, enabling fast log backtracking.
    pub match_index: LogIndex,
}

// ════════════════════════════════════════════════════════════════════════════
//  PreVote RPC (§9.6 — Raft dissertation, not in the original paper)
// ════════════════════════════════════════════════════════════════════════════

/// Pre-vote request — a speculative election probe.
///
/// Before incrementing its term and starting a real election, a candidate
/// sends PreVote to all peers. If a majority would grant the vote, the
/// candidate proceeds to a real election. Otherwise it stays as a follower,
/// avoiding term inflation that disrupts the cluster.
///
/// This prevents a partitioned node from bumping its term repeatedly and
/// forcing the rest of the cluster to step down when it rejoins.
///
/// The `term` field is the term the candidate *would* use (current_term + 1),
/// but the candidate does NOT actually increment its term yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreVoteArgs {
    /// The term the candidate would campaign in (current_term + 1).
    pub term: Term,
    /// The node requesting the pre-vote.
    pub candidate_id: NodeId,
    /// Index of the candidate's last log entry.
    pub last_log_index: LogIndex,
    /// Term of the candidate's last log entry.
    pub last_log_term: Term,
}

/// Response to a PreVote RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreVoteReply {
    /// The responder's current term.
    pub term: Term,
    /// True if the responder would grant a real vote.
    pub vote_granted: bool,
}
