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
    InstallSnapshot(InstallSnapshotArgs),
    InstallSnapshotResponse(InstallSnapshotReply),
    /// Sent by a follower to the known leader to initiate a linearizable read
    /// without touching the log (§8). The `reader_id` field lets the leader
    /// send the response directly to the originating follower.
    ReadIndexRequest(ReadIndexArgs),
    /// Leader's response once it has confirmed its leadership via a heartbeat
    /// quorum.  `read_index` is the commit index the caller must wait for;
    /// `0` means the leader rejected the request (it is no longer a leader).
    ReadIndexResponse(ReadIndexReply),
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
            Rpc::InstallSnapshot(args) => args.term,
            Rpc::InstallSnapshotResponse(reply) => reply.term,
            Rpc::ReadIndexRequest(args) => args.term,
            Rpc::ReadIndexResponse(reply) => reply.term,
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

// ════════════════════════════════════════════════════════════════════════════
//  InstallSnapshot RPC (§7)
// ════════════════════════════════════════════════════════════════════════════

/// Sent by the leader to bring a lagging follower up to date via a snapshot.
///
/// Raft snapshots can be large, so the protocol supports **chunked transfer**:
/// the leader splits the snapshot data into chunks and sends each chunk as a
/// separate `InstallSnapshot` RPC. `offset` gives each chunk's byte position
/// within the complete snapshot, and `done` marks the final chunk.
///
/// The receiving follower buffers chunks keyed by `offset` and, once `done`
/// is seen, assembles and installs the snapshot. Any existing log entries up
/// through `last_included_index` are then discarded.
///
/// Wire layout (see `wire` module):
/// ```text
/// [term: u64] [leader_id: u64] [last_included_index: u64] [last_included_term: u64]
/// [offset: u64] [data_len: u32] [data: bytes] [done: u8]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallSnapshotArgs {
    /// The leader's current term.
    pub term: Term,
    /// The leader's node ID, so the follower can redirect clients.
    pub leader_id: NodeId,
    /// Index of the last log entry covered by this snapshot. After installing
    /// the snapshot, the follower discards all log entries up to and including
    /// this index.
    pub last_included_index: LogIndex,
    /// Term of the entry at `last_included_index`. Used to satisfy AppendEntries
    /// log-consistency checks that probe the snapshot boundary.
    pub last_included_term: Term,
    /// Byte offset of this chunk within the complete snapshot.
    /// Zero for the first (or only) chunk.
    pub offset: u64,
    /// Raw snapshot bytes for this chunk.
    pub data: Vec<u8>,
    /// `true` if this is the final chunk of the snapshot.
    pub done: bool,
}

/// Response to an `InstallSnapshot` RPC.
///
/// The follower sends its current term so the leader can step down if it has
/// become stale.
///
/// Wire layout:
/// ```text
/// [term: u64]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallSnapshotReply {
    /// The responder's current term, for the leader to update itself if stale.
    pub term: Term,
}

// ════════════════════════════════════════════════════════════════════════════
//  ReadIndex RPCs (§8 — linearizable reads without log writes)
// ════════════════════════════════════════════════════════════════════════════

/// Sent by a follower (or a local client proxy) to the leader to initiate a
/// linearizable read.  The leader performs a heartbeat quorum round and replies
/// with the commit index the caller must wait for before executing its read.
///
/// Handled before the universal term check in `RaftNode::step()` — like
/// PreVote, this is an out-of-band exchange that must not trigger step-down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadIndexArgs {
    /// Sender's current term — carried so `Rpc::term()` compiles without
    /// special-casing; the receiver bypasses the universal term check for
    /// this message type.
    pub term: Term,
    /// Node ID of the originating reader.  The leader sends its reply
    /// directly to this node.
    pub reader_id: NodeId,
}

/// Response from the leader once it has confirmed its leadership via a
/// heartbeat quorum (or immediately when it has already heard from a quorum
/// during the current heartbeat cycle).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadIndexReply {
    /// The leader's current term at confirmation time.
    pub term: Term,
    /// The safe commit index: the caller must wait until
    /// `last_applied >= read_index` before executing the read.
    /// `0` indicates the responder is not the leader and the request was
    /// rejected — the caller should retry after locating the current leader.
    pub read_index: LogIndex,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──

    fn make_args(done: bool, offset: u64, data: Vec<u8>) -> InstallSnapshotArgs {
        InstallSnapshotArgs {
            term: 5,
            leader_id: 1,
            last_included_index: 42,
            last_included_term: 3,
            offset,
            data,
            done,
        }
    }

    // ── InstallSnapshotArgs: field correctness ──

    #[test]
    fn install_snapshot_args_fields_preserved() {
        let args = InstallSnapshotArgs {
            term: 7,
            leader_id: 2,
            last_included_index: 100,
            last_included_term: 6,
            offset: 0,
            data: vec![1, 2, 3],
            done: true,
        };
        assert_eq!(args.term, 7);
        assert_eq!(args.leader_id, 2);
        assert_eq!(args.last_included_index, 100);
        assert_eq!(args.last_included_term, 6);
        assert_eq!(args.offset, 0);
        assert_eq!(args.data, vec![1, 2, 3]);
        assert!(args.done);
    }

    #[test]
    fn install_snapshot_args_done_false() {
        let args = make_args(false, 0, vec![0xAB]);
        assert!(!args.done);
    }

    #[test]
    fn install_snapshot_args_non_zero_offset() {
        let args = make_args(false, 4096, vec![0u8; 16]);
        assert_eq!(args.offset, 4096);
        assert_eq!(args.data.len(), 16);
    }

    #[test]
    fn install_snapshot_args_empty_data() {
        let args = make_args(true, 0, vec![]);
        assert!(args.data.is_empty());
    }

    // ── InstallSnapshotReply: field correctness ──

    #[test]
    fn install_snapshot_reply_field_preserved() {
        let reply = InstallSnapshotReply { term: 9 };
        assert_eq!(reply.term, 9);
    }

    // ── Rpc::term() for new variants ──

    #[test]
    fn rpc_term_install_snapshot() {
        let rpc = Rpc::InstallSnapshot(make_args(true, 0, vec![]));
        assert_eq!(rpc.term(), 5);
    }

    #[test]
    fn rpc_term_install_snapshot_response() {
        let rpc = Rpc::InstallSnapshotResponse(InstallSnapshotReply { term: 12 });
        assert_eq!(rpc.term(), 12);
    }

    // ── Envelope::term() for new variants ──

    #[test]
    fn envelope_term_install_snapshot() {
        let env = Envelope {
            from: 1,
            to: 2,
            payload: Rpc::InstallSnapshot(make_args(true, 0, vec![])),
        };
        assert_eq!(env.term(), 5);
    }

    #[test]
    fn envelope_term_install_snapshot_response() {
        let env = Envelope {
            from: 2,
            to: 1,
            payload: Rpc::InstallSnapshotResponse(InstallSnapshotReply { term: 8 }),
        };
        assert_eq!(env.term(), 8);
    }

    // ── Serde roundtrips ──

    #[test]
    fn install_snapshot_args_serde_roundtrip() {
        let args = InstallSnapshotArgs {
            term: 5,
            leader_id: 1,
            last_included_index: 42,
            last_included_term: 3,
            offset: 1024,
            data: vec![10, 20, 30],
            done: false,
        };
        let json = serde_json::to_string(&args).unwrap();
        let decoded: InstallSnapshotArgs = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, args);
    }

    #[test]
    fn install_snapshot_args_done_flag_serde_roundtrip() {
        for done in [true, false] {
            let args = make_args(done, 0, vec![1]);
            let json = serde_json::to_string(&args).unwrap();
            let decoded: InstallSnapshotArgs = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded.done, done);
        }
    }

    #[test]
    fn install_snapshot_args_empty_data_serde_roundtrip() {
        let args = make_args(true, 0, vec![]);
        let json = serde_json::to_string(&args).unwrap();
        let decoded: InstallSnapshotArgs = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, args);
    }

    #[test]
    fn install_snapshot_args_large_offset_serde_roundtrip() {
        let args = make_args(false, u64::MAX, vec![0xFF]);
        let json = serde_json::to_string(&args).unwrap();
        let decoded: InstallSnapshotArgs = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.offset, u64::MAX);
    }

    #[test]
    fn install_snapshot_reply_serde_roundtrip() {
        let reply = InstallSnapshotReply { term: 99 };
        let json = serde_json::to_string(&reply).unwrap();
        let decoded: InstallSnapshotReply = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, reply);
    }

    #[test]
    fn rpc_install_snapshot_serde_roundtrip() {
        let rpc = Rpc::InstallSnapshot(InstallSnapshotArgs {
            term: 4,
            leader_id: 3,
            last_included_index: 50,
            last_included_term: 2,
            offset: 0,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            done: true,
        });
        let json = serde_json::to_string(&rpc).unwrap();
        let decoded: Rpc = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.term(), 4);
        if let Rpc::InstallSnapshot(args) = decoded {
            assert_eq!(args.last_included_index, 50);
            assert_eq!(args.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
            assert!(args.done);
        } else {
            panic!("expected InstallSnapshot variant");
        }
    }

    #[test]
    fn rpc_install_snapshot_response_serde_roundtrip() {
        let rpc = Rpc::InstallSnapshotResponse(InstallSnapshotReply { term: 7 });
        let json = serde_json::to_string(&rpc).unwrap();
        let decoded: Rpc = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.term(), 7);
        assert!(matches!(decoded, Rpc::InstallSnapshotResponse(_)));
    }

    // ── Backward-compatibility: existing variants still serialize correctly ──

    #[test]
    fn existing_rpc_variants_still_round_trip_via_serde() {
        let variants: Vec<Rpc> = vec![
            Rpc::RequestVote(RequestVoteArgs {
                term: 1, candidate_id: 1, last_log_index: 0, last_log_term: 0,
            }),
            Rpc::RequestVoteResponse(RequestVoteReply { term: 1, vote_granted: true }),
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1, leader_id: 1, prev_log_index: 0, prev_log_term: 0,
                entries: vec![], leader_commit: 0,
            }),
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1, success: true, match_index: 0,
            }),
            Rpc::PreVote(PreVoteArgs {
                term: 2, candidate_id: 2, last_log_index: 1, last_log_term: 1,
            }),
            Rpc::PreVoteResponse(PreVoteReply { term: 2, vote_granted: false }),
        ];
        for rpc in variants {
            let term = rpc.term();
            let json = serde_json::to_string(&rpc).unwrap();
            let decoded: Rpc = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded.term(), term);
        }
    }
}
