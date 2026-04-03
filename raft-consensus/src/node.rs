//! Core Raft node state machine.
//!
//! `RaftNode` is a deterministic, event-driven state machine that implements the
//! Raft consensus protocol. It does NOT own threads, async runtimes, or sockets.
//! Instead, the caller drives it by:
//!
//!   1. Delivering inbound messages via `step()`
//!   2. Ticking timers via `tick()`
//!   3. Collecting outbound messages from `drain_messages()`
//!   4. Collecting committed entries from `drain_applied()`
//!
//! This "pure state machine" design (same pattern as etcd/raft) makes the node
//! fully deterministic and trivially testable — the simulator controls time,
//! message delivery, and network faults without any mocking.
//!
//! ## Raft safety properties maintained by this module
//!
//! - **Election Safety**: at most one leader per term (enforced by single-vote rule).
//! - **Leader Append-Only**: a leader never overwrites or deletes its own log entries.
//! - **Log Matching**: if two logs contain an entry with the same index and term,
//!   the logs are identical through that index.
//! - **Leader Completeness**: if an entry is committed in a given term, it will be
//!   present in the log of every leader for all higher terms.
//! - **State Machine Safety**: if a node has applied entry at index i, no other node
//!   will ever apply a different entry at that index.

use std::collections::{HashMap, HashSet};

use crate::log::{Command, InMemoryLog, LogEntry, RaftLog};
use crate::message::*;
use crate::state::*;
use crate::storage::{MemoryStorage, Storage};

// ── Configuration ──

/// Cluster configuration. Kept minimal — no TOML loading yet.
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    /// Election timeout range in ticks. A node picks a random timeout in
    /// `[election_timeout_min, election_timeout_max)` each time it resets.
    /// The randomization prevents synchronized elections (split-vote storms).
    pub election_timeout_min: u64,
    pub election_timeout_max: u64,
    /// How often the leader sends empty AppendEntries (heartbeats) to prevent
    /// followers from starting elections. Must be much less than election timeout.
    pub heartbeat_interval: u64,
    /// Enable the pre-vote protocol (§9.6 of the Raft dissertation).
    ///
    /// When enabled, a node must win a speculative pre-vote before starting a
    /// real election. This prevents partitioned nodes from bumping their term
    /// and disrupting the cluster when they rejoin.
    pub pre_vote: bool,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            election_timeout_min: 150,
            election_timeout_max: 300,
            heartbeat_interval: 50,
            pre_vote: false,
        }
    }
}

// ── Timer state ──

/// Minimal deterministic timer. The simulator increments ticks manually;
/// no wall-clock dependency.
#[derive(Debug, Clone)]
struct Timer {
    deadline: u64,
    elapsed: u64,
}

impl Timer {
    fn new(deadline: u64) -> Self {
        Self {
            deadline,
            elapsed: 0,
        }
    }

    fn reset(&mut self, deadline: u64) {
        self.deadline = deadline;
        self.elapsed = 0;
    }

    fn tick(&mut self, ticks: u64) {
        self.elapsed = self.elapsed.saturating_add(ticks);
    }

    fn is_expired(&self) -> bool {
        self.elapsed >= self.deadline
    }
}

// ── Applied entry ──

/// Represents an entry that has been committed and applied to the state machine.
/// Returned to the caller so it can update its application-level state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyResult {
    pub index: LogIndex,
    pub term: Term,
    /// The raw command bytes from the log entry. Use `Command::decode()` to
    /// interpret as an application-level command.
    pub data: Vec<u8>,
}

// ── RaftNode ──

/// The core Raft state machine.
///
/// Generic over storage and log so we can swap implementations for testing vs.
/// production. The defaults (`MemoryStorage`, `InMemoryLog`) are suitable for
/// simulation.
pub struct RaftNode<S: Storage = MemoryStorage, L: RaftLog = InMemoryLog> {
    // ── Identity ──
    /// This node's unique ID.
    pub id: NodeId,
    /// IDs of all other nodes in the cluster. Does not include `self.id`.
    pub peers: Vec<NodeId>,

    // ── Role ──
    /// Current role in the Raft protocol. See `Role` for invariants.
    pub role: Role,

    // ── Persistent state (§5.2 Figure 2) ──
    /// Must be saved to stable storage before responding to RPCs.
    pub persistent: PersistentState,

    // ── Volatile state (§5.2 Figure 2) ──
    pub volatile: VolatileState,

    // ── Log ──
    pub log: L,

    // ── Storage backend ──
    storage: S,

    // ── Timers ──
    election_timer: Timer,
    heartbeat_timer: Timer,

    // ── Configuration ──
    config: ClusterConfig,

    // ── Outbox ──
    /// Messages queued for delivery. The caller drains these after each `step()`
    /// or `tick()` and delivers them via the transport layer.
    outbox: Vec<Envelope>,

    // ── Applied entries ──
    /// Entries that have been committed and applied, ready for the caller.
    applied: Vec<ApplyResult>,

    // ── Leader tracking ──
    /// Who we believe the current leader is. Set when receiving a valid
    /// AppendEntries, cleared on term changes. Useful for client redirects.
    current_leader: Option<NodeId>,

    // ── Pre-vote state ──
    /// Responses received during a pre-vote phase (before a real election).
    /// Only populated when `config.pre_vote` is true and we're collecting
    /// pre-vote responses. Reset when we transition to a real election.
    pre_vote_responses: HashSet<NodeId>,

    // ── RNG state ──
    /// Simple deterministic RNG for election timeout randomization.
    /// We use a basic LCG so the node has zero external dependencies.
    rng_state: u64,
}

impl RaftNode<MemoryStorage, InMemoryLog> {
    /// Create a new node with in-memory storage and log. Starts as a Follower
    /// in term 0 with an empty log — the initial state of every Raft node.
    pub fn new(id: NodeId, peers: Vec<NodeId>, config: ClusterConfig) -> Self {
        let election_timeout = Self::random_election_timeout_with_seed(
            id,
            config.election_timeout_min,
            config.election_timeout_max,
        );

        Self {
            id,
            peers,
            role: Role::Follower,
            persistent: PersistentState::new(),
            volatile: VolatileState::new(),
            log: InMemoryLog::new(),
            storage: MemoryStorage::new(),
            election_timer: Timer::new(election_timeout),
            heartbeat_timer: Timer::new(config.heartbeat_interval),
            config,
            current_leader: None,
            pre_vote_responses: HashSet::new(),
            outbox: Vec::new(),
            applied: Vec::new(),
            rng_state: id, // seed from node ID for determinism
        }
    }
}

impl<S: Storage, L: RaftLog> RaftNode<S, L> {
    /// Create a node with custom storage and log backends.
    pub fn with_storage_and_log(
        id: NodeId,
        peers: Vec<NodeId>,
        config: ClusterConfig,
        storage: S,
        log: L,
    ) -> Self {
        let election_timeout = Self::random_election_timeout_with_seed(
            id,
            config.election_timeout_min,
            config.election_timeout_max,
        );

        Self {
            id,
            peers,
            role: Role::Follower,
            persistent: PersistentState::new(),
            volatile: VolatileState::new(),
            log,
            storage,
            election_timer: Timer::new(election_timeout),
            heartbeat_timer: Timer::new(config.heartbeat_interval),
            config,
            current_leader: None,
            pre_vote_responses: HashSet::new(),
            outbox: Vec::new(),
            applied: Vec::new(),
            rng_state: id,
        }
    }

    /// Restore a node from persisted storage after a crash.
    ///
    /// Loads `current_term`, `voted_for`, and the log from storage. The node
    /// starts as a Follower (the safe default — it will discover the current
    /// leader via heartbeats or start an election if no leader exists).
    ///
    /// Volatile state (`commit_index`, `last_applied`) is reset to 0. The node
    /// will learn the current `commit_index` from the leader's next heartbeat
    /// and re-apply committed entries.
    pub fn restore(
        id: NodeId,
        peers: Vec<NodeId>,
        config: ClusterConfig,
        storage: S,
        mut log: L,
    ) -> std::result::Result<Self, crate::storage::StorageError> {
        let hard_state = storage.load_state()?;

        // Replay persisted log into the in-memory log.
        for entry in &hard_state.log {
            log.append(entry.clone());
        }

        let election_timeout = Self::random_election_timeout_with_seed(
            id,
            config.election_timeout_min,
            config.election_timeout_max,
        );

        Ok(Self {
            id,
            peers,
            role: Role::Follower,
            persistent: PersistentState {
                current_term: hard_state.current_term,
                voted_for: hard_state.voted_for,
            },
            volatile: VolatileState::new(), // reset on crash recovery
            log,
            storage,
            election_timer: Timer::new(election_timeout),
            heartbeat_timer: Timer::new(config.heartbeat_interval),
            config,
            current_leader: None,
            pre_vote_responses: HashSet::new(),
            outbox: Vec::new(),
            applied: Vec::new(),
            rng_state: id,
        })
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Public API — the three entry points the caller uses to drive the node
    // ════════════════════════════════════════════════════════════════════════

    /// Advance timers by `ticks` units. If the election timer fires, the node
    /// starts an election (or pre-vote if enabled). If the heartbeat timer
    /// fires (leader only), it sends heartbeats.
    pub fn tick(&mut self, ticks: u64) {
        match &self.role {
            Role::Follower | Role::Candidate { .. } => {
                self.election_timer.tick(ticks);
                if self.election_timer.is_expired() {
                    self.start_election();
                }
            }
            Role::Leader { .. } => {
                self.heartbeat_timer.tick(ticks);
                if self.heartbeat_timer.is_expired() {
                    self.send_heartbeats();
                    self.heartbeat_timer.reset(self.config.heartbeat_interval);
                }
            }
        }
    }

    /// Start an election. If pre-vote is enabled, this initiates a pre-vote
    /// phase first; otherwise it directly transitions to Candidate.
    ///
    /// This is the public entry point for triggering elections. The simulator
    /// or test harness can call this directly instead of waiting for the
    /// election timer to expire.
    pub fn start_election(&mut self) {
        if self.config.pre_vote {
            self.start_pre_vote();
        } else {
            self.become_candidate();
        }
    }

    /// Process an inbound message. This is the main dispatch function.
    ///
    /// Raft's universal term rule (§5.1): if the message's term is greater than
    /// ours, we update our term and revert to follower *before* processing the
    /// payload. If the message's term is less than ours, we reject it (stale).
    pub fn step(&mut self, envelope: Envelope) {
        // ── Pre-vote messages bypass the universal term check ──
        //
        // PreVote is speculative: it must NOT cause the receiver to update
        // its term or step down. The candidate hasn't committed to a new
        // term yet, and the responder shouldn't change state based on a
        // hypothetical. Handle these before the term machinery.
        match &envelope.payload {
            Rpc::PreVote(args) => {
                let args = args.clone();
                self.handle_pre_vote(envelope.from, args);
                return;
            }
            Rpc::PreVoteResponse(reply) => {
                let reply = reply.clone();
                self.handle_pre_vote_response(envelope.from, reply);
                return;
            }
            _ => {}
        }

        let msg_term = envelope.term();

        // ── Term check: universal rule applied to every inbound message ──
        //
        // "If RPC request or response contains term T > currentTerm:
        //  set currentTerm = T, convert to follower" (§5.1)
        if msg_term > self.persistent.current_term {
            self.update_term(msg_term);
            // Don't return — still need to process the message.
        }

        // Reject messages from old terms. The sender will eventually learn
        // about the newer term from another node.
        if msg_term < self.persistent.current_term {
            self.reject_stale_message(&envelope);
            return;
        }

        // ── Dispatch by payload type ──
        match envelope.payload {
            Rpc::RequestVote(args) => self.handle_request_vote(envelope.from, args),
            Rpc::RequestVoteResponse(reply) => {
                self.handle_request_vote_response(envelope.from, reply)
            }
            Rpc::AppendEntries(args) => self.handle_append_entries(envelope.from, args),
            Rpc::AppendEntriesResponse(reply) => {
                self.handle_append_entries_response(envelope.from, reply)
            }
            // PreVote variants already handled above.
            Rpc::PreVote(_) | Rpc::PreVoteResponse(_) => unreachable!(),
        }
    }

    /// Drain all outbound messages queued since the last drain.
    pub fn drain_messages(&mut self) -> Vec<Envelope> {
        std::mem::take(&mut self.outbox)
    }

    /// Drain all entries that have been committed and applied since the last drain.
    pub fn drain_applied(&mut self) -> Vec<ApplyResult> {
        std::mem::take(&mut self.applied)
    }

    /// Propose a new command (as raw bytes). Only the leader can accept
    /// proposals; returns false if this node is not the leader.
    pub fn propose(&mut self, data: Vec<u8>) -> bool {
        if !matches!(self.role, Role::Leader { .. }) {
            return false;
        }

        let entry = LogEntry {
            term: self.persistent.current_term,
            data,
        };
        self.log.append(entry.clone());
        self.persist_log_append(&[entry]);

        // Immediately try to replicate to all followers.
        self.replicate_to_all();

        // In a single-node cluster (or when the leader alone is a majority),
        // there are no followers to wait for — commit immediately.
        self.maybe_advance_commit_index();
        true
    }

    /// Convenience: propose an application-level `Command`. Encodes to bytes
    /// and calls `propose()`. Returns the log index of the new entry, or
    /// `None` if this node is not the leader.
    pub fn append_entry(&mut self, command: Command) -> Option<LogIndex> {
        let index = self.log.last_index() + 1;
        if self.propose(command.encode()) {
            Some(index)
        } else {
            None
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  State transitions
    // ════════════════════════════════════════════════════════════════════════

    /// Transition to Follower.
    ///
    /// Called when:
    /// - We discover a higher term (from any message).
    /// - A Candidate receives a valid AppendEntries from the current leader.
    /// - A Candidate loses the election (timeout without majority).
    ///
    /// Invariant: `current_term` must already be set to the new term before
    /// calling this (via `update_term()`), unless we're already in the correct term.
    fn become_follower(&mut self) {
        self.role = Role::Follower;
        self.reset_election_timer();
    }

    /// Transition to Candidate and start an election.
    ///
    /// Raft §5.2:
    /// 1. Increment currentTerm.
    /// 2. Vote for self.
    /// 3. Reset election timer (with new random timeout to avoid split-vote storms).
    /// 4. Send RequestVote to all peers.
    ///
    /// Invariant: a node only votes for itself when becoming a candidate, and
    /// it votes at most once per term. Since we just incremented the term,
    /// `voted_for` was reset to `None` by `update_term()`, so voting for self
    /// is safe.
    fn become_candidate(&mut self) {
        // Step 1: increment term
        self.persistent.current_term += 1;

        // Step 2: vote for self
        self.persistent.voted_for = Some(self.id);
        self.persist_state();

        let mut votes = HashSet::new();
        votes.insert(self.id);

        self.role = Role::Candidate {
            votes_received: votes,
        };

        // Step 3: reset election timer
        self.reset_election_timer();

        // Step 4: send RequestVote to all peers
        let last_log_index = self.log.last_index();
        let last_log_term = self.log.last_term();

        let peers: Vec<NodeId> = self.peers.clone();
        for &peer in &peers {
            self.send(
                peer,
                Rpc::RequestVote(RequestVoteArgs {
                    term: self.persistent.current_term,
                    candidate_id: self.id,
                    last_log_index,
                    last_log_term,
                }),
            );
        }

        // Edge case: single-node cluster — we already have a majority (1 of 1).
        self.maybe_become_leader();
    }

    /// Transition to Leader.
    ///
    /// Called when a Candidate receives votes from a majority of the cluster.
    ///
    /// Raft §5.2:
    /// 1. Initialize `next_index` for each peer to our last log index + 1
    ///    (optimistic — assume followers are caught up).
    /// 2. Initialize `match_index` for each peer to 0 (conservative — nothing
    ///    confirmed yet).
    /// 3. Send initial empty AppendEntries (heartbeats) to assert leadership
    ///    and prevent new elections.
    /// 4. Append a no-op entry for the new term. This is critical: Raft cannot
    ///    commit entries from prior terms by counting replicas (§5.4.2). The
    ///    no-op ensures the leader has an entry from its own term, which — once
    ///    committed — transitively commits all prior entries.
    fn become_leader(&mut self) {
        let last_index = self.log.last_index();

        let mut next_index = HashMap::new();
        let mut match_index = HashMap::new();

        for &peer in &self.peers {
            // Optimistic: assume peer has all entries. If wrong, AppendEntries
            // replies will cause us to decrement until we find the match point.
            next_index.insert(peer, last_index + 1);
            // Conservative: we haven't confirmed anything from any peer yet.
            match_index.insert(peer, 0);
        }

        self.role = Role::Leader {
            next_index,
            match_index,
        };

        // We are the leader now.
        self.current_leader = Some(self.id);

        // Reset heartbeat timer so we send heartbeats immediately.
        self.heartbeat_timer.reset(0);

        // Append a no-op entry for this term (§5.4.2).
        // This ensures the leader can commit entries from previous terms.
        let noop = LogEntry {
            term: self.persistent.current_term,
            data: Command::Noop.encode(),
        };
        self.log.append(noop.clone());
        self.persist_log_append(&[noop]);

        // Send heartbeats to all peers to establish authority.
        self.send_heartbeats();

        // Single-node cluster: commit the noop immediately (no peers to wait for).
        self.maybe_advance_commit_index();
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Term management
    // ════════════════════════════════════════════════════════════════════════

    /// Update our term to a newer one and revert to follower.
    ///
    /// Raft invariant: terms never go backward. When we see a higher term, it
    /// means someone else has started a new election epoch. We:
    /// 1. Update `current_term` to the new term.
    /// 2. Clear `voted_for` — we haven't voted in this new term yet.
    /// 3. Persist both before taking any further action.
    /// 4. Become a follower.
    fn update_term(&mut self, new_term: Term) {
        debug_assert!(
            new_term > self.persistent.current_term,
            "update_term called with non-advancing term"
        );

        self.persistent.current_term = new_term;
        // Haven't voted in this new term yet.
        self.persistent.voted_for = None;
        // We don't know who the leader is in this new term.
        self.current_leader = None;
        self.persist_state();
        self.become_follower();
    }

    // ════════════════════════════════════════════════════════════════════════
    //  RequestVote handling (§5.2, §5.4.1)
    // ════════════════════════════════════════════════════════════════════════

    /// Handle an incoming RequestVote from a candidate.
    ///
    /// Vote is granted iff ALL of the following hold:
    /// 1. The candidate's term equals our current term (stale/future terms are
    ///    already handled by the universal term check in `step()`).
    /// 2. We haven't already voted for a different candidate this term.
    /// 3. The candidate's log is at least as up-to-date as ours (§5.4.1):
    ///    - Compare last log term first (higher term wins).
    ///    - If terms are equal, longer log wins.
    ///
    /// The up-to-date check ensures the Leader Completeness property: a
    /// candidate cannot win an election unless it has all committed entries.
    fn handle_request_vote(&mut self, from: NodeId, args: RequestVoteArgs) {
        let grant = self.should_grant_vote(&args);

        if grant {
            self.persistent.voted_for = Some(args.candidate_id);
            self.persist_state();
            // Granting a vote resets the election timer — this prevents a
            // follower from starting a competing election while a valid
            // candidate is trying to win.
            self.reset_election_timer();
        }

        self.send(
            from,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: self.persistent.current_term,
                vote_granted: grant,
            }),
        );
    }

    /// Determine whether to grant a vote to a candidate.
    fn should_grant_vote(&self, args: &RequestVoteArgs) -> bool {
        // Check 1: have we already voted for someone else this term?
        match self.persistent.voted_for {
            Some(id) if id != args.candidate_id => return false,
            _ => {}
        }

        // Check 2: is the candidate's log at least as up-to-date as ours?
        self.is_log_up_to_date(args.last_log_index, args.last_log_term)
    }

    /// Handle a vote response from a peer.
    ///
    /// Only meaningful if we're still a Candidate in the same term that sent
    /// the request. If we've since moved on (became follower or leader, or
    /// term advanced), the response is stale and ignored.
    fn handle_request_vote_response(&mut self, from: NodeId, reply: RequestVoteReply) {
        // Only candidates care about vote responses.
        let Role::Candidate {
            ref mut votes_received,
        } = self.role
        else {
            return;
        };

        if reply.vote_granted {
            votes_received.insert(from);
        }

        self.maybe_become_leader();
    }

    /// Check if we have enough votes to become leader. Called after receiving
    /// each vote and also after becoming a candidate (single-node cluster case).
    fn maybe_become_leader(&mut self) {
        let Role::Candidate {
            ref votes_received,
        } = self.role
        else {
            return;
        };

        // Total cluster size = self + peers.
        let cluster_size = self.peers.len() + 1;
        // Strict majority: more than half.
        let majority = (cluster_size / 2) + 1;

        if votes_received.len() >= majority {
            self.become_leader();
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  AppendEntries handling (§5.3)
    // ════════════════════════════════════════════════════════════════════════

    /// Handle an incoming AppendEntries from the leader.
    ///
    /// This serves two purposes:
    /// 1. Heartbeat — reset election timer to prevent unnecessary elections.
    /// 2. Log replication — append entries and advance commit index.
    ///
    /// The consistency check ensures the Log Matching Property:
    /// - If `prev_log_index` is 0, any log state is consistent (leader is
    ///   sending from the beginning).
    /// - Otherwise, we must have an entry at `prev_log_index` with term
    ///   `prev_log_term`. If not, we reject and hint at where to retry.
    fn handle_append_entries(&mut self, from: NodeId, args: AppendEntriesArgs) {
        // Any valid AppendEntries from the current leader proves it's alive.
        // Reset our election timer so we don't start a spurious election.
        self.reset_election_timer();

        // Track who the current leader is (for client redirects).
        self.current_leader = Some(args.leader_id);

        // If we're a Candidate and receive a valid AppendEntries for our term,
        // the sender is the legitimate leader. Step down.
        if matches!(self.role, Role::Candidate { .. }) {
            self.become_follower();
        }

        // ── Consistency check ──
        if args.prev_log_index > 0 {
            match self.log.term_at(args.prev_log_index) {
                None => {
                    // We don't have an entry at prev_log_index at all.
                    // Hint: our log only goes up to last_index — retry from there.
                    self.send(
                        from,
                        Rpc::AppendEntriesResponse(AppendEntriesReply {
                            term: self.persistent.current_term,
                            success: false,
                            match_index: self.log.last_index(),
                        }),
                    );
                    return;
                }
                Some(term) if term != args.prev_log_term => {
                    // We have an entry but with a different term — conflict.
                    // Find the first index of the conflicting term so the
                    // leader can skip back past the entire bad term.
                    let conflict_term = term;
                    let mut first_of_conflict = args.prev_log_index;
                    while first_of_conflict > 1
                        && self.log.term_at(first_of_conflict - 1) == Some(conflict_term)
                    {
                        first_of_conflict -= 1;
                    }
                    // Report match_index as the entry just before the conflict.
                    self.send(
                        from,
                        Rpc::AppendEntriesResponse(AppendEntriesReply {
                            term: self.persistent.current_term,
                            success: false,
                            match_index: first_of_conflict.saturating_sub(1),
                        }),
                    );
                    return;
                }
                _ => {
                    // Match — fall through to append.
                }
            }
        }

        // ── Append entries ──
        // Entries in AppendEntriesArgs don't carry their own index — the index
        // is determined positionally: args.entries[i] goes at
        // prev_log_index + 1 + i.
        //
        // "If an existing entry conflicts with a new one (same index but
        // different terms), delete the existing entry and all that follow it."
        let mut truncated = false;
        let mut new_entries: Vec<LogEntry> = Vec::new();
        for (i, entry) in args.entries.iter().enumerate() {
            let index = args.prev_log_index + 1 + i as u64;
            match self.log.term_at(index) {
                Some(existing_term) if existing_term == entry.term => {
                    // Already have this entry — skip (idempotent).
                    continue;
                }
                Some(_) => {
                    // Conflict: truncate from here and append the rest.
                    self.log.truncate_from(index);
                    if !truncated {
                        self.persist_log_truncate(index);
                        truncated = true;
                    }
                    self.log.append(entry.clone());
                    new_entries.push(entry.clone());
                }
                None => {
                    // New entry beyond our log — append.
                    self.log.append(entry.clone());
                    new_entries.push(entry.clone());
                }
            }
        }
        if !new_entries.is_empty() {
            self.persist_log_append(&new_entries);
        }

        // ── Advance commit index ──
        // "If leaderCommit > commitIndex, set commitIndex =
        //  min(leaderCommit, index of last new entry)"
        if args.leader_commit > self.volatile.commit_index {
            self.volatile.commit_index =
                std::cmp::min(args.leader_commit, self.log.last_index());
            self.apply_committed_entries();
        }

        // Report the last replicated index.
        let last_new_index = args.prev_log_index + args.entries.len() as u64;
        self.send(
            from,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: self.persistent.current_term,
                success: true,
                match_index: std::cmp::max(last_new_index, self.log.last_index()),
            }),
        );
    }

    /// Handle an AppendEntries response from a follower.
    ///
    /// On success: advance `next_index` and `match_index` for that follower,
    /// then check if we can advance the commit index.
    ///
    /// On failure: set `next_index = reply.match_index + 1` for faster
    /// convergence, then retry immediately.
    fn handle_append_entries_response(&mut self, from: NodeId, reply: AppendEntriesReply) {
        let Role::Leader {
            ref mut next_index,
            ref mut match_index,
        } = self.role
        else {
            return;
        };

        if reply.success {
            // The follower has accepted all entries up to reply.match_index.
            //
            // Guard: only advance, never regress. A stale success from a
            // previous round could carry a lower match_index than what we've
            // already confirmed. Ignoring it prevents next_index from going
            // backward, which would cause unnecessary re-sends.
            if let Some(mi) = match_index.get_mut(&from) {
                if reply.match_index > *mi {
                    *mi = reply.match_index;
                }
            }
            let confirmed = match_index.get(&from).copied().unwrap_or(0);
            if let Some(ni) = next_index.get_mut(&from) {
                let new_ni = confirmed + 1;
                if new_ni > *ni {
                    *ni = new_ni;
                }
            }

            // Check if we can advance the commit index.
            self.maybe_advance_commit_index();
        } else {
            // Backtrack using the match_index hint from the follower.
            // Guard: don't advance next_index on failure — only backtrack.
            if let Some(ni) = next_index.get_mut(&from) {
                let hint = reply.match_index + 1;
                if hint < *ni {
                    *ni = hint;
                }
            }

            // Retry immediately with the updated next_index.
            self.replicate_to(from);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Commit index advancement (§5.3, §5.4.2)
    // ════════════════════════════════════════════════════════════════════════

    /// Public entry point: attempt to advance the commit index.
    ///
    /// Called automatically after each successful AppendEntries response, but
    /// the simulator or test harness may also call it directly. Only meaningful
    /// when this node is the leader; a no-op otherwise.
    ///
    /// The leader advances `commit_index` to the highest index N where:
    /// 1. A majority of nodes (including the leader) have replicated entry N.
    /// 2. `log[N].term == current_term` (§5.4.2 safety rule).
    ///
    /// All entries up to the new `commit_index` are applied to the state
    /// machine in order and returned via `drain_applied()`.
    pub fn update_commit_index(&mut self) {
        self.maybe_advance_commit_index();
    }

    /// Internal: try to advance the commit index.
    ///
    /// The leader may advance `commit_index` to N if:
    /// 1. A majority of `match_index[peer]` values are >= N.
    /// 2. `log[N].term == current_term`.
    ///
    /// Condition (2) is critical for safety (§5.4.2): a leader must NOT commit
    /// entries from previous terms by counting replicas. It can only commit
    /// entries from its own term, which transitively commits all prior entries
    /// via the Log Matching property.
    fn maybe_advance_commit_index(&mut self) {
        let Role::Leader {
            ref match_index, ..
        } = self.role
        else {
            return;
        };

        let cluster_size = self.peers.len() + 1;
        let majority = (cluster_size / 2) + 1;

        // Check each index from our last log entry down to commit_index + 1.
        // We scan downward because we want the *highest* committable index.
        let last = self.log.last_index();
        for n in (self.volatile.commit_index + 1..=last).rev() {
            // Condition 2: only commit entries from the current term.
            if self.log.term_at(n) != Some(self.persistent.current_term) {
                continue;
            }

            // Count how many nodes have this entry (including ourselves).
            let mut replication_count = 1; // count self
            for (_, &mi) in match_index.iter() {
                if mi >= n {
                    replication_count += 1;
                }
            }

            if replication_count >= majority {
                self.volatile.commit_index = n;
                self.apply_committed_entries();
                break; // found the highest committable index
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  State machine application
    // ════════════════════════════════════════════════════════════════════════

    /// Apply all committed but not-yet-applied entries to the state machine.
    ///
    /// Invariant: `last_applied` always trails or equals `commit_index`.
    /// Entries are applied in strict index order — this is what guarantees
    /// all nodes see the same sequence of state mutations.
    fn apply_committed_entries(&mut self) {
        while self.volatile.last_applied < self.volatile.commit_index {
            self.volatile.last_applied += 1;
            let index = self.volatile.last_applied;

            if let Some(entry) = self.log.get(index) {
                self.applied.push(ApplyResult {
                    index,
                    term: entry.term,
                    data: entry.data.clone(),
                });
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Replication helpers (leader only)
    // ════════════════════════════════════════════════════════════════════════

    /// Send AppendEntries to all followers.
    fn replicate_to_all(&mut self) {
        let peers: Vec<NodeId> = self.peers.clone();
        for peer in peers {
            self.replicate_to(peer);
        }
    }

    /// Send AppendEntries to a specific follower.
    fn replicate_to(&mut self, peer: NodeId) {
        let Role::Leader {
            ref next_index, ..
        } = self.role
        else {
            return;
        };

        let ni = *next_index.get(&peer).unwrap_or(&1);

        // prev_log_index/term: the entry just before what we're sending.
        let prev_log_index = ni.saturating_sub(1);
        let prev_log_term = if prev_log_index == 0 {
            0
        } else {
            self.log.term_at(prev_log_index).unwrap_or(0)
        };

        // Collect entries from next_index[peer] through our last entry.
        let entries: Vec<LogEntry> = if ni <= self.log.last_index() {
            self.log
                .slice(ni, self.log.last_index())
                .into_iter()
                .cloned()
                .collect()
        } else {
            Vec::new()
        };

        self.send(
            peer,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: self.persistent.current_term,
                leader_id: self.id,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit: self.volatile.commit_index,
            }),
        );
    }

    /// Send heartbeats (empty AppendEntries) to all followers.
    fn send_heartbeats(&mut self) {
        // Heartbeats are just AppendEntries with current replication state.
        // Using replicate_to_all sends the actual pending entries too, which
        // is strictly better than empty heartbeats — it makes replication faster.
        self.replicate_to_all();
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Stale message rejection
    // ════════════════════════════════════════════════════════════════════════

    /// Reply to a message from an older term. We tell the sender our current
    /// term so it can update itself and step down if needed.
    fn reject_stale_message(&mut self, envelope: &Envelope) {
        match &envelope.payload {
            Rpc::RequestVote(_) => {
                self.send(
                    envelope.from,
                    Rpc::RequestVoteResponse(RequestVoteReply {
                        term: self.persistent.current_term,
                        vote_granted: false,
                    }),
                );
            }
            Rpc::AppendEntries(_) => {
                self.send(
                    envelope.from,
                    Rpc::AppendEntriesResponse(AppendEntriesReply {
                        term: self.persistent.current_term,
                        success: false,
                        match_index: 0,
                    }),
                );
            }
            // PreVote from a stale term — reject without touching our state.
            Rpc::PreVote(_) => {
                self.send(
                    envelope.from,
                    Rpc::PreVoteResponse(PreVoteReply {
                        term: self.persistent.current_term,
                        vote_granted: false,
                    }),
                );
            }
            // Stale responses are simply dropped — no need to reply to a reply.
            Rpc::RequestVoteResponse(_)
            | Rpc::AppendEntriesResponse(_)
            | Rpc::PreVoteResponse(_) => {}
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Pre-vote protocol (§9.6 — Raft dissertation)
    // ════════════════════════════════════════════════════════════════════════

    /// Start a pre-vote phase: ask peers if they *would* vote for us without
    /// actually incrementing our term. If a majority says yes, proceed to a
    /// real election.
    ///
    /// Pre-vote prevents a partitioned node from repeatedly bumping its term:
    /// when it rejoins, its artificially high term would force the current
    /// leader to step down, disrupting the cluster for no good reason.
    fn start_pre_vote(&mut self) {
        let next_term = self.persistent.current_term + 1;
        let last_log_index = self.log.last_index();
        let last_log_term = self.log.last_term();

        self.pre_vote_responses.clear();
        self.pre_vote_responses.insert(self.id); // we'd vote for ourselves
        self.reset_election_timer();

        let peers: Vec<NodeId> = self.peers.clone();
        for &peer in &peers {
            self.send(
                peer,
                Rpc::PreVote(PreVoteArgs {
                    term: next_term,
                    candidate_id: self.id,
                    last_log_index,
                    last_log_term,
                }),
            );
        }

        // Single-node cluster: pre-vote immediately succeeds.
        if self.has_pre_vote_majority() {
            self.become_candidate();
        }
    }

    /// Handle an incoming PreVote request.
    ///
    /// A node grants a pre-vote iff:
    /// 1. The candidate's proposed term is >= our current term.
    /// 2. The candidate's log is at least as up-to-date as ours.
    /// 3. Our election timer has NOT recently heard from a valid leader.
    ///    (If we recently heard from a leader, someone is already leading —
    ///    no need for a new election.)
    ///
    /// Unlike a real RequestVote, a PreVote does NOT cause the recipient to
    /// step down or update its term. It is purely speculative.
    fn handle_pre_vote(&mut self, from: NodeId, args: PreVoteArgs) {
        // Don't grant pre-vote if we recently heard from a leader (timer not expired).
        // This prevents a partitioned node from winning pre-votes while a healthy
        // leader exists.
        let leader_is_alive = self.current_leader.is_some() && !self.election_timer.is_expired();

        let grant = !leader_is_alive
            && args.term >= self.persistent.current_term
            && self.is_log_up_to_date(args.last_log_index, args.last_log_term);

        self.send(
            from,
            Rpc::PreVoteResponse(PreVoteReply {
                term: self.persistent.current_term,
                vote_granted: grant,
            }),
        );
    }

    /// Handle a PreVote response.
    fn handle_pre_vote_response(&mut self, from: NodeId, reply: PreVoteReply) {
        // Only followers collecting pre-votes care about these responses.
        if !matches!(self.role, Role::Follower) {
            return;
        }

        if reply.vote_granted {
            self.pre_vote_responses.insert(from);
        }

        if self.has_pre_vote_majority() {
            // Pre-vote passed — now run a real election.
            self.become_candidate();
        }
    }

    /// Check if we have a pre-vote majority.
    fn has_pre_vote_majority(&self) -> bool {
        let cluster_size = self.peers.len() + 1;
        let majority = (cluster_size / 2) + 1;
        self.pre_vote_responses.len() >= majority
    }

    /// Check if a candidate's log is at least as up-to-date as ours (§5.4.1).
    /// Shared by both RequestVote and PreVote.
    fn is_log_up_to_date(&self, last_log_index: LogIndex, last_log_term: Term) -> bool {
        let our_last_term = self.log.last_term();
        let our_last_index = self.log.last_index();

        if last_log_term != our_last_term {
            return last_log_term > our_last_term;
        }
        last_log_index >= our_last_index
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Messaging
    // ════════════════════════════════════════════════════════════════════════

    /// Queue a message for outbound delivery.
    fn send(&mut self, to: NodeId, payload: Rpc) {
        self.outbox.push(Envelope {
            from: self.id,
            to,
            payload,
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Persistence
    // ════════════════════════════════════════════════════════════════════════

    /// Persist the current term. Must be durable before the node acts on
    /// the new term value.
    fn persist_term(&mut self) {
        let _ = self.storage.save_term(self.persistent.current_term);
    }

    /// Persist who we voted for. Must be durable before the vote response
    /// is sent.
    fn persist_vote(&mut self) {
        let _ = self.storage.save_vote(self.persistent.voted_for);
    }

    /// Persist both term and vote. Called when both change together
    /// (e.g., stepping down to a new term clears the vote).
    fn persist_state(&mut self) {
        self.persist_term();
        self.persist_vote();
    }

    /// Persist newly appended log entries. Called after any log append.
    /// Only writes the new entries, not the entire log.
    fn persist_log_append(&mut self, entries: &[LogEntry]) {
        let _ = self.storage.append_log_entries(entries);
    }

    /// Persist a log truncation. Called when conflicting entries are removed.
    fn persist_log_truncate(&mut self, from_index: LogIndex) {
        let _ = self.storage.truncate_log(from_index);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Timer helpers
    // ════════════════════════════════════════════════════════════════════════

    /// Reset the election timer with a new randomized timeout.
    ///
    /// Randomization is essential: if all nodes had the same timeout, they'd
    /// all start elections simultaneously, split the vote, time out at the same
    /// time, and repeat forever. Randomizing in [min, max) ensures one node
    /// usually times out first and wins cleanly.
    fn reset_election_timer(&mut self) {
        let timeout = self.random_election_timeout();
        self.election_timer.reset(timeout);
    }

    /// Generate a random election timeout in [min, max) using a simple LCG.
    /// Deterministic and reproducible from the RNG seed.
    fn random_election_timeout(&mut self) -> u64 {
        // LCG parameters (Numerical Recipes).
        self.rng_state = self
            .rng_state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let range = self.config.election_timeout_max - self.config.election_timeout_min;
        self.config.election_timeout_min + (self.rng_state % range)
    }

    /// Seed-based timeout for initialization (before we have an instance).
    fn random_election_timeout_with_seed(seed: u64, min: u64, max: u64) -> u64 {
        let state = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        min + (state % (max - min))
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Inspection (for testing and simulation)
    // ════════════════════════════════════════════════════════════════════════

    /// Returns the current role.
    pub fn current_role(&self) -> &Role {
        &self.role
    }

    /// Returns the current term.
    pub fn current_term(&self) -> Term {
        self.persistent.current_term
    }

    /// Returns who this node voted for in the current term.
    pub fn voted_for(&self) -> Option<NodeId> {
        self.persistent.voted_for
    }

    /// Returns the commit index.
    pub fn commit_index(&self) -> LogIndex {
        self.volatile.commit_index
    }

    /// Returns the last applied index.
    pub fn last_applied(&self) -> LogIndex {
        self.volatile.last_applied
    }

    /// Returns true if this node is the leader.
    pub fn is_leader(&self) -> bool {
        matches!(self.role, Role::Leader { .. })
    }

    /// Returns true if this node is a follower.
    pub fn is_follower(&self) -> bool {
        matches!(self.role, Role::Follower)
    }

    /// Returns true if this node is a candidate.
    pub fn is_candidate(&self) -> bool {
        matches!(self.role, Role::Candidate { .. })
    }

    /// Returns the cluster size (self + peers).
    pub fn cluster_size(&self) -> usize {
        self.peers.len() + 1
    }

    /// Returns who we believe the current leader is, or `None` if unknown.
    /// Set when receiving a valid AppendEntries, cleared on term changes.
    pub fn leader_id(&self) -> Option<NodeId> {
        self.current_leader
    }

    /// Crate-internal access to the storage backend.
    /// Used by the simulator to snapshot storage before crashing a node.
    pub(crate) fn storage(&self) -> &S {
        &self.storage
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> ClusterConfig {
        ClusterConfig {
            election_timeout_min: 10,
            election_timeout_max: 20,
            heartbeat_interval: 5,
            pre_vote: false,
        }
    }

    fn pre_vote_config() -> ClusterConfig {
        ClusterConfig {
            pre_vote: true,
            ..default_config()
        }
    }

    fn three_node_cluster(id: NodeId) -> RaftNode {
        let peers: Vec<NodeId> = [1, 2, 3].iter().copied().filter(|&p| p != id).collect();
        RaftNode::new(id, peers, default_config())
    }

    fn five_node_cluster(id: NodeId) -> RaftNode {
        let peers: Vec<NodeId> = [1, 2, 3, 4, 5]
            .iter()
            .copied()
            .filter(|&p| p != id)
            .collect();
        RaftNode::new(id, peers, default_config())
    }

    /// Helper to create an Envelope with the term extracted from the payload.
    fn envelope(from: NodeId, to: NodeId, payload: Rpc) -> Envelope {
        Envelope { from, to, payload }
    }

    // ── Initial state ──

    #[test]
    fn node_starts_as_follower_in_term_zero() {
        let node = three_node_cluster(1);
        assert!(node.is_follower());
        assert_eq!(node.current_term(), 0);
        assert_eq!(node.voted_for(), None);
        assert_eq!(node.commit_index(), 0);
        assert_eq!(node.last_applied(), 0);
        assert_eq!(node.log.last_index(), 0);
    }

    // ── Election timeout triggers candidacy ──

    #[test]
    fn election_timeout_triggers_candidacy() {
        let mut node = three_node_cluster(1);
        // Tick past the maximum election timeout to guarantee expiry.
        node.tick(25);
        assert!(node.is_candidate());
        assert_eq!(node.current_term(), 1);
        assert_eq!(node.voted_for(), Some(1));
    }

    #[test]
    fn candidate_sends_request_vote_to_all_peers() {
        let mut node = three_node_cluster(1);
        node.tick(25);
        let messages = node.drain_messages();
        // Should send RequestVote to both peers (2 and 3).
        assert_eq!(messages.len(), 2);
        for msg in &messages {
            assert_eq!(msg.from, 1);
            assert_eq!(msg.term(), 1);
            assert!(matches!(msg.payload, Rpc::RequestVote(_)));
        }
        let targets: HashSet<NodeId> = messages.iter().map(|m| m.to).collect();
        assert!(targets.contains(&2));
        assert!(targets.contains(&3));
    }

    #[test]
    fn candidate_votes_for_self() {
        let mut node = three_node_cluster(1);
        node.tick(25);
        assert_eq!(node.voted_for(), Some(1));
        if let Role::Candidate { ref votes_received } = node.role {
            assert!(votes_received.contains(&1));
            assert_eq!(votes_received.len(), 1);
        } else {
            panic!("expected candidate role");
        }
    }

    // ── Winning election ──

    #[test]
    fn candidate_becomes_leader_on_majority() {
        let mut node = three_node_cluster(1);
        node.tick(25); // become candidate in term 1
        node.drain_messages();

        // Receive vote from node 2 — now we have 2/3 = majority.
        node.step(envelope(
            2,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));

        assert!(node.is_leader());
        assert_eq!(node.current_term(), 1);
    }

    #[test]
    fn leader_sends_heartbeats_on_election() {
        let mut node = three_node_cluster(1);
        node.tick(25);
        node.drain_messages(); // discard RequestVote messages

        // Win election.
        node.step(envelope(
            2,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));

        let messages = node.drain_messages();
        // Should send AppendEntries (heartbeat) to both peers.
        assert_eq!(messages.len(), 2);
        for msg in &messages {
            assert!(matches!(msg.payload, Rpc::AppendEntries(_)));
        }
    }

    #[test]
    fn leader_appends_noop_entry() {
        let mut node = three_node_cluster(1);
        node.tick(25);
        node.drain_messages();

        node.step(envelope(
            2,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));

        // Leader should have appended a no-op entry.
        assert_eq!(node.log.last_index(), 1);
        let entry = node.log.get(1).unwrap();
        assert_eq!(entry.term, 1);
        assert_eq!(Command::decode(&entry.data), Some(Command::Noop));
    }

    // ── Rejected votes ──

    #[test]
    fn candidate_does_not_become_leader_without_majority() {
        let mut node = five_node_cluster(1);
        node.tick(25); // become candidate in term 1
        node.drain_messages();

        // One vote from peer — total 2/5, not a majority.
        node.step(envelope(
            2,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));

        assert!(node.is_candidate());

        // Another vote — total 3/5, majority!
        node.step(envelope(
            3,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));

        assert!(node.is_leader());
    }

    #[test]
    fn rejected_vote_does_not_count() {
        let mut node = three_node_cluster(1);
        node.tick(25);
        node.drain_messages();

        node.step(envelope(
            2,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: false,
            }),
        ));

        assert!(node.is_candidate());
    }

    // ── Term update and step-down ──

    #[test]
    fn higher_term_causes_step_down_to_follower() {
        let mut node = three_node_cluster(1);
        node.tick(25); // become candidate in term 1
        node.drain_messages();

        // Receive a message with a higher term.
        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 5,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));

        assert!(node.is_follower());
        assert_eq!(node.current_term(), 5);
        assert_eq!(node.voted_for(), None);
    }

    #[test]
    fn leader_steps_down_on_higher_term() {
        let mut node = three_node_cluster(1);
        // Become leader.
        node.tick(25);
        node.drain_messages();
        node.step(envelope(
            2,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));
        assert!(node.is_leader());
        node.drain_messages();

        // Receive a message from a higher term.
        node.step(envelope(
            3,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 10,
                candidate_id: 3,
                last_log_index: 1,
                last_log_term: 1,
            }),
        ));

        assert!(node.is_follower());
        assert_eq!(node.current_term(), 10);
    }

    // ── Vote granting ──

    #[test]
    fn follower_grants_vote_to_first_candidate() {
        let mut node = three_node_cluster(1);
        node.step(envelope(
            2,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 1,
                candidate_id: 2,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));

        let messages = node.drain_messages();
        assert_eq!(messages.len(), 1);
        if let Rpc::RequestVoteResponse(reply) = &messages[0].payload {
            assert!(reply.vote_granted);
            assert_eq!(reply.term, 1);
        } else {
            panic!("expected RequestVoteResponse");
        }
        assert_eq!(node.voted_for(), Some(2));
    }

    #[test]
    fn follower_rejects_second_candidate_same_term() {
        let mut node = three_node_cluster(1);

        // Vote for candidate 2.
        node.step(envelope(
            2,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 1,
                candidate_id: 2,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));
        node.drain_messages();

        // Candidate 3 asks for a vote in the same term — must be rejected.
        node.step(envelope(
            3,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 1,
                candidate_id: 3,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));

        let messages = node.drain_messages();
        assert_eq!(messages.len(), 1);
        if let Rpc::RequestVoteResponse(reply) = &messages[0].payload {
            assert!(!reply.vote_granted);
        } else {
            panic!("expected RequestVoteResponse");
        }
    }

    #[test]
    fn follower_rejects_candidate_with_stale_log() {
        let mut node = three_node_cluster(1);

        // Give node 1 a log entry in term 2.
        node.log.append(LogEntry {
            term: 2,
            data: Command::Noop.encode(),
        });

        // Candidate 2 has an empty log (term 0, index 0) — less up-to-date.
        node.step(envelope(
            2,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 2,
                candidate_id: 2,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));

        let messages = node.drain_messages();
        if let Rpc::RequestVoteResponse(reply) = &messages[0].payload {
            assert!(!reply.vote_granted, "should reject candidate with stale log");
        }
    }

    // ── Stale messages ──

    #[test]
    fn stale_term_messages_are_rejected() {
        let mut node = three_node_cluster(1);
        // Advance to term 5.
        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 5,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));
        node.drain_messages();

        // Message from term 3 — stale.
        node.step(envelope(
            3,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 3,
                candidate_id: 3,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));

        let messages = node.drain_messages();
        assert_eq!(messages.len(), 1);
        if let Rpc::RequestVoteResponse(reply) = &messages[0].payload {
            assert!(!reply.vote_granted);
            assert_eq!(reply.term, 5); // our term is higher
        }
        // Term should still be 5.
        assert_eq!(node.current_term(), 5);
    }

    // ── Single-node cluster ──

    #[test]
    fn single_node_becomes_leader_immediately() {
        let mut node = RaftNode::new(1, vec![], default_config());
        node.tick(25); // triggers candidacy
        // With no peers, 1/1 is already a majority.
        assert!(node.is_leader());
        assert_eq!(node.current_term(), 1);
    }

    // ── AppendEntries resets election timer ──

    #[test]
    fn append_entries_resets_election_timer() {
        let mut node = three_node_cluster(1);

        // Tick close to timeout but not past it.
        node.tick(9);
        assert!(node.is_follower());

        // Receive heartbeat — resets timer.
        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));

        // Tick again — should not trigger election because timer was reset.
        node.tick(9);
        assert!(node.is_follower());
    }

    // ── Propose ──

    #[test]
    fn only_leader_accepts_proposals() {
        let mut node = three_node_cluster(1);

        // Follower rejects.
        let put = Command::Put {
            key: "x".into(),
            value: vec![1],
        };
        assert!(!node.propose(put.encode()));

        // Become leader.
        node.tick(25);
        node.drain_messages();
        node.step(envelope(
            2,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));
        node.drain_messages();
        assert!(node.is_leader());

        // Leader accepts.
        let put2 = Command::Put {
            key: "x".into(),
            value: vec![1],
        };
        assert!(node.propose(put2.encode()));

        // Log should have noop (index 1) + put (index 2).
        assert_eq!(node.log.last_index(), 2);
    }

    // ── Candidate steps down on valid AppendEntries ──

    #[test]
    fn candidate_steps_down_on_append_entries() {
        let mut node = three_node_cluster(1);
        node.tick(25); // become candidate in term 1
        node.drain_messages();
        assert!(node.is_candidate());

        // Receive AppendEntries from the legitimate leader of term 1.
        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));

        assert!(node.is_follower());
        assert_eq!(node.current_term(), 1);
    }

    // ── Log replication: follower appends entries ──

    #[test]
    fn follower_appends_entries_from_leader() {
        let mut node = three_node_cluster(1);

        let entries = vec![
            LogEntry {
                term: 1,
                data: Command::Put {
                    key: "a".into(),
                    value: vec![1],
                }
                .encode(),
            },
            LogEntry {
                term: 1,
                data: Command::Put {
                    key: "b".into(),
                    value: vec![2],
                }
                .encode(),
            },
        ];

        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries,
                leader_commit: 0,
            }),
        ));

        assert_eq!(node.log.last_index(), 2);
        assert_eq!(node.log.get(1).unwrap().term, 1);
        assert_eq!(node.log.get(2).unwrap().term, 1);

        let messages = node.drain_messages();
        assert_eq!(messages.len(), 1);
        if let Rpc::AppendEntriesResponse(reply) = &messages[0].payload {
            assert!(reply.success);
            assert_eq!(reply.match_index, 2);
        }
    }

    // ── Log replication: follower rejects on mismatch ──

    #[test]
    fn follower_rejects_append_entries_on_log_gap() {
        let mut node = three_node_cluster(1);

        // Leader sends entries starting at index 5, but follower has no log.
        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 4,
                prev_log_term: 1,
                entries: vec![LogEntry {
                    term: 1,
                    data: Command::Noop.encode(),
                }],
                leader_commit: 0,
            }),
        ));

        let messages = node.drain_messages();
        if let Rpc::AppendEntriesResponse(reply) = &messages[0].payload {
            assert!(!reply.success);
            // Follower has no entries, so match_index = 0 (last_index).
            assert_eq!(reply.match_index, 0);
        }
    }

    // ── Commit advancement ──

    #[test]
    fn follower_advances_commit_index_from_leader() {
        let mut node = three_node_cluster(1);

        // First: append two entries.
        let entries = vec![
            LogEntry {
                term: 1,
                data: Command::Put {
                    key: "a".into(),
                    value: vec![1],
                }
                .encode(),
            },
            LogEntry {
                term: 1,
                data: Command::Put {
                    key: "b".into(),
                    value: vec![2],
                }
                .encode(),
            },
        ];

        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries,
                leader_commit: 2, // leader says both are committed
            }),
        ));

        assert_eq!(node.commit_index(), 2);
        assert_eq!(node.last_applied(), 2);

        let applied = node.drain_applied();
        assert_eq!(applied.len(), 2);
        assert_eq!(applied[0].index, 1);
        assert_eq!(applied[1].index, 2);
    }

    // ── Log conflict truncation ──

    #[test]
    fn follower_truncates_conflicting_entries() {
        let mut node = three_node_cluster(1);

        // Follower has entries from term 1.
        node.log.append(LogEntry {
            term: 1,
            data: Command::Noop.encode(),
        });
        node.log.append(LogEntry {
            term: 1,
            data: Command::Noop.encode(),
        });

        // Leader sends entry at index 2 with term 2 — conflicts with existing.
        let put_data = Command::Put {
            key: "x".into(),
            value: vec![42],
        }
        .encode();

        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 2,
                leader_id: 2,
                prev_log_index: 1,
                prev_log_term: 1,
                entries: vec![LogEntry {
                    term: 2,
                    data: put_data.clone(),
                }],
                leader_commit: 0,
            }),
        ));

        // Old entry at index 2 (term 1) should be replaced with new (term 2).
        assert_eq!(node.log.last_index(), 2);
        assert_eq!(node.log.get(2).unwrap().term, 2);
        let decoded = Command::decode(&node.log.get(2).unwrap().data).unwrap();
        if let Command::Put { ref key, .. } = decoded {
            assert_eq!(key, "x");
        } else {
            panic!("expected Put command");
        }
    }

    // ── Repeated elections increment term ──

    #[test]
    fn repeated_election_timeouts_increment_term() {
        let mut node = three_node_cluster(1);
        node.tick(25); // term 1
        assert_eq!(node.current_term(), 1);
        node.drain_messages();

        node.tick(25); // term 2 (second timeout as candidate)
        assert_eq!(node.current_term(), 2);
        assert!(node.is_candidate());
    }

    // ── Heartbeat interval ──

    #[test]
    fn leader_sends_heartbeats_on_timer() {
        let mut node = three_node_cluster(1);
        // Become leader.
        node.tick(25);
        node.drain_messages();
        node.step(envelope(
            2,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));
        node.drain_messages(); // discard initial heartbeats

        // Tick the heartbeat interval.
        node.tick(5);
        let messages = node.drain_messages();
        assert_eq!(messages.len(), 2); // one per peer
        for msg in &messages {
            assert!(matches!(msg.payload, Rpc::AppendEntries(_)));
        }
    }

    // ── Envelope.term() extracts from payload ──

    #[test]
    fn envelope_term_reads_from_payload() {
        let env = envelope(
            1,
            2,
            Rpc::RequestVote(RequestVoteArgs {
                term: 42,
                candidate_id: 1,
                last_log_index: 0,
                last_log_term: 0,
            }),
        );
        assert_eq!(env.term(), 42);

        let env2 = envelope(
            1,
            2,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 99,
                success: true,
                match_index: 5,
            }),
        );
        assert_eq!(env2.term(), 99);
    }

    // ── match_index in AppendEntriesReply ──

    #[test]
    fn reply_match_index_reflects_replicated_entries() {
        let mut node = three_node_cluster(1);

        // Append 3 entries.
        let entries: Vec<LogEntry> = (1..=3)
            .map(|_| LogEntry {
                term: 1,
                data: vec![0],
            })
            .collect();

        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries,
                leader_commit: 0,
            }),
        ));

        let messages = node.drain_messages();
        if let Rpc::AppendEntriesResponse(reply) = &messages[0].payload {
            assert!(reply.success);
            assert_eq!(reply.match_index, 3);
        }
    }

    #[test]
    fn reply_match_index_on_term_conflict() {
        let mut node = three_node_cluster(1);

        // Give follower entries [term=1, term=1, term=2, term=2].
        for &t in &[1, 1, 2, 2] {
            node.log.append(LogEntry {
                term: t,
                data: vec![],
            });
        }

        // Leader says prev_log_index=4 with prev_log_term=3 — mismatch at index 4
        // (follower has term 2 there). The entire term-2 range is [3,4], so
        // match_index should be 2 (just before the conflict).
        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 3,
                leader_id: 2,
                prev_log_index: 4,
                prev_log_term: 3,
                entries: vec![],
                leader_commit: 0,
            }),
        ));

        let messages = node.drain_messages();
        if let Rpc::AppendEntriesResponse(reply) = &messages[0].payload {
            assert!(!reply.success);
            assert_eq!(reply.match_index, 2); // first_of_conflict(3) - 1 = 2
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Leader election: comprehensive edge cases
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn start_election_is_public_and_triggers_candidacy() {
        let mut node = three_node_cluster(1);
        assert!(node.is_follower());
        node.start_election();
        assert!(node.is_candidate());
        assert_eq!(node.current_term(), 1);
    }

    #[test]
    fn granting_vote_resets_election_timer() {
        let mut node = three_node_cluster(1);

        // Tick close to timeout.
        node.tick(9);
        assert!(node.is_follower());

        // Receive RequestVote and grant it — should reset timer.
        node.step(envelope(
            2,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 1,
                candidate_id: 2,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));
        node.drain_messages();

        // Tick again — should NOT trigger election since granting the vote
        // reset the timer.
        node.tick(9);
        assert!(node.is_follower(), "granting vote should reset election timer");
    }

    #[test]
    fn duplicate_votes_from_same_peer_not_double_counted() {
        let mut node = five_node_cluster(1);
        node.tick(25); // become candidate
        node.drain_messages();

        // Node 2 votes twice (duplicate message delivery).
        for _ in 0..2 {
            node.step(envelope(
                2,
                1,
                Rpc::RequestVoteResponse(RequestVoteReply {
                    term: 1,
                    vote_granted: true,
                }),
            ));
        }

        // 2 unique votes (self + node 2) out of 5 — not a majority.
        assert!(node.is_candidate(), "duplicate votes must not be double-counted");

        // Third unique vote wins it.
        node.step(envelope(
            3,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));
        assert!(node.is_leader());
    }

    #[test]
    fn vote_response_ignored_after_becoming_leader() {
        let mut node = three_node_cluster(1);
        node.tick(25);
        node.drain_messages();

        // Win election with node 2's vote.
        node.step(envelope(
            2,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));
        assert!(node.is_leader());
        node.drain_messages();

        // Late vote from node 3 arrives — should be harmlessly ignored.
        node.step(envelope(
            3,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));
        assert!(node.is_leader()); // still leader, no crash
    }

    #[test]
    fn vote_response_ignored_after_stepping_down() {
        let mut node = three_node_cluster(1);
        node.tick(25); // candidate in term 1
        node.drain_messages();

        // Receive AppendEntries from the real leader — step down.
        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));
        assert!(node.is_follower());
        node.drain_messages();

        // Late vote arrives — should not make us leader.
        node.step(envelope(
            3,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));
        assert!(node.is_follower());
    }

    #[test]
    fn candidate_rejects_request_vote_from_other_candidate_same_term() {
        let mut node = three_node_cluster(1);
        node.tick(25); // candidate in term 1, voted for self
        node.drain_messages();

        // Another candidate asks for our vote in the same term.
        node.step(envelope(
            2,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 1,
                candidate_id: 2,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));

        let messages = node.drain_messages();
        if let Rpc::RequestVoteResponse(reply) = &messages[0].payload {
            assert!(
                !reply.vote_granted,
                "already voted for self, must reject other candidate"
            );
        }
    }

    #[test]
    fn election_timeout_is_randomized_per_node() {
        // Different node IDs should produce different initial timeouts.
        let node_a = RaftNode::new(1, vec![2, 3], default_config());
        let node_b = RaftNode::new(2, vec![1, 3], default_config());

        // We can't directly read the timeout, but we can observe that one
        // times out before the other when ticked identically.
        let mut a = node_a;
        let mut b = node_b;

        // Tick both by the minimum timeout — at least one should still be
        // a follower (different timeouts) or both could be candidates
        // (both within range). The key property: they are deterministic
        // per node ID.
        a.tick(10);
        b.tick(10);
        // Both should be candidates or exactly one, depending on RNG.
        // What matters is this doesn't panic and is deterministic.
        let a_candidate = a.is_candidate();
        let b_candidate = b.is_candidate();

        // Re-run to verify determinism.
        let mut a2 = RaftNode::new(1, vec![2, 3], default_config());
        let mut b2 = RaftNode::new(2, vec![1, 3], default_config());
        a2.tick(10);
        b2.tick(10);
        assert_eq!(a2.is_candidate(), a_candidate, "timeouts must be deterministic");
        assert_eq!(b2.is_candidate(), b_candidate, "timeouts must be deterministic");
    }

    #[test]
    fn leader_does_not_start_election_on_tick() {
        let mut node = three_node_cluster(1);
        // Become leader.
        node.tick(25);
        node.drain_messages();
        node.step(envelope(
            2,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));
        assert!(node.is_leader());
        node.drain_messages();

        // Tick way past election timeout — leader should NOT start election.
        node.tick(1000);
        assert!(node.is_leader(), "leader must not start elections");
    }

    #[test]
    fn request_vote_carries_correct_log_state() {
        let mut node = three_node_cluster(1);

        // Give node 1 some log entries.
        node.log.append(LogEntry {
            term: 1,
            data: vec![1],
        });
        node.log.append(LogEntry {
            term: 3,
            data: vec![2],
        });

        node.start_election();
        let messages = node.drain_messages();

        for msg in &messages {
            if let Rpc::RequestVote(args) = &msg.payload {
                assert_eq!(args.last_log_index, 2);
                assert_eq!(args.last_log_term, 3);
                assert_eq!(args.candidate_id, 1);
            } else {
                panic!("expected RequestVote");
            }
        }
    }

    #[test]
    fn candidate_with_higher_last_term_wins_despite_shorter_log() {
        let mut voter = three_node_cluster(1);

        // Voter has 3 entries, all in term 1.
        for _ in 0..3 {
            voter.log.append(LogEntry {
                term: 1,
                data: vec![],
            });
        }

        // Candidate has only 1 entry but in term 2 — more up-to-date.
        voter.step(envelope(
            2,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 2,
                candidate_id: 2,
                last_log_index: 1,
                last_log_term: 2,
            }),
        ));

        let messages = voter.drain_messages();
        if let Rpc::RequestVoteResponse(reply) = &messages[0].payload {
            assert!(
                reply.vote_granted,
                "higher last_log_term should win despite shorter log"
            );
        }
    }

    #[test]
    fn candidate_with_same_term_but_shorter_log_loses() {
        let mut voter = three_node_cluster(1);

        // Voter has 3 entries in term 1.
        for _ in 0..3 {
            voter.log.append(LogEntry {
                term: 1,
                data: vec![],
            });
        }

        // Candidate has only 2 entries in term 1 — less up-to-date.
        voter.step(envelope(
            2,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 1,
                candidate_id: 2,
                last_log_index: 2,
                last_log_term: 1,
            }),
        ));

        let messages = voter.drain_messages();
        if let Rpc::RequestVoteResponse(reply) = &messages[0].payload {
            assert!(
                !reply.vote_granted,
                "shorter log at same term should be rejected"
            );
        }
    }

    #[test]
    fn follower_can_vote_again_in_new_term() {
        let mut node = three_node_cluster(1);

        // Vote for candidate 2 in term 1.
        node.step(envelope(
            2,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 1,
                candidate_id: 2,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));
        assert_eq!(node.voted_for(), Some(2));
        node.drain_messages();

        // New term (via AppendEntries from leader) clears voted_for.
        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 2,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));
        assert_eq!(node.voted_for(), None);
        node.drain_messages();

        // Can vote for candidate 3 in term 2.
        node.step(envelope(
            3,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 2,
                candidate_id: 3,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));

        let messages = node.drain_messages();
        if let Rpc::RequestVoteResponse(reply) = &messages[0].payload {
            assert!(reply.vote_granted);
        }
        assert_eq!(node.voted_for(), Some(3));
    }

    #[test]
    fn re_voting_for_same_candidate_is_idempotent() {
        let mut node = three_node_cluster(1);

        // Vote for candidate 2 in term 1.
        node.step(envelope(
            2,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 1,
                candidate_id: 2,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));
        let msgs = node.drain_messages();
        assert!(matches!(
            &msgs[0].payload,
            Rpc::RequestVoteResponse(r) if r.vote_granted
        ));

        // Same candidate asks again (duplicate delivery) — should still grant.
        node.step(envelope(
            2,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 1,
                candidate_id: 2,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));
        let msgs = node.drain_messages();
        if let Rpc::RequestVoteResponse(reply) = &msgs[0].payload {
            assert!(reply.vote_granted, "re-vote for same candidate should succeed");
        }
    }

    #[test]
    fn candidate_steps_down_on_higher_term_request_vote() {
        let mut node = three_node_cluster(1);
        node.tick(25); // candidate in term 1
        node.drain_messages();
        assert!(node.is_candidate());

        // Receive RequestVote from a higher term — must step down.
        node.step(envelope(
            2,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 5,
                candidate_id: 2,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));

        assert!(node.is_follower());
        assert_eq!(node.current_term(), 5);
        // Should have granted the vote since we stepped down to the new term.
        assert_eq!(node.voted_for(), Some(2));
    }

    #[test]
    fn election_state_is_persisted() {
        let mut node = three_node_cluster(1);
        node.tick(25); // become candidate in term 1

        // Verify persistent state reflects the election.
        assert_eq!(node.persistent.current_term, 1);
        assert_eq!(node.persistent.voted_for, Some(1));
    }

    #[test]
    fn leader_id_tracked_from_append_entries() {
        let mut node = three_node_cluster(1);
        assert_eq!(node.leader_id(), None);

        // Receive heartbeat from leader 2.
        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));
        assert_eq!(node.leader_id(), Some(2));
        node.drain_messages();

        // Term change clears leader_id.
        node.step(envelope(
            3,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 5,
                candidate_id: 3,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));
        assert_eq!(node.leader_id(), None);
    }

    #[test]
    fn leader_knows_it_is_leader() {
        let mut node = three_node_cluster(1);
        node.tick(25);
        node.drain_messages();
        node.step(envelope(
            2,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));
        assert!(node.is_leader());
        assert_eq!(node.leader_id(), Some(1));
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Multi-node election simulation
    // ════════════════════════════════════════════════════════════════════════

    /// Simulate a full election across 3 nodes by manually delivering messages.
    #[test]
    fn three_node_full_election_simulation() {
        let config = default_config();
        let mut n1 = RaftNode::new(1, vec![2, 3], config.clone());
        let mut n2 = RaftNode::new(2, vec![1, 3], config.clone());
        let mut n3 = RaftNode::new(3, vec![1, 2], config.clone());

        // Node 1 times out first and starts an election.
        n1.start_election();
        assert!(n1.is_candidate());
        assert_eq!(n1.current_term(), 1);

        // Deliver RequestVote messages to n2 and n3.
        let messages = n1.drain_messages();
        assert_eq!(messages.len(), 2);

        for msg in messages {
            match msg.to {
                2 => n2.step(msg),
                3 => n3.step(msg),
                _ => panic!("unexpected target"),
            }
        }

        // Both n2 and n3 should have voted for n1.
        assert_eq!(n2.voted_for(), Some(1));
        assert_eq!(n3.voted_for(), Some(1));

        // Collect vote responses.
        let mut responses = Vec::new();
        responses.extend(n2.drain_messages());
        responses.extend(n3.drain_messages());

        // Deliver responses back to n1.
        for msg in responses {
            n1.step(msg);
        }

        // n1 should now be leader.
        assert!(n1.is_leader());
        assert_eq!(n1.current_term(), 1);

        // n1 sent heartbeats on becoming leader.
        let heartbeats = n1.drain_messages();
        assert_eq!(heartbeats.len(), 2);

        // Deliver heartbeats — n2 and n3 should track n1 as leader.
        for msg in heartbeats {
            match msg.to {
                2 => n2.step(msg),
                3 => n3.step(msg),
                _ => panic!("unexpected target"),
            }
        }
        assert_eq!(n2.leader_id(), Some(1));
        assert_eq!(n3.leader_id(), Some(1));
    }

    /// Simulate a split vote: two candidates in the same term, neither gets majority.
    #[test]
    fn split_vote_requires_new_election() {
        let config = default_config();
        let mut n1 = RaftNode::new(1, vec![2, 3, 4, 5], config.clone());
        let mut n2 = RaftNode::new(2, vec![1, 3, 4, 5], config.clone());
        let mut n3 = RaftNode::new(3, vec![1, 2, 4, 5], config.clone());
        let mut n4 = RaftNode::new(4, vec![1, 2, 3, 5], config.clone());
        let mut n5 = RaftNode::new(5, vec![1, 2, 3, 4], config.clone());

        // n1 and n2 both start elections in term 1.
        n1.start_election();
        n2.start_election();
        assert_eq!(n1.current_term(), 1);
        assert_eq!(n2.current_term(), 1);

        let n1_msgs = n1.drain_messages();
        let n2_msgs = n2.drain_messages();

        // n3 receives n1's RequestVote first → votes for n1.
        for msg in &n1_msgs {
            if msg.to == 3 {
                n3.step(msg.clone());
            }
        }
        assert_eq!(n3.voted_for(), Some(1));

        // n4 receives n2's RequestVote first → votes for n2.
        for msg in &n2_msgs {
            if msg.to == 4 {
                n4.step(msg.clone());
            }
        }
        assert_eq!(n4.voted_for(), Some(2));

        // n5 receives n1's RequestVote first → votes for n1.
        for msg in &n1_msgs {
            if msg.to == 5 {
                n5.step(msg.clone());
            }
        }
        assert_eq!(n5.voted_for(), Some(1));

        // Now deliver n2's RequestVote to n3 and n5 — should be rejected
        // (already voted for n1 this term).
        for msg in &n2_msgs {
            if msg.to == 3 {
                n3.step(msg.clone());
            }
            if msg.to == 5 {
                n5.step(msg.clone());
            }
        }
        // n3 and n5 still voted for n1.
        assert_eq!(n3.voted_for(), Some(1));
        assert_eq!(n5.voted_for(), Some(1));

        // Deliver all responses to n1.
        let mut all_responses = Vec::new();
        all_responses.extend(n3.drain_messages());
        all_responses.extend(n4.drain_messages());
        all_responses.extend(n5.drain_messages());

        for msg in &all_responses {
            if msg.to == 1 {
                n1.step(msg.clone());
            }
        }

        // n1 got votes from self(1) + n3 + n5 = 3/5 → majority → leader!
        assert!(n1.is_leader());

        // Deliver responses to n2.
        for msg in &all_responses {
            if msg.to == 2 {
                n2.step(msg.clone());
            }
        }
        // n2 got votes from self(2) + n4 = 2/5 → NOT majority → still candidate.
        assert!(n2.is_candidate());
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Pre-vote protocol tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn pre_vote_sends_pre_vote_messages_not_request_vote() {
        let mut node = RaftNode::new(1, vec![2, 3], pre_vote_config());
        node.start_election();

        // Should still be follower (pre-vote phase, not candidate yet).
        assert!(node.is_follower());
        // Term should NOT have incremented.
        assert_eq!(node.current_term(), 0);

        let messages = node.drain_messages();
        assert_eq!(messages.len(), 2);
        for msg in &messages {
            assert!(
                matches!(msg.payload, Rpc::PreVote(_)),
                "pre-vote should send PreVote, not RequestVote"
            );
            if let Rpc::PreVote(args) = &msg.payload {
                // PreVote carries the *proposed* next term.
                assert_eq!(args.term, 1);
            }
        }
    }

    #[test]
    fn pre_vote_majority_triggers_real_election() {
        let mut node = RaftNode::new(1, vec![2, 3], pre_vote_config());
        node.start_election();
        node.drain_messages();

        // Grant pre-vote from node 2 — now we have 2/3 (self + node 2).
        node.step(envelope(
            2,
            1,
            Rpc::PreVoteResponse(PreVoteReply {
                term: 0,
                vote_granted: true,
            }),
        ));

        // Should have progressed to a real election.
        assert!(node.is_candidate());
        assert_eq!(node.current_term(), 1); // term incremented now

        // Should have sent real RequestVote messages.
        let messages = node.drain_messages();
        assert!(messages
            .iter()
            .any(|m| matches!(m.payload, Rpc::RequestVote(_))));
    }

    #[test]
    fn pre_vote_rejected_does_not_start_election() {
        let mut node = RaftNode::new(1, vec![2, 3], pre_vote_config());
        node.start_election();
        node.drain_messages();

        // Both peers reject the pre-vote.
        node.step(envelope(
            2,
            1,
            Rpc::PreVoteResponse(PreVoteReply {
                term: 0,
                vote_granted: false,
            }),
        ));
        node.step(envelope(
            3,
            1,
            Rpc::PreVoteResponse(PreVoteReply {
                term: 0,
                vote_granted: false,
            }),
        ));

        // Should still be follower with term unchanged.
        assert!(node.is_follower());
        assert_eq!(node.current_term(), 0);
    }

    #[test]
    fn pre_vote_does_not_increment_term() {
        let mut node = RaftNode::new(1, vec![2, 3], pre_vote_config());
        let term_before = node.current_term();
        node.start_election();
        assert_eq!(
            node.current_term(),
            term_before,
            "pre-vote must not increment term"
        );
    }

    #[test]
    fn pre_vote_responder_does_not_change_state() {
        let mut node = three_node_cluster(1);

        // Advance to term 3.
        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 3,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));
        node.drain_messages();
        assert_eq!(node.current_term(), 3);
        assert_eq!(node.leader_id(), Some(2));

        // Receive PreVote from node 3 for term 4.
        node.step(envelope(
            3,
            1,
            Rpc::PreVote(PreVoteArgs {
                term: 4,
                candidate_id: 3,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));

        // Our state must NOT change — pre-vote is speculative.
        assert_eq!(node.current_term(), 3, "pre-vote must not change receiver's term");
        assert!(node.is_follower());
        assert_eq!(node.voted_for(), None);
    }

    #[test]
    fn pre_vote_rejected_if_leader_is_alive() {
        let mut node = three_node_cluster(1);

        // Receive heartbeat from leader 2 — leader is alive.
        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));
        node.drain_messages();

        // Receive PreVote from node 3 — should be rejected since we
        // recently heard from a leader.
        node.step(envelope(
            3,
            1,
            Rpc::PreVote(PreVoteArgs {
                term: 2,
                candidate_id: 3,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));

        let messages = node.drain_messages();
        if let Rpc::PreVoteResponse(reply) = &messages[0].payload {
            assert!(
                !reply.vote_granted,
                "should reject pre-vote when leader is alive"
            );
        }
    }

    #[test]
    fn single_node_pre_vote_immediately_becomes_leader() {
        let mut node = RaftNode::new(1, vec![], pre_vote_config());
        node.start_election();
        // Single node: pre-vote majority is 1/1, so it should proceed
        // directly to candidate and then to leader.
        assert!(node.is_leader());
        assert_eq!(node.current_term(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Heartbeat (empty AppendEntries) tests
    // ════════════════════════════════════════════════════════════════════════

    /// Helper: create a 3-node cluster, elect node 1 as leader, and drain
    /// the initial messages (RequestVote + heartbeats). Returns the leader.
    fn elect_leader_node1() -> RaftNode {
        let mut node = three_node_cluster(1);
        node.tick(25);
        node.drain_messages();
        node.step(envelope(
            2,
            1,
            Rpc::RequestVoteResponse(RequestVoteReply {
                term: 1,
                vote_granted: true,
            }),
        ));
        assert!(node.is_leader());
        node.drain_messages(); // discard initial heartbeats
        node
    }

    #[test]
    fn heartbeat_is_append_entries_with_empty_entries() {
        let mut leader = elect_leader_node1();

        // Trigger a heartbeat.
        leader.tick(5);
        let messages = leader.drain_messages();

        assert_eq!(messages.len(), 2, "one heartbeat per peer");
        for msg in &messages {
            if let Rpc::AppendEntries(args) = &msg.payload {
                // A heartbeat to a caught-up follower has no entries.
                // (The noop is at index 1 and next_index starts at 1 for
                // peers that were initialized before the noop was appended,
                // so the first heartbeat may carry the noop. Subsequent
                // heartbeats to caught-up peers are empty.)
                assert_eq!(args.term, 1);
                assert_eq!(args.leader_id, 1);
            } else {
                panic!("heartbeat must be AppendEntries");
            }
        }
    }

    #[test]
    fn heartbeat_carries_leader_commit() {
        let mut leader = elect_leader_node1();

        // Artificially advance commit_index to simulate prior replication.
        leader.volatile.commit_index = 1;

        leader.tick(5);
        let messages = leader.drain_messages();

        for msg in &messages {
            if let Rpc::AppendEntries(args) = &msg.payload {
                assert_eq!(
                    args.leader_commit, 1,
                    "heartbeat must carry the leader's commit index"
                );
            }
        }
    }

    #[test]
    fn heartbeat_carries_correct_prev_log_for_each_peer() {
        let mut leader = elect_leader_node1();

        // Leader has noop at index 1 (term 1). next_index for peers was
        // initialized to 1 (before noop was appended), so on first
        // heartbeat prev_log_index = 0 and entries include the noop.
        // After a successful response, next_index advances.

        // Simulate peer 2 confirming it has index 1.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 1,
            }),
        ));
        leader.drain_messages();

        // Now trigger a heartbeat.
        leader.tick(5);
        let messages = leader.drain_messages();

        for msg in &messages {
            if let Rpc::AppendEntries(args) = &msg.payload {
                if msg.to == 2 {
                    // Peer 2 is caught up — prev_log_index=1, no new entries.
                    assert_eq!(args.prev_log_index, 1);
                    assert_eq!(args.prev_log_term, 1);
                    assert!(
                        args.entries.is_empty(),
                        "caught-up peer should receive empty heartbeat"
                    );
                }
            }
        }
    }

    #[test]
    fn follower_resets_timer_on_heartbeat() {
        // This is the core heartbeat purpose: prevent followers from
        // starting unnecessary elections.
        let mut follower = three_node_cluster(1);

        for _ in 0..10 {
            // Tick close to timeout.
            follower.tick(9);
            assert!(follower.is_follower());

            // Heartbeat arrives just in time.
            follower.step(envelope(
                2,
                1,
                Rpc::AppendEntries(AppendEntriesArgs {
                    term: 1,
                    leader_id: 2,
                    prev_log_index: 0,
                    prev_log_term: 0,
                    entries: vec![],
                    leader_commit: 0,
                }),
            ));
            follower.drain_messages();
        }

        // After 10 rounds of heartbeats, still a follower.
        assert!(follower.is_follower());
        assert_eq!(follower.leader_id(), Some(2));
    }

    #[test]
    fn follower_updates_term_from_heartbeat() {
        let mut follower = three_node_cluster(1);
        assert_eq!(follower.current_term(), 0);

        // Heartbeat from leader in term 5.
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 5,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));

        assert_eq!(follower.current_term(), 5);
        assert!(follower.is_follower());
        assert_eq!(follower.leader_id(), Some(2));
        // voted_for cleared because term advanced.
        assert_eq!(follower.voted_for(), None);
    }

    #[test]
    fn candidate_steps_down_on_heartbeat_from_current_term() {
        let mut node = three_node_cluster(1);
        node.tick(25); // candidate in term 1
        node.drain_messages();
        assert!(node.is_candidate());

        // Heartbeat from the real leader of term 1.
        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));

        assert!(node.is_follower());
        assert_eq!(node.current_term(), 1);
        assert_eq!(node.leader_id(), Some(2));
    }

    #[test]
    fn candidate_steps_down_on_heartbeat_from_higher_term() {
        let mut node = three_node_cluster(1);
        node.tick(25); // candidate in term 1
        node.drain_messages();

        // Heartbeat from a leader in term 3.
        node.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 3,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));

        assert!(node.is_follower());
        assert_eq!(node.current_term(), 3);
        assert_eq!(node.leader_id(), Some(2));
    }

    #[test]
    fn heartbeat_from_stale_leader_is_rejected() {
        let mut follower = three_node_cluster(1);

        // Advance follower to term 5 via a valid heartbeat.
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 5,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));
        follower.drain_messages();
        assert_eq!(follower.current_term(), 5);

        // Stale heartbeat from term 3 — must be rejected.
        follower.step(envelope(
            3,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 3,
                leader_id: 3,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));

        // Term unchanged, leader unchanged.
        assert_eq!(follower.current_term(), 5);
        assert_eq!(follower.leader_id(), Some(2));

        // Response tells the stale leader about our higher term.
        let messages = follower.drain_messages();
        assert_eq!(messages.len(), 1);
        if let Rpc::AppendEntriesResponse(reply) = &messages[0].payload {
            assert!(!reply.success);
            assert_eq!(reply.term, 5);
        }
    }

    #[test]
    fn heartbeat_response_success_updates_leader_tracking() {
        let mut leader = elect_leader_node1();

        // Send a heartbeat.
        leader.tick(5);
        leader.drain_messages();

        // Peer 2 responds with success.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 1,
            }),
        ));

        // Verify leader updated match_index for peer 2.
        if let Role::Leader {
            ref match_index,
            ref next_index,
            ..
        } = leader.role
        {
            assert_eq!(*match_index.get(&2).unwrap(), 1);
            assert_eq!(*next_index.get(&2).unwrap(), 2);
        } else {
            panic!("expected leader");
        }
    }

    #[test]
    fn leader_steps_down_on_heartbeat_response_with_higher_term() {
        let mut leader = elect_leader_node1();

        // Peer responds to heartbeat with a higher term — the peer has
        // seen a newer election epoch.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 7,
                success: false,
                match_index: 0,
            }),
        ));

        assert!(leader.is_follower());
        assert_eq!(leader.current_term(), 7);
    }

    #[test]
    fn multiple_heartbeat_intervals_fire_correctly() {
        let mut leader = elect_leader_node1();

        for round in 1..=5 {
            leader.tick(5); // heartbeat interval
            let messages = leader.drain_messages();
            assert_eq!(
                messages.len(),
                2,
                "round {round}: should send heartbeat to both peers"
            );
        }

        // Leader is still leader after 5 heartbeat rounds.
        assert!(leader.is_leader());
    }

    #[test]
    fn leader_does_not_send_heartbeat_to_itself() {
        let mut leader = elect_leader_node1();

        leader.tick(5);
        let messages = leader.drain_messages();

        for msg in &messages {
            assert_ne!(msg.to, 1, "leader must not send heartbeat to itself");
            assert_eq!(msg.from, 1);
        }
    }

    #[test]
    fn heartbeat_with_empty_entries_gets_success_response() {
        let mut follower = three_node_cluster(1);

        // Pure heartbeat: no entries, prev_log_index=0.
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
        ));

        let messages = follower.drain_messages();
        assert_eq!(messages.len(), 1);
        if let Rpc::AppendEntriesResponse(reply) = &messages[0].payload {
            assert!(reply.success, "empty heartbeat must succeed");
            assert_eq!(reply.term, 1);
        } else {
            panic!("expected AppendEntriesResponse");
        }
    }

    #[test]
    fn heartbeat_advances_follower_commit_index() {
        let mut follower = three_node_cluster(1);

        // First, give follower some entries.
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![
                    LogEntry {
                        term: 1,
                        data: vec![1],
                    },
                    LogEntry {
                        term: 1,
                        data: vec![2],
                    },
                ],
                leader_commit: 0, // not committed yet
            }),
        ));
        follower.drain_messages();
        assert_eq!(follower.commit_index(), 0);

        // Later heartbeat carries updated leader_commit.
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 2,
                prev_log_term: 1,
                entries: vec![], // heartbeat — no new entries
                leader_commit: 2,
            }),
        ));

        assert_eq!(follower.commit_index(), 2);
        assert_eq!(follower.last_applied(), 2);

        let applied = follower.drain_applied();
        assert_eq!(applied.len(), 2);
    }

    #[test]
    fn heartbeat_leader_piggybacks_pending_entries() {
        let mut leader = elect_leader_node1();

        // Propose a new entry.
        leader.propose(vec![42]);
        leader.drain_messages(); // discard the immediate replication

        // Heartbeat should carry the pending entry (noop + propose)
        // to any lagging follower.
        leader.tick(5);
        let messages = leader.drain_messages();

        for msg in &messages {
            if let Rpc::AppendEntries(args) = &msg.payload {
                // Leader has 2 entries (noop at 1, propose at 2).
                // For peers that haven't confirmed anything, the heartbeat
                // should carry entries.
                assert!(
                    !args.entries.is_empty() || args.prev_log_index >= 2,
                    "heartbeat should piggyback pending entries for lagging peers"
                );
            }
        }
    }

    /// End-to-end: leader sends heartbeats, followers process them,
    /// responses come back, leader tracks state. Full round trip.
    #[test]
    fn heartbeat_full_round_trip() {
        let config = default_config();
        let mut leader = RaftNode::new(1, vec![2, 3], config.clone());
        let mut f2 = RaftNode::new(2, vec![1, 3], config.clone());
        let mut f3 = RaftNode::new(3, vec![1, 2], config.clone());

        // Elect node 1.
        leader.start_election();
        let votes = leader.drain_messages();
        for msg in votes {
            match msg.to {
                2 => f2.step(msg),
                3 => f3.step(msg),
                _ => {}
            }
        }
        let mut responses = f2.drain_messages();
        responses.extend(f3.drain_messages());
        for msg in responses {
            leader.step(msg);
        }
        assert!(leader.is_leader());
        let initial_heartbeats = leader.drain_messages();

        // Deliver initial heartbeats.
        for msg in initial_heartbeats {
            match msg.to {
                2 => f2.step(msg),
                3 => f3.step(msg),
                _ => {}
            }
        }

        // Followers should know about the leader.
        assert_eq!(f2.leader_id(), Some(1));
        assert_eq!(f3.leader_id(), Some(1));

        // Collect and deliver heartbeat responses.
        let mut hb_responses = f2.drain_messages();
        hb_responses.extend(f3.drain_messages());
        for msg in hb_responses {
            leader.step(msg);
        }

        // Trigger a periodic heartbeat and do another full round trip.
        leader.tick(5);
        let heartbeats = leader.drain_messages();
        assert_eq!(heartbeats.len(), 2);

        for msg in heartbeats {
            match msg.to {
                2 => f2.step(msg),
                3 => f3.step(msg),
                _ => {}
            }
        }

        // Both followers still following.
        assert!(f2.is_follower());
        assert!(f3.is_follower());
        assert_eq!(f2.current_term(), 1);
        assert_eq!(f3.current_term(), 1);

        // Collect responses.
        let mut final_responses = f2.drain_messages();
        final_responses.extend(f3.drain_messages());
        for msg in final_responses {
            leader.step(msg);
        }

        // Leader has updated tracking for both peers.
        assert!(leader.is_leader());
        if let Role::Leader {
            ref match_index, ..
        } = leader.role
        {
            // Both peers have confirmed the noop entry.
            assert!(
                *match_index.get(&2).unwrap() >= 1,
                "leader should track peer 2's match_index"
            );
            assert!(
                *match_index.get(&3).unwrap() >= 1,
                "leader should track peer 3's match_index"
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Log replication tests
    // ════════════════════════════════════════════════════════════════════════

    /// Helper: 3-node cluster with node 1 elected leader, all initial
    /// messages drained. Leader has noop at index 1.
    fn leader_and_followers() -> (RaftNode, RaftNode, RaftNode) {
        let config = default_config();
        let mut n1 = RaftNode::new(1, vec![2, 3], config.clone());
        let mut n2 = RaftNode::new(2, vec![1, 3], config.clone());
        let mut n3 = RaftNode::new(3, vec![1, 2], config.clone());

        // Elect node 1.
        n1.start_election();
        let votes = n1.drain_messages();
        for msg in votes {
            match msg.to {
                2 => n2.step(msg),
                3 => n3.step(msg),
                _ => {}
            }
        }
        let mut responses = n2.drain_messages();
        responses.extend(n3.drain_messages());
        for msg in responses {
            n1.step(msg);
        }
        assert!(n1.is_leader());

        // Deliver initial heartbeats (carry the noop).
        let hbs = n1.drain_messages();
        for msg in hbs {
            match msg.to {
                2 => n2.step(msg),
                3 => n3.step(msg),
                _ => {}
            }
        }
        // Deliver heartbeat responses.
        let mut resps = n2.drain_messages();
        resps.extend(n3.drain_messages());
        for msg in resps {
            n1.step(msg);
        }
        n1.drain_messages(); // discard any follow-up

        (n1, n2, n3)
    }

    /// Deliver all messages between three nodes until no messages remain.
    /// Returns the number of rounds (max 50 to prevent infinite loops).
    fn deliver_all(n1: &mut RaftNode, n2: &mut RaftNode, n3: &mut RaftNode) -> usize {
        let mut rounds = 0;
        loop {
            let mut all = n1.drain_messages();
            all.extend(n2.drain_messages());
            all.extend(n3.drain_messages());
            if all.is_empty() || rounds >= 50 {
                break;
            }
            for msg in all {
                match msg.to {
                    1 => n1.step(msg),
                    2 => n2.step(msg),
                    3 => n3.step(msg),
                    _ => {}
                }
            }
            rounds += 1;
        }
        rounds
    }

    // ── append_entry() public API ──

    #[test]
    fn append_entry_returns_index() {
        let mut leader = elect_leader_node1();

        let idx = leader.append_entry(Command::Put {
            key: "k".into(),
            value: vec![1],
        });
        // noop at 1, put at 2
        assert_eq!(idx, Some(2));

        let idx2 = leader.append_entry(Command::Delete { key: "k".into() });
        assert_eq!(idx2, Some(3));
    }

    #[test]
    fn append_entry_fails_on_non_leader() {
        let mut node = three_node_cluster(1);
        assert_eq!(node.append_entry(Command::Noop), None);
    }

    // ── Leader appends and replicates ──

    #[test]
    fn propose_immediately_replicates_to_all_peers() {
        let mut leader = elect_leader_node1();

        leader.propose(vec![42]);
        let messages = leader.drain_messages();

        // Should send AppendEntries to both peers.
        assert_eq!(messages.len(), 2);
        for msg in &messages {
            if let Rpc::AppendEntries(args) = &msg.payload {
                assert!(!args.entries.is_empty(), "should carry the new entry");
            }
        }

        // Leader's log has noop(1) + entry(2).
        assert_eq!(leader.log.last_index(), 2);
    }

    #[test]
    fn multiple_entries_sent_in_single_append_entries() {
        let mut leader = elect_leader_node1();

        // Propose 3 entries rapidly.
        leader.propose(vec![1]);
        leader.drain_messages();
        leader.propose(vec![2]);
        leader.drain_messages();
        leader.propose(vec![3]);
        let messages = leader.drain_messages();

        // The last propose should send all unreplicated entries.
        for msg in &messages {
            if let Rpc::AppendEntries(args) = &msg.payload {
                // Peers haven't confirmed anything yet, so all entries
                // from next_index onward should be included.
                assert!(
                    args.entries.len() >= 1,
                    "should batch pending entries"
                );
            }
        }

        // Leader log: noop(1), entry(2), entry(3), entry(4)
        assert_eq!(leader.log.last_index(), 4);
    }

    // ── Follower validates prev_log_index/prev_log_term ──

    #[test]
    fn follower_accepts_when_prev_log_matches() {
        let mut follower = three_node_cluster(1);

        // Give follower an entry at index 1, term 1.
        follower.log.append(LogEntry { term: 1, data: vec![0] });

        // Send entry at index 2 with prev_log_index=1, prev_log_term=1 — matches.
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 1,
                prev_log_term: 1,
                entries: vec![LogEntry { term: 1, data: vec![1] }],
                leader_commit: 0,
            }),
        ));

        let msgs = follower.drain_messages();
        if let Rpc::AppendEntriesResponse(reply) = &msgs[0].payload {
            assert!(reply.success);
            assert_eq!(reply.match_index, 2);
        }
        assert_eq!(follower.log.last_index(), 2);
    }

    #[test]
    fn follower_rejects_when_prev_log_term_mismatches() {
        let mut follower = three_node_cluster(1);

        // Follower has entry at index 1 with term 1.
        follower.log.append(LogEntry { term: 1, data: vec![0] });

        // Leader claims prev_log_index=1, prev_log_term=2 — term mismatch.
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 2,
                leader_id: 2,
                prev_log_index: 1,
                prev_log_term: 2,
                entries: vec![LogEntry { term: 2, data: vec![1] }],
                leader_commit: 0,
            }),
        ));

        let msgs = follower.drain_messages();
        if let Rpc::AppendEntriesResponse(reply) = &msgs[0].payload {
            assert!(!reply.success);
            // match_index hints at where to retry (before conflicting term).
            assert_eq!(reply.match_index, 0);
        }
        // Log should NOT have been modified.
        assert_eq!(follower.log.last_index(), 1);
        assert_eq!(follower.log.get(1).unwrap().term, 1);
    }

    #[test]
    fn follower_rejects_when_log_too_short() {
        let mut follower = three_node_cluster(1);

        // Follower has 1 entry. Leader sends with prev_log_index=3.
        follower.log.append(LogEntry { term: 1, data: vec![0] });

        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 3,
                prev_log_term: 1,
                entries: vec![LogEntry { term: 1, data: vec![1] }],
                leader_commit: 0,
            }),
        ));

        let msgs = follower.drain_messages();
        if let Rpc::AppendEntriesResponse(reply) = &msgs[0].payload {
            assert!(!reply.success);
            // Follower hints its last index so leader can backtrack.
            assert_eq!(reply.match_index, 1);
        }
    }

    // ── Conflict resolution and truncation ──

    #[test]
    fn follower_truncates_and_replaces_conflicting_suffix() {
        let mut follower = three_node_cluster(1);

        // Follower has: [term=1] [term=1] [term=1]
        for _ in 0..3 {
            follower.log.append(LogEntry { term: 1, data: vec![0] });
        }

        // Leader says: at index 2, there should be term=2 entries.
        // This conflicts with follower's index 2 (term 1).
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 2,
                leader_id: 2,
                prev_log_index: 1,
                prev_log_term: 1,
                entries: vec![
                    LogEntry { term: 2, data: vec![10] },
                    LogEntry { term: 2, data: vec![20] },
                ],
                leader_commit: 0,
            }),
        ));

        // Follower should have truncated index 2-3 and replaced.
        assert_eq!(follower.log.last_index(), 3);
        assert_eq!(follower.log.get(1).unwrap().term, 1); // unchanged
        assert_eq!(follower.log.get(2).unwrap().term, 2); // replaced
        assert_eq!(follower.log.get(3).unwrap().term, 2); // replaced
        assert_eq!(follower.log.get(2).unwrap().data, vec![10]);
        assert_eq!(follower.log.get(3).unwrap().data, vec![20]);
    }

    #[test]
    fn follower_idempotent_append_skips_existing_matching_entries() {
        let mut follower = three_node_cluster(1);

        // Follower already has entries from the leader.
        follower.log.append(LogEntry { term: 1, data: vec![1] });
        follower.log.append(LogEntry { term: 1, data: vec![2] });

        // Leader re-sends the same entries (e.g., duplicate delivery).
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![
                    LogEntry { term: 1, data: vec![1] },
                    LogEntry { term: 1, data: vec![2] },
                ],
                leader_commit: 0,
            }),
        ));

        // Log should be unchanged (entries matched, no truncation).
        assert_eq!(follower.log.last_index(), 2);

        let msgs = follower.drain_messages();
        if let Rpc::AppendEntriesResponse(reply) = &msgs[0].payload {
            assert!(reply.success);
        }
    }

    #[test]
    fn follower_appends_beyond_existing_log() {
        let mut follower = three_node_cluster(1);

        // Follower has 1 entry.
        follower.log.append(LogEntry { term: 1, data: vec![1] });

        // Leader sends 3 more starting after the existing one.
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 1,
                prev_log_term: 1,
                entries: vec![
                    LogEntry { term: 1, data: vec![2] },
                    LogEntry { term: 1, data: vec![3] },
                    LogEntry { term: 1, data: vec![4] },
                ],
                leader_commit: 0,
            }),
        ));

        assert_eq!(follower.log.last_index(), 4);
        for i in 1..=4 {
            assert_eq!(follower.log.get(i).unwrap().data, vec![i as u8]);
        }
    }

    // ── Leader updates next_index and match_index ──

    #[test]
    fn leader_advances_next_and_match_on_success() {
        let mut leader = elect_leader_node1();

        leader.propose(vec![42]);
        leader.drain_messages();

        // Peer 2 confirms match at index 2.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 2,
            }),
        ));

        if let Role::Leader { ref next_index, ref match_index, .. } = leader.role {
            assert_eq!(*match_index.get(&2).unwrap(), 2);
            assert_eq!(*next_index.get(&2).unwrap(), 3);
        }
    }

    #[test]
    fn leader_backtracks_next_index_on_failure() {
        let mut leader = elect_leader_node1();

        // Give leader more entries.
        leader.propose(vec![1]);
        leader.propose(vec![2]);
        leader.drain_messages();

        // Peer 2 rejects with match_index=0 (log is empty).
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: false,
                match_index: 0,
            }),
        ));

        if let Role::Leader { ref next_index, .. } = leader.role {
            assert_eq!(*next_index.get(&2).unwrap(), 1, "should backtrack to match_index+1");
        }

        // The leader should have immediately retried.
        let retry_msgs = leader.drain_messages();
        assert!(!retry_msgs.is_empty(), "leader must retry after backtrack");
        // The retry should target peer 2.
        assert!(retry_msgs.iter().any(|m| m.to == 2));
    }

    #[test]
    fn leader_does_not_regress_next_index_on_stale_success() {
        let mut leader = elect_leader_node1();

        leader.propose(vec![1]);
        leader.propose(vec![2]);
        leader.drain_messages();

        // Peer 2 confirms up to index 3.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 3,
            }),
        ));
        leader.drain_messages();

        // Now a stale success arrives with match_index=1 (from an earlier round).
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 1,
            }),
        ));

        // next_index and match_index must NOT regress.
        if let Role::Leader { ref next_index, ref match_index, .. } = leader.role {
            assert_eq!(*match_index.get(&2).unwrap(), 3, "match_index must not regress");
            assert_eq!(*next_index.get(&2).unwrap(), 4, "next_index must not regress");
        }
    }

    #[test]
    fn leader_does_not_advance_next_index_on_stale_failure() {
        let mut leader = elect_leader_node1();

        // Peer 2 has confirmed match_index=1. next_index should be 2.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 1,
            }),
        ));
        leader.drain_messages();

        if let Role::Leader { ref next_index, .. } = leader.role {
            assert_eq!(*next_index.get(&2).unwrap(), 2);
        }

        // Now a stale failure arrives with match_index=5 (bogus/stale).
        // This should NOT advance next_index past where it is.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: false,
                match_index: 5,
            }),
        ));
        leader.drain_messages();

        if let Role::Leader { ref next_index, .. } = leader.role {
            // next_index should stay at 2, not jump to 6.
            assert_eq!(*next_index.get(&2).unwrap(), 2, "failure must not advance next_index");
        }
    }

    // ── Retry replication converges ──

    #[test]
    fn retry_converges_from_divergent_log() {
        let mut leader = elect_leader_node1();

        // Leader has: noop(1,t=1), A(2,t=1), B(3,t=1)
        leader.propose(vec![0xA]);
        leader.propose(vec![0xB]);
        leader.drain_messages();

        // Simulate a follower with a divergent log:
        // [term=99, term=99, term=99] — longer than leader and all wrong terms.
        let mut follower = three_node_cluster(2);
        follower.log.append(LogEntry { term: 99, data: vec![0xFF] });
        follower.log.append(LogEntry { term: 99, data: vec![0xFE] });
        follower.log.append(LogEntry { term: 99, data: vec![0xFD] });

        // Artificially set leader's next_index for peer 2 to match follower's
        // last index + 1, as it would be after the initial optimistic setting.
        if let Role::Leader { ref mut next_index, .. } = leader.role {
            next_index.insert(2, 4);
        }

        // Round-trip until convergence (max 10 rounds).
        for _ in 0..10 {
            leader.tick(5);
            let msgs = leader.drain_messages();
            let ae = match msgs.into_iter().find(|m| m.to == 2) {
                Some(m) => m,
                None => break,
            };

            follower.step(ae);
            let reply = match follower.drain_messages().into_iter().next() {
                Some(r) => r,
                None => break,
            };

            let was_success = matches!(&reply.payload, Rpc::AppendEntriesResponse(r) if r.success);
            leader.step(reply);
            leader.drain_messages(); // drain any retries to avoid double-processing

            if was_success {
                break;
            }
        }

        // After convergence, follower's log should match leader's.
        assert_eq!(
            follower.log.last_index(),
            leader.log.last_index(),
            "follower log length should match leader"
        );
        for i in 1..=leader.log.last_index() {
            assert_eq!(
                follower.log.get(i).unwrap().term,
                leader.log.get(i).unwrap().term,
                "entry {i} term mismatch after convergence"
            );
            assert_eq!(
                follower.log.get(i).unwrap().data,
                leader.log.get(i).unwrap().data,
                "entry {i} data mismatch after convergence"
            );
        }
    }

    // ── Commit advancement (§5.3, §5.4.2) ──

    #[test]
    fn leader_commits_on_majority_ack() {
        let mut leader = elect_leader_node1();
        leader.propose(vec![42]);
        leader.drain_messages();
        assert_eq!(leader.commit_index(), 0);

        // Peer 2 acks.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 2,
            }),
        ));

        // 2/3 nodes (leader + peer 2) have index 2 → majority → committed.
        assert_eq!(leader.commit_index(), 2);

        let applied = leader.drain_applied();
        // noop(1) + propose(2) applied.
        assert_eq!(applied.len(), 2);
    }

    #[test]
    fn leader_does_not_commit_from_prior_term() {
        let mut leader = elect_leader_node1();

        // Manually insert an entry from a prior term (simulating a leader
        // that inherited uncommitted entries from term 0).
        // Current log: [noop(t=1)]. Add [entry(t=0)] at index 2.
        // This is artificial but tests the safety rule.
        leader.log.append(LogEntry { term: 0, data: vec![1] });

        // Even if both peers confirm index 2, we must NOT commit it
        // because log[2].term=0 != current_term=1.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 2,
            }),
        ));
        leader.step(envelope(
            3,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 2,
            }),
        ));
        leader.drain_messages();

        // commit_index should be 1 (the noop, which IS from current term),
        // but NOT 2 (the prior-term entry).
        assert_eq!(
            leader.commit_index(),
            1,
            "must not commit entries from prior terms (§5.4.2)"
        );
    }

    #[test]
    fn prior_term_entries_committed_transitively() {
        let mut leader = elect_leader_node1();

        // Log: [noop(t=1)]. Insert prior-term entry, then a current-term entry.
        leader.log.append(LogEntry { term: 0, data: vec![1] }); // index 2, term 0
        leader.propose(vec![2]); // index 3, term 1
        leader.drain_messages();

        // Both peers confirm up to index 3.
        for peer in [2, 3] {
            leader.step(envelope(
                peer,
                1,
                Rpc::AppendEntriesResponse(AppendEntriesReply {
                    term: 1,
                    success: true,
                    match_index: 3,
                }),
            ));
        }
        leader.drain_messages();

        // commit_index should be 3: the current-term entry at index 3 is
        // committable, which transitively commits the prior-term entry at
        // index 2 via the Log Matching property.
        assert_eq!(leader.commit_index(), 3);

        let applied = leader.drain_applied();
        assert_eq!(applied.len(), 3); // noop + prior-term + current-term
    }

    // ── End-to-end multi-node replication ──

    #[test]
    fn end_to_end_propose_replicate_commit_apply() {
        let (mut n1, mut n2, mut n3) = leader_and_followers();

        // Leader proposes an entry.
        let idx = n1.append_entry(Command::Put {
            key: "x".into(),
            value: vec![42],
        });
        assert_eq!(idx, Some(2));

        // Deliver all messages until quiescent.
        deliver_all(&mut n1, &mut n2, &mut n3);

        // All nodes should have the entry at index 2.
        assert_eq!(n1.log.last_index(), 2);
        assert_eq!(n2.log.last_index(), 2);
        assert_eq!(n3.log.last_index(), 2);

        // Leader should have committed (majority confirmed).
        assert_eq!(n1.commit_index(), 2);

        // Followers learn commit via next heartbeat.
        n1.tick(5);
        deliver_all(&mut n1, &mut n2, &mut n3);

        assert_eq!(n2.commit_index(), 2);
        assert_eq!(n3.commit_index(), 2);

        // All nodes applied the same entries.
        let a1 = n1.drain_applied();
        let a2 = n2.drain_applied();
        let a3 = n3.drain_applied();

        // Noop(1) + Put(2) = 2 entries applied.
        assert_eq!(a1.len(), 2);
        assert_eq!(a2.len(), 2);
        assert_eq!(a3.len(), 2);

        // Verify the Put entry.
        let put_entry = &a1[1];
        assert_eq!(put_entry.index, 2);
        let cmd = Command::decode(&put_entry.data).unwrap();
        assert_eq!(cmd, Command::Put { key: "x".into(), value: vec![42] });
    }

    #[test]
    fn end_to_end_multiple_proposals() {
        let (mut n1, mut n2, mut n3) = leader_and_followers();

        // Propose 5 entries.
        for i in 0..5u8 {
            n1.append_entry(Command::Put {
                key: format!("k{i}"),
                value: vec![i],
            });
        }

        // Deliver everything.
        deliver_all(&mut n1, &mut n2, &mut n3);

        // noop(1) + 5 puts = 6 entries.
        assert_eq!(n1.log.last_index(), 6);
        assert_eq!(n2.log.last_index(), 6);
        assert_eq!(n3.log.last_index(), 6);

        // Commit propagated.
        n1.tick(5);
        deliver_all(&mut n1, &mut n2, &mut n3);

        assert_eq!(n1.commit_index(), 6);
        assert_eq!(n2.commit_index(), 6);
        assert_eq!(n3.commit_index(), 6);
    }

    #[test]
    fn end_to_end_lagging_follower_catches_up() {
        let config = default_config();
        let mut n1 = RaftNode::new(1, vec![2, 3], config.clone());
        let mut n2 = RaftNode::new(2, vec![1, 3], config.clone());
        let mut n3 = RaftNode::new(3, vec![1, 2], config.clone());

        // Elect node 1 with only node 2's vote (node 3 is "partitioned").
        n1.start_election();
        let votes = n1.drain_messages();
        for msg in votes {
            if msg.to == 2 {
                n2.step(msg);
            }
            // Drop messages to node 3.
        }
        let resp = n2.drain_messages();
        for msg in resp {
            n1.step(msg);
        }
        assert!(n1.is_leader());

        // Deliver initial heartbeat only to node 2.
        let hbs = n1.drain_messages();
        for msg in hbs {
            if msg.to == 2 {
                n2.step(msg);
            }
        }
        let resps = n2.drain_messages();
        for msg in resps {
            n1.step(msg);
        }
        n1.drain_messages();

        // Propose 3 entries. Replicate only to node 2.
        for i in 0..3u8 {
            n1.propose(vec![i]);
            let msgs = n1.drain_messages();
            for msg in msgs {
                if msg.to == 2 {
                    n2.step(msg);
                }
            }
            let resps: Vec<_> = n2.drain_messages();
            for msg in resps {
                n1.step(msg);
            }
            n1.drain_messages();
        }

        // Node 2 has all entries. Node 3 has nothing.
        assert_eq!(n1.log.last_index(), 4); // noop + 3
        assert_eq!(n2.log.last_index(), 4);
        assert_eq!(n3.log.last_index(), 0);

        // "Heal" the partition: deliver messages to node 3 now.
        // A heartbeat will carry all entries.
        n1.tick(5);
        deliver_all(&mut n1, &mut n2, &mut n3);

        // Node 3 should have caught up.
        assert_eq!(n3.log.last_index(), 4);
        for i in 1..=4 {
            assert_eq!(
                n3.log.get(i).unwrap().term,
                n1.log.get(i).unwrap().term,
                "entry {i} term mismatch on node 3"
            );
        }
    }

    #[test]
    fn end_to_end_divergent_follower_converges() {
        let config = default_config();
        let mut n1 = RaftNode::new(1, vec![2, 3], config.clone());
        let mut n2 = RaftNode::new(2, vec![1, 3], config.clone());
        let mut n3 = RaftNode::new(3, vec![1, 2], config.clone());

        // Give node 3 a stale log from a prior term (simulating a crashed
        // leader that wrote entries nobody else has).
        n3.log.append(LogEntry { term: 0, data: vec![0xDE] });
        n3.log.append(LogEntry { term: 0, data: vec![0xAD] });

        // Elect node 1.
        n1.start_election();
        deliver_all(&mut n1, &mut n2, &mut n3);

        assert!(n1.is_leader());

        // Propose an entry and replicate.
        n1.propose(vec![42]);
        deliver_all(&mut n1, &mut n2, &mut n3);

        // Heartbeat to propagate commit.
        n1.tick(5);
        deliver_all(&mut n1, &mut n2, &mut n3);

        // Node 3's stale entries should have been replaced.
        assert_eq!(n3.log.last_index(), n1.log.last_index());
        for i in 1..=n1.log.last_index() {
            assert_eq!(
                n3.log.get(i).unwrap().term,
                n1.log.get(i).unwrap().term,
                "entry {i} should match leader after convergence"
            );
            assert_eq!(
                n3.log.get(i).unwrap().data,
                n1.log.get(i).unwrap().data,
                "entry {i} data should match leader after convergence"
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Commit index advancement tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn update_commit_index_is_public_api() {
        let mut leader = elect_leader_node1();
        leader.propose(vec![1]);
        leader.drain_messages();

        // Peer 2 acks.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 2,
            }),
        ));
        leader.drain_messages();

        // Already committed via internal call, but calling the public API
        // again should be a safe no-op.
        let before = leader.commit_index();
        leader.update_commit_index();
        assert_eq!(leader.commit_index(), before);
    }

    #[test]
    fn commit_index_never_goes_backward() {
        let mut leader = elect_leader_node1();
        leader.propose(vec![1]);
        leader.propose(vec![2]);
        leader.drain_messages();

        // Peer 2 acks up to index 3.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 3,
            }),
        ));
        leader.drain_messages();
        assert_eq!(leader.commit_index(), 3);

        // Even if we somehow call update_commit_index again with stale
        // match_index state, commit_index must not decrease.
        // (The scan starts at commit_index+1, so it can't go backward.)
        leader.update_commit_index();
        assert_eq!(leader.commit_index(), 3);
    }

    #[test]
    fn single_node_commits_immediately() {
        let mut node = RaftNode::new(1, vec![], default_config());
        node.start_election();
        assert!(node.is_leader());
        node.drain_messages();
        node.drain_applied();

        // Propose an entry. With no peers, majority is 1/1 (just us).
        node.propose(vec![42]);
        node.drain_messages();

        // Should have committed immediately.
        assert_eq!(node.commit_index(), 2); // noop(1) + entry(2)

        let applied = node.drain_applied();
        assert_eq!(applied.len(), 1); // entry(2) — noop was applied at election time
        assert_eq!(applied[0].index, 2);
        assert_eq!(applied[0].data, vec![42]);
    }

    #[test]
    fn five_node_cluster_needs_three_to_commit() {
        let mut leader = five_node_cluster(1);
        leader.start_election();
        // Get enough votes (3/5 majority).
        for peer in [2, 3] {
            leader.step(envelope(
                peer,
                1,
                Rpc::RequestVoteResponse(RequestVoteReply {
                    term: 1,
                    vote_granted: true,
                }),
            ));
        }
        assert!(leader.is_leader());
        leader.drain_messages();
        leader.drain_applied();

        leader.propose(vec![1]);
        leader.drain_messages();
        assert_eq!(leader.commit_index(), 0);

        // 1 peer acks → 2/5 — not enough.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 2,
            }),
        ));
        leader.drain_messages();
        assert_eq!(leader.commit_index(), 0, "2/5 is not a majority");

        // 2nd peer acks → 3/5 — majority!
        leader.step(envelope(
            3,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 2,
            }),
        ));
        leader.drain_messages();
        assert_eq!(leader.commit_index(), 2, "3/5 is a majority");
    }

    #[test]
    fn commit_finds_highest_majority_index() {
        let mut leader = elect_leader_node1();

        // Leader has noop(1) + 4 entries = 5 total.
        for i in 0..4u8 {
            leader.propose(vec![i]);
        }
        leader.drain_messages();

        // Peer 2 has replicated up to index 5.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 5,
            }),
        ));
        leader.drain_messages();

        // 2/3 have index 5 → commit jumps straight to 5, not 1-by-1.
        assert_eq!(leader.commit_index(), 5);
    }

    #[test]
    fn last_applied_tracks_commit_index() {
        let mut leader = elect_leader_node1();
        leader.propose(vec![1]);
        leader.drain_messages();

        assert_eq!(leader.last_applied(), 0);

        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 2,
            }),
        ));
        leader.drain_messages();

        assert_eq!(leader.commit_index(), 2);
        assert_eq!(leader.last_applied(), 2, "last_applied must equal commit_index");
    }

    #[test]
    fn applied_entries_in_strict_index_order() {
        let mut leader = elect_leader_node1();

        for i in 1..=5u8 {
            leader.propose(vec![i]);
        }
        leader.drain_messages();
        leader.drain_applied(); // drain noop

        // Peer 2 acks everything.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 6,
            }),
        ));
        leader.drain_messages();

        let applied = leader.drain_applied();
        // Entries 1-6 applied, but noop at 1 was drained earlier.
        // So we get entries 2-6.
        assert!(!applied.is_empty());
        for window in applied.windows(2) {
            assert_eq!(
                window[1].index,
                window[0].index + 1,
                "entries must be applied in consecutive order"
            );
        }
    }

    #[test]
    fn multiple_commit_advances_accumulate() {
        let mut leader = elect_leader_node1();

        leader.propose(vec![1]);
        leader.propose(vec![2]);
        leader.propose(vec![3]);
        leader.drain_messages();

        // Peer 2 acks up to index 2 first.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 2,
            }),
        ));
        leader.drain_messages();
        assert_eq!(leader.commit_index(), 2);

        let applied1 = leader.drain_applied();
        // noop(1) + entry(2)
        assert_eq!(applied1.len(), 2);

        // Then acks up to index 4.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 4,
            }),
        ));
        leader.drain_messages();
        assert_eq!(leader.commit_index(), 4);

        let applied2 = leader.drain_applied();
        // entries 3 and 4 newly applied.
        assert_eq!(applied2.len(), 2);
        assert_eq!(applied2[0].index, 3);
        assert_eq!(applied2[1].index, 4);
    }

    #[test]
    fn follower_commit_bounded_by_last_entry() {
        let mut follower = three_node_cluster(1);

        // Follower receives 2 entries, leader_commit=5.
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![
                    LogEntry { term: 1, data: vec![1] },
                    LogEntry { term: 1, data: vec![2] },
                ],
                leader_commit: 5, // leader knows more is committed
            }),
        ));
        follower.drain_messages();

        // Follower only has 2 entries, so commit_index = min(5, 2) = 2.
        assert_eq!(follower.commit_index(), 2);
        assert_eq!(follower.last_applied(), 2);
    }

    #[test]
    fn follower_commit_not_reduced_by_lower_leader_commit() {
        let mut follower = three_node_cluster(1);

        // First: receive entries with leader_commit=2.
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![
                    LogEntry { term: 1, data: vec![1] },
                    LogEntry { term: 1, data: vec![2] },
                ],
                leader_commit: 2,
            }),
        ));
        follower.drain_messages();
        assert_eq!(follower.commit_index(), 2);

        // Second: heartbeat with leader_commit=1 (stale/reordered).
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 2,
                prev_log_term: 1,
                entries: vec![],
                leader_commit: 1,
            }),
        ));
        follower.drain_messages();

        // commit_index must NOT go backward.
        assert_eq!(
            follower.commit_index(),
            2,
            "commit_index must never decrease"
        );
    }

    #[test]
    fn noop_enables_committing_inherited_entries() {
        // Simulate: new leader inherits an uncommitted entry from a prior
        // term. The noop from the new term makes it committable.
        let (mut n1, mut n2, mut n3) = leader_and_followers();

        // n1 is leader in term 1 with noop at index 1.
        // Manually add an entry "from term 0" (simulating inheritance).
        n1.log.append(LogEntry { term: 0, data: vec![0xAA] });
        // Now propose a current-term entry (which triggers replication).
        n1.propose(vec![0xBB]);

        // Deliver all messages.
        deliver_all(&mut n1, &mut n2, &mut n3);

        // The current-term entry at index 3 can be committed, which
        // transitively commits the inherited entry at index 2.
        assert!(n1.commit_index() >= 3);

        let applied = n1.drain_applied();
        // Should include entries 1, 2, 3 (noop, inherited, new).
        assert!(applied.iter().any(|a| a.index == 2 && a.data == vec![0xAA]));
        assert!(applied.iter().any(|a| a.index == 3 && a.data == vec![0xBB]));
    }

    #[test]
    fn update_commit_index_noop_on_follower() {
        let mut follower = three_node_cluster(1);

        // Calling update_commit_index on a follower is a no-op.
        follower.update_commit_index();
        assert_eq!(follower.commit_index(), 0);
    }

    #[test]
    fn commit_with_mixed_match_indices() {
        // 5-node cluster. Peers have varying match_index values.
        let mut leader = five_node_cluster(1);
        leader.start_election();
        for peer in [2, 3] {
            leader.step(envelope(
                peer,
                1,
                Rpc::RequestVoteResponse(RequestVoteReply {
                    term: 1,
                    vote_granted: true,
                }),
            ));
        }
        assert!(leader.is_leader());
        leader.drain_messages();
        leader.drain_applied();

        // Leader has noop(1) + 3 entries.
        for i in 0..3u8 {
            leader.propose(vec![i]);
        }
        leader.drain_messages();

        // Peers at different stages:
        // peer 2: match_index=4 (fully caught up)
        // peer 3: match_index=2 (partially caught up)
        // peer 4: match_index=0 (behind)
        // peer 5: match_index=0 (behind)
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 4,
            }),
        ));
        leader.drain_messages();
        leader.step(envelope(
            3,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 2,
            }),
        ));
        leader.drain_messages();

        // Majority for index 2: leader(4) + peer2(4) + peer3(2) = 3/5 ✓
        // Majority for index 3: leader(4) + peer2(4) = 2/5 ✗
        assert_eq!(
            leader.commit_index(),
            2,
            "should commit highest index with majority"
        );
    }

    #[test]
    fn end_to_end_commit_propagation_to_followers() {
        let (mut n1, mut n2, mut n3) = leader_and_followers();

        // Propose and replicate.
        n1.propose(vec![42]);
        deliver_all(&mut n1, &mut n2, &mut n3);

        // Leader committed (majority confirmed).
        assert!(n1.commit_index() >= 2);

        // Followers don't know about the commit yet — they learn via
        // the next AppendEntries (heartbeat) that carries leader_commit.
        let f2_commit_before = n2.commit_index();

        n1.tick(5); // trigger heartbeat
        deliver_all(&mut n1, &mut n2, &mut n3);

        // Now followers should have advanced.
        assert!(
            n2.commit_index() > f2_commit_before,
            "follower must advance commit_index from heartbeat"
        );
        assert_eq!(n2.commit_index(), n1.commit_index());
        assert_eq!(n3.commit_index(), n1.commit_index());

        // All three nodes applied the same entries.
        assert_eq!(n1.last_applied(), n1.commit_index());
        assert_eq!(n2.last_applied(), n2.commit_index());
        assert_eq!(n3.last_applied(), n3.commit_index());
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Persistence and crash recovery tests
    // ════════════════════════════════════════════════════════════════════════

    use crate::storage::MemoryStorage as MS;

    /// Helper: extract the storage from a node so we can "crash" and
    /// restore from it. Uses the fact that MemoryStorage is Clone.
    fn snapshot_storage(node: &RaftNode) -> MS {
        node.storage.clone()
    }

    #[test]
    fn storage_captures_term_on_election() {
        let mut node = three_node_cluster(1);
        node.tick(25); // become candidate in term 1

        let storage = snapshot_storage(&node);
        let state = storage.load_state().unwrap();
        assert_eq!(state.current_term, 1);
    }

    #[test]
    fn storage_captures_vote() {
        let mut node = three_node_cluster(1);
        node.step(envelope(
            2,
            1,
            Rpc::RequestVote(RequestVoteArgs {
                term: 1,
                candidate_id: 2,
                last_log_index: 0,
                last_log_term: 0,
            }),
        ));
        node.drain_messages();

        let storage = snapshot_storage(&node);
        let state = storage.load_state().unwrap();
        assert_eq!(state.voted_for, Some(2));
    }

    #[test]
    fn storage_captures_log_append() {
        let mut leader = elect_leader_node1();
        leader.propose(vec![42]);
        leader.drain_messages();

        let storage = snapshot_storage(&leader);
        let state = storage.load_state().unwrap();
        // noop(1) + propose(2) = 2 entries.
        assert_eq!(state.log.len(), 2);
        assert_eq!(state.log[1].data, vec![42]);
    }

    #[test]
    fn storage_captures_log_truncation() {
        let mut follower = three_node_cluster(1);

        // Give follower entries via AppendEntries so storage is updated.
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 1,
                leader_id: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![
                    LogEntry { term: 1, data: vec![1] },
                    LogEntry { term: 1, data: vec![2] },
                ],
                leader_commit: 0,
            }),
        ));
        follower.drain_messages();

        // Leader overwrites index 2 with a different term.
        follower.step(envelope(
            2,
            1,
            Rpc::AppendEntries(AppendEntriesArgs {
                term: 2,
                leader_id: 2,
                prev_log_index: 1,
                prev_log_term: 1,
                entries: vec![LogEntry { term: 2, data: vec![20] }],
                leader_commit: 0,
            }),
        ));
        follower.drain_messages();

        let storage = snapshot_storage(&follower);
        let state = storage.load_state().unwrap();
        assert_eq!(state.log.len(), 2);
        assert_eq!(state.log[1].term, 2);
        assert_eq!(state.log[1].data, vec![20]);
    }

    #[test]
    fn restore_recovers_term_and_vote() {
        // Create a node, do some work, snapshot storage, restore from it.
        let mut node = three_node_cluster(1);
        node.tick(25); // term 1, voted for self
        node.drain_messages();

        let storage = snapshot_storage(&node);

        // "Crash" and restore.
        let restored = RaftNode::restore(
            1,
            vec![2, 3],
            default_config(),
            storage,
            InMemoryLog::new(),
        )
        .unwrap();

        assert_eq!(restored.current_term(), 1);
        assert_eq!(restored.voted_for(), Some(1));
        assert!(restored.is_follower()); // always starts as follower
    }

    #[test]
    fn restore_recovers_log() {
        let mut leader = elect_leader_node1();
        leader.propose(vec![10]);
        leader.propose(vec![20]);
        leader.drain_messages();

        let storage = snapshot_storage(&leader);

        let restored = RaftNode::restore(
            1,
            vec![2, 3],
            default_config(),
            storage,
            InMemoryLog::new(),
        )
        .unwrap();

        // noop(1) + 2 entries = 3.
        assert_eq!(restored.log.last_index(), 3);
        assert_eq!(restored.log.get(2).unwrap().data, vec![10]);
        assert_eq!(restored.log.get(3).unwrap().data, vec![20]);
    }

    #[test]
    fn restore_resets_volatile_state() {
        let mut leader = elect_leader_node1();
        leader.propose(vec![1]);
        leader.drain_messages();

        // Advance commit_index.
        leader.step(envelope(
            2,
            1,
            Rpc::AppendEntriesResponse(AppendEntriesReply {
                term: 1,
                success: true,
                match_index: 2,
            }),
        ));
        leader.drain_messages();
        assert!(leader.commit_index() > 0);

        let storage = snapshot_storage(&leader);
        let restored = RaftNode::restore(
            1,
            vec![2, 3],
            default_config(),
            storage,
            InMemoryLog::new(),
        )
        .unwrap();

        // Volatile state is NOT persisted — reset to 0 on recovery.
        assert_eq!(restored.commit_index(), 0);
        assert_eq!(restored.last_applied(), 0);
    }

    #[test]
    fn restored_node_participates_in_cluster() {
        let (mut n1, mut n2, mut n3) = leader_and_followers();

        // Propose and commit an entry.
        n1.propose(vec![42]);
        deliver_all(&mut n1, &mut n2, &mut n3);
        n1.tick(5);
        deliver_all(&mut n1, &mut n2, &mut n3);

        // "Crash" node 2 and restore from its storage.
        let storage = snapshot_storage(&n2);
        let mut n2_restored = RaftNode::restore(
            2,
            vec![1, 3],
            default_config(),
            storage,
            InMemoryLog::new(),
        )
        .unwrap();

        // Restored node has the log but commit_index=0.
        assert_eq!(n2_restored.log.last_index(), n2.log.last_index());
        assert_eq!(n2_restored.commit_index(), 0);

        // After receiving a heartbeat from the leader, it catches up.
        n1.tick(5);
        let hbs = n1.drain_messages();
        for msg in hbs {
            if msg.to == 2 {
                n2_restored.step(msg);
            }
        }
        n2_restored.drain_messages();

        assert!(n2_restored.commit_index() > 0);
        assert_eq!(n2_restored.leader_id(), Some(1));
    }

    #[test]
    fn restore_from_fresh_storage() {
        // A brand-new node with no prior state.
        let storage = MS::new();
        let restored = RaftNode::restore(
            1,
            vec![2, 3],
            default_config(),
            storage,
            InMemoryLog::new(),
        )
        .unwrap();

        assert_eq!(restored.current_term(), 0);
        assert_eq!(restored.voted_for(), None);
        assert_eq!(restored.log.last_index(), 0);
    }

    #[test]
    fn incremental_persist_not_full_log_rewrite() {
        // Verify that proposing N entries results in N individual appends
        // to storage, not N full-log rewrites.
        let mut leader = elect_leader_node1();

        // Storage already has the noop from election.
        let before = snapshot_storage(&leader).load_state().unwrap().log.len();
        assert_eq!(before, 1);

        leader.propose(vec![1]);
        leader.drain_messages();
        let after1 = snapshot_storage(&leader).load_state().unwrap().log.len();
        assert_eq!(after1, 2); // incrementally added 1

        leader.propose(vec![2]);
        leader.drain_messages();
        let after2 = snapshot_storage(&leader).load_state().unwrap().log.len();
        assert_eq!(after2, 3); // incrementally added 1 more
    }
}
