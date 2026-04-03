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
        self.log.append(entry);
        self.persist_log();

        // Immediately try to replicate to all followers.
        self.replicate_to_all();
        true
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
        self.log.append(noop);
        self.persist_log();

        // Send heartbeats to all peers to establish authority.
        self.send_heartbeats();
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
                    self.log.append(entry.clone());
                }
                None => {
                    // New entry beyond our log — append.
                    self.log.append(entry.clone());
                }
            }
        }
        self.persist_log();

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
            if let Some(mi) = match_index.get_mut(&from) {
                if reply.match_index > *mi {
                    *mi = reply.match_index;
                }
            }
            if let Some(ni) = next_index.get_mut(&from) {
                *ni = reply.match_index + 1;
            }

            // Check if we can advance the commit index.
            self.maybe_advance_commit_index();
        } else {
            // Backtrack using the match_index hint from the follower.
            if let Some(ni) = next_index.get_mut(&from) {
                *ni = reply.match_index + 1;
            }

            // Retry immediately with the updated next_index.
            self.replicate_to(from);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Commit index advancement (§5.3, §5.4.2)
    // ════════════════════════════════════════════════════════════════════════

    /// Try to advance the commit index.
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

    /// Persist the current term and voted_for. Must be called before responding
    /// to any RPC that depends on the updated state.
    fn persist_state(&mut self) {
        // In a production system, failure here is fatal — we cannot safely
        // continue if persistent state is not durable.
        let _ = self.storage.save_state(&self.persistent);
    }

    /// Persist the log. Called after any log mutation.
    fn persist_log(&mut self) {
        // Collect all entries for saving. A real implementation would use
        // incremental writes, but for MemoryStorage this is fine.
        let entries: Vec<LogEntry> = (1..=self.log.last_index())
            .filter_map(|i| self.log.get(i).cloned())
            .collect();
        let _ = self.storage.save_log(&entries);
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
}
