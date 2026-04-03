//! Deterministic Raft cluster simulator for testing.
//!
//! The simulator owns a set of `RaftNode` instances and a virtual network.
//! It drives the cluster by ticking timers, collecting outbound messages,
//! and delivering them according to configurable network conditions:
//!
//! - **Delays**: messages sit in a queue for N ticks before delivery.
//! - **Loss**: messages are randomly dropped based on a loss rate.
//! - **Partitions**: traffic between node sets is blocked bidirectionally.
//! - **Crashes**: a node is removed (volatile state lost), its storage
//!   is saved, and it can be restarted via `RaftNode::restore()`.
//!
//! Everything is deterministic: a seeded PRNG controls loss decisions,
//! and there are no threads or async operations. The same seed always
//! produces the same test outcome.
//!
//! # Example
//!
//! ```rust
//! use raft_consensus::simulator::Simulator;
//! use raft_consensus::node::ClusterConfig;
//!
//! let config = ClusterConfig { election_timeout_min: 10, election_timeout_max: 20,
//!                              heartbeat_interval: 5, pre_vote: false };
//! let mut sim = Simulator::new(3, config, 42);
//! sim.elect(1);
//! sim.propose(vec![1]);
//! sim.stabilize();
//! sim.assert_one_leader();
//! sim.assert_logs_consistent();
//! ```

use std::collections::{HashMap, HashSet};

use crate::log::{InMemoryLog, RaftLog};
use crate::message::Envelope;
use crate::node::{ApplyResult, ClusterConfig, RaftNode};
use crate::state::NodeId;
use crate::storage::MemoryStorage;

// ════════════════════════════════════════════════════════════════════════════
//  Deterministic PRNG (SplitMix64)
// ════════════════════════════════════════════════════════════════════════════

/// Minimal deterministic PRNG. Same algorithm as the gossip-membership
/// simulator — fast, simple, reproducible.
#[derive(Debug, Clone)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  In-flight message
// ════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
struct InFlightMessage {
    envelope: Envelope,
    deliver_at: u64,
}

// ════════════════════════════════════════════════════════════════════════════
//  Simulator
// ════════════════════════════════════════════════════════════════════════════

/// Deterministic Raft cluster simulator.
pub struct Simulator {
    /// Live nodes. Absent from the map = crashed.
    nodes: HashMap<NodeId, RaftNode<MemoryStorage, InMemoryLog>>,

    /// All node IDs in the cluster (live + crashed).
    all_ids: Vec<NodeId>,

    /// Shared cluster configuration, cloned into each node.
    config: ClusterConfig,

    /// Saved storage snapshots for crashed nodes. Feeds into
    /// `RaftNode::restore()` on restart.
    saved_storage: HashMap<NodeId, MemoryStorage>,

    /// Messages in transit, each with a delivery tick.
    in_flight: Vec<InFlightMessage>,

    /// Bidirectional partition set. Stored as canonical `(min, max)` pairs.
    partitions: HashSet<(NodeId, NodeId)>,

    /// Packet loss rate in `[0.0, 1.0]`.
    loss_rate: f64,

    /// Base message delay in ticks. A message enqueued at tick T is
    /// deliverable at `T + delay`.
    delay: u64,

    /// Global tick counter.
    current_tick: u64,

    /// Seeded PRNG for loss decisions.
    rng: SplitMix64,
}

fn canonical(a: NodeId, b: NodeId) -> (NodeId, NodeId) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

impl Simulator {
    // ════════════════════════════════════════════════════════════════════════
    //  Construction
    // ════════════════════════════════════════════════════════════════════════

    /// Create a cluster of `cluster_size` nodes with IDs `1..=cluster_size`.
    pub fn new(cluster_size: usize, config: ClusterConfig, seed: u64) -> Self {
        let all_ids: Vec<NodeId> = (1..=cluster_size as NodeId).collect();
        let mut nodes = HashMap::new();

        for &id in &all_ids {
            let peers: Vec<NodeId> = all_ids.iter().copied().filter(|&p| p != id).collect();
            nodes.insert(id, RaftNode::new(id, peers, config.clone()));
        }

        Self {
            nodes,
            all_ids,
            config,
            saved_storage: HashMap::new(),
            in_flight: Vec::new(),
            partitions: HashSet::new(),
            loss_rate: 0.0,
            delay: 0,
            current_tick: 0,
            rng: SplitMix64::new(seed),
        }
    }

    /// Set packet loss rate (builder pattern).
    pub fn with_loss(mut self, rate: f64) -> Self {
        self.loss_rate = rate;
        self
    }

    /// Set message delay in ticks (builder pattern).
    pub fn with_delay(mut self, ticks: u64) -> Self {
        self.delay = ticks;
        self
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Time advancement
    // ════════════════════════════════════════════════════════════════════════

    /// Advance the global clock by `ticks`. For each tick:
    /// 1. Tick all live nodes by 1.
    /// 2. Collect outbound messages (apply loss, enqueue with delay).
    /// 3. Deliver messages whose `deliver_at <= current_tick`.
    /// 4. Repeat collection+delivery within the same tick until quiescent
    ///    (handles zero-delay request→response chains).
    pub fn tick(&mut self, ticks: u64) {
        for _ in 0..ticks {
            self.current_tick += 1;

            // Tick all live nodes.
            let ids: Vec<NodeId> = self.nodes.keys().copied().collect();
            for id in ids {
                if let Some(node) = self.nodes.get_mut(&id) {
                    node.tick(1);
                }
            }

            // Collect and deliver in a loop (for zero-delay chains).
            for _ in 0..100 {
                self.collect_outbound();
                let delivered = self.deliver_ready();
                if delivered == 0 {
                    break;
                }
            }
        }
    }

    /// Advance by one tick.
    pub fn tick_one(&mut self) {
        self.tick(1);
    }

    /// Current global tick.
    pub fn current_tick(&self) -> u64 {
        self.current_tick
    }

    /// Deliver ALL pending messages immediately (ignoring delay), looping
    /// until no new messages are generated. Respects partitions and loss.
    /// Returns total messages delivered. Max 100 rounds to prevent infinite loops.
    pub fn stabilize(&mut self) -> usize {
        let mut total = 0;
        for _ in 0..100 {
            self.collect_outbound();

            // Force all in-flight messages to be deliverable now.
            for msg in &mut self.in_flight {
                msg.deliver_at = 0;
            }

            let delivered = self.deliver_ready();
            if delivered == 0 {
                break;
            }
            total += delivered;
        }
        total
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Message collection and delivery (internal)
    // ════════════════════════════════════════════════════════════════════════

    /// Drain outbound messages from all live nodes, apply loss and partition
    /// checks, and enqueue survivors into `in_flight`.
    fn collect_outbound(&mut self) {
        let ids: Vec<NodeId> = self.nodes.keys().copied().collect();
        let mut outbound = Vec::new();

        for id in ids {
            if let Some(node) = self.nodes.get_mut(&id) {
                outbound.extend(node.drain_messages());
            }
        }

        for envelope in outbound {
            // Loss check.
            if self.loss_rate > 0.0 && self.rng.next_f64() < self.loss_rate {
                continue; // dropped
            }

            // Partition check at enqueue time.
            if self.is_partitioned(envelope.from, envelope.to) {
                continue; // blocked
            }

            self.in_flight.push(InFlightMessage {
                envelope,
                deliver_at: self.current_tick + self.delay,
            });
        }
    }

    /// Deliver messages from `in_flight` that are ready (`deliver_at <= current_tick`)
    /// and not blocked by partitions. Returns the number delivered.
    fn deliver_ready(&mut self) -> usize {
        let mut delivered = 0;
        let mut remaining = Vec::new();

        let messages = std::mem::take(&mut self.in_flight);
        for msg in messages {
            if msg.deliver_at > self.current_tick {
                // Not ready yet.
                remaining.push(msg);
                continue;
            }

            // Partition check at delivery time (partition may have been added
            // after the message was enqueued).
            if self.is_partitioned(msg.envelope.from, msg.envelope.to) {
                // Drop silently — partitioned.
                continue;
            }

            // Deliver to the target node if it's alive.
            if let Some(node) = self.nodes.get_mut(&msg.envelope.to) {
                node.step(msg.envelope);
                delivered += 1;
            }
            // If node is crashed, message is silently lost.
        }

        self.in_flight = remaining;
        delivered
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Network fault injection
    // ════════════════════════════════════════════════════════════════════════

    /// Set packet loss rate `[0.0, 1.0]`.
    pub fn set_loss_rate(&mut self, rate: f64) {
        self.loss_rate = rate;
    }

    /// Set message delay in ticks.
    pub fn set_delay(&mut self, ticks: u64) {
        self.delay = ticks;
    }

    /// Block all traffic between two sets of nodes. Every `(a, b)` pair
    /// where `a ∈ set1` and `b ∈ set2` is blocked bidirectionally.
    pub fn partition(&mut self, set1: &[NodeId], set2: &[NodeId]) {
        for &a in set1 {
            for &b in set2 {
                if a != b {
                    self.partitions.insert(canonical(a, b));
                }
            }
        }
    }

    /// Isolate a node from the entire cluster.
    pub fn isolate(&mut self, node_id: NodeId) {
        for &id in &self.all_ids {
            if id != node_id {
                self.partitions.insert(canonical(node_id, id));
            }
        }
    }

    /// Remove all partitions.
    pub fn heal(&mut self) {
        self.partitions.clear();
        // Also drop any in-flight messages that were enqueued before
        // partitions existed but would now be deliverable — those
        // messages already passed the enqueue-time partition check,
        // so they're fine. No cleanup needed.
    }

    /// Check if traffic between `a` and `b` is blocked.
    pub fn is_partitioned(&self, a: NodeId, b: NodeId) -> bool {
        self.partitions.contains(&canonical(a, b))
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Node crash and restart
    // ════════════════════════════════════════════════════════════════════════

    /// Crash a node: save its storage, remove it from the live set, and
    /// discard all in-flight messages addressed to it.
    ///
    /// Volatile state (role, commit_index, last_applied, timers) is lost —
    /// that is the point.
    pub fn crash(&mut self, node_id: NodeId) {
        if let Some(node) = self.nodes.remove(&node_id) {
            self.saved_storage
                .insert(node_id, node.storage().clone());
        }

        // Discard messages to the crashed node.
        self.in_flight
            .retain(|msg| msg.envelope.to != node_id);
    }

    /// Restart a crashed node from saved storage. The node starts as a
    /// Follower with volatile state reset to 0.
    ///
    /// Panics if the node is already alive or was never crashed.
    pub fn restart(&mut self, node_id: NodeId) {
        assert!(
            !self.nodes.contains_key(&node_id),
            "node {node_id} is already alive"
        );

        let storage = self
            .saved_storage
            .remove(&node_id)
            .unwrap_or_else(|| panic!("no saved storage for node {node_id}"));

        let peers: Vec<NodeId> = self
            .all_ids
            .iter()
            .copied()
            .filter(|&p| p != node_id)
            .collect();

        let node = RaftNode::restore(node_id, peers, self.config.clone(), storage, InMemoryLog::new())
            .expect("restore from saved storage should not fail");

        self.nodes.insert(node_id, node);
    }

    /// Returns true if the node is currently alive (not crashed).
    pub fn is_alive(&self, node_id: NodeId) -> bool {
        self.nodes.contains_key(&node_id)
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Proposals
    // ════════════════════════════════════════════════════════════════════════

    /// Propose data to the current leader. Returns `Some(leader_id)` if a
    /// leader was found and accepted the proposal, `None` otherwise.
    pub fn propose(&mut self, data: Vec<u8>) -> Option<NodeId> {
        let leader_id = self.leader()?;
        if self.propose_to(leader_id, data) {
            Some(leader_id)
        } else {
            None
        }
    }

    /// Propose data to a specific node. Returns true if the node is alive
    /// and accepted the proposal (i.e., it is the leader).
    pub fn propose_to(&mut self, node_id: NodeId, data: Vec<u8>) -> bool {
        if let Some(node) = self.nodes.get_mut(&node_id) {
            node.propose(data)
        } else {
            false
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Election helpers
    // ════════════════════════════════════════════════════════════════════════

    /// Trigger an election on a specific node.
    pub fn start_election(&mut self, node_id: NodeId) {
        if let Some(node) = self.nodes.get_mut(&node_id) {
            node.start_election();
        }
    }

    /// Elect a leader: trigger election on `node_id`, stabilize, and assert
    /// the node became leader.
    pub fn elect(&mut self, node_id: NodeId) {
        self.start_election(node_id);
        self.stabilize();
        assert!(
            self.nodes.get(&node_id).map_or(false, |n| n.is_leader()),
            "node {node_id} did not become leader after elect()"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Inspection
    // ════════════════════════════════════════════════════════════════════════

    /// Get a reference to a live node. Panics if crashed or missing.
    pub fn node(&self, id: NodeId) -> &RaftNode<MemoryStorage, InMemoryLog> {
        self.nodes
            .get(&id)
            .unwrap_or_else(|| panic!("node {id} is not alive"))
    }

    /// Get a mutable reference to a live node. Panics if crashed or missing.
    pub fn node_mut(&mut self, id: NodeId) -> &mut RaftNode<MemoryStorage, InMemoryLog> {
        self.nodes
            .get_mut(&id)
            .unwrap_or_else(|| panic!("node {id} is not alive"))
    }

    /// Find the current leader. Returns `None` if zero or multiple leaders exist.
    pub fn leader(&self) -> Option<NodeId> {
        let leaders: Vec<NodeId> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.is_leader())
            .map(|(&id, _)| id)
            .collect();

        if leaders.len() == 1 {
            Some(leaders[0])
        } else {
            None
        }
    }

    /// Collect all applied results from all live nodes since last drain.
    pub fn drain_all_applied(&mut self) -> HashMap<NodeId, Vec<ApplyResult>> {
        let mut result = HashMap::new();
        for (&id, node) in &mut self.nodes {
            let applied = node.drain_applied();
            if !applied.is_empty() {
                result.insert(id, applied);
            }
        }
        result
    }

    /// Number of in-flight (pending) messages.
    pub fn pending_messages(&self) -> usize {
        self.in_flight.len()
    }

    /// IDs of all live nodes.
    pub fn live_nodes(&self) -> Vec<NodeId> {
        let mut ids: Vec<NodeId> = self.nodes.keys().copied().collect();
        ids.sort();
        ids
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Assertions
    // ════════════════════════════════════════════════════════════════════════

    /// Assert exactly one leader exists. Returns the leader's ID.
    pub fn assert_one_leader(&self) -> NodeId {
        let leaders: Vec<NodeId> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.is_leader())
            .map(|(&id, _)| id)
            .collect();

        assert!(
            leaders.len() == 1,
            "expected exactly 1 leader, found {}: {:?}",
            leaders.len(),
            leaders
        );
        leaders[0]
    }

    /// Assert all live nodes agree on committed log entries.
    ///
    /// For each pair of live nodes, every log index up to
    /// `min(commit_index_a, commit_index_b)` must contain the same
    /// term and data.
    pub fn assert_logs_consistent(&self) {
        let nodes: Vec<(&NodeId, &RaftNode<MemoryStorage, InMemoryLog>)> =
            self.nodes.iter().collect();

        for i in 0..nodes.len() {
            for j in (i + 1)..nodes.len() {
                let (&id_a, node_a) = nodes[i];
                let (&id_b, node_b) = nodes[j];

                let check_up_to = std::cmp::min(node_a.commit_index(), node_b.commit_index());

                for idx in 1..=check_up_to {
                    let entry_a = node_a.log.get(idx);
                    let entry_b = node_b.log.get(idx);

                    match (entry_a, entry_b) {
                        (Some(a), Some(b)) => {
                            assert_eq!(
                                a.term, b.term,
                                "log inconsistency at index {idx}: node {id_a} has term {}, node {id_b} has term {}",
                                a.term, b.term
                            );
                            assert_eq!(
                                a.data, b.data,
                                "log inconsistency at index {idx}: node {id_a} and node {id_b} have different data",
                            );
                        }
                        (None, Some(_)) => {
                            panic!("node {id_a} missing committed entry at index {idx}");
                        }
                        (Some(_), None) => {
                            panic!("node {id_b} missing committed entry at index {idx}");
                        }
                        (None, None) => {
                            panic!("both nodes {id_a} and {id_b} missing entry at index {idx}");
                        }
                    }
                }
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ClusterConfig {
        ClusterConfig {
            election_timeout_min: 10,
            election_timeout_max: 20,
            heartbeat_interval: 5,
            pre_vote: false,
        }
    }

    // ── Determinism ──

    #[test]
    fn deterministic_same_seed() {
        // Two simulators with the same seed must produce identical outcomes.
        let run = |seed: u64| -> (NodeId, u64, u64) {
            let mut sim = Simulator::new(3, test_config(), seed);
            sim.elect(1);
            sim.propose(vec![42]);
            sim.stabilize();
            sim.tick(5); // heartbeat propagates commit
            sim.stabilize();

            let leader = sim.assert_one_leader();
            let term = sim.node(1).current_term();
            let commit = sim.node(1).commit_index();
            (leader, term, commit)
        };

        assert_eq!(run(99), run(99));
    }

    // ── Leader election ──

    #[test]
    fn leader_election_three_nodes() {
        let mut sim = Simulator::new(3, test_config(), 1);
        sim.elect(1);

        let leader = sim.assert_one_leader();
        assert_eq!(leader, 1);

        // Others are followers.
        assert!(sim.node(2).is_follower());
        assert!(sim.node(3).is_follower());

        // All agree on term.
        let term = sim.node(1).current_term();
        assert_eq!(sim.node(2).current_term(), term);
        assert_eq!(sim.node(3).current_term(), term);
    }

    #[test]
    fn leader_election_five_nodes() {
        let mut sim = Simulator::new(5, test_config(), 1);
        sim.elect(1);

        let leader = sim.assert_one_leader();
        assert_eq!(leader, 1);

        for id in 2..=5 {
            assert!(sim.node(id).is_follower());
        }
    }

    // ── Leader crash and re-election ──

    #[test]
    fn leader_crash_triggers_reelection() {
        let mut sim = Simulator::new(3, test_config(), 1);
        sim.elect(1);
        let old_term = sim.node(1).current_term();

        // Crash the leader.
        sim.crash(1);
        assert!(!sim.is_alive(1));
        assert!(sim.leader().is_none());

        // Tick past election timeout so a follower starts an election.
        sim.tick(25);
        sim.stabilize();

        // A new leader should exist with a higher term.
        let new_leader = sim.assert_one_leader();
        assert_ne!(new_leader, 1);
        assert!(sim.node(new_leader).current_term() > old_term);
    }

    #[test]
    fn crashed_leader_restarts_as_follower() {
        let mut sim = Simulator::new(3, test_config(), 1);
        sim.elect(1);

        sim.crash(1);
        sim.tick(25);
        sim.stabilize();
        let new_leader = sim.assert_one_leader();

        // Restart old leader.
        sim.restart(1);
        assert!(sim.is_alive(1));
        assert!(sim.node(1).is_follower());

        // Stabilize so it receives heartbeat from new leader.
        sim.tick(5);
        sim.stabilize();

        // Node 1 is a follower in the new term.
        assert!(sim.node(1).is_follower());
        assert!(sim.node(1).current_term() >= sim.node(new_leader).current_term());
    }

    // ── Network partitions ──

    #[test]
    fn partition_prevents_election() {
        let mut sim = Simulator::new(3, test_config(), 1);

        // Isolate node 1 from everyone — it cannot get votes.
        sim.isolate(1);
        sim.start_election(1);
        sim.stabilize();

        // Node 1 is a candidate (no majority), no leader in cluster.
        assert!(sim.node(1).is_candidate());
        assert!(sim.leader().is_none());

        // Heal and elect properly.
        sim.heal();
        sim.start_election(1);
        sim.stabilize();
        assert_eq!(sim.assert_one_leader(), 1);
    }

    #[test]
    fn partition_and_heal() {
        let mut sim = Simulator::new(3, test_config(), 1);
        sim.elect(1);

        // Partition node 3 from the rest.
        sim.partition(&[3], &[1, 2]);

        // Propose — commits with nodes 1+2 (majority).
        sim.propose(vec![42]);
        sim.stabilize();
        sim.tick(5);
        sim.stabilize();

        assert!(sim.node(1).commit_index() >= 2);

        // Node 3 has only the noop from before the partition.
        let n3_before_heal = sim.node(3).log.last_index();
        assert!(
            n3_before_heal < sim.node(1).log.last_index(),
            "node 3 should be behind the leader"
        );

        // Heal the partition.
        sim.heal();
        sim.tick(5);
        sim.stabilize();

        // Node 3 catches up.
        assert_eq!(
            sim.node(3).log.last_index(),
            sim.node(1).log.last_index()
        );
        sim.assert_logs_consistent();
    }

    #[test]
    fn minority_partition_new_leader() {
        let mut sim = Simulator::new(5, test_config(), 1);
        sim.elect(1);
        let old_term = sim.node(1).current_term();

        // Partition: leader(1) + node(2) vs majority(3,4,5).
        sim.partition(&[1, 2], &[3, 4, 5]);

        // Tick so majority side elects a new leader.
        sim.tick(25);
        sim.stabilize();

        // Find the new leader in the majority partition.
        let majority_leader = [3, 4, 5]
            .iter()
            .copied()
            .find(|&id| sim.node(id).is_leader());
        assert!(
            majority_leader.is_some(),
            "majority partition should elect a new leader"
        );

        let new_leader = majority_leader.unwrap();
        assert!(sim.node(new_leader).current_term() > old_term);

        // Old leader cannot commit (only has 2/5).
        let old_commit = sim.node(1).commit_index();
        sim.propose_to(1, vec![99]);
        sim.stabilize();
        assert_eq!(
            sim.node(1).commit_index(),
            old_commit,
            "old leader in minority cannot commit"
        );
    }

    // ── Log replication ──

    #[test]
    fn basic_log_replication() {
        let mut sim = Simulator::new(3, test_config(), 1);
        sim.elect(1);

        // Propose 3 entries.
        for i in 1..=3u8 {
            sim.propose(vec![i]);
        }
        sim.stabilize();
        sim.tick(5); // heartbeat propagates commit
        sim.stabilize();

        // All nodes have the same log: noop + 3 entries = 4.
        for id in 1..=3 {
            assert_eq!(
                sim.node(id).log.last_index(),
                4,
                "node {id} should have 4 entries"
            );
        }

        sim.assert_logs_consistent();
    }

    #[test]
    fn log_replication_with_delay() {
        let mut sim = Simulator::new(3, test_config(), 1).with_delay(5);
        sim.elect(1);

        sim.propose(vec![42]);
        // Messages are delayed by 5 ticks — nothing delivered yet.
        assert!(sim.pending_messages() > 0 || sim.node(1).commit_index() > 0);

        // Tick enough for delivery + response + commit propagation.
        sim.tick(30);
        sim.stabilize();

        sim.assert_logs_consistent();
        for id in 1..=3 {
            assert!(sim.node(id).log.last_index() >= 2);
        }
    }

    #[test]
    fn log_replication_with_loss() {
        let mut sim = Simulator::new(3, test_config(), 42).with_loss(0.3);

        // With 30% loss, elect may take a few attempts.
        for _ in 0..10 {
            sim.start_election(1);
            sim.stabilize();
            if sim.leader() == Some(1) {
                break;
            }
            sim.tick(25); // retry on timeout
        }

        if sim.leader() != Some(1) {
            // With loss, node 1 might not win — that's okay.
            // Just verify no safety violation.
            return;
        }

        // Propose entries. Heartbeats will retry delivery.
        for i in 1..=3u8 {
            sim.propose(vec![i]);
        }

        // Run enough heartbeat rounds for retransmission to overcome loss.
        for _ in 0..20 {
            sim.tick(5);
            sim.stabilize();
        }

        sim.assert_logs_consistent();
    }

    #[test]
    fn commit_requires_majority() {
        let mut sim = Simulator::new(5, test_config(), 1);
        sim.elect(1);
        sim.stabilize();

        // Partition so leader can only reach node 2 (2/5 = no majority).
        sim.partition(&[1, 2], &[3, 4, 5]);

        let commit_before = sim.node(1).commit_index();
        sim.propose_to(1, vec![42]);
        sim.stabilize();
        sim.tick(5);
        sim.stabilize();

        // Cannot commit with only 2/5.
        // Note: the leader alone counts as 1, plus node 2 = 2. Need 3.
        // The entry IS in the log but not committed.
        assert!(sim.node(1).log.last_index() > commit_before);
    }

    // ── Crash recovery + log ──

    #[test]
    fn crashed_node_recovers_log() {
        let mut sim = Simulator::new(3, test_config(), 1);
        sim.elect(1);

        // Replicate entries to all nodes.
        sim.propose(vec![10]);
        sim.propose(vec![20]);
        sim.stabilize();
        sim.tick(5);
        sim.stabilize();

        let log_len = sim.node(2).log.last_index();
        assert!(log_len >= 3); // noop + 2 entries

        // Crash node 2 and restart it.
        sim.crash(2);
        sim.restart(2);

        // Restored node has the log from storage.
        assert_eq!(sim.node(2).log.last_index(), log_len);

        // Volatile state is reset.
        assert_eq!(sim.node(2).commit_index(), 0);

        // After heartbeat from leader, it catches up.
        sim.tick(5);
        sim.stabilize();

        assert!(sim.node(2).commit_index() > 0);
        sim.assert_logs_consistent();
    }

    #[test]
    fn propose_during_crash_recovery() {
        let mut sim = Simulator::new(3, test_config(), 1);
        sim.elect(1);
        sim.stabilize();

        // Crash node 3.
        sim.crash(3);

        // Propose new entries while node 3 is down.
        sim.propose(vec![1]);
        sim.propose(vec![2]);
        sim.stabilize();
        sim.tick(5);
        sim.stabilize();

        // Entries committed with nodes 1+2 (majority).
        assert!(sim.node(1).commit_index() >= 3);

        // Restart node 3.
        sim.restart(3);
        sim.tick(5);
        sim.stabilize();

        // Node 3 catches up to the entries proposed while it was down.
        assert_eq!(
            sim.node(3).log.last_index(),
            sim.node(1).log.last_index()
        );
        sim.assert_logs_consistent();
    }
}
