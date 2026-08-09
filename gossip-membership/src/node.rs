/// Node identity and per-node configuration.
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::time::{Instant, SystemTime};

use crate::message::status;

pub type NodeId = u64;

// ── Status ────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeStatus {
    /// Node is known-alive (heartbeat advancing).
    Alive = 0,
    /// Node has not responded recently; may be dead.
    Suspect = 1,
    /// Node is considered failed. Terminal state until the node re-joins.
    Dead = 2,
}

impl NodeStatus {
    pub fn to_wire(self) -> u8 {
        match self {
            NodeStatus::Alive => status::ALIVE,
            NodeStatus::Suspect => status::SUSPECT,
            NodeStatus::Dead => status::DEAD,
        }
    }

    pub fn from_wire(b: u8) -> Option<Self> {
        match b {
            status::ALIVE => Some(NodeStatus::Alive),
            status::SUSPECT => Some(NodeStatus::Suspect),
            status::DEAD => Some(NodeStatus::Dead),
            _ => None,
        }
    }
}

// ── Per-node state (local representation) ─────────────────────────────────────
#[derive(Debug, Clone)]
pub struct NodeState {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub heartbeat: u32,
    /// Incarnation number (SWIM §4.2). A node increments its own incarnation
    /// when it learns that it has been suspected, allowing it to refute the
    /// suspicion without inflating its heartbeat counter.
    pub incarnation: u32,
    pub status: NodeStatus,
    /// Monotonic timestamp of last update. NOT transmitted on the wire.
    pub last_update: Instant,
    /// Set when status transitions to Suspect; used to time-out to Dead.
    pub suspect_since: Option<Instant>,
    /// Number of times this node has been suspected. Used for suspicion
    /// acceleration heuristics - higher counts get gossiped more frequently.
    /// NOT transmitted on the wire (local tracking only).
    pub suspect_count: u32,
}

impl NodeState {
    /// Create a new Alive entry at incarnation 0.
    pub fn new_alive(node_id: NodeId, addr: SocketAddr, heartbeat: u32) -> Self {
        Self {
            node_id,
            addr,
            heartbeat,
            incarnation: 0,
            status: NodeStatus::Alive,
            last_update: Instant::now(),
            suspect_since: None,
            suspect_count: 0,
        }
    }
}

// ── Node identity generation ──────────────────────────────────────────────────
/// Generate a pseudo-random node ID seeded by current time and local address.
/// Matches the ISN generation pattern used in tcp-over-udp (no `rand` dep).
pub fn generate_node_id(addr: SocketAddr) -> NodeId {
    let mut h = DefaultHasher::new();
    SystemTime::now().hash(&mut h);
    addr.hash(&mut h);
    // Mix in the process ID for extra differentiation in local testing.
    std::process::id().hash(&mut h);
    h.finish()
}

// ── Node configuration ────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// How often to increment own heartbeat (ms).
    pub heartbeat_interval_ms: u64,
    /// How often to run one gossip round (ms).
    pub gossip_interval_ms: u64,
    /// How often to run the failure-detection scan / probe cycle (ms).
    pub probe_interval_ms: u64,
    /// Probe timeout: how long to wait for an ACK before escalating (ms).
    pub probe_timeout_ms: u64,
    /// Suspect timeout base: how long a Suspect node stays Suspect before becoming Dead (ms).
    pub suspect_timeout_ms: u64,
    /// Log-scaling multiplier for the suspect timeout.  Effective timeout is
    /// `base * (1 + multiplier * log2(cluster_size))`, so larger clusters wait
    /// proportionally longer before declaring Dead — matching SWIM's O(log n)
    /// protocol period.
    pub suspect_timeout_multiplier: f64,
    /// Maximum random jitter (ms) added to the suspect timeout.  Each
    /// observer-suspect pair gets a deterministic offset derived from
    /// `hash(local_id, suspect_id)`, desynchronising Dead declarations across
    /// the cluster and preventing a thundering herd of concurrent state changes.
    pub suspect_timeout_jitter_ms: u64,
    /// Enable suspicion acceleration: suspected nodes get gossiped more frequently.
    pub suspicion_acceleration: bool,
    /// Weight factor for suspicion score in gossip prioritization.
    /// Higher values give suspected nodes more priority in gossip digest.
    pub suspicion_weight: f64,
    /// Number of additional gossip targets to use for suspected nodes.
    /// These extra targets help propagate suspicion faster via multi-path.
    pub suspicion_multi_path: usize,
    /// Number of indirect probers to use (k in SWIM).
    pub indirect_probe_k: usize,
    /// Base max entries to include in one GOSSIP message.
    pub gossip_fanout: usize,
    /// When `true`, effective fanout scales with cluster size:
    /// `base_fanout * ceil(log2(n))`.  This ensures information spreads in
    /// O(log n) rounds even as the cluster grows.
    pub adaptive_fanout: bool,
    /// Base max gossip messages to send per gossip round.  Capped at the
    /// number of live peers.  Setting this to 1 gives classic single-target
    /// gossip; higher values increase dissemination speed at the cost of
    /// bandwidth.
    pub max_gossip_sends: usize,
    /// When `true`, the number of gossip targets per round scales with
    /// cluster size: `max_gossip_sends * ceil(log2(n))`.  This ensures
    /// information reaches every node in O(log n) rounds even as the
    /// cluster grows.
    pub adaptive_gossip_targets: bool,
    /// How long after becoming Dead before an entry is garbage-collected (ms).
    pub dead_retention_ms: u64,
    /// Max membership entries to piggyback on PING/ACK messages.
    pub piggyback_max: usize,
    /// How often to log a metrics summary (ms).  0 = disabled.
    pub metrics_log_interval_ms: u64,
    /// TCP port for the Prometheus-compatible HTTP metrics endpoint.
    /// 0 = disabled.  When set, serves `/metrics` in Prometheus text
    /// exposition format and `/metrics/json` as JSON.
    pub metrics_server_port: u16,
    /// How often to run an anti-entropy round (ms).  0 = disabled.
    /// Anti-entropy pushes the full membership table to one random peer,
    /// ensuring convergence even under sustained packet loss.
    pub anti_entropy_interval_ms: u64,
    /// Inbound rate limiting: global token bucket capacity (burst).
    /// 0 = disabled (no rate limiting).
    pub inbound_global_capacity: u32,
    /// Inbound rate limiting: global tokens refilled per second.
    pub inbound_global_refill_rate: u32,
    /// Inbound rate limiting: per-peer token bucket capacity (burst).
    pub inbound_peer_capacity: u32,
    /// Inbound rate limiting: per-peer tokens refilled per second.
    pub inbound_peer_refill_rate: u32,
    /// Timeout before retransmitting a REQUEST_ACK message (ms).
    pub reliable_ack_timeout_ms: u64,
    /// Maximum number of retransmission attempts for REQUEST_ACK messages.
    pub reliable_max_retries: u8,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_ms: 500,
            gossip_interval_ms: 200,
            probe_interval_ms: 1_000,
            probe_timeout_ms: 500,
            suspect_timeout_ms: 3_000,
            suspect_timeout_multiplier: 0.5,
            suspect_timeout_jitter_ms: 1_000,
            suspicion_acceleration: false,
            suspicion_weight: 2.0,
            suspicion_multi_path: 1,
            indirect_probe_k: 2,
            gossip_fanout: 50,
            adaptive_fanout: true,
            max_gossip_sends: 1,
            adaptive_gossip_targets: true,
            dead_retention_ms: 15_000,
            piggyback_max: 6,
            metrics_log_interval_ms: 10_000,
            metrics_server_port: 0, // disabled by default
            anti_entropy_interval_ms: 10_000,
            inbound_global_capacity: 1000,
            inbound_global_refill_rate: 500,
            inbound_peer_capacity: 100,
            inbound_peer_refill_rate: 50,
            reliable_ack_timeout_ms: 500,
            reliable_max_retries: 3,
        }
    }
}

impl NodeConfig {
    /// Faster timeouts for integration tests so they finish quickly.
    pub fn fast() -> Self {
        Self {
            heartbeat_interval_ms: 50,
            gossip_interval_ms: 50,
            probe_interval_ms: 100,
            probe_timeout_ms: 100,
            suspect_timeout_ms: 300,
            suspect_timeout_multiplier: 0.5,
            suspect_timeout_jitter_ms: 50,
            suspicion_acceleration: false,
            suspicion_weight: 2.0,
            suspicion_multi_path: 1,
            indirect_probe_k: 2,
            gossip_fanout: 50,
            adaptive_fanout: true,
            max_gossip_sends: 1,
            adaptive_gossip_targets: true,
            dead_retention_ms: 1_000,
            piggyback_max: 6,
            metrics_log_interval_ms: 0,  // disabled in tests
            metrics_server_port: 0,      // disabled in tests
            anti_entropy_interval_ms: 0, // disabled by default in tests
            inbound_global_capacity: 0,  // disabled in tests
            inbound_global_refill_rate: 0,
            inbound_peer_capacity: 0,
            inbound_peer_refill_rate: 0,
            reliable_ack_timeout_ms: 50,
            reliable_max_retries: 3,
        }
    }
}
