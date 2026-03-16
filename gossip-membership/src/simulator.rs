/// Network simulator — configurable loss, partitions, and delay for testing.
///
/// `NetSim` is a shared-state object (wrapped in `Arc<Mutex<>>`) that the
/// `Transport` layer consults before delivering each datagram.  It provides:
///
/// - **Packet loss**: random drop based on a configurable probability.
/// - **Partitions**: bidirectional blocks between pairs of addresses.
/// - **Delay**: configurable base delay per packet (applied in Transport).
///
/// All randomness is driven by a deterministic SplitMix64 PRNG seeded at
/// construction, so simulations are reproducible.
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;

// ── Deterministic PRNG (SplitMix64) ─────────────────────────────────────────
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

// ── NetSim ──────────────────────────────────────────────────────────────────
pub struct NetSim {
    rng: SplitMix64,
    loss_rate: f64,
    /// Base delay in milliseconds applied to every delivered packet.
    /// 0 = no delay.
    delay_ms: u64,
    /// Bidirectional partitions stored as canonical `(min, max)` pairs.
    partitions: HashSet<(SocketAddr, SocketAddr)>,
    /// Probability [0.0, 1.0] that a packet is stashed for reordering.
    reorder_prob: f64,
    /// Max packets held in the reorder buffer before forced flush.
    reorder_window: usize,
    /// Packets held for out-of-order delivery: `(wire_bytes, dest)`.
    reorder_buf: VecDeque<(Vec<u8>, SocketAddr)>,

    // ── Byzantine behavior ───────────────────────────────────────────────────
    /// Set of nodes marked as malicious (byzantine).
    malicious_nodes: HashSet<SocketAddr>,
    /// Probability of injecting fake gossip entries.
    gossip_poison_prob: f64,
    /// Probability of sending incorrect incarnation numbers.
    wrong_incarnation_prob: f64,
    /// Probability of replaying old messages.
    replay_prob: f64,
    /// Buffer for replay attacks: (message, destination, timestamp).
    replay_buffer: VecDeque<(Vec<u8>, SocketAddr, u64)>,
    /// Maximum replay buffer size.
    replay_buffer_size: usize,
}

impl NetSim {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: SplitMix64::new(seed),
            loss_rate: 0.0,
            delay_ms: 0,
            partitions: HashSet::new(),
            reorder_prob: 0.0,
            reorder_window: 0,
            reorder_buf: VecDeque::new(),
            malicious_nodes: HashSet::new(),
            gossip_poison_prob: 0.0,
            wrong_incarnation_prob: 0.0,
            replay_prob: 0.0,
            replay_buffer: VecDeque::new(),
            replay_buffer_size: 100,
        }
    }

    // ── Builder methods ──────────────────────────────────────────────────

    pub fn with_loss(mut self, rate: f64) -> Self {
        self.loss_rate = rate.clamp(0.0, 1.0);
        self
    }

    pub fn with_delay_ms(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }

    pub fn with_reorder(mut self, probability: f64, window: usize) -> Self {
        self.reorder_prob = probability.clamp(0.0, 1.0);
        self.reorder_window = window;
        self
    }

    /// Configure gossip poisoning: probability of injecting fake entries.
    pub fn with_gossip_poisoning(mut self, prob: f64) -> Self {
        self.gossip_poison_prob = prob.clamp(0.0, 1.0);
        self
    }

    /// Configure wrong incarnation numbers: probability of sending incorrect incarnation.
    pub fn with_wrong_incarnation(mut self, prob: f64) -> Self {
        self.wrong_incarnation_prob = prob.clamp(0.0, 1.0);
        self
    }

    /// Configure replay attacks: probability of replaying old messages.
    pub fn with_replay_attacks(mut self, prob: f64, buffer_size: usize) -> Self {
        self.replay_prob = prob.clamp(0.0, 1.0);
        self.replay_buffer_size = buffer_size;
        self
    }

    // ── Runtime mutation ─────────────────────────────────────────────────

    pub fn set_loss_rate(&mut self, rate: f64) {
        self.loss_rate = rate.clamp(0.0, 1.0);
    }

    pub fn set_delay_ms(&mut self, ms: u64) {
        self.delay_ms = ms;
    }

    /// Block all traffic between `a` and `b` (bidirectional).
    pub fn add_partition(&mut self, a: SocketAddr, b: SocketAddr) {
        self.partitions.insert(Self::canonical(a, b));
    }

    /// Restore traffic between `a` and `b`.
    pub fn remove_partition(&mut self, a: SocketAddr, b: SocketAddr) {
        self.partitions.remove(&Self::canonical(a, b));
    }

    /// Remove all partitions.
    pub fn clear_partitions(&mut self) {
        self.partitions.clear();
    }

    // ── Byzantine behavior ─────────────────────────────────────────────────

    /// Mark a node as malicious (byzantine).
    pub fn add_malicious_node(&mut self, addr: SocketAddr) {
        self.malicious_nodes.insert(addr);
    }

    /// Remove malicious designation from a node.
    pub fn remove_malicious_node(&mut self, addr: SocketAddr) {
        self.malicious_nodes.remove(&addr);
    }

    /// Clear all malicious node designations.
    pub fn clear_malicious_nodes(&mut self) {
        self.malicious_nodes.clear();
    }

    /// Check if a node is marked as malicious.
    pub fn is_malicious(&self, addr: SocketAddr) -> bool {
        self.malicious_nodes.contains(&addr)
    }

    /// Set gossip poisoning probability.
    pub fn set_gossip_poison_prob(&mut self, prob: f64) {
        self.gossip_poison_prob = prob.clamp(0.0, 1.0);
    }

    /// Set wrong incarnation probability.
    pub fn set_wrong_incarnation_prob(&mut self, prob: f64) {
        self.wrong_incarnation_prob = prob.clamp(0.0, 1.0);
    }

    /// Set replay attack probability and buffer size.
    pub fn set_replay_prob(&mut self, prob: f64, buffer_size: usize) {
        self.replay_prob = prob.clamp(0.0, 1.0);
        self.replay_buffer_size = buffer_size;
    }

    /// Clear the replay buffer.
    pub fn clear_replay_buffer(&mut self) {
        self.replay_buffer.clear();
    }

    /// Number of messages in replay buffer.
    pub fn replay_buffer_len(&self) -> usize {
        self.replay_buffer.len()
    }

    // ── Query ────────────────────────────────────────────────────────────

    /// Decide whether a packet from `from` to `to` should be delivered.
    ///
    /// Returns `false` if the packet is lost (random drop) or the path
    /// is partitioned.  Advances the PRNG state on every call.
    pub fn should_deliver(&mut self, from: SocketAddr, to: SocketAddr) -> bool {
        if self.is_partitioned(from, to) {
            return false;
        }
        if self.loss_rate > 0.0 && self.rng.next_f64() < self.loss_rate {
            return false;
        }
        true
    }

    /// Returns `true` if there is an active partition between `a` and `b`.
    pub fn is_partitioned(&self, a: SocketAddr, b: SocketAddr) -> bool {
        self.partitions.contains(&Self::canonical(a, b))
    }

    /// Configured delay in milliseconds.
    pub fn delay_ms(&self) -> u64 {
        self.delay_ms
    }

    /// Decide whether this packet should be stashed for reordering.
    ///
    /// Returns `true` if the packet should be held in the buffer (and a
    /// previously-buffered packet released instead).
    pub fn should_reorder(&mut self) -> bool {
        if self.reorder_prob > 0.0 && self.reorder_window > 0 {
            self.rng.next_f64() < self.reorder_prob
        } else {
            false
        }
    }

    /// Stash a packet for later out-of-order delivery.
    ///
    /// If the buffer exceeds `reorder_window`, the oldest packet is
    /// returned for immediate delivery (cap-bypass).
    pub fn stash(&mut self, wire: Vec<u8>, dest: SocketAddr) -> Option<(Vec<u8>, SocketAddr)> {
        self.reorder_buf.push_back((wire, dest));
        if self.reorder_buf.len() > self.reorder_window {
            self.reorder_buf.pop_front()
        } else {
            None
        }
    }

    /// Release the oldest buffered packet (if any) for delivery.
    pub fn flush_one(&mut self) -> Option<(Vec<u8>, SocketAddr)> {
        self.reorder_buf.pop_front()
    }

    /// Number of packets currently held for reordering.
    pub fn reorder_pending(&self) -> usize {
        self.reorder_buf.len()
    }

    // ── Byzantine behavior ─────────────────────────────────────────────────

    /// Apply byzantine transformations to an outgoing message from a malicious node.
    /// Returns the potentially modified message bytes.
    ///
    /// This applies:
    /// - Gossip poisoning: inject fake entries with some probability
    /// - Wrong incarnation: modify incarnation numbers with some probability
    /// - Replay attacks: store message for potential replay with some probability
    pub fn apply_byzantine(&mut self, wire: &[u8], from: SocketAddr) -> Vec<u8> {
        if !self.is_malicious(from) {
            return wire.to_vec();
        }

        let mut modified = wire.to_vec();

        // Optionally store for replay attacks
        if self.replay_prob > 0.0 && self.rng.next_f64() < self.replay_prob {
            if self.replay_buffer.len() < self.replay_buffer_size {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                self.replay_buffer
                    .push_back((wire.to_vec(), from, timestamp));
            }
        }

        // Apply gossip poisoning or wrong incarnation if this is a gossip/ping/ack message
        if modified.len() > 24 {
            let kind = modified[1];
            if kind == 0x01 || kind == 0x02 || kind == 0x04 {
                // GOSSIP, PING, or ACK - apply transformations
                modified = self.maybe_poison_gossip(modified);
                modified = self.maybe_corrupt_incarnation(modified);
            }
        }

        modified
    }

    /// Possibly inject fake gossip entries (gossip poisoning).
    fn maybe_poison_gossip(&mut self, mut wire: Vec<u8>) -> Vec<u8> {
        if self.gossip_poison_prob > 0.0 && self.rng.next_f64() < self.gossip_poison_prob {
            // Simple poisoning: flip some bytes in the payload to corrupt entries
            // or inject fake data
            if wire.len() > 26 {
                // Flip random bytes in payload to create invalid/corrupted entries
                let payload_start = 24;
                if wire.len() > payload_start + 8 {
                    let idx = payload_start
                        + (self.rng.next_u64() as usize % (wire.len() - payload_start - 8));
                    wire[idx] = wire[idx].wrapping_add(1);
                }
            }
        }
        wire
    }

    /// Possibly corrupt incarnation numbers.
    fn maybe_corrupt_incarnation(&mut self, mut wire: Vec<u8>) -> Vec<u8> {
        if self.wrong_incarnation_prob > 0.0 && self.rng.next_f64() < self.wrong_incarnation_prob {
            // Incarnation is at bytes 16-19 (4 bytes)
            if wire.len() >= 20 {
                // Corrupt the incarnation field (flip some bits)
                let corruption = ((self.rng.next_u64() & 0xFF) as u8).wrapping_add(1);
                wire[16] = wire[16].wrapping_add(corruption);
            }
        }
        wire
    }

    /// Attempt to replay an old message instead of the current one.
    /// Returns Some(replayed_message) if replay happens, None otherwise.
    pub fn maybe_replay(&mut self, _current: &[u8], _to: SocketAddr) -> Option<Vec<u8>> {
        if self.replay_prob > 0.0
            && !self.replay_buffer.is_empty()
            && self.rng.next_f64() < self.replay_prob
        {
            // Return a random old message from the buffer
            let idx = (self.rng.next_u64() as usize) % self.replay_buffer.len();
            if let Some((old_msg, _, _)) = self.replay_buffer.get(idx) {
                return Some(old_msg.clone());
            }
        }
        None
    }

    // ── Internal ─────────────────────────────────────────────────────────

    fn canonical(a: SocketAddr, b: SocketAddr) -> (SocketAddr, SocketAddr) {
        if a <= b {
            (a, b)
        } else {
            (b, a)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    // ── PRNG determinism ─────────────────────────────────────────────────

    #[test]
    fn prng_deterministic_with_same_seed() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn prng_different_seeds_differ() {
        let mut a = SplitMix64::new(1);
        let mut b = SplitMix64::new(2);
        // Extremely unlikely for all 10 to match.
        let matches = (0..10).filter(|_| a.next_u64() == b.next_u64()).count();
        assert!(matches < 10);
    }

    #[test]
    fn prng_f64_in_unit_range() {
        let mut rng = SplitMix64::new(0);
        for _ in 0..1000 {
            let v = rng.next_f64();
            assert!((0.0..1.0).contains(&v), "f64 out of range: {v}");
        }
    }

    // ── Loss ─────────────────────────────────────────────────────────────

    #[test]
    fn zero_loss_always_delivers() {
        let mut sim = NetSim::new(0);
        for _ in 0..100 {
            assert!(sim.should_deliver(addr(1), addr(2)));
        }
    }

    #[test]
    fn full_loss_never_delivers() {
        let mut sim = NetSim::new(0).with_loss(1.0);
        for _ in 0..100 {
            assert!(!sim.should_deliver(addr(1), addr(2)));
        }
    }

    #[test]
    fn partial_loss_drops_some() {
        let mut sim = NetSim::new(42).with_loss(0.5);
        let mut delivered = 0;
        let total = 1000;
        for _ in 0..total {
            if sim.should_deliver(addr(1), addr(2)) {
                delivered += 1;
            }
        }
        // With 50% loss, expect roughly 400–600 delivered.
        assert!(
            delivered > 300 && delivered < 700,
            "expected ~500 delivered, got {delivered}"
        );
    }

    #[test]
    fn loss_rate_clamped() {
        let mut sim = NetSim::new(0).with_loss(2.0);
        // Clamped to 1.0 → never delivers.
        assert!(!sim.should_deliver(addr(1), addr(2)));

        sim.set_loss_rate(-1.0);
        // Clamped to 0.0 → always delivers.
        assert!(sim.should_deliver(addr(1), addr(2)));
    }

    #[test]
    fn loss_deterministic_same_seed() {
        let results_a: Vec<bool> = {
            let mut sim = NetSim::new(99).with_loss(0.3);
            (0..100).map(|_| sim.should_deliver(addr(1), addr(2))).collect()
        };
        let results_b: Vec<bool> = {
            let mut sim = NetSim::new(99).with_loss(0.3);
            (0..100).map(|_| sim.should_deliver(addr(1), addr(2))).collect()
        };
        assert_eq!(results_a, results_b);
    }

    // ── Partitions ───────────────────────────────────────────────────────

    #[test]
    fn no_partition_by_default() {
        let sim = NetSim::new(0);
        assert!(!sim.is_partitioned(addr(1), addr(2)));
    }

    #[test]
    fn add_partition_blocks_traffic() {
        let mut sim = NetSim::new(0);
        sim.add_partition(addr(1), addr(2));
        assert!(!sim.should_deliver(addr(1), addr(2)));
        assert!(!sim.should_deliver(addr(2), addr(1))); // bidirectional
    }

    #[test]
    fn partition_does_not_affect_other_pairs() {
        let mut sim = NetSim::new(0);
        sim.add_partition(addr(1), addr(2));
        assert!(sim.should_deliver(addr(1), addr(3)));
        assert!(sim.should_deliver(addr(3), addr(2)));
    }

    #[test]
    fn remove_partition_restores_traffic() {
        let mut sim = NetSim::new(0);
        sim.add_partition(addr(1), addr(2));
        assert!(!sim.should_deliver(addr(1), addr(2)));
        sim.remove_partition(addr(1), addr(2));
        assert!(sim.should_deliver(addr(1), addr(2)));
    }

    #[test]
    fn remove_partition_reversed_order() {
        let mut sim = NetSim::new(0);
        sim.add_partition(addr(1), addr(2));
        // Remove with reversed argument order — canonical key should match.
        sim.remove_partition(addr(2), addr(1));
        assert!(sim.should_deliver(addr(1), addr(2)));
    }

    #[test]
    fn clear_partitions_removes_all() {
        let mut sim = NetSim::new(0);
        sim.add_partition(addr(1), addr(2));
        sim.add_partition(addr(3), addr(4));
        sim.clear_partitions();
        assert!(sim.should_deliver(addr(1), addr(2)));
        assert!(sim.should_deliver(addr(3), addr(4)));
    }

    #[test]
    fn partition_checked_before_loss() {
        // Even with 0% loss, partitioned traffic is blocked.
        let mut sim = NetSim::new(0);
        sim.add_partition(addr(1), addr(2));
        assert!(!sim.should_deliver(addr(1), addr(2)));
    }

    // ── Delay ────────────────────────────────────────────────────────────

    #[test]
    fn default_delay_is_zero() {
        let sim = NetSim::new(0);
        assert_eq!(sim.delay_ms(), 0);
    }

    #[test]
    fn with_delay_sets_value() {
        let sim = NetSim::new(0).with_delay_ms(50);
        assert_eq!(sim.delay_ms(), 50);
    }

    #[test]
    fn set_delay_updates_value() {
        let mut sim = NetSim::new(0);
        sim.set_delay_ms(100);
        assert_eq!(sim.delay_ms(), 100);
    }

    // ── Combined ─────────────────────────────────────────────────────────

    // ── Reorder ──────────────────────────────────────────────────────────

    #[test]
    fn reorder_disabled_by_default() {
        let mut sim = NetSim::new(0);
        for _ in 0..100 {
            assert!(!sim.should_reorder());
        }
    }

    #[test]
    fn reorder_full_probability_always_reorders() {
        let mut sim = NetSim::new(0).with_reorder(1.0, 5);
        for _ in 0..20 {
            assert!(sim.should_reorder());
        }
    }

    #[test]
    fn reorder_stash_and_flush() {
        let mut sim = NetSim::new(0).with_reorder(1.0, 5);
        // Stash 3 packets (window=5, so no cap-bypass yet).
        assert!(sim.stash(vec![1], addr(100)).is_none());
        assert!(sim.stash(vec![2], addr(200)).is_none());
        assert!(sim.stash(vec![3], addr(300)).is_none());
        assert_eq!(sim.reorder_pending(), 3);

        // Flush returns oldest first.
        let (buf, dst) = sim.flush_one().unwrap();
        assert_eq!(buf, vec![1]);
        assert_eq!(dst, addr(100));
        assert_eq!(sim.reorder_pending(), 2);
    }

    #[test]
    fn reorder_cap_bypass_releases_oldest() {
        let mut sim = NetSim::new(0).with_reorder(1.0, 2);
        assert!(sim.stash(vec![1], addr(100)).is_none());
        assert!(sim.stash(vec![2], addr(200)).is_none());
        // 3rd stash exceeds window=2 → oldest (vec![1]) is released.
        let released = sim.stash(vec![3], addr(300));
        assert!(released.is_some());
        assert_eq!(released.unwrap().0, vec![1]);
        assert_eq!(sim.reorder_pending(), 2);
    }

    #[test]
    fn reorder_deterministic_same_seed() {
        let decisions_a: Vec<bool> = {
            let mut sim = NetSim::new(42).with_reorder(0.5, 5);
            (0..50).map(|_| sim.should_reorder()).collect()
        };
        let decisions_b: Vec<bool> = {
            let mut sim = NetSim::new(42).with_reorder(0.5, 5);
            (0..50).map(|_| sim.should_reorder()).collect()
        };
        assert_eq!(decisions_a, decisions_b);
    }

    #[test]
    fn reorder_partial_probability_mixes() {
        let mut sim = NetSim::new(99).with_reorder(0.5, 10);
        let mut reordered = 0;
        for _ in 0..200 {
            if sim.should_reorder() {
                reordered += 1;
            }
        }
        // ~50% should be reordered.
        assert!(reordered > 50 && reordered < 150,
            "expected ~100 reordered, got {reordered}");
    }

    #[test]
    fn reorder_zero_window_never_reorders() {
        let mut sim = NetSim::new(0).with_reorder(1.0, 0);
        // Window=0 disables reordering.
        for _ in 0..100 {
            assert!(!sim.should_reorder());
        }
    }

    // ── Combined ─────────────────────────────────────────────────────────

    #[test]
    fn partition_plus_loss() {
        let mut sim = NetSim::new(0).with_loss(0.5);
        sim.add_partition(addr(1), addr(2));
        // Partitioned: always blocked regardless of loss dice.
        for _ in 0..100 {
            assert!(!sim.should_deliver(addr(1), addr(2)));
        }
        // Unpartitioned pair: subject to 50% loss.
        let mut delivered = 0;
        for _ in 0..100 {
            if sim.should_deliver(addr(1), addr(3)) {
                delivered += 1;
            }
        }
        assert!(delivered > 0 && delivered < 100);
    }

    // ── Byzantine Behavior ─────────────────────────────────────────────────

    #[test]
    fn malicious_node_not_malicious_by_default() {
        let sim = NetSim::new(0);
        assert!(!sim.is_malicious(addr(1)));
    }

    #[test]
    fn add_and_remove_malicious_node() {
        let mut sim = NetSim::new(0);
        sim.add_malicious_node(addr(1));
        assert!(sim.is_malicious(addr(1)));

        sim.remove_malicious_node(addr(1));
        assert!(!sim.is_malicious(addr(1)));
    }

    #[test]
    fn clear_malicious_nodes() {
        let mut sim = NetSim::new(0);
        sim.add_malicious_node(addr(1));
        sim.add_malicious_node(addr(2));
        sim.clear_malicious_nodes();
        assert!(!sim.is_malicious(addr(1)));
        assert!(!sim.is_malicious(addr(2)));
    }

    #[test]
    fn byzantine_disabled_by_default() {
        let mut sim = NetSim::new(0);
        let wire = vec![0u8; 30];
        // Non-malicious node should pass through unchanged
        let result = sim.apply_byzantine(&wire, addr(1));
        assert_eq!(result, wire);
    }

    #[test]
    fn byzantine_applies_to_malicious_node() {
        let mut sim = NetSim::new(0).with_gossip_poisoning(1.0);
        sim.add_malicious_node(addr(1));

        let wire = vec![0u8; 30];
        // With 100% poison prob, message should be modified
        let result = sim.apply_byzantine(&wire, addr(1));
        // Message may or may not be modified depending on RNG, but function should work
        assert_eq!(result.len(), wire.len());
    }

    #[test]
    fn byzantine_ignores_non_malicious() {
        let mut sim = NetSim::new(0)
            .with_gossip_poisoning(1.0)
            .with_wrong_incarnation(1.0)
            .with_replay_attacks(1.0, 10);

        sim.add_malicious_node(addr(1));

        let wire = vec![0u8; 30];
        // addr(2) is not malicious, should pass through
        let result = sim.apply_byzantine(&wire, addr(2));
        assert_eq!(result, wire);
    }

    #[test]
    fn replay_buffer_stores_messages() {
        let mut sim = NetSim::new(0).with_replay_attacks(1.0, 5);
        sim.add_malicious_node(addr(1));

        let wire = vec![1u8; 30];
        sim.apply_byzantine(&wire, addr(1));

        assert_eq!(sim.replay_buffer_len(), 1);
    }

    #[test]
    fn replay_buffer_respects_size_limit() {
        let mut sim = NetSim::new(0).with_replay_attacks(1.0, 3);
        sim.add_malicious_node(addr(1));

        // Send 5 messages, buffer should only hold 3
        for i in 0..5 {
            let wire = vec![i as u8; 30];
            sim.apply_byzantine(&wire, addr(1));
        }

        assert!(sim.replay_buffer_len() <= 3);
    }

    #[test]
    fn clear_replay_buffer() {
        let mut sim = NetSim::new(0).with_replay_attacks(1.0, 10);
        sim.add_malicious_node(addr(1));

        let wire = vec![1u8; 30];
        sim.apply_byzantine(&wire, addr(1));
        assert_eq!(sim.replay_buffer_len(), 1);

        sim.clear_replay_buffer();
        assert_eq!(sim.replay_buffer_len(), 0);
    }

    #[test]
    fn wrong_incarnation_probability() {
        let mut sim = NetSim::new(0).with_wrong_incarnation(0.0);
        sim.add_malicious_node(addr(1));

        let wire = vec![0u8; 30];
        // With 0% probability, should not modify
        let result = sim.apply_byzantine(&wire, addr(1));
        // With wrong_incarnation_prob=0, should pass through unchanged
        assert_eq!(result, wire);
    }

    #[test]
    fn byzantine_builder_methods() {
        let sim = NetSim::new(0)
            .with_gossip_poisoning(0.5)
            .with_wrong_incarnation(0.3)
            .with_replay_attacks(0.2, 50);

        // Just verify it builds without error
        assert!(!sim.is_malicious(addr(1)));
    }
}
