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
use std::collections::{HashMap, HashSet, VecDeque};
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
    /// Burst packet loss: probability of starting a new burst.
    burst_start_prob: f64,
    /// Burst packet loss: average burst length in packets.
    avg_burst_length: u32,
    /// Burst packet loss: remaining packets to drop in current burst.
    burst_remaining: u32,
    /// Latency spikes: probability of a spike occurring.
    spike_prob: f64,
    /// Latency spikes: additional delay in ms when spike occurs.
    spike_delay_ms: u64,
    /// Latency spikes: current spike delay state (0 if no spike).
    current_spike_delay: u64,
    /// Asymmetric loss: loss rate for specific (from, to) pairs.
    asymmetric_loss: HashMap<(SocketAddr, SocketAddr), f64>,
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
            burst_start_prob: 0.0,
            avg_burst_length: 0,
            burst_remaining: 0,
            spike_prob: 0.0,
            spike_delay_ms: 0,
            current_spike_delay: 0,
            asymmetric_loss: HashMap::new(),
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

    pub fn with_burst_loss(mut self, start_prob: f64, avg_length: u32) -> Self {
        self.burst_start_prob = start_prob.clamp(0.0, 1.0);
        self.avg_burst_length = avg_length;
        self
    }

    pub fn with_latency_spikes(mut self, spike_prob: f64, spike_delay_ms: u64) -> Self {
        self.spike_prob = spike_prob.clamp(0.0, 1.0);
        self.spike_delay_ms = spike_delay_ms;
        self
    }

    pub fn with_asymmetric_loss(mut self, from: SocketAddr, to: SocketAddr, rate: f64) -> Self {
        self.asymmetric_loss
            .insert((from, to), rate.clamp(0.0, 1.0));
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

    pub fn set_burst_loss(&mut self, start_prob: f64, avg_length: u32) {
        self.burst_start_prob = start_prob.clamp(0.0, 1.0);
        self.avg_burst_length = avg_length;
    }

    pub fn set_latency_spikes(&mut self, spike_prob: f64, spike_delay_ms: u64) {
        self.spike_prob = spike_prob.clamp(0.0, 1.0);
        self.spike_delay_ms = spike_delay_ms;
    }

    pub fn set_asymmetric_loss(&mut self, from: SocketAddr, to: SocketAddr, rate: f64) {
        self.asymmetric_loss
            .insert((from, to), rate.clamp(0.0, 1.0));
    }

    pub fn remove_asymmetric_loss(&mut self, from: SocketAddr, to: SocketAddr) {
        self.asymmetric_loss.remove(&(from, to));
    }

    pub fn clear_asymmetric_loss(&mut self) {
        self.asymmetric_loss.clear();
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
        if self.burst_remaining > 0 {
            self.burst_remaining -= 1;
            return false;
        }
        if self.burst_start_prob > 0.0 && self.rng.next_f64() < self.burst_start_prob {
            let burst_len = if self.avg_burst_length > 0 {
                let r = self.rng.next_f64() * (self.avg_burst_length as f64 * 2.0);
                r as u32 + self.avg_burst_length
            } else {
                1
            };
            self.burst_remaining = burst_len.saturating_sub(1);
            return false;
        }
        if self.loss_rate > 0.0 && self.rng.next_f64() < self.loss_rate {
            return false;
        }
        if let Some(&asym_rate) = self.asymmetric_loss.get(&(from, to)) {
            if asym_rate > 0.0 && self.rng.next_f64() < asym_rate {
                return false;
            }
        }
        if self.current_spike_delay > 0 {
            self.current_spike_delay = 0;
        } else if self.spike_prob > 0.0 && self.rng.next_f64() < self.spike_prob {
            self.current_spike_delay = self.spike_delay_ms;
        }
        true
    }

    /// Returns `true` if there is an active partition between `a` and `b`.
    pub fn is_partitioned(&self, a: SocketAddr, b: SocketAddr) -> bool {
        self.partitions.contains(&Self::canonical(a, b))
    }

    /// Base delay in milliseconds (without spikes).
    pub fn base_delay_ms(&self) -> u64 {
        self.delay_ms
    }

    /// Total delay in milliseconds (base + spike if active).
    pub fn delay_ms(&self) -> u64 {
        self.delay_ms + self.current_spike_delay
    }

    /// Returns `true` if currently in a burst loss period.
    pub fn in_burst(&self) -> bool {
        self.burst_remaining > 0
    }

    /// Number of packets remaining to drop in the current burst.
    pub fn burst_remaining(&self) -> u32 {
        self.burst_remaining
    }

    /// Returns `true` if currently in a latency spike.
    pub fn in_spike(&self) -> bool {
        self.current_spike_delay > 0
    }

    /// Trigger/update latency spike state. Should be called when determining delay.
    pub fn update_spike(&mut self) {
        if self.current_spike_delay > 0 {
            self.current_spike_delay = 0;
        } else if self.spike_prob > 0.0 && self.rng.next_f64() < self.spike_prob {
            self.current_spike_delay = self.spike_delay_ms;
        }
    }

    /// Get the asymmetric loss rate for a specific pair.
    pub fn asymmetric_loss_rate(&self, from: SocketAddr, to: SocketAddr) -> Option<f64> {
        self.asymmetric_loss.get(&(from, to)).copied()
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

    // ── Burst Loss ─────────────────────────────────────────────────────────

    #[test]
    fn burst_loss_disabled_by_default() {
        let sim = NetSim::new(0);
        assert!(!sim.in_burst());
        assert_eq!(sim.burst_remaining(), 0);
    }

    #[test]
    fn burst_loss_configured_via_builder() {
        let sim = NetSim::new(0).with_burst_loss(0.5, 5);
        assert!(!sim.in_burst());
    }

    #[test]
    fn burst_loss_drops_consecutive_packets() {
        let mut sim = NetSim::new(42).with_loss(1.0).with_burst_loss(1.0, 3);
        for _ in 0..10 {
            assert!(!sim.should_deliver(addr(1), addr(2)));
        }
        assert!(sim.in_burst() || sim.burst_remaining() > 0);
    }

    #[test]
    fn burst_loss_with_zero_probability() {
        let mut sim = NetSim::new(0).with_burst_loss(0.0, 5);
        let mut delivered = 0;
        for _ in 0..100 {
            if sim.should_deliver(addr(1), addr(2)) {
                delivered += 1;
            }
        }
        assert_eq!(delivered, 100);
    }

    // ── Latency Spikes ───────────────────────────────────────────────────

    #[test]
    fn latency_spikes_disabled_by_default() {
        let sim = NetSim::new(0);
        assert!(!sim.in_spike());
        assert_eq!(sim.delay_ms(), 0);
    }

    #[test]
    fn latency_spikes_configured_via_builder() {
        let sim = NetSim::new(0).with_latency_spikes(0.5, 100);
        assert!(!sim.in_spike());
    }

    #[test]
    fn latency_spikes_increases_delay() {
        let mut sim = NetSim::new(0).with_latency_spikes(1.0, 100);
        assert_eq!(sim.delay_ms(), 0);
        sim.should_deliver(addr(1), addr(2));
        assert!(sim.in_spike());
        assert_eq!(sim.delay_ms(), 100);
    }

    #[test]
    fn latency_spikes_base_delay_preserved() {
        let mut sim = NetSim::new(0)
            .with_delay_ms(50)
            .with_latency_spikes(1.0, 100);
        assert_eq!(sim.base_delay_ms(), 50);
        assert_eq!(sim.delay_ms(), 50);
        sim.should_deliver(addr(1), addr(2));
        assert_eq!(sim.delay_ms(), 150);
    }

    // ── Asymmetric Loss ─────────────────────────────────────────────────

    #[test]
    fn asymmetric_loss_disabled_by_default() {
        let sim = NetSim::new(0);
        assert_eq!(sim.asymmetric_loss_rate(addr(1), addr(2)), None);
    }

    #[test]
    fn asymmetric_loss_configured_via_builder() {
        let sim = NetSim::new(0).with_asymmetric_loss(addr(1), addr(2), 0.5);
        assert_eq!(sim.asymmetric_loss_rate(addr(1), addr(2)), Some(0.5));
    }

    #[test]
    fn asymmetric_loss_takes_precedence() {
        let mut sim = NetSim::new(0)
            .with_loss(0.0)
            .with_asymmetric_loss(addr(1), addr(2), 1.0);
        for _ in 0..10 {
            assert!(!sim.should_deliver(addr(1), addr(2)));
        }
        assert!(sim.should_deliver(addr(1), addr(3)));
    }

    #[test]
    fn asymmetric_loss_different_directions() {
        let mut sim = NetSim::new(0).with_asymmetric_loss(addr(1), addr(2), 1.0);
        for _ in 0..10 {
            assert!(!sim.should_deliver(addr(1), addr(2)));
        }
        for _ in 0..10 {
            assert!(sim.should_deliver(addr(2), addr(1)));
        }
    }

    #[test]
    fn asymmetric_loss_runtime_mutation() {
        let mut sim = NetSim::new(0);
        assert!(sim.should_deliver(addr(1), addr(2)));
        sim.set_asymmetric_loss(addr(1), addr(2), 1.0);
        assert!(!sim.should_deliver(addr(1), addr(2)));
        sim.remove_asymmetric_loss(addr(1), addr(2));
        assert!(sim.should_deliver(addr(1), addr(2)));
    }

    #[test]
    fn asymmetric_loss_clear_all() {
        let mut sim = NetSim::new(0)
            .with_asymmetric_loss(addr(1), addr(2), 1.0)
            .with_asymmetric_loss(addr(3), addr(4), 1.0);
        assert!(!sim.should_deliver(addr(1), addr(2)));
        assert!(!sim.should_deliver(addr(3), addr(4)));
        sim.clear_asymmetric_loss();
        assert!(sim.should_deliver(addr(1), addr(2)));
        assert!(sim.should_deliver(addr(3), addr(4)));
    }

    #[test]
    fn asymmetric_loss_combined_with_burst() {
        let mut sim = NetSim::new(0)
            .with_loss(0.0)
            .with_asymmetric_loss(addr(1), addr(2), 1.0)
            .with_burst_loss(0.0, 3);
        assert!(!sim.should_deliver(addr(1), addr(2)));
        assert!(!sim.should_deliver(addr(1), addr(2)));
        assert!(!sim.should_deliver(addr(1), addr(2)));
        assert!(!sim.should_deliver(addr(1), addr(2)));
    }
}
