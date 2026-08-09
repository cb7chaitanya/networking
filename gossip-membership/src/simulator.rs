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
    // ── DNS Amplification Attack Simulation ─────────────────────────────────
    /// Enable DNS amplification attack simulation.
    amplification_enabled: bool,
    /// Query size in bytes (small, e.g., ~40 bytes for DNS query).
    amplification_query_size: usize,
    /// Response size in bytes (large, e.g., ~3000 bytes for DNS response).
    amplification_response_size: usize,
    /// Amplification factor (response_size / query_size), computed automatically.
    amplification_factor: f64,
    // ── Query Storm Simulation ─────────────────────────────────────────────
    /// Enable query storm simulation.
    query_storm_enabled: bool,
    /// Queries per second to simulate.
    query_storm_rate: u64,
    /// Burst size: number of queries to send in a single burst.
    query_storm_burst: u32,
    /// Track queries sent in current window.
    queries_this_burst: u32,
    // ── Resolver Behavior Metrics ───────────────────────────────────────────
    /// Total bytes sent (cumulative).
    bytes_sent: u64,
    /// Total bytes received (cumulative).
    bytes_received: u64,
    /// Total packets sent.
    packets_sent: u64,
    /// Total packets received.
    packets_received: u64,
    /// Queries dropped due to rate limiting.
    queries_dropped: u64,
    /// Peak query rate observed.
    peak_query_rate: u64,
    /// Current query rate (queries in last second).
    current_query_rate: u64,
    /// Query rate tracking window.
    query_rate_window: Vec<std::time::Instant>,
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
            // DNS Amplification Attack
            amplification_enabled: false,
            amplification_query_size: 40,
            amplification_response_size: 3000,
            amplification_factor: 1.0,
            // Query Storm
            query_storm_enabled: false,
            query_storm_rate: 0,
            query_storm_burst: 0,
            queries_this_burst: 0,
            // Resolver Metrics
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            queries_dropped: 0,
            peak_query_rate: 0,
            current_query_rate: 0,
            query_rate_window: Vec::new(),
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

    // ── DNS Amplification Attack Builder ───────────────────────────────────

    /// Enable DNS amplification attack simulation with default sizes.
    /// Default: 40 byte query → 3000 byte response (75x amplification).
    pub fn with_amplification(mut self) -> Self {
        self.amplification_enabled = true;
        self.amplification_query_size = 40;
        self.amplification_response_size = 3000;
        self.amplification_factor = 3000.0 / 40.0;
        self
    }

    /// Configure amplification attack with custom sizes.
    /// `query_size` and `response_size` are in bytes.
    pub fn with_amplification_sizes(mut self, query_size: usize, response_size: usize) -> Self {
        self.amplification_enabled = true;
        self.amplification_query_size = query_size.max(1);
        self.amplification_response_size = response_size.max(1);
        self.amplification_factor = response_size as f64 / query_size.max(1) as f64;
        self
    }

    // ── Query Storm Builder ────────────────────────────────────────────────

    /// Enable query storm simulation with specified rate (queries per second).
    pub fn with_query_storm(mut self, queries_per_second: u64, burst_size: u32) -> Self {
        self.query_storm_enabled = true;
        self.query_storm_rate = queries_per_second;
        self.query_storm_burst = burst_size;
        self.queries_this_burst = 0;
        self
    }

    // ── Runtime mutation ─────────────────────────────────────────────────

    pub fn set_loss_rate(&mut self, rate: f64) {
        self.loss_rate = rate.clamp(0.0, 1.0);
    }

    pub fn set_delay_ms(&mut self, ms: u64) {
        self.delay_ms = ms;
    }

    // ── DNS Amplification Attack Runtime ───────────────────────────────────

    /// Returns true if amplification attack is enabled.
    pub fn is_amplification_enabled(&self) -> bool {
        self.amplification_enabled
    }

    /// Get the amplification factor (response_size / query_size).
    pub fn amplification_factor(&self) -> f64 {
        self.amplification_factor
    }

    /// Simulate sending a query. Returns the effective "cost" in bytes.
    /// For amplification attack, this tracks the small query being sent.
    pub fn record_query_sent(&mut self, size_bytes: usize) -> usize {
        self.packets_sent += 1;
        self.bytes_sent += size_bytes as u64;
        size_bytes
    }

    /// Simulate receiving a response. Returns the effective "cost" in bytes.
    /// For amplification attack, this tracks the large response being received.
    pub fn record_response_received(&mut self, size_bytes: usize) -> usize {
        self.packets_received += 1;
        self.bytes_received += size_bytes as u64;
        size_bytes
    }

    /// Get effective bytes for amplification simulation.
    /// If amplification is enabled, converts query to response size.
    pub fn amplification_effective_size(&self, is_response: bool) -> usize {
        if self.amplification_enabled {
            if is_response {
                self.amplification_response_size
            } else {
                self.amplification_query_size
            }
        } else {
            40 // default DNS query size
        }
    }

    // ── Query Storm Runtime ───────────────────────────────────────────────

    /// Check if a query should be allowed under query storm rate limiting.
    /// Uses sliding window algorithm for true QPS enforcement.
    /// Returns true if query should be allowed, false if dropped due to rate limit.
    pub fn should_allow_query(&mut self) -> bool {
        if !self.query_storm_enabled {
            return true;
        }

        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(1);

        // Remove queries older than the sliding window (1 second)
        self.query_rate_window
            .retain(|t| now.duration_since(*t) < window_duration);

        // Check if we're within rate limit
        if self.query_rate_window.len() < self.query_storm_rate as usize {
            self.query_rate_window.push(now);
            self.queries_this_burst += 1;

            // Track peak rate
            let current_rate = self.query_rate_window.len() as u64;
            if current_rate > self.peak_query_rate {
                self.peak_query_rate = current_rate;
            }

            true
        } else {
            self.queries_dropped += 1;
            false
        }
    }

    /// Get current query rate (queries per second) - sliding window count.
    pub fn current_query_rate(&self) -> u64 {
        self.query_rate_window.len() as u64
    }

    /// Get peak query rate observed.
    pub fn peak_query_rate(&self) -> u64 {
        self.peak_query_rate
    }

    /// Get number of queries dropped due to rate limiting.
    pub fn queries_dropped(&self) -> u64 {
        self.queries_dropped
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

    // ── Resolver Behavior Metrics ─────────────────────────────────────────

    /// Total bytes sent (cumulative).
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Total bytes received (cumulative).
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Total packets sent.
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent
    }

    /// Total packets received.
    pub fn packets_received(&self) -> u64 {
        self.packets_received
    }

    /// Get amplification ratio (bytes_received / bytes_sent).
    /// Useful for measuring amplification attack impact.
    pub fn amplification_ratio(&self) -> f64 {
        if self.bytes_sent > 0 {
            self.bytes_received as f64 / self.bytes_sent as f64
        } else {
            1.0
        }
    }

    /// Reset all metrics.
    pub fn reset_metrics(&mut self) {
        self.bytes_sent = 0;
        self.bytes_received = 0;
        self.packets_sent = 0;
        self.packets_received = 0;
        self.queries_dropped = 0;
        self.peak_query_rate = 0;
        self.current_query_rate = 0;
        self.query_rate_window.clear();
        self.queries_this_burst = 0;
    }

    /// Check if query storm is enabled.
    pub fn is_query_storm_enabled(&self) -> bool {
        self.query_storm_enabled
    }

    /// Get query storm rate (queries per second).
    pub fn query_storm_rate(&self) -> u64 {
        self.query_storm_rate
    }

    /// Get query storm burst size.
    pub fn query_storm_burst(&self) -> u32 {
        self.query_storm_burst
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

    // ── DNS Amplification Attack Tests ─────────────────────────────────────

    #[test]
    fn amplification_disabled_by_default() {
        let sim = NetSim::new(0);
        assert!(!sim.is_amplification_enabled());
    }

    #[test]
    fn amplification_enabled_builder() {
        let sim = NetSim::new(0).with_amplification();
        assert!(sim.is_amplification_enabled());
        assert!((sim.amplification_factor() - 75.0).abs() < 0.1);
    }

    #[test]
    fn amplification_custom_sizes() {
        let sim = NetSim::new(0).with_amplification_sizes(50, 5000);
        assert!(sim.is_amplification_enabled());
        assert!((sim.amplification_factor() - 100.0).abs() < 0.1);
    }

    #[test]
    fn amplification_effective_size_query() {
        let sim = NetSim::new(0).with_amplification();
        assert_eq!(sim.amplification_effective_size(false), 40);
    }

    #[test]
    fn amplification_effective_size_response() {
        let sim = NetSim::new(0).with_amplification();
        assert_eq!(sim.amplification_effective_size(true), 3000);
    }

    #[test]
    fn amplification_records_metrics() {
        let mut sim = NetSim::new(0).with_amplification();

        // Record small query sent
        sim.record_query_sent(40);
        assert_eq!(sim.bytes_sent(), 40);
        assert_eq!(sim.packets_sent(), 1);

        // Record large response received
        sim.record_response_received(3000);
        assert_eq!(sim.bytes_received(), 3000);
        assert_eq!(sim.packets_received(), 1);

        // Amplification ratio should be 75x
        assert!((sim.amplification_ratio() - 75.0).abs() < 0.1);
    }

    // ── Query Storm Tests ─────────────────────────────────────────────────

    #[test]
    fn query_storm_disabled_by_default() {
        let sim = NetSim::new(0);
        assert!(!sim.is_query_storm_enabled());
    }

    #[test]
    fn query_storm_enabled_builder() {
        let sim = NetSim::new(0).with_query_storm(1000, 100);
        assert!(sim.is_query_storm_enabled());
        assert_eq!(sim.query_storm_rate(), 1000);
        assert_eq!(sim.query_storm_burst(), 100);
    }

    #[test]
    fn query_storm_allows_queries_within_burst() {
        // 10 QPS limit (sliding window)
        let mut sim = NetSim::new(0).with_query_storm(10, 100);

        // First 10 queries should be allowed
        for _ in 0..10 {
            assert!(sim.should_allow_query());
        }

        // 11th query should be dropped (over 10 QPS)
        assert!(!sim.should_allow_query());
        assert_eq!(sim.queries_dropped(), 1);
    }

    #[test]
    fn query_storm_tracks_peak_rate() {
        // Now first param is QPS (not burst), second is ignored in sliding window
        let mut sim = NetSim::new(0).with_query_storm(10, 100);

        // Send 5 queries (within 10 QPS limit)
        for _ in 0..5 {
            sim.should_allow_query();
        }

        // Wait for sliding window to clear
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Send more queries - should be allowed again
        for _ in 0..3 {
            sim.should_allow_query();
        }

        // Peak should be at least 5
        assert!(sim.peak_query_rate() >= 5);
    }

    #[test]
    fn query_storm_respects_rate_limit() {
        // 10 QPS limit (sliding window)
        let mut sim = NetSim::new(0).with_query_storm(10, 100);

        // First 10 queries should be allowed
        for _ in 0..10 {
            assert!(sim.should_allow_query());
        }

        // 11th query should be dropped
        assert!(!sim.should_allow_query());
        assert_eq!(sim.queries_dropped(), 1);
    }

    #[test]
    fn query_storm_sliding_window_allows_after_time() {
        // 5 QPS limit
        let mut sim = NetSim::new(0).with_query_storm(5, 100);

        // Use up the 5 QPS
        for _ in 0..5 {
            assert!(sim.should_allow_query());
        }

        // This should be dropped
        assert!(!sim.should_allow_query());

        // Wait for window to slide
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Should be allowed again
        assert!(sim.should_allow_query());
    }

    #[test]
    fn query_storm_true_qps_enforcement() {
        // Strict 20 QPS limit
        let mut sim = NetSim::new(0).with_query_storm(20, 100);

        let mut allowed = 0;

        // Send 50 queries rapidly
        for _ in 0..50 {
            if sim.should_allow_query() {
                allowed += 1;
            }
        }

        // Should allow ~20 (the QPS limit), not 50
        assert!(allowed <= 25, "Expected ~20 allowed, got {}", allowed);
        assert!(sim.queries_dropped() > 0, "Some queries should be dropped");
    }

    // ── Resolver Metrics Tests ───────────────────────────────────────────

    #[test]
    fn metrics_zero_by_default() {
        let sim = NetSim::new(0);
        assert_eq!(sim.bytes_sent(), 0);
        assert_eq!(sim.bytes_received(), 0);
        assert_eq!(sim.packets_sent(), 0);
        assert_eq!(sim.packets_received(), 0);
        assert_eq!(sim.queries_dropped(), 0);
    }

    #[test]
    fn metrics_accumulate() {
        let mut sim = NetSim::new(0);

        sim.record_query_sent(100);
        sim.record_query_sent(200);
        sim.record_response_received(1000);

        assert_eq!(sim.bytes_sent(), 300);
        assert_eq!(sim.bytes_received(), 1000);
        assert_eq!(sim.packets_sent(), 2);
        assert_eq!(sim.packets_received(), 1);
    }

    #[test]
    fn metrics_reset() {
        let mut sim = NetSim::new(0);

        sim.record_query_sent(100);
        sim.record_response_received(1000);
        sim.should_allow_query();

        sim.reset_metrics();

        assert_eq!(sim.bytes_sent(), 0);
        assert_eq!(sim.bytes_received(), 0);
        assert_eq!(sim.queries_dropped(), 0);
    }

    #[test]
    fn amplification_ratio_calculation() {
        let mut sim = NetSim::new(0);

        // 1 byte sent, 100 bytes received = 100x amplification
        sim.record_query_sent(1);
        sim.record_response_received(100);
        assert!((sim.amplification_ratio() - 100.0).abs() < 0.1);

        sim.reset_metrics();

        // No sent bytes = ratio of 1.0
        sim.record_response_received(100);
        assert!((sim.amplification_ratio() - 1.0).abs() < 0.1);
    }
}
