/// SWIM-style failure detector.
///
/// This module is purely a data structure — it holds probe state and emits
/// decisions, but performs no I/O. The event loop in `main.rs` drives it by
/// calling `record_probe_sent`, `record_ack`, and `scan` at appropriate times.
///
/// Two-phase detection:
///   1. Direct probe: send PING, wait `probe_timeout`.
///   2. Indirect probe: if no ACK, send PING_REQ to k intermediaries.
///   3. If still no ACK after another `probe_timeout`, transition → Suspect.
///   4. Separate suspect scan promotes Suspect → Dead after `suspect_timeout`
///      (this lives in the event loop, using `MembershipTable::expired_suspects`).
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::node::NodeId;

// ── Configuration for adaptive probing ────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    /// Enable adaptive probe interval based on latency, failure rate, and cluster size.
    pub enabled: bool,
    /// Minimum probe interval (ms).
    pub min_interval_ms: u64,
    /// Maximum probe interval (ms).
    pub max_interval_ms: u64,
    /// Base probe interval (ms) - used when adaptive is disabled or for initial calculation.
    pub base_interval_ms: u64,
    /// Number of latency samples to keep per peer for rolling average.
    pub latency_window_size: usize,
    /// Number of probe results to track for failure rate calculation.
    pub failure_window_size: usize,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_interval_ms: 100,
            max_interval_ms: 5000,
            base_interval_ms: 1000,
            latency_window_size: 10,
            failure_window_size: 20,
        }
    }
}

// ── Per-peer statistics for adaptive probing ───────────────────────────────────
#[derive(Debug, Clone)]
struct PeerStats {
    /// Rolling window of observed latencies (in ms).
    latency_history: Vec<u64>,
    /// Rolling window of probe outcomes: true = success, false = timeout/failure.
    probe_history: Vec<bool>,
    /// Sum of latency_history for efficient average calculation.
    latency_sum: u64,
}

impl PeerStats {
    fn new(window_size: usize) -> Self {
        Self {
            latency_history: Vec::with_capacity(window_size),
            probe_history: Vec::with_capacity(window_size),
            latency_sum: 0,
        }
    }

    fn record_success(&mut self, latency_ms: u64, window_size: usize) {
        self.latency_sum += latency_ms;
        self.latency_history.push(latency_ms);
        self.probe_history.push(true);

        // Trim to window size
        while self.latency_history.len() > window_size {
            self.latency_sum -= self.latency_history.remove(0);
        }
        while self.probe_history.len() > window_size {
            self.probe_history.remove(0);
        }
    }

    fn record_failure(&mut self, window_size: usize) {
        self.probe_history.push(false);

        while self.probe_history.len() > window_size {
            self.probe_history.remove(0);
        }
    }

    fn average_latency_ms(&self) -> u64 {
        if self.latency_history.is_empty() {
            return 0;
        }
        self.latency_sum / self.latency_history.len() as u64
    }

    fn failure_rate(&self) -> f64 {
        if self.probe_history.is_empty() {
            return 0.0;
        }
        let failures = self.probe_history.iter().filter(|&&r| !r).count();
        failures as f64 / self.probe_history.len() as f64
    }
}

// ── State machines for pending probes ─────────────────────────────────────────
#[derive(Debug)]
enum ProbePhase {
    Direct { sent_at: Instant },
    Indirect { sent_at: Instant },
}

// ── Failure detector ──────────────────────────────────────────────────────────
pub struct FailureDetector {
    /// Time to wait for an ACK before escalating / suspecting.
    probe_timeout: Duration,
    /// In-flight probes indexed by target node ID.
    pending: HashMap<NodeId, ProbePhase>,
    /// Per-peer statistics for adaptive probing.
    peer_stats: HashMap<NodeId, PeerStats>,
    /// Configuration for adaptive probing.
    adaptive_config: AdaptiveConfig,
    /// Expected latency for new peers (ms) - used when no history exists.
    expected_latency_ms: u64,
}

impl FailureDetector {
    pub fn new(probe_timeout: Duration) -> Self {
        Self {
            probe_timeout,
            pending: HashMap::new(),
            peer_stats: HashMap::new(),
            adaptive_config: AdaptiveConfig::default(),
            expected_latency_ms: 100, // Default 100ms expected latency
        }
    }

    pub fn with_adaptive_config(mut self, config: AdaptiveConfig) -> Self {
        self.adaptive_config = config.clone();
        let base_interval = config.base_interval_ms;
        if base_interval > 0 {
            self.expected_latency_ms = base_interval / 10; // 10% of base
        }
        self
    }

    /// Call this after sending a PING to `id`.
    pub fn record_probe_sent(&mut self, id: NodeId) {
        // Only start a new direct probe if we don't already have one in flight.
        self.pending.entry(id).or_insert(ProbePhase::Direct {
            sent_at: Instant::now(),
        });
    }

    /// Call this after receiving an ACK (or Gossip, which implies liveness) from `id`.
    /// Returns `true` if a pending probe for that node was resolved.
    /// Also records the latency for adaptive probing.
    pub fn record_ack(&mut self, id: NodeId, now: Instant) -> bool {
        // Calculate latency if we have a pending probe
        let latency_ms = if let Some(phase) = self.pending.get(&id) {
            let sent_at = match phase {
                ProbePhase::Direct { sent_at } => sent_at,
                ProbePhase::Indirect { sent_at } => sent_at,
            };
            now.duration_since(*sent_at).as_millis() as u64
        } else {
            0
        };

        // Record success in peer stats
        if latency_ms > 0 {
            let stats = self
                .peer_stats
                .entry(id)
                .or_insert_with(|| PeerStats::new(self.adaptive_config.latency_window_size));
            stats.record_success(latency_ms, self.adaptive_config.latency_window_size);
        }

        self.pending.remove(&id).is_some()
    }

    /// Call this after receiving an ACK (legacy version without timestamp).
    pub fn record_ack_legacy(&mut self, id: NodeId) -> bool {
        self.record_ack(id, Instant::now())
    }

    /// Record a probe failure (timeout) for a peer.
    pub fn record_probe_failure(&mut self, id: NodeId) {
        let stats = self
            .peer_stats
            .entry(id)
            .or_insert_with(|| PeerStats::new(self.adaptive_config.failure_window_size));
        stats.record_failure(self.adaptive_config.failure_window_size);
    }

    /// Call this after sending PING_REQ messages for `id` via intermediaries.
    /// Upgrades the probe phase from Direct to Indirect.
    pub fn record_indirect_probe_sent(&mut self, id: NodeId) {
        self.pending.insert(
            id,
            ProbePhase::Indirect {
                sent_at: Instant::now(),
            },
        );
    }

    /// Scan all pending probes for timeouts. Must be called periodically
    /// (typically on every probe tick in the event loop).
    ///
    /// Returns a `ScanResult` describing the actions the event loop should take.
    pub fn scan(&mut self, now: Instant) -> ScanResult {
        let mut result = ScanResult::default();

        let mut to_escalate = Vec::new();
        let mut to_suspect = Vec::new();

        for (&id, phase) in &self.pending {
            match phase {
                ProbePhase::Direct { sent_at } => {
                    if now.duration_since(*sent_at) >= self.probe_timeout {
                        to_escalate.push(id);
                    }
                }
                ProbePhase::Indirect { sent_at } => {
                    if now.duration_since(*sent_at) >= self.probe_timeout {
                        to_suspect.push(id);
                    }
                }
            }
        }

        // Escalate direct timeouts to indirect.
        for id in &to_escalate {
            self.pending.insert(
                *id,
                ProbePhase::Indirect {
                    sent_at: Instant::now(),
                },
            );
            result.escalate_to_indirect.push(*id);
        }

        // Indirect timeouts → declare suspect; remove from pending.
        for id in &to_suspect {
            self.pending.remove(id);
            self.record_probe_failure(*id);
            result.declare_suspect.push(*id);
        }

        result
    }

    /// True if there is currently a pending probe for `id`.
    pub fn is_probing(&self, id: NodeId) -> bool {
        self.pending.contains_key(&id)
    }

    /// Get the adaptive probe interval based on current conditions.
    ///
    /// Parameters:
    /// - `cluster_size`: Number of nodes in the cluster
    ///
    /// Returns the calculated probe interval in milliseconds.
    pub fn adaptive_interval_ms(&self, cluster_size: usize) -> u64 {
        if !self.adaptive_config.enabled {
            return self.adaptive_config.base_interval_ms;
        }

        let base = self.adaptive_config.base_interval_ms as f64;

        // Factor 1: Latency - probe more frequently if latency is high to avoid false timeouts
        // Higher latency = shorter interval (divide more)
        let avg_latency = self.average_latency_ms();
        let latency_factor = if avg_latency > 0 {
            let ratio = avg_latency as f64 / self.expected_latency_ms as f64;
            // When ratio > 1 (latency higher than expected), factor > 1, making interval shorter
            // When ratio < 1 (latency lower than expected), factor < 1, making interval longer
            ratio.clamp(0.5, 3.0)
        } else {
            1.0
        };

        // Factor 2: Failure rate - probe more aggressively when failures are high
        // Higher failure rate = shorter interval (divide more)
        let failure_rate = self.average_failure_rate();
        let failure_factor = 1.0 + (failure_rate * 3.0).clamp(0.0, 2.0);

        // Factor 3: Cluster size - in larger clusters, we can probe less frequently
        // because gossip provides more indirect failure detection
        // Larger cluster = longer interval (multiply more)
        let cluster_factor = if cluster_size > 10 {
            1.0 + (cluster_size as f64).log2() * 0.1
        } else {
            1.0
        };

        let adaptive_interval = base / latency_factor / failure_factor * cluster_factor;

        // Clamp to configured min/max
        adaptive_interval.clamp(
            self.adaptive_config.min_interval_ms as f64,
            self.adaptive_config.max_interval_ms as f64,
        ) as u64
    }

    /// Get average latency across all peers (in ms).
    pub fn average_latency_ms(&self) -> u64 {
        if self.peer_stats.is_empty() {
            return 0;
        }
        let total: u64 = self
            .peer_stats
            .values()
            .map(|s| s.average_latency_ms())
            .sum();
        total / self.peer_stats.len() as u64
    }

    /// Get average failure rate across all peers (0.0 to 1.0).
    pub fn average_failure_rate(&self) -> f64 {
        if self.peer_stats.is_empty() {
            return 0.0;
        }
        let total: f64 = self.peer_stats.values().map(|s| s.failure_rate()).sum();
        total / self.peer_stats.len() as f64
    }

    /// Get latency for a specific peer (in ms), or 0 if unknown.
    pub fn peer_latency_ms(&self, id: NodeId) -> u64 {
        self.peer_stats
            .get(&id)
            .map(|s| s.average_latency_ms())
            .unwrap_or(0)
    }

    /// Get failure rate for a specific peer (0.0 to 1.0), or 0 if unknown.
    pub fn peer_failure_rate(&self, id: NodeId) -> f64 {
        self.peer_stats
            .get(&id)
            .map(|s| s.failure_rate())
            .unwrap_or(0.0)
    }

    /// Get the number of peers being tracked.
    pub fn tracked_peers(&self) -> usize {
        self.peer_stats.len()
    }
}

/// Decisions returned from `scan`.
#[derive(Debug, Default)]
pub struct ScanResult {
    /// Direct probes timed out — caller should send PING_REQ to intermediaries
    /// and call `record_indirect_probe_sent` for each target.
    pub escalate_to_indirect: Vec<NodeId>,
    /// Indirect probes timed out — caller should call `table.suspect(id)`.
    pub declare_suspect: Vec<NodeId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn ack_resolves_probe() {
        let mut fd = FailureDetector::new(Duration::from_millis(100));
        fd.record_probe_sent(1);
        assert!(fd.is_probing(1));
        assert!(fd.record_ack_legacy(1));
        assert!(!fd.is_probing(1));
    }

    #[test]
    fn no_ack_escalates_to_indirect() {
        let mut fd = FailureDetector::new(Duration::from_millis(1));
        fd.record_probe_sent(99);
        std::thread::sleep(Duration::from_millis(5));
        let result = fd.scan(Instant::now());
        assert!(result.escalate_to_indirect.contains(&99));
        assert!(fd.is_probing(99)); // still tracking as Indirect
    }

    #[test]
    fn indirect_timeout_declares_suspect() {
        let mut fd = FailureDetector::new(Duration::from_millis(1));
        fd.record_probe_sent(42);
        std::thread::sleep(Duration::from_millis(5));
        fd.scan(Instant::now()); // escalate to indirect
        std::thread::sleep(Duration::from_millis(5));
        let result = fd.scan(Instant::now());
        assert!(result.declare_suspect.contains(&42));
        assert!(!fd.is_probing(42)); // removed after declaring suspect
    }

    #[test]
    fn ack_after_escalation_still_resolves() {
        let mut fd = FailureDetector::new(Duration::from_millis(1));
        fd.record_probe_sent(7);
        std::thread::sleep(Duration::from_millis(5));
        fd.scan(Instant::now()); // now Indirect
        assert!(fd.record_ack_legacy(7));
        assert!(!fd.is_probing(7));
    }

    #[test]
    fn no_duplicate_probes() {
        let mut fd = FailureDetector::new(Duration::from_millis(100));
        fd.record_probe_sent(5);
        fd.record_probe_sent(5); // second call is a no-op
        assert_eq!(fd.pending.len(), 1);
    }

    // ── Adaptive probing tests ─────────────────────────────────────────────────

    #[test]
    fn adaptive_disabled_returns_base_interval() {
        let config = AdaptiveConfig {
            enabled: false,
            base_interval_ms: 1000,
            min_interval_ms: 100,
            max_interval_ms: 5000,
            latency_window_size: 10,
            failure_window_size: 20,
        };
        let fd = FailureDetector::new(Duration::from_millis(500)).with_adaptive_config(config);

        assert_eq!(fd.adaptive_interval_ms(5), 1000);
    }

    #[test]
    fn adaptive_small_cluster_returns_base() {
        let config = AdaptiveConfig {
            enabled: true,
            base_interval_ms: 1000,
            min_interval_ms: 100,
            max_interval_ms: 5000,
            latency_window_size: 10,
            failure_window_size: 20,
        };
        let fd = FailureDetector::new(Duration::from_millis(500)).with_adaptive_config(config);

        // Small cluster, no stats -> should return base interval
        let interval = fd.adaptive_interval_ms(5);
        assert!(interval >= 900 && interval <= 1100);
    }

    #[test]
    fn adaptive_high_failure_rate_increases_frequency() {
        let config = AdaptiveConfig {
            enabled: true,
            base_interval_ms: 1000,
            min_interval_ms: 100,
            max_interval_ms: 5000,
            latency_window_size: 10,
            failure_window_size: 20,
        };
        let mut fd = FailureDetector::new(Duration::from_millis(500)).with_adaptive_config(config);

        // Record failures for a peer
        for _ in 0..15 {
            fd.record_probe_failure(1);
        }
        // Record some successes to keep in window
        for _ in 0..5 {
            let stats = fd.peer_stats.entry(1).or_insert_with(|| PeerStats::new(20));
            stats.record_success(100, 20);
        }

        let interval = fd.adaptive_interval_ms(5);
        // With ~75% failure rate, interval should be shorter (more aggressive probing)
        assert!(
            interval < 1000,
            "Expected interval < 1000ms, got {}ms",
            interval
        );
    }

    #[test]
    fn adaptive_large_cluster_decreases_frequency() {
        let config = AdaptiveConfig {
            enabled: true,
            base_interval_ms: 1000,
            min_interval_ms: 100,
            max_interval_ms: 5000,
            latency_window_size: 10,
            failure_window_size: 20,
        };
        let fd = FailureDetector::new(Duration::from_millis(500)).with_adaptive_config(config);

        // Large cluster (100 nodes) should have slightly longer interval
        let interval = fd.adaptive_interval_ms(100);
        // log2(100) ≈ 6.64, so factor ≈ 1.66
        assert!(
            interval > 1000,
            "Expected interval > 1000ms for large cluster, got {}ms",
            interval
        );
    }

    #[test]
    fn adaptive_interval_clamped_to_max() {
        let config = AdaptiveConfig {
            enabled: true,
            base_interval_ms: 1000,
            min_interval_ms: 100,
            max_interval_ms: 2000, // Low max
            latency_window_size: 10,
            failure_window_size: 20,
        };
        let fd = FailureDetector::new(Duration::from_millis(500)).with_adaptive_config(config);

        // Even with large cluster factor, should clamp to max
        let interval = fd.adaptive_interval_ms(1000);
        assert!(
            interval >= 1900 && interval <= 2000,
            "Expected ~2000ms, got {}ms",
            interval
        );
    }

    #[test]
    fn adaptive_interval_clamped_to_min() {
        let config = AdaptiveConfig {
            enabled: true,
            base_interval_ms: 500,
            min_interval_ms: 100,
            max_interval_ms: 5000,
            latency_window_size: 10,
            failure_window_size: 20,
        };
        let fd = FailureDetector::new(Duration::from_millis(500)).with_adaptive_config(config);

        // Small cluster, low base, should stay near base
        let interval = fd.adaptive_interval_ms(5);
        assert!(
            interval >= 100,
            "Expected interval >= 100ms, got {}ms",
            interval
        );
    }

    #[test]
    fn peer_stats_tracks_latency() {
        let config = AdaptiveConfig {
            enabled: true,
            base_interval_ms: 1000,
            min_interval_ms: 100,
            max_interval_ms: 5000,
            latency_window_size: 5,
            failure_window_size: 5,
        };
        let mut fd = FailureDetector::new(Duration::from_millis(500)).with_adaptive_config(config);

        // Record some latencies with actual delays
        for _ in 0..5 {
            fd.record_probe_sent(1);
            std::thread::sleep(Duration::from_millis(100));
            fd.record_ack(1, Instant::now());
        }

        // Should have average around 100ms (plus some overhead)
        let avg = fd.peer_latency_ms(1);
        assert!(avg >= 50 && avg <= 200, "Expected ~100ms, got {}ms", avg);
    }

    #[test]
    fn peer_stats_tracks_failure_rate() {
        let config = AdaptiveConfig {
            enabled: true,
            base_interval_ms: 1000,
            min_interval_ms: 100,
            max_interval_ms: 5000,
            latency_window_size: 10,
            failure_window_size: 10,
        };
        let mut fd = FailureDetector::new(Duration::from_millis(500)).with_adaptive_config(config);

        // Record 7 failures and 3 successes
        for _ in 0..7 {
            fd.record_probe_failure(1);
        }
        for _ in 0..3 {
            let stats = fd.peer_stats.entry(1).or_insert_with(|| PeerStats::new(10));
            stats.record_success(100, 10);
        }

        let rate = fd.peer_failure_rate(1);
        assert!((rate - 0.7).abs() < 0.1, "Expected ~0.7, got {}", rate);
    }

    #[test]
    fn average_latency_across_peers() {
        let config = AdaptiveConfig {
            enabled: true,
            base_interval_ms: 1000,
            min_interval_ms: 100,
            max_interval_ms: 5000,
            latency_window_size: 10,
            failure_window_size: 10,
        };
        let mut fd = FailureDetector::new(Duration::from_millis(500)).with_adaptive_config(config);

        // Record latencies for different peers
        for id in 1..=3 {
            fd.record_probe_sent(id);
            std::thread::sleep(Duration::from_millis(1));
            fd.record_ack(id, Instant::now());
        }

        let avg = fd.average_latency_ms();
        assert!(avg > 0, "Expected positive average latency");
    }

    #[test]
    fn tracked_peers_count() {
        let config = AdaptiveConfig::default();
        let mut fd = FailureDetector::new(Duration::from_millis(500)).with_adaptive_config(config);

        fd.record_probe_failure(1);
        fd.record_probe_failure(2);
        fd.record_probe_failure(3);

        assert_eq!(fd.tracked_peers(), 3);
    }
}
