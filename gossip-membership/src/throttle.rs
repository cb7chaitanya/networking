/// Gossip backpressure and adaptive throttling.
///
/// Prevents slow nodes from being overwhelmed by gossip fanout through
/// three cooperating components:
///
/// - **`QueueDepthMonitor`** — tracks pending inbound messages awaiting
///   processing, exposing the current depth and a high-water mark.
///
/// - **`BackpressureSignal`** — converts the raw depth into a normalised
///   pressure ratio (0.0–1.0) and provides saturation / shedding decisions.
///
/// - **`AdaptiveThrottle`** — uses the pressure signal to dynamically
///   reduce gossip fanout, stretch the gossip interval, and probabilistically
///   skip gossip rounds when the node is overloaded.
///
/// All types are synchronous, allocation-free, and suitable for use in a
/// hot event loop.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::SystemTime;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ── Queue depth monitor ───────────────────────────────────────────────────────

/// Tracks the number of messages currently in-flight (received but not yet
/// fully processed) and records the peak observed depth.
#[derive(Debug, Clone)]
pub struct QueueDepthMonitor {
    /// Maximum queue depth before the node is considered overloaded.
    capacity: u64,
    /// Current number of pending messages.
    pending: Arc<AtomicU64>,
    /// Peak pending count observed since creation / last reset.
    high_water_mark: Arc<AtomicU64>,
}

impl QueueDepthMonitor {
    /// Create a new monitor with the given capacity threshold.
    pub fn new(capacity: u64) -> Self {
        Self {
            capacity: capacity.max(1), // avoid div-by-zero
            pending: Arc::new(AtomicU64::new(0)),
            high_water_mark: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Record one new inbound message.
    pub fn increment(&self) {
        let p = self.pending.fetch_add(1, Ordering::Relaxed) + 1;
        self.high_water_mark.fetch_max(p, Ordering::Relaxed);
    }

    /// Record one message as fully processed.
    pub fn decrement(&self) {
        let mut curr = self.pending.load(Ordering::Relaxed);
        loop {
            if curr == 0 { break; }
            match self.pending.compare_exchange_weak(curr, curr - 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(new) => curr = new,
            }
        }
    }

    /// Current number of pending messages.
    pub fn depth(&self) -> u64 {
        self.pending.load(Ordering::Relaxed)
    }

    /// Peak pending count observed.
    pub fn high_water_mark(&self) -> u64 {
        self.high_water_mark.load(Ordering::Relaxed)
    }

    /// Configured capacity threshold.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Reset the high-water mark (e.g. after snapshotting into metrics).
    pub fn reset_high_water_mark(&self) {
        self.high_water_mark.store(self.depth(), Ordering::Relaxed);
    }
}

// ── Backpressure signal ───────────────────────────────────────────────────────

/// Converts raw queue depth into a normalised pressure ratio and provides
/// saturation / load-shedding decisions.
#[derive(Debug)]
pub struct BackpressureSignal {
    /// Pressure at or above which the node is considered saturated.
    saturation_threshold: f64,
    /// Pressure above which probabilistic shedding kicks in.
    shed_threshold: f64,
}

impl BackpressureSignal {
    /// Create a signal with default thresholds (saturated ≥ 0.8, shedding > 0.5).
    pub fn new() -> Self {
        Self {
            saturation_threshold: 0.8,
            shed_threshold: 0.5,
        }
    }

    /// Create with custom thresholds. Both values are clamped to [0.0, 1.0].
    pub fn with_thresholds(saturation: f64, shed: f64) -> Self {
        Self {
            saturation_threshold: saturation.clamp(0.0, 1.0),
            shed_threshold: shed.clamp(0.0, 1.0),
        }
    }

    /// Compute the current pressure ratio (0.0–1.0) from a queue monitor.
    pub fn pressure(&self, monitor: &QueueDepthMonitor) -> f64 {
        let ratio = monitor.depth() as f64 / monitor.capacity() as f64;
        ratio.min(1.0)
    }

    /// Returns `true` when pressure is at or above the saturation threshold.
    pub fn is_saturated(&self, monitor: &QueueDepthMonitor) -> bool {
        self.pressure(monitor) >= self.saturation_threshold
    }

    /// Returns `true` probabilistically when pressure exceeds the shed
    /// threshold.  Probability ramps linearly from 0 at `shed_threshold` to
    /// 1.0 at pressure = 1.0.
    ///
    /// Uses a cheap hash-based PRNG seeded by the current time so the
    /// decision varies per call without requiring a `rand` dependency.
    pub fn should_shed(&self, monitor: &QueueDepthMonitor) -> bool {
        let p = self.pressure(monitor);
        if p <= self.shed_threshold {
            return false;
        }
        let range = 1.0 - self.shed_threshold;
        if range <= 0.0 {
            return true;
        }
        let probability = (p - self.shed_threshold) / range;

        // Cheap pseudo-random roll.
        let mut h = DefaultHasher::new();
        SystemTime::now().hash(&mut h);
        monitor.depth().hash(&mut h);
        let roll = (h.finish() % 1000) as f64 / 1000.0;

        roll < probability
    }
}

impl Default for BackpressureSignal {
    fn default() -> Self {
        Self::new()
    }
}

// ── Adaptive throttle ─────────────────────────────────────────────────────────

/// Dynamically adjusts gossip parameters based on local backpressure.
#[derive(Debug)]
pub struct AdaptiveThrottle {
    signal: BackpressureSignal,
    /// How aggressively to reduce fanout under pressure (0.0 = no effect,
    /// 1.0 = reduce to 1 at full pressure).
    damping_factor: f64,
    /// How much to stretch the gossip interval under pressure.  At full
    /// pressure the interval is multiplied by `1.0 + stretch_factor`.
    stretch_factor: f64,
}

impl AdaptiveThrottle {
    /// Create an adaptive throttle with the given tuning parameters.
    ///
    /// - `damping_factor`: 0.0–1.0 — fraction of fanout removed at full pressure.
    /// - `stretch_factor`: ≥ 0.0 — multiplier added to gossip interval at full pressure.
    pub fn new(damping_factor: f64, stretch_factor: f64) -> Self {
        Self {
            signal: BackpressureSignal::new(),
            damping_factor: damping_factor.clamp(0.0, 1.0),
            stretch_factor: stretch_factor.max(0.0),
        }
    }

    /// Access the underlying backpressure signal.
    pub fn signal(&self) -> &BackpressureSignal {
        &self.signal
    }

    /// Current pressure ratio (0.0–1.0).
    pub fn pressure(&self, monitor: &QueueDepthMonitor) -> f64 {
        self.signal.pressure(monitor)
    }

    /// Compute the effective fanout, reduced by pressure.
    ///
    /// `effective = base * (1.0 - pressure * damping_factor)`, floored at 1.
    pub fn effective_fanout(&self, base_fanout: usize, monitor: &QueueDepthMonitor) -> usize {
        let p = self.signal.pressure(monitor);
        let scale = 1.0 - p * self.damping_factor;
        let result = (base_fanout as f64 * scale).round() as usize;
        result.max(1)
    }

    /// Compute the effective gossip interval, stretched by pressure.
    ///
    /// `effective = base * (1.0 + pressure * stretch_factor)`.
    pub fn effective_interval_ms(&self, base_ms: u64, monitor: &QueueDepthMonitor) -> u64 {
        let p = self.signal.pressure(monitor);
        let multiplier = 1.0 + p * self.stretch_factor;
        (base_ms as f64 * multiplier).round() as u64
    }

    /// Returns `true` when the gossip round should be skipped entirely
    /// due to extreme backpressure (uses probabilistic shedding).
    pub fn should_skip_round(&self, monitor: &QueueDepthMonitor) -> bool {
        self.signal.should_shed(monitor)
    }

    /// Returns `true` when the node is saturated.
    pub fn is_saturated(&self, monitor: &QueueDepthMonitor) -> bool {
        self.signal.is_saturated(monitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── QueueDepthMonitor ────────────────────────────────────────────────────

    #[test]
    fn monitor_starts_empty() {
        let m = QueueDepthMonitor::new(100);
        assert_eq!(m.depth(), 0);
        assert_eq!(m.high_water_mark(), 0);
        assert_eq!(m.capacity(), 100);
    }

    #[test]
    fn monitor_increment_decrement() {
        let m = QueueDepthMonitor::new(100);
        m.increment();
        m.increment();
        m.increment();
        assert_eq!(m.depth(), 3);
        m.decrement();
        assert_eq!(m.depth(), 2);
    }

    #[test]
    fn monitor_high_water_mark_tracks_peak() {
        let m = QueueDepthMonitor::new(100);
        m.increment();
        m.increment();
        m.increment(); // peak = 3
        m.decrement();
        m.decrement(); // depth = 1, but HWM = 3
        assert_eq!(m.depth(), 1);
        assert_eq!(m.high_water_mark(), 3);
    }

    #[test]
    fn monitor_decrement_no_underflow() {
        let m = QueueDepthMonitor::new(100);
        m.decrement();
        m.decrement();
        assert_eq!(m.depth(), 0);
    }

    #[test]
    fn monitor_zero_capacity_clamped_to_one() {
        let m = QueueDepthMonitor::new(0);
        assert_eq!(m.capacity(), 1);
    }

    #[test]
    fn monitor_reset_high_water_mark() {
        let m = QueueDepthMonitor::new(100);
        for _ in 0..10 {
            m.increment();
        }
        for _ in 0..7 {
            m.decrement();
        }
        assert_eq!(m.high_water_mark(), 10);
        m.reset_high_water_mark();
        assert_eq!(m.high_water_mark(), 3); // current depth
    }

    // ── BackpressureSignal ───────────────────────────────────────────────────

    #[test]
    fn signal_pressure_zero_when_empty() {
        let s = BackpressureSignal::new();
        let m = QueueDepthMonitor::new(100);
        assert!((s.pressure(&m) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn signal_pressure_one_at_capacity() {
        let s = BackpressureSignal::new();
        let m = QueueDepthMonitor::new(10);
        for _ in 0..10 {
            m.increment();
        }
        assert!((s.pressure(&m) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn signal_pressure_capped_at_one() {
        let s = BackpressureSignal::new();
        let m = QueueDepthMonitor::new(10);
        for _ in 0..20 {
            m.increment();
        }
        assert!((s.pressure(&m) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn signal_not_saturated_below_threshold() {
        let s = BackpressureSignal::new(); // threshold = 0.8
        let m = QueueDepthMonitor::new(100);
        for _ in 0..79 {
            m.increment();
        }
        assert!(!s.is_saturated(&m));
    }

    #[test]
    fn signal_saturated_at_threshold() {
        let s = BackpressureSignal::new();
        let m = QueueDepthMonitor::new(100);
        for _ in 0..80 {
            m.increment();
        }
        assert!(s.is_saturated(&m));
    }

    #[test]
    fn signal_no_shed_below_shed_threshold() {
        let s = BackpressureSignal::new(); // shed threshold = 0.5
        let m = QueueDepthMonitor::new(100);
        for _ in 0..49 {
            m.increment();
        }
        // At 49% pressure, should never shed.
        for _ in 0..100 {
            assert!(!s.should_shed(&m));
        }
    }

    #[test]
    fn signal_always_sheds_at_full_pressure() {
        // At pressure = 1.0, probability = 1.0 → always sheds.
        let s = BackpressureSignal::new();
        let m = QueueDepthMonitor::new(10);
        for _ in 0..10 {
            m.increment();
        }
        // should_shed uses time-based randomness, but at p=1.0 it's certain.
        assert!(s.should_shed(&m));
    }

    #[test]
    fn signal_custom_thresholds() {
        let s = BackpressureSignal::with_thresholds(0.5, 0.3);
        let m = QueueDepthMonitor::new(100);
        for _ in 0..50 {
            m.increment();
        }
        assert!(s.is_saturated(&m)); // 50% >= 0.5 threshold
    }

    // ── AdaptiveThrottle ─────────────────────────────────────────────────────

    #[test]
    fn throttle_full_fanout_when_idle() {
        let t = AdaptiveThrottle::new(0.8, 2.0);
        let m = QueueDepthMonitor::new(100);
        assert_eq!(t.effective_fanout(10, &m), 10);
    }

    #[test]
    fn throttle_reduced_fanout_under_pressure() {
        let t = AdaptiveThrottle::new(1.0, 2.0); // damping = 1.0
        let m = QueueDepthMonitor::new(100);
        for _ in 0..50 {
            m.increment();
        }
        // pressure = 0.5, scale = 1.0 - 0.5 * 1.0 = 0.5
        // effective = round(10 * 0.5) = 5
        assert_eq!(t.effective_fanout(10, &m), 5);
    }

    #[test]
    fn throttle_fanout_floored_at_one() {
        let t = AdaptiveThrottle::new(1.0, 2.0);
        let m = QueueDepthMonitor::new(10);
        for _ in 0..10 {
            m.increment();
        }
        // pressure = 1.0, scale = 0.0 → floor at 1
        assert_eq!(t.effective_fanout(10, &m), 1);
    }

    #[test]
    fn throttle_zero_damping_no_reduction() {
        let t = AdaptiveThrottle::new(0.0, 2.0);
        let m = QueueDepthMonitor::new(10);
        for _ in 0..10 {
            m.increment();
        }
        // damping = 0, so no reduction even at full pressure.
        assert_eq!(t.effective_fanout(10, &m), 10);
    }

    #[test]
    fn throttle_interval_unchanged_when_idle() {
        let t = AdaptiveThrottle::new(0.8, 2.0);
        let m = QueueDepthMonitor::new(100);
        assert_eq!(t.effective_interval_ms(200, &m), 200);
    }

    #[test]
    fn throttle_interval_stretched_under_pressure() {
        let t = AdaptiveThrottle::new(0.8, 2.0); // stretch = 2.0
        let m = QueueDepthMonitor::new(100);
        for _ in 0..100 {
            m.increment();
        }
        // pressure = 1.0, multiplier = 1.0 + 1.0 * 2.0 = 3.0
        // effective = round(200 * 3.0) = 600
        assert_eq!(t.effective_interval_ms(200, &m), 600);
    }

    #[test]
    fn throttle_interval_partial_pressure() {
        let t = AdaptiveThrottle::new(0.8, 2.0);
        let m = QueueDepthMonitor::new(100);
        for _ in 0..50 {
            m.increment();
        }
        // pressure = 0.5, multiplier = 1.0 + 0.5 * 2.0 = 2.0
        // effective = round(200 * 2.0) = 400
        assert_eq!(t.effective_interval_ms(200, &m), 400);
    }

    #[test]
    fn throttle_not_saturated_when_idle() {
        let t = AdaptiveThrottle::new(0.8, 2.0);
        let m = QueueDepthMonitor::new(100);
        assert!(!t.is_saturated(&m));
    }

    #[test]
    fn throttle_saturated_at_high_pressure() {
        let t = AdaptiveThrottle::new(0.8, 2.0);
        let m = QueueDepthMonitor::new(100);
        for _ in 0..85 {
            m.increment();
        }
        assert!(t.is_saturated(&m));
    }

    #[test]
    fn throttle_pressure_reflects_monitor() {
        let t = AdaptiveThrottle::new(0.8, 2.0);
        let m = QueueDepthMonitor::new(200);
        for _ in 0..100 {
            m.increment();
        }
        assert!((t.pressure(&m) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn throttle_does_not_skip_when_idle() {
        let t = AdaptiveThrottle::new(0.8, 2.0);
        let m = QueueDepthMonitor::new(100);
        // At 0 pressure, should never skip.
        for _ in 0..100 {
            assert!(!t.should_skip_round(&m));
        }
    }

    #[test]
    fn throttle_skips_at_full_pressure() {
        let t = AdaptiveThrottle::new(0.8, 2.0);
        let m = QueueDepthMonitor::new(10);
        for _ in 0..10 {
            m.increment();
        }
        // At full pressure, should always skip.
        assert!(t.should_skip_round(&m));
    }
}
