//! TCP-style RTT estimation and adaptive retransmission timeout (RFC 6298).
//!
//! # Algorithm
//!
//! On the **first** RTT measurement `R`:
//! ```text
//! SRTT   ← R
//! RTTVAR ← R / 2
//! RTO    ← SRTT + max(G, 4 · RTTVAR)
//! ```
//!
//! On **subsequent** measurements `R'`:
//! ```text
//! RTTVAR ← (3/4) · RTTVAR + (1/4) · |SRTT − R'|
//! SRTT   ← (7/8) · SRTT   + (1/8) · R'
//! RTO    ← SRTT + max(G, 4 · RTTVAR)
//! ```
//!
//! where `G` is the clock granularity (1 ms here).
//!
//! On **timeout** (exponential back-off, RFC 6298 §5.5):
//! ```text
//! RTO ← min(2 · RTO, MAX_RTO)
//! ```
//!
//! # Karn's Algorithm
//!
//! RTT samples from **retransmitted** segments must never be fed into the
//! estimator.  When a segment has been sent more than once it is impossible
//! to know which transmission the ACK is responding to.  Callers enforce this
//! by only calling [`RttEstimator::record_sample`] when the acked segment had
//! `tx_count == 1` (see [`crate::gbn_sender::AckResult::rtt_sample`]).

use std::time::Duration;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Clock granularity term used in the RTO formula (RFC 6298 §2.2).
const CLOCK_GRANULARITY: Duration = Duration::from_millis(1);

/// Initial RTO before any sample is available (RFC 6298 §2.1).
pub const INITIAL_RTO: Duration = Duration::from_secs(1);

/// Floor on RTO.  RFC 6298 recommends 1 s for the public internet; we use
/// 200 ms so local/LAN tests can observe meaningful convergence below 1 s.
pub const MIN_RTO: Duration = Duration::from_millis(200);

/// Ceiling on RTO after repeated back-off (RFC 6298 §2.5).
pub const MAX_RTO: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// RttEstimator
// ---------------------------------------------------------------------------

/// RFC 6298 RTT estimator and adaptive RTO calculator.
///
/// Maintains a smoothed RTT ([`srtt`]) and a mean deviation ([`rttvar`])
/// and derives a dynamic retransmit timeout from them.
///
/// [`srtt`]: RttEstimator::srtt
/// [`rttvar`]: RttEstimator::rttvar
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Smoothed RTT (None until the first sample arrives).
    srtt: Option<Duration>,

    /// RTT mean deviation (None until the first sample arrives).
    rttvar: Option<Duration>,

    /// Current RTO value (updated after every sample or back-off).
    rto: Duration,

    /// Absolute minimum for `rto`.
    min_rto: Duration,

    /// Absolute maximum for `rto`.
    max_rto: Duration,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator {
    /// Create a new estimator with default parameters.
    ///
    /// RTO starts at [`INITIAL_RTO`] (1 s) and is reduced as samples arrive.
    pub fn new() -> Self {
        Self {
            srtt: None,
            rttvar: None,
            rto: INITIAL_RTO,
            min_rto: MIN_RTO,
            max_rto: MAX_RTO,
        }
    }

    /// Record one RTT measurement and update SRTT, RTTVAR, and RTO.
    ///
    /// **Only call this for segments with `tx_count == 1` (Karn's algorithm).**
    /// Samples from retransmitted segments are ambiguous and must be
    /// discarded to avoid poisoning the estimator.
    ///
    /// Implements RFC 6298 §2.2 and §2.3.
    pub fn record_sample(&mut self, sample: Duration) {
        match (self.srtt, self.rttvar) {
            (None, _) => {
                // First measurement (RFC 6298 §2.2).
                self.srtt = Some(sample);
                self.rttvar = Some(sample / 2);
            }
            (Some(srtt), Some(rttvar)) => {
                // Subsequent measurements (RFC 6298 §2.3).
                let diff = if sample > srtt {
                    sample - srtt
                } else {
                    srtt - sample
                };
                self.rttvar = Some(rttvar * 3 / 4 + diff / 4);
                self.srtt = Some(srtt * 7 / 8 + sample / 8);
            }
            _ => unreachable!(),
        }
        self.recompute_rto();
    }

    /// Double the RTO on retransmit timeout (RFC 6298 §5.5).
    ///
    /// The SRTT/RTTVAR estimators are **not** modified.  The first subsequent
    /// clean ACK will call [`record_sample`] and recompute RTO from the
    /// smoothed estimates, effectively "unsetting" the back-off.
    ///
    /// [`record_sample`]: Self::record_sample
    pub fn back_off(&mut self) {
        self.rto = (self.rto * 2).min(self.max_rto);
    }

    /// Current RTO.  Use this value for the retransmit timer deadline.
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Smoothed RTT estimate (`SRTT`).
    ///
    /// Returns `None` before the first sample has been recorded.
    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// RTT mean deviation (`RTTVAR`).
    ///
    /// Returns `None` before the first sample has been recorded.
    pub fn rttvar(&self) -> Option<Duration> {
        self.rttvar
    }

    /// `true` once at least one RTT sample has been recorded.
    pub fn has_sample(&self) -> bool {
        self.srtt.is_some()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Recompute `rto` from the current SRTT and RTTVAR (RFC 6298 §2.2–2.3).
    fn recompute_rto(&mut self) {
        self.rto = match (self.srtt, self.rttvar) {
            (Some(srtt), Some(rttvar)) => {
                // RTO = SRTT + max(G, 4·RTTVAR)
                srtt + (rttvar * 4).max(CLOCK_GRANULARITY)
            }
            _ => INITIAL_RTO,
        }
        .max(self.min_rto)
        .min(self.max_rto);
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_has_no_sample() {
        let r = RttEstimator::new();
        assert!(!r.has_sample());
        assert_eq!(r.rto(), INITIAL_RTO);
        assert_eq!(r.srtt(), None);
        assert_eq!(r.rttvar(), None);
    }

    #[test]
    fn first_sample_sets_srtt_and_rttvar() {
        let mut r = RttEstimator::new();
        r.record_sample(Duration::from_millis(100));

        assert!(r.has_sample());
        assert_eq!(r.srtt(), Some(Duration::from_millis(100)));
        assert_eq!(r.rttvar(), Some(Duration::from_millis(50)));
        // RTO = 100ms + max(1ms, 4×50ms) = 100ms + 200ms = 300ms ≥ MIN_RTO(200ms)
        assert_eq!(r.rto(), Duration::from_millis(300));
    }

    #[test]
    fn subsequent_samples_update_srtt_ewma() {
        let mut r = RttEstimator::new();
        // Warm up with 200 ms.
        r.record_sample(Duration::from_millis(200));

        // Feed eight identical 100 ms samples; SRTT should converge toward 100 ms.
        for _ in 0..8 {
            r.record_sample(Duration::from_millis(100));
        }

        let srtt = r.srtt().unwrap();
        assert!(
            srtt >= Duration::from_millis(100) && srtt <= Duration::from_millis(180),
            "SRTT {srtt:?} should be converging toward 100 ms"
        );
    }

    #[test]
    fn constant_rtt_converges_srtt_exactly() {
        let mut r = RttEstimator::new();
        // After many identical samples the EWMA converges to the true value.
        for _ in 0..32 {
            r.record_sample(Duration::from_millis(50));
        }
        let srtt = r.srtt().unwrap();
        // Allow ±2 ms rounding error from integer arithmetic.
        assert!(
            srtt.as_millis().abs_diff(50) <= 2,
            "SRTT should ≈ 50ms, got {srtt:?}"
        );
    }

    #[test]
    fn rto_includes_four_rttvar() {
        let mut r = RttEstimator::new();
        // First sample: SRTT=100ms, RTTVAR=50ms → RTO=100+4×50=300ms
        r.record_sample(Duration::from_millis(100));
        assert_eq!(r.rto(), Duration::from_millis(300));
    }

    #[test]
    fn rto_floored_at_min_rto() {
        let mut r = RttEstimator::new();
        // Feed tiny samples; computed RTO would be well below MIN_RTO.
        for _ in 0..20 {
            r.record_sample(Duration::from_micros(50));
        }
        assert_eq!(
            r.rto(),
            MIN_RTO,
            "RTO should be clamped at MIN_RTO, got {:?}",
            r.rto()
        );
    }

    #[test]
    fn back_off_doubles_rto() {
        let mut r = RttEstimator::new();
        let initial = r.rto();
        r.back_off();
        assert_eq!(r.rto(), initial * 2);
    }

    #[test]
    fn back_off_caps_at_max_rto() {
        let mut r = RttEstimator::new();
        for _ in 0..30 {
            r.back_off();
        }
        assert_eq!(r.rto(), MAX_RTO);
    }

    #[test]
    fn record_sample_after_back_off_resets_rto() {
        let mut r = RttEstimator::new();
        // Simulate two timeouts: RTO is now 4 s.
        r.back_off();
        r.back_off();
        assert_eq!(r.rto(), Duration::from_secs(4));

        // First clean ACK: re-derives RTO from SRTT/RTTVAR.
        r.record_sample(Duration::from_millis(100));
        // RTO = 100ms + 4×50ms = 300ms < 4s
        assert!(
            r.rto() < Duration::from_secs(4),
            "record_sample should undo back-off"
        );
    }

    #[test]
    fn jitter_widens_rttvar() {
        let mut r = RttEstimator::new();
        // Alternating samples: 50 ms and 150 ms (mean 100 ms, jitter ±50 ms).
        for i in 0..10 {
            let ms = if i % 2 == 0 { 50 } else { 150 };
            r.record_sample(Duration::from_millis(ms));
        }
        // High jitter → RTTVAR should be substantial.
        let rttvar = r.rttvar().unwrap();
        assert!(
            rttvar > Duration::from_millis(5),
            "jitter should inflate RTTVAR, got {rttvar:?}"
        );
        // And RTO should exceed SRTT.
        assert!(
            r.rto() > r.srtt().unwrap(),
            "RTO must exceed SRTT when there is jitter"
        );
    }

    #[test]
    fn back_off_does_not_touch_srtt_rttvar() {
        let mut r = RttEstimator::new();
        r.record_sample(Duration::from_millis(100));
        let srtt_before = r.srtt();
        let rttvar_before = r.rttvar();

        r.back_off();
        r.back_off();

        // SRTT and RTTVAR must be unaffected by back-off.
        assert_eq!(r.srtt(), srtt_before, "back_off must not modify SRTT");
        assert_eq!(r.rttvar(), rttvar_before, "back_off must not modify RTTVAR");
    }
}
