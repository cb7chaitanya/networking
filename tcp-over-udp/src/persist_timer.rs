//! RFC 793 §3.7 persist timer for zero-window flow-control stalls.
//!
//! When the peer advertises `rwnd = 0`, the sender must stop transmitting new
//! data and instead send periodic **probe** segments to elicit a window update.
//! This timer tracks that state independently of the retransmit timer.
//!
//! # Orthogonality
//!
//! The persist timer and the retransmit timer are mutually exclusive:
//!
//! ```text
//! retransmit_armed   persist.is_active()   Meaning
//! ───────────────    ───────────────────   ──────────────────────────────
//! false              false                 Idle — no unacked data
//! true               false                 Normal — SR retransmit running
//! false              true                  Stalled — persist probing
//! true               true                  IMPOSSIBLE (invariant violation)
//! ```
//!
//! The `GbnConnection` event loop enforces this by clearing the other timer
//! whenever one is armed.
//!
//! # Back-off
//!
//! The initial probe interval is [`PERSIST_INIT`] (1 s, per RFC 793).  Each
//! call to [`PersistTimer::on_probe_sent`] doubles the interval up to
//! [`PERSIST_MAX`] (60 s).  The interval resets to [`PERSIST_INIT`] when the
//! window reopens so a subsequent stall starts fresh.
//!
//! Persist probes do **not** count against the retransmit retry budget and do
//! **not** trigger congestion-control penalties.

use std::time::Duration;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Initial probe interval (RFC 793 §3.7 and RFC 6429 §3).
pub const PERSIST_INIT: Duration = Duration::from_secs(1);

/// Maximum probe interval after repeated back-off.
pub const PERSIST_MAX: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// PersistTransition
// ---------------------------------------------------------------------------

/// Describes how the persist timer's activation state changed after an
/// [`PersistTimer::on_rwnd_update`] call.
///
/// The connection layer uses this to arm or disarm the underlying tokio timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistTransition {
    /// `rwnd` just transitioned from non-zero to zero — arm the persist timer.
    Activated,
    /// `rwnd` just transitioned from zero to non-zero — disarm and reset.
    Deactivated,
    /// No state change (e.g. consecutive `rwnd == 0` updates while stalled).
    Unchanged,
}

// ---------------------------------------------------------------------------
// PersistTimer
// ---------------------------------------------------------------------------

/// RFC 793 persist timer state machine.
///
/// Owned by [`crate::gbn_sender::GbnSender`]; the actual `tokio::time::Sleep`
/// future lives in the connection layer so that it participates in the
/// `tokio::select!` alongside the retransmit timer.
///
/// # Usage
///
/// ```ignore
/// // When an ACK arrives:
/// let transition = sender.update_peer_rwnd(h.window);
/// match transition {
///     PersistTransition::Activated   => { /* arm persist tokio timer */   }
///     PersistTransition::Deactivated => { /* disarm persist tokio timer */ }
///     PersistTransition::Unchanged   => {}
/// }
///
/// // When the persist tokio timer fires:
/// send_probe(..);
/// sender.persist.on_probe_sent();
/// reset_timer(sender.persist.interval());
/// ```
#[derive(Debug, Clone)]
pub struct PersistTimer {
    /// Whether the timer is currently active (peer window == 0).
    active: bool,

    /// Current probe interval; backs off after each probe.
    interval: Duration,

    /// Total probes sent since creation (monotonically increasing).
    /// Exposed via [`probe_count`] for test assertions.
    ///
    /// [`probe_count`]: Self::probe_count
    probe_count: u64,
}

impl Default for PersistTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistTimer {
    /// Create a new, inactive persist timer with default parameters.
    pub fn new() -> Self {
        Self {
            active: false,
            interval: PERSIST_INIT,
            probe_count: 0,
        }
    }

    // -----------------------------------------------------------------------
    // State transitions
    // -----------------------------------------------------------------------

    /// Update the persist timer in response to a new advertised `rwnd` value.
    ///
    /// Must be called whenever an ACK is received that carries an updated
    /// window field.  Returns a [`PersistTransition`] that the connection layer
    /// uses to arm or disarm the underlying tokio timer.
    pub fn on_rwnd_update(&mut self, rwnd: usize) -> PersistTransition {
        match (self.active, rwnd == 0) {
            (false, true) => {
                // Window just closed: activate persist.
                self.active = true;
                PersistTransition::Activated
            }
            (true, false) => {
                // Window reopened (possibly mid-backoff): deactivate and reset.
                self.active = false;
                self.interval = PERSIST_INIT; // fresh start for the next stall
                PersistTransition::Deactivated
            }
            _ => PersistTransition::Unchanged,
        }
    }

    /// Record that a probe was just sent.
    ///
    /// Increments the probe counter and doubles the probe interval (bounded by
    /// [`PERSIST_MAX`]).  Call this *after* the probe packet is transmitted.
    pub fn on_probe_sent(&mut self) {
        self.probe_count += 1;
        self.interval = (self.interval * 2).min(PERSIST_MAX);
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// `true` when the persist timer is active (peer window is zero).
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Current probe interval.  Use this to reset the tokio timer after each
    /// probe fires.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Total number of probes sent since this timer was created.
    pub fn probe_count(&self) -> u64 {
        self.probe_count
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_is_inactive() {
        let t = PersistTimer::new();
        assert!(!t.is_active());
        assert_eq!(t.interval(), PERSIST_INIT);
        assert_eq!(t.probe_count(), 0);
    }

    #[test]
    fn activates_on_zero_rwnd() {
        let mut t = PersistTimer::new();
        assert_eq!(t.on_rwnd_update(0), PersistTransition::Activated);
        assert!(t.is_active());
    }

    #[test]
    fn deactivates_on_positive_rwnd() {
        let mut t = PersistTimer::new();
        t.on_rwnd_update(0);
        assert_eq!(t.on_rwnd_update(1), PersistTransition::Deactivated);
        assert!(!t.is_active());
    }

    #[test]
    fn deactivation_resets_interval() {
        let mut t = PersistTimer::new();
        t.on_rwnd_update(0);
        t.on_probe_sent(); // interval → 2 s
        t.on_probe_sent(); // interval → 4 s
        t.on_rwnd_update(100); // deactivate
        assert_eq!(t.interval(), PERSIST_INIT, "interval must reset after deactivation");
    }

    #[test]
    fn idempotent_consecutive_zero_updates() {
        let mut t = PersistTimer::new();
        t.on_rwnd_update(0); // Activated
        assert_eq!(t.on_rwnd_update(0), PersistTransition::Unchanged);
        assert_eq!(t.on_rwnd_update(0), PersistTransition::Unchanged);
        assert!(t.is_active());
    }

    #[test]
    fn idempotent_consecutive_positive_updates() {
        let mut t = PersistTimer::new();
        assert_eq!(t.on_rwnd_update(100), PersistTransition::Unchanged);
        assert_eq!(t.on_rwnd_update(200), PersistTransition::Unchanged);
        assert!(!t.is_active());
    }

    #[test]
    fn on_probe_sent_doubles_interval() {
        let mut t = PersistTimer::new();
        t.on_rwnd_update(0);

        t.on_probe_sent();
        assert_eq!(t.interval(), PERSIST_INIT * 2);
        assert_eq!(t.probe_count(), 1);

        t.on_probe_sent();
        assert_eq!(t.interval(), PERSIST_INIT * 4);
        assert_eq!(t.probe_count(), 2);
    }

    #[test]
    fn interval_capped_at_persist_max() {
        let mut t = PersistTimer::new();
        t.on_rwnd_update(0);
        for _ in 0..30 {
            t.on_probe_sent();
        }
        assert_eq!(t.interval(), PERSIST_MAX, "interval must be capped at PERSIST_MAX");
    }

    #[test]
    fn probe_count_monotonically_increases() {
        let mut t = PersistTimer::new();
        t.on_rwnd_update(0);
        for i in 1..=5 {
            t.on_probe_sent();
            assert_eq!(t.probe_count(), i);
        }
    }

    #[test]
    fn reactivation_after_window_reopens() {
        let mut t = PersistTimer::new();
        // First stall
        t.on_rwnd_update(0);
        t.on_probe_sent();
        t.on_probe_sent(); // interval = 4 s
        t.on_rwnd_update(512); // window opens, interval resets

        // Second stall — should start fresh from PERSIST_INIT
        assert_eq!(t.on_rwnd_update(0), PersistTransition::Activated);
        assert_eq!(t.interval(), PERSIST_INIT);
        assert!(t.is_active());
    }
}
