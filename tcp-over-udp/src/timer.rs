//! Retransmit and keep-alive timer management.
//!
//! Reliable delivery requires that unacknowledged segments are re-sent if no
//! ACK arrives within a bounded time.  This module provides:
//! - [`RetransmitTimer`] — fires when the oldest unacknowledged segment has
//!   been in flight longer than the retransmit timeout (RTO).
//! - [`TimerHandle`] — a lightweight, cloneable reference used by
//!   [`crate::connection::Connection`] to arm, reset, and cancel timers
//!   without owning the underlying task.
//!
//! RTO is computed using a variant of Jacobson's algorithm (RFC 6298):
//!   `RTO = SRTT + 4 × RTTVAR`
//! and doubles on each consecutive timeout (exponential back-off) up to a
//! configurable maximum.
//!
//! No timer logic is implemented yet — this file defines the types and
//! documents the intended API.

use std::time::Duration;

/// Adjustable timeout parameters.
///
/// TODO: load these from CLI flags or a config struct.
pub struct TimerConfig {
    /// Initial RTO before any RTT sample is available.
    pub initial_rto: Duration,
    /// Maximum RTO after repeated back-off.
    pub max_rto: Duration,
    /// Interval between keep-alive probes (when enabled).
    pub keepalive_interval: Duration,
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            initial_rto: Duration::from_millis(1000),
            max_rto: Duration::from_secs(60),
            keepalive_interval: Duration::from_secs(30),
        }
    }
}

/// A running retransmit timer for one connection.
///
/// TODO: wrap a `tokio::time::Sleep` future and expose arm/reset/cancel methods.
pub struct RetransmitTimer {
    pub config: TimerConfig,
    /// Current RTO, updated after each RTT sample.
    pub current_rto: Duration,
    /// Smoothed RTT estimate (SRTT).
    pub srtt: Option<Duration>,
    /// RTT variance estimate (RTTVAR).
    pub rttvar: Option<Duration>,
}

impl Default for RetransmitTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl RetransmitTimer {
    /// Construct a new timer with default configuration.
    pub fn new() -> Self {
        let config = TimerConfig::default();
        let rto = config.initial_rto;
        Self {
            config,
            current_rto: rto,
            srtt: None,
            rttvar: None,
        }
    }

    /// Record a new RTT sample and update SRTT / RTTVAR / RTO (RFC 6298 §2).
    ///
    /// On the first sample:  SRTT = R,  RTTVAR = R/2,  RTO = SRTT + 4·RTTVAR.
    /// Subsequent samples:   RTTVAR = 3/4·RTTVAR + 1/4·|SRTT − R|
    ///                       SRTT   = 7/8·SRTT   + 1/8·R
    pub fn record_rtt_sample(&mut self, sample: Duration) {
        match (self.srtt, self.rttvar) {
            (None, _) => {
                // First measurement.
                self.srtt = Some(sample);
                self.rttvar = Some(sample / 2);
            }
            (Some(srtt), Some(rttvar)) => {
                let diff = sample.abs_diff(srtt);
                self.rttvar = Some(rttvar * 3 / 4 + diff / 4);
                self.srtt = Some(srtt * 7 / 8 + sample / 8);
            }
            _ => unreachable!(),
        }
        self.reset();
    }

    /// Double the RTO on retransmit timeout (exponential back-off, RFC 6298 §5.5).
    ///
    /// Capped at `config.max_rto` to prevent indefinite growth.
    pub fn back_off(&mut self) {
        self.current_rto = (self.current_rto * 2).min(self.config.max_rto);
    }

    /// Restore `current_rto` from the current SRTT / RTTVAR estimates.
    ///
    /// Falls back to `initial_rto` before the first RTT sample is available.
    pub fn reset(&mut self) {
        self.current_rto = match (self.srtt, self.rttvar) {
            (Some(srtt), Some(rttvar)) => (srtt + rttvar * 4).min(self.config.max_rto),
            _ => self.config.initial_rto,
        };
    }
}

/// Cheap handle passed to [`crate::connection::Connection`].
///
/// TODO: contain a `tokio::sync::watch::Sender` or similar to communicate
///       with the timer task without ownership.
pub struct TimerHandle;

impl TimerHandle {
    /// Arm the timer for the given duration.
    ///
    /// TODO: send deadline to the timer task.
    pub fn arm(&self, _duration: Duration) {
        todo!("arm timer")
    }

    /// Cancel a pending timer.
    ///
    /// TODO: send cancel signal to the timer task.
    pub fn cancel(&self) {
        todo!("cancel timer")
    }
}
