//! Pluggable congestion-control abstraction.
//!
//! # Extension point
//!
//! Implement [`CongestionControl`] to swap in a different algorithm.
//! [`GbnSender`] is generic over CC with a default of [`RenoCC`], so
//! existing code compiles without change, while callers that need a
//! different algorithm can use turbofish syntax:
//! ```ignore
//! GbnConnection::<CubicCC>::connect(socket, peer, 4).await?
//! ```
//!
//! # How CUBIC would plug in
//!
//! ```ignore
//! pub struct CubicCC {
//!     cwnd: f64,
//!     ssthresh: usize,
//!     w_max: f64,       // cwnd before last reduction
//!     k: f64,           // time to recover to W_max
//!     t_epoch: Instant, // start of current CA epoch
//!     window_size: usize,
//! }
//!
//! impl CongestionControl for CubicCC {
//!     fn on_ack(&mut self, _acked_segments: usize) {
//!         let t = self.t_epoch.elapsed().as_secs_f64();
//!         // W_cubic(t) = C*(t-K)^3 + W_max   (C = 0.4)
//!         let w_cubic = 0.4 * (t - self.k).powi(3) + self.w_max;
//!         self.cwnd = w_cubic.max(self.cwnd).min(self.window_size as f64);
//!     }
//!     fn on_loss(&mut self, _in_flight: usize, kind: LossKind) {
//!         self.w_max = self.cwnd;
//!         // β_cubic = 0.7  (vs Reno's 0.5)
//!         self.ssthresh = ((self.cwnd * 0.7) as usize).max(2);
//!         // K = (W_max * (1-β) / C)^(1/3)
//!         self.k = (self.w_max * 0.3 / 0.4).cbrt();
//!         self.t_epoch = Instant::now();
//!         match kind {
//!             LossKind::Timeout      => self.cwnd = 1.0,
//!             LossKind::TripleDupAck => self.cwnd = self.ssthresh as f64,
//!         }
//!     }
//!     fn cwnd(&self) -> usize { self.cwnd as usize }
//! }
//! ```
//!
//! [`GbnSender`]: crate::gbn_sender::GbnSender

use std::fmt::Debug;

// ---------------------------------------------------------------------------
// CongestionState
// ---------------------------------------------------------------------------

/// Current phase of the TCP Reno congestion-control state machine.
///
/// This type lives here so that [`RenoCC`] and its callers can refer to
/// it without depending on `gbn_sender`.  It is re-exported from
/// `gbn_sender` for backward compatibility with existing code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CongestionState {
    /// `cwnd` grows by 1 per newly-acked segment (exponential until `ssthresh`).
    SlowStart,
    /// `cwnd` grows by 1 per RTT (additive increase).
    CongestionAvoidance,
    /// Entered on 3 duplicate ACKs; exits to CA when a new ACK advances the window.
    FastRecovery,
}

// ---------------------------------------------------------------------------
// LossKind
// ---------------------------------------------------------------------------

/// The kind of loss event detected by the connection layer.
///
/// Passed to [`CongestionControl::on_loss`] so that the CC algorithm can
/// distinguish between a retransmit-timeout and a fast-retransmit trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossKind {
    /// The retransmit timer expired before the segment was acknowledged.
    Timeout,
    /// Three consecutive duplicate ACKs were received (RFC 5681 fast retransmit).
    TripleDupAck,
}

// ---------------------------------------------------------------------------
// CongestionControl trait
// ---------------------------------------------------------------------------

/// A pluggable congestion-control algorithm for [`GbnSender`].
///
/// Implementors receive callbacks whenever an ACK or a loss event is
/// observed, and expose the current congestion window via [`cwnd`].
/// [`GbnSender`] calls these methods at the appropriate protocol points;
/// the algorithm's internal state is entirely encapsulated.
///
/// # Contract
///
/// - `cwnd()` returns the window size in **segments** (not bytes).
/// - `on_ack` is called with the number of *newly* acknowledged segments.
/// - `on_loss` is called with the number of segments currently in flight
///   and the kind of loss event, so that the algorithm can compute
///   `ssthresh ← max(2, in_flight / 2)` or equivalent.
///
/// [`GbnSender`]: crate::gbn_sender::GbnSender
/// [`cwnd`]: Self::cwnd
pub trait CongestionControl: Debug + Send + 'static {
    /// React to newly-acknowledged segments.
    ///
    /// Called by [`GbnSender`] after [`on_ack`] reports that `acked_segments`
    /// segments have left the network.  The algorithm should grow `cwnd`
    /// according to its rules (slow start, AIMD, cubic, …).
    ///
    /// [`GbnSender`]: crate::gbn_sender::GbnSender
    /// [`on_ack`]: crate::gbn_sender::GbnSender::on_ack
    fn on_ack(&mut self, acked_segments: usize);

    /// React to a loss event.
    ///
    /// `in_flight` is the number of unacknowledged segments at the moment
    /// the loss is detected.  The algorithm should reduce `cwnd` and, if
    /// applicable, set a new slow-start threshold.
    fn on_loss(&mut self, in_flight: usize, kind: LossKind);

    /// Current congestion window in segments.
    ///
    /// [`GbnSender::can_send`] calls this on every send to enforce the
    /// effective window = `min(window_size, cwnd)`.
    ///
    /// [`GbnSender::can_send`]: crate::gbn_sender::GbnSender::can_send
    fn cwnd(&self) -> usize;
}

// ---------------------------------------------------------------------------
// Reno constants
// ---------------------------------------------------------------------------

/// Initial congestion window: 1 segment (RFC 5681 §3.1).
pub const INITIAL_CWND: usize = 1;

/// Initial slow-start threshold: effectively unlimited until the first loss.
pub const INITIAL_SSTHRESH: usize = 64;

// ---------------------------------------------------------------------------
// RenoCC
// ---------------------------------------------------------------------------

/// TCP Reno congestion control.
///
/// Implements slow start, congestion avoidance, and fast recovery as
/// described in RFC 5681.  This is the default [`CongestionControl`]
/// used by [`GbnSender`].
///
/// [`GbnSender`]: crate::gbn_sender::GbnSender
#[derive(Debug)]
pub struct RenoCC {
    /// Congestion window in segments.
    pub cwnd: usize,

    /// Slow-start threshold in segments.
    pub ssthresh: usize,

    /// Current Reno phase.
    pub cc_state: CongestionState,

    /// Partial-increment accumulator for congestion avoidance.
    /// Incremented by `acked_count` on every ACK; when it reaches `cwnd`,
    /// `cwnd` is increased by 1 and the counter resets.
    cwnd_ca_counter: usize,

    /// Hard ceiling on `cwnd` (the sender's configured window size).
    window_size: usize,
}

impl RenoCC {
    /// Create a new [`RenoCC`] with the given window ceiling.
    pub fn new(window_size: usize) -> Self {
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            cc_state: CongestionState::SlowStart,
            cwnd_ca_counter: 0,
            window_size,
        }
    }
}

impl CongestionControl for RenoCC {
    fn on_ack(&mut self, acked_count: usize) {
        match self.cc_state {
            CongestionState::SlowStart => {
                // Exponential growth: +1 segment per newly-acked segment.
                self.cwnd = (self.cwnd + acked_count).min(self.window_size);
                if self.cwnd >= self.ssthresh {
                    self.cc_state = CongestionState::CongestionAvoidance;
                    self.cwnd_ca_counter = 0;
                    log::debug!("[cc] SS→CA cwnd={} ssthresh={}", self.cwnd, self.ssthresh);
                }
            }
            CongestionState::CongestionAvoidance => {
                // Additive increase: +1 segment per RTT.
                self.cwnd_ca_counter += acked_count;
                if self.cwnd_ca_counter >= self.cwnd {
                    self.cwnd_ca_counter = 0;
                    self.cwnd = (self.cwnd + 1).min(self.window_size);
                    log::debug!("[cc] CA cwnd={}", self.cwnd);
                }
            }
            CongestionState::FastRecovery => {
                // A new (non-duplicate) ACK exits fast recovery.
                self.cwnd = self.ssthresh;
                self.cc_state = CongestionState::CongestionAvoidance;
                self.cwnd_ca_counter = 0;
                log::debug!("[cc] FR→CA cwnd=ssthresh={}", self.cwnd);
            }
        }
    }

    fn on_loss(&mut self, in_flight: usize, kind: LossKind) {
        self.ssthresh = (in_flight / 2).max(2);
        self.cwnd_ca_counter = 0;
        match kind {
            LossKind::Timeout => {
                self.cwnd = 1;
                self.cc_state = CongestionState::SlowStart;
                log::debug!(
                    "[cc] timeout → SS  ssthresh={}  cwnd=1  in_flight={}",
                    self.ssthresh, in_flight
                );
            }
            LossKind::TripleDupAck => {
                self.cwnd = self.ssthresh + 3; // Reno inflation
                self.cc_state = CongestionState::FastRecovery;
                log::debug!(
                    "[cc] 3-dup-ACK → FR  ssthresh={}  cwnd={}  in_flight={}",
                    self.ssthresh, self.cwnd, in_flight
                );
            }
        }
    }

    fn cwnd(&self) -> usize {
        self.cwnd
    }
}
