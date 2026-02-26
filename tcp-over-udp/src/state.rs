//! Connection finite-state machine (FSM) types.
//!
//! This module defines every possible state a [`crate::connection::Connection`]
//! can occupy, mirroring the TCP state diagram (RFC 793 §3.2) adapted for our
//! protocol.  State transitions are *not* implemented here — they live in
//! [`crate::connection`] — but all legal transitions are documented as
//! `TODO` comments so they serve as a roadmap.
//!
//! Keeping state types in their own module makes it easy to add guard logic,
//! entry/exit actions, or tracing without touching connection plumbing.

/// All possible states of the connection FSM.
///
/// ```text
//  CLOSED ──SYN sent──▶ SYN_SENT ──SYN-ACK──▶ ESTABLISHED
//    ▲                                              │
//    │                                    FIN sent  │
//    │                                              ▼
//  TIME_WAIT ◀── LAST_ACK ◀── CLOSE_WAIT ◀── FIN_WAIT_1
//                                                   │
//                                         FIN rcvd  │
//                                                   ▼
//                               FIN_WAIT_2 ──FIN──▶ CLOSING
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// No connection exists; initial state.
    Closed,
    /// SYN has been sent; waiting for SYN-ACK.
    ///
    /// TODO: transition to `Established` on SYN-ACK, or `Closed` on RST/timeout.
    SynSent,
    /// SYN received; SYN-ACK sent; waiting for ACK.
    ///
    /// TODO: transition to `Established` on ACK.
    SynReceived,
    /// Three-way handshake complete; data transfer in progress.
    ///
    /// TODO: transition to `FinWait1` on local close, `CloseWait` on peer FIN.
    Established,
    /// Local side sent FIN; waiting for ACK.
    ///
    /// TODO: transition to `FinWait2` on ACK, `Closing` on simultaneous FIN.
    FinWait1,
    /// ACK of local FIN received; waiting for peer's FIN.
    ///
    /// TODO: transition to `TimeWait` on peer FIN+ACK.
    FinWait2,
    /// Peer's FIN received; local close pending.
    ///
    /// TODO: transition to `LastAck` after sending FIN.
    CloseWait,
    /// Both sides sent FIN simultaneously.
    ///
    /// TODO: transition to `TimeWait` on ACK.
    Closing,
    /// Waiting for final ACK of peer's FIN.
    ///
    /// TODO: transition to `Closed` on ACK.
    LastAck,
    /// Waiting 2×MSL before freeing port; prevents stale segment confusion.
    ///
    /// TODO: transition to `Closed` after 2×MSL timer fires.
    TimeWait,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::Closed
    }
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: replace with a derive-based or macro-generated impl if needed.
        write!(f, "{self:?}")
    }
}
