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

impl FailureDetector {
    pub fn new(probe_timeout: Duration) -> Self {
        Self {
            probe_timeout,
            pending: HashMap::new(),
        }
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
    pub fn record_ack(&mut self, id: NodeId) -> bool {
        self.pending.remove(&id).is_some()
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
            result.declare_suspect.push(*id);
        }

        result
    }

    /// True if there is currently a pending probe for `id`.
    pub fn is_probing(&self, id: NodeId) -> bool {
        self.pending.contains_key(&id)
    }
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
        assert!(fd.record_ack(1));
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
        assert!(fd.record_ack(7));
        assert!(!fd.is_probing(7));
    }

    #[test]
    fn no_duplicate_probes() {
        let mut fd = FailureDetector::new(Duration::from_millis(100));
        fd.record_probe_sent(5);
        fd.record_probe_sent(5); // second call is a no-op
        assert_eq!(fd.pending.len(), 1);
    }
}
