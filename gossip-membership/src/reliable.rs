/// Reliable message delivery — tracks outgoing messages that expect an ACK
/// and retransmits them on timeout.
///
/// The sender sets the `REQUEST_ACK` flag on a message before sending.
/// When the receiver processes a message with this flag, it responds with
/// an ACK.  If the sender doesn't receive any message from the target
/// within the timeout window, it retransmits up to `max_retries` times.
///
/// Keyed by target `NodeId` — at most one pending message per target.
/// If a new message is tracked to the same target before the old one is
/// acked, the old entry is replaced.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::message::Message;
use crate::node::NodeId;

/// One in-flight message awaiting acknowledgement.
#[derive(Debug, Clone)]
pub struct PendingAck {
    pub message: Message,
    pub target_addr: SocketAddr,
    pub deadline: Instant,
    pub retries_left: u8,
}

/// Result of a retry scan.
pub struct RetryResult {
    /// Messages to retransmit: `(target_id, message, target_addr)`.
    pub retransmits: Vec<(NodeId, Message, SocketAddr)>,
    /// Number of entries that exhausted all retries and were removed.
    pub exhausted: usize,
}

/// Tracks messages awaiting acknowledgement, with timeout-based retransmission.
pub struct PendingAcks {
    pending: HashMap<NodeId, PendingAck>,
    timeout: Duration,
}

impl PendingAcks {
    pub fn new(timeout: Duration) -> Self {
        Self {
            pending: HashMap::new(),
            timeout,
        }
    }

    /// Register a message as expecting an ACK from `target_id`.
    ///
    /// If there is already a pending entry for this target, it is replaced.
    pub fn track(
        &mut self,
        target_id: NodeId,
        message: Message,
        target_addr: SocketAddr,
        max_retries: u8,
    ) {
        self.pending.insert(
            target_id,
            PendingAck {
                message,
                target_addr,
                deadline: Instant::now() + self.timeout,
                retries_left: max_retries,
            },
        );
    }

    /// Record that we received a message from `node_id`, clearing any pending
    /// ACK expectation.  Returns `true` if there was a pending entry.
    pub fn ack(&mut self, node_id: NodeId) -> bool {
        self.pending.remove(&node_id).is_some()
    }

    /// Collect messages whose deadline has passed and that still have retries
    /// remaining.  Returns a `RetryResult` containing the messages to
    /// retransmit and the number of entries that exhausted all retries.
    pub fn collect_retries(&mut self, now: Instant) -> RetryResult {
        let mut retransmits = Vec::new();
        let mut exhausted_ids = Vec::new();

        for (&target_id, entry) in self.pending.iter_mut() {
            if now >= entry.deadline {
                if entry.retries_left > 0 {
                    entry.retries_left -= 1;
                    entry.deadline = now + self.timeout;
                    retransmits.push((target_id, entry.message.clone(), entry.target_addr));
                } else {
                    exhausted_ids.push(target_id);
                }
            }
        }

        let exhausted = exhausted_ids.len();
        for id in exhausted_ids {
            log::warn!(
                "[reliable] exhausted retries for target {id} — giving up"
            );
            self.pending.remove(&id);
        }

        RetryResult { retransmits, exhausted }
    }

    /// Number of pending entries (for testing / metrics).
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Returns `true` if there are no pending entries.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{build_leave, flags};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn leave_msg() -> Message {
        let mut m = build_leave(1, 0, 0);
        m.flags |= flags::REQUEST_ACK;
        m
    }

    #[test]
    fn track_and_ack_clears_entry() {
        let mut pa = PendingAcks::new(Duration::from_millis(100));
        pa.track(42, leave_msg(), addr(9000), 3);
        assert_eq!(pa.len(), 1);
        assert!(pa.ack(42));
        assert!(pa.is_empty());
    }

    #[test]
    fn ack_unknown_returns_false() {
        let mut pa = PendingAcks::new(Duration::from_millis(100));
        assert!(!pa.ack(99));
    }

    #[test]
    fn collect_retries_before_deadline_returns_empty() {
        let mut pa = PendingAcks::new(Duration::from_millis(500));
        pa.track(42, leave_msg(), addr(9000), 3);
        let result = pa.collect_retries(Instant::now());
        assert!(result.retransmits.is_empty());
        assert_eq!(result.exhausted, 0);
        assert_eq!(pa.len(), 1); // still pending
    }

    #[test]
    fn collect_retries_after_deadline_returns_entry() {
        let mut pa = PendingAcks::new(Duration::from_millis(10));
        pa.track(42, leave_msg(), addr(9000), 3);

        // Simulate time passing beyond deadline.
        let later = Instant::now() + Duration::from_millis(20);
        let result = pa.collect_retries(later);
        assert_eq!(result.retransmits.len(), 1);
        assert_eq!(result.retransmits[0].0, 42);
        assert_eq!(result.exhausted, 0);
        // Entry still pending with decremented retries.
        assert_eq!(pa.len(), 1);
    }

    #[test]
    fn exhausted_retries_removes_entry() {
        let mut pa = PendingAcks::new(Duration::from_millis(10));
        pa.track(42, leave_msg(), addr(9000), 1);

        // First timeout: retries_left goes 1→0, retransmit returned.
        let t1 = Instant::now() + Duration::from_millis(20);
        let r1 = pa.collect_retries(t1);
        assert_eq!(r1.retransmits.len(), 1);
        assert_eq!(r1.exhausted, 0);
        assert_eq!(pa.len(), 1);

        // Second timeout: retries_left == 0, entry removed.
        let t2 = t1 + Duration::from_millis(20);
        let r2 = pa.collect_retries(t2);
        assert!(r2.retransmits.is_empty());
        assert_eq!(r2.exhausted, 1);
        assert!(pa.is_empty());
    }

    #[test]
    fn track_replaces_existing_entry() {
        let mut pa = PendingAcks::new(Duration::from_millis(100));
        pa.track(42, leave_msg(), addr(9000), 1);
        // Replace with higher retries.
        pa.track(42, leave_msg(), addr(9001), 5);
        assert_eq!(pa.len(), 1);
        // Ack should clear the replacement.
        assert!(pa.ack(42));
        assert!(pa.is_empty());
    }

    #[test]
    fn multiple_targets_independent() {
        let mut pa = PendingAcks::new(Duration::from_millis(10));
        pa.track(1, leave_msg(), addr(9001), 2);
        pa.track(2, leave_msg(), addr(9002), 2);
        assert_eq!(pa.len(), 2);

        // Ack only target 1.
        pa.ack(1);
        assert_eq!(pa.len(), 1);

        // Target 2 times out.
        let later = Instant::now() + Duration::from_millis(20);
        let result = pa.collect_retries(later);
        assert_eq!(result.retransmits.len(), 1);
        assert_eq!(result.retransmits[0].0, 2);
    }
}
