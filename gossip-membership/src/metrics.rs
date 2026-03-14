/// Protocol metrics — lightweight counters for gossip health observability.
///
/// All fields are simple `u64` counters that the event loop increments
/// as messages flow through the system.  The struct is intentionally
/// not `Arc`-wrapped: each node owns its own copy and the periodic log
/// emitter reads it directly.

/// Outcome of a single `merge_entry` call, used by the event loop to
/// update the appropriate metrics counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Brand-new node added to the table.
    New,
    /// Existing entry was updated (newer incarnation, heartbeat, or status).
    Updated,
    /// Incoming entry was stale or equivalent — discarded.
    Stale,
    /// Entry was about ourselves (ignored or refuted).
    SelfEntry,
}

#[derive(Debug, Clone, Default)]
pub struct Metrics {
    // ── Gossip ───────────────────────────────────────────────────────────────
    /// Number of gossip rounds initiated (one per gossip tick).
    pub gossip_rounds: u64,
    /// Total gossip messages sent (≥ rounds when multi-target).
    pub gossip_sent: u64,
    /// Gossip messages received.
    pub gossip_recv: u64,

    // ── Probes ───────────────────────────────────────────────────────────────
    /// PING messages sent.
    pub pings_sent: u64,
    /// PING messages received.
    pub pings_recv: u64,
    /// ACK messages sent.
    pub acks_sent: u64,
    /// ACK messages received.
    pub acks_recv: u64,
    /// PING_REQ messages sent.
    pub ping_reqs_sent: u64,
    /// PING_REQ messages received (and forwarded).
    pub ping_reqs_recv: u64,
    /// Direct probes that timed out and were escalated to indirect.
    pub probe_direct_timeouts: u64,
    /// Indirect probes that timed out — node declared Suspect.
    pub probe_failures: u64,

    // ── Merges ───────────────────────────────────────────────────────────────
    /// New nodes discovered via merge.
    pub merges_new: u64,
    /// Existing entries updated (incoming was newer).
    pub merges_updated: u64,
    /// Incoming entries rejected as stale (merge conflicts).
    pub merges_stale: u64,

    // ── Reliable delivery ───────────────────────────────────────────────────
    /// REQUEST_ACK messages retransmitted after timeout.
    pub reliable_retries: u64,
    /// REQUEST_ACK messages that exhausted all retries without receiving an ACK.
    pub reliable_exhausted: u64,
}

impl Metrics {
    /// Record the outcome of a `merge_entry` call.
    pub fn record_merge(&mut self, outcome: MergeOutcome) {
        match outcome {
            MergeOutcome::New => self.merges_new += 1,
            MergeOutcome::Updated => self.merges_updated += 1,
            MergeOutcome::Stale => self.merges_stale += 1,
            MergeOutcome::SelfEntry => {} // not counted — noise
        }
    }

    /// Format a one-line summary suitable for `log::info!`.
    pub fn summary(&self, alive: usize, suspect: usize, dead: usize) -> String {
        format!(
            "gossip_rounds={} gossip_sent={} gossip_recv={} \
             pings_sent={} pings_recv={} acks_sent={} acks_recv={} \
             ping_reqs_sent={} ping_reqs_recv={} \
             probe_direct_timeouts={} probe_failures={} \
             merges_new={} merges_updated={} merges_stale={} \
             reliable_retries={} reliable_exhausted={} \
             alive={} suspect={} dead={}",
            self.gossip_rounds,
            self.gossip_sent,
            self.gossip_recv,
            self.pings_sent,
            self.pings_recv,
            self.acks_sent,
            self.acks_recv,
            self.ping_reqs_sent,
            self.ping_reqs_recv,
            self.probe_direct_timeouts,
            self.probe_failures,
            self.merges_new,
            self.merges_updated,
            self.merges_stale,
            self.reliable_retries,
            self.reliable_exhausted,
            alive,
            suspect,
            dead,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_merge_new() {
        let mut m = Metrics::default();
        m.record_merge(MergeOutcome::New);
        assert_eq!(m.merges_new, 1);
        assert_eq!(m.merges_updated, 0);
        assert_eq!(m.merges_stale, 0);
    }

    #[test]
    fn record_merge_updated() {
        let mut m = Metrics::default();
        m.record_merge(MergeOutcome::Updated);
        assert_eq!(m.merges_updated, 1);
    }

    #[test]
    fn record_merge_stale() {
        let mut m = Metrics::default();
        m.record_merge(MergeOutcome::Stale);
        assert_eq!(m.merges_stale, 1);
    }

    #[test]
    fn record_merge_self_not_counted() {
        let mut m = Metrics::default();
        m.record_merge(MergeOutcome::SelfEntry);
        assert_eq!(m.merges_new, 0);
        assert_eq!(m.merges_updated, 0);
        assert_eq!(m.merges_stale, 0);
    }

    #[test]
    fn summary_format() {
        let m = Metrics {
            gossip_rounds: 10,
            gossip_sent: 12,
            gossip_recv: 8,
            probe_failures: 1,
            merges_new: 3,
            merges_stale: 2,
            ..Default::default()
        };
        let s = m.summary(4, 1, 0);
        assert!(s.contains("gossip_rounds=10"));
        assert!(s.contains("probe_failures=1"));
        assert!(s.contains("merges_stale=2"));
        assert!(s.contains("alive=4"));
        assert!(s.contains("suspect=1"));
        assert!(s.contains("dead=0"));
    }

    #[test]
    fn default_is_all_zeros() {
        let m = Metrics::default();
        assert_eq!(m.gossip_rounds, 0);
        assert_eq!(m.gossip_sent, 0);
        assert_eq!(m.probe_failures, 0);
        assert_eq!(m.merges_new, 0);
    }
}
