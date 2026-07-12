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

    // ── Anti-entropy ──────────────────────────────────────────────────────
    /// Full-sync anti-entropy messages sent.
    pub anti_entropy_sent: u64,

    // ── Rate limiting ─────────────────────────────────────────────────────
    /// Inbound packets dropped by the rate limiter.
    pub rate_limited: u64,

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

    /// Format as Prometheus text exposition format.
    ///
    /// Each counter is emitted as a `# TYPE` + value line.  Gauges for
    /// cluster membership status counts are included when provided.
    pub fn prometheus(&self, alive: usize, suspect: usize, dead: usize) -> String {
        let mut out = String::with_capacity(2048);
        // Helper macro to reduce repetition.
        macro_rules! counter {
            ($name:expr, $help:expr, $val:expr) => {
                out.push_str(concat!("# HELP ", $name, " ", $help, "\n"));
                out.push_str(concat!("# TYPE ", $name, " counter\n"));
                out.push_str(&format!(concat!($name, " {}\n"), $val));
            };
        }
        macro_rules! gauge {
            ($name:expr, $help:expr, $val:expr) => {
                out.push_str(concat!("# HELP ", $name, " ", $help, "\n"));
                out.push_str(concat!("# TYPE ", $name, " gauge\n"));
                out.push_str(&format!(concat!($name, " {}\n"), $val));
            };
        }

        counter!("swim_gossip_rounds_total", "Gossip rounds initiated.", self.gossip_rounds);
        counter!("swim_gossip_sent_total", "Gossip messages sent.", self.gossip_sent);
        counter!("swim_gossip_recv_total", "Gossip messages received.", self.gossip_recv);
        counter!("swim_pings_sent_total", "PING messages sent.", self.pings_sent);
        counter!("swim_pings_recv_total", "PING messages received.", self.pings_recv);
        counter!("swim_acks_sent_total", "ACK messages sent.", self.acks_sent);
        counter!("swim_acks_recv_total", "ACK messages received.", self.acks_recv);
        counter!("swim_ping_reqs_sent_total", "PING_REQ messages sent.", self.ping_reqs_sent);
        counter!("swim_ping_reqs_recv_total", "PING_REQ messages received.", self.ping_reqs_recv);
        counter!("swim_probe_direct_timeouts_total", "Direct probes that timed out.", self.probe_direct_timeouts);
        counter!("swim_probe_failures_total", "Probes that resulted in Suspect.", self.probe_failures);
        counter!("swim_merges_new_total", "New nodes discovered via merge.", self.merges_new);
        counter!("swim_merges_updated_total", "Existing entries updated.", self.merges_updated);
        counter!("swim_merges_stale_total", "Stale entries rejected.", self.merges_stale);
        counter!("swim_anti_entropy_sent_total", "Anti-entropy full syncs sent.", self.anti_entropy_sent);
        counter!("swim_rate_limited_total", "Inbound packets dropped by rate limiter.", self.rate_limited);
        counter!("swim_reliable_retries_total", "REQUEST_ACK retransmissions.", self.reliable_retries);
        counter!("swim_reliable_exhausted_total", "REQUEST_ACK retries exhausted.", self.reliable_exhausted);

        gauge!("swim_members_alive", "Number of Alive members.", alive);
        gauge!("swim_members_suspect", "Number of Suspect members.", suspect);
        gauge!("swim_members_dead", "Number of Dead members.", dead);

        out
    }

    /// Format as a JSON object for log-based dashboards.
    pub fn json(&self, alive: usize, suspect: usize, dead: usize) -> String {
        format!(
            r#"{{"gossip_rounds":{},"gossip_sent":{},"gossip_recv":{},"pings_sent":{},"pings_recv":{},"acks_sent":{},"acks_recv":{},"ping_reqs_sent":{},"ping_reqs_recv":{},"probe_direct_timeouts":{},"probe_failures":{},"merges_new":{},"merges_updated":{},"merges_stale":{},"anti_entropy_sent":{},"rate_limited":{},"reliable_retries":{},"reliable_exhausted":{},"alive":{},"suspect":{},"dead":{}}}"#,
            self.gossip_rounds, self.gossip_sent, self.gossip_recv,
            self.pings_sent, self.pings_recv,
            self.acks_sent, self.acks_recv,
            self.ping_reqs_sent, self.ping_reqs_recv,
            self.probe_direct_timeouts, self.probe_failures,
            self.merges_new, self.merges_updated, self.merges_stale,
            self.anti_entropy_sent,
            self.rate_limited,
            self.reliable_retries, self.reliable_exhausted,
            alive, suspect, dead,
        )
    }

    /// Format a one-line summary suitable for `log::info!`.
    pub fn summary(&self, alive: usize, suspect: usize, dead: usize) -> String {
        format!(
            "gossip_rounds={} gossip_sent={} gossip_recv={} \
             pings_sent={} pings_recv={} acks_sent={} acks_recv={} \
             ping_reqs_sent={} ping_reqs_recv={} \
             probe_direct_timeouts={} probe_failures={} \
             merges_new={} merges_updated={} merges_stale={} \
             anti_entropy_sent={} rate_limited={} \
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
            self.anti_entropy_sent,
            self.rate_limited,
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
    fn prometheus_format_contains_all_metrics() {
        let m = Metrics {
            gossip_rounds: 10,
            gossip_sent: 12,
            probe_failures: 1,
            merges_new: 3,
            anti_entropy_sent: 2,
            ..Default::default()
        };
        let p = m.prometheus(5, 1, 2);
        // Counters.
        assert!(p.contains("# TYPE swim_gossip_rounds_total counter"));
        assert!(p.contains("swim_gossip_rounds_total 10"));
        assert!(p.contains("swim_gossip_sent_total 12"));
        assert!(p.contains("swim_probe_failures_total 1"));
        assert!(p.contains("swim_merges_new_total 3"));
        assert!(p.contains("swim_anti_entropy_sent_total 2"));
        // Gauges.
        assert!(p.contains("# TYPE swim_members_alive gauge"));
        assert!(p.contains("swim_members_alive 5"));
        assert!(p.contains("swim_members_suspect 1"));
        assert!(p.contains("swim_members_dead 2"));
    }

    #[test]
    fn prometheus_format_valid_exposition() {
        let m = Metrics::default();
        let p = m.prometheus(0, 0, 0);
        // Every non-empty, non-comment line should match "metric_name value".
        for line in p.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(parts.len(), 2, "invalid exposition line: {line}");
            assert!(parts[0].starts_with("swim_"), "metric should have swim_ prefix: {line}");
            assert!(parts[1].parse::<u64>().is_ok(), "value should be numeric: {line}");
        }
    }

    #[test]
    fn json_format_valid() {
        let m = Metrics {
            gossip_rounds: 5,
            pings_sent: 3,
            ..Default::default()
        };
        let j = m.json(2, 0, 1);
        assert!(j.starts_with('{'));
        assert!(j.ends_with('}'));
        assert!(j.contains(r#""gossip_rounds":5"#));
        assert!(j.contains(r#""pings_sent":3"#));
        assert!(j.contains(r#""alive":2"#));
        assert!(j.contains(r#""dead":1"#));
    }

    #[test]
    fn json_format_all_zeros() {
        let m = Metrics::default();
        let j = m.json(0, 0, 0);
        assert!(j.contains(r#""gossip_rounds":0"#));
        assert!(j.contains(r#""alive":0"#));
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
