//! Prometheus-compatible metrics for a single Raft node.
//!
//! `RaftMetrics` is a lock-free, thread-safe snapshot of a node's operating
//! state.  Scalar fields use `AtomicU64` so the HTTP server thread can read
//! them without coordinating with the Raft thread.  Per-peer gauges
//! (`peer_match_index`, `peer_next_index`) are stored behind a `Mutex` because
//! the peer set is dynamic; scrape-time reads are rare so contention is not a
//! concern.
//!
//! ## Counters (monotonically increasing)
//! - `elections_total`              — elections this node has initiated
//! - `vote_requests_total`          — `RequestVote` RPCs sent
//! - `append_entries_total`         — `AppendEntries` RPCs sent
//! - `snapshots_sent_total`         — `InstallSnapshot` RPCs sent
//! - `snapshots_received_total`     — snapshots installed as follower
//! - `proposals_total`              — entries proposed by the application
//! - `proposals_committed_total`    — entries committed to the log
//! - `term_changes_total`           — term increments observed
//! - `transport_bytes_sent_total`   — TCP bytes written to peers
//! - `transport_bytes_received_total` — TCP bytes read from peers
//! - `transport_reconnects_total`   — outgoing TCP reconnect attempts
//! - `wal_bytes_written_total`      — bytes appended to the WAL
//!
//! ## Gauges (can go up or down)
//! - `current_term`          — Raft term number
//! - `commit_index`          — highest committed log index
//! - `last_applied`          — highest applied log index
//! - `leader_id`             — node ID of the current leader; `0` = unknown
//! - `is_leader`             — `1` while this node is the leader, else `0`
//! - `snapshot_last_index`   — log index of the most recently installed snapshot
//! - `wal_segment_count`     — number of WAL segment files on disk
//! - `wal_active_segment_bytes` — bytes written to the current active segment
//!
//! ## Per-peer gauges (rendered with `{peer="<id>"}` labels)
//! - `peer_match_index` — highest log index confirmed replicated to each peer
//! - `peer_next_index`  — next log index to send to each peer
//!
//! ## Usage
//!
//! ```rust
//! use std::sync::Arc;
//! use raft_consensus::metrics::RaftMetrics;
//!
//! let m = Arc::new(RaftMetrics::new());
//! m.inc_elections();
//! m.set_current_term(3);
//! assert_eq!(m.elections_total(), 1);
//! assert_eq!(m.current_term(), 3);
//! println!("{}", m.render_prometheus());
//! ```

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

// ════════════════════════════════════════════════════════════════════════════
//  RaftMetrics
// ════════════════════════════════════════════════════════════════════════════

/// Thread-safe metric store for a single Raft node.
pub struct RaftMetrics {
    // ── Counters ─────────────────────────────────────────────────────────────
    elections_total: AtomicU64,
    vote_requests_total: AtomicU64,
    append_entries_total: AtomicU64,
    snapshots_sent_total: AtomicU64,
    snapshots_received_total: AtomicU64,
    proposals_total: AtomicU64,
    proposals_committed_total: AtomicU64,
    term_changes_total: AtomicU64,
    transport_bytes_sent_total: AtomicU64,
    transport_bytes_received_total: AtomicU64,
    transport_reconnects_total: AtomicU64,
    wal_bytes_written_total: AtomicU64,

    // ── Gauges ───────────────────────────────────────────────────────────────
    current_term: AtomicU64,
    commit_index: AtomicU64,
    last_applied: AtomicU64,
    /// Node ID of the current known leader.  `0` means "no leader known".
    leader_id: AtomicU64,
    /// 1 while this node is the leader, 0 otherwise.
    is_leader: AtomicU64,
    snapshot_last_index: AtomicU64,
    wal_segment_count: AtomicU64,
    wal_active_segment_bytes: AtomicU64,

    // ── Per-peer gauges (keyed by peer NodeId) ────────────────────────────
    peer_match_index: Mutex<HashMap<u64, u64>>,
    peer_next_index: Mutex<HashMap<u64, u64>>,
}

impl RaftMetrics {
    /// Create a zeroed metrics store.
    pub fn new() -> Self {
        Self {
            elections_total: AtomicU64::new(0),
            vote_requests_total: AtomicU64::new(0),
            append_entries_total: AtomicU64::new(0),
            snapshots_sent_total: AtomicU64::new(0),
            snapshots_received_total: AtomicU64::new(0),
            proposals_total: AtomicU64::new(0),
            proposals_committed_total: AtomicU64::new(0),
            term_changes_total: AtomicU64::new(0),
            transport_bytes_sent_total: AtomicU64::new(0),
            transport_bytes_received_total: AtomicU64::new(0),
            transport_reconnects_total: AtomicU64::new(0),
            wal_bytes_written_total: AtomicU64::new(0),
            current_term: AtomicU64::new(0),
            commit_index: AtomicU64::new(0),
            last_applied: AtomicU64::new(0),
            leader_id: AtomicU64::new(0),
            is_leader: AtomicU64::new(0),
            snapshot_last_index: AtomicU64::new(0),
            wal_segment_count: AtomicU64::new(0),
            wal_active_segment_bytes: AtomicU64::new(0),
            peer_match_index: Mutex::new(HashMap::new()),
            peer_next_index: Mutex::new(HashMap::new()),
        }
    }

    // ── Counter incrementers ──────────────────────────────────────────────

    pub fn inc_elections(&self) {
        self.elections_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_vote_requests(&self) {
        self.vote_requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_append_entries(&self) {
        self.append_entries_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_snapshots_sent(&self) {
        self.snapshots_sent_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_snapshots_received(&self) {
        self.snapshots_received_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_proposals(&self) {
        self.proposals_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment committed-entry counter by `n` (one call per commit boundary).
    pub fn add_proposals_committed(&self, n: u64) {
        self.proposals_committed_total.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_term_changes(&self) {
        self.term_changes_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_transport_bytes_sent(&self, n: u64) {
        self.transport_bytes_sent_total.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_transport_bytes_received(&self, n: u64) {
        self.transport_bytes_received_total.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_transport_reconnects(&self) {
        self.transport_reconnects_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_wal_bytes_written(&self, n: u64) {
        self.wal_bytes_written_total.fetch_add(n, Ordering::Relaxed);
    }

    // ── Gauge setters ─────────────────────────────────────────────────────

    pub fn set_current_term(&self, v: u64) {
        self.current_term.store(v, Ordering::Relaxed);
    }

    pub fn set_commit_index(&self, v: u64) {
        self.commit_index.store(v, Ordering::Relaxed);
    }

    pub fn set_last_applied(&self, v: u64) {
        self.last_applied.store(v, Ordering::Relaxed);
    }

    /// Set the known leader ID.  Pass `0` when the leader is unknown.
    pub fn set_leader_id(&self, v: u64) {
        self.leader_id.store(v, Ordering::Relaxed);
    }

    /// Set to `1` when this node becomes leader, `0` otherwise.
    pub fn set_is_leader(&self, v: u64) {
        self.is_leader.store(v, Ordering::Relaxed);
    }

    pub fn set_snapshot_last_index(&self, v: u64) {
        self.snapshot_last_index.store(v, Ordering::Relaxed);
    }

    pub fn set_wal_segment_count(&self, v: u64) {
        self.wal_segment_count.store(v, Ordering::Relaxed);
    }

    pub fn set_wal_active_segment_bytes(&self, v: u64) {
        self.wal_active_segment_bytes.store(v, Ordering::Relaxed);
    }

    // ── Per-peer gauge setters ────────────────────────────────────────────

    /// Update the highest log index confirmed replicated to `peer`.
    pub fn update_peer_match_index(&self, peer: u64, v: u64) {
        if let Ok(mut map) = self.peer_match_index.lock() {
            map.insert(peer, v);
        }
    }

    /// Update the next log index to send to `peer`.
    pub fn update_peer_next_index(&self, peer: u64, v: u64) {
        if let Ok(mut map) = self.peer_next_index.lock() {
            map.insert(peer, v);
        }
    }

    // ── Scalar readers (used by the HTTP server thread) ───────────────────

    pub fn elections_total(&self) -> u64 {
        self.elections_total.load(Ordering::Relaxed)
    }

    pub fn vote_requests_total(&self) -> u64 {
        self.vote_requests_total.load(Ordering::Relaxed)
    }

    pub fn append_entries_total(&self) -> u64 {
        self.append_entries_total.load(Ordering::Relaxed)
    }

    pub fn snapshots_sent_total(&self) -> u64 {
        self.snapshots_sent_total.load(Ordering::Relaxed)
    }

    pub fn snapshots_received_total(&self) -> u64 {
        self.snapshots_received_total.load(Ordering::Relaxed)
    }

    pub fn proposals_total(&self) -> u64 {
        self.proposals_total.load(Ordering::Relaxed)
    }

    pub fn proposals_committed_total(&self) -> u64 {
        self.proposals_committed_total.load(Ordering::Relaxed)
    }

    pub fn term_changes_total(&self) -> u64 {
        self.term_changes_total.load(Ordering::Relaxed)
    }

    pub fn transport_bytes_sent_total(&self) -> u64 {
        self.transport_bytes_sent_total.load(Ordering::Relaxed)
    }

    pub fn transport_bytes_received_total(&self) -> u64 {
        self.transport_bytes_received_total.load(Ordering::Relaxed)
    }

    pub fn transport_reconnects_total(&self) -> u64 {
        self.transport_reconnects_total.load(Ordering::Relaxed)
    }

    pub fn wal_bytes_written_total(&self) -> u64 {
        self.wal_bytes_written_total.load(Ordering::Relaxed)
    }

    pub fn current_term(&self) -> u64 {
        self.current_term.load(Ordering::Relaxed)
    }

    pub fn commit_index(&self) -> u64 {
        self.commit_index.load(Ordering::Relaxed)
    }

    pub fn last_applied(&self) -> u64 {
        self.last_applied.load(Ordering::Relaxed)
    }

    pub fn leader_id(&self) -> u64 {
        self.leader_id.load(Ordering::Relaxed)
    }

    pub fn is_leader(&self) -> u64 {
        self.is_leader.load(Ordering::Relaxed)
    }

    pub fn snapshot_last_index(&self) -> u64 {
        self.snapshot_last_index.load(Ordering::Relaxed)
    }

    pub fn wal_segment_count(&self) -> u64 {
        self.wal_segment_count.load(Ordering::Relaxed)
    }

    pub fn wal_active_segment_bytes(&self) -> u64 {
        self.wal_active_segment_bytes.load(Ordering::Relaxed)
    }

    // ── Renderers ─────────────────────────────────────────────────────────

    /// Render all metrics in Prometheus text exposition format (version 0.0.4).
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);

        // ── Counters ──
        counter(&mut out, "raft_elections_total",
            "Total elections initiated by this node.",
            self.elections_total());
        counter(&mut out, "raft_vote_requests_total",
            "Total RequestVote RPCs sent.",
            self.vote_requests_total());
        counter(&mut out, "raft_append_entries_total",
            "Total AppendEntries RPCs sent.",
            self.append_entries_total());
        counter(&mut out, "raft_snapshots_sent_total",
            "Total InstallSnapshot RPCs sent as leader.",
            self.snapshots_sent_total());
        counter(&mut out, "raft_snapshots_received_total",
            "Total snapshots installed as follower.",
            self.snapshots_received_total());
        counter(&mut out, "raft_proposals_total",
            "Total log entries proposed by the application.",
            self.proposals_total());
        counter(&mut out, "raft_proposals_committed_total",
            "Total log entries committed.",
            self.proposals_committed_total());
        counter(&mut out, "raft_term_changes_total",
            "Total Raft term increments observed.",
            self.term_changes_total());
        counter(&mut out, "raft_transport_bytes_sent_total",
            "Total TCP bytes sent to peers.",
            self.transport_bytes_sent_total());
        counter(&mut out, "raft_transport_bytes_received_total",
            "Total TCP bytes received from peers.",
            self.transport_bytes_received_total());
        counter(&mut out, "raft_transport_reconnects_total",
            "Total outgoing TCP reconnect attempts.",
            self.transport_reconnects_total());
        counter(&mut out, "raft_wal_bytes_written_total",
            "Total bytes appended to the WAL across all segments.",
            self.wal_bytes_written_total());

        // ── Gauges ──
        gauge(&mut out, "raft_current_term",
            "Current Raft term number.",
            self.current_term());
        gauge(&mut out, "raft_commit_index",
            "Highest log index known to be committed.",
            self.commit_index());
        gauge(&mut out, "raft_last_applied",
            "Highest log index applied to the state machine.",
            self.last_applied());
        gauge(&mut out, "raft_leader_id",
            "Node ID of the current known leader (0 = unknown).",
            self.leader_id());
        gauge(&mut out, "raft_is_leader",
            "1 while this node is the Raft leader, 0 otherwise.",
            self.is_leader());
        gauge(&mut out, "raft_snapshot_last_index",
            "Log index of the most recently installed snapshot.",
            self.snapshot_last_index());
        gauge(&mut out, "raft_wal_segment_count",
            "Number of WAL segment files on disk.",
            self.wal_segment_count());
        gauge(&mut out, "raft_wal_active_segment_bytes",
            "Bytes written to the current active WAL segment.",
            self.wal_active_segment_bytes());

        // ── Per-peer gauges ──
        if let Ok(map) = self.peer_match_index.lock() {
            if !map.is_empty() {
                out.push_str("# HELP raft_peer_match_index Highest log index confirmed replicated to each peer.\n");
                out.push_str("# TYPE raft_peer_match_index gauge\n");
                let mut peers: Vec<u64> = map.keys().copied().collect();
                peers.sort_unstable();
                for peer in peers {
                    if let Some(&v) = map.get(&peer) {
                        out.push_str(&format!("raft_peer_match_index{{peer=\"{peer}\"}} {v}\n"));
                    }
                }
            }
        }

        if let Ok(map) = self.peer_next_index.lock() {
            if !map.is_empty() {
                out.push_str("# HELP raft_peer_next_index Next log index to send to each peer.\n");
                out.push_str("# TYPE raft_peer_next_index gauge\n");
                let mut peers: Vec<u64> = map.keys().copied().collect();
                peers.sort_unstable();
                for peer in peers {
                    if let Some(&v) = map.get(&peer) {
                        out.push_str(&format!("raft_peer_next_index{{peer=\"{peer}\"}} {v}\n"));
                    }
                }
            }
        }

        out
    }

    /// Render all metrics as a JSON object.
    pub fn render_json(&self) -> String {
        format!(
            "{{\
\"current_term\":{ct},\
\"commit_index\":{ci},\
\"last_applied\":{la},\
\"leader_id\":{lid},\
\"is_leader\":{il},\
\"elections_total\":{el},\
\"vote_requests_total\":{vr},\
\"append_entries_total\":{ae},\
\"snapshots_sent_total\":{ss},\
\"snapshots_received_total\":{sr},\
\"proposals_total\":{pt},\
\"proposals_committed_total\":{pc},\
\"term_changes_total\":{tc},\
\"transport_bytes_sent_total\":{tbs},\
\"transport_bytes_received_total\":{tbr},\
\"transport_reconnects_total\":{tre},\
\"wal_bytes_written_total\":{wbw},\
\"snapshot_last_index\":{sli},\
\"wal_segment_count\":{wsc},\
\"wal_active_segment_bytes\":{wasb}\
}}",
            ct   = self.current_term(),
            ci   = self.commit_index(),
            la   = self.last_applied(),
            lid  = self.leader_id(),
            il   = self.is_leader(),
            el   = self.elections_total(),
            vr   = self.vote_requests_total(),
            ae   = self.append_entries_total(),
            ss   = self.snapshots_sent_total(),
            sr   = self.snapshots_received_total(),
            pt   = self.proposals_total(),
            pc   = self.proposals_committed_total(),
            tc   = self.term_changes_total(),
            tbs  = self.transport_bytes_sent_total(),
            tbr  = self.transport_bytes_received_total(),
            tre  = self.transport_reconnects_total(),
            wbw  = self.wal_bytes_written_total(),
            sli  = self.snapshot_last_index(),
            wsc  = self.wal_segment_count(),
            wasb = self.wal_active_segment_bytes(),
        )
    }
}

impl Default for RaftMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ── Prometheus text format helpers ───────────────────────────────────────────

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    metric_line(out, name, "counter", help, value);
}

fn gauge(out: &mut String, name: &str, help: &str, value: u64) {
    metric_line(out, name, "gauge", help, value);
}

fn metric_line(out: &mut String, name: &str, typ: &str, help: &str, value: u64) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(typ);
    out.push('\n');
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

// ════════════════════════════════════════════════════════════════════════════
//  Tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_start_at_zero() {
        let m = RaftMetrics::new();
        assert_eq!(m.elections_total(), 0);
        assert_eq!(m.vote_requests_total(), 0);
        assert_eq!(m.append_entries_total(), 0);
        assert_eq!(m.snapshots_sent_total(), 0);
        assert_eq!(m.snapshots_received_total(), 0);
        assert_eq!(m.proposals_total(), 0);
        assert_eq!(m.proposals_committed_total(), 0);
        assert_eq!(m.term_changes_total(), 0);
        assert_eq!(m.transport_bytes_sent_total(), 0);
        assert_eq!(m.transport_bytes_received_total(), 0);
        assert_eq!(m.transport_reconnects_total(), 0);
        assert_eq!(m.wal_bytes_written_total(), 0);
    }

    #[test]
    fn gauges_start_at_zero() {
        let m = RaftMetrics::new();
        assert_eq!(m.current_term(), 0);
        assert_eq!(m.commit_index(), 0);
        assert_eq!(m.last_applied(), 0);
        assert_eq!(m.leader_id(), 0);
        assert_eq!(m.is_leader(), 0);
        assert_eq!(m.snapshot_last_index(), 0);
        assert_eq!(m.wal_segment_count(), 0);
        assert_eq!(m.wal_active_segment_bytes(), 0);
    }

    #[test]
    fn counters_increment() {
        let m = RaftMetrics::new();
        m.inc_elections();
        m.inc_elections();
        m.inc_vote_requests();
        m.inc_append_entries();
        m.inc_append_entries();
        m.inc_append_entries();
        m.inc_snapshots_sent();
        m.inc_snapshots_received();
        m.inc_proposals();
        m.inc_proposals();
        m.add_proposals_committed(5);
        m.inc_term_changes();
        m.add_transport_bytes_sent(1024);
        m.add_transport_bytes_received(512);
        m.inc_transport_reconnects();
        m.add_wal_bytes_written(4096);
        assert_eq!(m.elections_total(), 2);
        assert_eq!(m.vote_requests_total(), 1);
        assert_eq!(m.append_entries_total(), 3);
        assert_eq!(m.snapshots_sent_total(), 1);
        assert_eq!(m.snapshots_received_total(), 1);
        assert_eq!(m.proposals_total(), 2);
        assert_eq!(m.proposals_committed_total(), 5);
        assert_eq!(m.term_changes_total(), 1);
        assert_eq!(m.transport_bytes_sent_total(), 1024);
        assert_eq!(m.transport_bytes_received_total(), 512);
        assert_eq!(m.transport_reconnects_total(), 1);
        assert_eq!(m.wal_bytes_written_total(), 4096);
    }

    #[test]
    fn gauges_update() {
        let m = RaftMetrics::new();
        m.set_current_term(7);
        m.set_commit_index(42);
        m.set_last_applied(42);
        m.set_leader_id(3);
        m.set_is_leader(1);
        m.set_snapshot_last_index(10);
        m.set_wal_segment_count(3);
        m.set_wal_active_segment_bytes(1024);
        assert_eq!(m.current_term(), 7);
        assert_eq!(m.commit_index(), 42);
        assert_eq!(m.last_applied(), 42);
        assert_eq!(m.leader_id(), 3);
        assert_eq!(m.is_leader(), 1);
        assert_eq!(m.snapshot_last_index(), 10);
        assert_eq!(m.wal_segment_count(), 3);
        assert_eq!(m.wal_active_segment_bytes(), 1024);
    }

    #[test]
    fn leader_id_zero_means_unknown() {
        let m = RaftMetrics::new();
        m.set_leader_id(5);
        assert_eq!(m.leader_id(), 5);
        m.set_leader_id(0);
        assert_eq!(m.leader_id(), 0);
    }

    #[test]
    fn per_peer_metrics() {
        let m = RaftMetrics::new();
        m.update_peer_match_index(2, 10);
        m.update_peer_match_index(3, 8);
        m.update_peer_next_index(2, 11);
        m.update_peer_next_index(3, 9);

        let text = m.render_prometheus();
        assert!(text.contains("raft_peer_match_index{peer=\"2\"} 10"));
        assert!(text.contains("raft_peer_match_index{peer=\"3\"} 8"));
        assert!(text.contains("raft_peer_next_index{peer=\"2\"} 11"));
        assert!(text.contains("raft_peer_next_index{peer=\"3\"} 9"));
    }

    #[test]
    fn prometheus_output_contains_all_metric_names() {
        let m = RaftMetrics::new();
        let text = m.render_prometheus();
        for name in &[
            "raft_elections_total",
            "raft_vote_requests_total",
            "raft_append_entries_total",
            "raft_snapshots_sent_total",
            "raft_snapshots_received_total",
            "raft_proposals_total",
            "raft_proposals_committed_total",
            "raft_term_changes_total",
            "raft_transport_bytes_sent_total",
            "raft_transport_bytes_received_total",
            "raft_transport_reconnects_total",
            "raft_wal_bytes_written_total",
            "raft_current_term",
            "raft_commit_index",
            "raft_last_applied",
            "raft_leader_id",
            "raft_is_leader",
            "raft_snapshot_last_index",
            "raft_wal_segment_count",
            "raft_wal_active_segment_bytes",
        ] {
            assert!(text.contains(name), "missing metric: {name}");
        }
    }

    #[test]
    fn prometheus_output_contains_type_hints() {
        let m = RaftMetrics::new();
        let text = m.render_prometheus();
        assert!(text.contains("# TYPE raft_elections_total counter"));
        assert!(text.contains("# TYPE raft_append_entries_total counter"));
        assert!(text.contains("# TYPE raft_proposals_total counter"));
        assert!(text.contains("# TYPE raft_current_term gauge"));
        assert!(text.contains("# TYPE raft_is_leader gauge"));
    }

    #[test]
    fn prometheus_output_contains_help_text() {
        let m = RaftMetrics::new();
        let text = m.render_prometheus();
        assert!(text.contains("# HELP raft_elections_total"));
        assert!(text.contains("# HELP raft_current_term"));
        assert!(text.contains("# HELP raft_is_leader"));
        assert!(text.contains("# HELP raft_proposals_total"));
    }

    #[test]
    fn prometheus_values_reflect_current_state() {
        let m = RaftMetrics::new();
        m.inc_elections();
        m.inc_elections();
        m.inc_elections();
        m.set_current_term(5);
        m.set_leader_id(2);
        m.set_is_leader(1);
        let text = m.render_prometheus();
        assert!(text.contains("raft_elections_total 3\n"));
        assert!(text.contains("raft_current_term 5\n"));
        assert!(text.contains("raft_leader_id 2\n"));
        assert!(text.contains("raft_is_leader 1\n"));
    }

    #[test]
    fn json_output_contains_all_keys() {
        let m = RaftMetrics::new();
        let json = m.render_json();
        for key in &[
            "current_term",
            "commit_index",
            "last_applied",
            "leader_id",
            "is_leader",
            "elections_total",
            "vote_requests_total",
            "append_entries_total",
            "snapshots_sent_total",
            "snapshots_received_total",
            "proposals_total",
            "proposals_committed_total",
            "term_changes_total",
            "transport_bytes_sent_total",
            "transport_bytes_received_total",
            "transport_reconnects_total",
            "wal_bytes_written_total",
            "snapshot_last_index",
            "wal_segment_count",
            "wal_active_segment_bytes",
        ] {
            assert!(json.contains(key), "missing key in JSON: {key}");
        }
    }

    #[test]
    fn json_output_is_valid_object() {
        let m = RaftMetrics::new();
        let json = m.render_json();
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
    }

    #[test]
    fn json_values_reflect_current_state() {
        let m = RaftMetrics::new();
        m.set_current_term(9);
        m.set_commit_index(15);
        m.inc_elections();
        m.set_is_leader(1);
        let json = m.render_json();
        assert!(json.contains("\"current_term\":9"));
        assert!(json.contains("\"commit_index\":15"));
        assert!(json.contains("\"elections_total\":1"));
        assert!(json.contains("\"is_leader\":1"));
    }

    #[test]
    fn default_impl() {
        let m = RaftMetrics::default();
        assert_eq!(m.elections_total(), 0);
    }
}
