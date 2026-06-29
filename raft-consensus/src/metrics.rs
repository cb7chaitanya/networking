//! Prometheus-compatible metrics for a single Raft node.
//!
//! `RaftMetrics` is a lock-free, thread-safe snapshot of a node's operating
//! state. All fields use `AtomicU64` so the HTTP server thread can read them
//! without coordinating with the Raft thread.
//!
//! ## Counters (monotonically increasing)
//! - `elections_total`       — elections this node has initiated
//! - `vote_requests_total`   — `RequestVote` RPCs sent
//! - `append_entries_total`  — `AppendEntries` RPCs sent
//! - `snapshots_sent_total`  — `InstallSnapshot` RPCs sent
//!
//! ## Gauges (can go up or down)
//! - `current_term`          — Raft term number
//! - `commit_index`          — highest committed log index
//! - `last_applied`          — highest applied log index
//! - `leader_id`             — node ID of the current leader; `0` = unknown
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

use std::sync::atomic::{AtomicU64, Ordering};

// ── RaftMetrics ──

/// Thread-safe metric store for a single Raft node.
///
/// Methods that start with `inc_` are counter incrementers.
/// Methods that start with `set_` are gauge setters.
/// Both sets take `&self` (not `&mut self`) and are safe to call from any thread.
pub struct RaftMetrics {
    // ── Counters ──
    elections_total: AtomicU64,
    vote_requests_total: AtomicU64,
    append_entries_total: AtomicU64,
    snapshots_sent_total: AtomicU64,

    // ── Gauges ──
    current_term: AtomicU64,
    commit_index: AtomicU64,
    last_applied: AtomicU64,
    /// Node ID of the current known leader.  `0` means "no leader known".
    leader_id: AtomicU64,
}

impl RaftMetrics {
    /// Create a zeroed metrics store.
    pub fn new() -> Self {
        Self {
            elections_total: AtomicU64::new(0),
            vote_requests_total: AtomicU64::new(0),
            append_entries_total: AtomicU64::new(0),
            snapshots_sent_total: AtomicU64::new(0),
            current_term: AtomicU64::new(0),
            commit_index: AtomicU64::new(0),
            last_applied: AtomicU64::new(0),
            leader_id: AtomicU64::new(0),
        }
    }

    // ── Counter incrementers ──

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

    // ── Gauge setters ──

    pub fn set_current_term(&self, v: u64) {
        self.current_term.store(v, Ordering::Relaxed);
    }

    pub fn set_commit_index(&self, v: u64) {
        self.commit_index.store(v, Ordering::Relaxed);
    }

    pub fn set_last_applied(&self, v: u64) {
        self.last_applied.store(v, Ordering::Relaxed);
    }

    /// Set the known leader ID.  Pass `0` when the leader is unknown
    /// (during elections or after a term change).
    pub fn set_leader_id(&self, v: u64) {
        self.leader_id.store(v, Ordering::Relaxed);
    }

    // ── Readers (used by the HTTP server thread) ──

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

    // ── Renderers ──

    /// Render all metrics in the Prometheus text exposition format (version 0.0.4).
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(512);
        counter(&mut out, "elections_total",
            "Total elections initiated by this node.",
            self.elections_total());
        counter(&mut out, "vote_requests_total",
            "Total RequestVote RPCs sent.",
            self.vote_requests_total());
        counter(&mut out, "append_entries_total",
            "Total AppendEntries RPCs sent.",
            self.append_entries_total());
        counter(&mut out, "snapshots_sent_total",
            "Total InstallSnapshot RPCs sent.",
            self.snapshots_sent_total());
        gauge(&mut out, "current_term",
            "Current Raft term number.",
            self.current_term());
        gauge(&mut out, "commit_index",
            "Highest log index known to be committed.",
            self.commit_index());
        gauge(&mut out, "last_applied",
            "Highest log index applied to the state machine.",
            self.last_applied());
        gauge(&mut out, "leader_id",
            "Node ID of the current known leader (0 = unknown).",
            self.leader_id());
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
\"elections_total\":{el},\
\"vote_requests_total\":{vr},\
\"append_entries_total\":{ae},\
\"snapshots_sent_total\":{ss}\
}}",
            ct  = self.current_term(),
            ci  = self.commit_index(),
            la  = self.last_applied(),
            lid = self.leader_id(),
            el  = self.elections_total(),
            vr  = self.vote_requests_total(),
            ae  = self.append_entries_total(),
            ss  = self.snapshots_sent_total(),
        )
    }
}

impl Default for RaftMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ── Prometheus text format helpers ──

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
    }

    #[test]
    fn gauges_start_at_zero() {
        let m = RaftMetrics::new();
        assert_eq!(m.current_term(), 0);
        assert_eq!(m.commit_index(), 0);
        assert_eq!(m.last_applied(), 0);
        assert_eq!(m.leader_id(), 0);
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
        assert_eq!(m.elections_total(), 2);
        assert_eq!(m.vote_requests_total(), 1);
        assert_eq!(m.append_entries_total(), 3);
        assert_eq!(m.snapshots_sent_total(), 1);
    }

    #[test]
    fn gauges_update() {
        let m = RaftMetrics::new();
        m.set_current_term(7);
        m.set_commit_index(42);
        m.set_last_applied(42);
        m.set_leader_id(3);
        assert_eq!(m.current_term(), 7);
        assert_eq!(m.commit_index(), 42);
        assert_eq!(m.last_applied(), 42);
        assert_eq!(m.leader_id(), 3);
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
    fn prometheus_output_contains_all_metric_names() {
        let m = RaftMetrics::new();
        let text = m.render_prometheus();
        for name in &[
            "elections_total",
            "vote_requests_total",
            "append_entries_total",
            "snapshots_sent_total",
            "current_term",
            "commit_index",
            "last_applied",
            "leader_id",
        ] {
            assert!(text.contains(name), "missing metric: {name}");
        }
    }

    #[test]
    fn prometheus_output_contains_type_hints() {
        let m = RaftMetrics::new();
        let text = m.render_prometheus();
        assert!(text.contains("# TYPE elections_total counter"));
        assert!(text.contains("# TYPE append_entries_total counter"));
        assert!(text.contains("# TYPE current_term gauge"));
        assert!(text.contains("# TYPE leader_id gauge"));
    }

    #[test]
    fn prometheus_output_contains_help_text() {
        let m = RaftMetrics::new();
        let text = m.render_prometheus();
        assert!(text.contains("# HELP elections_total"));
        assert!(text.contains("# HELP current_term"));
    }

    #[test]
    fn prometheus_values_reflect_current_state() {
        let m = RaftMetrics::new();
        m.inc_elections();
        m.inc_elections();
        m.inc_elections();
        m.set_current_term(5);
        m.set_leader_id(2);
        let text = m.render_prometheus();
        assert!(text.contains("elections_total 3\n"));
        assert!(text.contains("current_term 5\n"));
        assert!(text.contains("leader_id 2\n"));
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
            "elections_total",
            "vote_requests_total",
            "append_entries_total",
            "snapshots_sent_total",
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
        let json = m.render_json();
        assert!(json.contains("\"current_term\":9"));
        assert!(json.contains("\"commit_index\":15"));
        assert!(json.contains("\"elections_total\":1"));
    }

    #[test]
    fn default_impl() {
        let m = RaftMetrics::default();
        assert_eq!(m.elections_total(), 0);
    }
}
