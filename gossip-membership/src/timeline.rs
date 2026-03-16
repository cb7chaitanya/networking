/// Timeline event logger — structured, append-only log of SWIM protocol events.
///
/// Records every significant protocol event (suspect, gossip spread, dead
/// declaration, etc.) with wall-clock timestamps and monotonic offsets.
/// The full log can be exported as JSON for offline analysis or served
/// via the metrics HTTP endpoint.
use std::time::{Instant, SystemTime};

use serde::Serialize;

// ── Event kinds ──────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEventKind {
    /// A node was marked Suspect (failed probes).
    NodeSuspected,
    /// A gossip round was disseminated to peers.
    GossipSpread,
    /// A Suspect node was promoted to Dead after timeout.
    NodeDeclaredDead,
    /// A previously unknown node was discovered.
    NodeJoined,
    /// A node was confirmed alive (ACK / heartbeat received).
    NodeAlive,
    /// A direct probe timed out and was escalated to indirect probing.
    ProbeTimeout,
    /// Indirect probe (PING_REQ) was sent via intermediaries.
    IndirectProbe,
    /// A node sent a graceful LEAVE message.
    Leave,
}

impl TimelineEventKind {
    pub fn css_class(&self) -> &'static str {
        match self {
            TimelineEventKind::NodeSuspected => "suspect",
            TimelineEventKind::GossipSpread => "gossip",
            TimelineEventKind::NodeDeclaredDead => "dead",
            TimelineEventKind::NodeJoined => "joined",
            TimelineEventKind::NodeAlive => "alive",
            TimelineEventKind::ProbeTimeout => "timeout",
            TimelineEventKind::IndirectProbe => "indirect",
            TimelineEventKind::Leave => "leave",
        }
    }
}

// ── Single event ─────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize)]
pub struct TimelineEvent {
    /// Milliseconds since the first recorded event (monotonic).
    pub offset_ms: u64,
    /// ISO 8601 wall-clock timestamp.
    pub wall_clock: String,
    /// What happened.
    pub kind: TimelineEventKind,
    /// Node that observed / initiated the event.
    pub source_node: u64,
    /// Node affected by the event (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_node: Option<u64>,
    /// Human-readable detail string.
    pub detail: String,
}

// ── Timeline log ─────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize)]
pub struct TimelineLog {
    events: Vec<TimelineEvent>,
    #[serde(skip)]
    epoch: Option<Instant>,
}

impl Default for TimelineLog {
    fn default() -> Self {
        Self::new()
    }
}

impl TimelineLog {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            epoch: None,
        }
    }

    /// Append an event to the log.  Timestamps are computed automatically.
    pub fn record(
        &mut self,
        kind: TimelineEventKind,
        source_node: u64,
        target_node: Option<u64>,
        detail: impl Into<String>,
    ) {
        let now = Instant::now();
        let epoch = *self.epoch.get_or_insert(now);
        let offset_ms = now.duration_since(epoch).as_millis() as u64;

        let wall_clock = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| {
                let secs = d.as_secs();
                let millis = d.subsec_millis();
                // Simple ISO-ish format without pulling in chrono.
                let (s, ms) = (secs, millis);
                format!(
                    "{}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                    1970 + s / 31_536_000,
                    (s % 31_536_000) / 2_592_000 + 1,
                    (s % 2_592_000) / 86400 + 1,
                    (s % 86400) / 3600,
                    (s % 3600) / 60,
                    s % 60,
                    ms,
                )
            })
            .unwrap_or_else(|_| "unknown".to_string());

        self.events.push(TimelineEvent {
            offset_ms,
            wall_clock,
            kind,
            source_node,
            target_node,
            detail: detail.into(),
        });
    }

    /// Serialize the full timeline to a JSON string.
    pub fn export_json(&self) -> String {
        serde_json::to_string_pretty(&self.events).unwrap_or_else(|e| {
            format!(r#"{{"error":"serialization failed: {}"}}"#, e)
        })
    }

    /// Write the timeline JSON to a file.
    pub fn export_json_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::write(path, self.export_json())
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_export() {
        let mut log = TimelineLog::new();
        log.record(
            TimelineEventKind::NodeSuspected,
            1,
            Some(2),
            "node 1 suspects node 2",
        );
        log.record(
            TimelineEventKind::GossipSpread,
            1,
            None,
            "gossip round to 3 peers",
        );
        log.record(
            TimelineEventKind::NodeDeclaredDead,
            1,
            Some(2),
            "node 2 declared dead after timeout",
        );
        assert_eq!(log.len(), 3);
        let json = log.export_json();
        assert!(json.contains("node_suspected"));
        assert!(json.contains("gossip_spread"));
        assert!(json.contains("node_declared_dead"));
        // First event offset should be 0.
        assert!(json.contains(r#""offset_ms": 0"#));
    }

    #[test]
    fn empty_log_exports_empty_array() {
        let log = TimelineLog::new();
        assert!(log.is_empty());
        assert_eq!(log.export_json(), "[]");
    }
}
