/// Gossip propagation visualization — event types and output formatters.
///
/// Captures message-level events from the transport layer and renders them
/// as plain text, Graphviz DOT, or JSON timeline.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use crate::message::{kind, Message};

// ── Event types ──────────────────────────────────────────────────────────────

/// A single gossip event captured during a simulation run.
#[derive(Debug, Clone)]
pub struct GossipEvent {
    /// Monotonic timestamp relative to simulation start.
    pub timestamp: Instant,
    /// Source address (sender).
    pub from: SocketAddr,
    /// Destination address (receiver).
    pub to: SocketAddr,
    /// Human-readable message kind.
    pub kind: &'static str,
    /// Number of membership entries carried (0 for PING/ACK).
    pub entry_count: usize,
    /// Wire size in bytes.
    pub bytes: usize,
}

impl GossipEvent {
    pub fn message_sent(from: SocketAddr, to: SocketAddr, msg: &Message, bytes: usize) -> Self {
        let (kind_str, entry_count) = msg_meta(msg);
        Self {
            timestamp: Instant::now(),
            from,
            to,
            kind: kind_str,
            entry_count,
            bytes,
        }
    }

    pub fn message_received(
        from: SocketAddr,
        to: SocketAddr,
        msg: &Message,
        bytes: usize,
    ) -> Self {
        let (kind_str, entry_count) = msg_meta(msg);
        Self {
            timestamp: Instant::now(),
            from,
            to,
            kind: kind_str,
            entry_count,
            bytes,
        }
    }
}

fn msg_meta(msg: &Message) -> (&'static str, usize) {
    match msg.kind {
        kind::GOSSIP => {
            let count = match &msg.payload {
                crate::message::MessagePayload::Gossip(entries) => entries.len(),
                _ => 0,
            };
            ("GOSSIP", count)
        }
        kind::PING => {
            let count = match &msg.payload {
                crate::message::MessagePayload::Ping(entries) => entries.len(),
                _ => 0,
            };
            ("PING", count)
        }
        kind::PING_REQ => ("PING_REQ", 0),
        kind::ACK => {
            let count = match &msg.payload {
                crate::message::MessagePayload::Ack(entries) => entries.len(),
                _ => 0,
            };
            ("ACK", count)
        }
        kind::LEAVE => ("LEAVE", 0),
        kind::ANTI_ENTROPY => ("ANTI_ENTROPY", 0),
        _ => ("UNKNOWN", 0),
    }
}

// ── Event collector ──────────────────────────────────────────────────────────

/// Collects gossip events and assigns short labels to nodes.
pub struct EventCollector {
    events: Vec<GossipEvent>,
    /// Maps socket address → short label (A, B, C, …).
    labels: HashMap<SocketAddr, String>,
    start: Instant,
}

impl EventCollector {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            labels: HashMap::new(),
            start: Instant::now(),
        }
    }

    /// Register a node address and assign it a label.
    pub fn register_node(&mut self, addr: SocketAddr) {
        let n = self.labels.len();
        let label = node_label(n);
        self.labels.insert(addr, label);
    }

    /// Add events from the channel into the collector.
    pub fn add_event(&mut self, event: GossipEvent) {
        self.events.push(event);
    }

    /// Sort events by timestamp.
    pub fn finalize(&mut self) {
        self.events.sort_by_key(|e| e.timestamp);
        // Deduplicate send/recv pairs: keep only "sent" events since each
        // message appears as both a send (at source) and receive (at dest).
        let mut seen = std::collections::HashSet::new();
        self.events.retain(|e| {
            // Key: (from, to, timestamp rounded to ms, kind)
            let ms = e.timestamp.duration_since(self.start).as_millis();
            let key = (e.from, e.to, ms / 5, e.kind);
            seen.insert(key)
        });
    }

    fn label(&self, addr: &SocketAddr) -> String {
        self.labels
            .get(addr)
            .cloned()
            .unwrap_or_else(|| addr.to_string())
    }

    fn elapsed_ms(&self, ts: Instant) -> u64 {
        ts.duration_since(self.start).as_millis() as u64
    }

    // ── Output formatters ────────────────────────────────────────────────────

    /// Render as plain text showing propagation flow.
    pub fn format_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Gossip Propagation Trace ({} events, {} nodes)\n",
            self.events.len(),
            self.labels.len()
        ));
        out.push_str(&"─".repeat(60));
        out.push('\n');

        // Legend
        out.push_str("\nNodes:\n");
        let mut sorted_labels: Vec<_> = self.labels.iter().collect();
        sorted_labels.sort_by_key(|(_, label)| (*label).clone());
        for (addr, label) in &sorted_labels {
            out.push_str(&format!("  {label} = {addr}\n"));
        }
        out.push('\n');

        // Events
        for event in &self.events {
            let from = self.label(&event.from);
            let to = self.label(&event.to);
            let ms = self.elapsed_ms(event.timestamp);
            let detail = if event.entry_count > 0 {
                format!(" ({} entries, {} bytes)", event.entry_count, event.bytes)
            } else {
                format!(" ({} bytes)", event.bytes)
            };
            out.push_str(&format!(
                "  [{ms:>6}ms] {from} -> {to}  {}{detail}\n",
                event.kind
            ));
        }

        // Summary
        out.push('\n');
        out.push_str(&self.format_summary());
        out
    }

    /// Render as Graphviz DOT.
    pub fn format_dot(&self) -> String {
        let mut out = String::new();
        out.push_str("digraph gossip {\n");
        out.push_str("  rankdir=LR;\n");
        out.push_str("  node [shape=circle, style=filled, fillcolor=lightblue];\n\n");

        // Node declarations
        let mut sorted_labels: Vec<_> = self.labels.iter().collect();
        sorted_labels.sort_by_key(|(_, label)| (*label).clone());
        for (addr, label) in &sorted_labels {
            out.push_str(&format!(
                "  {label} [label=\"{label}\\n{}\"];\n",
                addr.port()
            ));
        }
        out.push('\n');

        // Edge weights: count messages per (from, to, kind)
        let mut edges: HashMap<(String, String, &str), usize> = HashMap::new();
        for event in &self.events {
            let from = self.label(&event.from);
            let to = self.label(&event.to);
            *edges.entry((from, to, event.kind)).or_default() += 1;
        }

        // Render edges
        let mut sorted_edges: Vec<_> = edges.iter().collect();
        sorted_edges.sort_by_key(|((f, t, k), _)| (f.clone(), t.clone(), *k));
        for ((from, to, kind), count) in sorted_edges {
            let color = match *kind {
                "GOSSIP" => "blue",
                "PING" => "green",
                "ACK" => "gray",
                "PING_REQ" => "orange",
                _ => "black",
            };
            let width = if *count > 5 { 2.0 } else { 1.0 };
            out.push_str(&format!(
                "  {from} -> {to} [label=\"{kind} x{count}\", color={color}, penwidth={width}];\n"
            ));
        }

        // Legend
        out.push_str("\n  // Legend\n");
        out.push_str("  subgraph cluster_legend {\n");
        out.push_str("    label=\"Legend\";\n");
        out.push_str("    style=dashed;\n");
        out.push_str("    legend_gossip [label=\"GOSSIP\", shape=plaintext, fontcolor=blue];\n");
        out.push_str("    legend_ping [label=\"PING\", shape=plaintext, fontcolor=green];\n");
        out.push_str("    legend_ack [label=\"ACK\", shape=plaintext, fontcolor=gray];\n");
        out.push_str(
            "    legend_pingreq [label=\"PING_REQ\", shape=plaintext, fontcolor=orange];\n",
        );
        out.push_str("  }\n");

        out.push_str("}\n");
        out
    }

    /// Render as JSON timeline.
    pub fn format_json(&self) -> String {
        let mut events_json = Vec::new();
        for event in &self.events {
            let from = self.label(&event.from);
            let to = self.label(&event.to);
            let ms = self.elapsed_ms(event.timestamp);
            events_json.push(format!(
                "    {{\n      \"timestamp_ms\": {ms},\n      \"from\": \"{from}\",\n      \"to\": \"{to}\",\n      \"kind\": \"{}\",\n      \"entry_count\": {},\n      \"bytes\": {}\n    }}",
                event.kind, event.entry_count, event.bytes
            ));
        }

        // Node list
        let mut nodes_json = Vec::new();
        let mut sorted_labels: Vec<_> = self.labels.iter().collect();
        sorted_labels.sort_by_key(|(_, label)| (*label).clone());
        for (addr, label) in &sorted_labels {
            nodes_json.push(format!(
                "    {{ \"label\": \"{label}\", \"addr\": \"{}\" }}",
                addr
            ));
        }

        // Summary stats
        let summary = self.summary_stats();

        format!(
            "{{\n  \"nodes\": [\n{}\n  ],\n  \"summary\": {{\n    \"total_messages\": {},\n    \"gossip_count\": {},\n    \"ping_count\": {},\n    \"ack_count\": {},\n    \"ping_req_count\": {},\n    \"total_bytes\": {},\n    \"duration_ms\": {}\n  }},\n  \"events\": [\n{}\n  ]\n}}",
            nodes_json.join(",\n"),
            summary.total,
            summary.gossip,
            summary.ping,
            summary.ack,
            summary.ping_req,
            summary.total_bytes,
            summary.duration_ms,
            events_json.join(",\n")
        )
    }

    fn format_summary(&self) -> String {
        let s = self.summary_stats();
        let mut out = String::new();
        out.push_str("Summary:\n");
        out.push_str(&format!("  Total messages : {}\n", s.total));
        out.push_str(&format!("  GOSSIP         : {}\n", s.gossip));
        out.push_str(&format!("  PING           : {}\n", s.ping));
        out.push_str(&format!("  ACK            : {}\n", s.ack));
        out.push_str(&format!("  PING_REQ       : {}\n", s.ping_req));
        out.push_str(&format!("  Total bytes    : {}\n", s.total_bytes));
        out.push_str(&format!("  Duration       : {}ms\n", s.duration_ms));
        out
    }

    fn summary_stats(&self) -> SummaryStats {
        let mut gossip = 0usize;
        let mut ping = 0usize;
        let mut ack = 0usize;
        let mut ping_req = 0usize;
        let mut total_bytes = 0usize;

        for e in &self.events {
            match e.kind {
                "GOSSIP" => gossip += 1,
                "PING" => ping += 1,
                "ACK" => ack += 1,
                "PING_REQ" => ping_req += 1,
                _ => {}
            }
            total_bytes += e.bytes;
        }

        let duration_ms = self
            .events
            .last()
            .map(|e| self.elapsed_ms(e.timestamp))
            .unwrap_or(0);

        SummaryStats {
            total: self.events.len(),
            gossip,
            ping,
            ack,
            ping_req,
            total_bytes,
            duration_ms,
        }
    }
}

struct SummaryStats {
    total: usize,
    gossip: usize,
    ping: usize,
    ack: usize,
    ping_req: usize,
    total_bytes: usize,
    duration_ms: u64,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Generate a short label: A, B, C, …, Z, AA, AB, …
fn node_label(index: usize) -> String {
    if index < 26 {
        String::from((b'A' + index as u8) as char)
    } else {
        format!(
            "{}{}",
            (b'A' + (index / 26 - 1) as u8) as char,
            (b'A' + (index % 26) as u8) as char
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_sequential() {
        assert_eq!(node_label(0), "A");
        assert_eq!(node_label(1), "B");
        assert_eq!(node_label(25), "Z");
        assert_eq!(node_label(26), "AA");
        assert_eq!(node_label(27), "AB");
    }
}
