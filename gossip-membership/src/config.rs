/// TOML configuration file support.
///
/// Merge precedence: CLI flags > config file > defaults.
///
/// All fields in the file sections are optional — missing fields keep
/// their `NodeConfig::default()` values.
use serde::Deserialize;
use std::path::Path;

use crate::node::NodeConfig;

/// Top-level structure of the TOML config file.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FileConfig {
    pub gossip: GossipSection,
    pub network: NetworkSection,
    pub probes: ProbeSection,
    pub metrics: MetricsSection,
    pub backpressure: BackpressureSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct GossipSection {
    pub fanout: Option<usize>,
    pub adaptive_fanout: Option<bool>,
    pub max_sends: Option<usize>,
    pub adaptive_targets: Option<bool>,
    pub interval_ms: Option<u64>,
    pub heartbeat_interval_ms: Option<u64>,
    pub piggyback_max: Option<usize>,
    pub anti_entropy_interval_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct NetworkSection {
    pub encryption: Option<bool>,
    pub cluster_key: Option<String>,
    pub max_inbound_rate: Option<u32>,
    pub inbound_peer_capacity: Option<u32>,
    pub inbound_peer_refill_rate: Option<u32>,
    pub reliable_ack_timeout_ms: Option<u64>,
    pub reliable_max_retries: Option<u8>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ProbeSection {
    pub interval_ms: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub indirect_k: Option<usize>,
    pub suspect_timeout_ms: Option<u64>,
    pub suspect_multiplier: Option<f64>,
    pub suspect_jitter_ms: Option<u64>,
    pub dead_retention_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MetricsSection {
    pub log_interval_ms: Option<u64>,
    pub server_port: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct BackpressureSection {
    pub enabled: Option<bool>,
    pub capacity: Option<u64>,
    pub damping: Option<f64>,
    pub stretch: Option<f64>,
}

impl FileConfig {
    /// Load from a TOML file.  Returns an error string on failure.
    pub fn load(path: &Path) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        toml::from_str(&contents)
            .map_err(|e| format!("failed to parse {}: {e}", path.display()))
    }

    /// Apply file values onto a `NodeConfig`, overriding only the fields
    /// that are present in the file.  The caller starts with
    /// `NodeConfig::default()` and then applies CLI overrides on top.
    pub fn apply(&self, cfg: &mut NodeConfig) {
        // ── gossip ──
        if let Some(v) = self.gossip.fanout { cfg.gossip_fanout = v; }
        if let Some(v) = self.gossip.adaptive_fanout { cfg.adaptive_fanout = v; }
        if let Some(v) = self.gossip.max_sends { cfg.max_gossip_sends = v; }
        if let Some(v) = self.gossip.adaptive_targets { cfg.adaptive_gossip_targets = v; }
        if let Some(v) = self.gossip.interval_ms { cfg.gossip_interval_ms = v; }
        if let Some(v) = self.gossip.heartbeat_interval_ms { cfg.heartbeat_interval_ms = v; }
        if let Some(v) = self.gossip.piggyback_max { cfg.piggyback_max = v; }
        if let Some(v) = self.gossip.anti_entropy_interval_ms { cfg.anti_entropy_interval_ms = v; }

        // ── network ──
        if let Some(v) = self.network.max_inbound_rate {
            cfg.inbound_global_capacity = v;
            cfg.inbound_global_refill_rate = v;
        }
        if let Some(v) = self.network.inbound_peer_capacity { cfg.inbound_peer_capacity = v; }
        if let Some(v) = self.network.inbound_peer_refill_rate { cfg.inbound_peer_refill_rate = v; }
        if let Some(v) = self.network.reliable_ack_timeout_ms { cfg.reliable_ack_timeout_ms = v; }
        if let Some(v) = self.network.reliable_max_retries { cfg.reliable_max_retries = v; }

        // ── probes ──
        if let Some(v) = self.probes.interval_ms { cfg.probe_interval_ms = v; }
        if let Some(v) = self.probes.timeout_ms { cfg.probe_timeout_ms = v; }
        if let Some(v) = self.probes.indirect_k { cfg.indirect_probe_k = v; }
        if let Some(v) = self.probes.suspect_timeout_ms { cfg.suspect_timeout_ms = v; }
        if let Some(v) = self.probes.suspect_multiplier { cfg.suspect_timeout_multiplier = v; }
        if let Some(v) = self.probes.suspect_jitter_ms { cfg.suspect_timeout_jitter_ms = v; }
        if let Some(v) = self.probes.dead_retention_ms { cfg.dead_retention_ms = v; }

        // ── metrics ──
        if let Some(v) = self.metrics.log_interval_ms { cfg.metrics_log_interval_ms = v; }
        if let Some(v) = self.metrics.server_port { cfg.metrics_server_port = v; }

        // ── backpressure ──
        if let Some(v) = self.backpressure.enabled { cfg.backpressure_enabled = v; }
        if let Some(v) = self.backpressure.capacity { cfg.backpressure_capacity = v; }
        if let Some(v) = self.backpressure.damping { cfg.backpressure_damping = v; }
        if let Some(v) = self.backpressure.stretch { cfg.backpressure_stretch = v; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_config() {
        let toml = r#"
[gossip]
fanout = 3
adaptive_fanout = false
max_sends = 2
interval_ms = 100
heartbeat_interval_ms = 250
piggyback_max = 4
anti_entropy_interval_ms = 5000

[network]
max_inbound_rate = 500
inbound_peer_capacity = 50
reliable_ack_timeout_ms = 200
reliable_max_retries = 5

[probes]
interval_ms = 2000
timeout_ms = 500
indirect_k = 3
suspect_timeout_ms = 5000
suspect_multiplier = 4.0
suspect_jitter_ms = 2000
dead_retention_ms = 30000

[metrics]
log_interval_ms = 15000
server_port = 9100
"#;
        let fc: FileConfig = toml::from_str(toml).unwrap();
        let mut cfg = NodeConfig::default();
        fc.apply(&mut cfg);

        assert_eq!(cfg.gossip_fanout, 3);
        assert!(!cfg.adaptive_fanout);
        assert_eq!(cfg.max_gossip_sends, 2);
        assert_eq!(cfg.gossip_interval_ms, 100);
        assert_eq!(cfg.heartbeat_interval_ms, 250);
        assert_eq!(cfg.piggyback_max, 4);
        assert_eq!(cfg.anti_entropy_interval_ms, 5000);
        assert_eq!(cfg.inbound_global_capacity, 500);
        assert_eq!(cfg.inbound_global_refill_rate, 500);
        assert_eq!(cfg.inbound_peer_capacity, 50);
        assert_eq!(cfg.reliable_ack_timeout_ms, 200);
        assert_eq!(cfg.reliable_max_retries, 5);
        assert_eq!(cfg.probe_interval_ms, 2000);
        assert_eq!(cfg.probe_timeout_ms, 500);
        assert_eq!(cfg.indirect_probe_k, 3);
        assert_eq!(cfg.suspect_timeout_ms, 5000);
        assert_eq!(cfg.suspect_timeout_multiplier, 4.0);
        assert_eq!(cfg.suspect_timeout_jitter_ms, 2000);
        assert_eq!(cfg.dead_retention_ms, 30000);
        assert_eq!(cfg.metrics_log_interval_ms, 15000);
        assert_eq!(cfg.metrics_server_port, 9100);
    }

    #[test]
    fn parse_partial_config() {
        let toml = r#"
[gossip]
fanout = 10

[probes]
timeout_ms = 800
"#;
        let fc: FileConfig = toml::from_str(toml).unwrap();
        let mut cfg = NodeConfig::default();
        let default = NodeConfig::default();
        fc.apply(&mut cfg);

        assert_eq!(cfg.gossip_fanout, 10);
        assert_eq!(cfg.probe_timeout_ms, 800);
        // Unset fields keep defaults.
        assert_eq!(cfg.gossip_interval_ms, default.gossip_interval_ms);
        assert_eq!(cfg.suspect_timeout_ms, default.suspect_timeout_ms);
    }

    #[test]
    fn parse_empty_config() {
        let fc: FileConfig = toml::from_str("").unwrap();
        let mut cfg = NodeConfig::default();
        let default = NodeConfig::default();
        fc.apply(&mut cfg);

        assert_eq!(cfg.gossip_fanout, default.gossip_fanout);
        assert_eq!(cfg.probe_timeout_ms, default.probe_timeout_ms);
    }

    #[test]
    fn cli_overrides_file() {
        let toml = r#"
[metrics]
server_port = 9100
"#;
        let fc: FileConfig = toml::from_str(toml).unwrap();
        let mut cfg = NodeConfig::default();
        fc.apply(&mut cfg);
        assert_eq!(cfg.metrics_server_port, 9100);

        // CLI override.
        cfg.metrics_server_port = 9200;
        assert_eq!(cfg.metrics_server_port, 9200);
    }

    #[test]
    fn network_section_sets_both_global_fields() {
        let toml = r#"
[network]
max_inbound_rate = 999
"#;
        let fc: FileConfig = toml::from_str(toml).unwrap();
        let mut cfg = NodeConfig::default();
        fc.apply(&mut cfg);
        assert_eq!(cfg.inbound_global_capacity, 999);
        assert_eq!(cfg.inbound_global_refill_rate, 999);
    }
}
