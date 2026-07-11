# Raft Consensus — Observability

This document describes the metrics system, the Prometheus / Grafana stack, and how to run it against a local 3-node cluster.

---

## Metrics architecture

Every `raft_node` process exposes an HTTP server (enabled via `--metrics host:port`) with three endpoints:

| Endpoint    | Content-Type             | Purpose                              |
|-------------|--------------------------|--------------------------------------|
| `/metrics`  | `text/plain` (Prometheus) | Prometheus scrape target            |
| `/raft`     | `application/json`       | Human-readable JSON snapshot         |
| `/healthz`  | `application/json`       | Liveness probe `{"status":"ok"}`     |

All Prometheus metric names carry the `raft_` prefix.

### Metrics reference

#### Counters

| Metric | Description |
|--------|-------------|
| `raft_elections_total` | Number of elections started by this node |
| `raft_term_changes_total` | Number of times `current_term` incremented |
| `raft_vote_requests_total` | `RequestVote` RPCs sent |
| `raft_append_entries_total` | `AppendEntries` RPCs sent |
| `raft_snapshots_sent_total` | `InstallSnapshot` RPCs sent |
| `raft_snapshots_received_total` | `InstallSnapshot` RPCs received |
| `raft_proposals_total` | Client proposals accepted (leader only) |
| `raft_proposals_committed_total` | Log entries committed |
| `raft_transport_bytes_sent_total` | TCP bytes sent |
| `raft_transport_bytes_received_total` | TCP bytes received |
| `raft_transport_reconnects_total` | TCP reconnect attempts |
| `raft_wal_bytes_written_total` | Raw bytes appended to WAL segments |

#### Gauges

| Metric | Description |
|--------|-------------|
| `raft_current_term` | Raft term this node is on |
| `raft_commit_index` | Highest log index known to be committed |
| `raft_last_applied` | Highest log index applied to the state machine |
| `raft_leader_id` | Node ID of the current leader (0 = none) |
| `raft_is_leader` | 1 if this node is leader, 0 otherwise |
| `raft_snapshot_last_index` | `last_included_index` of the last received snapshot |
| `raft_wal_segment_count` | Number of WAL segment files on disk |
| `raft_wal_active_segment_bytes` | Bytes written to the current WAL segment |

#### Per-peer gauges (leader only)

| Metric | Label | Description |
|--------|-------|-------------|
| `raft_peer_match_index` | `peer="<id>"` | Highest replicated index for this peer |
| `raft_peer_next_index` | `peer="<id>"` | Next index the leader will send to this peer |

---

## Quick start

### 1 — Start the 3-node cluster

```bash
cd raft-consensus
./observability/run-cluster.sh
```

This builds the release binary and starts three nodes:

| Node | Raft addr | Metrics addr |
|------|-----------|--------------|
| 1 | `127.0.0.1:7001` | `http://127.0.0.1:9001` |
| 2 | `127.0.0.1:7002` | `http://127.0.0.1:9002` |
| 3 | `127.0.0.1:7003` | `http://127.0.0.1:9003` |

### 2 — Start Prometheus + Grafana

```bash
cd observability
docker compose up -d
```

| Service | URL |
|---------|-----|
| Prometheus | http://localhost:9090 |
| Grafana | http://localhost:3000 (admin / admin) |

### 3 — Open the dashboard

Grafana auto-provisions the **Raft Consensus** dashboard. Navigate to
**Dashboards → Raft → Raft Consensus** (or use the home dashboard link).

---

## Dashboard sections

### Leader Timeline
Two panels show which node holds leadership over time:
- **Leader ID per Node** — the `raft_leader_id` gauge scraped from each node. In a stable cluster all nodes agree on the same value.
- **Is Leader** — the `raft_is_leader` boolean, one series per node. Exactly one line should be `1` at any time.

### Term History
- **Current Term** — `raft_current_term` per node. Term increments on each election; a rapidly climbing term indicates instability.
- **Election Rate** — `rate(raft_elections_total[1m])` and `rate(raft_term_changes_total[1m])`. In a healthy cluster both rates hover near zero between leader failures.

### Proposal Throughput
- **Proposal Rate** — `rate(raft_proposals_total[30s])` showing how fast the leader accepts client proposals.
- **Commit Rate** — `rate(raft_proposals_committed_total[30s])` showing how fast entries reach quorum. The gap between these two rates reveals replication backpressure.

### Commit Latency
- **Commit Index vs Last Applied** — overlaid time series. The delta between the two lines is the apply backlog.
- **Apply Lag (entries)** — `raft_commit_index - raft_last_applied` surfaced as a single gauge. Non-zero means the state machine is behind.

### Replication Lag
- **Peer Match Index** — per-peer `raft_peer_match_index{peer="..."}` as seen from the leader. All peers should track the leader's commit index closely.
- **Replication Lag** — `max(raft_commit_index) - raft_peer_match_index`. Zero means fully caught up.

### Follower Status
- **AppendEntries Rate** — heartbeats + replication messages per second.
- **Vote Request Rate** — `RequestVote` RPCs; spikes during elections.
- **Peer Next Index** — the leader's optimistic send pointer per follower.

### Snapshot Activity
- **Snapshot Send / Receive Rate** — `InstallSnapshot` throughput. Followers that fall behind the log compaction point will show a receive spike.
- **Last Snapshot Index** — `raft_snapshot_last_index`; advances each time a snapshot is installed.

### WAL Growth
- **WAL Write Rate** — `rate(raft_wal_bytes_written_total[30s])` in bytes per second.
- **WAL Segment Count** — number of on-disk segment files; grows until compaction.
- **WAL Active Segment Size** — bytes in the current open segment; resets to 0 on rotation.

### Transport Bandwidth
- **Transport Bandwidth (tx / rx)** — TCP send and receive rates in bytes per second.
- **Transport Reconnect Rate** — failed connect attempts per second. Sustained non-zero values indicate a peer is unreachable.

### Cluster Overview (Stat Panels)
Six stat panels give an at-a-glance cluster summary:

| Panel | PromQL |
|-------|--------|
| Max Term | `max(raft_current_term)` |
| Max Commit Index | `max(raft_commit_index)` |
| Total Elections | `sum(raft_elections_total)` |
| Commit Throughput | `sum(rate(raft_proposals_committed_total[1m]))` |
| Total WAL Bytes Written | `sum(raft_wal_bytes_written_total)` |
| Total Transport Bytes Sent | `sum(raft_transport_bytes_sent_total)` |

---

## File layout

```
observability/
├── docker-compose.yml          # Prometheus + Grafana services
├── prometheus.yml              # Scrape config (3 nodes via host.docker.internal)
├── run-cluster.sh              # Build + launch 3-node demo cluster
└── grafana/
    ├── provisioning/
    │   ├── datasources/
    │   │   └── datasource.yml  # Prometheus datasource
    │   └── dashboards/
    │       └── dashboard.yml   # Dashboard file-provider config
    └── dashboards/
        └── raft.json           # Full Raft Consensus Grafana dashboard
```

---

## Prometheus scrape config

The scrape interval is **5 s** to match the node tick frequency. Targets are addressed via `host.docker.internal` so the Docker containers can reach processes running on the host.

```yaml
scrape_configs:
  - job_name: "raft_cluster"
    static_configs:
      - targets:
          - "host.docker.internal:9001"
          - "host.docker.internal:9002"
          - "host.docker.internal:9003"
```

---

## Manually querying metrics

```bash
# Prometheus text format
curl 127.0.0.1:9001/metrics

# JSON snapshot
curl 127.0.0.1:9001/raft | jq .

# Health check
curl 127.0.0.1:9001/healthz
```
