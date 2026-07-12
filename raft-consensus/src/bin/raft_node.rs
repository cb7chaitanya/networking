//! Standalone Raft node process.
//!
//! # Usage
//!
//! ```text
//! raft_node --id 1 --addr 127.0.0.1:7001 \
//!           --peer 2=127.0.0.1:7002       \
//!           --peer 3=127.0.0.1:7003       \
//!           [--metrics 127.0.0.1:9001]    \
//!           [--tick-ms 10]
//! ```
//!
//! All flags are required except `--metrics` (default: disabled) and
//! `--tick-ms` (default: 10).
//!
//! # 3-node cluster quick-start
//!
//! ```text
//! # Terminal 1
//! cargo run --bin raft_node -- --id 1 --addr 127.0.0.1:7001 \
//!     --peer 2=127.0.0.1:7002 --peer 3=127.0.0.1:7003 --metrics 127.0.0.1:9001
//!
//! # Terminal 2
//! cargo run --bin raft_node -- --id 2 --addr 127.0.0.1:7002 \
//!     --peer 1=127.0.0.1:7001 --peer 3=127.0.0.1:7003 --metrics 127.0.0.1:9002
//!
//! # Terminal 3
//! cargo run --bin raft_node -- --id 3 --addr 127.0.0.1:7003 \
//!     --peer 1=127.0.0.1:7001 --peer 2=127.0.0.1:7002 --metrics 127.0.0.1:9003
//! ```
//!
//! After a few hundred milliseconds one node wins the election.  Poll any
//! node's `/raft` endpoint to see who the leader is:
//!
//! ```text
//! curl 127.0.0.1:9001/raft
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use raft_consensus::node::ClusterConfig;
use raft_consensus::server::MetricsServer;
use raft_consensus::transport::NodeRunner;

// ── Raft defaults ─────────────────────────────────────────────────────────────

const DEFAULT_TICK_MS: u64 = 10;
const ELECTION_TIMEOUT_MIN: u64 = 15; // ticks → 150 ms at 10 ms/tick
const ELECTION_TIMEOUT_MAX: u64 = 30; // ticks → 300 ms
const HEARTBEAT_INTERVAL: u64 = 5; // ticks → 50 ms

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;

    eprintln!(
        "[node {}] starting — listening on {} with {} peer(s)",
        args.id,
        args.addr,
        args.peers.len()
    );

    let config = ClusterConfig {
        election_timeout_min: ELECTION_TIMEOUT_MIN,
        election_timeout_max: ELECTION_TIMEOUT_MAX,
        heartbeat_interval: HEARTBEAT_INTERVAL,
        pre_vote: false,
    };

    let (runner, handle) = NodeRunner::new(
        args.id,
        args.peers,
        args.addr,
        config,
        args.tick_ms,
    )
    .await?;

    eprintln!("[node {}] bound to {}", args.id, handle.bound_addr);

    // Start the optional Prometheus / health HTTP server.
    if let Some(metrics_addr) = args.metrics_addr {
        let bound = MetricsServer::spawn(&metrics_addr, Arc::clone(&handle.metrics))?;
        eprintln!("[node {}] metrics at http://{bound}/metrics", args.id);
    }

    // Start a background task that prints status every 2 seconds.
    {
        let metrics = Arc::clone(&handle.metrics);
        let id = args.id;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                interval.tick().await;
                let leader = metrics.leader_id();
                let term = metrics.current_term();
                let commit = metrics.commit_index();
                let role = if leader == id {
                    "LEADER"
                } else if leader == 0 {
                    "FOLLOWER (no leader)"
                } else {
                    "FOLLOWER"
                };
                eprintln!(
                    "[node {id}] role={role} term={term} commit={commit} leader={leader}"
                );
            }
        });
    }

    // Optional self-driven workload: if --propose-rate N is set, the leader
    // proposes N synthetic entries per second so metrics show live activity.
    if args.propose_rate > 0 {
        let metrics = Arc::clone(&handle.metrics);
        let propose_tx = handle.propose_tx.clone();
        let id = args.id;
        let rate = args.propose_rate;
        tokio::spawn(async move {
            let interval_us = 1_000_000u64 / rate as u64;
            let mut ticker = tokio::time::interval(Duration::from_micros(interval_us));
            let mut seq: u64 = 0;
            loop {
                ticker.tick().await;
                if metrics.leader_id() == id {
                    seq += 1;
                    let _ = propose_tx.send(format!("workload:{seq}").into_bytes());
                }
            }
        });
    }

    // Run the Raft event loop forever.
    runner.run().await;

    Ok(())
}

// ── CLI parser ────────────────────────────────────────────────────────────────

struct Args {
    id: u64,
    addr: SocketAddr,
    peers: Vec<(u64, SocketAddr)>,
    metrics_addr: Option<String>,
    tick_ms: u64,
    propose_rate: u32,
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let mut id: Option<u64> = None;
    let mut addr: Option<SocketAddr> = None;
    let mut peers: Vec<(u64, SocketAddr)> = Vec::new();
    let mut metrics_addr: Option<String> = None;
    let mut tick_ms = DEFAULT_TICK_MS;
    let mut propose_rate: u32 = 0;

    let mut raw = std::env::args().skip(1).peekable();
    while let Some(flag) = raw.next() {
        let val = raw
            .next()
            .ok_or_else(|| format!("flag {flag} requires a value"))?;
        match flag.as_str() {
            "--id" => id = Some(val.parse()?),
            "--addr" => addr = Some(val.parse()?),
            "--peer" => {
                // Format: "2=127.0.0.1:7002"
                let (pid, paddr) = val
                    .split_once('=')
                    .ok_or_else(|| format!("--peer must be id=addr, got {val}"))?;
                peers.push((pid.parse()?, paddr.parse()?));
            }
            "--metrics" => metrics_addr = Some(val),
            "--tick-ms" => tick_ms = val.parse()?,
            "--propose-rate" => propose_rate = val.parse()?,
            other => return Err(format!("unknown flag: {other}").into()),
        }
    }

    Ok(Args {
        id: id.ok_or("--id required")?,
        addr: addr.ok_or("--addr required")?,
        peers,
        metrics_addr,
        tick_ms,
        propose_rate,
    })
}
