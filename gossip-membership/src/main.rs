/// Gossip-based distributed membership protocol — CLI entry point.
///
/// Usage:
///   # Generate a cluster key:
///   cargo run -- --generate-key
///
///   # Start a standalone bootstrap node (encrypted):
///   cargo run -- --bind 127.0.0.1:7000 --cluster-key <HEX>
///
///   # Join an existing cluster:
///   cargo run -- --bind 127.0.0.1:7001 --peers 127.0.0.1:7000 --cluster-key <HEX>
///
///   # Load configuration from a TOML file:
///   cargo run -- --config gossip.toml --bind 127.0.0.1:7000
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use tokio::sync::oneshot;

use gossip_membership::config::FileConfig;
use gossip_membership::crypto::{self, ClusterKey};
use gossip_membership::node::NodeConfig;
use gossip_membership::runner::{run_node, Node};
use gossip_membership::transport::Transport;

// ── CLI ────────────────────────────────────────────────────────────────────────
#[derive(Parser, Debug)]
#[command(
    name = "gossip-membership",
    about = "Gossip-based distributed membership protocol"
)]
struct Args {
    /// Path to a TOML configuration file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Local address to bind (e.g. 127.0.0.1:7000)
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: SocketAddr,

    /// Comma-separated list of bootstrap peer addresses (e.g. 127.0.0.1:7000)
    #[arg(long, value_delimiter = ',', default_value = "")]
    peers: Vec<String>,

    /// Shared cluster key (64 hex chars = 256-bit ChaCha20-Poly1305 key).
    /// All nodes in the cluster must use the same key.
    #[arg(long)]
    cluster_key: Option<String>,

    /// Generate a random cluster key, print it, and exit.
    #[arg(long)]
    generate_key: bool,

    /// TCP port for the Prometheus-compatible HTTP metrics endpoint.
    /// Serves /metrics (Prometheus text) and /metrics/json (JSON).
    #[arg(long)]
    metrics_port: Option<u16>,
}

// ── main ───────────────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    // --generate-key: print a random key and exit.
    if args.generate_key {
        let key_bytes = crypto::generate_key();
        println!("{}", crypto::key_to_hex(&key_bytes));
        return;
    }

    // ── Build config: defaults → file → CLI ──────────────────────────────
    let mut config = NodeConfig::default();

    // Layer 2: config file (if provided).
    let file_config = if let Some(ref path) = args.config {
        match FileConfig::load(path) {
            Ok(fc) => {
                log::info!("loaded config from {}", path.display());
                fc
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        FileConfig::default()
    };
    file_config.apply(&mut config);

    // Layer 3: CLI flags override file values.
    if let Some(port) = args.metrics_port {
        config.metrics_server_port = port;
    }

    // ── Cluster key: CLI flag > file config ──────────────────────────────
    let key_hex = args
        .cluster_key
        .as_deref()
        .or(file_config.network.cluster_key.as_deref());

    let cluster_key: Option<ClusterKey> = key_hex.map(|hex| {
        let bytes = crypto::key_from_hex(hex).unwrap_or_else(|| {
            eprintln!("error: cluster key must be exactly 64 hex characters");
            std::process::exit(1);
        });
        ClusterKey::from_bytes(bytes)
    });

    let peers: Vec<SocketAddr> = args
        .peers
        .iter()
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            s.parse()
                .map_err(|e| log::warn!("bad peer address {s}: {e}"))
                .ok()
        })
        .collect();

    let mut transport = Transport::bind(args.bind)
        .await
        .expect("failed to bind UDP socket");

    if let Some(key) = cluster_key {
        transport = transport.with_key(key);
        log::info!("encryption enabled (ChaCha20-Poly1305)");
    }

    log::info!("bound to {}", transport.local_addr);

    let node = Node::new(transport, config, &peers);

    // The main binary runs until Ctrl-C.
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = shutdown_tx.send(());
    });

    run_node(node, shutdown_rx).await;
}
