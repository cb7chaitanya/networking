/// Gossip propagation visualizer — spawns a local cluster and traces message flow.
///
/// Usage:
///   # Text output (default):
///   cargo run --bin gossip-viz -- --nodes 5 --duration 3
///
///   # Graphviz DOT:
///   cargo run --bin gossip-viz -- --nodes 4 --duration 2 --format dot > gossip.dot
///   dot -Tpng gossip.dot -o gossip.png
///
///   # JSON timeline:
///   cargo run --bin gossip-viz -- --nodes 6 --duration 5 --format json > timeline.json
use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use tokio::sync::{mpsc, oneshot};

use gossip_membership::node::NodeConfig;
use gossip_membership::runner::{run_node, Node};
use gossip_membership::transport::Transport;
use gossip_membership::viz::{EventCollector, GossipEvent};

// ── CLI ────────────────────────────────────────────────────────────────────────
#[derive(Parser, Debug)]
#[command(
    name = "gossip-viz",
    about = "Visualize gossip message propagation across a local cluster"
)]
struct Args {
    /// Number of nodes in the local cluster.
    #[arg(long, default_value = "5")]
    nodes: usize,

    /// How long to run the simulation (seconds).
    #[arg(long, default_value = "3")]
    duration: u64,

    /// Output format: text, dot, json.
    #[arg(long, default_value = "text")]
    format: String,

    /// Write output to a file instead of stdout.
    #[arg(long, short)]
    output: Option<String>,
}

// ── main ───────────────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() {
    // Suppress normal gossip logging — we only want the viz output.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let args = Args::parse();

    if args.nodes < 2 {
        eprintln!("error: need at least 2 nodes");
        std::process::exit(1);
    }

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<GossipEvent>();

    // Use fast config for visualization — things happen quickly.
    let config = NodeConfig::fast();

    // Bind all nodes to localhost with OS-assigned ports.
    let mut transports = Vec::new();
    for _ in 0..args.nodes {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let transport = Transport::bind(addr)
            .await
            .expect("failed to bind UDP socket")
            .with_event_sink(event_tx.clone());
        transports.push(transport);
    }

    // Collect all addresses for peer discovery.
    let addrs: Vec<SocketAddr> = transports.iter().map(|t| t.local_addr).collect();

    let mut collector = EventCollector::new();
    for &addr in &addrs {
        collector.register_node(addr);
    }

    // Spawn nodes. Each node knows about all others as bootstrap peers.
    let mut shutdown_txs = Vec::new();
    for (i, transport) in transports.into_iter().enumerate() {
        let peers: Vec<SocketAddr> = addrs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, a)| *a)
            .collect();
        let (stx, srx) = oneshot::channel();
        shutdown_txs.push(stx);
        let cfg = config.clone();
        tokio::spawn(async move {
            let node = Node::new(transport, cfg, &peers);
            run_node(node, srx).await;
        });
    }

    // Drop our copy of event_tx so the channel closes when all nodes stop.
    drop(event_tx);

    // Run for the specified duration, collecting events.
    let duration = Duration::from_secs(args.duration);
    let deadline = tokio::time::Instant::now() + duration;

    eprintln!("Running {} nodes for {}s...", args.nodes, args.duration);

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            event = event_rx.recv() => {
                match event {
                    Some(e) => collector.add_event(e),
                    None => break,
                }
            }
        }
    }

    // Shut down all nodes.
    for tx in shutdown_txs {
        let _ = tx.send(());
    }

    // Small delay to let final messages drain.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Drain remaining events.
    while let Ok(e) = event_rx.try_recv() {
        collector.add_event(e);
    }

    collector.finalize();

    let output = match args.format.as_str() {
        "dot" | "graphviz" => collector.format_dot(),
        "json" => collector.format_json(),
        _ => collector.format_text(),
    };

    // Write output.
    match args.output {
        Some(path) => {
            std::fs::write(&path, &output).expect("failed to write output file");
            eprintln!("Output written to {path}");
        }
        None => print!("{output}"),
    }
}
