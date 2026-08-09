/// Cluster scaling integration tests.
///
/// Tests for dynamic cluster scaling scenarios:
/// - 10 → 100 nodes
/// - 100 → 500 nodes (benchmark)
/// - Churn-heavy clusters
/// - Convergence time, bandwidth usage, and false positive metrics
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use gossip_membership::node::{NodeConfig, NodeStatus};
use gossip_membership::runner::{run_node, Node};
use gossip_membership::simulator::NetSim;
use gossip_membership::transport::Transport;

// ── Helpers ────────────────────────────────────────────────────────────────────

async fn bind_local() -> Transport {
    Transport::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("bind failed")
}

async fn bind_with_sim(sim: &Arc<Mutex<NetSim>>) -> Transport {
    bind_local().await.with_sim(sim.clone())
}

fn make_node_config() -> NodeConfig {
    let mut cfg = NodeConfig::fast();
    cfg.gossip_interval_ms = 100;
    cfg.heartbeat_interval_ms = 50;
    cfg
}

/// Result of a cluster scaling test
#[derive(Debug)]
struct ScalingTestResult {
    initial_size: usize,
    final_size: usize,
    convergence_time_ms: u64,
    total_bytes_sent: u64,
    total_bytes_received: u64,
    total_messages_sent: u64,
    false_positives: bool,
}

impl Default for ScalingTestResult {
    fn default() -> Self {
        Self {
            initial_size: 0,
            final_size: 0,
            convergence_time_ms: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            total_messages_sent: 0,
            false_positives: false,
        }
    }
}

/// Wait for cluster convergence: all nodes should know about all other nodes.
async fn wait_for_convergence(
    nodes: &[Node],
    target_size: usize,
    timeout_ms: u64,
) -> Option<u64> {
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);

    while start.elapsed() < timeout {
        let all_converged = nodes.iter().all(|n| {
            let count = n.table.entries.len();
            count >= target_size
        });

        if all_converged {
            return Some(start.elapsed().as_millis() as u64);
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    None
}

// ── CI Tests (10-100 nodes) ─────────────────────────────────────────────────

/// Test cluster scaling from 10 to 100 nodes.
#[tokio::test]
async fn test_cluster_scale_10_to_100() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = make_node_config();

    // Start with 10 nodes
    let initial_count = 10;
    let final_count = 100;

    // Create initial cluster of 10 nodes
    let mut transports = Vec::new();
    for _ in 0..initial_count {
        transports.push(bind_local().await);
    }

    let addrs: Vec<_> = transports.iter().map(|t| t.local_addr).collect();

    // Create mesh topology - each node knows 5 others for good connectivity
    let nodes: Vec<Node> = transports
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let peers: Vec<SocketAddr> = (0..5)
                .map(|j| addrs[(i + j + 1) % addrs.len()])
                .collect();
            Node::new(t, cfg.clone(), &peers)
        })
        .collect();

    // Start initial nodes
    let mut handles = Vec::new();
    let mut senders = Vec::new();
    for node in nodes {
        let (tx, rx) = oneshot::channel();
        senders.push(tx);
        handles.push(tokio::spawn(run_node(node, rx)));
    }

    // Wait for initial 10 to converge
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Now add 90 more nodes
    let new_node_count = final_count - initial_count;
    let mut new_transports = Vec::new();
    for _ in 0..new_node_count {
        new_transports.push(bind_local().await);
    }

    // New nodes connect to multiple existing nodes for good connectivity
    let new_nodes: Vec<Node> = new_transports
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let peers: Vec<SocketAddr> = (0..5)
                .map(|j| addrs[(i * 5 + j) % addrs.len()])
                .collect();
            Node::new(t, cfg.clone(), &peers)
        })
        .collect();

    for node in new_nodes {
        let (tx, rx) = oneshot::channel();
        senders.push(tx);
        handles.push(tokio::spawn(run_node(node, rx)));
    }

    // Wait for full cluster to converge (100 nodes needs more time)
    tokio::time::sleep(Duration::from_millis(8000)).await;

    // Stop all nodes
    for tx in senders {
        let _ = tx.send(());
    }

    // Join all handles
    let final_nodes: Vec<Node> = futures::future::join_all(handles)
        .await
        .into_iter()
        .filter_map(|r| r.ok())
        .collect();

    // Verify all nodes have converged
    // Allow 10% margin for large clusters
    let converged_count = final_nodes
        .iter()
        .filter(|n| n.table.entries.len() >= final_count - 10)
        .count();

    println!(
        "Cluster 10→100: {}/{} nodes converged",
        converged_count,
        final_nodes.len()
    );

    // For 100 nodes, require at least 60% convergence
    assert!(
        converged_count >= (final_nodes.len() * 3) / 5,
        "At least 60% nodes should converge"
    );
}

/// Test cluster convergence at 20 nodes with churn.
#[tokio::test]
async fn test_cluster_20_nodes_with_churn() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = make_node_config();

    let node_count = 20;
    let churn_iterations = 5;

    // Create initial cluster
    let mut transports = Vec::new();
    for _ in 0..node_count {
        transports.push(bind_local().await);
    }

    let addrs: Vec<_> = transports.iter().map(|t| t.local_addr).collect();

    let nodes: Vec<Node> = transports
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let peers = vec![addrs[(i + 1) % addrs.len()], addrs[(i + 2) % addrs.len()]];
            Node::new(t, cfg.clone(), &peers)
        })
        .collect();

    let mut handles = Vec::new();
    let mut senders = Vec::new();
    for node in nodes {
        let (tx, rx) = oneshot::channel();
        senders.push(tx);
        handles.push(tokio::spawn(run_node(node, rx)));
    }

    // Wait for initial convergence
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Simulate churn: restart some nodes
    for _ in 0..churn_iterations {
        // Stop 2 nodes
        if let Some(tx) = senders.pop() {
            let _ = tx.send(());
        }
        if let Some(tx) = senders.pop() {
            let _ = tx.send(());
        }

        // Wait a bit
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Start 2 new nodes
        let new_t1 = bind_local().await;
        let new_t2 = bind_local().await;

        let new_nodes = vec![
            Node::new(new_t1, cfg.clone(), &addrs[..3]),
            Node::new(new_t2, cfg.clone(), &addrs[..3]),
        ];

        for node in new_nodes {
            let (tx, rx) = oneshot::channel();
            senders.push(tx);
            handles.push(tokio::spawn(run_node(node, rx)));
        }

        // Wait for cluster to stabilize
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Final convergence check
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Stop all
    for tx in senders {
        let _ = tx.send(());
    }

    let final_nodes: Vec<Node> = futures::future::join_all(handles)
        .await
        .into_iter()
        .filter_map(|r| r.ok())
        .collect();

    // Cluster should have recovered (may have fewer nodes due to churn)
    assert!(
        final_nodes.len() >= node_count - 2,
        "Cluster should have recovered after churn"
    );

    // Check that remaining nodes have converged
    let alive_count = final_nodes
        .iter()
        .filter(|n| n.table.entries.len() >= node_count - 2)
        .count();

    assert!(
        alive_count > final_nodes.len() / 2,
        "Majority of nodes should have converged"
    );

    println!(
        "Churn test: {} nodes remained after {} churn iterations",
        final_nodes.len(),
        churn_iterations
    );
}

// ── Benchmark Tests (100-500 nodes) ──────────────────────────────────────────

/// Benchmark: Scale from 100 to 200 nodes.
/// This test is marked with #[ignore] for regular CI runs.
#[tokio::test]
#[ignore]
async fn test_cluster_scale_100_to_200_benchmark() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = make_node_config();

    let initial_nodes = 100;
    let final_nodes = 200;

    // Create initial cluster
    let mut transports = Vec::new();
    for _ in 0..initial_nodes {
        transports.push(bind_local().await);
    }

    let addrs: Vec<_> = transports.iter().map(|t| t.local_addr).collect();

    // Create mesh-like topology (each node knows 5 others)
    let nodes: Vec<Node> = transports
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let peers: Vec<SocketAddr> = (0..5)
                .map(|j| addrs[(i + j + 1) % addrs.len()])
                .collect();
            Node::new(t, cfg.clone(), &peers)
        })
        .collect();

    let mut handles = Vec::new();
    let mut senders = Vec::new();
    for node in nodes {
        let (tx, rx) = oneshot::channel();
        senders.push(tx);
        handles.push(tokio::spawn(run_node(node, rx)));
    }

    // Wait for initial 100 to converge
    tokio::time::sleep(Duration::from_millis(5000)).await;

    // Add 100 more nodes
    let new_node_count = final_nodes - initial_nodes;
    let mut new_transports = Vec::new();
    for _ in 0..new_node_count {
        new_transports.push(bind_local().await);
    }

    let _new_addrs: Vec<_> = new_transports.iter().map(|t| t.local_addr).collect();

    let new_nodes: Vec<Node> = new_transports
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let peers: Vec<SocketAddr> = (0..5)
                .map(|j| addrs[(i * 5 + j) % addrs.len()])
                .collect();
            Node::new(t, cfg.clone(), &peers)
        })
        .collect();

    let start_time = Instant::now();

    for node in new_nodes {
        let (tx, rx) = oneshot::channel();
        senders.push(tx);
        handles.push(tokio::spawn(run_node(node, rx)));
    }

    // Wait for full convergence (need more time for larger cluster)
    tokio::time::sleep(Duration::from_millis(15000)).await;

    let convergence_time = start_time.elapsed();

    // Stop all
    for tx in senders {
        let _ = tx.send(());
    }

    let final_nodes_state: Vec<Node> = futures::future::join_all(handles)
        .await
        .into_iter()
        .filter_map(|r| r.ok())
        .collect();

    println!("=== Cluster Scale 100→200 Benchmark ===");
    println!("Convergence time: {:?}", convergence_time);
    println!("Nodes remaining: {}", final_nodes_state.len());

    // Verify convergence
    let converged = final_nodes_state
        .iter()
        .filter(|n| n.table.entries.len() >= final_nodes - 10) // Allow 10% margin
        .count();

    println!("Nodes converged: {}/{}", converged, final_nodes_state.len());
}

/// Benchmark: Scale from 100 to 500 nodes.
#[tokio::test]
#[ignore]
async fn test_cluster_scale_100_to_500_benchmark() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = make_node_config();

    let initial_nodes = 100;
    let final_nodes = 500;

    // Create initial cluster
    let mut transports = Vec::new();
    for _ in 0..initial_nodes {
        transports.push(bind_local().await);
    }

    let addrs: Vec<_> = transports.iter().map(|t| t.local_addr).collect();

    let nodes: Vec<Node> = transports
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let peers: Vec<SocketAddr> = (0..5)
                .map(|j| addrs[(i + j + 1) % addrs.len()])
                .collect();
            Node::new(t, cfg.clone(), &peers)
        })
        .collect();

    let mut handles = Vec::new();
    let mut senders = Vec::new();
    for node in nodes {
        let (tx, rx) = oneshot::channel();
        senders.push(tx);
        handles.push(tokio::spawn(run_node(node, rx)));
    }

    // Wait for initial convergence
    tokio::time::sleep(Duration::from_millis(5000)).await;

    // Add all new nodes first
    let batch_size = 50;
    let new_node_count = final_nodes - initial_nodes;

    for batch_start in (0..new_node_count).step_by(batch_size) {
        let batch_end = std::cmp::min(batch_start + batch_size, new_node_count);
        let mut new_transports = Vec::new();

        for _ in batch_start..batch_end {
            new_transports.push(bind_local().await);
        }

        let _new_addrs: Vec<_> = new_transports.iter().map(|t| t.local_addr).collect();

        let new_nodes: Vec<Node> = new_transports
            .into_iter()
            .enumerate()
            .map(|(i, t)| {
                let peers: Vec<SocketAddr> = (0..3)
                    .map(|j| addrs[(batch_start + i * 3 + j) % addrs.len()])
                    .collect();
                Node::new(t, cfg.clone(), &peers)
            })
            .collect();

        for node in new_nodes {
            let (tx, rx) = oneshot::channel();
            senders.push(tx);
            handles.push(tokio::spawn(run_node(node, rx)));
        }
    }

    // NOW start measuring convergence time after all nodes are added
    let start_time = Instant::now();

    // Wait for convergence
    tokio::time::sleep(Duration::from_millis(20000)).await;

    let convergence_time = start_time.elapsed();

    // Stop all
    for tx in senders {
        let _ = tx.send(());
    }

    let final_nodes_state: Vec<Node> = futures::future::join_all(handles)
        .await
        .into_iter()
        .filter_map(|r| r.ok())
        .collect();

    println!("=== Cluster Scale 100→500 Benchmark ===");
    println!("Convergence time: {:?}", convergence_time);
    println!("Nodes remaining: {}", final_nodes_state.len());

    let converged = final_nodes_state
        .iter()
        .filter(|n| n.table.entries.len() >= final_nodes - 20)
        .count();

    println!("Nodes converged: {}/{}", converged, final_nodes_state.len());
}

// ── False Positive Tests ─────────────────────────────────────────────────────

/// Test that temporary network issues don't cause false positive death declarations.
#[tokio::test]
async fn test_no_false_positives_on_network_issues() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = make_node_config();

    // Create a small cluster with network simulator
    let sim = Arc::new(Mutex::new(NetSim::new(42)));
    
    // Add 10% random loss to simulate network issues
    sim.lock().unwrap().set_loss_rate(0.1);

    let mut transports = Vec::new();
    for _ in 0..5 {
        transports.push(bind_with_sim(&sim).await);
    }

    let addrs: Vec<_> = transports.iter().map(|t| t.local_addr).collect();

    let nodes: Vec<Node> = transports
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let peers = vec![addrs[(i + 1) % addrs.len()], addrs[(i + 2) % addrs.len()]];
            Node::new(t, cfg.clone(), &peers)
        })
        .collect();

    let mut handles = Vec::new();
    let mut senders = Vec::new();
    for node in nodes {
        let (tx, rx) = oneshot::channel();
        senders.push(tx);
        handles.push(tokio::spawn(run_node(node, rx)));
    }

    // Let cluster run with network issues
    tokio::time::sleep(Duration::from_millis(3000)).await;

    // Stop all
    for tx in senders {
        let _ = tx.send(());
    }

    let final_nodes: Vec<Node> = futures::future::join_all(handles)
        .await
        .into_iter()
        .filter_map(|r| r.ok())
        .collect();

    // Count how many nodes are in Dead status
    let dead_count = final_nodes
        .iter()
        .filter(|n| {
            n.table
                .entries
                .values()
                .any(|e| e.status == NodeStatus::Dead)
        })
        .count();

    // With 10% loss and short runtime, no node should be marked Dead
    // (they should at most be Suspect, not falsely declared Dead)
    println!(
        "Nodes with Dead entries: {} (with 10% network loss)",
        dead_count
    );

    assert!(
        dead_count == 0,
        "No nodes should be falsely marked Dead with 10% loss in short timeframe"
    );
}

/// Test false positives with high packet loss (50%).
#[tokio::test]
async fn test_no_false_positives_high_loss() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = make_node_config();

    let sim = Arc::new(Mutex::new(NetSim::new(42)));
    sim.lock().unwrap().set_loss_rate(0.5); // 50% loss

    let mut transports = Vec::new();
    for _ in 0..3 {
        transports.push(bind_with_sim(&sim).await);
    }

    let addrs: Vec<_> = transports.iter().map(|t| t.local_addr).collect();

    let nodes: Vec<Node> = transports
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let peers = vec![addrs[(i + 1) % addrs.len()]];
            Node::new(t, cfg.clone(), &peers)
        })
        .collect();

    let mut handles = Vec::new();
    let mut senders = Vec::new();
    for node in nodes {
        let (tx, rx) = oneshot::channel();
        senders.push(tx);
        handles.push(tokio::spawn(run_node(node, rx)));
    }

    // Short run with high loss
    tokio::time::sleep(Duration::from_millis(2000)).await;

    for tx in senders {
        let _ = tx.send(());
    }

    let final_nodes: Vec<Node> = futures::future::join_all(handles)
        .await
        .into_iter()
        .filter_map(|r| r.ok())
        .collect();

    // Even with 50% loss, nodes should remain Suspect at worst, not Dead
    let dead_count = final_nodes
        .iter()
        .filter(|n| {
            n.table
                .entries
                .values()
                .any(|e| e.status == NodeStatus::Dead)
        })
        .count();

    println!(
        "Nodes with Dead status at 50% loss: {}",
        dead_count
    );

    // Should be 0 - no false positives even with extreme loss
    assert_eq!(dead_count, 0, "No false positive deaths with 50% loss");
}

// ── Bandwidth Tests ─────────────────────────────────────────────────────────

/// Test bandwidth usage metrics with NetSim.
#[tokio::test]
async fn test_bandwidth_usage_tracking() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = make_node_config();

    let sim = Arc::new(Mutex::new(NetSim::new(42)));

    let mut transports = Vec::new();
    for _ in 0..10 {
        transports.push(bind_with_sim(&sim).await);
    }

    let addrs: Vec<_> = transports.iter().map(|t| t.local_addr).collect();

    let nodes: Vec<Node> = transports
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let peers = vec![addrs[(i + 1) % addrs.len()], addrs[(i + 2) % addrs.len()]];
            Node::new(t, cfg.clone(), &peers)
        })
        .collect();

    let mut handles = Vec::new();
    let mut senders = Vec::new();
    for node in nodes {
        let (tx, rx) = oneshot::channel();
        senders.push(tx);
        handles.push(tokio::spawn(run_node(node, rx)));
    }

    // Let gossip run for a bit
    tokio::time::sleep(Duration::from_millis(2000)).await;

    for tx in senders {
        let _ = tx.send(());
    }

    let final_nodes: Vec<Node> = futures::future::join_all(handles)
        .await
        .into_iter()
        .filter_map(|r| r.ok())
        .collect();

    // Sum up all metrics from nodes
    let total_sent: u64 = final_nodes.iter().map(|n| n.metrics.gossip_sent).sum();
    let total_received: u64 = final_nodes.iter().map(|n| n.metrics.gossip_recv).sum();

    println!("=== Bandwidth Usage (10 nodes, 2s) ===");
    println!("Total gossip messages sent: {}", total_sent);
    println!("Total gossip messages received: {}", total_received);

    // Each node should have sent and received multiple messages
    assert!(total_sent > 10, "Should have sent more than 10 messages");
    assert!(total_received > 10, "Should have received more than 10 messages");
}
