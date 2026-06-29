//! 3-node Raft demo cluster (all in one process, connected over TCP).
//!
//! Each node binds a real `TcpListener` on a loopback port, so traffic goes
//! through the OS network stack even though all three nodes live in the same
//! process.  This makes the demo runnable with a single `cargo run --bin
//! raft_demo` while still exercising the full TCP transport.
//!
//! What the demo does:
//! 1. Starts nodes 1, 2, 3 on ports 7001–7003.
//! 2. Waits for one of them to win the election (≤ 1 s).
//! 3. Proposes 5 log entries through the leader.
//! 4. Waits for replication to complete.
//! 5. Prints the final state of all three nodes.
//! 6. Simulates a leader crash by cancelling its task.
//! 7. Waits for re-election and prints the new leader.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time;

use raft_consensus::node::ClusterConfig;
use raft_consensus::transport::{LiveNodeState, NodeHandle, NodeRunner};

// ── Config ────────────────────────────────────────────────────────────────────

const TICK_MS: u64 = 10;

fn demo_config() -> ClusterConfig {
    ClusterConfig {
        election_timeout_min: 15,
        election_timeout_max: 30,
        heartbeat_interval: 5,
        pre_vote: false,
    }
}

// ── Per-node topology ─────────────────────────────────────────────────────────

struct NodeDesc {
    id: u64,
    bind: SocketAddr,
    peers: Vec<(u64, SocketAddr)>,
}

fn topology() -> Vec<NodeDesc> {
    let addrs: Vec<SocketAddr> = (1u64..=3)
        .map(|i| format!("127.0.0.1:{}", 7000 + i).parse().unwrap())
        .collect();

    (0..3)
        .map(|i| {
            let id = i as u64 + 1;
            let peers = (0..3usize)
                .filter(|&j| j != i)
                .map(|j| (j as u64 + 1, addrs[j]))
                .collect();
            NodeDesc {
                id,
                bind: addrs[i],
                peers,
            }
        })
        .collect()
}

// ── Demo harness ──────────────────────────────────────────────────────────────

struct RunningNode {
    handle: NodeHandle,
    state: Arc<Mutex<LiveNodeState>>,
    task: JoinHandle<()>,
}

async fn start_node(desc: NodeDesc) -> RunningNode {
    let (runner, handle) = NodeRunner::new(
        desc.id,
        desc.peers,
        desc.bind,
        demo_config(),
        TICK_MS,
    )
    .await
    .expect("NodeRunner::new should not fail on loopback");

    let state: Arc<Mutex<LiveNodeState>> = Default::default();
    let state_clone = Arc::clone(&state);

    let task = tokio::spawn(runner.run_with_state(state_clone));
    RunningNode { handle, state, task }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Poll `nodes` until one is the leader, waiting up to `timeout`.
/// Returns the index into `nodes` of the leader, or `None` on timeout.
async fn wait_for_leader(nodes: &[&RunningNode], timeout: Duration) -> Option<usize> {
    let deadline = time::Instant::now() + timeout;
    loop {
        for (i, n) in nodes.iter().enumerate() {
            if n.state.lock().unwrap().is_leader {
                return Some(i);
            }
        }
        if time::Instant::now() >= deadline {
            return None;
        }
        time::sleep(Duration::from_millis(50)).await;
    }
}

fn print_state_indexed(label: &str, nodes: &[(u64, &RunningNode)]) {
    println!("\n── {label} ──");
    for (id, n) in nodes {
        let s = n.state.lock().unwrap();
        let role = if s.is_leader { "LEADER  " } else { "follower" };
        let lid = n.handle.metrics.leader_id();
        let term = n.handle.metrics.current_term();
        println!(
            "  node {id} | {role} | term={term:2} | commit={:2} | known_leader={lid}",
            s.commit_index,
        );
    }
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // ── Phase 1: start all 3 nodes ────────────────────────────────────────────
    println!("Starting 3-node Raft cluster on 127.0.0.1:7001-7003 …");
    let descs = topology();
    let mut nodes: Vec<(u64, RunningNode)> = Vec::new();
    for desc in descs {
        let id = desc.id;
        let node = start_node(desc).await;
        println!("  node {id} listening on {}", node.handle.bound_addr);
        nodes.push((id, node));
    }

    // ── Phase 2: wait for first election ─────────────────────────────────────
    println!("\nWaiting for leader election …");
    let node_refs: Vec<&RunningNode> = nodes.iter().map(|(_, n)| n).collect();
    let leader_idx = wait_for_leader(&node_refs, Duration::from_secs(3))
        .await
        .expect("no leader elected within 3 seconds");

    let leader_id = nodes[leader_idx].0;
    println!("  Leader elected: node {leader_id}");
    print_state_indexed(
        "After election",
        &nodes.iter().map(|(id, n)| (*id, n)).collect::<Vec<_>>(),
    );

    // ── Phase 3: propose 5 entries through the leader ─────────────────────────
    println!("\nProposing 5 log entries through node {leader_id} …");
    let leader_handle = &nodes[leader_idx].1.handle;
    for i in 1u32..=5 {
        let payload = format!("entry-{i}").into_bytes();
        leader_handle.propose(payload);
    }

    // Allow time for replication (heartbeat interval = 50 ms, a few rounds).
    time::sleep(Duration::from_millis(600)).await;

    print_state_indexed(
        "After replication",
        &nodes.iter().map(|(id, n)| (*id, n)).collect::<Vec<_>>(),
    );

    // ── Phase 4: simulate leader crash ───────────────────────────────────────
    println!("\nSimulating crash of leader (node {leader_id}) …");
    let crashed_task = &nodes[leader_idx].1.task;
    crashed_task.abort();

    // Give remaining nodes time to detect the timeout and elect a new leader.
    time::sleep(Duration::from_millis(1_000)).await;

    let survivors: Vec<(u64, &RunningNode)> = nodes
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != leader_idx)
        .map(|(_, (id, n))| (*id, n))
        .collect();

    let survivor_refs: Vec<&RunningNode> = survivors.iter().map(|(_, n)| *n).collect();
    if let Some(new_leader_local) = wait_for_leader(&survivor_refs, Duration::from_secs(3)).await {
        let new_leader_id = survivors[new_leader_local].0;
        println!("  New leader elected: node {new_leader_id}");
    } else {
        println!("  WARNING: no new leader elected within 3 seconds");
    }

    print_state_indexed("After re-election (survivors only)", &survivors);

    println!("\nDemo complete.");
}
