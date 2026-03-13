/// Integration tests for the gossip membership protocol.
///
/// Each test spawns multiple in-process nodes (real UDP sockets on 127.0.0.1:0),
/// allows gossip to converge, then asserts on the final membership tables.
/// This mirrors the pattern in tcp-over-udp's `tests/gbn_tests.rs`.
///
/// Note: NodeConfig::fast() is used so tests complete in < 2 seconds.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::sync::oneshot;

use gossip_membership::membership::MembershipTable;
use gossip_membership::node::{NodeConfig, NodeStatus};
use gossip_membership::transport::Transport;

// Re-export the public run_node from main is not possible directly; we use
// the library's public items and duplicate the minimal harness here.
// The Node and run_node are pub in main.rs (compiled as a binary).
// For tests we use the library crate's public surface and copy the runner.
use gossip_membership::{
    failure_detector::FailureDetector,
    gossip,
    membership::{placeholder_id_for, wire_to_node_state},
    message::{build_ack, build_ping, build_ping_req, MessagePayload},
    node::{generate_node_id, NodeState},
};

// ── Minimal in-test node runner ───────────────────────────────────────────────
// We inline a stripped copy of run_node so the test crate does not need to
// import from the binary crate.  (Importing from a [[bin]] is not supported.)

pub struct TestNode {
    pub id: u64,
    pub config: NodeConfig,
    transport: Transport,
    pub table: MembershipTable,
    failure_det: FailureDetector,
}

impl TestNode {
    pub fn new(transport: Transport, config: NodeConfig, peers: &[SocketAddr]) -> Self {
        let id = generate_node_id(transport.local_addr);
        let mut table = MembershipTable::new(id, transport.local_addr);
        for &p in peers {
            table.add_bootstrap_peer(p);
        }
        let failure_det = FailureDetector::new(Duration::from_millis(config.probe_timeout_ms));
        Self { id, config, transport, table, failure_det }
    }
}

pub async fn run_test_node(
    mut node: TestNode,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> TestNode {
    let mut gossip_tick =
        tokio::time::interval(Duration::from_millis(node.config.gossip_interval_ms));
    let mut hb_tick =
        tokio::time::interval(Duration::from_millis(node.config.heartbeat_interval_ms));
    let mut probe_tick =
        tokio::time::interval(Duration::from_millis(node.config.probe_interval_ms));
    gossip_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    hb_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    probe_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,

            result = node.transport.recv_from() => {
                if let Ok((msg, from)) = result {
                    // Clean up any bootstrap placeholder before inserting real entry.
                    node.table.remove_placeholder_for_addr(from, msg.sender_id);
                    // Record sender liveness.
                    let alive = NodeState::new_alive(msg.sender_id, from, msg.sender_heartbeat);
                    node.table.merge_entry(&alive);
                    node.failure_det.record_ack(msg.sender_id);

                    match &msg.payload {
                        MessagePayload::Gossip(entries) => {
                            let states: Vec<_> = entries.iter().filter_map(wire_to_node_state).collect();
                            node.table.merge_digest(&states);
                        }
                        MessagePayload::Ping => {
                            let ack = build_ack(node.id, node.table.our_heartbeat());
                            let _ = node.transport.send_to(&ack, from).await;
                        }
                        MessagePayload::PingReq(req) => {
                            let ping = build_ping(node.id, node.table.our_heartbeat());
                            let _ = node.transport.send_to(&ping, SocketAddr::V4(req.target_addr)).await;
                        }
                        MessagePayload::Ack => {}
                    }
                }
            }

            _ = hb_tick.tick() => {
                node.table.tick_heartbeat();
            }

            _ = gossip_tick.tick() => {
                if let Some((_, peer_addr)) = gossip::pick_random_peer(&node.table, node.id) {
                    let msg = gossip::build_gossip_message(
                        &node.table, node.id, node.table.our_heartbeat(), node.config.gossip_fanout,
                    );
                    let _ = node.transport.send_to(&msg, peer_addr).await;
                }
            }

            _ = probe_tick.tick() => {
                use std::time::Instant;
                let scan = node.failure_det.scan(Instant::now());
                for id in scan.escalate_to_indirect {
                    if let Some(target_state) = node.table.entries.get(&id) {
                        if let SocketAddr::V4(target_addr) = target_state.addr {
                            let intermediaries = gossip::pick_k_random_peers(
                                &node.table, node.id, id, node.config.indirect_probe_k,
                            );
                            for (_, inter_addr) in &intermediaries {
                                let req = build_ping_req(node.id, node.table.our_heartbeat(), id, target_addr);
                                let _ = node.transport.send_to(&req, *inter_addr).await;
                            }
                            if !intermediaries.is_empty() {
                                node.failure_det.record_indirect_probe_sent(id);
                            }
                        }
                    }
                }
                for id in scan.declare_suspect {
                    node.table.suspect(id);
                }
                for id in node.table.expired_suspects(Duration::from_millis(node.config.suspect_timeout_ms)) {
                    node.table.declare_dead(id);
                }
                node.table.gc_dead(Duration::from_millis(node.config.dead_retention_ms));

                if let Some((target_id, target_addr)) = gossip::pick_random_peer(&node.table, node.id) {
                    if !node.failure_det.is_probing(target_id) {
                        let ping = build_ping(node.id, node.table.our_heartbeat());
                        if node.transport.send_to(&ping, target_addr).await.is_ok() {
                            node.failure_det.record_probe_sent(target_id);
                        }
                    }
                }
            }
        }
    }
    node
}

// ── Helper ─────────────────────────────────────────────────────────────────────
async fn bind_local() -> Transport {
    Transport::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("bind failed")
}

// ── Tests ──────────────────────────────────────────────────────────────────────

/// Two nodes bootstrap with each other's address; after a short wait both
/// should know about the other.
#[tokio::test]
async fn test_two_nodes_discover_each_other() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();

    let t1 = bind_local().await;
    let t2 = bind_local().await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    let n1 = TestNode::new(t1, cfg.clone(), &[addr2]);
    let n2 = TestNode::new(t2, cfg.clone(), &[addr1]);
    let id1 = n1.id;
    let id2 = n2.id;

    let (tx1, rx1) = oneshot::channel::<()>();
    let (tx2, rx2) = oneshot::channel::<()>();

    let h1 = tokio::spawn(run_test_node(n1, rx1));
    let h2 = tokio::spawn(run_test_node(n2, rx2));

    // Allow several gossip rounds to complete.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());

    let node1 = h1.await.unwrap();
    let node2 = h2.await.unwrap();

    // Each node should have learned about the other.
    assert!(
        node1.table.entries.values().any(|e| e.node_id == id2),
        "node1 does not know about node2"
    );
    assert!(
        node2.table.entries.values().any(|e| e.node_id == id1),
        "node2 does not know about node1"
    );
}

/// Three nodes with full peer seeding should converge: every node knows all others.
#[tokio::test]
async fn test_three_nodes_converge() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();

    let t1 = bind_local().await;
    let t2 = bind_local().await;
    let t3 = bind_local().await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;
    let addr3 = t3.local_addr;

    let n1 = TestNode::new(t1, cfg.clone(), &[addr2, addr3]);
    let n2 = TestNode::new(t2, cfg.clone(), &[addr1, addr3]);
    let n3 = TestNode::new(t3, cfg.clone(), &[addr1, addr2]);
    let id1 = n1.id;
    let id2 = n2.id;
    let id3 = n3.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();

    let h1 = tokio::spawn(run_test_node(n1, rx1));
    let h2 = tokio::spawn(run_test_node(n2, rx2));
    let h3 = tokio::spawn(run_test_node(n3, rx3));

    tokio::time::sleep(Duration::from_millis(800)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());
    let _ = tx3.send(());

    let node1 = h1.await.unwrap();
    let node2 = h2.await.unwrap();
    let node3 = h3.await.unwrap();

    for (name, node, expect_ids) in [
        ("node1", &node1, [id2, id3]),
        ("node2", &node2, [id1, id3]),
        ("node3", &node3, [id1, id2]),
    ] {
        for eid in expect_ids {
            let found = node.table.entries.values().any(|e| e.node_id == eid);
            assert!(found, "{name} does not know about node {eid}");
        }
    }
}

/// A node that is seeded with only one peer (ring topology) should still
/// discover the third node through gossip propagation.
#[tokio::test]
async fn test_gossip_propagation_ring() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();

    let t1 = bind_local().await;
    let t2 = bind_local().await;
    let t3 = bind_local().await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;
    let addr3 = t3.local_addr;

    // Ring: 1→2→3→1
    let n1 = TestNode::new(t1, cfg.clone(), &[addr2]);
    let n2 = TestNode::new(t2, cfg.clone(), &[addr3]);
    let n3 = TestNode::new(t3, cfg.clone(), &[addr1]);
    let id1 = n1.id;
    let id2 = n2.id;
    let id3 = n3.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();

    let h1 = tokio::spawn(run_test_node(n1, rx1));
    let h2 = tokio::spawn(run_test_node(n2, rx2));
    let h3 = tokio::spawn(run_test_node(n3, rx3));

    // Ring convergence requires multiple hops — allow more time.
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());
    let _ = tx3.send(());

    let node1 = h1.await.unwrap();
    let _node2 = h2.await.unwrap();
    let node3 = h3.await.unwrap();

    // Node1 must have learned about node3 through node2 (gossip propagation).
    assert!(
        node1.table.entries.values().any(|e| e.node_id == id3),
        "ring: node1 did not learn about node3 via gossip"
    );
    assert!(
        node3.table.entries.values().any(|e| e.node_id == id2),
        "ring: node3 did not learn about node2 via gossip"
    );
    // Suppress unused variable warnings.
    let _ = (id1, id2);
}

/// Dead merge rule: once a node is Dead in one table it should remain Dead
/// even if a gossip with a higher-heartbeat Alive entry arrives.
#[tokio::test]
async fn test_dead_is_terminal_in_merge() {
    use gossip_membership::membership::MembershipTable;
    use gossip_membership::node::{NodeState, NodeStatus};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let self_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000);
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9001);
    let mut table = MembershipTable::new(1, self_addr);

    // Insert peer as Dead.
    let mut dead = NodeState::new_alive(2, peer_addr, 10);
    dead.status = NodeStatus::Dead;
    table.merge_entry(&dead);
    assert_eq!(table.entries[&2].status, NodeStatus::Dead);

    // Attempt resurrection with a higher heartbeat.
    table.merge_entry(&NodeState::new_alive(2, peer_addr, 20));
    assert_eq!(table.entries[&2].status, NodeStatus::Dead, "Dead must be terminal");
}

/// Heartbeat counter wraps around u32::MAX without panicking.
#[tokio::test]
async fn test_heartbeat_wraps() {
    use gossip_membership::membership::MembershipTable;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000);
    let mut table = MembershipTable::new(1, addr);

    // Manually set heartbeat near overflow.
    table.entries.get_mut(&1).unwrap().heartbeat = u32::MAX - 1;
    // Access local_heartbeat via our_heartbeat() then simulate two ticks.
    // We drive tick_heartbeat directly.
    table.tick_heartbeat();
    table.tick_heartbeat(); // wraps to 1 (0 after MAX, then 1)
    // No panic is the assertion — wrapping_add is used internally.
    assert!(table.our_heartbeat() < 10); // wrapped
}

/// Failure detection: a node with a stale heartbeat that never updates should
/// eventually be marked Suspect.
#[tokio::test]
async fn test_failure_detection_suspect() {
    let _ = env_logger::builder().is_test(true).try_init();

    // Use very short timeouts.
    let mut cfg = NodeConfig::fast();
    cfg.probe_timeout_ms = 30;
    cfg.suspect_timeout_ms = 200;

    let t1 = bind_local().await;
    let t2 = bind_local().await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    let n1 = TestNode::new(t1, cfg.clone(), &[addr2]);
    let n2 = TestNode::new(t2, cfg.clone(), &[addr1]);
    let id2 = n2.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    // Start node1; node2 starts but we shut it down quickly so it stops responding.
    let h1 = tokio::spawn(run_test_node(n1, rx1));
    let h2 = tokio::spawn(run_test_node(n2, rx2));

    // Let them discover each other first.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Kill node2 (stop responding).
    let _ = tx2.send(());
    h2.await.unwrap();

    // Wait for node1 to detect the failure.
    tokio::time::sleep(Duration::from_millis(600)).await;

    let _ = tx1.send(());
    let node1 = h1.await.unwrap();

    let status = node1
        .table
        .entries
        .values()
        .find(|e| e.node_id == id2)
        .map(|e| e.status);

    assert!(
        matches!(status, Some(NodeStatus::Suspect) | Some(NodeStatus::Dead)),
        "node2 should be Suspect or Dead after silence, got {status:?}"
    );
}

/// Gossip message encode/decode roundtrip for the common case.
#[tokio::test]
async fn test_gossip_message_encode_decode() {
    use gossip_membership::message::{
        build_gossip, Message, MessagePayload, WireNodeEntry, status,
    };
    use std::net::Ipv4Addr;

    let entry = WireNodeEntry {
        node_id: 12345,
        heartbeat: 7,
        incarnation: 0,
        status: status::ALIVE,
        ip: u32::from(Ipv4Addr::new(127, 0, 0, 1)),
        port: 8080,
    };
    let msg = build_gossip(42, 3, vec![entry.clone()]);
    let buf = msg.encode().unwrap();
    let decoded = Message::decode(&buf).unwrap();
    assert_eq!(decoded.sender_id, 42);
    assert_eq!(decoded.sender_heartbeat, 3);
    match decoded.payload {
        MessagePayload::Gossip(entries) => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0], entry);
        }
        _ => panic!("expected Gossip payload"),
    }
}

/// Merging 5 nodes worth of gossip into one table produces the correct live count.
#[tokio::test]
async fn test_membership_merge_five_nodes() {
    use gossip_membership::membership::MembershipTable;
    use gossip_membership::node::NodeState;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let self_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10000);
    let mut table = MembershipTable::new(1, self_addr);

    for i in 2u64..=6 {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 10000 + i as u16);
        table.merge_entry(&NodeState::new_alive(i, addr, i as u32));
    }

    // All 5 peers + self = 6 total.
    assert_eq!(table.entries.len(), 6);
    // live_nodes excludes self.
    assert_eq!(table.live_nodes().len(), 5);
}

/// Verifies that the gossip_digest respects the fanout limit.
#[test]
fn test_gossip_digest_fanout_limit() {
    use gossip_membership::membership::MembershipTable;
    use gossip_membership::node::NodeState;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let self_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
    let mut table = MembershipTable::new(1, self_addr);

    for i in 2u64..=20 {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000 + i as u16);
        table.merge_entry(&NodeState::new_alive(i, addr, i as u32));
    }

    let digest = table.gossip_digest(5);
    assert_eq!(digest.len(), 5, "digest should be capped at fanout");
}

/// Multiple nodes in a star topology (all seeded with the hub) converge.
#[tokio::test]
async fn test_star_topology_five_nodes() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();

    // Hub node.
    let hub_transport = bind_local().await;
    let hub_addr = hub_transport.local_addr;

    let mut transports = vec![hub_transport];
    for _ in 0..4 {
        transports.push(bind_local().await);
    }
    let addrs: Vec<_> = transports.iter().map(|t| t.local_addr).collect();

    // All spoke nodes seed with hub only; hub seeds with all spokes.
    let nodes: Vec<TestNode> = transports
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let peers: Vec<SocketAddr> = if i == 0 {
                addrs[1..].to_vec()
            } else {
                vec![hub_addr]
            };
            TestNode::new(t, cfg.clone(), &peers)
        })
        .collect();

    let ids: Vec<u64> = nodes.iter().map(|n| n.id).collect();

    let mut handles = Vec::new();
    let mut senders = Vec::new();
    for node in nodes {
        let (tx, rx) = oneshot::channel();
        senders.push(tx);
        handles.push(tokio::spawn(run_test_node(node, rx)));
    }

    // Allow ample time for spoke→hub→spoke propagation.
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    for tx in senders {
        let _ = tx.send(());
    }

    let final_nodes: Vec<TestNode> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    // Every node should know every other node.
    for (i, node) in final_nodes.iter().enumerate() {
        for (j, &expected_id) in ids.iter().enumerate() {
            if i == j {
                continue;
            }
            assert!(
                node.table.entries.values().any(|e| e.node_id == expected_id),
                "node[{i}] does not know about node[{j}] (id={expected_id})"
            );
        }
    }
}

/// When node B bootstraps with node A's address, a placeholder entry is created
/// under a synthetic ID.  Once node A sends its first message, the placeholder
/// must be removed and replaced by A's real entry — no duplicates.
#[tokio::test]
async fn test_placeholder_cleaned_up_on_first_message() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();

    let ta = bind_local().await;
    let tb = bind_local().await;
    let addr_a = ta.local_addr;

    // Node A has no bootstrap peers; node B bootstraps with A's address.
    let na = TestNode::new(ta, cfg.clone(), &[]);
    let nb = TestNode::new(tb, cfg.clone(), &[addr_a]);
    let id_a = na.id;

    // Before any gossip, B's table must contain the placeholder for A's address.
    let placeholder = placeholder_id_for(addr_a);
    assert!(
        nb.table.entries.contains_key(&placeholder),
        "placeholder entry should exist in B's table before any gossip"
    );

    let (tx_a, rx_a) = oneshot::channel::<()>();
    let (tx_b, rx_b) = oneshot::channel::<()>();

    let ha = tokio::spawn(run_test_node(na, rx_a));
    let hb = tokio::spawn(run_test_node(nb, rx_b));

    // Allow several gossip rounds (gossip_interval_ms = 50 ms in fast config).
    tokio::time::sleep(Duration::from_millis(400)).await;

    let _ = tx_a.send(());
    let _ = tx_b.send(());

    let _node_a = ha.await.unwrap();
    let node_b = hb.await.unwrap();

    // B must have A's real entry.
    assert!(
        node_b.table.entries.contains_key(&id_a),
        "node B should have real entry for node A after gossip"
    );

    // Placeholder must be gone.
    assert!(
        !node_b.table.entries.contains_key(&placeholder),
        "placeholder entry for node A's address must be removed once real entry is seen"
    );
}

/// After bootstrap and a few gossip rounds, each peer address appears exactly
/// once in each node's membership table (no duplicate entries).
#[tokio::test]
async fn test_no_duplicate_entries_after_gossip() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();

    let ta = bind_local().await;
    let tb = bind_local().await;
    let addr_a = ta.local_addr;
    let addr_b = tb.local_addr;

    // Both nodes bootstrap with each other — each starts with one placeholder.
    let na = TestNode::new(ta, cfg.clone(), &[addr_b]);
    let nb = TestNode::new(tb, cfg.clone(), &[addr_a]);

    let (tx_a, rx_a) = oneshot::channel::<()>();
    let (tx_b, rx_b) = oneshot::channel::<()>();

    let ha = tokio::spawn(run_test_node(na, rx_a));
    let hb = tokio::spawn(run_test_node(nb, rx_b));

    tokio::time::sleep(Duration::from_millis(400)).await;

    let _ = tx_a.send(());
    let _ = tx_b.send(());

    let node_a = ha.await.unwrap();
    let node_b = hb.await.unwrap();

    // No address should appear more than once in either table.
    for (name, node) in [("node_a", &node_a), ("node_b", &node_b)] {
        let mut seen = std::collections::HashSet::new();
        for entry in node.table.entries.values() {
            assert!(
                seen.insert(entry.addr),
                "{name}: address {} appears more than once (duplicate entry)",
                entry.addr
            );
        }
    }
}
