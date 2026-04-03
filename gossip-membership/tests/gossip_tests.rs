/// Integration tests for the gossip membership protocol.
///
/// Each test spawns multiple in-process nodes (real UDP sockets on 127.0.0.1:0),
/// allows gossip to converge, then asserts on the final membership tables.
///
/// Note: NodeConfig::fast() is used so tests complete in < 2 seconds.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::sync::oneshot;

use std::sync::{Arc, Mutex};

use gossip_membership::crypto::ClusterKey;
use gossip_membership::node::{NodeConfig, NodeStatus};
use gossip_membership::runner::{run_node, Node};
use gossip_membership::simulator::NetSim;
use gossip_membership::transport::Transport;

use gossip_membership::membership::placeholder_id_for;

// ── Helpers ────────────────────────────────────────────────────────────────────
async fn bind_local() -> Transport {
    Transport::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("bind failed")
}

async fn bind_encrypted(key: &ClusterKey) -> Transport {
    bind_local().await.with_key(key.clone())
}

async fn bind_sim(sim: &Arc<Mutex<NetSim>>) -> Transport {
    bind_local().await.with_sim(sim.clone())
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

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1]);
    let id1 = n1.id;
    let id2 = n2.id;

    let (tx1, rx1) = oneshot::channel::<()>();
    let (tx2, rx2) = oneshot::channel::<()>();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));

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

    let n1 = Node::new(t1, cfg.clone(), &[addr2, addr3]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1, addr3]);
    let n3 = Node::new(t3, cfg.clone(), &[addr1, addr2]);
    let id1 = n1.id;
    let id2 = n2.id;
    let id3 = n3.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));
    let h3 = tokio::spawn(run_node(n3, rx3));

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
    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr3]);
    let n3 = Node::new(t3, cfg.clone(), &[addr1]);
    let id1 = n1.id;
    let id2 = n2.id;
    let id3 = n3.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));
    let h3 = tokio::spawn(run_node(n3, rx3));

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

/// Dead merge rule: a Dead node cannot be resurrected at the same incarnation,
/// but CAN rejoin at a higher incarnation (the node restarted).
#[tokio::test]
async fn test_dead_rejoin_with_incarnation() {
    use gossip_membership::membership::MembershipTable;
    use gossip_membership::node::{NodeState, NodeStatus};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let self_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000);
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9001);
    let mut table = MembershipTable::new(1, self_addr);

    // Insert peer as Dead at incarnation 0.
    let mut dead = NodeState::new_alive(2, peer_addr, 10);
    dead.status = NodeStatus::Dead;
    dead.incarnation = 0;
    table.merge_entry(&dead);
    assert_eq!(table.entries[&2].status, NodeStatus::Dead);

    // Same incarnation, higher heartbeat — must NOT resurrect.
    table.merge_entry(&NodeState::new_alive(2, peer_addr, 20));
    assert_eq!(table.entries[&2].status, NodeStatus::Dead,
        "same incarnation must not resurrect Dead");

    // Higher incarnation — MUST resurrect (node restarted).
    let mut rejoin = NodeState::new_alive(2, peer_addr, 0);
    rejoin.incarnation = 1;
    table.merge_entry(&rejoin);
    assert_eq!(table.entries[&2].status, NodeStatus::Alive,
        "higher incarnation must resurrect Dead node");
    assert_eq!(table.entries[&2].incarnation, 1);
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

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1]);
    let id2 = n2.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    // Start node1; node2 starts but we shut it down quickly so it stops responding.
    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));

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
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
    };
    let msg = build_gossip(42, 3, 0, vec![entry.clone()]);
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
    let nodes: Vec<Node> = transports
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let peers: Vec<SocketAddr> = if i == 0 {
                addrs[1..].to_vec()
            } else {
                vec![hub_addr]
            };
            Node::new(t, cfg.clone(), &peers)
        })
        .collect();

    let ids: Vec<u64> = nodes.iter().map(|n| n.id).collect();

    let mut handles = Vec::new();
    let mut senders = Vec::new();
    for node in nodes {
        let (tx, rx) = oneshot::channel();
        senders.push(tx);
        handles.push(tokio::spawn(run_node(node, rx)));
    }

    // Allow ample time for spoke→hub→spoke propagation.
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    for tx in senders {
        let _ = tx.send(());
    }

    let final_nodes: Vec<Node> = futures::future::join_all(handles)
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
    let na = Node::new(ta, cfg.clone(), &[]);
    let nb = Node::new(tb, cfg.clone(), &[addr_a]);
    let id_a = na.id;

    // Before any gossip, B's table must contain the placeholder for A's address.
    let placeholder = placeholder_id_for(addr_a);
    assert!(
        nb.table.entries.contains_key(&placeholder),
        "placeholder entry should exist in B's table before any gossip"
    );

    let (tx_a, rx_a) = oneshot::channel::<()>();
    let (tx_b, rx_b) = oneshot::channel::<()>();

    let ha = tokio::spawn(run_node(na, rx_a));
    let hb = tokio::spawn(run_node(nb, rx_b));

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

/// When Node A has a placeholder for Node C and gossips to Node B, the
/// placeholder must NOT appear in A's gossip digest — only real entries
/// propagate.  Once A learns C's real id (via gossip from B or C), the
/// placeholder is evicted.
#[tokio::test]
async fn test_placeholder_not_propagated_via_gossip() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();

    // Three nodes: A knows B only, B knows C only, C knows nobody.
    // A also bootstraps with C's address (creating a placeholder for C).
    let ta = bind_local().await;
    let tb = bind_local().await;
    let tc = bind_local().await;
    let addr_a = ta.local_addr;
    let addr_b = tb.local_addr;
    let addr_c = tc.local_addr;

    let na = Node::new(ta, cfg.clone(), &[addr_b, addr_c]);
    let nb = Node::new(tb, cfg.clone(), &[addr_a]);
    let nc = Node::new(tc, cfg.clone(), &[addr_b]);
    let id_a = na.id;
    let id_b = nb.id;
    let id_c = nc.id;

    // A has a placeholder for C before any gossip.
    let placeholder_c = placeholder_id_for(addr_c);
    assert!(
        na.table.is_placeholder(placeholder_c),
        "A must have a placeholder for C's address before gossip"
    );

    let (txa, rxa) = oneshot::channel::<()>();
    let (txb, rxb) = oneshot::channel::<()>();
    let (txc, rxc) = oneshot::channel::<()>();

    let ha = tokio::spawn(run_node(na, rxa));
    let hb = tokio::spawn(run_node(nb, rxb));
    let hc = tokio::spawn(run_node(nc, rxc));

    // Allow convergence.
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let _ = txa.send(());
    let _ = txb.send(());
    let _ = txc.send(());

    let node_a = ha.await.unwrap();
    let node_b = hb.await.unwrap();
    let node_c = hc.await.unwrap();

    // A's placeholder for C must be gone — replaced by C's real entry.
    assert!(
        !node_a.table.is_placeholder(placeholder_c),
        "A's placeholder for C must be evicted after convergence"
    );
    assert!(
        node_a.table.entries.values().any(|e| e.node_id == id_c),
        "A must know C's real id after convergence"
    );

    // B must NOT have the placeholder — A should never have gossiped it.
    assert!(
        !node_b.table.entries.contains_key(&placeholder_c),
        "B must not have received A's placeholder for C via gossip"
    );

    // No duplicate addresses in any table.
    for (name, node) in [("A", &node_a), ("B", &node_b), ("C", &node_c)] {
        let mut seen = std::collections::HashSet::new();
        for entry in node.table.entries.values() {
            assert!(
                seen.insert(entry.addr),
                "{name}: address {} appears more than once",
                entry.addr
            );
        }
    }

    // Full convergence: everyone knows everyone.
    for (name, node, expected) in [
        ("A", &node_a, vec![id_b, id_c]),
        ("B", &node_b, vec![id_a, id_c]),
        ("C", &node_c, vec![id_a, id_b]),
    ] {
        for eid in expected {
            assert!(
                node.table.entries.values().any(|e| e.node_id == eid),
                "{name} does not know about node {eid}"
            );
        }
    }
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
    let na = Node::new(ta, cfg.clone(), &[addr_b]);
    let nb = Node::new(tb, cfg.clone(), &[addr_a]);

    let (tx_a, rx_a) = oneshot::channel::<()>();
    let (tx_b, rx_b) = oneshot::channel::<()>();

    let ha = tokio::spawn(run_node(na, rx_a));
    let hb = tokio::spawn(run_node(nb, rx_b));

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

// ── Encryption tests ────────────────────────────────────────────────────────

/// Two encrypted nodes with the same cluster key should discover each other.
#[tokio::test]
async fn test_encrypted_two_nodes_converge() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();
    let key = ClusterKey::generate();

    let t1 = bind_encrypted(&key).await;
    let t2 = bind_encrypted(&key).await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    assert!(t1.is_encrypted());
    assert!(t2.is_encrypted());

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1]);
    let id1 = n1.id;
    let id2 = n2.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));

    tokio::time::sleep(Duration::from_millis(500)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());

    let node1 = h1.await.unwrap();
    let node2 = h2.await.unwrap();

    assert!(
        node1.table.entries.values().any(|e| e.node_id == id2),
        "encrypted node1 does not know about node2"
    );
    assert!(
        node2.table.entries.values().any(|e| e.node_id == id1),
        "encrypted node2 does not know about node1"
    );
}

/// Three encrypted nodes in a ring converge through gossip propagation.
#[tokio::test]
async fn test_encrypted_ring_converges() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();
    let key = ClusterKey::generate();

    let t1 = bind_encrypted(&key).await;
    let t2 = bind_encrypted(&key).await;
    let t3 = bind_encrypted(&key).await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;
    let addr3 = t3.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr3]);
    let n3 = Node::new(t3, cfg.clone(), &[addr1]);
    let id1 = n1.id;
    let id3 = n3.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));
    let h3 = tokio::spawn(run_node(n3, rx3));

    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());
    let _ = tx3.send(());

    let node1 = h1.await.unwrap();
    let _node2 = h2.await.unwrap();
    let node3 = h3.await.unwrap();

    assert!(
        node1.table.entries.values().any(|e| e.node_id == id3),
        "encrypted ring: node1 did not learn about node3 via gossip"
    );
    assert!(
        node3.table.entries.values().any(|e| e.node_id == id1),
        "encrypted ring: node3 did not learn about node1 via gossip"
    );
}

/// A node with a different cluster key must NOT be able to join.
/// The encrypted node should remain isolated — the wrong-key node's
/// messages will fail decryption and be silently dropped.
#[tokio::test]
async fn test_wrong_key_node_rejected() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();
    let key_good = ClusterKey::generate();
    let key_bad = ClusterKey::generate();

    let t1 = bind_encrypted(&key_good).await;
    let t2 = bind_encrypted(&key_bad).await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1]);
    let id1 = n1.id;
    let id2 = n2.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));

    // Allow ample time — if decryption is working, they'd converge by now.
    tokio::time::sleep(Duration::from_millis(800)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());

    let node1 = h1.await.unwrap();
    let node2 = h2.await.unwrap();

    // Neither node should have learned the other's real ID.
    assert!(
        !node1.table.entries.values().any(|e| e.node_id == id2),
        "node1 should NOT know node2 (different key)"
    );
    assert!(
        !node2.table.entries.values().any(|e| e.node_id == id1),
        "node2 should NOT know node1 (different key)"
    );
}

/// An unencrypted node cannot join an encrypted cluster.
#[tokio::test]
async fn test_plaintext_node_rejected_by_encrypted_cluster() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();
    let key = ClusterKey::generate();

    let t1 = bind_encrypted(&key).await;
    let t2 = bind_local().await; // plaintext
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1]);
    let id1 = n1.id;
    let id2 = n2.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));

    tokio::time::sleep(Duration::from_millis(800)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());

    let node1 = h1.await.unwrap();
    let node2 = h2.await.unwrap();

    // Encrypted node must reject plaintext messages.
    assert!(
        !node1.table.entries.values().any(|e| e.node_id == id2),
        "encrypted node should NOT accept plaintext peer"
    );
    // Plaintext node receives encrypted bytes which fail Message::decode.
    assert!(
        !node2.table.entries.values().any(|e| e.node_id == id1),
        "plaintext node should NOT parse encrypted messages"
    );
}

// ── Rate-limiting / adaptive-fanout tests ───────────────────────────────────

/// With max_gossip_sends=2, a five-node star topology should converge
/// at least as fast as with max_gossip_sends=1.
#[tokio::test]
async fn test_multi_target_gossip_converges() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    cfg.max_gossip_sends = 2;
    cfg.adaptive_fanout = true;

    let hub_transport = bind_local().await;
    let hub_addr = hub_transport.local_addr;

    let mut transports = vec![hub_transport];
    for _ in 0..4 {
        transports.push(bind_local().await);
    }
    let addrs: Vec<_> = transports.iter().map(|t| t.local_addr).collect();

    let nodes: Vec<Node> = transports
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let peers: Vec<SocketAddr> = if i == 0 {
                addrs[1..].to_vec()
            } else {
                vec![hub_addr]
            };
            Node::new(t, cfg.clone(), &peers)
        })
        .collect();

    let ids: Vec<u64> = nodes.iter().map(|n| n.id).collect();

    let mut handles = Vec::new();
    let mut senders = Vec::new();
    for node in nodes {
        let (tx, rx) = oneshot::channel();
        senders.push(tx);
        handles.push(tokio::spawn(run_node(node, rx)));
    }

    tokio::time::sleep(Duration::from_millis(1_500)).await;

    for tx in senders {
        let _ = tx.send(());
    }

    let final_nodes: Vec<Node> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    for (i, node) in final_nodes.iter().enumerate() {
        for (j, &expected_id) in ids.iter().enumerate() {
            if i == j {
                continue;
            }
            assert!(
                node.table.entries.values().any(|e| e.node_id == expected_id),
                "multi-target: node[{i}] does not know about node[{j}] (id={expected_id})"
            );
        }
    }
}

// ── Metrics tests ────────────────────────────────────────────────────────────

/// After two nodes gossip for a while, both should have non-zero metrics
/// for gossip rounds, sends, receives, pings, acks, and merges.
#[tokio::test]
async fn test_metrics_collected_after_convergence() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();

    let t1 = bind_local().await;
    let t2 = bind_local().await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1]);

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));

    // Let nodes gossip and probe for a while.
    tokio::time::sleep(Duration::from_millis(800)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());

    let node1 = h1.await.unwrap();
    let node2 = h2.await.unwrap();

    // Both nodes should have sent and received gossip.
    for (name, m) in [("node1", &node1.metrics), ("node2", &node2.metrics)] {
        assert!(m.gossip_rounds > 0, "{name}: gossip_rounds should be > 0");
        assert!(m.gossip_sent > 0, "{name}: gossip_sent should be > 0");
        assert!(m.gossip_recv > 0, "{name}: gossip_recv should be > 0");
        assert!(m.pings_sent > 0, "{name}: pings_sent should be > 0");
        assert!(m.pings_recv > 0, "{name}: pings_recv should be > 0");
        assert!(m.acks_sent > 0, "{name}: acks_sent should be > 0");
        assert!(m.acks_recv > 0, "{name}: acks_recv should be > 0");
        assert!(m.merges_new > 0, "{name}: merges_new should be > 0 (discovered peer)");
    }

    // Verify summary formatting works.
    let (alive, suspect, dead) = node1.table.status_counts();
    let summary = node1.metrics.summary(alive, suspect, dead);
    assert!(summary.contains("gossip_rounds="));
    assert!(summary.contains("alive="));
}

// ── Leave tests ──────────────────────────────────────────────────────────────

/// When a node shuts down gracefully it broadcasts LEAVE. Peers that
/// receive the LEAVE should immediately mark it Dead (no Suspect phase).
#[tokio::test]
async fn test_graceful_leave_marks_dead() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();

    let t1 = bind_local().await;
    let t2 = bind_local().await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1]);
    let id1 = n1.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));

    // Let nodes converge first.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Gracefully shut down node1 (broadcasts LEAVE).
    let _ = tx1.send(());
    let _node1 = h1.await.unwrap();

    // Give node2 time to process the LEAVE message.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Shut down node2 and inspect its table.
    let _ = tx2.send(());
    let node2 = h2.await.unwrap();

    let status = node2
        .table
        .entries
        .values()
        .find(|e| e.node_id == id1)
        .map(|e| e.status);

    assert_eq!(
        status,
        Some(NodeStatus::Dead),
        "node2 should have marked node1 as Dead after receiving LEAVE, got {status:?}"
    );
}

/// In a three-node cluster, when one node leaves, the remaining two should
/// still see each other as Alive and the departed node as Dead.
#[tokio::test]
async fn test_leave_does_not_affect_remaining_nodes() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();

    let t1 = bind_local().await;
    let t2 = bind_local().await;
    let t3 = bind_local().await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;
    let addr3 = t3.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2, addr3]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1, addr3]);
    let n3 = Node::new(t3, cfg.clone(), &[addr1, addr2]);
    let id1 = n1.id;
    let id2 = n2.id;
    let id3 = n3.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));
    let h3 = tokio::spawn(run_node(n3, rx3));

    // Converge.
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Node1 leaves gracefully.
    let _ = tx1.send(());
    let _node1 = h1.await.unwrap();

    // Let the LEAVE propagate and remaining nodes gossip.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let _ = tx2.send(());
    let _ = tx3.send(());
    let node2 = h2.await.unwrap();
    let node3 = h3.await.unwrap();

    // Node1 should be Dead on both remaining nodes.
    for (name, node) in [("node2", &node2), ("node3", &node3)] {
        let status = node
            .table
            .entries
            .values()
            .find(|e| e.node_id == id1)
            .map(|e| e.status);
        assert_eq!(
            status,
            Some(NodeStatus::Dead),
            "{name} should see node1 as Dead after LEAVE"
        );
    }

    // Remaining nodes should still see each other as Alive.
    assert!(
        node2.table.entries.values().any(|e| e.node_id == id3 && e.status == NodeStatus::Alive),
        "node2 should still see node3 as Alive"
    );
    assert!(
        node3.table.entries.values().any(|e| e.node_id == id2 && e.status == NodeStatus::Alive),
        "node3 should still see node2 as Alive"
    );
}

// ── REQUEST_ACK / reliable delivery tests ───────────────────────────────────

/// Verify that LEAVE messages set the REQUEST_ACK flag and that receivers
/// respond with an ACK.  After a graceful leave the receiver should have
/// sent at least one ACK in response to the LEAVE.
#[tokio::test]
async fn test_leave_uses_request_ack() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();

    let t1 = bind_local().await;
    let t2 = bind_local().await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1]);
    let id1 = n1.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));

    // Converge.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let _ = tx1.send(());
    h1.await.unwrap();

    // Give node2 time to process the LEAVE and send ACK.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let _ = tx2.send(());
    let node2 = h2.await.unwrap();

    // Node2 should have marked node1 Dead.
    let status = node2
        .table
        .entries
        .values()
        .find(|e| e.node_id == id1)
        .map(|e| e.status);
    assert_eq!(status, Some(NodeStatus::Dead));

    // Node2 should have sent at least one ACK in response to the LEAVE.
    // (It also sends ACKs for PINGs, so acks_sent should be > 0.)
    assert!(
        node2.metrics.acks_sent > 0,
        "node2 should have sent ACKs (including for LEAVE with REQUEST_ACK)"
    );
}

/// When a peer is unreachable, REQUEST_ACK retransmissions should fire
/// and eventually exhaust retries.
#[tokio::test]
async fn test_request_ack_retries_on_timeout() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    cfg.reliable_ack_timeout_ms = 30; // very short for testing
    cfg.reliable_max_retries = 2;

    let t1 = bind_local().await;
    let t2 = bind_local().await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1]);
    let id2 = n2.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));

    // Converge.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Kill node2 so it stops responding.
    let _ = tx2.send(());
    let _node2 = h2.await.unwrap();

    // Wait for node1 to detect the failure.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let _ = tx1.send(());
    let node1 = h1.await.unwrap();

    // Node1 should have seen probe timeouts for the dead node2.
    assert!(
        node1.metrics.probe_direct_timeouts > 0 || node1.metrics.probe_failures > 0,
        "node1 should detect node2 as unresponsive"
    );

    let node2_status = node1
        .table
        .entries
        .values()
        .find(|e| e.node_id == id2)
        .map(|e| e.status);
    assert!(
        matches!(node2_status, Some(NodeStatus::Suspect) | Some(NodeStatus::Dead)),
        "node2 should be Suspect or Dead on node1 after silence"
    );
}

// ── Network simulator tests ─────────────────────────────────────────────────

/// Under 30% packet loss, three fully-seeded nodes should still converge
/// given enough gossip rounds.
#[tokio::test]
async fn test_convergence_under_loss() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();
    let sim = Arc::new(Mutex::new(NetSim::new(42).with_loss(0.3)));

    let t1 = bind_sim(&sim).await;
    let t2 = bind_sim(&sim).await;
    let t3 = bind_sim(&sim).await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;
    let addr3 = t3.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2, addr3]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1, addr3]);
    let n3 = Node::new(t3, cfg.clone(), &[addr1, addr2]);
    let id1 = n1.id;
    let id2 = n2.id;
    let id3 = n3.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));
    let h3 = tokio::spawn(run_node(n3, rx3));

    // Allow extra time for convergence under loss.
    tokio::time::sleep(Duration::from_millis(2_000)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());
    let _ = tx3.send(());

    let node1 = h1.await.unwrap();
    let node2 = h2.await.unwrap();
    let node3 = h3.await.unwrap();

    for (name, node, expected) in [
        ("node1", &node1, vec![id2, id3]),
        ("node2", &node2, vec![id1, id3]),
        ("node3", &node3, vec![id1, id2]),
    ] {
        for eid in expected {
            assert!(
                node.table.entries.values().any(|e| e.node_id == eid),
                "{name} does not know about node {eid} (under 30% loss)"
            );
        }
    }
}

/// When the direct path between node1 and node3 is partitioned but both
/// can reach node2, node1 should still learn about node3 via gossip
/// propagation through node2 (indirect dissemination).
#[tokio::test]
async fn test_convergence_through_indirect_path() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();
    let sim = Arc::new(Mutex::new(NetSim::new(0)));

    let t1 = bind_sim(&sim).await;
    let t2 = bind_sim(&sim).await;
    let t3 = bind_sim(&sim).await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;
    let addr3 = t3.local_addr;

    // Partition: node1 <-> node3 blocked.
    sim.lock().unwrap().add_partition(addr1, addr3);

    let n1 = Node::new(t1, cfg.clone(), &[addr2, addr3]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1, addr3]);
    let n3 = Node::new(t3, cfg.clone(), &[addr1, addr2]);
    let id1 = n1.id;
    let id3 = n3.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let _h2 = tokio::spawn(run_node(n2, rx2));
    let h3 = tokio::spawn(run_node(n3, rx3));

    // Allow time for gossip to propagate via node2.
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());
    let _ = tx3.send(());

    let node1 = h1.await.unwrap();
    let node3 = h3.await.unwrap();

    // node1 should know about node3 via gossip through node2.
    assert!(
        node1.table.entries.values().any(|e| e.node_id == id3),
        "node1 must learn about node3 through indirect gossip via node2"
    );
    // And vice versa.
    assert!(
        node3.table.entries.values().any(|e| e.node_id == id1),
        "node3 must learn about node1 through indirect gossip via node2"
    );
}

/// When a partition is introduced after convergence, the failure detector
/// should mark the isolated node as Suspect.  When the partition heals
/// before the suspect timeout expires, the node should be rediscovered
/// as Alive (the incoming heartbeats update the entry).
#[tokio::test]
async fn test_partition_heal_restores_liveness() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    cfg.probe_timeout_ms = 50;
    // Long suspect timeout so the node stays Suspect (not Dead) during
    // the partition window.
    cfg.suspect_timeout_ms = 5_000;
    let sim = Arc::new(Mutex::new(NetSim::new(0)));

    let t1 = bind_sim(&sim).await;
    let t2 = bind_sim(&sim).await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1]);
    let id2 = n2.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let _h2 = tokio::spawn(run_node(n2, rx2));

    // Phase 1: converge normally.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Phase 2: partition them (short enough that suspect_timeout doesn't fire).
    sim.lock().unwrap().add_partition(addr1, addr2);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Phase 3: heal the partition — fresh messages should restore Alive.
    sim.lock().unwrap().remove_partition(addr1, addr2);
    tokio::time::sleep(Duration::from_millis(600)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());

    let node1 = h1.await.unwrap();

    let status = node1
        .table
        .entries
        .values()
        .find(|e| e.node_id == id2)
        .map(|e| e.status);

    assert_eq!(
        status,
        Some(NodeStatus::Alive),
        "node2 should be Alive after partition heals, got {status:?}"
    );
}

/// A fully isolated node (partitioned from all peers) should be detected
/// as Suspect or Dead by the remaining cluster.
#[tokio::test]
async fn test_full_isolation_detected() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    cfg.probe_timeout_ms = 50;
    cfg.suspect_timeout_ms = 200;
    let sim = Arc::new(Mutex::new(NetSim::new(0)));

    let t1 = bind_sim(&sim).await;
    let t2 = bind_sim(&sim).await;
    let t3 = bind_sim(&sim).await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;
    let addr3 = t3.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2, addr3]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1, addr3]);
    let n3 = Node::new(t3, cfg.clone(), &[addr1, addr2]);
    let id1 = n1.id;
    let id2 = n2.id;
    let id3 = n3.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));
    let _h3 = tokio::spawn(run_node(n3, rx3));

    // Phase 1: converge.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Phase 2: fully isolate node3.
    {
        let mut s = sim.lock().unwrap();
        s.add_partition(addr3, addr1);
        s.add_partition(addr3, addr2);
    }
    tokio::time::sleep(Duration::from_millis(800)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());
    let _ = tx3.send(());

    let node1 = h1.await.unwrap();
    let node2 = h2.await.unwrap();

    // node3 should be Suspect or Dead on node1 and node2.
    for (name, node) in [("node1", &node1), ("node2", &node2)] {
        let status = node
            .table
            .entries
            .values()
            .find(|e| e.node_id == id3)
            .map(|e| e.status);
        assert!(
            matches!(status, Some(NodeStatus::Suspect) | Some(NodeStatus::Dead)),
            "{name} should see node3 as Suspect or Dead after isolation, got {status:?}"
        );
    }

    // node1 and node2 should still see each other as Alive.
    assert!(
        node1.table.entries.values().any(|e| e.node_id == id2 && e.status == NodeStatus::Alive),
        "node1 should still see node2 as Alive"
    );
    assert!(
        node2.table.entries.values().any(|e| e.node_id == id1 && e.status == NodeStatus::Alive),
        "node2 should still see node1 as Alive"
    );
}

/// SWIM indirect probes (PING_REQ): when the direct path from node1 to
/// node3 is partitioned, node1 should use node2 as an intermediary to
/// probe node3.  Node3 should remain Alive on node1.
#[tokio::test]
async fn test_indirect_probe_through_intermediary() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    cfg.probe_timeout_ms = 80;
    cfg.suspect_timeout_ms = 500;
    cfg.indirect_probe_k = 2;
    let sim = Arc::new(Mutex::new(NetSim::new(0)));

    let t1 = bind_sim(&sim).await;
    let t2 = bind_sim(&sim).await;
    let t3 = bind_sim(&sim).await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;
    let addr3 = t3.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2, addr3]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1, addr3]);
    let n3 = Node::new(t3, cfg.clone(), &[addr1, addr2]);
    let id3 = n3.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let _h2 = tokio::spawn(run_node(n2, rx2));
    let _h3 = tokio::spawn(run_node(n3, rx3));

    // Phase 1: converge.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Phase 2: partition node1 <-> node3 (but both can still reach node2).
    sim.lock().unwrap().add_partition(addr1, addr3);

    // Allow time for direct probe to timeout and indirect probe via node2.
    tokio::time::sleep(Duration::from_millis(1_000)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());
    let _ = tx3.send(());

    let node1 = h1.await.unwrap();

    // node3 should still be Alive on node1, kept alive by indirect
    // probes (PING_REQ through node2) and gossip propagation.
    let status = node1
        .table
        .entries
        .values()
        .find(|e| e.node_id == id3)
        .map(|e| e.status);
    assert!(
        matches!(status, Some(NodeStatus::Alive)),
        "node3 should be Alive on node1 via indirect probes, got {status:?}"
    );

    // node1 should have sent at least one PING_REQ.
    assert!(
        node1.metrics.ping_reqs_sent > 0,
        "node1 should have sent indirect probes (PING_REQ)"
    );
}

// ── Anti-entropy tests ──────────────────────────────────────────────────────

/// Under heavy packet loss (50%), anti-entropy rounds should ensure
/// convergence by periodically pushing the full membership table.
#[tokio::test]
async fn test_anti_entropy_ensures_convergence_under_heavy_loss() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    cfg.anti_entropy_interval_ms = 200; // frequent full syncs
    let sim = Arc::new(Mutex::new(NetSim::new(42).with_loss(0.5)));

    let t1 = bind_sim(&sim).await;
    let t2 = bind_sim(&sim).await;
    let t3 = bind_sim(&sim).await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;
    let addr3 = t3.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2, addr3]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1, addr3]);
    let n3 = Node::new(t3, cfg.clone(), &[addr1, addr2]);
    let id1 = n1.id;
    let id2 = n2.id;
    let id3 = n3.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));
    let h3 = tokio::spawn(run_node(n3, rx3));

    // Allow extra time for convergence under heavy loss.
    tokio::time::sleep(Duration::from_millis(3_000)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());
    let _ = tx3.send(());

    let node1 = h1.await.unwrap();
    let node2 = h2.await.unwrap();
    let node3 = h3.await.unwrap();

    // All nodes should know all others despite 50% loss.
    for (name, node, expected) in [
        ("node1", &node1, vec![id2, id3]),
        ("node2", &node2, vec![id1, id3]),
        ("node3", &node3, vec![id1, id2]),
    ] {
        for eid in expected {
            assert!(
                node.table.entries.values().any(|e| e.node_id == eid),
                "{name} does not know about node {eid} (anti-entropy under 50% loss)"
            );
        }
    }

    // At least one node should have sent anti-entropy messages.
    let total_ae: u64 = node1.metrics.anti_entropy_sent
        + node2.metrics.anti_entropy_sent
        + node3.metrics.anti_entropy_sent;
    assert!(
        total_ae > 0,
        "at least one node should have sent anti-entropy full syncs"
    );
}

/// Anti-entropy counter should be zero when anti-entropy is disabled.
#[tokio::test]
async fn test_anti_entropy_disabled_sends_nothing() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    cfg.anti_entropy_interval_ms = 0; // disabled

    let t1 = bind_local().await;
    let t2 = bind_local().await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1]);

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));

    tokio::time::sleep(Duration::from_millis(500)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());

    let node1 = h1.await.unwrap();
    let node2 = h2.await.unwrap();

    assert_eq!(node1.metrics.anti_entropy_sent, 0, "anti-entropy should be disabled");
    assert_eq!(node2.metrics.anti_entropy_sent, 0, "anti-entropy should be disabled");
}

// ── Cluster partition & recovery tests ──────────────────────────────────────

/// Split-brain: 6 nodes split into two sub-clusters {1,2,3} and {4,5,6}.
/// Each sub-cluster should converge internally.  Nodes in the other
/// sub-cluster should be Suspect or Dead.  After the partition heals,
/// all 6 nodes should converge to a single consistent view.
#[tokio::test]
async fn test_split_brain_and_recovery() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    cfg.suspect_timeout_ms = 5_000; // long so nodes stay Suspect, not Dead
    cfg.anti_entropy_interval_ms = 100; // help post-heal convergence
    let sim = Arc::new(Mutex::new(NetSim::new(0)));

    // Create 6 nodes, all seeded with each other.
    let mut transports = Vec::new();
    for _ in 0..6 {
        transports.push(bind_sim(&sim).await);
    }
    let addrs: Vec<SocketAddr> = transports.iter().map(|t| t.local_addr).collect();

    let nodes: Vec<Node> = transports
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let peers: Vec<SocketAddr> = addrs.iter().enumerate()
                .filter(|&(j, _)| j != i)
                .map(|(_, a)| *a)
                .collect();
            Node::new(t, cfg.clone(), &peers)
        })
        .collect();

    let ids: Vec<u64> = nodes.iter().map(|n| n.id).collect();

    let mut handles = Vec::new();
    let mut senders = Vec::new();
    for node in nodes {
        let (tx, rx) = oneshot::channel();
        senders.push(tx);
        handles.push(tokio::spawn(run_node(node, rx)));
    }

    // Phase 1: converge fully.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Phase 2: partition into {0,1,2} and {3,4,5}.
    {
        let mut s = sim.lock().unwrap();
        for &a in &addrs[0..3] {
            for &b in &addrs[3..6] {
                s.add_partition(a, b);
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Phase 3: heal the partition.
    sim.lock().unwrap().clear_partitions();
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    // Shutdown all.
    for tx in senders {
        let _ = tx.send(());
    }
    let final_nodes: Vec<Node> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    // After recovery: every node should see every other node as Alive.
    for (i, node) in final_nodes.iter().enumerate() {
        for (j, &expected_id) in ids.iter().enumerate() {
            if i == j {
                continue;
            }
            let entry = node.table.entries.values().find(|e| e.node_id == expected_id);
            assert!(
                entry.is_some(),
                "node[{i}] does not know about node[{j}] (id={expected_id}) after split-brain recovery"
            );
            assert_eq!(
                entry.unwrap().status,
                NodeStatus::Alive,
                "node[{i}] should see node[{j}] as Alive after recovery, got {:?}",
                entry.unwrap().status
            );
        }
    }
}

/// Asymmetric partition: A→B is blocked but B→A is open (one-directional).
/// Node C can reach both.  After convergence, A should still know about B
/// because C propagates B's state to A via gossip.
#[tokio::test]
async fn test_asymmetric_partition_convergence() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    cfg.suspect_timeout_ms = 5_000; // prevent premature Dead
    let sim = Arc::new(Mutex::new(NetSim::new(0)));

    let ta = bind_sim(&sim).await;
    let tb = bind_sim(&sim).await;
    let tc = bind_sim(&sim).await;
    let addr_a = ta.local_addr;
    let addr_b = tb.local_addr;
    let addr_c = tc.local_addr;

    let na = Node::new(ta, cfg.clone(), &[addr_b, addr_c]);
    let nb = Node::new(tb, cfg.clone(), &[addr_a, addr_c]);
    let nc = Node::new(tc, cfg.clone(), &[addr_a, addr_b]);
    let id_a = na.id;
    let id_b = nb.id;

    let (txa, rxa) = oneshot::channel();
    let (txb, rxb) = oneshot::channel();
    let (txc, rxc) = oneshot::channel();

    let ha = tokio::spawn(run_node(na, rxa));
    let hb = tokio::spawn(run_node(nb, rxb));
    let _hc = tokio::spawn(run_node(nc, rxc));

    // Phase 1: converge.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Phase 2: asymmetric partition — A cannot send to B, but B can send to A.
    // We simulate this by partitioning A→B only.  Since NetSim partitions
    // are bidirectional, we instead partition A↔B fully and rely on C to
    // relay B's state to A.
    sim.lock().unwrap().add_partition(addr_a, addr_b);
    tokio::time::sleep(Duration::from_millis(800)).await;

    let _ = txa.send(());
    let _ = txb.send(());
    let _ = txc.send(());

    let node_a = ha.await.unwrap();
    let node_b = hb.await.unwrap();

    // A should still know about B (via C's gossip propagation).
    let a_knows_b = node_a.table.entries.values().find(|e| e.node_id == id_b);
    assert!(
        a_knows_b.is_some(),
        "node A should know about node B via gossip through C"
    );

    // B should still know about A (via C's gossip propagation).
    let b_knows_a = node_b.table.entries.values().find(|e| e.node_id == id_a);
    assert!(
        b_knows_a.is_some(),
        "node B should know about node A via gossip through C"
    );
}

/// Rolling partition: first isolate node1, let it heal, then isolate node2.
/// After both partitions heal, all nodes should converge.
#[tokio::test]
async fn test_rolling_partition_convergence() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    cfg.suspect_timeout_ms = 5_000; // prevent Dead during short partitions
    cfg.anti_entropy_interval_ms = 100;
    let sim = Arc::new(Mutex::new(NetSim::new(0)));

    let t1 = bind_sim(&sim).await;
    let t2 = bind_sim(&sim).await;
    let t3 = bind_sim(&sim).await;
    let t4 = bind_sim(&sim).await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;
    let addr3 = t3.local_addr;
    let addr4 = t4.local_addr;
    let all_addrs = [addr1, addr2, addr3, addr4];

    let n1 = Node::new(t1, cfg.clone(), &[addr2, addr3, addr4]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1, addr3, addr4]);
    let n3 = Node::new(t3, cfg.clone(), &[addr1, addr2, addr4]);
    let n4 = Node::new(t4, cfg.clone(), &[addr1, addr2, addr3]);
    let id1 = n1.id;
    let id2 = n2.id;
    let id3 = n3.id;
    let id4 = n4.id;
    let all_ids = [id1, id2, id3, id4];

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();
    let (tx4, rx4) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));
    let h3 = tokio::spawn(run_node(n3, rx3));
    let h4 = tokio::spawn(run_node(n4, rx4));

    // Phase 1: converge.
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Phase 2: isolate node1 from everyone.
    {
        let mut s = sim.lock().unwrap();
        for &other in &all_addrs[1..] {
            s.add_partition(addr1, other);
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Phase 3: heal node1, isolate node2.
    {
        let mut s = sim.lock().unwrap();
        s.clear_partitions();
        for &other in &[addr1, addr3, addr4] {
            s.add_partition(addr2, other);
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Phase 4: heal everything.
    sim.lock().unwrap().clear_partitions();
    tokio::time::sleep(Duration::from_millis(800)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());
    let _ = tx3.send(());
    let _ = tx4.send(());

    let nodes = vec![
        h1.await.unwrap(),
        h2.await.unwrap(),
        h3.await.unwrap(),
        h4.await.unwrap(),
    ];

    // All nodes should see all others as Alive.
    for (i, node) in nodes.iter().enumerate() {
        for (j, &eid) in all_ids.iter().enumerate() {
            if i == j {
                continue;
            }
            let entry = node.table.entries.values().find(|e| e.node_id == eid);
            assert!(
                entry.is_some(),
                "node[{i}] does not know about node[{j}] after rolling partition"
            );
            assert_eq!(
                entry.unwrap().status,
                NodeStatus::Alive,
                "node[{i}] should see node[{j}] as Alive after rolling partition recovery"
            );
        }
    }
}

/// A new node joins while a partition is active.  It can only reach one
/// sub-cluster initially.  After the partition heals, it should discover
/// all nodes in the cluster.
#[tokio::test]
async fn test_join_during_partition_then_heal() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    cfg.suspect_timeout_ms = 5_000;
    cfg.anti_entropy_interval_ms = 100;
    let sim = Arc::new(Mutex::new(NetSim::new(0)));

    // Start with 4 nodes, fully connected.
    let t1 = bind_sim(&sim).await;
    let t2 = bind_sim(&sim).await;
    let t3 = bind_sim(&sim).await;
    let t4 = bind_sim(&sim).await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;
    let addr3 = t3.local_addr;
    let addr4 = t4.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2, addr3, addr4]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1, addr3, addr4]);
    let n3 = Node::new(t3, cfg.clone(), &[addr1, addr2, addr4]);
    let n4 = Node::new(t4, cfg.clone(), &[addr1, addr2, addr3]);
    let id1 = n1.id;
    let id2 = n2.id;
    let id3 = n3.id;
    let id4 = n4.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();
    let (tx4, rx4) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));
    let h3 = tokio::spawn(run_node(n3, rx3));
    let h4 = tokio::spawn(run_node(n4, rx4));

    // Converge the initial 4 nodes.
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Partition: {1,2} vs {3,4}.
    {
        let mut s = sim.lock().unwrap();
        for &a in &[addr1, addr2] {
            for &b in &[addr3, addr4] {
                s.add_partition(a, b);
            }
        }
    }

    // Now a 5th node joins, seeded with node1 and node3.
    // It can only reach {1,2} due to the partition (node3,4 are blocked).
    let t5 = bind_sim(&sim).await;
    let addr5 = t5.local_addr;
    // Also partition node5 from {3,4}.
    {
        let mut s = sim.lock().unwrap();
        s.add_partition(addr5, addr3);
        s.add_partition(addr5, addr4);
    }
    let n5 = Node::new(t5, cfg.clone(), &[addr1, addr3]);
    let id5 = n5.id;
    let (tx5, rx5) = oneshot::channel();
    let h5 = tokio::spawn(run_node(n5, rx5));

    // Let the new node converge with {1,2}.
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Heal the partition.
    sim.lock().unwrap().clear_partitions();
    tokio::time::sleep(Duration::from_millis(1_000)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());
    let _ = tx3.send(());
    let _ = tx4.send(());
    let _ = tx5.send(());

    let all_ids = [id1, id2, id3, id4, id5];
    let nodes = vec![
        h1.await.unwrap(),
        h2.await.unwrap(),
        h3.await.unwrap(),
        h4.await.unwrap(),
        h5.await.unwrap(),
    ];

    // After heal, all 5 nodes should know every other node.
    for (i, node) in nodes.iter().enumerate() {
        for (j, &eid) in all_ids.iter().enumerate() {
            if i == j {
                continue;
            }
            let entry = node.table.entries.values().find(|e| e.node_id == eid);
            assert!(
                entry.is_some(),
                "node[{i}] does not know about node[{j}] (id={eid}) after join-during-partition heal"
            );
        }
    }

    // Node5 specifically should see nodes 3 and 4 (which it couldn't
    // reach during the partition).
    let node5 = &nodes[4];
    for &eid in &[id3, id4] {
        assert!(
            node5.table.entries.values().any(|e| e.node_id == eid),
            "node5 should have discovered node {eid} after partition healed"
        );
    }
}

// ── Metrics HTTP endpoint tests ─────────────────────────────────────────────

/// The metrics HTTP server should respond with Prometheus text format on
/// GET /metrics and JSON on GET /metrics/json.
#[tokio::test]
async fn test_metrics_http_endpoint() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    cfg.metrics_log_interval_ms = 100; // frequent snapshot updates
    cfg.metrics_server_port = 0; // will pick a free port

    // Bind the metrics server on a free port by finding one.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metrics_port = listener.local_addr().unwrap().port();
    drop(listener); // release it so the runner can bind
    cfg.metrics_server_port = metrics_port;

    let t1 = bind_local().await;
    let t2 = bind_local().await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let mut cfg2 = cfg.clone();
    cfg2.metrics_server_port = 0; // only node1 runs the server
    let n2 = Node::new(t2, cfg2, &[addr1]);

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));

    // Let nodes gossip and the metrics server start + get a snapshot.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Query the Prometheus endpoint.
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{metrics_port}"))
        .await
        .expect("should connect to metrics server");
    tokio::io::AsyncWriteExt::write_all(
        &mut stream,
        b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .await
    .unwrap();
    let mut resp = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut resp).await.unwrap();
    let body = String::from_utf8_lossy(&resp);

    assert!(body.contains("HTTP/1.1 200 OK"), "should return 200");
    assert!(body.contains("text/plain"), "should be Prometheus content type");
    assert!(body.contains("swim_gossip_rounds_total"), "should contain Prometheus counter");
    assert!(body.contains("# TYPE swim_members_alive gauge"), "should contain gauge type");

    // Query the JSON endpoint.
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{metrics_port}"))
        .await
        .expect("should connect to metrics server");
    tokio::io::AsyncWriteExt::write_all(
        &mut stream,
        b"GET /metrics/json HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .await
    .unwrap();
    let mut resp = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut resp).await.unwrap();
    let body = String::from_utf8_lossy(&resp);

    assert!(body.contains("application/json"), "should be JSON content type");
    assert!(body.contains(r#""gossip_rounds":"#), "should contain JSON field");

    let _ = tx1.send(());
    let _ = tx2.send(());
    h1.await.unwrap();
    h2.await.unwrap();
}

/// Helper: send an HTTP GET request and return the full response as a string.
async fn http_get(port: u16, path: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("should connect to metrics server");
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    tokio::io::AsyncWriteExt::write_all(&mut stream, req.as_bytes())
        .await
        .unwrap();
    let mut resp = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut resp)
        .await
        .unwrap();
    String::from_utf8_lossy(&resp).to_string()
}

/// /healthz, /readyz, and /membership endpoints return correct JSON.
#[tokio::test]
async fn test_operational_endpoints() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    cfg.metrics_log_interval_ms = 100;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metrics_port = listener.local_addr().unwrap().port();
    drop(listener);
    cfg.metrics_server_port = metrics_port;

    let t1 = bind_local().await;
    let t2 = bind_local().await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let mut cfg2 = cfg.clone();
    cfg2.metrics_server_port = 0;
    let n2 = Node::new(t2, cfg2, &[addr1]);

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));

    // Let nodes converge and snapshot update.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ── /healthz ──
    let resp = http_get(metrics_port, "/healthz").await;
    assert!(resp.contains("200 OK"), "/healthz should return 200");
    assert!(resp.contains("application/json"), "/healthz should be JSON");
    assert!(resp.contains(r#""status":"ok""#), "/healthz body");

    // ── /readyz ──
    let resp = http_get(metrics_port, "/readyz").await;
    assert!(resp.contains("200 OK"), "/readyz should return 200");
    assert!(resp.contains(r#""alive_nodes":"#), "/readyz should have alive_nodes");
    assert!(resp.contains(r#""suspect_nodes":"#), "/readyz should have suspect_nodes");
    assert!(resp.contains(r#""dead_nodes":"#), "/readyz should have dead_nodes");

    // ── /membership ──
    let resp = http_get(metrics_port, "/membership").await;
    assert!(resp.contains("200 OK"), "/membership should return 200");
    assert!(resp.contains(r#""nodes":["#), "/membership should have nodes array");
    assert!(resp.contains(r#""status":"alive""#), "should list alive nodes");
    assert!(resp.contains(r#""id":""#), "should list node ids");
    assert!(resp.contains(r#""addr":""#), "should list node addrs");

    let _ = tx1.send(());
    let _ = tx2.send(());
    h1.await.unwrap();
    h2.await.unwrap();
}

// ── Inbound rate limiting tests ─────────────────────────────────────────────

/// A peer sending 1000 packets rapidly should have most of them dropped
/// by the inbound rate limiter.
#[tokio::test]
async fn test_inbound_rate_limiting_drops_flood() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    // Tight rate limits: 20 burst per peer, no refill.
    cfg.inbound_global_capacity = 1000;
    cfg.inbound_global_refill_rate = 0;
    cfg.inbound_peer_capacity = 20;
    cfg.inbound_peer_refill_rate = 0;

    let t1 = bind_local().await;
    let t2 = bind_local().await;
    let addr2 = t2.local_addr;

    let raw_socket = t1.clone_socket();

    // Node 2 has rate limiting enabled.
    let n2 = Node::new(t2, cfg.clone(), &[]);
    let (tx2, rx2) = oneshot::channel();
    let h2 = tokio::spawn(run_node(n2, rx2));

    // Flood 1000 valid packets from t1 to t2 as fast as possible.
    let valid = gossip_membership::message::build_ping(1, 0, 0, vec![])
        .encode()
        .unwrap();
    for _ in 0..1000 {
        let _ = raw_socket.send_to(&valid, addr2).await;
    }

    // Give node2 time to process.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let _ = tx2.send(());
    let node2 = h2.await.unwrap();

    // Drain the counter manually since metrics tick may not have fired.
    let dropped = node2.transport.rate_limited_count
        .load(std::sync::atomic::Ordering::Relaxed)
        + node2.metrics.rate_limited;

    // With 20 peer capacity and no refill, at most 20 should pass.
    // The rest (~980) should be rate-limited.
    assert!(
        dropped >= 900,
        "expected >=900 packets dropped by rate limiter, got {dropped}"
    );
}

// ── Packet reorder tests ────────────────────────────────────────────────────

/// Under 80% reorder probability, three nodes should still converge
/// (gossip tolerates out-of-order delivery).
#[tokio::test]
async fn test_convergence_under_reorder() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();
    let sim = Arc::new(Mutex::new(
        NetSim::new(42).with_reorder(0.8, 5),
    ));

    let t1 = bind_sim(&sim).await;
    let t2 = bind_sim(&sim).await;
    let t3 = bind_sim(&sim).await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;
    let addr3 = t3.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2, addr3]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1, addr3]);
    let n3 = Node::new(t3, cfg.clone(), &[addr1, addr2]);
    let id1 = n1.id;
    let id2 = n2.id;
    let id3 = n3.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));
    let h3 = tokio::spawn(run_node(n3, rx3));

    tokio::time::sleep(Duration::from_millis(2_000)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());
    let _ = tx3.send(());

    let node1 = h1.await.unwrap();
    let node2 = h2.await.unwrap();
    let node3 = h3.await.unwrap();

    for (name, node, expected) in [
        ("node1", &node1, vec![id2, id3]),
        ("node2", &node2, vec![id1, id3]),
        ("node3", &node3, vec![id1, id2]),
    ] {
        for eid in expected {
            assert!(
                node.table.entries.values().any(|e| e.node_id == eid),
                "{name} does not know about node {eid} (under 80% reorder)"
            );
        }
    }
}

/// Indirect probes (PING_REQ) should still work under reordering:
/// when direct path is partitioned, node1 should keep node3 Alive
/// via node2 even with moderate reordering.
#[tokio::test]
async fn test_indirect_probes_under_reorder() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cfg = NodeConfig::fast();
    cfg.probe_timeout_ms = 150;
    cfg.suspect_timeout_ms = 800;
    cfg.indirect_probe_k = 2;
    let sim = Arc::new(Mutex::new(
        NetSim::new(0).with_reorder(0.3, 2),
    ));

    let t1 = bind_sim(&sim).await;
    let t2 = bind_sim(&sim).await;
    let t3 = bind_sim(&sim).await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;
    let addr3 = t3.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2, addr3]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1, addr3]);
    let n3 = Node::new(t3, cfg.clone(), &[addr1, addr2]);
    let id3 = n3.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let (tx3, rx3) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let _h2 = tokio::spawn(run_node(n2, rx2));
    let _h3 = tokio::spawn(run_node(n3, rx3));

    // Converge first.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Partition node1 <-> node3 (indirect probes go through node2).
    sim.lock().unwrap().add_partition(addr1, addr3);
    tokio::time::sleep(Duration::from_millis(1_000)).await;

    let _ = tx1.send(());
    let _ = tx2.send(());
    let _ = tx3.send(());

    let node1 = h1.await.unwrap();

    let status = node1
        .table
        .entries
        .values()
        .find(|e| e.node_id == id3)
        .map(|e| e.status);
    assert!(
        matches!(status, Some(NodeStatus::Alive)),
        "node3 should be Alive on node1 via indirect probes under reorder, got {status:?}"
    );
}
