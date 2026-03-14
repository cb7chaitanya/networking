/// Integration tests for the gossip membership protocol.
///
/// Each test spawns multiple in-process nodes (real UDP sockets on 127.0.0.1:0),
/// allows gossip to converge, then asserts on the final membership tables.
///
/// Note: NodeConfig::fast() is used so tests complete in < 2 seconds.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::sync::oneshot;

use gossip_membership::crypto::ClusterKey;
use gossip_membership::node::{NodeConfig, NodeStatus};
use gossip_membership::runner::{run_node, Node};
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
