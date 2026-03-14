/// Gossip round logic — peer selection and message construction.
///
/// This module is pure logic with no I/O. It operates on the membership table
/// and produces `Message` values; the event loop is responsible for sending them.
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::time::SystemTime;

use crate::membership::MembershipTable;
use crate::message::{build_gossip, Message};
use crate::node::NodeId;

/// Pick a random live peer from the membership table, excluding `self_id`.
///
/// Uses `DefaultHasher` + `SystemTime` for pseudorandomness (no `rand` dep),
/// matching the ISN-generation pattern from tcp-over-udp's `connection.rs`.
///
/// Returns `None` if no live peers are known.
pub fn pick_random_peer(
    table: &MembershipTable,
    self_id: NodeId,
) -> Option<(NodeId, SocketAddr)> {
    let live: Vec<(NodeId, SocketAddr)> = table
        .entries
        .values()
        .filter(|e| {
            e.node_id != self_id
                && matches!(
                    e.status,
                    crate::node::NodeStatus::Alive | crate::node::NodeStatus::Suspect
                )
        })
        .map(|e| (e.node_id, e.addr))
        .collect();

    if live.is_empty() {
        return None;
    }

    // Cheap pseudorandom index.
    let mut h = DefaultHasher::new();
    SystemTime::now().hash(&mut h);
    self_id.hash(&mut h);
    let idx = (h.finish() as usize) % live.len();
    Some(live[idx])
}

/// Pick up to `k` random live peers, excluding `self_id` and `exclude`.
/// Used to select indirect-probe intermediaries.
pub fn pick_k_random_peers(
    table: &MembershipTable,
    self_id: NodeId,
    exclude: NodeId,
    k: usize,
) -> Vec<(NodeId, SocketAddr)> {
    let mut live: Vec<(NodeId, SocketAddr)> = table
        .entries
        .values()
        .filter(|e| {
            e.node_id != self_id
                && e.node_id != exclude
                && matches!(
                    e.status,
                    crate::node::NodeStatus::Alive | crate::node::NodeStatus::Suspect
                )
        })
        .map(|e| (e.node_id, e.addr))
        .collect();

    if live.is_empty() {
        return vec![];
    }

    // Shuffle by rotating a hash-derived offset.
    let mut h = DefaultHasher::new();
    SystemTime::now().hash(&mut h);
    (self_id, exclude).hash(&mut h);
    let offset = (h.finish() as usize) % live.len();
    live.rotate_left(offset);
    live.truncate(k);
    live
}

/// Pick up to `max_targets` distinct random live peers for gossip this round.
///
/// This is the rate-limiting mechanism: instead of always gossiping to
/// exactly one peer, the event loop calls this once per gossip tick to get
/// the set of targets for the round, bounded by `max_targets` and the
/// number of live peers.
pub fn pick_gossip_targets(
    table: &MembershipTable,
    self_id: NodeId,
    max_targets: usize,
) -> Vec<(NodeId, SocketAddr)> {
    let mut live: Vec<(NodeId, SocketAddr)> = table
        .entries
        .values()
        .filter(|e| {
            e.node_id != self_id
                && matches!(
                    e.status,
                    crate::node::NodeStatus::Alive | crate::node::NodeStatus::Suspect
                )
        })
        .map(|e| (e.node_id, e.addr))
        .collect();

    if live.is_empty() {
        return vec![];
    }

    // Shuffle by rotating a hash-derived offset, then truncate.
    let mut h = DefaultHasher::new();
    SystemTime::now().hash(&mut h);
    self_id.hash(&mut h);
    let offset = (h.finish() as usize) % live.len();
    live.rotate_left(offset);
    live.truncate(max_targets);
    live
}

/// Compute the effective number of gossip targets per round.
///
/// When `adaptive` is `true`, scales with cluster size:
/// `base * ceil(log2(n)).max(1)`, so larger clusters push gossip to
/// more peers per round and dissemination still completes in O(log n)
/// rounds.  The result is further capped at `cluster_size - 1` (can't
/// gossip to more peers than exist).
///
/// When `adaptive` is `false`, returns `base` unchanged.
pub fn effective_gossip_targets(base: usize, cluster_size: usize, adaptive: bool) -> usize {
    if !adaptive || cluster_size <= 2 {
        return base;
    }
    let log2_n = (cluster_size as f64).log2().ceil().max(1.0) as usize;
    let scaled = base.saturating_mul(log2_n);
    // Can't target more peers than exist (excluding self).
    scaled.min(cluster_size.saturating_sub(1))
}

/// Compute the effective gossip fanout (max entries per message).
///
/// When `adaptive` is `true`, scales with cluster size:
/// `base * ceil(log2(n)).max(1)`, so larger clusters carry more entries
/// per message and dissemination still completes in O(log n) rounds.
///
/// When `adaptive` is `false`, returns `base` unchanged.
pub fn effective_fanout(base: usize, cluster_size: usize, adaptive: bool) -> usize {
    if !adaptive || cluster_size <= 2 {
        return base;
    }
    let log2_n = (cluster_size as f64).log2().ceil().max(1.0) as usize;
    base.saturating_mul(log2_n)
}

/// Build a full-sync GOSSIP message containing every non-placeholder entry
/// in the table.  Used for anti-entropy rounds.
pub fn build_full_sync_message(
    table: &MembershipTable,
    sender_id: NodeId,
    sender_heartbeat: u32,
    sender_incarnation: u32,
) -> Message {
    let entries = table.gossip_wire_entries(usize::MAX);
    build_gossip(sender_id, sender_heartbeat, sender_incarnation, entries)
}

/// Build the GOSSIP message to broadcast this round.
pub fn build_gossip_message(
    table: &MembershipTable,
    sender_id: NodeId,
    sender_heartbeat: u32,
    sender_incarnation: u32,
    fanout: usize,
) -> Message {
    let entries = table.gossip_wire_entries(fanout);
    build_gossip(sender_id, sender_heartbeat, sender_incarnation, entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use crate::message::{kind, MessagePayload};
    use crate::node::{NodeState, NodeStatus};

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    /// Helper: insert a peer with a given status.
    fn insert_with_status(t: &mut MembershipTable, id: NodeId, port: u16, status: NodeStatus) {
        let mut s = NodeState::new_alive(id, make_addr(port), 1);
        s.status = status;
        t.merge_entry(&s);
        // merge_entry won't store Dead directly for a new entry (it inserts as
        // Alive then we overwrite), so force it via the entry map.
        if status == NodeStatus::Dead {
            t.entries.get_mut(&id).unwrap().status = NodeStatus::Dead;
        }
    }

    // ── effective_gossip_targets tests ──────────────────────────────────────

    #[test]
    fn gossip_targets_non_adaptive_returns_base() {
        assert_eq!(effective_gossip_targets(2, 100, false), 2);
        assert_eq!(effective_gossip_targets(2, 1, false), 2);
    }

    #[test]
    fn gossip_targets_adaptive_small_cluster_returns_base() {
        assert_eq!(effective_gossip_targets(1, 1, true), 1);
        assert_eq!(effective_gossip_targets(1, 2, true), 1);
    }

    #[test]
    fn gossip_targets_adaptive_scales_with_cluster_size() {
        // 8 nodes: ceil(log2(8)) = 3 → 1 * 3 = 3
        assert_eq!(effective_gossip_targets(1, 8, true), 3);
        // 16 nodes: ceil(log2(16)) = 4 → 1 * 4 = 4
        assert_eq!(effective_gossip_targets(1, 16, true), 4);
        // 100 nodes: ceil(log2(100)) = 7 → 1 * 7 = 7
        assert_eq!(effective_gossip_targets(1, 100, true), 7);
    }

    #[test]
    fn gossip_targets_adaptive_with_higher_base() {
        // base=2, 16 nodes: 2 * 4 = 8
        assert_eq!(effective_gossip_targets(2, 16, true), 8);
    }

    #[test]
    fn gossip_targets_capped_at_cluster_minus_one() {
        // base=10, 5 nodes: 10 * 3 = 30, but only 4 peers → capped at 4.
        assert_eq!(effective_gossip_targets(10, 5, true), 4);
    }

    #[test]
    fn gossip_targets_base_zero_returns_zero() {
        assert_eq!(effective_gossip_targets(0, 100, true), 0);
    }

    #[test]
    fn gossip_targets_cluster_size_zero() {
        assert_eq!(effective_gossip_targets(1, 0, true), 1);
    }

    // ── effective_fanout tests ────────────────────────────────────────────────

    #[test]
    fn fanout_non_adaptive_returns_base() {
        assert_eq!(effective_fanout(10, 100, false), 10);
        assert_eq!(effective_fanout(10, 1, false), 10);
    }

    #[test]
    fn fanout_adaptive_small_cluster_returns_base() {
        // ≤ 2 nodes: no scaling.
        assert_eq!(effective_fanout(10, 1, true), 10);
        assert_eq!(effective_fanout(10, 2, true), 10);
    }

    #[test]
    fn fanout_adaptive_scales_with_cluster_size() {
        // 8 nodes: ceil(log2(8)) = 3 → 10 * 3 = 30
        assert_eq!(effective_fanout(10, 8, true), 30);
        // 16 nodes: ceil(log2(16)) = 4 → 10 * 4 = 40
        assert_eq!(effective_fanout(10, 16, true), 40);
        // 100 nodes: ceil(log2(100)) = 7 → 10 * 7 = 70
        assert_eq!(effective_fanout(10, 100, true), 70);
    }

    #[test]
    fn fanout_adaptive_three_nodes() {
        // 3 nodes: ceil(log2(3)) = 2 → 10 * 2 = 20
        assert_eq!(effective_fanout(10, 3, true), 20);
    }

    #[test]
    fn fanout_base_zero_returns_zero() {
        assert_eq!(effective_fanout(0, 100, true), 0);
        assert_eq!(effective_fanout(0, 100, false), 0);
    }

    #[test]
    fn fanout_cluster_size_zero_returns_base() {
        // Degenerate — should not panic.
        assert_eq!(effective_fanout(10, 0, true), 10);
    }

    #[test]
    fn fanout_large_base_saturates() {
        // usize::MAX * anything should not panic — saturating_mul.
        let result = effective_fanout(usize::MAX, 1024, true);
        assert_eq!(result, usize::MAX);
    }

    // ── pick_random_peer tests ───────────────────────────────────────────────

    #[test]
    fn random_peer_none_when_alone() {
        let t = MembershipTable::new(1, make_addr(1000));
        assert!(pick_random_peer(&t, 1).is_none());
    }

    #[test]
    fn random_peer_returns_live_peer() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 5));
        // Only one peer — must return it.
        let (id, addr) = pick_random_peer(&t, 1).unwrap();
        assert_eq!(id, 2);
        assert_eq!(addr, make_addr(2000));
    }

    #[test]
    fn random_peer_excludes_dead() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        insert_with_status(&mut t, 2, 2000, NodeStatus::Dead);
        assert!(pick_random_peer(&t, 1).is_none());
    }

    #[test]
    fn random_peer_includes_suspect() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        insert_with_status(&mut t, 2, 2000, NodeStatus::Suspect);
        let (id, _) = pick_random_peer(&t, 1).unwrap();
        assert_eq!(id, 2);
    }

    #[test]
    fn random_peer_never_returns_self() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 1));
        // Call many times — must never return self_id.
        for _ in 0..50 {
            let (id, _) = pick_random_peer(&t, 1).unwrap();
            assert_ne!(id, 1);
        }
    }

    // ── pick_k_random_peers tests ────────────────────────────────────────────

    #[test]
    fn k_peers_empty_when_alone() {
        let t = MembershipTable::new(1, make_addr(1000));
        let peers = pick_k_random_peers(&t, 1, 99, 5);
        assert!(peers.is_empty());
    }

    #[test]
    fn k_peers_excludes_self_and_target() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 1));
        t.merge_entry(&NodeState::new_alive(3, make_addr(3000), 1));
        t.merge_entry(&NodeState::new_alive(4, make_addr(4000), 1));

        // Exclude self=1 and target=2 → only 3 and 4 eligible.
        let peers = pick_k_random_peers(&t, 1, 2, 10);
        assert_eq!(peers.len(), 2);
        for (id, _) in &peers {
            assert_ne!(*id, 1, "must not include self");
            assert_ne!(*id, 2, "must not include excluded target");
        }
    }

    #[test]
    fn k_peers_capped_at_k() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        for i in 2..=10u64 {
            t.merge_entry(&NodeState::new_alive(i, make_addr(1000 + i as u16), 1));
        }
        let peers = pick_k_random_peers(&t, 1, 99, 3);
        assert_eq!(peers.len(), 3);
        // All unique.
        let ids: std::collections::HashSet<_> = peers.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn k_peers_returns_all_if_fewer_than_k() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 1));
        t.merge_entry(&NodeState::new_alive(3, make_addr(3000), 1));
        // Exclude target=99 (not present) → 2 eligible peers, request k=10.
        let peers = pick_k_random_peers(&t, 1, 99, 10);
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn k_peers_excludes_dead() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 1));
        insert_with_status(&mut t, 3, 3000, NodeStatus::Dead);
        let peers = pick_k_random_peers(&t, 1, 99, 10);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].0, 2);
    }

    #[test]
    fn k_peers_includes_suspect() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        insert_with_status(&mut t, 2, 2000, NodeStatus::Suspect);
        let peers = pick_k_random_peers(&t, 1, 99, 10);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].0, 2);
    }

    // ── pick_gossip_targets tests ─────────────────────────────────────────────

    #[test]
    fn targets_empty_when_alone() {
        let t = MembershipTable::new(1, make_addr(1000));
        let targets = pick_gossip_targets(&t, 1, 5);
        assert!(targets.is_empty());
    }

    #[test]
    fn targets_capped_at_max() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        for i in 2..=10u64 {
            t.merge_entry(&NodeState::new_alive(i, make_addr(1000 + i as u16), i as u32));
        }
        let targets = pick_gossip_targets(&t, 1, 3);
        assert_eq!(targets.len(), 3);
        // All targets must be unique.
        let ids: std::collections::HashSet<_> = targets.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn targets_capped_at_live_peers() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 1));
        // Request more targets than available.
        let targets = pick_gossip_targets(&t, 1, 10);
        assert_eq!(targets.len(), 1);
    }

    #[test]
    fn targets_excludes_self() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 1));
        let targets = pick_gossip_targets(&t, 1, 5);
        assert!(targets.iter().all(|(id, _)| *id != 1));
    }

    #[test]
    fn targets_excludes_dead_nodes() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 1));
        insert_with_status(&mut t, 3, 3000, NodeStatus::Dead);
        let targets = pick_gossip_targets(&t, 1, 10);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, 2);
    }

    #[test]
    fn targets_includes_suspect_nodes() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        insert_with_status(&mut t, 2, 2000, NodeStatus::Suspect);
        let targets = pick_gossip_targets(&t, 1, 10);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, 2);
    }

    #[test]
    fn targets_all_unique_ids() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        for i in 2..=20u64 {
            t.merge_entry(&NodeState::new_alive(i, make_addr(1000 + i as u16), 1));
        }
        let targets = pick_gossip_targets(&t, 1, 10);
        let ids: std::collections::HashSet<_> = targets.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids.len(), targets.len(), "all target IDs must be distinct");
    }

    #[test]
    fn targets_max_zero_returns_empty() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 1));
        let targets = pick_gossip_targets(&t, 1, 0);
        assert!(targets.is_empty());
    }

    // ── build_gossip_message tests ───────────────────────────────────────────

    #[test]
    fn gossip_message_has_correct_kind() {
        let t = MembershipTable::new(1, make_addr(1000));
        let msg = build_gossip_message(&t, 1, 42, 3, 10);
        assert_eq!(msg.kind, kind::GOSSIP);
    }

    #[test]
    fn gossip_message_has_correct_sender_fields() {
        let t = MembershipTable::new(1, make_addr(1000));
        let msg = build_gossip_message(&t, 1, 42, 3, 10);
        assert_eq!(msg.sender_id, 1);
        assert_eq!(msg.sender_heartbeat, 42);
        assert_eq!(msg.sender_incarnation, 3);
    }

    #[test]
    fn gossip_message_contains_table_entries() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 5));
        t.merge_entry(&NodeState::new_alive(3, make_addr(3000), 7));

        let msg = build_gossip_message(&t, 1, 0, 0, 50);
        match &msg.payload {
            MessagePayload::Gossip(entries) => {
                // Table has self + 2 peers = 3 entries.
                assert_eq!(entries.len(), 3);
                let ids: std::collections::HashSet<_> = entries.iter().map(|e| e.node_id).collect();
                assert!(ids.contains(&1));
                assert!(ids.contains(&2));
                assert!(ids.contains(&3));
            }
            _ => panic!("expected Gossip payload"),
        }
    }

    #[test]
    fn gossip_message_respects_fanout_limit() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        for i in 2..=20u64 {
            t.merge_entry(&NodeState::new_alive(i, make_addr(1000 + i as u16), 1));
        }
        // 20 entries in table (self + 19 peers), fanout=5.
        let msg = build_gossip_message(&t, 1, 0, 0, 5);
        match &msg.payload {
            MessagePayload::Gossip(entries) => {
                assert_eq!(entries.len(), 5);
            }
            _ => panic!("expected Gossip payload"),
        }
    }

    #[test]
    fn gossip_message_empty_table_produces_self_only() {
        let t = MembershipTable::new(1, make_addr(1000));
        let msg = build_gossip_message(&t, 1, 0, 0, 50);
        match &msg.payload {
            MessagePayload::Gossip(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].node_id, 1);
            }
            _ => panic!("expected Gossip payload"),
        }
    }

    #[test]
    fn gossip_message_encodes_and_decodes() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 5));

        let msg = build_gossip_message(&t, 1, 99, 7, 50);
        let buf = msg.encode().unwrap();
        let decoded = crate::message::Message::decode(&buf).unwrap();

        assert_eq!(decoded.kind, kind::GOSSIP);
        assert_eq!(decoded.sender_id, 1);
        assert_eq!(decoded.sender_heartbeat, 99);
        assert_eq!(decoded.sender_incarnation, 7);
        match decoded.payload {
            MessagePayload::Gossip(entries) => {
                assert_eq!(entries.len(), 2);
            }
            _ => panic!("expected Gossip payload"),
        }
    }

    #[test]
    fn gossip_message_excludes_placeholders() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.add_bootstrap_peer(make_addr(9000)); // creates a placeholder
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 1));

        // Table has 3 entries (self + placeholder + real peer), but gossip
        // digest excludes placeholders → only 2 in the message.
        let msg = build_gossip_message(&t, 1, 0, 0, 50);
        match &msg.payload {
            MessagePayload::Gossip(entries) => {
                assert_eq!(entries.len(), 2);
                let ids: std::collections::HashSet<_> = entries.iter().map(|e| e.node_id).collect();
                assert!(ids.contains(&1));
                assert!(ids.contains(&2));
            }
            _ => panic!("expected Gossip payload"),
        }
    }

    #[test]
    fn gossip_message_includes_dead_entries() {
        // Dead entries are gossiped so other nodes learn about failures.
        let mut t = MembershipTable::new(1, make_addr(1000));
        insert_with_status(&mut t, 2, 2000, NodeStatus::Dead);

        let msg = build_gossip_message(&t, 1, 0, 0, 50);
        match &msg.payload {
            MessagePayload::Gossip(entries) => {
                let dead_entry = entries.iter().find(|e| e.node_id == 2);
                assert!(dead_entry.is_some(), "Dead entries must be included in gossip");
                assert_eq!(dead_entry.unwrap().status, crate::message::status::DEAD);
            }
            _ => panic!("expected Gossip payload"),
        }
    }

    // ── build_full_sync_message tests ───────────────────────────────────────

    #[test]
    fn full_sync_includes_all_entries() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        for i in 2..=10u64 {
            t.merge_entry(&NodeState::new_alive(i, make_addr(1000 + i as u16), 1));
        }
        let msg = build_full_sync_message(&t, 1, 0, 0);
        match &msg.payload {
            MessagePayload::Gossip(entries) => {
                // All 10 entries (self + 9 peers).
                assert_eq!(entries.len(), 10);
            }
            _ => panic!("expected Gossip payload"),
        }
    }

    #[test]
    fn full_sync_excludes_placeholders() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.add_bootstrap_peer(make_addr(9000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 1));
        let msg = build_full_sync_message(&t, 1, 0, 0);
        match &msg.payload {
            MessagePayload::Gossip(entries) => {
                assert_eq!(entries.len(), 2); // self + peer, no placeholder
            }
            _ => panic!("expected Gossip payload"),
        }
    }

    #[test]
    fn gossip_message_fanout_zero_produces_empty_payload() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 1));
        let msg = build_gossip_message(&t, 1, 0, 0, 0);
        match &msg.payload {
            MessagePayload::Gossip(entries) => {
                assert!(entries.is_empty());
            }
            _ => panic!("expected Gossip payload"),
        }
    }
}
