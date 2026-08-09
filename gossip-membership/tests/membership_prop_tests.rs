/// Property-based tests for the membership merge algorithm using proptest.
///
/// The SWIM merge has a deliberate asymmetry: Dead is terminal at the
/// same incarnation.  This means `merge(Alive(hb=5), Dead(hb=3))` !=
/// `merge(Dead(hb=3), Alive(hb=5))` when both share the same incarnation.
/// This is by design — the protocol relies on epidemic dissemination to
/// propagate Dead state before stale Alive entries can interfere.
///
/// The tests below verify the properties that DO hold unconditionally.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use proptest::prelude::*;

use gossip_membership::membership::MembershipTable;
use gossip_membership::node::{NodeState, NodeStatus};

// ── Helpers ─────────────────────────────────────────────────────────────────

fn addr_for(id: u64) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, (id >> 8) as u8, id as u8)),
        9000 + id as u16,
    )
}

fn fresh_table() -> MembershipTable {
    MembershipTable::new(0, addr_for(0))
}

fn observable(s: &NodeState) -> (u64, u32, u32, NodeStatus) {
    (s.node_id, s.incarnation, s.heartbeat, s.status)
}

fn tables_equal(a: &MembershipTable, b: &MembershipTable) -> bool {
    if a.entries.len() != b.entries.len() {
        return false;
    }
    for (id, sa) in &a.entries {
        match b.entries.get(id) {
            Some(sb) if observable(sa) == observable(sb) => {}
            _ => return false,
        }
    }
    true
}

// ── Proptest strategies ─────────────────────────────────────────────────────

fn arb_status() -> impl Strategy<Value = NodeStatus> {
    prop_oneof![
        Just(NodeStatus::Alive),
        Just(NodeStatus::Suspect),
        Just(NodeStatus::Dead),
    ]
}

fn arb_node_state() -> impl Strategy<Value = NodeState> {
    (1u64..=20, 0u32..=5, 0u32..=50, arb_status()).prop_map(|(id, inc, hb, status)| {
        let mut s = NodeState::new_alive(id, addr_for(id), hb);
        s.incarnation = inc;
        s.status = status;
        s
    })
}

/// Updates for the same node at the same (inc, hb), varying only status.
/// Commutativity provably holds for this case.
fn arb_same_version_updates() -> impl Strategy<Value = Vec<NodeState>> {
    (
        1u64..=20,
        0u32..=5,
        0u32..=50,
        prop::collection::vec(arb_status(), 2..=8),
    )
        .prop_map(|(id, inc, hb, statuses)| {
            statuses
                .into_iter()
                .map(|st| {
                    let mut s = NodeState::new_alive(id, addr_for(id), hb);
                    s.incarnation = inc;
                    s.status = st;
                    s
                })
                .collect()
        })
}

// ── Property tests ──────────────────────────────────────────────────────────

proptest! {
    /// **Idempotency**: merge(A, A) == A.
    #[test]
    fn merge_is_idempotent(entry in arb_node_state()) {
        let mut t1 = fresh_table();
        t1.merge_entry(&entry);

        let mut t2 = fresh_table();
        t2.merge_entry(&entry);
        t2.merge_entry(&entry);

        prop_assert!(tables_equal(&t1, &t2),
            "merge(A) != merge(A,A): {:?}", observable(&entry));
    }

    /// **Commutativity at same (inc, hb)**: when two entries differ only
    /// in status, merge order doesn't matter — most severe wins.
    #[test]
    fn commutativity_same_version(updates in arb_same_version_updates()) {
        let mut t_fwd = fresh_table();
        for u in &updates {
            t_fwd.merge_entry(u);
        }

        let mut t_rev = fresh_table();
        for u in updates.iter().rev() {
            t_rev.merge_entry(u);
        }

        prop_assert!(tables_equal(&t_fwd, &t_rev),
            "same (inc,hb) updates must be commutative");
    }

    /// **Commutativity across incarnations**: when entries have different
    /// incarnations, the highest incarnation wins regardless of order.
    #[test]
    fn commutativity_different_incarnations(
        id in 1u64..=20,
        inc_a in 0u32..=3,
        inc_b in 4u32..=8,
        hb_a in 0u32..=50,
        hb_b in 0u32..=50,
        st_a in arb_status(),
        st_b in arb_status(),
    ) {
        let mut a = NodeState::new_alive(id, addr_for(id), hb_a);
        a.incarnation = inc_a;
        a.status = st_a;

        let mut b = NodeState::new_alive(id, addr_for(id), hb_b);
        b.incarnation = inc_b;
        b.status = st_b;

        let mut t1 = fresh_table();
        t1.merge_entry(&a);
        t1.merge_entry(&b);

        let mut t2 = fresh_table();
        t2.merge_entry(&b);
        t2.merge_entry(&a);

        prop_assert!(tables_equal(&t1, &t2));
    }

    /// **Dead terminality**: Dead at inc=N blocks Alive/Suspect at inc=N.
    #[test]
    fn dead_terminal_at_same_incarnation(
        inc in 0u32..=5,
        hb_dead in 0u32..=50,
        hb_alive in 0u32..=50,
        id in 1u64..=20,
    ) {
        let mut table = fresh_table();

        let mut dead = NodeState::new_alive(id, addr_for(id), hb_dead);
        dead.incarnation = inc;
        dead.status = NodeStatus::Dead;
        table.merge_entry(&dead);

        let mut alive = NodeState::new_alive(id, addr_for(id), hb_alive);
        alive.incarnation = inc;
        table.merge_entry(&alive);

        prop_assert_eq!(table.entries.get(&id).unwrap().status, NodeStatus::Dead);
    }

    /// **Dead resurrection**: higher incarnation overrides Dead.
    #[test]
    fn dead_overridden_by_higher_incarnation(
        inc in 0u32..=4,
        id in 1u64..=20,
    ) {
        let mut table = fresh_table();

        let mut dead = NodeState::new_alive(id, addr_for(id), 10);
        dead.incarnation = inc;
        dead.status = NodeStatus::Dead;
        table.merge_entry(&dead);

        let mut rejoin = NodeState::new_alive(id, addr_for(id), 0);
        rejoin.incarnation = inc + 1;
        table.merge_entry(&rejoin);

        let e = table.entries.get(&id).unwrap();
        prop_assert_eq!(e.status, NodeStatus::Alive);
        prop_assert_eq!(e.incarnation, inc + 1);
    }

    /// **Higher incarnation always wins** regardless of other fields.
    #[test]
    fn higher_incarnation_always_wins(
        id in 1u64..=20,
        inc_low in 0u32..=3,
        inc_high in 4u32..=8,
        hb_low in 0u32..=100,
        hb_high in 0u32..=100,
        st_low in arb_status(),
        st_high in arb_status(),
    ) {
        let mut table = fresh_table();

        let mut old = NodeState::new_alive(id, addr_for(id), hb_low);
        old.incarnation = inc_low;
        old.status = st_low;
        table.merge_entry(&old);

        let mut new = NodeState::new_alive(id, addr_for(id), hb_high);
        new.incarnation = inc_high;
        new.status = st_high;
        table.merge_entry(&new);

        let e = table.entries.get(&id).unwrap();
        prop_assert_eq!(e.incarnation, inc_high);
        prop_assert_eq!(e.status, st_high);
        prop_assert_eq!(e.heartbeat, hb_high);
    }

    /// **Status severity**: at same (inc, hb), Suspect > Alive and
    /// Dead > Suspect.
    #[test]
    fn status_severity_ordering(
        id in 1u64..=20,
        inc in 0u32..=5,
        hb in 0u32..=50,
    ) {
        let mut t = fresh_table();

        let mut alive = NodeState::new_alive(id, addr_for(id), hb);
        alive.incarnation = inc;
        t.merge_entry(&alive);

        let mut suspect = NodeState::new_alive(id, addr_for(id), hb);
        suspect.incarnation = inc;
        suspect.status = NodeStatus::Suspect;
        t.merge_entry(&suspect);
        prop_assert_eq!(t.entries.get(&id).unwrap().status, NodeStatus::Suspect);

        let mut dead = NodeState::new_alive(id, addr_for(id), hb);
        dead.incarnation = inc;
        dead.status = NodeStatus::Dead;
        t.merge_entry(&dead);
        prop_assert_eq!(t.entries.get(&id).unwrap().status, NodeStatus::Dead);
    }

    /// **Convergence with distinct incarnations**: when all updates for
    /// each node have distinct incarnations, merge is order-independent.
    #[test]
    fn convergence_distinct_incarnations(seed in any::<u64>()) {
        use rand::seq::SliceRandom;
        use rand::SeedableRng;

        let mut updates = Vec::new();
        for id in 1u64..=5 {
            for inc in 0u32..=3 {
                let st = match (id + inc as u64) % 3 {
                    0 => NodeStatus::Alive,
                    1 => NodeStatus::Suspect,
                    _ => NodeStatus::Dead,
                };
                let mut s = NodeState::new_alive(id, addr_for(id), inc * 10);
                s.incarnation = inc;
                s.status = st;
                updates.push(s);
            }
        }

        let mut perm1 = updates.clone();
        let mut perm2 = updates;
        let mut rng1 = rand::rngs::StdRng::seed_from_u64(seed);
        let mut rng2 = rand::rngs::StdRng::seed_from_u64(seed.wrapping_add(7));
        perm1.shuffle(&mut rng1);
        perm2.shuffle(&mut rng2);

        let mut t1 = fresh_table();
        for u in &perm1 { t1.merge_entry(u); }
        let mut t2 = fresh_table();
        for u in &perm2 { t2.merge_entry(u); }

        prop_assert!(tables_equal(&t1, &t2),
            "distinct-incarnation updates must converge under any ordering");
    }

    /// **Convergence with same-version status updates**: when all entries
    /// for a node share (inc, hb) and differ only in status, any order
    /// converges to the most severe status.
    #[test]
    fn convergence_same_version_status(updates in arb_same_version_updates()) {
        use rand::seq::SliceRandom;
        use rand::SeedableRng;

        let mut perm1 = updates.clone();
        let mut perm2 = updates;
        let mut rng = rand::rngs::StdRng::seed_from_u64(12345);
        perm1.shuffle(&mut rng);
        let mut rng = rand::rngs::StdRng::seed_from_u64(67890);
        perm2.shuffle(&mut rng);

        let mut t1 = fresh_table();
        for u in &perm1 { t1.merge_entry(u); }
        let mut t2 = fresh_table();
        for u in &perm2 { t2.merge_entry(u); }

        prop_assert!(tables_equal(&t1, &t2));
    }
}
