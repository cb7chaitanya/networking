/// Membership table: stores the cluster-wide view of node state and implements
/// the gossip merge rules.
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::message::{status, WireNodeEntry};
use crate::metrics::MergeOutcome;
use crate::node::{NodeId, NodeState, NodeStatus};

// ── Table ─────────────────────────────────────────────────────────────────────
pub struct MembershipTable {
    pub entries: HashMap<NodeId, NodeState>,
    pub local_id: NodeId,
    local_addr: SocketAddr,
    local_heartbeat: u32,
    /// Our own incarnation number. Incremented whenever we learn we have been
    /// suspected, allowing us to refute without inflating our heartbeat counter.
    local_incarnation: u32,
    /// Node IDs that are bootstrap placeholders (synthetic, pre-real-id).
    /// Tracked so we can (a) filter them from gossip output and (b) evict them
    /// when a real entry for the same address arrives.
    placeholder_ids: HashSet<NodeId>,
}

impl MembershipTable {
    pub fn new(local_id: NodeId, local_addr: SocketAddr) -> Self {
        let mut t = Self {
            entries: HashMap::new(),
            local_id,
            local_addr,
            local_heartbeat: 0,
            local_incarnation: 0,
            placeholder_ids: HashSet::new(),
        };
        // Seed our own entry as Alive with heartbeat 0, incarnation 0.
        t.entries.insert(
            local_id,
            NodeState::new_alive(local_id, local_addr, 0),
        );
        t
    }

    pub fn our_heartbeat(&self) -> u32 {
        self.local_heartbeat
    }

    pub fn our_incarnation(&self) -> u32 {
        self.local_incarnation
    }

    /// Increment our own heartbeat counter and refresh our membership entry.
    /// Called on every heartbeat tick.
    pub fn tick_heartbeat(&mut self) {
        self.local_heartbeat = self.local_heartbeat.wrapping_add(1);
        let hb = self.local_heartbeat;
        let inc = self.local_incarnation;
        let addr = self.local_addr;
        let id = self.local_id;
        let entry = self.entries.entry(id).or_insert_with(|| {
            NodeState::new_alive(id, addr, 0)
        });
        entry.heartbeat = hb;
        entry.incarnation = inc;
        entry.status = NodeStatus::Alive;
        entry.last_update = Instant::now();
    }

    // ── Merge rules ───────────────────────────────────────────────────────────
    /// Merge a single incoming node state from a gossip digest.
    ///
    /// Rules (in priority order):
    /// 1. Ignore entries about ourselves — we are the authority on our own state.
    ///    Exception: if remote gossip says we are Suspect/Dead at an incarnation
    ///    >= ours, we must refute by incrementing our incarnation and re-asserting
    ///    Alive (SWIM §4.2 — no heartbeat inflation).
    /// 2. Insert unknown entries unconditionally.
    /// 3. Dead entries: a higher incarnation can resurrect a Dead node (rejoin).
    ///    Same or lower incarnation cannot override Dead.
    /// 4. Higher incarnation always wins (wrapping-safe, RFC 1982 arithmetic).
    /// 5. Equal incarnation: higher heartbeat wins.
    /// 6. Equal incarnation + equal heartbeat: more severe status wins.
    /// 7. Otherwise discard — existing entry is equally or more current.
    pub fn merge_entry(&mut self, incoming: &NodeState) -> MergeOutcome {
        // Discard stale placeholder views of our own address.  When a peer
        // bootstraps it creates a synthetic placeholder entry for us (with a
        // derived node_id) and may gossip it before learning our real id.
        // That entry has our local_addr but a different node_id, so the
        // self-id check below would miss it and create a duplicate address entry.
        // We are always the authority on our own address, so any entry that
        // carries local_addr but a different node_id must be discarded.
        if incoming.addr == self.local_addr && incoming.node_id != self.local_id {
            return MergeOutcome::SelfEntry;
        }

        // Rule 1: never let remote nodes overwrite our own entry.
        if incoming.node_id == self.local_id {
            // Refute suspicion: only act when the remote claims our status is
            // non-Alive at an incarnation >= our current one.  If the remote's
            // incarnation is stale (lower than ours), our already-gossiped
            // refutation supersedes it — no action needed.
            if incoming.status != NodeStatus::Alive
                && !is_newer(self.local_incarnation, incoming.incarnation)
            {
                self.local_incarnation = self.local_incarnation.wrapping_add(1);
                let inc = self.local_incarnation;
                let hb = self.local_heartbeat;
                let addr = self.local_addr;
                let id = self.local_id;
                log::info!(
                    "[membership] received suspicion at incarnation {}; refuting with incarnation {}",
                    incoming.incarnation,
                    inc,
                );
                let e = self.entries.entry(id).or_insert_with(|| NodeState::new_alive(id, addr, 0));
                e.incarnation = inc;
                e.heartbeat = hb;
                e.status = NodeStatus::Alive;
                e.last_update = Instant::now();
            }
            return MergeOutcome::SelfEntry;
        }

        let now = Instant::now();
        let existing = self.entries.get(&incoming.node_id);

        match existing {
            // Rule 2: new node.
            None => {
                // If we hold a placeholder for this address, evict it now —
                // the incoming entry carries the real node_id.
                self.evict_placeholder_at(incoming.addr);

                self.entries.insert(incoming.node_id, {
                    let mut s = incoming.clone();
                    s.last_update = now;
                    s
                });
                log::info!(
                    "[membership] new node {} @ {} (hb={}, inc={}, status={:?})",
                    incoming.node_id,
                    incoming.addr,
                    incoming.heartbeat,
                    incoming.incarnation,
                    incoming.status
                );
                MergeOutcome::New
            }
            Some(existing) => {
                // Rule 3: Dead can only be overridden by a higher incarnation
                // (the node restarted and is rejoining the cluster).
                if existing.status == NodeStatus::Dead
                    && !is_newer(incoming.incarnation, existing.incarnation)
                {
                    return MergeOutcome::Stale;
                }

                let update = if is_newer(incoming.incarnation, existing.incarnation) {
                    // Rule 4: higher incarnation always wins (including Dead → Alive rejoin).
                    true
                } else if incoming.incarnation == existing.incarnation {
                    if is_newer(incoming.heartbeat, existing.heartbeat) {
                        // Rule 5: same incarnation, newer heartbeat wins.
                        true
                    } else if incoming.heartbeat == existing.heartbeat
                        && incoming.status > existing.status
                    {
                        // Rule 6: same incarnation + heartbeat, more severe status wins.
                        true
                    } else {
                        // Rule 7: discard.
                        false
                    }
                } else {
                    // Incoming incarnation is older — discard.
                    false
                };

                if update {
                    let old_status = existing.status;
                    let entry = self.entries.get_mut(&incoming.node_id).unwrap();
                    entry.heartbeat = incoming.heartbeat;
                    entry.incarnation = incoming.incarnation;
                    entry.addr = incoming.addr;
                    entry.last_update = now;

                    if incoming.status != old_status {
                        log::info!(
                            "[membership] node {} status: {:?} → {:?} (hb={}, inc={})",
                            incoming.node_id,
                            old_status,
                            incoming.status,
                            incoming.heartbeat,
                            incoming.incarnation,
                        );
                    }

                    entry.status = incoming.status;
                    if incoming.status == NodeStatus::Suspect && old_status != NodeStatus::Suspect {
                        entry.suspect_since = Some(now);
                    } else if incoming.status != NodeStatus::Suspect {
                        entry.suspect_since = None;
                    }
                    MergeOutcome::Updated
                } else {
                    MergeOutcome::Stale
                }
            }
        }
    }

    /// Merge a full gossip digest (slice of node states).
    /// Returns the outcomes for each entry so the caller can update metrics.
    pub fn merge_digest(&mut self, entries: &[NodeState]) -> Vec<MergeOutcome> {
        entries.iter().map(|e| self.merge_entry(e)).collect()
    }

    // ── Status transitions ────────────────────────────────────────────────────
    pub fn suspect(&mut self, id: NodeId) {
        if let Some(e) = self.entries.get_mut(&id) {
            if e.status == NodeStatus::Alive {
                log::info!("[membership] node {} → Suspect", id);
                e.status = NodeStatus::Suspect;
                e.suspect_since = Some(Instant::now());
                e.last_update = Instant::now();
            }
        }
    }

    pub fn declare_dead(&mut self, id: NodeId) {
        if let Some(e) = self.entries.get_mut(&id) {
            if e.status != NodeStatus::Dead {
                log::info!("[membership] node {} → Dead", id);
                e.status = NodeStatus::Dead;
                e.suspect_since = None;
                e.last_update = Instant::now();
            }
        }
    }

    // ── Queries ───────────────────────────────────────────────────────────────
    /// Count entries by status: `(alive, suspect, dead)`.
    pub fn status_counts(&self) -> (usize, usize, usize) {
        let mut alive = 0usize;
        let mut suspect = 0usize;
        let mut dead = 0usize;
        for e in self.entries.values() {
            match e.status {
                NodeStatus::Alive => alive += 1,
                NodeStatus::Suspect => suspect += 1,
                NodeStatus::Dead => dead += 1,
            }
        }
        (alive, suspect, dead)
    }

    /// Return IDs of all nodes currently Alive or Suspect, excluding ourselves.
    pub fn live_nodes(&self) -> Vec<NodeId> {
        self.entries
            .values()
            .filter(|e| {
                e.node_id != self.local_id
                    && matches!(e.status, NodeStatus::Alive | NodeStatus::Suspect)
            })
            .map(|e| e.node_id)
            .collect()
    }

    /// Return all entries where `suspect_since` has exceeded `timeout`, so the
    /// event loop can promote them to Dead.
    pub fn expired_suspects(&self, timeout: Duration) -> Vec<NodeId> {
        let now = Instant::now();
        self.entries
            .values()
            .filter(|e| {
                e.status == NodeStatus::Suspect
                    && e.suspect_since
                        .map(|s| now.duration_since(s) >= timeout)
                        .unwrap_or(false)
            })
            .map(|e| e.node_id)
            .collect()
    }

    /// Compute the effective suspect timeout scaled by cluster size.
    ///
    /// Formula: `base * (1 + multiplier * log2(n))` where `n` is the number
    /// of known entries.  This matches SWIM's O(log n) protocol period scaling
    /// so larger clusters tolerate higher latency before declaring Dead.
    pub fn suspect_timeout(&self, base_ms: u64, multiplier: f64) -> Duration {
        let n = self.entries.len().max(1) as f64;
        let scale = 1.0 + multiplier * n.log2().max(0.0);
        Duration::from_millis((base_ms as f64 * scale) as u64)
    }

    /// Return IDs of Suspects that have exceeded their jittered deadline.
    ///
    /// Each observer-suspect pair gets a deterministic jitter offset derived
    /// from `hash(local_id, suspect_id) % jitter_ms`, so different nodes in
    /// the cluster will promote the same suspect to Dead at staggered times.
    /// This prevents a thundering herd of simultaneous Dead declarations.
    pub fn expired_suspects_jittered(
        &self,
        base_ms: u64,
        multiplier: f64,
        jitter_ms: u64,
    ) -> Vec<NodeId> {
        let base = self.suspect_timeout(base_ms, multiplier);
        let now = Instant::now();
        self.entries
            .values()
            .filter(|e| {
                e.status == NodeStatus::Suspect
                    && e.suspect_since
                        .map(|s| {
                            let jitter = suspect_jitter(self.local_id, e.node_id, jitter_ms);
                            now.duration_since(s) >= base + jitter
                        })
                        .unwrap_or(false)
            })
            .map(|e| e.node_id)
            .collect()
    }

    /// Remove Dead entries that have been dead for longer than `retention`.
    /// This prevents unbounded growth of the gossip digest.
    pub fn gc_dead(&mut self, retention: Duration) {
        let now = Instant::now();
        self.entries.retain(|_, e| {
            if e.status == NodeStatus::Dead {
                now.duration_since(e.last_update) < retention
            } else {
                true
            }
        });
    }

    /// Return up to `max_entries` entries for gossiping, prioritising recently
    /// updated entries so fresh information spreads faster (infection-style).
    ///
    /// Placeholder entries (bootstrap peers whose real IDs we haven't learned
    /// yet) are excluded — they are local bookkeeping and must not propagate.
    pub fn gossip_digest(&self, max_entries: usize) -> Vec<NodeState> {
        let mut all: Vec<&NodeState> = self
            .entries
            .values()
            .filter(|e| !self.placeholder_ids.contains(&e.node_id))
            .collect();
        // Most recently updated first.
        all.sort_by(|a, b| b.last_update.cmp(&a.last_update));
        all.truncate(max_entries);
        all.into_iter().cloned().collect()
    }

    /// Returns `true` if `id` is a bootstrap placeholder (synthetic node ID).
    pub fn is_placeholder(&self, id: NodeId) -> bool {
        self.placeholder_ids.contains(&id)
    }

    /// Convert a gossip digest into wire entries.
    pub fn gossip_wire_entries(&self, max_entries: usize) -> Vec<WireNodeEntry> {
        self.gossip_digest(max_entries)
            .iter()
            .filter_map(|s| node_state_to_wire(s))
            .collect()
    }

    /// Add a bootstrap peer to the table (used at startup before any gossip).
    pub fn add_bootstrap_peer(&mut self, addr: SocketAddr) {
        // We don't know the peer's node_id yet; derive a placeholder key from
        // the address. The real entry will be corrected by the first gossip round.
        let placeholder_id = placeholder_id_for(addr);
        if !self.entries.contains_key(&placeholder_id) {
            log::debug!("[membership] bootstrap peer {} (placeholder id={})", addr, placeholder_id);
            self.entries.insert(
                placeholder_id,
                NodeState::new_alive(placeholder_id, addr, 0),
            );
            self.placeholder_ids.insert(placeholder_id);
        }
    }

    /// Remove the placeholder entry for `addr` if the real sender's `id` differs.
    ///
    /// Called on every incoming message before inserting the real node entry.
    /// If the sender's real `id` matches the placeholder ID, the entry is already
    /// correct and nothing happens.
    ///
    /// This is safe to call unconditionally: if no placeholder exists the
    /// operation is a no-op.  Because the event loop processes messages
    /// sequentially there are no concurrent mutation hazards.
    pub fn remove_placeholder_for_addr(&mut self, addr: SocketAddr, real_id: NodeId) {
        let placeholder_id = placeholder_id_for(addr);
        if real_id == placeholder_id {
            return;
        }
        if self.entries.get(&placeholder_id).map(|e| e.addr == addr).unwrap_or(false) {
            self.entries.remove(&placeholder_id);
            self.placeholder_ids.remove(&placeholder_id);
            log::debug!(
                "[membership] removed placeholder {} for {} (real id={})",
                placeholder_id, addr, real_id
            );
        }
    }

    /// Evict a placeholder whose address matches `addr`.
    ///
    /// Called from `merge_entry` when inserting a real node entry. This handles
    /// the case where we learn a node's real ID through gossip (not a direct
    /// message), so `remove_placeholder_for_addr` was never called for it.
    fn evict_placeholder_at(&mut self, addr: SocketAddr) {
        let placeholder_id = placeholder_id_for(addr);
        if self.placeholder_ids.contains(&placeholder_id) {
            if self.entries.get(&placeholder_id).map(|e| e.addr == addr).unwrap_or(false) {
                self.entries.remove(&placeholder_id);
                self.placeholder_ids.remove(&placeholder_id);
                log::debug!(
                    "[membership] evicted placeholder {} for addr {} (real entry arriving via gossip)",
                    placeholder_id, addr
                );
            }
        }
    }
}

// ── Conversion helpers ────────────────────────────────────────────────────────
/// Convert a `NodeState` to a wire entry (supports both IPv4 and IPv6).
pub fn node_state_to_wire(s: &NodeState) -> Option<WireNodeEntry> {
    Some(WireNodeEntry {
        node_id: s.node_id,
        heartbeat: s.heartbeat,
        incarnation: s.incarnation,
        status: s.status.to_wire(),
        addr: s.addr,
    })
}

/// Convert a received wire entry into a local `NodeState`.
pub fn wire_to_node_state(e: &WireNodeEntry) -> Option<NodeState> {
    let status = NodeStatus::from_wire(e.status)?;
    Some(NodeState {
        node_id: e.node_id,
        addr: e.addr,
        heartbeat: e.heartbeat,
        incarnation: e.incarnation,
        status,
        last_update: Instant::now(),
        suspect_since: if status == NodeStatus::Suspect {
            Some(Instant::now())
        } else {
            None
        },
    })
}

/// Derive a deterministic placeholder `NodeId` from a `SocketAddr`.
///
/// Used for bootstrap peers whose real IDs we don't yet know.  The XOR
/// sentinel ensures placeholder IDs cannot collide with real node IDs
/// generated by [`crate::node::generate_node_id`].
pub fn placeholder_id_for(addr: SocketAddr) -> NodeId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    addr.hash(&mut h);
    h.finish() ^ 0xDEAD_BEEF_0000_0000
}

// ── Suspect jitter ───────────────────────────────────────────────────────
/// Deterministic per-observer-per-suspect jitter.
///
/// Returns a `Duration` in `[0, max_jitter_ms)` derived from
/// `hash(observer_id, suspect_id)`.  Because each node in the cluster has a
/// unique `observer_id`, the same suspect gets a different jitter offset on
/// each observer, spreading out Dead declarations in time.
fn suspect_jitter(observer_id: NodeId, suspect_id: NodeId, max_jitter_ms: u64) -> Duration {
    if max_jitter_ms == 0 {
        return Duration::ZERO;
    }
    let mut h = DefaultHasher::new();
    observer_id.hash(&mut h);
    suspect_id.hash(&mut h);
    let jitter_ms = h.finish() % max_jitter_ms;
    Duration::from_millis(jitter_ms)
}

// ── Heartbeat ordering ────────────────────────────────────────────────────────

/// Returns `true` if heartbeat `a` is strictly newer than `b` using
/// TCP-style serial-number arithmetic (RFC 1982).
///
/// A heartbeat is newer when `(a.wrapping_sub(b)) < 2^31`, which handles
/// wrap-around from `u32::MAX` back to `0` correctly.
///
/// # Examples
/// ```
/// use gossip_membership::membership::is_newer;
/// assert!(is_newer(1, 0));
/// assert!(is_newer(0, u32::MAX));   // wrap: 0 is newer than MAX
/// assert!(!is_newer(0, 1));
/// assert!(!is_newer(5, 5));         // equal → not newer
/// ```
pub fn is_newer(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < (1u32 << 31)
}

// ── Status wire constants exposed for tests ───────────────────────────────────
pub use status::{ALIVE, DEAD, SUSPECT};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn insert_new_entry() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        let peer = NodeState::new_alive(2, make_addr(2000), 1);
        t.merge_entry(&peer);
        assert_eq!(t.entries[&2].heartbeat, 1);
        assert_eq!(t.entries[&2].status, NodeStatus::Alive);
    }

    #[test]
    fn higher_heartbeat_wins() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 1));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 5));
        assert_eq!(t.entries[&2].heartbeat, 5);
    }

    #[test]
    fn lower_heartbeat_ignored() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 5));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 3));
        assert_eq!(t.entries[&2].heartbeat, 5);
    }

    #[test]
    fn dead_blocks_same_incarnation() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        let mut dead = NodeState::new_alive(2, make_addr(2000), 10);
        dead.status = NodeStatus::Dead;
        t.merge_entry(&dead);
        // Alive with higher heartbeat but same incarnation must not resurrect.
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 20));
        assert_eq!(t.entries[&2].status, NodeStatus::Dead);
    }

    /// A Dead node can rejoin the cluster with a higher incarnation number.
    #[test]
    fn dead_node_rejoins_with_higher_incarnation() {
        let mut t = MembershipTable::new(1, make_addr(1000));

        // Mark peer as Dead at incarnation 0.
        let mut dead = NodeState::new_alive(2, make_addr(2000), 10);
        dead.status = NodeStatus::Dead;
        dead.incarnation = 0;
        t.merge_entry(&dead);
        assert_eq!(t.entries[&2].status, NodeStatus::Dead);

        // Peer restarts and announces itself at incarnation 1.
        let mut rejoin = NodeState::new_alive(2, make_addr(2000), 0);
        rejoin.incarnation = 1;
        t.merge_entry(&rejoin);

        assert_eq!(t.entries[&2].status, NodeStatus::Alive, "higher incarnation must resurrect Dead");
        assert_eq!(t.entries[&2].incarnation, 1);
        assert_eq!(t.entries[&2].heartbeat, 0);
    }

    /// A Dead node cannot rejoin with a lower incarnation.
    #[test]
    fn dead_node_cannot_rejoin_with_lower_incarnation() {
        let mut t = MembershipTable::new(1, make_addr(1000));

        let mut dead = NodeState::new_alive(2, make_addr(2000), 10);
        dead.status = NodeStatus::Dead;
        dead.incarnation = 3;
        t.merge_entry(&dead);

        // Stale rejoin at incarnation 1 — must be rejected.
        let mut stale_rejoin = NodeState::new_alive(2, make_addr(2000), 0);
        stale_rejoin.incarnation = 1;
        t.merge_entry(&stale_rejoin);

        assert_eq!(t.entries[&2].status, NodeStatus::Dead);
        assert_eq!(t.entries[&2].incarnation, 3);
    }

    #[test]
    fn same_heartbeat_suspect_beats_alive() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 3));
        let mut suspect = NodeState::new_alive(2, make_addr(2000), 3);
        suspect.status = NodeStatus::Suspect;
        t.merge_entry(&suspect);
        assert_eq!(t.entries[&2].status, NodeStatus::Suspect);
    }

    #[test]
    fn self_entry_not_overwritten() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.tick_heartbeat();
        let fake = NodeState::new_alive(1, make_addr(9999), 999);
        t.merge_entry(&fake);
        // Our address and heartbeat are ours — addr must not be overwritten.
        assert_eq!(t.entries[&1].addr, make_addr(1000));
    }

    #[test]
    fn tick_heartbeat_increments() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.tick_heartbeat();
        t.tick_heartbeat();
        assert_eq!(t.our_heartbeat(), 2);
        assert_eq!(t.entries[&1].heartbeat, 2);
    }

    #[test]
    fn expired_suspects_returned() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        let mut s = NodeState::new_alive(2, make_addr(2000), 1);
        s.status = NodeStatus::Suspect;
        s.suspect_since = Some(Instant::now() - Duration::from_secs(10));
        t.entries.insert(2, s);
        let expired = t.expired_suspects(Duration::from_secs(5));
        assert!(expired.contains(&2));
    }

    #[test]
    fn gc_removes_old_dead_entries() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        let mut dead = NodeState::new_alive(2, make_addr(2000), 5);
        dead.status = NodeStatus::Dead;
        dead.last_update = Instant::now() - Duration::from_secs(100);
        t.entries.insert(2, dead);
        t.gc_dead(Duration::from_secs(30));
        assert!(!t.entries.contains_key(&2));
    }

    #[test]
    fn live_nodes_excludes_dead_and_self() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 1));
        let mut dead = NodeState::new_alive(3, make_addr(3000), 1);
        dead.status = NodeStatus::Dead;
        t.merge_entry(&dead);
        let live = t.live_nodes();
        assert!(live.contains(&2));
        assert!(!live.contains(&3));
        assert!(!live.contains(&1)); // self
    }

    // ── is_newer unit tests ───────────────────────────────────────────────────

    #[test]
    fn is_newer_basic() {
        assert!(is_newer(1, 0));
        assert!(is_newer(100, 99));
        assert!(!is_newer(0, 1));
        assert!(!is_newer(99, 100));
    }

    #[test]
    fn is_newer_equal_is_not_newer() {
        assert!(!is_newer(0, 0));
        assert!(!is_newer(5, 5));
        assert!(!is_newer(u32::MAX, u32::MAX));
    }

    #[test]
    fn is_newer_wraparound_max_to_zero() {
        // 0 was produced by wrapping_add(MAX, 1) — it is newer than MAX.
        assert!(is_newer(0, u32::MAX));
        assert!(is_newer(1, u32::MAX));
        assert!(is_newer(0, u32::MAX - 1));
    }

    #[test]
    fn is_newer_near_boundary() {
        let half = 1u32 << 31; // 2^31
        // Exactly half the range apart: a.wrapping_sub(b) == 2^31 → NOT newer
        // (ambiguous region; we treat it as not newer for safety).
        assert!(!is_newer(half, 0));
        // One less than half: clearly newer.
        assert!(is_newer(half - 1, 0));
        // One more than half: clearly older.
        assert!(!is_newer(half + 1, 0));
    }

    // ── merge_entry wraparound tests ──────────────────────────────────────────

    #[test]
    fn merge_accepts_wrapped_heartbeat() {
        // Simulate a node whose heartbeat wrapped: existing=MAX, incoming=1.
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), u32::MAX));
        // Wrapped heartbeat (0, then 1) must win over MAX.
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 0));
        assert_eq!(t.entries[&2].heartbeat, 0, "wrapped hb=0 should beat hb=MAX");
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 1));
        assert_eq!(t.entries[&2].heartbeat, 1, "wrapped hb=1 should beat hb=0");
    }

    #[test]
    fn merge_rejects_old_heartbeat_after_wraparound() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        // Node has already wrapped; current heartbeat is 5.
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), 5));
        // A stale pre-wrap value (e.g. MAX) must not overwrite the newer 5.
        t.merge_entry(&NodeState::new_alive(2, make_addr(2000), u32::MAX));
        assert_eq!(t.entries[&2].heartbeat, 5, "stale pre-wrap hb=MAX must not overwrite hb=5");
    }

    #[test]
    fn gossip_digest_most_recent_first() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        // Age the self entry so it sorts below the peers we are about to insert.
        t.entries.get_mut(&1).unwrap().last_update =
            Instant::now() - Duration::from_secs(10);
        for i in 2..=6u64 {
            let mut s = NodeState::new_alive(i, make_addr(i as u16 * 1000), i as u32);
            // Stagger last_update: node 6 is most recent (400 ms ago).
            s.last_update = Instant::now() - Duration::from_millis((10 - i) * 100);
            t.entries.insert(i, s);
        }
        let digest = t.gossip_digest(3);
        // Node 6 has the most recent last_update and must appear first.
        assert_eq!(digest[0].node_id, 6);
    }

    // ── Incarnation tests ─────────────────────────────────────────────────────

    /// When a node receives gossip claiming it is Suspected at the same
    /// incarnation, it must bump its incarnation to 1 and remain Alive.
    #[test]
    fn refute_suspicion_increments_incarnation() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        assert_eq!(t.our_incarnation(), 0);

        // Simulate receiving gossip that says we (node 1) are Suspect at inc=0.
        let mut suspect_self = NodeState::new_alive(1, make_addr(1000), 5);
        suspect_self.status = NodeStatus::Suspect;
        suspect_self.incarnation = 0;
        t.merge_entry(&suspect_self);

        // Incarnation must have been bumped.
        assert_eq!(t.our_incarnation(), 1, "incarnation must increment on refutation");
        // Our own entry must be Alive.
        assert_eq!(t.entries[&1].status, NodeStatus::Alive);
        assert_eq!(t.entries[&1].incarnation, 1);
    }

    /// Stale suspicion (lower incarnation than ours) must be silently ignored;
    /// no refutation is needed because our already-gossiped incarnation wins.
    #[test]
    fn stale_suspicion_not_refuted() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        // Advance our incarnation to 3 (as if we've already refuted twice).
        t.local_incarnation = 3;
        t.entries.get_mut(&1).unwrap().incarnation = 3;

        // Receive an old suspicion at incarnation 1.
        let mut stale_suspect = NodeState::new_alive(1, make_addr(1000), 0);
        stale_suspect.status = NodeStatus::Suspect;
        stale_suspect.incarnation = 1;
        t.merge_entry(&stale_suspect);

        // Incarnation must not have changed.
        assert_eq!(t.our_incarnation(), 3, "stale suspicion must not trigger refutation");
        assert_eq!(t.entries[&1].status, NodeStatus::Alive);
    }

    /// A Dead accusation at our current incarnation also triggers a refutation.
    #[test]
    fn refute_dead_accusation() {
        let mut t = MembershipTable::new(1, make_addr(1000));

        let mut dead_self = NodeState::new_alive(1, make_addr(1000), 0);
        dead_self.status = NodeStatus::Dead;
        dead_self.incarnation = 0;
        t.merge_entry(&dead_self);

        assert_eq!(t.our_incarnation(), 1, "Dead accusation must trigger incarnation bump");
        assert_eq!(t.entries[&1].status, NodeStatus::Alive);
    }

    /// Higher incarnation beats lower incarnation regardless of heartbeat.
    #[test]
    fn higher_incarnation_wins_over_heartbeat() {
        let mut t = MembershipTable::new(1, make_addr(1000));

        // Insert peer at incarnation=0, heartbeat=100.
        let mut old = NodeState::new_alive(2, make_addr(2000), 100);
        old.incarnation = 0;
        t.merge_entry(&old);
        assert_eq!(t.entries[&2].heartbeat, 100);

        // Incoming at incarnation=1, heartbeat=0 must win.
        let mut newer_inc = NodeState::new_alive(2, make_addr(2000), 0);
        newer_inc.incarnation = 1;
        t.merge_entry(&newer_inc);
        assert_eq!(t.entries[&2].incarnation, 1, "higher incarnation must win");
        assert_eq!(t.entries[&2].heartbeat, 0, "heartbeat must update to the winner's value");
    }

    /// Lower incarnation must not overwrite a higher incarnation entry.
    #[test]
    fn lower_incarnation_ignored() {
        let mut t = MembershipTable::new(1, make_addr(1000));

        let mut current = NodeState::new_alive(2, make_addr(2000), 5);
        current.incarnation = 2;
        t.merge_entry(&current);

        // Stale entry at incarnation=1, even with higher heartbeat — must be discarded.
        let mut stale = NodeState::new_alive(2, make_addr(2000), 999);
        stale.incarnation = 1;
        t.merge_entry(&stale);

        assert_eq!(t.entries[&2].incarnation, 2, "stale incarnation must be discarded");
        assert_eq!(t.entries[&2].heartbeat, 5, "heartbeat must not be overwritten");
    }

    /// Same incarnation: higher heartbeat wins (existing per-incarnation rule).
    #[test]
    fn same_incarnation_higher_heartbeat_wins() {
        let mut t = MembershipTable::new(1, make_addr(1000));

        let mut a = NodeState::new_alive(2, make_addr(2000), 3);
        a.incarnation = 1;
        t.merge_entry(&a);

        let mut b = NodeState::new_alive(2, make_addr(2000), 10);
        b.incarnation = 1;
        t.merge_entry(&b);

        assert_eq!(t.entries[&2].heartbeat, 10);
        assert_eq!(t.entries[&2].incarnation, 1);
    }

    /// Same incarnation + same heartbeat: Suspect beats Alive.
    #[test]
    fn same_incarnation_same_heartbeat_suspect_beats_alive() {
        let mut t = MembershipTable::new(1, make_addr(1000));

        let mut alive = NodeState::new_alive(2, make_addr(2000), 7);
        alive.incarnation = 2;
        t.merge_entry(&alive);

        let mut suspect = NodeState::new_alive(2, make_addr(2000), 7);
        suspect.incarnation = 2;
        suspect.status = NodeStatus::Suspect;
        t.merge_entry(&suspect);

        assert_eq!(t.entries[&2].status, NodeStatus::Suspect);
    }

    /// Incarnation numbers survive a node_state → wire → node_state roundtrip.
    #[test]
    fn incarnation_survives_wire_roundtrip() {
        let mut s = NodeState::new_alive(42, make_addr(5000), 7);
        s.incarnation = 3;
        s.status = NodeStatus::Suspect;

        let wire = node_state_to_wire(&s).expect("IPv4 must produce Some");
        assert_eq!(wire.incarnation, 3);

        let back = wire_to_node_state(&wire).expect("valid wire entry");
        assert_eq!(back.incarnation, 3);
        assert_eq!(back.status, NodeStatus::Suspect);
    }

    // ── Placeholder tests ─────────────────────────────────────────────────────

    /// Bootstrap placeholders must be tracked and queryable.
    #[test]
    fn placeholder_tracked_on_add() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.add_bootstrap_peer(make_addr(2000));
        let pid = placeholder_id_for(make_addr(2000));
        assert!(t.is_placeholder(pid));
        assert!(t.entries.contains_key(&pid));
    }

    /// Placeholder entries must never appear in gossip_digest.
    #[test]
    fn placeholder_excluded_from_gossip_digest() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.add_bootstrap_peer(make_addr(2000));
        let pid = placeholder_id_for(make_addr(2000));

        // Table has self + placeholder = 2 entries.
        assert_eq!(t.entries.len(), 2);

        // Digest must only contain self — placeholder is filtered.
        let digest = t.gossip_digest(50);
        assert_eq!(digest.len(), 1, "placeholder must not appear in gossip digest");
        assert_eq!(digest[0].node_id, 1);
        assert!(!digest.iter().any(|e| e.node_id == pid));
    }

    /// remove_placeholder_for_addr clears placeholder from both entries and
    /// the tracking set.
    #[test]
    fn remove_placeholder_clears_tracking() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.add_bootstrap_peer(make_addr(2000));
        let pid = placeholder_id_for(make_addr(2000));
        assert!(t.is_placeholder(pid));

        // Simulate learning the real id for addr 2000.
        t.remove_placeholder_for_addr(make_addr(2000), 42);
        assert!(!t.is_placeholder(pid));
        assert!(!t.entries.contains_key(&pid));
    }

    /// When a gossip entry carries a real node_id for an address we only know
    /// via a placeholder, merge_entry must evict the placeholder.
    #[test]
    fn gossip_entry_evicts_placeholder() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        t.add_bootstrap_peer(make_addr(3000));
        let pid = placeholder_id_for(make_addr(3000));
        assert!(t.entries.contains_key(&pid));

        // A gossip tells us the real node at addr 3000 has id=99.
        let real = NodeState::new_alive(99, make_addr(3000), 5);
        t.merge_entry(&real);

        // Placeholder must be gone; real entry must exist.
        assert!(!t.entries.contains_key(&pid), "placeholder must be evicted");
        assert!(!t.is_placeholder(pid));
        assert_eq!(t.entries[&99].heartbeat, 5);
    }

    /// Placeholder for our own address is discarded by the local_addr guard
    /// in merge_entry (no duplicate address entries).
    #[test]
    fn placeholder_for_own_addr_discarded() {
        let mut t = MembershipTable::new(1, make_addr(1000));

        // Simulate receiving a gossip entry that has our address but a
        // different (placeholder-style) node_id.
        let stale = NodeState::new_alive(0xDEAD, make_addr(1000), 0);
        t.merge_entry(&stale);

        // Only our own entry should exist for addr 1000.
        let count = t.entries.values().filter(|e| e.addr == make_addr(1000)).count();
        assert_eq!(count, 1, "only one entry for our own address");
        assert_eq!(t.entries[&1].addr, make_addr(1000));
    }

    // ── Suspect timeout scaling & jitter tests ───────────────────────────────

    /// suspect_timeout scales with cluster size (log2).
    #[test]
    fn suspect_timeout_scales_with_cluster_size() {
        let mut t = MembershipTable::new(1, make_addr(1000));

        // With only self (1 entry): log2(1) = 0, scale = 1.0.
        let t1 = t.suspect_timeout(1000, 0.5);
        assert_eq!(t1, Duration::from_millis(1000));

        // Add 15 peers → 16 entries: log2(16) = 4, scale = 3.0.
        // Use port offsets that don't collide with self (port 1000).
        for i in 2..=16u64 {
            t.merge_entry(&NodeState::new_alive(i, make_addr(2000 + i as u16), i as u32));
        }
        let t16 = t.suspect_timeout(1000, 0.5);
        // Allow 50 ms tolerance for floating-point truncation.
        assert!(
            t16 >= Duration::from_millis(2950) && t16 <= Duration::from_millis(3050),
            "expected ~3000 ms for 16 entries, got {t16:?}"
        );

        // Larger multiplier amplifies the scaling.
        let t16_big = t.suspect_timeout(1000, 1.0);
        assert!(
            t16_big >= Duration::from_millis(4950) && t16_big <= Duration::from_millis(5050),
            "expected ~5000 ms for 16 entries with multiplier=1.0, got {t16_big:?}"
        );
    }

    /// Zero multiplier disables cluster-size scaling.
    #[test]
    fn suspect_timeout_zero_multiplier() {
        let mut t = MembershipTable::new(1, make_addr(1000));
        for i in 2..=32u64 {
            t.merge_entry(&NodeState::new_alive(i, make_addr(i as u16 * 100), i as u32));
        }
        let timeout = t.suspect_timeout(500, 0.0);
        assert_eq!(timeout, Duration::from_millis(500));
    }

    /// suspect_jitter returns deterministic values in [0, max).
    #[test]
    fn suspect_jitter_deterministic_and_bounded() {
        let j1 = suspect_jitter(1, 42, 1000);
        let j2 = suspect_jitter(1, 42, 1000);
        assert_eq!(j1, j2, "same inputs must produce same jitter");
        assert!(j1 < Duration::from_millis(1000));
    }

    /// Different observers get different jitter for the same suspect,
    /// ensuring Dead declarations are staggered.
    #[test]
    fn suspect_jitter_differs_across_observers() {
        // Not guaranteed to differ for all pairs (hash collisions possible),
        // but with these specific IDs it should.
        let j_a = suspect_jitter(1, 99, 10_000);
        let j_b = suspect_jitter(2, 99, 10_000);
        // With 10 s range, two random offsets are extremely unlikely to match.
        assert_ne!(j_a, j_b, "different observers should (almost always) get different jitter");
    }

    /// Zero jitter_ms produces zero duration (no division by zero).
    #[test]
    fn suspect_jitter_zero_max() {
        assert_eq!(suspect_jitter(1, 2, 0), Duration::ZERO);
    }

    /// expired_suspects_jittered respects the jittered deadline.
    #[test]
    fn expired_suspects_jittered_basic() {
        let mut t = MembershipTable::new(1, make_addr(1000));

        // Insert a suspect that became suspect 5 s ago.
        let mut s = NodeState::new_alive(2, make_addr(2000), 1);
        s.status = NodeStatus::Suspect;
        s.suspect_since = Some(Instant::now() - Duration::from_secs(5));
        t.entries.insert(2, s);

        // With base=1000 ms, multiplier=0.0, jitter=0: effective ≈ 1 s.
        // 5 s > 1 s → should be expired.
        let expired = t.expired_suspects_jittered(1000, 0.0, 0);
        assert!(expired.contains(&2), "suspect 5 s old must be expired with 1 s timeout");

        // With base=10000 ms: effective ≈ 10 s.  5 s < 10 s → not expired.
        let not_expired = t.expired_suspects_jittered(10_000, 0.0, 0);
        assert!(!not_expired.contains(&2));
    }
}
