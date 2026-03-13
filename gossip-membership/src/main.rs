/// Gossip-based distributed membership protocol — node runner and CLI.
///
/// Usage:
///   # Start a standalone bootstrap node:
///   cargo run -- --bind 127.0.0.1:7000
///
///   # Join an existing cluster:
///   cargo run -- --bind 127.0.0.1:7001 --peers 127.0.0.1:7000
///   cargo run -- --bind 127.0.0.1:7002 --peers 127.0.0.1:7000,127.0.0.1:7001
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::sync::oneshot;

use gossip_membership::failure_detector::FailureDetector;
use gossip_membership::gossip;
use gossip_membership::membership::{wire_to_node_state, MembershipTable};
use gossip_membership::message::{
    build_ack, build_ping, build_ping_req, MessagePayload,
};
use gossip_membership::node::{generate_node_id, NodeConfig, NodeId};
use gossip_membership::transport::Transport;

// ── CLI ────────────────────────────────────────────────────────────────────────
#[derive(Parser, Debug)]
#[command(name = "gossip-membership", about = "Gossip-based distributed membership protocol")]
struct Args {
    /// Local address to bind (e.g. 127.0.0.1:7000)
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: SocketAddr,

    /// Comma-separated list of bootstrap peer addresses (e.g. 127.0.0.1:7000)
    #[arg(long, value_delimiter = ',', default_value = "")]
    peers: Vec<String>,
}

// ── Node ───────────────────────────────────────────────────────────────────────
pub struct Node {
    pub id: NodeId,
    pub config: NodeConfig,
    transport: Transport,
    table: MembershipTable,
    failure_det: FailureDetector,
}

impl Node {
    pub fn new(transport: Transport, config: NodeConfig, peers: &[SocketAddr]) -> Self {
        let id = generate_node_id(transport.local_addr);
        let mut table = MembershipTable::new(id, transport.local_addr);
        for &peer_addr in peers {
            table.add_bootstrap_peer(peer_addr);
        }
        let failure_det =
            FailureDetector::new(Duration::from_millis(config.probe_timeout_ms));
        log::info!(
            "[node] started id={} addr={}",
            id,
            transport.local_addr
        );
        Self {
            id,
            config,
            transport,
            table,
            failure_det,
        }
    }
}

// ── Event loop ─────────────────────────────────────────────────────────────────
/// Run a node until `shutdown_rx` fires. Returns the final `Node` so callers
/// (e.g. tests) can inspect the membership table.
pub async fn run_node(
    mut node: Node,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Node {
    let mut gossip_tick =
        tokio::time::interval(Duration::from_millis(node.config.gossip_interval_ms));
    let mut hb_tick =
        tokio::time::interval(Duration::from_millis(node.config.heartbeat_interval_ms));
    let mut probe_tick =
        tokio::time::interval(Duration::from_millis(node.config.probe_interval_ms));

    // Don't burst on startup — skip missed ticks rather than compressing them.
    gossip_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    hb_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    probe_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // ── Shutdown signal ────────────────────────────────────────────────
            _ = &mut shutdown_rx => {
                log::info!("[node {}] shutting down", node.id);
                break;
            }

            // ── Branch 1: receive incoming UDP datagram ────────────────────────
            result = node.transport.recv_from() => {
                match result {
                    Ok((msg, from_addr)) => handle_message(&mut node, msg, from_addr).await,
                    Err(e) => log::warn!("[node {}] recv error: {e}", node.id),
                }
            }

            // ── Branch 2: heartbeat tick ──────────────────────────────────────
            _ = hb_tick.tick() => {
                node.table.tick_heartbeat();
                log::trace!(
                    "[node {}] heartbeat={}",
                    node.id,
                    node.table.our_heartbeat()
                );
            }

            // ── Branch 3: gossip round ─────────────────────────────────────────
            _ = gossip_tick.tick() => {
                if let Some((peer_id, peer_addr)) =
                    gossip::pick_random_peer(&node.table, node.id)
                {
                    let msg = gossip::build_gossip_message(
                        &node.table,
                        node.id,
                        node.table.our_heartbeat(),
                        node.config.gossip_fanout,
                    );
                    match node.transport.send_to(&msg, peer_addr).await {
                        Ok(()) => log::debug!(
                            "[node {}] gossip → peer {} @ {}",
                            node.id, peer_id, peer_addr
                        ),
                        Err(e) => log::warn!(
                            "[node {}] gossip send failed to {peer_addr}: {e}",
                            node.id
                        ),
                    }
                }
            }

            // ── Branch 4: failure detection scan ─────────────────────────────
            _ = probe_tick.tick() => {
                let now = Instant::now();

                // Step 1: check pending probes for timeouts.
                let scan = node.failure_det.scan(now);

                for target_id in scan.escalate_to_indirect {
                    // Direct probe timed out; send PING_REQ to k intermediaries.
                    if let Some(target_state) = node.table.entries.get(&target_id) {
                        let target_addr = match target_state.addr {
                            SocketAddr::V4(a) => a,
                            _ => continue,
                        };
                        let intermediaries = gossip::pick_k_random_peers(
                            &node.table,
                            node.id,
                            target_id,
                            node.config.indirect_probe_k,
                        );
                        for (_, inter_addr) in &intermediaries {
                            let req = build_ping_req(
                                node.id,
                                node.table.our_heartbeat(),
                                target_id,
                                target_addr,
                            );
                            let _ = node.transport.send_to(&req, *inter_addr).await;
                        }
                        if !intermediaries.is_empty() {
                            node.failure_det.record_indirect_probe_sent(target_id);
                            log::debug!(
                                "[node {}] indirect probe for {target_id} via {} nodes",
                                node.id,
                                intermediaries.len()
                            );
                        }
                    }
                }

                for id in scan.declare_suspect {
                    node.table.suspect(id);
                }

                // Step 2: promote expired Suspects to Dead.
                for id in node.table.expired_suspects(
                    Duration::from_millis(node.config.suspect_timeout_ms),
                ) {
                    node.table.declare_dead(id);
                }

                // Step 3: garbage-collect old Dead entries.
                node.table.gc_dead(Duration::from_millis(node.config.dead_retention_ms));

                // Step 4: probe one random live node.
                if let Some((target_id, target_addr)) =
                    gossip::pick_random_peer(&node.table, node.id)
                {
                    if !node.failure_det.is_probing(target_id) {
                        let piggyback = node.table.gossip_wire_entries(node.config.piggyback_max);
                        let ping = build_ping(node.id, node.table.our_heartbeat(), piggyback);
                        match node.transport.send_to(&ping, target_addr).await {
                            Ok(()) => {
                                node.failure_det.record_probe_sent(target_id);
                                log::debug!(
                                    "[node {}] PING → {} @ {}",
                                    node.id, target_id, target_addr
                                );
                            }
                            Err(e) => log::warn!(
                                "[node {}] ping send failed to {target_addr}: {e}",
                                node.id
                            ),
                        }
                    }
                }
            }
        }
    }

    node
}

// ── Message handler ────────────────────────────────────────────────────────────
async fn handle_message(
    node: &mut Node,
    msg: gossip_membership::message::Message,
    from_addr: SocketAddr,
) {
    // If this sender was previously known only as a bootstrap placeholder,
    // remove that stale entry before inserting the real one.
    node.table.remove_placeholder_for_addr(from_addr, msg.sender_id);

    // Any message from a node proves it is alive — record liveness from header.
    let sender_alive = gossip_membership::node::NodeState::new_alive(
        msg.sender_id,
        from_addr,
        msg.sender_heartbeat,
    );
    node.table.merge_entry(&sender_alive);

    // If we had an in-flight probe for this sender, an incoming message resolves it.
    node.failure_det.record_ack(msg.sender_id);

    match &msg.payload {
        MessagePayload::Gossip(entries) => {
            let states: Vec<_> = entries.iter().filter_map(wire_to_node_state).collect();
            log::debug!(
                "[node {}] gossip from {} ({} entries)",
                node.id,
                msg.sender_id,
                states.len()
            );
            node.table.merge_digest(&states);
        }

        MessagePayload::Ping(ref entries) => {
            // Merge piggybacked membership entries.
            if !entries.is_empty() {
                let states: Vec<_> = entries.iter().filter_map(wire_to_node_state).collect();
                node.table.merge_digest(&states);
            }
            // Respond immediately with an ACK so the sender clears its probe.
            let piggyback = node.table.gossip_wire_entries(node.config.piggyback_max);
            let ack = build_ack(node.id, node.table.our_heartbeat(), piggyback);
            if let Err(e) = node.transport.send_to(&ack, from_addr).await {
                log::warn!("[node {}] ACK send failed to {from_addr}: {e}", node.id);
            } else {
                log::trace!("[node {}] ACK → {} @ {}", node.id, msg.sender_id, from_addr);
            }
        }

        MessagePayload::PingReq(req) => {
            // Forward a PING to the target on behalf of the requester.
            // We do not wait for or forward the ACK — the requester has its
            // own timeout and will receive the ACK directly if the target is alive.
            let target_addr = SocketAddr::V4(req.target_addr);
            let piggyback = node.table.gossip_wire_entries(node.config.piggyback_max);
            let ping = build_ping(node.id, node.table.our_heartbeat(), piggyback);
            if let Err(e) = node.transport.send_to(&ping, target_addr).await {
                log::warn!(
                    "[node {}] indirect PING to {} failed: {e}",
                    node.id, target_addr
                );
            } else {
                log::debug!(
                    "[node {}] forwarded PING → {} (for requester {})",
                    node.id,
                    req.target_id,
                    msg.sender_id
                );
            }
        }

        MessagePayload::Ack(ref entries) => {
            // Merge piggybacked membership entries.
            if !entries.is_empty() {
                let states: Vec<_> = entries.iter().filter_map(wire_to_node_state).collect();
                node.table.merge_digest(&states);
            }
            log::trace!(
                "[node {}] ACK from {} @ {} ({} piggybacked)",
                node.id,
                msg.sender_id,
                from_addr,
                entries.len()
            );
        }
    }
}

// ── main ───────────────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    let peers: Vec<SocketAddr> = args
        .peers
        .iter()
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            s.parse().map_err(|e| log::warn!("bad peer address {s}: {e}")).ok()
        })
        .collect();

    let transport = Transport::bind(args.bind)
        .await
        .expect("failed to bind UDP socket");

    log::info!("bound to {}", transport.local_addr);

    let config = NodeConfig::default();
    let node = Node::new(transport, config, &peers);

    // The main binary runs until Ctrl-C.
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = shutdown_tx.send(());
    });

    run_node(node, shutdown_rx).await;
}
