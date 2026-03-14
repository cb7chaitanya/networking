/// Gossip-based distributed membership protocol — node runner and CLI.
///
/// Usage:
///   # Generate a cluster key:
///   cargo run -- --generate-key
///
///   # Start a standalone bootstrap node (encrypted):
///   cargo run -- --bind 127.0.0.1:7000 --cluster-key <HEX>
///
///   # Join an existing cluster:
///   cargo run -- --bind 127.0.0.1:7001 --peers 127.0.0.1:7000 --cluster-key <HEX>
///   cargo run -- --bind 127.0.0.1:7002 --peers 127.0.0.1:7000,127.0.0.1:7001 --cluster-key <HEX>
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::sync::oneshot;

use gossip_membership::crypto::{self, ClusterKey};
use gossip_membership::failure_detector::FailureDetector;
use gossip_membership::gossip;
use gossip_membership::membership::{wire_to_node_state, MembershipTable};
use gossip_membership::message::{
    build_ack, build_leave, build_ping, build_ping_req, MessagePayload,
};
use gossip_membership::metrics::Metrics;
use gossip_membership::node::{generate_node_id, NodeConfig, NodeId};
use gossip_membership::reliable::PendingAcks;
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

    /// Shared cluster key (64 hex chars = 256-bit ChaCha20-Poly1305 key).
    /// All nodes in the cluster must use the same key.
    #[arg(long)]
    cluster_key: Option<String>,

    /// Generate a random cluster key, print it, and exit.
    #[arg(long)]
    generate_key: bool,
}

// ── Node ───────────────────────────────────────────────────────────────────────
pub struct Node {
    pub id: NodeId,
    pub config: NodeConfig,
    transport: Transport,
    table: MembershipTable,
    failure_det: FailureDetector,
    pub metrics: Metrics,
    pending_acks: PendingAcks,
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
        let pending_acks =
            PendingAcks::new(Duration::from_millis(config.reliable_ack_timeout_ms));
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
            metrics: Metrics::default(),
            pending_acks,
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

    // Metrics logging timer (disabled when interval == 0).
    let metrics_ms = node.config.metrics_log_interval_ms;
    let mut metrics_tick = tokio::time::interval(if metrics_ms > 0 {
        Duration::from_millis(metrics_ms)
    } else {
        Duration::from_secs(3600) // effectively disabled
    });

    // Don't burst on startup — skip missed ticks rather than compressing them.
    gossip_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    hb_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    probe_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    metrics_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // ── Shutdown signal ────────────────────────────────────────────────
            _ = &mut shutdown_rx => {
                log::info!("[node {}] broadcasting LEAVE and shutting down", node.id);
                let leave = build_leave(
                    node.id,
                    node.table.our_heartbeat(),
                    node.table.our_incarnation(),
                ).with_request_ack();
                let live = node.table.live_nodes();
                for peer_id in &live {
                    if let Some(e) = node.table.entries.get(peer_id) {
                        let _ = node.transport.send_to(&leave, e.addr).await;
                    }
                }
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

            // ── Branch 3: gossip round (rate-limited) ─────────────────────────
            _ = gossip_tick.tick() => {
                let targets = gossip::pick_gossip_targets(
                    &node.table,
                    node.id,
                    node.config.max_gossip_sends,
                );
                if !targets.is_empty() {
                    node.metrics.gossip_rounds += 1;
                    let fanout = gossip::effective_fanout(
                        node.config.gossip_fanout,
                        node.table.entries.len(),
                        node.config.adaptive_fanout,
                    );
                    let msg = gossip::build_gossip_message(
                        &node.table,
                        node.id,
                        node.table.our_heartbeat(),
                        node.table.our_incarnation(),
                        fanout,
                    );
                    for (peer_id, peer_addr) in &targets {
                        match node.transport.send_to(&msg, *peer_addr).await {
                            Ok(()) => {
                                node.metrics.gossip_sent += 1;
                                log::debug!(
                                    "[node {}] gossip → peer {} @ {}",
                                    node.id, peer_id, peer_addr
                                );
                            }
                            Err(e) => log::warn!(
                                "[node {}] gossip send failed to {peer_addr}: {e}",
                                node.id
                            ),
                        }
                    }
                }
            }

            // ── Branch 4: failure detection scan ─────────────────────────────
            _ = probe_tick.tick() => {
                let now = Instant::now();

                // Step 1: check pending probes for timeouts.
                let scan = node.failure_det.scan(now);

                node.metrics.probe_direct_timeouts += scan.escalate_to_indirect.len() as u64;

                for target_id in scan.escalate_to_indirect {
                    // Direct probe timed out; send PING_REQ to k intermediaries.
                    if let Some(target_state) = node.table.entries.get(&target_id) {
                        let target_addr = target_state.addr;
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
                                node.table.our_incarnation(),
                                target_id,
                                target_addr,
                            );
                            if node.transport.send_to(&req, *inter_addr).await.is_ok() {
                                node.metrics.ping_reqs_sent += 1;
                            }
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

                node.metrics.probe_failures += scan.declare_suspect.len() as u64;
                for id in scan.declare_suspect {
                    node.table.suspect(id);
                }

                // Step 2: promote expired Suspects to Dead (jittered to
                // desynchronise declarations across the cluster).
                for id in node.table.expired_suspects_jittered(
                    node.config.suspect_timeout_ms,
                    node.config.suspect_timeout_multiplier,
                    node.config.suspect_timeout_jitter_ms,
                ) {
                    node.table.declare_dead(id);
                }

                // Step 3: garbage-collect old Dead entries.
                node.table.gc_dead(Duration::from_millis(node.config.dead_retention_ms));

                // Step 3b: retransmit REQUEST_ACK messages that timed out.
                let retry_result = node.pending_acks.collect_retries(now);
                for (target_id, retry_msg, target_addr) in retry_result.retransmits {
                    node.metrics.reliable_retries += 1;
                    log::debug!(
                        "[node {}] retransmitting REQUEST_ACK message to {} @ {}",
                        node.id, target_id, target_addr
                    );
                    let _ = node.transport.send_to(&retry_msg, target_addr).await;
                }
                node.metrics.reliable_exhausted += retry_result.exhausted as u64;

                // Step 4: probe one random live node.
                if let Some((target_id, target_addr)) =
                    gossip::pick_random_peer(&node.table, node.id)
                {
                    if !node.failure_det.is_probing(target_id) {
                        let piggyback = node.table.gossip_wire_entries(node.config.piggyback_max);
                        let ping = build_ping(node.id, node.table.our_heartbeat(), node.table.our_incarnation(), piggyback);
                        match node.transport.send_to(&ping, target_addr).await {
                            Ok(()) => {
                                node.metrics.pings_sent += 1;
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

            // ── Branch 5: periodic metrics log ───────────────────────────────
            _ = metrics_tick.tick(), if metrics_ms > 0 => {
                let (alive, suspect, dead) = node.table.status_counts();
                log::info!(
                    "[metrics] {}",
                    node.metrics.summary(alive, suspect, dead)
                );
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
    let mut sender_alive = gossip_membership::node::NodeState::new_alive(
        msg.sender_id,
        from_addr,
        msg.sender_heartbeat,
    );
    sender_alive.incarnation = msg.sender_incarnation;
    let outcome = node.table.merge_entry(&sender_alive);
    node.metrics.record_merge(outcome);

    // If we had an in-flight probe for this sender, an incoming message resolves it.
    node.failure_det.record_ack(msg.sender_id);

    // Clear any pending reliable-delivery entry for this sender.
    node.pending_acks.ack(msg.sender_id);

    match &msg.payload {
        MessagePayload::Gossip(entries) => {
            node.metrics.gossip_recv += 1;
            let states: Vec<_> = entries.iter().filter_map(wire_to_node_state).collect();
            log::debug!(
                "[node {}] gossip from {} ({} entries)",
                node.id,
                msg.sender_id,
                states.len()
            );
            for o in node.table.merge_digest(&states) {
                node.metrics.record_merge(o);
            }
            // Respond with ACK if the sender requested reliable delivery.
            if msg.requests_ack() {
                let ack = build_ack(node.id, node.table.our_heartbeat(), node.table.our_incarnation(), vec![]);
                if node.transport.send_to(&ack, from_addr).await.is_ok() {
                    node.metrics.acks_sent += 1;
                }
            }
        }

        MessagePayload::Ping(ref entries) => {
            node.metrics.pings_recv += 1;
            // Merge piggybacked membership entries.
            if !entries.is_empty() {
                let states: Vec<_> = entries.iter().filter_map(wire_to_node_state).collect();
                for o in node.table.merge_digest(&states) {
                    node.metrics.record_merge(o);
                }
            }
            // Respond immediately with an ACK so the sender clears its probe.
            let piggyback = node.table.gossip_wire_entries(node.config.piggyback_max);
            let ack = build_ack(node.id, node.table.our_heartbeat(), node.table.our_incarnation(), piggyback);
            if let Err(e) = node.transport.send_to(&ack, from_addr).await {
                log::warn!("[node {}] ACK send failed to {from_addr}: {e}", node.id);
            } else {
                node.metrics.acks_sent += 1;
                log::trace!("[node {}] ACK → {} @ {}", node.id, msg.sender_id, from_addr);
            }
        }

        MessagePayload::PingReq(req) => {
            node.metrics.ping_reqs_recv += 1;
            // Forward a PING to the target on behalf of the requester.
            let target_addr = req.target_addr;
            let piggyback = node.table.gossip_wire_entries(node.config.piggyback_max);
            let ping = build_ping(node.id, node.table.our_heartbeat(), node.table.our_incarnation(), piggyback);
            if let Err(e) = node.transport.send_to(&ping, target_addr).await {
                log::warn!(
                    "[node {}] indirect PING to {} failed: {e}",
                    node.id, target_addr
                );
            } else {
                node.metrics.pings_sent += 1;
                log::debug!(
                    "[node {}] forwarded PING → {} (for requester {})",
                    node.id,
                    req.target_id,
                    msg.sender_id
                );
            }
        }

        MessagePayload::Ack(ref entries) => {
            node.metrics.acks_recv += 1;
            // Merge piggybacked membership entries.
            if !entries.is_empty() {
                let states: Vec<_> = entries.iter().filter_map(wire_to_node_state).collect();
                for o in node.table.merge_digest(&states) {
                    node.metrics.record_merge(o);
                }
            }
            log::trace!(
                "[node {}] ACK from {} @ {} ({} piggybacked)",
                node.id,
                msg.sender_id,
                from_addr,
                entries.len()
            );
        }

        MessagePayload::Leave => {
            log::info!(
                "[node {}] LEAVE from {} @ {} — marking Dead immediately",
                node.id,
                msg.sender_id,
                from_addr,
            );
            // Respond with ACK before marking dead so the departing node
            // knows we received its LEAVE.
            if msg.requests_ack() {
                let ack = build_ack(node.id, node.table.our_heartbeat(), node.table.our_incarnation(), vec![]);
                let _ = node.transport.send_to(&ack, from_addr).await;
                node.metrics.acks_sent += 1;
            }
            node.table.declare_dead(msg.sender_id);
        }
    }
}

// ── main ───────────────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    // --generate-key: print a random key and exit.
    if args.generate_key {
        let key_bytes = crypto::generate_key();
        println!("{}", crypto::key_to_hex(&key_bytes));
        return;
    }

    // Parse optional cluster key.
    let cluster_key: Option<ClusterKey> = args.cluster_key.as_deref().map(|hex| {
        let bytes = crypto::key_from_hex(hex)
            .unwrap_or_else(|| {
                eprintln!("error: --cluster-key must be exactly 64 hex characters");
                std::process::exit(1);
            });
        ClusterKey::from_bytes(bytes)
    });

    let peers: Vec<SocketAddr> = args
        .peers
        .iter()
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            s.parse().map_err(|e| log::warn!("bad peer address {s}: {e}")).ok()
        })
        .collect();

    let mut transport = Transport::bind(args.bind)
        .await
        .expect("failed to bind UDP socket");

    if let Some(key) = cluster_key {
        transport = transport.with_key(key);
        log::info!("encryption enabled (ChaCha20-Poly1305)");
    }

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
