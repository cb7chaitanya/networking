/// Reusable node runner — the core event loop shared by the binary and tests.
///
/// Contains the `Node` struct (protocol state) and `run_node` (event loop).
/// The binary crate adds CLI parsing; integration tests use `Node` directly.
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::anti_entropy::ChunkAssembler;
use crate::failure_detector::FailureDetector;
use crate::gossip;
use crate::membership::{wire_to_node_state, MembershipTable};
use crate::message::{
    build_ack, build_leave, build_ping, build_ping_req, MessagePayload,
};
use crate::metrics::Metrics;
use crate::node::{generate_node_id, NodeConfig, NodeId, NodeState};
use crate::reliable::PendingAcks;
use crate::timeline::{TimelineEventKind, TimelineLog};
use crate::transport::Transport;

// ── Node ───────────────────────────────────────────────────────────────────────
pub struct Node {
    pub id: NodeId,
    pub config: NodeConfig,
    pub transport: Transport,
    pub table: MembershipTable,
    pub failure_det: FailureDetector,
    pub metrics: Metrics,
    pub pending_acks: PendingAcks,
    pub chunk_assembler: ChunkAssembler,
    pub timeline: TimelineLog,
    /// Monotonic counter for anti-entropy table snapshots.
    ae_version: u64,
}

impl Node {
    pub fn new(mut transport: Transport, config: NodeConfig, peers: &[SocketAddr]) -> Self {
        // Attach inbound rate limiter if configured.
        if config.inbound_global_capacity > 0 {
            transport = transport.with_rate_limit(
                crate::rate_limit::RateLimitConfig {
                    global_capacity: config.inbound_global_capacity,
                    global_refill_rate: config.inbound_global_refill_rate,
                    peer_capacity: config.inbound_peer_capacity,
                    peer_refill_rate: config.inbound_peer_refill_rate,
                },
            );
        }
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
        let chunk_assembler = ChunkAssembler::new(Duration::from_secs(5));
        Self {
            id,
            config,
            transport,
            table,
            failure_det,
            metrics: Metrics::default(),
            pending_acks,
            chunk_assembler,
            timeline: TimelineLog::new(),
            ae_version: 0,
        }
    }
}

/// One member entry for the /membership endpoint.
#[derive(Clone)]
struct MemberInfo {
    id: u64,
    addr: SocketAddr,
    status: &'static str,
}

/// Snapshot of metrics + cluster status for the HTTP endpoint.
#[derive(Clone, Default)]
struct MetricsSnapshot {
    metrics: crate::metrics::Metrics,
    alive: usize,
    suspect: usize,
    dead: usize,
    members: Vec<MemberInfo>,
    timeline_json: String,
}

impl Default for MemberInfo {
    fn default() -> Self {
        Self {
            id: 0,
            addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            status: "unknown",
        }
    }
}

/// Serve Prometheus metrics over HTTP on the given port.
///
/// Runs until the `shutdown` future completes.  Responds to any request
/// path containing "json" with JSON, everything else with Prometheus text.
async fn metrics_server(port: u16, shared: Arc<Mutex<MetricsSnapshot>>) {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            log::info!("[metrics-server] listening on {}", l.local_addr().unwrap());
            l
        }
        Err(e) => {
            log::warn!("[metrics-server] failed to bind {addr}: {e}");
            return;
        }
    };

    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Read enough of the request to determine the path.
        let mut req_buf = vec![0u8; 512];
        let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut req_buf).await {
            Ok(n) => n,
            Err(_) => continue,
        };
        let req = String::from_utf8_lossy(&req_buf[..n]);

        let snap = shared.lock().unwrap().clone();

        // Extract the request path from the first line: "GET /path HTTP/1.1"
        let path = req.split_whitespace().nth(1).unwrap_or("/");

        let (content_type, body) = if path == "/healthz" {
            ("application/json", r#"{"status":"ok"}"#.to_string())
        } else if path == "/readyz" {
            ("application/json", format!(
                r#"{{"alive_nodes":{},"suspect_nodes":{},"dead_nodes":{}}}"#,
                snap.alive, snap.suspect, snap.dead,
            ))
        } else if path == "/membership" {
            let nodes: Vec<String> = snap.members.iter().map(|m| {
                format!(
                    r#"{{"id":"{}","addr":"{}","status":"{}"}}"#,
                    m.id, m.addr, m.status,
                )
            }).collect();
            ("application/json", format!(r#"{{"nodes":[{}]}}"#, nodes.join(",")))
        } else if path == "/timeline" {
            ("application/json", snap.timeline_json.clone())
        } else if path.contains("json") {
            ("application/json", snap.metrics.json(snap.alive, snap.suspect, snap.dead))
        } else {
            ("text/plain; version=0.0.4; charset=utf-8",
             snap.metrics.prometheus(snap.alive, snap.suspect, snap.dead))
        };

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes()).await;
    }
}

// ── Event loop ─────────────────────────────────────────────────────────────────
/// Run a node until `shutdown_rx` fires. Returns the final `Node` so callers
/// (e.g. tests) can inspect the membership table and metrics.
pub async fn run_node(
    mut node: Node,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Node {
    // Start metrics HTTP server if configured.
    let metrics_shared = Arc::new(Mutex::new(MetricsSnapshot::default()));
    if node.config.metrics_server_port > 0 {
        let shared = metrics_shared.clone();
        let port = node.config.metrics_server_port;
        tokio::spawn(async move {
            metrics_server(port, shared).await;
        });
    }

    let mut gossip_tick =
        tokio::time::interval(Duration::from_millis(node.config.gossip_interval_ms));
    let mut hb_tick =
        tokio::time::interval(Duration::from_millis(node.config.heartbeat_interval_ms));
    let mut probe_tick =
        tokio::time::interval(Duration::from_millis(node.config.probe_interval_ms));

    // Anti-entropy timer (disabled when interval == 0).
    let anti_entropy_ms = node.config.anti_entropy_interval_ms;
    let mut anti_entropy_tick = tokio::time::interval(if anti_entropy_ms > 0 {
        Duration::from_millis(anti_entropy_ms)
    } else {
        Duration::from_secs(3600) // effectively disabled
    });

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
    anti_entropy_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    metrics_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // ── Shutdown signal ────────────────────────────────────────────────
            _ = &mut shutdown_rx => {
                log::info!("[node {}] broadcasting LEAVE and shutting down", node.id);
                node.timeline.record(
                    TimelineEventKind::Leave,
                    node.id,
                    None,
                    "local node shutting down",
                );
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
                // Auto-export timeline JSON on shutdown.
                if let Err(e) = node.timeline.export_json_file(std::path::Path::new("timeline.json")) {
                    log::warn!("[timeline] failed to write timeline.json: {e}");
                } else {
                    log::info!("[timeline] exported {} events to timeline.json", node.timeline.len());
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

            // ── Branch 3: gossip round (rate-limited, adaptive targets) ────────
            _ = gossip_tick.tick() => {
                let max_targets = gossip::effective_gossip_targets(
                    node.config.max_gossip_sends,
                    node.table.entries.len(),
                    node.config.adaptive_gossip_targets,
                );
                let targets = gossip::pick_gossip_targets(
                    &node.table,
                    node.id,
                    max_targets,
                );
                if !targets.is_empty() {
                    node.metrics.gossip_rounds += 1;
                    node.timeline.record(
                        TimelineEventKind::GossipSpread,
                        node.id,
                        None,
                        format!("gossip round to {} peer(s)", targets.len()),
                    );
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
                    node.timeline.record(
                        TimelineEventKind::ProbeTimeout,
                        node.id,
                        Some(target_id),
                        format!("direct probe timed out for node {target_id}"),
                    );
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
                            node.timeline.record(
                                TimelineEventKind::IndirectProbe,
                                node.id,
                                Some(target_id),
                                format!("indirect probe via {} intermediaries", intermediaries.len()),
                            );
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
                    node.timeline.record(
                        TimelineEventKind::NodeSuspected,
                        node.id,
                        Some(id),
                        format!("node {id} suspected after probe failure"),
                    );
                    node.table.suspect(id);
                }

                // Step 2: promote expired Suspects to Dead (jittered to
                // desynchronise declarations across the cluster).
                for id in node.table.expired_suspects_jittered(
                    node.config.suspect_timeout_ms,
                    node.config.suspect_timeout_multiplier,
                    node.config.suspect_timeout_jitter_ms,
                ) {
                    node.timeline.record(
                        TimelineEventKind::NodeDeclaredDead,
                        node.id,
                        Some(id),
                        format!("node {id} declared dead after suspect timeout"),
                    );
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

            // ── Branch 5: anti-entropy chunked sync ──────────────────────────
            _ = anti_entropy_tick.tick(), if anti_entropy_ms > 0 => {
                if let Some((peer_id, peer_addr)) =
                    gossip::pick_random_peer(&node.table, node.id)
                {
                    node.ae_version = node.ae_version.wrapping_add(1);
                    let entries = node.table.gossip_wire_entries(usize::MAX);
                    let chunks = crate::anti_entropy::build_chunks(
                        &entries,
                        node.id,
                        node.table.our_heartbeat(),
                        node.table.our_incarnation(),
                        node.ae_version,
                    );
                    let n_chunks = chunks.len();
                    for chunk_msg in chunks {
                        match node.transport.send_to(&chunk_msg, peer_addr).await {
                            Ok(()) => {
                                node.metrics.anti_entropy_sent += 1;
                            }
                            Err(e) => {
                                log::warn!(
                                    "[node {}] anti-entropy chunk send failed to {peer_addr}: {e}",
                                    node.id
                                );
                                break;
                            }
                        }
                    }
                    log::debug!(
                        "[node {}] anti-entropy → peer {} @ {} ({} chunks, version {})",
                        node.id, peer_id, peer_addr, n_chunks, node.ae_version
                    );
                }

                // Expire stale incomplete assemblies.
                node.chunk_assembler.expire(Instant::now());
            }

            // ── Branch 6: periodic metrics log ───────────────────────────────
            _ = metrics_tick.tick(), if metrics_ms > 0 => {
                // Drain rate-limited counter from transport into metrics.
                node.metrics.rate_limited += node.transport.rate_limited_count
                    .swap(0, std::sync::atomic::Ordering::Relaxed);
                let (alive, suspect, dead) = node.table.status_counts();
                log::info!(
                    "[metrics] {}",
                    node.metrics.summary(alive, suspect, dead)
                );
                // Update shared snapshot for the HTTP server.
                if node.config.metrics_server_port > 0 {
                    let members: Vec<MemberInfo> = node.table.entries.values()
                        .map(|e| MemberInfo {
                            id: e.node_id,
                            addr: e.addr,
                            status: match e.status {
                                crate::node::NodeStatus::Alive => "alive",
                                crate::node::NodeStatus::Suspect => "suspect",
                                crate::node::NodeStatus::Dead => "dead",
                            },
                        })
                        .collect();
                    let mut snap = metrics_shared.lock().unwrap();
                    snap.metrics = node.metrics.clone();
                    snap.alive = alive;
                    snap.suspect = suspect;
                    snap.dead = dead;
                    snap.members = members;
                    snap.timeline_json = node.timeline.export_json();
                }
            }
        }
    }

    node
}

// ── Message handler ────────────────────────────────────────────────────────────
async fn handle_message(
    node: &mut Node,
    msg: crate::message::Message,
    from_addr: SocketAddr,
) {
    // If this sender was previously known only as a bootstrap placeholder,
    // remove that stale entry before inserting the real one.
    node.table.remove_placeholder_for_addr(from_addr, msg.sender_id);

    // Any message from a node proves it is alive — record liveness from header.
    let mut sender_alive = NodeState::new_alive(
        msg.sender_id,
        from_addr,
        msg.sender_heartbeat,
    );
    sender_alive.incarnation = msg.sender_incarnation;
    let outcome = node.table.merge_entry(&sender_alive);
    if outcome == crate::metrics::MergeOutcome::New {
        node.timeline.record(
            TimelineEventKind::NodeJoined,
            node.id,
            Some(msg.sender_id),
            format!("discovered node {} @ {}", msg.sender_id, from_addr),
        );
    }
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
            node.timeline.record(
                TimelineEventKind::Leave,
                node.id,
                Some(msg.sender_id),
                format!("received LEAVE from node {} @ {}", msg.sender_id, from_addr),
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

        MessagePayload::AntiEntropyChunk(ref chunk) => {
            log::debug!(
                "[node {}] anti-entropy chunk {}/{} from {} (version {})",
                node.id,
                chunk.chunk_index + 1,
                chunk.total_chunks,
                msg.sender_id,
                chunk.table_version,
            );
            if let Some(all_entries) = node.chunk_assembler.feed(
                msg.sender_id,
                chunk.table_version,
                chunk.chunk_index,
                chunk.total_chunks,
                chunk.entries.clone(),
            ) {
                let states: Vec<_> = all_entries.iter().filter_map(wire_to_node_state).collect();
                log::debug!(
                    "[node {}] anti-entropy assembly complete: {} entries from {}",
                    node.id,
                    states.len(),
                    msg.sender_id,
                );
                for o in node.table.merge_digest(&states) {
                    node.metrics.record_merge(o);
                }
            }
        }
    }
}
